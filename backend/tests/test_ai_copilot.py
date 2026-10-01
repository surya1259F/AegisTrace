import uuid
import pytest
import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import (
    Case,
    EvidenceItem,
    Finding,
    ExecutionArtifact,
    CorrelationGroup,
    InvestigationPlan,
    ToolExecution,
    InvestigatorDecision
)
from backend.app.services.ai_provider import (
    ProviderId,
    ProviderResponse,
    ProviderError,
    OpenAIAdapter
)
from backend.app.services.ai_copilot import (
    AIClaimType,
    AIClaimItem,
    AICopilotResponse,
    AIExplanationResponse,
    parse_ai_json_output,
    build_case_copilot_context,
    validate_and_sanitize_claims,
    run_deterministic_copilot_fallback,
    run_copilot_query,
    explain_case_finding
)

MOCK_API_KEY = "sk-proj-test1234567890secretkey12345"


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_sample_case_data(db: Session):
    case_id = str(uuid.uuid4())
    case = Case(
        id=case_id,
        name=f"Forensic Investigation {case_id[:8]}",
        case_number=f"CAS-{case_id[:6]}",
        status="ACTIVE"
    )
    db.add(case)

    evidence = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case_id,
        name="disk_dump.raw",
        original_path="/evidence/disk_dump.raw",
        storage_path="/vault/disk_dump.raw",
        evidence_type="DISK_IMAGE",
        size_bytes=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        integrity_status="VERIFIED"
    )
    db.add(evidence)

    finding = Finding(
        id=str(uuid.uuid4()),
        case_id=case_id,
        title="Unusual LSASS Process Injection",
        description="Detected memory pattern matching Mimikatz injector",
        agent="volatile_mem",
        tool="volatility3",
        finding_type="SUSPICIOUS_PROCESS",
        severity="CRITICAL",
        mitre_techniques=["T1003.001"],
        raw_output_reference='{"mitre_techniques": ["T1003.001"]}'
    )
    db.add(finding)

    artifact = ExecutionArtifact(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence.id,
        agent="volatile_mem",
        tool="volatility3",
        artifact_type="MEMORY_DUMP",
        source_reference="/tmp/mem_01.raw"
    )
    db.add(artifact)

    correlation = CorrelationGroup(
        id=str(uuid.uuid4()),
        case_id=case_id,
        title="Credential Access Campaign",
        description="Credential access via LSASS injection",
        dimension="PROCESS_TIMELINE",
        rule="CORR-LSASS-01",
        correlated_entity="lsass.exe",
        supporting_finding_ids=[finding.id]
    )
    db.add(correlation)

    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case_id,
        status="EXECUTING",
        strategy_summary="Analyze LSASS injection and trace network connections"
    )
    db.add(plan)

    execution = ToolExecution(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence.id,
        tool_id="volatility3",
        status="COMPLETED"
    )
    db.add(execution)

    decision = InvestigatorDecision(
        id=str(uuid.uuid4()),
        case_id=case_id,
        investigator_id="inv-1",
        investigator_name="Lead Investigator",
        decision="ISOLATE_HOST",
        rationale="Active credential dumping confirmed"
    )
    db.add(decision)

    db.commit()
    return case_id, finding.id, artifact.id


# -----------------------------------------------------------------------------
# 1. JSON Parser Tests
# -----------------------------------------------------------------------------

def test_parse_ai_json_output_valid():
    raw = '{"answer": "Analysis complete", "claims": []}'
    res = parse_ai_json_output(raw)
    assert res == {"answer": "Analysis complete", "claims": []}


def test_parse_ai_json_output_markdown_fence():
    raw = "```json\n{\n  \"answer\": \"Analysis complete\",\n  \"claims\": []\n}\n```"
    res = parse_ai_json_output(raw)
    assert res == {"answer": "Analysis complete", "claims": []}


def test_parse_ai_json_output_embedded():
    raw = "Here is the response:\n{\"answer\": \"Embedded json\"}\nEnd of response."
    res = parse_ai_json_output(raw)
    assert res == {"answer": "Embedded json"}


def test_parse_ai_json_output_invalid():
    assert parse_ai_json_output("Not json at all") is None
    assert parse_ai_json_output("") is None
    assert parse_ai_json_output(None) is None


# -----------------------------------------------------------------------------
# 2. Context Builder & Truncation Tests
# -----------------------------------------------------------------------------

def test_build_case_copilot_context_not_found(db_session):
    fake_id = str(uuid.uuid4())
    with pytest.raises(HTTPException) as exc_info:
        build_case_copilot_context(fake_id, db_session)
    assert exc_info.value.status_code == 404


def test_build_case_copilot_context_success(db_session):
    case_id, finding_id, artifact_id = create_sample_case_data(db_session)

    context, truncated, valid_f_ids, valid_a_ids = build_case_copilot_context(case_id, db_session)

    assert truncated is False
    assert context["case"]["id"] == case_id
    assert len(context["evidence"]) == 1
    assert len(context["findings"]) == 1
    assert len(context["artifacts"]) == 1
    assert len(context["correlations"]) == 1
    assert len(context["plans"]) == 1
    assert len(context["executions"]) == 1
    assert len(context["decisions"]) == 1

    assert finding_id in valid_f_ids
    assert artifact_id in valid_a_ids


def test_build_case_copilot_context_truncation(db_session):
    case_id, _, _ = create_sample_case_data(db_session)

    # Force strict truncation with small character budget
    context, truncated, valid_f_ids, valid_a_ids = build_case_copilot_context(case_id, db_session, max_chars=250)

    assert truncated is True
    # Verify JSON context structure remains unbroken
    assert isinstance(context["evidence"], list)
    assert isinstance(context["findings"], list)


# -----------------------------------------------------------------------------
# 3. Provenance Sanitization Tests
# -----------------------------------------------------------------------------

def test_validate_and_sanitize_claims():
    valid_f = {"finding-1"}
    valid_a = {"artifact-1"}

    raw_claims = [
        # Valid FACT via finding
        {
            "claim_type": "FACT",
            "statement": "LSASS memory dump analyzed",
            "source_finding_id": "finding-1"
        },
        # Valid FACT via artifact
        {
            "claim_type": "FACT",
            "statement": "Disk dump verified",
            "source_artifact_id": "artifact-1"
        },
        # Invalid FACT (fake finding id) -> downgraded to INFERENCE
        {
            "claim_type": "FACT",
            "statement": "Attacker compromised AD controller",
            "source_finding_id": "fake-finding-999"
        },
        # INFERENCE claim -> stays INFERENCE
        {
            "claim_type": "INFERENCE",
            "statement": "Attacker likely used Cobalt Strike"
        },
        # UNVERIFIED claim -> UNVERIFIED
        {
            "claim_type": "UNKNOWN",
            "statement": "Speculative claim"
        }
    ]

    sanitized = validate_and_sanitize_claims(raw_claims, valid_f, valid_a)

    assert len(sanitized) == 5

    assert sanitized[0].claim_type == AIClaimType.FACT
    assert sanitized[0].source_finding_id == "finding-1"

    assert sanitized[1].claim_type == AIClaimType.FACT
    assert sanitized[1].source_artifact_id == "artifact-1"

    # Downgraded
    assert sanitized[2].claim_type == AIClaimType.INFERENCE
    assert sanitized[2].source_finding_id is None

    assert sanitized[3].claim_type == AIClaimType.INFERENCE
    assert sanitized[4].claim_type == AIClaimType.UNVERIFIED


# -----------------------------------------------------------------------------
# 4. Deterministic Fallback Copilot Engine Tests
# -----------------------------------------------------------------------------

def test_run_deterministic_copilot_fallback(db_session):
    case_id, finding_id, artifact_id = create_sample_case_data(db_session)
    context, truncated, valid_f, valid_a = build_case_copilot_context(case_id, db_session)

    res = run_deterministic_copilot_fallback(context, "What happened?", truncated, valid_f, valid_a)

    assert res.execution_mode == "DETERMINISTIC_FALLBACK"
    assert res.fallback_used is True
    assert res.provider_status == "FALLBACK_EXECUTED"
    assert res.provider == "local_stub"
    assert len(res.claims) == 1
    assert res.claims[0].source_finding_id == finding_id


# -----------------------------------------------------------------------------
# 5. Copilot Orchestration Queries
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_copilot_query_local_stub(db_session):
    case_id, finding_id, _ = create_sample_case_data(db_session)

    res = await run_copilot_query(
        case_id=case_id,
        query="Summarize findings",
        db=db_session,
        provider="local_stub"
    )

    assert res.execution_mode == "DETERMINISTIC_FALLBACK"
    assert res.fallback_used is True
    assert res.provider_status == "FALLBACK_EXECUTED"


@pytest.mark.asyncio
async def test_run_copilot_query_external_success(monkeypatch, db_session):
    case_id, finding_id, _ = create_sample_case_data(db_session)

    def mock_handler(request: httpx.Request):
        mock_body = {
            "id": "chatcmpl-copilot123",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": (
                        "{\n"
                        '  "answer": "Identified credential injection in LSASS process.",\n'
                        '  "claims": [\n'
                        f'    {{"claim_type": "FACT", "statement": "LSASS injected", "source_finding_id": "{finding_id}"}}\n'
                        "  ]\n"
                        "}"
                    )
                }
            }]
        }
        return httpx.Response(200, json=mock_body)

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = await run_copilot_query(
        case_id=case_id,
        query="Analyze memory dump findings",
        db=db_session,
        provider="openai",
        api_key=MOCK_API_KEY
    )

    assert res.execution_mode == "EXTERNAL_LLM"
    assert res.fallback_used is False
    assert res.provider_status == "SUCCESS"
    assert res.answer == "Identified credential injection in LSASS process."
    assert len(res.claims) == 1
    assert res.claims[0].claim_type == AIClaimType.FACT
    assert res.claims[0].source_finding_id == finding_id


@pytest.mark.asyncio
async def test_run_copilot_query_provider_error_triggers_fallback(monkeypatch, db_session):
    case_id, _, _ = create_sample_case_data(db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(500, json={"error": "Internal Server Error"})

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = await run_copilot_query(
        case_id=case_id,
        query="Analyze memory dump findings",
        db=db_session,
        provider="openai",
        api_key=MOCK_API_KEY
    )

    assert res.execution_mode == "DETERMINISTIC_FALLBACK"
    assert res.fallback_used is True
    assert res.provider_status == "FALLBACK_EXECUTED"


@pytest.mark.asyncio
async def test_run_copilot_query_unparseable_json_triggers_fallback(monkeypatch, db_session):
    case_id, _, _ = create_sample_case_data(db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "Plain text output without JSON"}}]
        })

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = await run_copilot_query(
        case_id=case_id,
        query="Analyze memory dump findings",
        db=db_session,
        provider="openai",
        api_key=MOCK_API_KEY
    )

    assert res.execution_mode == "DETERMINISTIC_FALLBACK"
    assert res.fallback_used is True
    assert res.provider_status == "FALLBACK_EXECUTED"


# -----------------------------------------------------------------------------
# 6. Finding Explanation Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_explain_case_finding_not_found(db_session):
    case_id, finding_id, _ = create_sample_case_data(db_session)
    fake_id = str(uuid.uuid4())

    # Case not found
    with pytest.raises(HTTPException) as exc1:
        await explain_case_finding(fake_id, finding_id, db_session)
    assert exc1.value.status_code == 404

    # Finding not found in case
    with pytest.raises(HTTPException) as exc2:
        await explain_case_finding(case_id, fake_id, db_session)
    assert exc2.value.status_code == 404


@pytest.mark.asyncio
async def test_explain_case_finding_local_stub(db_session):
    case_id, finding_id, _ = create_sample_case_data(db_session)

    res = await explain_case_finding(
        case_id=case_id,
        finding_id=finding_id,
        db=db_session,
        provider="local_stub"
    )

    assert res.finding_id == finding_id
    assert res.execution_mode == "DETERMINISTIC_FALLBACK"
    assert res.fallback_used is True
    assert res.provider_status == "FALLBACK_EXECUTED"
    assert "T1003.001" in res.mitre_techniques


@pytest.mark.asyncio
async def test_explain_case_finding_external_success(monkeypatch, db_session):
    case_id, finding_id, _ = create_sample_case_data(db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(200, json={
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": '{"explanation": "Detailed explanation of T1003.001 LSASS dumping technique."}'
                }
            }]
        })

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = await explain_case_finding(
        case_id=case_id,
        finding_id=finding_id,
        db=db_session,
        provider="openai",
        api_key=MOCK_API_KEY
    )

    assert res.finding_id == finding_id
    assert res.execution_mode == "EXTERNAL_LLM"
    assert res.fallback_used is False
    assert res.provider_status == "SUCCESS"
    assert "LSASS dumping technique" in res.explanation
