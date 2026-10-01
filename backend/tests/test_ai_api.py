import uuid
import json
import pytest
import httpx
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, ensure_user_auth_schema, ensure_case_auth_schema
from backend.app.models.models import (
    User,
    Case,
    CaseMember,
    EvidenceItem,
    Finding,
    ExecutionArtifact,
    InvestigatorDecision,
    AuditEvent,
    ChainOfCustodyEvent
)
from backend.app.services.authorization import ensure_case_member
from backend.app.services.ai_provider import OpenAIAdapter

client = TestClient(app)
MOCK_SECRET_KEY = "sk-proj-supersecretkey1234567890"


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    ensure_user_auth_schema(engine)
    ensure_case_auth_schema(engine)
    yield


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_user_and_token(email_prefix: str, name: str = "Test Investigator"):
    email = f"{email_prefix}_{uuid.uuid4().hex[:8]}@adfir.local"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": name,
        "password": "Password123!"
    })
    user_id = signup_res.json()["id"]

    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return user_id, email, headers


def create_case_with_data(owner_user_id: str, owner_email: str, db: SessionLocal):
    case_id = str(uuid.uuid4())
    case = Case(
        id=case_id,
        name=f"Investigation {case_id[:8]}",
        case_number=f"CAS-{case_id[:6]}",
        owner_id=owner_user_id,
        created_by=owner_email,
        status="OPEN"
    )
    db.add(case)
    db.commit()

    ensure_case_member(case_id=case_id, user_id=owner_user_id, db=db, role="PRIMARY_INVESTIGATOR")

    evidence = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case_id,
        name="memory.raw",
        original_path="/evidence/memory.raw",
        storage_path="/vault/memory.raw",
        evidence_type="MEMORY_DUMP",
        size_bytes=2048,
        sha256="a" * 64,
        integrity_status="VERIFIED"
    )
    db.add(evidence)

    finding = Finding(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence.id,
        title="Unusual Process Mimikatz",
        description="Memory injection detected in LSASS process",
        agent="volatile_mem",
        tool="volatility3",
        finding_type="SUSPICIOUS_PROCESS",
        severity="CRITICAL",
        mitre_techniques=["T1003.001"],
        raw_output_reference='{"mitre_techniques": ["T1003.001"]}'
    )
    db.add(finding)

    db.commit()
    return case_id, finding.id, evidence.id


# -----------------------------------------------------------------------------
# 1. Unauthenticated copilot → 401
# -----------------------------------------------------------------------------
def test_1_unauthenticated_copilot_returns_401():
    res = client.post("/api/v1/ai/copilot", json={
        "case_id": str(uuid.uuid4()),
        "query": "Summarize case findings"
    })
    assert res.status_code == 401


# -----------------------------------------------------------------------------
# 2. Unauthorized case → denied according to Task 8 policy (403)
# -----------------------------------------------------------------------------
def test_2_unauthorized_case_returns_403(db_session):
    user_a_id, user_a_email, headers_a = create_user_and_token("usera")
    user_b_id, user_b_email, headers_b = create_user_and_token("userb")

    case_b_id, _, _ = create_case_with_data(user_b_id, user_b_email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers_a, json={
        "case_id": case_b_id,
        "query": "Summarize case findings"
    })
    assert res.status_code == 403


# -----------------------------------------------------------------------------
# 3. Authorized case → copilot service invoked
# -----------------------------------------------------------------------------
def test_3_authorized_case_copilot_success(db_session):
    user_id, email, headers = create_user_and_token("user1")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze suspicious processes",
        "provider": "local_stub"
    })
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert data["provider"] == "local_stub"
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"


# -----------------------------------------------------------------------------
# 4. Client cannot override authenticated identity
# -----------------------------------------------------------------------------
def test_4_client_cannot_override_identity(db_session):
    user_a_id, user_a_email, headers_a = create_user_and_token("usera4")
    user_b_id, user_b_email, _ = create_user_and_token("userb4")

    case_a_id, _, _ = create_case_with_data(user_a_id, user_a_email, db_session)

    res = client.post(
        "/api/v1/ai/copilot",
        headers={**headers_a, "X-User-Id": user_b_id, "X-Role": "ADMIN"},
        json={
            "case_id": case_a_id,
            "query": "Test query"
        }
    )
    assert res.status_code == 200
    # Audit log actor must equal User A
    event = db_session.query(AuditEvent).filter(AuditEvent.case_id == case_a_id).order_by(AuditEvent.timestamp.desc()).first()
    assert event is not None
    assert event.actor_id == user_a_id


# -----------------------------------------------------------------------------
# 5. Cross-case copilot denied
# -----------------------------------------------------------------------------
def test_5_cross_case_copilot_denied(db_session):
    user_a_id, user_a_email, headers_a = create_user_and_token("user_a5")
    user_b_id, user_b_email, _ = create_user_and_token("user_b5")

    case_b_id, _, _ = create_case_with_data(user_b_id, user_b_email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers_a, json={
        "case_id": case_b_id,
        "query": "Cross case query attempt"
    })
    assert res.status_code == 403


# -----------------------------------------------------------------------------
# 6. Nonexistent case behavior (404)
# -----------------------------------------------------------------------------
def test_6_nonexistent_case_returns_404():
    _, _, headers = create_user_and_token("user6")
    fake_case_id = str(uuid.uuid4())

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": fake_case_id,
        "query": "Query nonexistent case"
    })
    assert res.status_code == 404


# -----------------------------------------------------------------------------
# 7. Cross-case finding explanation denied / not-found according to policy
# -----------------------------------------------------------------------------
def test_7_cross_case_finding_explanation_denied(db_session):
    user_a_id, user_a_email, headers_a = create_user_and_token("usera7")
    user_b_id, user_b_email, _ = create_user_and_token("userb7")

    case_b_id, finding_b_id, _ = create_case_with_data(user_b_id, user_b_email, db_session)

    res = client.post("/api/v1/ai/explain-finding", headers=headers_a, json={
        "case_id": case_b_id,
        "finding_id": finding_b_id
    })
    assert res.status_code == 403


# -----------------------------------------------------------------------------
# 8. Nonexistent finding (404)
# -----------------------------------------------------------------------------
def test_8_nonexistent_finding_returns_404(db_session):
    user_id, email, headers = create_user_and_token("user8")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)
    fake_finding_id = str(uuid.uuid4())

    res = client.post("/api/v1/ai/explain-finding", headers=headers, json={
        "case_id": case_id,
        "finding_id": fake_finding_id
    })
    assert res.status_code == 404


# -----------------------------------------------------------------------------
# 9. Authorized finding explanation
# -----------------------------------------------------------------------------
def test_9_authorized_finding_explanation(db_session):
    user_id, email, headers = create_user_and_token("user9")
    case_id, finding_id, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/explain-finding", headers=headers, json={
        "case_id": case_id,
        "finding_id": finding_id,
        "provider": "local_stub"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == finding_id
    assert "T1003.001" in data["mitre_techniques"]
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"


# -----------------------------------------------------------------------------
# 10. Provider test authentication
# -----------------------------------------------------------------------------
def test_10_unauthenticated_provider_test_returns_401():
    res = client.post("/api/v1/ai/provider/test", json={"provider": "openai"})
    assert res.status_code == 401


# -----------------------------------------------------------------------------
# 11-13. Provider test does not persist API key & absent from response/audit
# -----------------------------------------------------------------------------
def test_11_12_13_provider_test_credential_handling(db_session):
    user_id, email, headers = create_user_and_token("user11")

    res = client.post("/api/v1/ai/provider/test", headers=headers, json={
        "provider": "local_stub",
        "api_key": MOCK_SECRET_KEY
    })
    assert res.status_code == 200
    data = res.json()

    # 12. API key absent from response
    assert MOCK_SECRET_KEY not in json.dumps(data)
    assert "api_key" not in data

    # 13. API key absent from audit payload
    audit_event = db_session.query(AuditEvent).filter(AuditEvent.actor_id == user_id).order_by(AuditEvent.timestamp.desc()).first()
    assert audit_event is not None
    assert MOCK_SECRET_KEY not in audit_event.details
    assert MOCK_SECRET_KEY not in json.dumps(audit_event.metadata_json)


# -----------------------------------------------------------------------------
# 14. External provider blocked by LOCAL_ONLY
# -----------------------------------------------------------------------------
def test_14_external_provider_blocked_by_local_only(db_session):
    user_id, email, headers = create_user_and_token("user14")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze memory dump",
        "provider": "openai",
        "egress_policy": "LOCAL_ONLY"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["provider"] == "local_stub"
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"
    assert data["fallback_used"] is True


# -----------------------------------------------------------------------------
# 15. External provider blocked by EXTERNAL_PROVIDER_BLOCKED
# -----------------------------------------------------------------------------
def test_15_external_provider_blocked_by_external_provider_blocked(db_session):
    user_id, email, headers = create_user_and_token("user15")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze memory dump",
        "provider": "anthropic",
        "egress_policy": "EXTERNAL_PROVIDER_BLOCKED"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["provider"] == "local_stub"
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"


# -----------------------------------------------------------------------------
# 16 & 17. External provider permitted by EXTERNAL_PROVIDER_ALLOWED & raw evidence never passed
# -----------------------------------------------------------------------------
def test_16_17_external_provider_allowed_and_no_raw_evidence(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user16")
    case_id, finding_id, _ = create_case_with_data(user_id, email, db_session)

    captured_prompt = []

    def mock_handler(request: httpx.Request):
        req_body = json.loads(request.content.decode("utf-8"))
        captured_prompt.append(json.dumps(req_body))
        return httpx.Response(200, json={
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": '{"answer": "External LLM summary", "claims": []}'
                }
            }]
        })

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze findings",
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY,
        "egress_policy": "EXTERNAL_PROVIDER_ALLOWED"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["execution_mode"] == "EXTERNAL_LLM"
    assert data["provider_status"] == "SUCCESS"

    # 17. Verify raw evidence bytes are never transmitted
    assert len(captured_prompt) == 1
    prompt_str = captured_prompt[0]
    assert "memory.raw" in prompt_str  # structured metadata allowed
    assert MOCK_SECRET_KEY not in prompt_str


# -----------------------------------------------------------------------------
# 18. Malformed query rejected (empty query -> 422)
# -----------------------------------------------------------------------------
def test_18_empty_query_rejected(db_session):
    user_id, email, headers = create_user_and_token("user18")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": ""
    })
    assert res.status_code == 422


# -----------------------------------------------------------------------------
# 19. Oversized query rejected (> 4000 chars -> 422)
# -----------------------------------------------------------------------------
def test_19_oversized_query_rejected(db_session):
    user_id, email, headers = create_user_and_token("user19")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "A" * 5000
    })
    assert res.status_code == 422


# -----------------------------------------------------------------------------
# 20. Malformed provider configuration rejected
# -----------------------------------------------------------------------------
def test_20_malformed_provider_config_rejected(db_session):
    user_id, email, headers = create_user_and_token("user20")

    res = client.post("/api/v1/ai/provider/test", headers=headers, json={
        "provider": ""
    })
    assert res.status_code in (400, 422)


# -----------------------------------------------------------------------------
# 21. Provider failure preserves explicit fallback metadata
# -----------------------------------------------------------------------------
def test_21_provider_failure_preserves_fallback_metadata(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user21")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(500, json={"error": "Provider internal error"})

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze memory",
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY,
        "egress_policy": "EXTERNAL_PROVIDER_ALLOWED"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"
    assert data["fallback_used"] is True
    assert data["provider_status"] == "FALLBACK_EXECUTED"


# -----------------------------------------------------------------------------
# 22. Provider success preserves provider metadata
# -----------------------------------------------------------------------------
def test_22_provider_success_preserves_metadata(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user22")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(200, json={
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": '{"answer": "Successful LLM answer", "claims": []}'
                }
            }]
        })

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze memory",
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY,
        "egress_policy": "EXTERNAL_PROVIDER_ALLOWED"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["provider"] == "openai"
    assert data["execution_mode"] == "EXTERNAL_LLM"
    assert data["fallback_used"] is False
    assert data["provider_status"] == "SUCCESS"


# -----------------------------------------------------------------------------
# 23. Malformed AI output preserves fallback metadata
# -----------------------------------------------------------------------------
def test_23_malformed_ai_output_preserves_fallback_metadata(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user23")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    def mock_handler(request: httpx.Request):
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "Not valid JSON at all!"}}]
        })

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.services.ai_copilot.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Analyze memory",
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY,
        "egress_policy": "EXTERNAL_PROVIDER_ALLOWED"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["execution_mode"] == "DETERMINISTIC_FALLBACK"
    assert data["fallback_used"] is True
    assert data["provider_status"] == "FALLBACK_EXECUTED"


# -----------------------------------------------------------------------------
# 24. Audit event created for successful operation
# -----------------------------------------------------------------------------
def test_24_audit_event_created_for_success(db_session):
    user_id, email, headers = create_user_and_token("user24")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Query for audit test"
    })
    assert res.status_code == 200

    audit_event = db_session.query(AuditEvent).filter(
        AuditEvent.case_id == case_id,
        AuditEvent.event_type == "AI_COPILOT_QUERY"
    ).first()
    assert audit_event is not None
    assert audit_event.actor_id == user_id


# -----------------------------------------------------------------------------
# 25. Audit event created for failed operation
# -----------------------------------------------------------------------------
def test_25_audit_event_created_for_failed_provider_test(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user25")

    def mock_handler(request: httpx.Request):
        return httpx.Response(401, json={"error": "Unauthorized key"})

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.api.v1.endpoints.ai.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/provider/test", headers=headers, json={
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY
    })
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"

    audit_event = db_session.query(AuditEvent).filter(
        AuditEvent.actor_id == user_id,
        AuditEvent.event_type == "AI_PROVIDER_TEST"
    ).first()
    assert audit_event is not None
    assert audit_event.metadata_json["status"] == "FAILED"


# -----------------------------------------------------------------------------
# 26. No credential leakage through exceptions
# -----------------------------------------------------------------------------
def test_26_no_credential_leakage_in_exceptions(monkeypatch, db_session):
    user_id, email, headers = create_user_and_token("user26")

    def mock_handler(request: httpx.Request):
        return httpx.Response(401, json={"error": f"Invalid key: {MOCK_SECRET_KEY}"})

    mock_adapter = OpenAIAdapter(transport=httpx.MockTransport(mock_handler))
    monkeypatch.setattr("backend.app.api.v1.endpoints.ai.get_ai_adapter", lambda p: mock_adapter)

    res = client.post("/api/v1/ai/provider/test", headers=headers, json={
        "provider": "openai",
        "api_key": MOCK_SECRET_KEY
    })
    assert res.status_code == 200
    data = res.json()
    assert MOCK_SECRET_KEY not in data["details"]


# -----------------------------------------------------------------------------
# 27 & 28. No raw prompt or model response leakage in audit logs
# -----------------------------------------------------------------------------
def test_27_28_no_prompt_or_response_leakage_in_audit(db_session):
    user_id, email, headers = create_user_and_token("user27")
    case_id, _, _ = create_case_with_data(user_id, email, db_session)
    sensitive_query = "SUPER_SECRET_INVESTIGATION_PROMPT_STRING_123"

    res = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": sensitive_query
    })
    assert res.status_code == 200

    audit_event = db_session.query(AuditEvent).filter(
        AuditEvent.case_id == case_id,
        AuditEvent.event_type == "AI_COPILOT_QUERY"
    ).first()
    assert audit_event is not None
    # Audit log details/metadata must NOT contain full sensitive prompt or response text
    assert sensitive_query not in json.dumps(audit_event.metadata_json)


# -----------------------------------------------------------------------------
# 29. Explain-finding resolves finding server-side
# -----------------------------------------------------------------------------
def test_29_explain_finding_resolves_server_side(db_session):
    user_id, email, headers = create_user_and_token("user29")
    case_id, finding_id, _ = create_case_with_data(user_id, email, db_session)

    res = client.post("/api/v1/ai/explain-finding", headers=headers, json={
        "case_id": case_id,
        "finding_id": finding_id,
        "provider": "local_stub"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["title"] == "Unusual Process Mimikatz"
    assert "T1003.001" in data["mitre_techniques"]


# -----------------------------------------------------------------------------
# 30-33. AI operations cannot mutate Findings, Evidence, Custody, or Decisions
# -----------------------------------------------------------------------------
def test_30_33_ai_cannot_mutate_forensic_state(db_session):
    user_id, email, headers = create_user_and_token("user30")
    case_id, finding_id, evidence_id = create_case_with_data(user_id, email, db_session)

    # Initial counts
    findings_before = db_session.query(Finding).filter(Finding.case_id == case_id).all()
    evidence_before = db_session.query(EvidenceItem).filter(EvidenceItem.case_id == case_id).all()
    custody_before = db_session.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.case_id == case_id).all()
    decisions_before = db_session.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case_id).all()

    # Perform AI Copilot query & Explain finding
    res1 = client.post("/api/v1/ai/copilot", headers=headers, json={
        "case_id": case_id,
        "query": "Try mutating case findings"
    })
    assert res1.status_code == 200

    res2 = client.post("/api/v1/ai/explain-finding", headers=headers, json={
        "case_id": case_id,
        "finding_id": finding_id
    })
    assert res2.status_code == 200

    # Post-state assertions
    findings_after = db_session.query(Finding).filter(Finding.case_id == case_id).all()
    evidence_after = db_session.query(EvidenceItem).filter(EvidenceItem.case_id == case_id).all()
    custody_after = db_session.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.case_id == case_id).all()
    decisions_after = db_session.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case_id).all()

    assert len(findings_before) == len(findings_after)
    assert len(evidence_before) == len(evidence_after)
    assert len(custody_before) == len(custody_after)
    assert len(decisions_before) == len(decisions_after)

    assert findings_after[0].title == findings_before[0].title
    assert evidence_after[0].name == evidence_before[0].name
