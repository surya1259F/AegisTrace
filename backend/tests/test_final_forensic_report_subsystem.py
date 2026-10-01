"""
ADFIR — Phase 2 / Step 20: Final Forensic Report Subsystem Tests

Comprehensive tests verifying:
1. Generation of evidence-grounded, versioned final forensic reports with all 12 sections.
2. Evidence grounding: Claims reference supporting evidence/artifacts; FACT/INFERENCE/UNVERIFIED classification preserved.
3. Unsupported claims handling: Ungrounded statements marked UNVERIFIED and tallied in verification metrics.
4. Complete multi-tier provenance lineage trace:
   Evidence -> Execution -> Output -> Artifact -> Normalized Artifact -> Timeline/Correlation -> Finding -> AI Reasoning -> Review -> Report.
5. Cryptographic integrity: SHA-256 hash preservation, canonical report digest, and tamper detection.
6. Chain of custody preservation and inclusion in final report.
7. Investigator decisions preservation: ACCEPT, CHALLENGE, and REJECT with investigator rationale and timestamps.
8. Report versioning: Sequential version incrementing, version listing, and latest/historical snapshot retrieval.
9. Case isolation, RBAC, and cross-case IDOR protection (403 Forbidden on unauthorized access).
10. Integrity verification API: Clean verification vs. tampered detection.
11. Export API: Validated markdown and JSON downloads.
"""

import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm.attributes import flag_modified

from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import (
    Case,
    CaseMember,
    User,
    EvidenceItem,
    ChainOfCustodyEvent,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    TimelineEvent,
    ArtifactRelationship,
    ForensicCorrelationGroup,
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    Report,
    AuditEvent
)
from backend.app.schemas.schemas import ForensicReportGenerateRequest
from backend.app.services.final_report import (
    FinalForensicReportService,
    compute_canonical_json_hash
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="rep_usr", case_prefix="rep_case"):
    """Creates an investigator user and an authorized case."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{username_prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Forensic Investigator {username_prefix}",
        organization="DFIR Reporting Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("ReportPass@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-rep-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing final forensic report subsystem",
        created_by=user.id,
        owner_id=user.id,
        status="ACTIVE"
    )
    db.add(case)
    db.commit()

    member = CaseMember(
        id=str(uuid.uuid4()),
        case_id=case.id,
        user_id=user.id,
        role="PRIMARY_INVESTIGATOR"
    )
    db.add(member)
    db.commit()
    db.refresh(case)
    db.refresh(user)
    return user, case


def get_auth_headers(user: User) -> dict:
    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    return {"Authorization": f"Bearer {token}"}


def populate_case_forensic_pipeline(db, case, user) -> Dict[str, Any]:
    """Populates structured evidence, executions, artifacts, timeline, correlations, findings, reasoning, and reviews."""
    # 1. Evidence Item
    ev_hash = "a" * 64
    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigation_id=case.id,
        name="server_disk_image.raw",
        evidence_type="disk_image",
        source_kind="DISK_IMAGE",
        original_path="/raw/server_disk_image.raw",
        storage_path="/vault/secure/server_disk_image.raw",
        sha256_hash=ev_hash,
        size_bytes=524288,
        status="ACQUIRED",
        read_only_verified=True
    )
    db.add(ev)
    db.commit()

    # Chain of Custody
    ce = ChainOfCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=ev.id,
        case_id=case.id,
        event_type="ACQUISITION_VERIFIED",
        actor_id=user.id,
        actor=user.name,
        description="Evidence acquired with SHA-256 preservation verification: Bit-stream image verified against hardware write-blocker",
        sha256=ev_hash,
        event_hash="e1" * 32,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(ce)
    db.commit()

    # 2. Tool Execution & Output
    fe = ForensicExecution(
        id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        task_key="DISK_PARSING",
        tool_id="sleuthkit",
        tool_version="4.12.0",
        executable_path="/usr/bin/fls",
        validated_argv=["/usr/bin/fls", "-r", ev.original_path],
        host_platform="Linux",
        host_architecture="x86_64",
        workspace_path="/tmp/workspace",
        execution_status="COMPLETED",
        exit_code=0
    )
    db.add(fe)
    db.commit()

    exo = ExecutionOutput(
        id=str(uuid.uuid4()),
        case_id=case.id,
        execution_id=fe.id,
        request_id=fe.request_id,
        evidence_id=ev.id,
        tool_id="sleuthkit",
        output_type="TOOL_OUTPUT",
        filename="fls_output.json",
        relative_path="outputs/fls_output.json",
        storage_path="/tmp/fls_output.json",
        sha256_hash="b" * 64
    )
    db.add(exo)
    db.commit()

    # 3. Structured & Normalized Artifacts
    art = StructuredArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        execution_id=fe.id,
        raw_output_id=exo.id,
        evidence_id=ev.id,
        parser_name="fls_parser",
        parser_version="1.0.0",
        artifact_type="PERSISTENCE_CRON",
        source_reference="/etc/cron.d/persistence_job",
        normalized_data={"command": "/usr/local/bin/mal_agent", "schedule": "@reboot"},
        raw_record="@reboot /usr/local/bin/mal_agent",
        sha256_hash="c" * 64,
        source_raw_output_hash=exo.sha256_hash,
        extraction_status="EXTRACTED",
        created_at=datetime.now(timezone.utc)
    )
    db.add(art)
    db.commit()

    norm_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=art.id,
        entity_type="SCHEDULED_TASK",
        entity_identity="TASK:persistence_job",
        normalized_fields={"job_name": "persistence_job", "binary": "/usr/local/bin/mal_agent"},
        evidence_reference={"id": ev.id, "name": ev.name},
        provenance_summary={"tool_id": "sleuthkit"},
        occurrence_count=1,
        sha256_hash="d" * 64,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db.add(norm_art)
    db.commit()

    # 4. Timeline Event
    te = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        normalized_artifact_id=norm_art.id,
        structured_artifact_id=art.id,
        timestamp_utc=datetime.now(timezone.utc),
        original_timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="CRON_MODIFIED",
        event_source="FLS",
        event_data={"description": "Cron persistence job created under /etc/cron.d"},
        confidence_score=0.95,
        sha256_hash="e" * 64,
        source_artifact_hash=norm_art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db.add(te)
    db.commit()

    # 5. Correlation Group
    cg = ForensicCorrelationGroup(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Persistence via Crontab Execution",
        description="Correlated execution of unauthorized binary /usr/local/bin/mal_agent via cron",
        member_artifact_ids=[art.id],
        member_event_ids=[te.id],
        relationship_ids=[],
        contributing_domains=["PERSISTENCE_MECHANISM"],
        source_evidence_ids=[ev.id],
        confidence_score=0.92,
        provenance={"rule": "R-CRON-STARTUP-01"},
        sha256_hash="f" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db.add(cg)
    db.commit()

    # 6. Deterministic Findings
    finding_1 = DeterministicFinding(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Unauthorized Cron Persistence Binary Detected",
        description="A periodic crontab task executing an unauthorized binary was detected.",
        observed_facts=[{"field": "command", "observed": "@reboot /usr/local/bin/mal_agent"}],
        finding_type="persistence_mechanism",
        severity="HIGH",
        severity_rule="RULE-PERSIST-001",
        confidence=0.95,
        confidence_inputs={"artifact_confidence": 0.95, "rule_weight": 0.9},
        supporting_artifact_ids=[art.id],
        supporting_event_ids=[te.id],
        supporting_relationship_ids=[],
        supporting_group_ids=[cg.id],
        supporting_evidence_ids=[ev.id],
        provenance={"rule_engine": "ADFIR_Deterministic_V1"},
        sha256_hash="f" * 64,
        created_at=datetime.now(timezone.utc)
    )
    finding_1.verification_status = "SUPPORTED"
    finding_1.mitre_techniques = ["T1053.003"]
    db.add(finding_1)

    # Finding 2: Ungrounded finding to verify unsupported claims handling
    finding_ungrounded = DeterministicFinding(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Potential Network Exfiltration Observed (Speculative)",
        description="Speculative network exfiltration without confirmed artifacts.",
        observed_facts=[],
        finding_type="network_exfiltration",
        severity="LOW",
        severity_rule="RULE-SPEC-002",
        confidence=0.40,
        confidence_inputs={"speculative": True},
        supporting_artifact_ids=[],
        supporting_event_ids=[],
        supporting_relationship_ids=[],
        supporting_group_ids=[],
        supporting_evidence_ids=[],
        provenance={"rule_engine": "ADFIR_Deterministic_V1"},
        sha256_hash="0" * 64,
        created_at=datetime.now(timezone.utc)
    )
    finding_ungrounded.verification_status = "UNVERIFIED"
    finding_ungrounded.mitre_techniques = ["T1041"]
    db.add(finding_ungrounded)
    db.commit()

    # 7. Governed AI Reasoning Record
    air = AIReasoningRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        objective="Analyze attack persistence chain",
        execution_mode="DETERMINISTIC_FALLBACK",
        provider="local_stub",
        model="gpt-4o-mini-deterministic",
        input_references={"finding_ids": [finding_1.id], "evidence_ids": [ev.id]},
        statements=[
            {
                "statement_id": "stmt-001",
                "insight": "The cron job executes an unauthorized binary at system startup.",
                "classification": "FACT",
                "confidence": 0.95,
                "supporting_evidence_ids": [ev.id],
                "supporting_artifact_ids": [art.id],
                "citations_verified": True
            },
            {
                "statement_id": "stmt-002",
                "insight": "Attacker likely maintained access via SSH key injection elsewhere.",
                "classification": "INFERENCE",
                "confidence": 0.65,
                "supporting_evidence_ids": [ev.id],
                "supporting_artifact_ids": [art.id],
                "citations_verified": True
            },
            {
                "statement_id": "stmt-003",
                "insight": "External command and control server resides at 198.51.100.24 without network traces.",
                "classification": "UNVERIFIED",
                "confidence": 0.30,
                "supporting_evidence_ids": [],
                "supporting_artifact_ids": [],
                "citations_verified": False
            }
        ],
        sha256_hash="e" * 64
    )
    db.add(air)
    db.commit()

    # 8. Investigator Reviews
    rev_accept = InvestigatorReviewRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigator_id=user.id,
        investigator_name=user.name,
        target_type="FINDING",
        target_id=finding_1.id,
        decision="ACCEPT",
        comment="Corroborated by filesystem inode timestamp and crontab entry.",
        supporting_references=[art.id, ev.id],
        resulting_workflow_action="ACCEPTED_CLAIM",
        sha256_hash="11" * 32
    )
    db.add(rev_accept)

    rev_reject = InvestigatorReviewRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigator_id=user.id,
        investigator_name=user.name,
        target_type="AI_REASONING",
        target_id=air.id,
        statement_id="stmt-003",
        decision="REJECT",
        comment="No network telemetry or PCAP exists for 198.51.100.24. Claim rejected.",
        supporting_references=[],
        resulting_workflow_action="REJECTED_CLAIM",
        sha256_hash="22" * 32
    )
    db.add(rev_reject)
    db.commit()

    return {
        "evidence": ev,
        "execution": fe,
        "structured_artifact": art,
        "normalized_artifact": norm_art,
        "timeline_event": te,
        "correlation_group": cg,
        "finding_1": finding_1,
        "finding_ungrounded": finding_ungrounded,
        "ai_reasoning": air,
        "rev_accept": rev_accept,
        "rev_reject": rev_reject
    }


# =============================================================================
# TEST CASES
# =============================================================================

def test_generate_final_forensic_report_all_12_sections(db_session):
    """
    Test 1: Verify synthesis of Final Forensic Report containing all 12 required sections.
    """
    user, case = create_test_user_and_case(db_session, "sec_usr", "sec_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(
        f"/api/v1/cases/{case.id}/reports/generate",
        headers=headers,
        json={"title": "Official Test Incident Report"}
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case.id
    assert data["version"] == 1
    assert data["status"] == "OFFICIAL_FINAL"
    assert "report_hash" in data and len(data["report_hash"]) == 64
    assert data["report_hash"] == data["sha256_hash"]

    # Verify all 12 sections are present and non-empty
    sections = data["sections"]
    expected_sections = [
        "case_information",
        "evidence_inventory",
        "hashes_preservation",
        "chain_of_custody",
        "tool_executions",
        "artifacts",
        "timeline",
        "correlations",
        "findings",
        "confidence_verification",
        "investigator_decisions",
        "explainability_provenance"
    ]
    for sec_name in expected_sections:
        assert sec_name in sections, f"Missing section: {sec_name}"

    assert sections["case_information"]["case_id"] == case.id
    assert len(sections["evidence_inventory"]) >= 1
    assert len(sections["hashes_preservation"]) >= 1
    assert len(sections["chain_of_custody"]) >= 1
    assert len(sections["tool_executions"]) >= 1
    assert sections["artifacts"]["structured_count"] >= 1
    assert len(sections["timeline"]) >= 1
    assert sections["correlations"]["groups_count"] >= 1
    assert sections["findings"]["total_findings"] >= 2
    assert "overall_integrity_status" in sections["confidence_verification"]
    assert sections["investigator_decisions"]["total_reviews"] >= 2
    assert "pipeline_trace" in sections["explainability_provenance"]


def test_evidence_grounded_claims_and_classifications(db_session):
    """
    Test 2: Verify every claim references supporting evidence/artifacts and preserves FACT/INFERENCE/UNVERIFIED.
    """
    user, case = create_test_user_and_case(db_session, "ground_usr", "ground_case")
    headers = get_auth_headers(user)
    pipeline_data = populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert res.status_code == 200
    data = res.json()
    items = data["sections"]["findings"]["items"]

    # Check deterministic finding classification
    det_item = next(i for i in items if i["id"] == pipeline_data["finding_1"].id)
    assert det_item["classification"] == "FACT"
    assert det_item["is_grounded"] is True
    assert pipeline_data["evidence"].id in det_item["supporting_evidence_ids"]
    assert pipeline_data["structured_artifact"].id in det_item["supporting_artifact_ids"]

    # Check AI reasoning statements classifications
    ai_fact = next(i for i in items if "stmt-001" in i["id"])
    assert ai_fact["classification"] == "FACT"
    assert ai_fact["is_grounded"] is True

    ai_inference = next(i for i in items if "stmt-002" in i["id"])
    assert ai_inference["classification"] == "INFERENCE"
    assert ai_inference["is_grounded"] is True


def test_unsupported_claim_handling(db_session):
    """
    Test 3: Unsupported or ungrounded claims must be explicitly marked UNVERIFIED.
    """
    user, case = create_test_user_and_case(db_session, "unsupp_usr", "unsupp_case")
    headers = get_auth_headers(user)
    pipeline_data = populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert res.status_code == 200
    data = res.json()
    items = data["sections"]["findings"]["items"]

    # Check ungrounded deterministic finding
    ungrounded_f = next(i for i in items if i["id"] == pipeline_data["finding_ungrounded"].id)
    assert ungrounded_f["is_grounded"] is False
    assert ungrounded_f["verification_status"] == "UNVERIFIED"

    # Check ungrounded AI statement
    unsupp_ai = next(i for i in items if "stmt-003" in i["id"])
    assert unsupp_ai["is_grounded"] is False
    assert unsupp_ai["classification"] == "UNVERIFIED"
    assert unsupp_ai["verification_status"] == "UNVERIFIED"

    # Check confidence verification count
    conf_ver = data["sections"]["confidence_verification"]
    assert conf_ver["unsupported_claims_count"] >= 2


def test_provenance_full_lineage(db_session):
    """
    Test 4: Verify complete lineage: Evidence -> Execution -> Output -> Artifact -> Normalized -> Timeline/Correlation -> Finding -> AI -> Review -> Report.
    """
    user, case = create_test_user_and_case(db_session, "prov_usr", "prov_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    gen_res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert gen_res.status_code == 200
    report_id = gen_res.json()["id"]

    prov_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/provenance", headers=headers)
    assert prov_res.status_code == 200
    prov_data = prov_res.json()

    assert prov_data["report_id"] == report_id
    assert prov_data["version"] == 1
    assert "graph" in prov_data
    assert "pipeline" in prov_data["graph"]
    assert len(prov_data["lineage"]) >= 4

    # Verify node counts
    assert prov_data["node_counts"]["evidence"] >= 1
    assert prov_data["node_counts"]["executions"] >= 1
    assert prov_data["node_counts"]["findings"] >= 2
    assert prov_data["node_counts"]["reviews"] >= 2


def test_hashes_and_evidence_integrity_verification(db_session):
    """
    Test 5: Verify evidence hashes, inclusion in report sections, and canonical report SHA-256.
    """
    user, case = create_test_user_and_case(db_session, "hash_usr", "hash_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert res.status_code == 200
    data = res.json()

    # Report SHA-256
    report_hash = data["report_hash"]
    assert len(report_hash) == 64
    assert report_hash == compute_canonical_json_hash(data["sections"])

    # Evidence hashes preservation
    hashes = data["sections"]["hashes_preservation"]
    assert len(hashes) >= 1
    for h in hashes:
        assert len(h["registered_sha256"]) == 64
        assert h["integrity_status"] in ["VERIFIED", "INTEGRITY_WARNING", "UNCHECKED"]


def test_chain_of_custody_inclusion(db_session):
    """
    Test 6: Verify chain-of-custody chronological logs with actor, action, timestamp, and hash.
    """
    user, case = create_test_user_and_case(db_session, "cust_usr", "cust_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert res.status_code == 200
    custody = res.json()["sections"]["chain_of_custody"]

    assert len(custody) >= 1
    assert custody[0]["action"] == "ACQUISITION_VERIFIED"
    assert custody[0]["actor"] == user.name
    assert custody[0]["timestamp"] is not None
    assert len(custody[0]["event_hash"]) > 0


def test_investigator_decisions_preservation(db_session):
    """
    Test 7: Verify accepted, challenged, and rejected investigator decisions are preserved and displayed with rationale.
    """
    user, case = create_test_user_and_case(db_session, "dec_usr", "dec_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={})
    assert res.status_code == 200
    data = res.json()
    dec_sec = data["sections"]["investigator_decisions"]

    assert dec_sec["accepted_count"] >= 1
    assert dec_sec["rejected_count"] >= 1
    assert dec_sec["total_reviews"] >= 2

    # Check that rejected claim is visibly distinguished
    items = data["sections"]["findings"]["items"]
    rejected_item = next(i for i in items if i["investigator_decision"] == "REJECT")
    assert rejected_item["investigator_decision"] == "REJECT"
    assert "No network telemetry" in rejected_item["investigator_rationale"]

    # Verify markdown highlights rejected decision
    md = data["full_report_markdown"]
    assert "REJECTED BY INVESTIGATOR" in md
    assert "ACCEPTED" in md


def test_report_versioning(db_session):
    """
    Test 8: Verify sequential versioning, version list, latest report, and historical snapshot retrieval.
    """
    user, case = create_test_user_and_case(db_session, "ver_usr", "ver_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    # 1. Generate Version 1
    v1_res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={"title": "Report v1"})
    assert v1_res.status_code == 200
    v1_data = v1_res.json()
    assert v1_data["version"] == 1
    v1_id = v1_data["id"]

    # 2. Generate Version 2
    v2_res = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={"title": "Report v2"})
    assert v2_res.status_code == 200
    v2_data = v2_res.json()
    assert v2_data["version"] == 2
    v2_id = v2_data["id"]
    assert v1_id != v2_id

    # 3. List versions: ordered version descending
    list_res = client.get(f"/api/v1/cases/{case.id}/reports", headers=headers)
    assert list_res.status_code == 200
    versions = list_res.json()
    assert len(versions) == 2
    assert versions[0]["version"] == 2
    assert versions[1]["version"] == 1

    # 4. Get latest version
    latest_res = client.get(f"/api/v1/cases/{case.id}/reports/latest", headers=headers)
    assert latest_res.status_code == 200
    assert latest_res.json()["version"] == 2

    # 5. Retrieve historical v1 directly
    get_v1_res = client.get(f"/api/v1/cases/{case.id}/reports/{v1_id}", headers=headers)
    assert get_v1_res.status_code == 200
    assert get_v1_res.json()["version"] == 1


def test_case_isolation_and_cross_case_idor_protection(db_session):
    """
    Test 9: Case isolation and IDOR protection: User A cannot generate, view, list, verify, or export reports for Case B.
    """
    user_a, case_a = create_test_user_and_case(db_session, "usr_a", "case_a")
    user_b, case_b = create_test_user_and_case(db_session, "usr_b", "case_b")
    headers_a = get_auth_headers(user_a)
    headers_b = get_auth_headers(user_b)
    populate_case_forensic_pipeline(db_session, case_b, user_b)

    # User B generates report on Case B
    rep_b = client.post(f"/api/v1/cases/{case_b.id}/reports/generate", headers=headers_b, json={}).json()
    report_b_id = rep_b["id"]

    # 1. User A tries to generate report on Case B -> 403 Forbidden
    res = client.post(f"/api/v1/cases/{case_b.id}/reports/generate", headers=headers_a, json={})
    assert res.status_code == 403

    # 2. User A tries to list reports for Case B -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports", headers=headers_a)
    assert res.status_code == 403

    # 3. User A tries to get latest report for Case B -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports/latest", headers=headers_a)
    assert res.status_code == 403

    # 4. User A tries to get report by ID for Case B -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports/{report_b_id}", headers=headers_a)
    assert res.status_code == 403

    # 5. User A tries to verify integrity of Case B report -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports/{report_b_id}/integrity", headers=headers_a)
    assert res.status_code == 403

    # 6. User A tries to view provenance for Case B report -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports/{report_b_id}/provenance", headers=headers_a)
    assert res.status_code == 403

    # 7. User A tries to export Case B report -> 403 Forbidden
    res = client.get(f"/api/v1/cases/{case_b.id}/reports/{report_b_id}/export", headers=headers_a)
    assert res.status_code == 403


def test_report_integrity_verification_and_tamper_detection(db_session):
    """
    Test 10: Verify report integrity endpoint detects clean state and flags tampering.
    """
    user, case = create_test_user_and_case(db_session, "int_usr", "int_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    # 1. Clean verification
    rep = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={}).json()
    report_id = rep["id"]

    clean_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/integrity", headers=headers)
    assert clean_res.status_code == 200
    clean_data = clean_res.json()
    assert clean_data["integrity_status"] == "VERIFIED"
    assert clean_data["tamper_detected"] is False

    # 2. Tampering test: Modify persisted sections in database
    db_report = db_session.query(Report).filter(Report.id == report_id).first()
    tampered_sections = dict(db_report.sections)
    tampered_sections["findings"]["items"].append({
        "id": "tampered-finding",
        "title": "Fabricated finding injected by unauthorized actor",
        "severity": "CRITICAL"
    })
    db_report.sections = tampered_sections
    flag_modified(db_report, "sections")
    db_session.commit()

    tampered_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/integrity", headers=headers)
    assert tampered_res.status_code == 200
    tampered_data = tampered_res.json()
    assert tampered_data["integrity_status"] == "TAMPERED"
    assert tampered_data["tamper_detected"] is True
    assert tampered_data["computed_hash"] != tampered_data["expected_hash"]


def test_report_export_markdown_and_json(db_session):
    """
    Test 11: Verify report download/export endpoints for markdown and JSON formats.
    """
    user, case = create_test_user_and_case(db_session, "exp_usr", "exp_case")
    headers = get_auth_headers(user)
    populate_case_forensic_pipeline(db_session, case, user)

    rep = client.post(f"/api/v1/cases/{case.id}/reports/generate", headers=headers, json={}).json()
    report_id = rep["id"]

    # 1. Export as Markdown
    md_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/export?format=markdown", headers=headers)
    assert md_res.status_code == 200
    assert "text/markdown" in md_res.headers.get("content-type", "")
    assert "ADFIR OFFICIAL FINAL FORENSIC REPORT" in md_res.text
    assert "SECTION 1: CASE INFORMATION" in md_res.text
    assert "attachment;" in md_res.headers.get("content-disposition", "")

    # 2. Export as JSON
    json_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/export?format=json", headers=headers)
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers.get("content-type", "")
    data = json.loads(json_res.text)
    assert data["id"] == report_id
    assert "sections" in data
    assert "provenance" in data
    assert "report_hash" in data
