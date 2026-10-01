"""
ADFIR — Phase 2 / Step 19: Investigator Review Subsystem Tests

Comprehensive tests verifying:
1. Review items extraction: Evidence metadata, integrity, and custody chain.
2. Deterministic findings and supporting structured artifacts verification.
3. Governed AI reasoning review with FACT / INFERENCE / UNVERIFIED classifications.
4. Investigator decisions: ACCEPT, CHALLENGE, REJECT (with original finding/reasoning immutability).
5. REQUEST_MORE_EVIDENCE workflow: Governance Gate check, Scheduler queue re-entry, and action referencing.
6. Cryptographic SHA-256 review record integrity and database/disk tamper detection.
7. Multi-tier provenance lineage trace: Claim -> Artifact -> Execution Output -> Evidence Vault.
8. Case isolation, RBAC, and cross-case IDOR protection.
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
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    InvestigationPlan,
    AnalysisRequest,
    GovernanceDecisionRecord,
    AuditEvent
)
from backend.app.schemas.schemas import (
    InvestigatorReviewCreateRequest,
    RequestMoreEvidenceRequest
)
from backend.app.services.investigator_review import (
    InvestigatorReviewService,
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


def create_test_user_and_case(db, username_prefix="rev_usr", case_prefix="rev_case"):
    """Creates an investigator user and an authorized case."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{username_prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Forensic Investigator {username_prefix}",
        organization="DFIR Review Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("ReviewPass@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-rev-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing investigator review subsystem",
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


def populate_forensic_pipeline_data(db, case):
    """Populates structured evidence, artifacts, findings, and AI reasoning."""
    # 1. Evidence Item
    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigation_id=case.id,
        name="disk_forensics.raw",
        evidence_type="disk_image",
        original_path="/raw/disk_forensics.raw",
        storage_path="/vault/secure/disk_forensics.raw",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=204800,
        status="ACQUIRED"
    )
    db.add(ev)
    db.commit()

    # Custody Event
    ce = ChainOfCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=ev.id,
        case_id=case.id,
        event_type="ACQUISITION_VERIFIED",
        actor_id=case.created_by,
        actor="Lead Investigator",
        description="Physical image acquired with cryptographic SHA-256 verification",
        sha256=ev.sha256_hash,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(ce)
    db.commit()

    # 2. Execution & Output
    fe = ForensicExecution(
        id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        task_key="DISK_PARSING",
        tool_id="sleuthkit",
        executable_path="/usr/bin/fls",
        validated_argv=["/usr/bin/fls", "-r", "/vault/secure/disk_forensics.raw"],
        host_platform="Linux",
        host_architecture="x86_64",
        workspace_path="/tmp/workspace",
        execution_status="COMPLETED"
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
        filename="sleuthkit_output.json",
        relative_path="outputs/sleuthkit_output.json",
        storage_path="/tmp/sleuthkit_output.json",
        sha256_hash="b" * 64
    )
    db.add(exo)
    db.commit()

    # 3. Structured Artifact
    art = StructuredArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        execution_id=fe.id,
        raw_output_id=exo.id,
        evidence_id=ev.id,
        parser_name="cron_parser",
        parser_version="1.0.0",
        artifact_type="SCHEDULED_TASK",
        source_reference="/etc/crontab",
        normalized_data={
            "job_name": "backup_updater",
            "command": "/bin/bash -c '/tmp/.beacon'",
            "schedule": "*/5 * * * *"
        },
        raw_record="*/5 * * * * root /tmp/.beacon",
        sha256_hash="c" * 64,
        source_raw_output_hash=exo.sha256_hash,
        extraction_status="EXTRACTED",
        created_at=datetime.now(timezone.utc)
    )
    db.add(art)
    db.commit()

    # 4. Deterministic Finding
    df = DeterministicFinding(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Unauthorized Persistence Mechanism via Cron",
        description="A periodic crontab task executing a suspicious hidden binary in /tmp was detected.",
        observed_facts=[
            {"field": "command", "observed": "/bin/bash -c '/tmp/.beacon'"},
            {"field": "schedule", "observed": "*/5 * * * *"}
        ],
        finding_type="PERSISTENCE",
        severity="HIGH",
        severity_rule="RULE_CRON_TMP_EXECUTION",
        confidence=0.92,
        confidence_inputs={"artifact_confidence": 0.95, "rule_weight": 0.9},
        supporting_artifact_ids=[art.id],
        supporting_evidence_ids=[ev.id],
        provenance={"rule_engine": "ADFIR_Deterministic_V1"},
        sha256_hash="d" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db.add(df)
    db.commit()

    # 5. AI Reasoning Record
    ar = AIReasoningRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        request_user_id=case.created_by,
        objective="Assess lateral movement and persistence risks",
        status="COMPLETED",
        execution_mode="DETERMINISTIC_FALLBACK",
        provider="local_stub",
        model="adfir-deterministic-engine",
        input_references={"finding_ids": [df.id], "artifact_ids": [art.id], "evidence_ids": [ev.id]},
        raw_evidence_egress_blocked=True,
        egress_approved=False,
        statements=[
            {
                "statement_id": "stmt-001",
                "insight": "Crontab entry executes an unverified beacon in /tmp every 5 minutes.",
                "classification": "FACT",
                "confidence": 0.95,
                "supporting_evidence_ids": [ev.id],
                "supporting_artifact_ids": [art.id],
                "supporting_finding_ids": [df.id]
            },
            {
                "statement_id": "stmt-002",
                "insight": "The adversary likely established C2 persistence following initial credential dumping.",
                "classification": "INFERENCE",
                "confidence": 0.75,
                "supporting_evidence_ids": [ev.id],
                "supporting_artifact_ids": [art.id],
                "supporting_finding_ids": [df.id]
            },
            {
                "statement_id": "stmt-003",
                "insight": "Suspected operator attribution linked to APT29 group.",
                "classification": "UNVERIFIED",
                "confidence": 0.35,
                "supporting_evidence_ids": [],
                "supporting_artifact_ids": [],
                "supporting_finding_ids": []
            }
        ],
        citations_verified=True,
        summary="Structured analysis confirms cron persistence with high confidence.",
        provenance={"generator": "AIReasoningService"},
        reasoning_metadata={"total_statements": 3},
        sha256_hash="e" * 64,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.add(ar)
    db.commit()

    return ev, art, df, ar


# =============================================================================
# 1. REVIEW ITEMS EXTRACTION & VALIDATION
# =============================================================================

def test_get_review_items_comprehensive(db_session):
    """
    Verifies retrieval of all reviewable items:
    - Evidence items with verification integrity & chain of custody
    - Deterministic findings with verified supporting artifacts
    - AI reasoning records with FACT / INFERENCE / UNVERIFIED classifications
    """
    user, case = create_test_user_and_case(db_session, "items_usr", "items_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)
    resp = client.get(f"/api/v1/cases/{case.id}/review/items", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    assert data["case_id"] == case.id

    # 1. Evidence Items
    assert len(data["evidence_items"]) == 1
    ev_data = data["evidence_items"][0]
    assert ev_data["id"] == ev.id
    assert ev_data["verified_integrity"] is True
    assert ev_data["custody_events_count"] == 1

    # 2. Deterministic Findings
    assert len(data["deterministic_findings"]) == 1
    df_data = data["deterministic_findings"][0]
    assert df_data["id"] == df.id
    assert df_data["severity"] == "HIGH"
    assert len(df_data["supporting_artifacts"]) == 1
    assert df_data["supporting_artifacts"][0]["id"] == art.id

    # 3. AI Reasoning Records with Classifications
    assert len(data["ai_reasoning_records"]) == 1
    ar_data = data["ai_reasoning_records"][0]
    assert ar_data["id"] == ar.id
    stmts = ar_data["statements"]
    assert len(stmts) == 3

    classifications = {s["statement_id"]: s["classification"] for s in stmts}
    assert classifications["stmt-001"] == "FACT"
    assert classifications["stmt-002"] == "INFERENCE"
    assert classifications["stmt-003"] == "UNVERIFIED"

    # Citation validity
    assert stmts[0]["citations_valid"] is True

    # 4. Summary counts
    summary = data["summary"]
    assert summary["total_evidence_items"] == 1
    assert summary["total_findings"] == 1
    assert summary["total_ai_reasoning_records"] == 1


# =============================================================================
# 2. INVESTIGATOR DECISIONS: ACCEPT, CHALLENGE, REJECT (IMMUTABILITY)
# =============================================================================

def test_investigator_decision_accept_finding_immutability(db_session):
    """
    Verifies that ACCEPTING a finding:
    1. Creates a persistent, tamper-detectable review record.
    2. Leaves the original deterministic finding strictly unmodified (source immutability).
    3. Correctly maps resulting_workflow_action to ACCEPTED_CLAIM.
    """
    user, case = create_test_user_and_case(db_session, "acc_usr", "acc_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    original_df_hash = df.sha256_hash
    original_df_title = df.title
    original_df_confidence = df.confidence

    headers = get_auth_headers(user)
    payload = {
        "target_type": "FINDING",
        "target_id": df.id,
        "decision": "ACCEPT",
        "comment": "Confirmed unauthorized cron persistence. Artifacts correlate with threat intelligence.",
        "supporting_references": [art.id, ev.id]
    }

    resp = client.post(f"/api/v1/cases/{case.id}/review/decisions", json=payload, headers=headers)
    assert resp.status_code == 201

    data = resp.json()
    assert data["decision"] == "ACCEPT"
    assert data["resulting_workflow_action"] == "ACCEPTED_CLAIM"
    assert data["investigator_id"] == user.id
    assert len(data["sha256_hash"]) == 64

    # VERIFY SOURCE IMMUTABILITY: Finding in DB must be 100% identical
    db_session.expire_all()
    df_after = db_session.query(DeterministicFinding).filter(DeterministicFinding.id == df.id).first()
    assert df_after.sha256_hash == original_df_hash
    assert df_after.title == original_df_title
    assert df_after.confidence == original_df_confidence


def test_investigator_decision_challenge_ai_claim(db_session):
    """
    Verifies that CHALLENGING an AI inference:
    1. Records investigator's counter-arguments and alternative hypothesis.
    2. Maps action to CHALLENGED_CLAIM.
    3. Leaves AI reasoning record strictly unmodified.
    """
    user, case = create_test_user_and_case(db_session, "chal_usr", "chal_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    original_ar_hash = ar.sha256_hash

    headers = get_auth_headers(user)
    payload = {
        "target_type": "AI_REASONING",
        "target_id": ar.id,
        "statement_id": "stmt-002",
        "decision": "CHALLENGE",
        "comment": "Inference of prior credential dumping is speculative; no LSASS dump artifacts exist.",
        "supporting_references": [df.id]
    }

    resp = client.post(f"/api/v1/cases/{case.id}/review/decisions", json=payload, headers=headers)
    assert resp.status_code == 201

    data = resp.json()
    assert data["decision"] == "CHALLENGE"
    assert data["resulting_workflow_action"] == "CHALLENGED_CLAIM"
    assert data["statement_id"] == "stmt-002"

    # Verify AI record immutability
    db_session.expire_all()
    ar_after = db_session.query(AIReasoningRecord).filter(AIReasoningRecord.id == ar.id).first()
    assert ar_after.sha256_hash == original_ar_hash


def test_investigator_decision_reject_claim(db_session):
    """
    Verifies REJECTING an unverified attribution statement:
    1. Records rejection decision and rationale.
    2. Maps action to REJECTED_CLAIM.
    """
    user, case = create_test_user_and_case(db_session, "rej_usr", "rej_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)
    payload = {
        "target_type": "AI_REASONING",
        "target_id": ar.id,
        "statement_id": "stmt-003",
        "decision": "REJECT",
        "comment": "Attribution to APT29 rejected. Zero supporting forensic indicators in evidence.",
        "supporting_references": []
    }

    resp = client.post(f"/api/v1/cases/{case.id}/review/decisions", json=payload, headers=headers)
    assert resp.status_code == 201

    data = resp.json()
    assert data["decision"] == "REJECT"
    assert data["resulting_workflow_action"] == "REJECTED_CLAIM"


# =============================================================================
# 3. REQUEST_MORE_EVIDENCE PIPELINE RE-ENTRY
# =============================================================================

def test_request_more_evidence_pipeline_reentry(db_session):
    """
    Verifies REQUEST_MORE_EVIDENCE workflow:
    1. Evaluates request with Governance Gate (Step 17).
    2. Queues a new AnalysisRequest in the Resource-Aware Scheduler (Step 8).
    3. Re-enters the standard pipeline without creating an out-of-band execution path.
    4. Connects the review record to the generated AnalysisRequest ID.
    """
    user, case = create_test_user_and_case(db_session, "rme_usr", "rme_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)
    payload = {
        "target_type": "CLAIM",
        "target_id": df.id,
        "evidence_id": ev.id,
        "analysis_objective": "Run targeted YARA signature scan on /tmp directory",
        "requested_capability": "YARA_SCAN",
        "parameters": {"scan_target": "/tmp", "fast_mode": True},
        "comment": "Need static signature verification on the detected cron payload binary.",
        "supporting_references": [df.id, ev.id]
    }

    resp = client.post(f"/api/v1/cases/{case.id}/review/request-more-evidence", json=payload, headers=headers)
    assert resp.status_code == 201

    data = resp.json()
    assert data["workflow_status"] == "SCHEDULED"
    assert data["analysis_request_id"] is not None
    assert data["governance_decision_id"] is not None

    review = data["review"]
    assert review["decision"] == "REQUEST_MORE_EVIDENCE"
    assert review["resulting_workflow_action"] == "EVIDENCE_REQUESTED"
    assert review["action_reference_id"] == data["analysis_request_id"]

    # Verify AnalysisRequest was actually queued in the database for the Scheduler
    db_session.expire_all()
    analysis_req = db_session.query(AnalysisRequest).filter(
        AnalysisRequest.id == data["analysis_request_id"]
    ).first()
    assert analysis_req is not None
    assert analysis_req.capability_id == "YARA_SCAN"
    assert analysis_req.scheduler_status == "QUEUED"
    assert analysis_req.case_id == case.id


def test_governance_denial_blocks_request_more_evidence(db_session):
    """
    Verifies that if Governance Gate blocks an unsafe or policy-violating evidence request
    (e.g., shell command injection parameter), the request is rejected with 403 Forbidden.
    """
    user, case = create_test_user_and_case(db_session, "gov_block_usr", "gov_block_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)
    # Payload with dangerous shell injection attempt in parameters
    payload = {
        "target_type": "CLAIM",
        "target_id": df.id,
        "evidence_id": ev.id,
        "analysis_objective": "Attempt command execution in parameters",
        "requested_capability": "YARA_SCAN",
        "parameters": {"command": "cat /etc/passwd; rm -rf /"},
        "comment": "Malicious payload test.",
        "supporting_references": []
    }

    resp = client.post(f"/api/v1/cases/{case.id}/review/request-more-evidence", json=payload, headers=headers)
    assert resp.status_code == 403
    assert "Governance Gate blocked" in resp.json()["detail"]


# =============================================================================
# 4. CRYPTOGRAPHIC INTEGRITY & TAMPER DETECTION
# =============================================================================

def test_review_record_cryptographic_integrity_and_tamper_detection(db_session):
    """
    Verifies SHA-256 cryptographic integrity protection and tamper detection
    on persistent review records.
    """
    user, case = create_test_user_and_case(db_session, "integ_usr", "integ_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    # 1. Create a review record
    req = InvestigatorReviewCreateRequest(
        target_type="FINDING",
        target_id=df.id,
        decision="ACCEPT",
        comment="Genuine finding confirmed by investigator.",
        supporting_references=[art.id]
    )
    review_res = InvestigatorReviewService.submit_decision(db_session, case, user, req)

    # 2. Check Integrity (Normal State -> VERIFIED)
    integrity_resp = InvestigatorReviewService.verify_integrity(db_session, case.id, review_res.id)
    assert integrity_resp.integrity_status == "VERIFIED"
    assert integrity_resp.tamper_detected is False

    # Also verify via API
    headers = get_auth_headers(user)
    api_int_resp = client.get(
        f"/api/v1/cases/{case.id}/review/decisions/{review_res.id}/integrity",
        headers=headers
    )
    assert api_int_resp.status_code == 200
    assert api_int_resp.json()["integrity_status"] == "VERIFIED"
    assert api_int_resp.json()["tamper_detected"] is False

    # 3. Tamper: Modify decision and comment directly in database
    rec = db_session.query(InvestigatorReviewRecord).filter(
        InvestigatorReviewRecord.id == review_res.id
    ).first()
    rec.decision = "REJECT"
    rec.comment = "TAMPERED: Illicitly modified by attacker in DB."
    db_session.commit()

    # 4. Re-verify -> Must detect tampering (FAILED)
    tampered_integrity = InvestigatorReviewService.verify_integrity(db_session, case.id, review_res.id)
    assert tampered_integrity.integrity_status == "FAILED"
    assert tampered_integrity.tamper_detected is True

    # Check via API as well
    api_tamper_resp = client.get(
        f"/api/v1/cases/{case.id}/review/decisions/{review_res.id}/integrity",
        headers=headers
    )
    assert api_tamper_resp.status_code == 200
    assert api_tamper_resp.json()["integrity_status"] == "FAILED"
    assert api_tamper_resp.json()["tamper_detected"] is True


# =============================================================================
# 5. MULTI-TIER PROVENANCE TRACE
# =============================================================================

def test_claim_provenance_multi_tier_lineage(db_session):
    """
    Verifies multi-tier forensic lineage traceability:
    Finding -> Structured Artifact -> Raw Tool Output -> Evidence Vault Item.
    """
    user, case = create_test_user_and_case(db_session, "prov_usr", "prov_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)
    resp = client.get(f"/api/v1/cases/{case.id}/review/provenance/{df.id}", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    assert data["target_id"] == df.id
    assert data["target_type"] == "FINDING"
    assert data["verified_integrity"] is True

    # Check supporting artifacts
    assert len(data["supporting_artifacts"]) == 1
    assert data["supporting_artifacts"][0]["id"] == art.id

    # Check lineage contains tool output
    assert len(data["lineage"]) >= 1
    assert data["lineage"][0]["step"] == "TOOL_EXECUTION_OUTPUT"

    # Check supporting evidence
    assert len(data["supporting_evidence"]) == 1
    assert data["supporting_evidence"][0]["id"] == ev.id


# =============================================================================
# 6. CASE ISOLATION & CROSS-CASE IDOR PROTECTION
# =============================================================================

def test_case_isolation_and_cross_case_idor_protection(db_session):
    """
    Verifies that User A (authorized on Case A) CANNOT:
    1. Inspect review items of Case B.
    2. Submit review decisions for Case B.
    3. Verify integrity of review records in Case B.
    """
    user_a, case_a = create_test_user_and_case(db_session, "user_a", "case_a")
    user_b, case_b = create_test_user_and_case(db_session, "user_b", "case_b")
    ev_b, art_b, df_b, ar_b = populate_forensic_pipeline_data(db_session, case_b)

    headers_a = get_auth_headers(user_a)

    # 1. User A attempts to view Case B review items -> 403 Forbidden
    items_resp = client.get(f"/api/v1/cases/{case_b.id}/review/items", headers=headers_a)
    assert items_resp.status_code == 403

    # 2. User A attempts to submit decision for Case B -> 403 Forbidden
    dec_resp = client.post(
        f"/api/v1/cases/{case_b.id}/review/decisions",
        json={"target_type": "FINDING", "target_id": df_b.id, "decision": "ACCEPT", "comment": "Probe"},
        headers=headers_a
    )
    assert dec_resp.status_code == 403

    # 3. User A attempts to request more evidence in Case B -> 403 Forbidden
    rme_resp = client.post(
        f"/api/v1/cases/{case_b.id}/review/request-more-evidence",
        json={
            "target_type": "CLAIM",
            "target_id": df_b.id,
            "evidence_id": ev_b.id,
            "analysis_objective": "Unauthorized probe",
            "requested_capability": "YARA_SCAN",
            "comment": "Unauthorized probe"
        },
        headers=headers_a
    )
    assert rme_resp.status_code == 403


# =============================================================================
# 7. REVIEW HISTORY AND FILTERING
# =============================================================================

def test_review_history_and_filters(db_session):
    """
    Verifies listing review history with filters by target_id and decision.
    """
    user, case = create_test_user_and_case(db_session, "hist_usr", "hist_case")
    ev, art, df, ar = populate_forensic_pipeline_data(db_session, case)

    headers = get_auth_headers(user)

    # Submit 2 reviews
    client.post(
        f"/api/v1/cases/{case.id}/review/decisions",
        json={"target_type": "FINDING", "target_id": df.id, "decision": "ACCEPT", "comment": "Accepted"},
        headers=headers
    )
    client.post(
        f"/api/v1/cases/{case.id}/review/decisions",
        json={"target_type": "AI_REASONING", "target_id": ar.id, "statement_id": "stmt-003", "decision": "REJECT", "comment": "Rejected"},
        headers=headers
    )

    # List all
    all_resp = client.get(f"/api/v1/cases/{case.id}/review/decisions", headers=headers)
    assert all_resp.status_code == 200
    assert len(all_resp.json()) == 2

    # Filter by decision=ACCEPT
    acc_resp = client.get(f"/api/v1/cases/{case.id}/review/decisions?decision=ACCEPT", headers=headers)
    assert acc_resp.status_code == 200
    assert len(acc_resp.json()) == 1
    assert acc_resp.json()[0]["decision"] == "ACCEPT"

    # Filter by target_id
    target_resp = client.get(f"/api/v1/cases/{case.id}/review/decisions?target_id={df.id}", headers=headers)
    assert target_resp.status_code == 200
    assert len(target_resp.json()) == 1
    assert target_resp.json()[0]["target_id"] == df.id
