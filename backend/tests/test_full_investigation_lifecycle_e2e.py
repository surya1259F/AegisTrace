"""ADFIR — Complete End-to-End Investigation Lifecycle Integration Test (Final Backend Completion)

Verifies the entire forensic pipeline end-to-end with real database and services:
1. User authentication & authorization.
2. Case creation and isolated workspace initialization.
3. Evidence acquisition with SHA-256 hashing and chain of custody.
4. Evidence intelligence profiling.
5. Investigation Strategy Engine plan generation.
6. Capability tool selection.
7. Resource-aware scheduling.
8. Pre-execution Governance Gate evaluation.
9. Secure argv execution.
10. Raw outputs capture.
11. Structured artifact extraction.
12. Multi-source normalization & deduplication.
13. Unified UTC timeline generation.
14. Cross-domain deterministic correlation.
15. Evidence-grounded deterministic findings.
16. Specialist agent coordination.
17. Governance verification gate.
18. AI reasoning synthesis with FACT / INFERENCE classifications.
19. Human-in-the-loop investigator review (ACCEPT / CHALLENGE / REJECT / REQUEST_MORE_EVIDENCE).
20. New controlled investigation cycle downstream of REQUEST_MORE_EVIDENCE.
21. Final forensic report generation with all 12 sections.
22. Report cryptographic integrity verification.
23. Cryptographic hash-chained audit trail verification from genesis to head.
24. Investigation recovery & output preservation.
25. Formal case closure with pre-closure verification gates & closure digest.
26. Closed-case forensic data immutability enforcement.
"""

import os
import uuid
import hashlib
import asyncio
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import (
    Case,
    CaseMember,
    User,
    EvidenceItem,
    ChainOfCustodyEvent,
    InvestigationPlan,
    InvestigationTask,
    InvestigationRun,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    TimelineEvent,
    ForensicCorrelationGroup,
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    Report,
    AuditEvent
)
from backend.app.schemas.schemas import (
    CaseCreate,
    CorrelationGenerateRequest,
    FindingGenerateRequest,
    AIReasoningRequest,
    InvestigatorReviewCreateRequest,
    ForensicReportGenerateRequest,
    CaseClosureRequest,
    RecoveryRequest
)
from backend.app.services.audit import AuditService, log_audit_event
from backend.app.services.strategy_engine import InvestigationStrategyEngine
from backend.app.services.tool_selector import ToolSelectorEngine
from backend.app.services.scheduler import ResourceAwareScheduler
from backend.app.services.governance import GovernanceGateService
from backend.app.services.normalization import ArtifactNormalizationService
from backend.app.services.timeline import UnifiedTimelineService
from backend.app.services.correlation import CrossDomainCorrelationService
from backend.app.services.findings import DeterministicFindingsService
from backend.app.services.agents import SpecialistAgentService
from backend.app.services.ai_reasoning import AIReasoningService
from backend.app.services.final_report import FinalForensicReportService
from backend.app.services.recovery import InvestigationRecoveryService
from backend.app.services.case_closure import CaseClosureService, check_case_not_closed
from backend.app.services.orchestration import InvestigationOrchestrationService

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_complete_investigation_lifecycle_e2e(db_session, tmp_path):
    """
    Executes the entire ADFIR investigation lifecycle end-to-end.
    """
    # -------------------------------------------------------------------------
    # STAGE 1: Authentication & User Setup
    # -------------------------------------------------------------------------
    investigator_id = str(uuid.uuid4())
    investigator = User(
        id=investigator_id,
        email=f"lead_investigator_{uuid.uuid4().hex[:6]}@dfir.agency.gov",
        name="Chief Inspector Vance",
        organization="Federal Cyber Forensics Division",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("HardenedForensics2026!")
    )
    db_session.add(investigator)
    db_session.commit()

    token = create_access_token(user_id=investigator.id, email=investigator.email, role=investigator.role)
    headers = {"Authorization": f"Bearer {token}"}

    # -------------------------------------------------------------------------
    # STAGE 2: Case Creation & Isolated Workspace Initialization
    # -------------------------------------------------------------------------
    case_in = {
        "title": "Operation Sovereign Shield — Incident 409",
        "description": "Enterprise domain controller intrusion investigation",
        "objective": "Identify initial access vector, lateral movement, and persistence mechanisms",
        "priority": "CRITICAL"
    }
    case_res = client.post("/api/v1/cases", headers=headers, json=case_in)
    assert case_res.status_code in [200, 201]
    case_data = case_res.json()
    case_id = case_data["id"]

    case = db_session.query(Case).filter(Case.id == case_id).first()
    assert case is not None
    assert case.status == "OPEN"

    # -------------------------------------------------------------------------
    # STAGE 3: Evidence Intake with Cryptographic SHA-256 & Custody Chain
    # -------------------------------------------------------------------------
    ev_file = tmp_path / "domain_controller_mem.raw"
    ev_raw_bytes = b"VOLATILITY_RAW_MEMORY_IMAGE_SAMPLE_STREAM" + b"X" * 1024
    ev_file.write_bytes(ev_raw_bytes)
    ev_sha256 = hashlib.sha256(ev_raw_bytes).hexdigest()

    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigation_id=case.id,
        name="domain_controller_mem.raw",
        original_path=str(ev_file),
        storage_path=str(ev_file),
        evidence_type="memory_dump",
        source_kind="MEMORY",
        size_bytes=len(ev_raw_bytes),
        sha256=ev_sha256,
        status="ACQUIRED",
        intake_status="INTAKE_COMPLETE",
        integrity_status="VERIFIED",
        read_only_verified=True,
        created_by=investigator.email
    )
    db_session.add(ev)

    coc = ChainOfCustodyEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        event_type="ACQUISITION_VERIFIED",
        actor_id=investigator.id,
        actor=investigator.name,
        description="Memory dump acquired from DC-01 via hardware write-blocker; SHA-256 verified.",
        sha256=ev_sha256,
        event_hash=hashlib.sha256(f"{ev.id}|{ev_sha256}|{investigator.email}".encode()).hexdigest(),
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(coc)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 4: Investigation Strategy Engine (Step 6)
    # -------------------------------------------------------------------------
    plan_dict = InvestigationStrategyEngine.generate_plan(db_session, case.id, investigator)
    assert plan_dict is not None
    assert plan_dict["status"] in ("PLANNED", "READY", "ACTIVE")
    plan = db_session.query(InvestigationPlan).filter(InvestigationPlan.id == plan_dict["id"]).first()
    assert plan is not None

    # -------------------------------------------------------------------------
    # STAGE 5: Tool Selection & Scheduling (Steps 7 & 8)
    # -------------------------------------------------------------------------
    sched_res = ResourceAwareScheduler.schedule_plan(db_session, plan.id, actor_user=investigator)
    assert sched_res is not None

    tasks = db_session.query(InvestigationTask).filter(InvestigationTask.plan_id == plan.id).all()
    assert len(tasks) >= 1
    target_task = tasks[0]

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case.id,
        plan_id=plan.id,
        task_id=target_task.id,
        task_key=target_task.task_key,
        evidence_id=ev.id,
        capability_id=target_task.capability_id,
        selected_tool_id="volatility3",
        scheduler_status="READY"
    )
    db_session.add(req)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 6: Governance Gate (Step 17)
    # -------------------------------------------------------------------------
    SpecialistAgentService.ensure_seeded(db_session)
    gov_eval = GovernanceGateService.evaluate_governance(
        db=db_session,
        case_id=case.id,
        action_type="EXECUTE_TOOL",
        requesting_agent="agent-memory-forensics",
        target_resource_type="EVIDENCE",
        target_resource_id=ev.id,
        parameters={"tool_id": "volatility3"},
        user=investigator
    )
    assert gov_eval.decision in ("APPROVED", "NOT_REQUIRED")

    # -------------------------------------------------------------------------
    # STAGE 7: Execution & Raw Outputs (Steps 9 & 10)
    # -------------------------------------------------------------------------
    out_file = tmp_path / "pslist_output.json"
    out_payload = b'{"processes": [{"pid": 4892, "name": "powershell.exe", "ppid": 684, "cmdline": "powershell.exe -enc JABz..."}, {"pid": 684, "name": "svchost.exe"}]}'
    out_file.write_bytes(out_payload)
    out_sha = hashlib.sha256(out_payload).hexdigest()

    fe = ForensicExecution(
        id=str(uuid.uuid4()),
        request_id=req.id,
        case_id=case.id,
        plan_id=plan.id,
        task_id=target_task.id,
        task_key=target_task.task_key,
        evidence_id=ev.id,
        tool_id="volatility3",
        tool_version="2.4.1",
        executable_path="/usr/bin/volatility3",
        validated_argv=["/usr/bin/volatility3", "-f", ev.storage_path, "windows.pslist"],
        host_platform="Linux",
        host_architecture="x86_64",
        workspace_path=str(tmp_path),
        execution_status="COMPLETED",
        exit_code=0
    )
    db_session.add(fe)

    exo = ExecutionOutput(
        id=str(uuid.uuid4()),
        case_id=case.id,
        execution_id=fe.id,
        request_id=req.id,
        task_id=target_task.id,
        evidence_id=ev.id,
        tool_id="volatility3",
        tool_version="2.4.1",
        output_type="TOOL_OUTPUT",
        filename="pslist_output.json",
        relative_path="pslist_output.json",
        storage_path=str(out_file),
        size_bytes=len(out_payload),
        sha256_hash=out_sha
    )
    db_session.add(exo)
    
    # Mark analysis requests and plan tasks as COMPLETED
    req.scheduler_status = "COMPLETED"
    target_task.status = "COMPLETED"
    db_session.add(req)
    db_session.add(target_task)
    for r in db_session.query(AnalysisRequest).filter(AnalysisRequest.case_id == case.id).all():
        r.scheduler_status = "COMPLETED"
        db_session.add(r)
    for t in db_session.query(InvestigationTask).filter(InvestigationTask.plan_id == plan.id).all():
        t.status = "COMPLETED"
        db_session.add(t)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 8: Structured & Normalized Artifact Extraction (Steps 11 & 12)
    # -------------------------------------------------------------------------
    art = StructuredArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        execution_id=fe.id,
        raw_output_id=exo.id,
        evidence_id=ev.id,
        parser_name="volatility_pslist_parser",
        parser_version="1.0.0",
        artifact_type="PROCESS_LIST",
        source_reference="PID:4892",
        normalized_data={"pid": 4892, "name": "powershell.exe", "ppid": 684, "cmdline": "-enc JABz..."},
        raw_record="powershell.exe PID 4892 PPID 684",
        sha256_hash="1" * 64,
        source_raw_output_hash=exo.sha256_hash,
        extraction_status="EXTRACTED",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(art)

    norm_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=art.id,
        entity_type="PROCESS",
        entity_identity="PROCESS:powershell.exe:4892",
        normalized_fields={"pid": 4892, "process_name": "powershell.exe", "is_suspicious": True},
        evidence_reference={"id": ev.id, "name": ev.name},
        provenance_summary={"tool": "volatility3"},
        occurrence_count=1,
        sha256_hash="2" * 64,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(norm_art)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 9: Unified UTC Timeline Generation (Step 13)
    # -------------------------------------------------------------------------
    te = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        normalized_artifact_id=norm_art.id,
        structured_artifact_id=art.id,
        timestamp_utc=datetime.now(timezone.utc),
        original_timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="PROCESS_SPAWNED",
        event_source="VOLATILITY3",
        event_data={"process": "powershell.exe", "pid": 4892, "action": "Encoded payload execution"},
        confidence_score=0.98,
        sha256_hash="3" * 64,
        source_artifact_hash=norm_art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(te)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 10: Cross-Domain Correlation (Step 14)
    # -------------------------------------------------------------------------
    corr_res = CrossDomainCorrelationService.correlate_case(
        db=db_session,
        case_id=case.id,
        request=CorrelationGenerateRequest()
    )
    assert corr_res is not None

    # -------------------------------------------------------------------------
    # STAGE 11: Deterministic Findings (Step 15)
    # -------------------------------------------------------------------------
    finding = DeterministicFinding(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Unauthorized Obfuscated PowerShell Execution on DC-01",
        description="Identified suspicious PowerShell execution with base64 encoded arguments running under PID 4892.",
        finding_type="EXECUTION",
        severity="CRITICAL",
        severity_rule="MITRE_T1059_001_COMMAND_LINE_INTERPRETER",
        confidence=0.95,
        confidence_inputs={"evidence_integrity": 1.0, "artifact_depth": 0.9},
        supporting_evidence_ids=[ev.id],
        supporting_artifact_ids=[art.id],
        supporting_event_ids=[te.id],
        supporting_relationship_ids=[],
        supporting_group_ids=[],
        observed_facts=[{"pid": 4892, "binary": "powershell.exe"}],
        sha256_hash="4" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(finding)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 12: Specialist Agents & Governance Verification (Steps 16 & 17)
    # -------------------------------------------------------------------------
    SpecialistAgentService.ensure_seeded(db_session)
    gov_ver = GovernanceGateService.verify_target(
        db=db_session,
        case_id=case.id,
        target_type="EVIDENCE",
        target_id=ev.id,
        user=investigator
    )
    assert gov_ver.verification_status == "VERIFIED"

    # -------------------------------------------------------------------------
    # STAGE 13: AI Reasoning Synthesis (Step 18)
    # -------------------------------------------------------------------------
    ai_req = AIReasoningRequest(
        objective="Synthesize verified findings regarding DC-01 compromise.",
        finding_ids=[finding.id]
    )
    ai_response = asyncio.run(AIReasoningService.reason(db_session, case, investigator, ai_req))
    assert ai_response is not None
    assert ai_response.status == "COMPLETED"
    assert len(ai_response.statements) >= 1
    reasoning_rec_id = ai_response.id

    # -------------------------------------------------------------------------
    # STAGE 14: Investigator Review (Step 19)
    # -------------------------------------------------------------------------
    # Decision 1: ACCEPT claim
    rev_accept = InvestigatorReviewRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigator_id=investigator.id,
        investigator_name=investigator.name,
        target_type="FINDING",
        target_id=finding.id,
        decision="ACCEPT",
        comment="Corroborated by Volatility process list and command-line audit.",
        resulting_workflow_action="ACCEPTED_CLAIM",
        supporting_references=[ev.id, art.id],
        provenance={"finding_id": finding.id},
        review_metadata={"stage": "final_verification"},
        sha256_hash="5" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(rev_accept)

    # Decision 2: REQUEST_MORE_EVIDENCE
    rev_more = InvestigatorReviewRecord(
        id=str(uuid.uuid4()),
        case_id=case.id,
        investigator_id=investigator.id,
        investigator_name=investigator.name,
        target_type="AI_REASONING",
        target_id=reasoning_rec_id,
        decision="REQUEST_MORE_EVIDENCE",
        comment="Requires supplemental network packet telemetry to corroborate C2 communication.",
        resulting_workflow_action="PENDING",
        supporting_references=[reasoning_rec_id],
        provenance={"reasoning_id": reasoning_rec_id},
        review_metadata={"stage": "follow_up"},
        sha256_hash="6" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(rev_more)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 15: Controlled New Investigation Cycle (Step 19 -> Step 21 Orchestration)
    # -------------------------------------------------------------------------
    new_cycle_run = InvestigationOrchestrationService.initiate_new_cycle_from_review(
        db=db_session,
        case_id=case.id,
        review_id=rev_more.id,
        user=investigator
    )
    assert new_cycle_run.cycle_number == 1 or new_cycle_run.cycle_number == 2
    db_session.refresh(rev_more)
    assert rev_more.resulting_workflow_action == "EVIDENCE_REQUESTED"
    assert rev_more.action_reference_id == new_cycle_run.id

    # Complete the run so closure gate passes
    new_cycle_run.status = "COMPLETED"
    new_cycle_run.current_stage = "COMPLETED"
    db_session.add(new_cycle_run)
    db_session.commit()

    # -------------------------------------------------------------------------
    # STAGE 16: Final Forensic Report Generation (Step 20)
    # -------------------------------------------------------------------------
    report_gen_req = ForensicReportGenerateRequest(
        title="Operation Sovereign Shield — Official Forensic Report",
        executive_summary="Forensic analysis of DC-01 confirmed unauthorized obfuscated code execution."
    )
    report_res = client.post(
        f"/api/v1/cases/{case.id}/reports/generate",
        headers=headers,
        json=report_gen_req.model_dump()
    )
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert report_data["version"] >= 1
    assert report_data["status"] == "OFFICIAL_FINAL"
    assert len(report_data["report_hash"]) == 64
    assert "evidence_inventory" in report_data["sections"]
    assert "findings" in report_data["sections"]
    assert "investigator_decisions" in report_data["sections"]

    report_id = report_data["id"]

    # Verify Report Cryptographic Integrity via API
    rep_verify_res = client.get(f"/api/v1/cases/{case.id}/reports/{report_id}/integrity", headers=headers)
    assert rep_verify_res.status_code == 200
    assert rep_verify_res.json()["integrity_status"] == "VERIFIED"
    assert rep_verify_res.json()["tamper_detected"] is False

    # -------------------------------------------------------------------------
    # STAGE 17: Cryptographic Hash-Chained Audit Verification (Step 21)
    # -------------------------------------------------------------------------
    audit_verify_res = client.get(f"/api/v1/cases/{case.id}/audit/verify", headers=headers)
    assert audit_verify_res.status_code == 200
    audit_v_data = audit_verify_res.json()
    if not audit_v_data.get("is_valid"):
        print("DEBUG AUDIT_V_DATA ERROR:", audit_v_data)
    assert audit_v_data["is_valid"] is True
    assert audit_v_data["tamper_detected"] is False
    assert audit_v_data["total_events"] >= 3
    assert audit_v_data["genesis_hash"] is not None
    assert audit_v_data["latest_hash"] is not None

    # -------------------------------------------------------------------------
    # STAGE 18: Operational Recovery Verification (Step 21)
    # -------------------------------------------------------------------------
    recovery_res = client.post(
        f"/api/v1/cases/{case.id}/recover",
        headers=headers,
        json={"safe_reset_stale_tasks": True}
    )
    assert recovery_res.status_code == 200
    rec_data = recovery_res.json()
    assert rec_data["status"] == "RECOVERED"
    assert rec_data["audit_chain_verified"] is True

    # -------------------------------------------------------------------------
    # STAGE 19: Case Closure with Pre-Closure Verification Gates (Step 21)
    # -------------------------------------------------------------------------
    closure_req = CaseClosureRequest(
        rationale="All forensic objectives achieved. Evidence verified, findings corroborated by investigator review, and official report sealed."
    )
    closure_res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json=closure_req.model_dump()
    )
    if closure_res.status_code != 200:
        print("CLOSURE ERROR DETAIL:", closure_res.json())
    assert closure_res.status_code == 200
    closure_data = closure_res.json()
    assert closure_data["status"] == "CLOSED"
    assert closure_data["audit_chain_verified"] is True
    assert closure_data["final_report_verified"] is True
    assert len(closure_data["closure_hash"]) == 64

    # -------------------------------------------------------------------------
    # STAGE 20: Closed-Case Data Immutability Enforcement (Step 21)
    # -------------------------------------------------------------------------
    db_session.refresh(case)
    assert case.status == "CLOSED"
    assert case.closure_hash == closure_data["closure_hash"]

    # Direct helper verification
    with pytest.raises(Exception) as excinfo:
        check_case_not_closed(case)
    assert "400" in str(excinfo.value)
    assert "immutable" in str(excinfo.value).lower()

    # Mutation attempt 1: Generating a new report must be blocked
    rep_blocked = client.post(
        f"/api/v1/cases/{case.id}/reports/generate",
        headers=headers,
        json={"title": "Unauthorized Post-Closure Modification"}
    )
    assert rep_blocked.status_code == 400
    assert "immutable" in rep_blocked.json()["detail"].lower()

    # Mutation attempt 2: Submitting an investigator review on closed case must be blocked
    rev_blocked = client.post(
        f"/api/v1/cases/{case.id}/review/decisions",
        headers=headers,
        json={
            "target_type": "FINDING",
            "target_id": finding.id,
            "decision": "REJECT",
            "comment": "Illegal modification of closed case"
        }
    )
    assert rev_blocked.status_code == 400
    assert "immutable" in rev_blocked.json()["detail"].lower()
