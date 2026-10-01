"""ADFIR — Recovery & Case Closure Subsystem Tests (Final Backend Completion)

Verifies:
1. Operational recovery from interrupted RUNNING runs and tasks.
2. Output preservation: existing valid outputs are never rerun or overwritten.
3. Case closure Gate 1: Rejection if active runs or tasks remain.
4. Case closure Gate 2: Rejection if raw evidence integrity is corrupted or missing.
5. Case closure Gate 3: Rejection if audit chain tampering is detected.
6. Case closure Gate 4: Rejection if official final forensic report is missing.
7. Successful case closure with canonical closure hash and audit event.
8. Forensic data immutability on closed cases: mutations reject with 400 Bad Request.
9. Case isolation and cross-case IDOR protection on recovery and closure endpoints.
"""

import os
import uuid
import hashlib
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
    InvestigationPlan,
    InvestigationRun,
    InvestigationTask,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    Report,
    AuditEvent
)
from backend.app.schemas.schemas import CaseClosureRequest, RecoveryRequest
from backend.app.services.audit import log_audit_event, AuditService
from backend.app.services.final_report import FinalForensicReportService
from backend.app.services.case_closure import CaseClosureService, check_case_not_closed
from backend.app.services.recovery import InvestigationRecoveryService

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_user_and_case(db: Session, prefix="rec_cls"):
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Lead Auditor {prefix}",
        organization="DFIR Hardening Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("Pass@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-{prefix}-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:10].upper()}",
        name=f"Case {prefix}",
        description="Recovery and closure test case",
        created_by=user.id,
        owner_id=user.id,
        status="OPEN"
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

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}
    return user, case, headers


def test_recovery_interrupted_tasks_resets_safely(db_session, tmp_path):
    """Test 1: Recovers from interrupted RUNNING runs and tasks safely."""
    user, case, headers = create_user_and_case(db_session, "stale")

    # Log initial genesis audit event
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    # Create stale run
    run = InvestigationRun(
        id=str(uuid.uuid4()),
        case_id=case.id,
        cycle_number=1,
        current_stage="SECURE_EXECUTION",
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        created_by=user.name
    )
    db_session.add(run)

    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        objective="Recovery Test Plan",
        created_by=user.name or user.email,
        status="ACTIVE"
    )
    db_session.add(plan)

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        run_id=run.id,
        task_type="FORENSIC_ANALYSIS",
        tool_id="volatility3",
        status="RUNNING",
        priority=1
    )
    db_session.add(task)

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case.id,
        plan_id=plan.id,
        task_id=task.id,
        tool_id="volatility3",
        scheduler_status="RUNNING"
    )
    db_session.add(req)
    db_session.commit()

    # Recover via API
    res = client.post(f"/api/v1/cases/{case.id}/recover", headers=headers, json={"safe_reset_stale_tasks": True})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "RECOVERED"
    assert data["recovered_runs_count"] >= 1
    assert data["interrupted_tasks_resumed"] >= 1
    assert data["audit_chain_verified"] is True

    # Verify task and run transitioned
    db_session.refresh(run)
    db_session.refresh(task)
    db_session.refresh(req)
    assert run.status == "RECOVERED"
    assert task.status == "READY"
    assert req.scheduler_status == "READY"


def test_recovery_preserves_valid_completed_executions(db_session, tmp_path):
    """Test 2: Never blindly reruns completed executions when outputs are intact."""
    user, case, headers = create_user_and_case(db_session, "pres")

    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    # Create dummy output file on disk
    out_file = tmp_path / "preserved_output.json"
    content = b'{"analysis": "successful_mem_dump"}'
    out_file.write_bytes(content)
    file_sha = hashlib.sha256(content).hexdigest()

    run = InvestigationRun(
        id=str(uuid.uuid4()),
        case_id=case.id,
        cycle_number=1,
        current_stage="SECURE_EXECUTION",
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        created_by=user.name
    )
    db_session.add(run)

    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        objective="Preservation Test Plan",
        created_by=user.name or user.email,
        status="ACTIVE"
    )
    db_session.add(plan)

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        run_id=run.id,
        task_key="task-volatility-preservation",
        task_type="FORENSIC_ANALYSIS",
        tool_id="volatility3",
        status="RUNNING",
        priority=1
    )
    db_session.add(task)

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case.id,
        plan_id=plan.id,
        task_id=task.id,
        tool_id="volatility3",
        scheduler_status="RUNNING"
    )
    db_session.add(req)

    exec_rec = ForensicExecution(
        id=str(uuid.uuid4()),
        request_id=req.id,
        case_id=case.id,
        plan_id=plan.id,
        task_id=task.id,
        task_key=task.task_key,
        tool_id="volatility3",
        execution_status="RUNNING"
    )
    db_session.add(exec_rec)

    output = ExecutionOutput(
        id=str(uuid.uuid4()),
        execution_id=exec_rec.id,
        request_id=req.id,
        case_id=case.id,
        task_id=task.id,
        tool_id="volatility3",
        filename="preserved_output.json",
        relative_path="preserved_output.json",
        storage_path=str(out_file),
        sha256_hash=file_sha,
        output_type="JSON"
    )
    db_session.add(output)
    db_session.commit()

    # Recover
    res = client.post(f"/api/v1/cases/{case.id}/recover", headers=headers, json={"safe_reset_stale_tasks": True})
    assert res.status_code == 200
    data = res.json()
    assert data["valid_outputs_preserved"] >= 1

    # Verify execution marked COMPLETED because output was intact
    db_session.refresh(exec_rec)
    db_session.refresh(task)
    assert exec_rec.execution_status == "COMPLETED"
    assert task.status == "COMPLETED"


def test_case_closure_fails_on_active_runs(db_session):
    """Test 3: Case closure rejected if active runs are present."""
    user, case, headers = create_user_and_case(db_session, "act_run")
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    run = InvestigationRun(
        id=str(uuid.uuid4()),
        case_id=case.id,
        cycle_number=1,
        current_stage="STRATEGY",
        status="RUNNING",
        created_by=user.name
    )
    db_session.add(run)
    db_session.commit()

    res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json={"rationale": "Attempting closure while run active"}
    )
    assert res.status_code == 422
    assert "active investigation run" in res.json()["detail"].lower()


def test_case_closure_fails_on_evidence_integrity_violation(db_session, tmp_path):
    """Test 4: Case closure rejected if evidence file is tampered or missing."""
    user, case, headers = create_user_and_case(db_session, "ev_bad")
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    ev_path = tmp_path / "disk.img"
    ev_path.write_bytes(b"original evidence bytes")
    orig_hash = hashlib.sha256(b"original evidence bytes").hexdigest()

    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        name="disk.img",
        evidence_type="DISK_IMAGE",
        original_path=str(ev_path),
        storage_path=str(ev_path),
        sha256=orig_hash,
        size_bytes=23
    )
    db_session.add(ev)
    db_session.commit()

    # Tamper with evidence file
    ev_path.write_bytes(b"adversary tampering with evidence")

    res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json={"rationale": "Attempting closure with tampered evidence"}
    )
    assert res.status_code == 422
    assert "evidence integrity check failed" in res.json()["detail"].lower()


def test_case_closure_fails_on_missing_final_report(db_session):
    """Test 5: Case closure rejected if official final report has not been generated."""
    user, case, headers = create_user_and_case(db_session, "no_rep")
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json={"rationale": "Attempting closure without final report"}
    )
    assert res.status_code == 422
    assert "final forensic report" in res.json()["detail"].lower()


def test_case_closure_fails_on_audit_chain_tamper(db_session):
    """Test 6: Case closure rejected if audit chain was tampered."""
    user, case, headers = create_user_and_case(db_session, "tamper_aud")
    ev0 = log_audit_event(db=db_session, event_type="E0", details="Genesis", case_id=case.id)
    ev1 = log_audit_event(db=db_session, event_type="E1", details="Action", case_id=case.id)

    # Tamper with audit event in DB
    ev1.details = "TAMPERED PAYLOAD"
    db_session.add(ev1)
    db_session.commit()

    res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json={"rationale": "Attempting closure with tampered audit trail"}
    )
    assert res.status_code == 422
    assert "audit chain tampering detected" in res.json()["detail"].lower()


def test_case_closure_success_and_immutability(db_session, tmp_path):
    """Test 7: Successful case closure and subsequent mutation rejection."""
    user, case, headers = create_user_and_case(db_session, "close_ok")

    # 1. Clean audit event
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    # 2. Clean verified evidence
    ev_path = tmp_path / "valid.log"
    ev_bytes = b"clean server logs"
    ev_path.write_bytes(ev_bytes)
    ev_hash = hashlib.sha256(ev_bytes).hexdigest()

    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        name="valid.log",
        evidence_type="LOG_FILE",
        original_path=str(ev_path),
        storage_path=str(ev_path),
        sha256=ev_hash,
        size_bytes=len(ev_bytes)
    )
    db_session.add(ev)

    # 3. Clean official final report
    report_hash = "f" * 64
    rep = Report(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Official Final Forensic Report",
        version=1,
        status="OFFICIAL_FINAL",
        report_hash=report_hash,
        full_report_markdown="# Final Report",
        provenance={"sections": 12},
        executive_summary="Claims: 1",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(rep)
    db_session.commit()

    # Close Case
    close_res = client.post(
        f"/api/v1/cases/{case.id}/close",
        headers=headers,
        json={"rationale": "Investigation fully completed, verified, and grounded."}
    )
    assert close_res.status_code == 200
    close_data = close_res.json()
    assert close_data["status"] == "CLOSED"
    assert len(close_data["closure_hash"]) == 64
    assert close_data["evidence_verified_count"] >= 1
    assert close_data["audit_chain_verified"] is True
    assert close_data["final_report_verified"] is True

    # Immutability Check: Subsequent mutations on closed case must return 400 Bad Request
    db_session.refresh(case)
    with pytest.raises(Exception) as excinfo:
        check_case_not_closed(case)
    assert "400" in str(excinfo.value)

    # Verify intake evidence fails on closed case
    intake_res = client.post(
        f"/api/v1/cases/{case.id}/evidence/intake",
        headers=headers,
        json={"file_path": str(ev_path)}
    )
    assert intake_res.status_code == 400
    assert "immutable" in intake_res.json()["detail"].lower()

    # Verify PATCH /v1/cases/{id} fails on closed case
    patch_v1_res = client.patch(
        f"/api/v1/cases/{case.id}",
        headers=headers,
        json={"description": "Attempting to modify closed case"}
    )
    assert patch_v1_res.status_code == 400
    assert "immutable" in patch_v1_res.json()["detail"].lower()

    # Verify legacy PATCH /cases/{id} fails on closed case
    patch_legacy_res = client.patch(
        f"/api/cases/{case.id}",
        headers=headers,
        json={"description": "Attempting to modify closed case via legacy route"}
    )
    assert patch_legacy_res.status_code == 400
    assert "immutable" in patch_legacy_res.json()["detail"].lower()


def test_patch_status_closed_enforces_closure_gates(db_session):
    """Test: PATCH with status=CLOSED strictly delegates to CaseClosureService and enforces gates."""
    user, case, headers = create_user_and_case(db_session, "patch_gate")

    # 1. Attempting to set status=CLOSED via PATCH /v1/cases/{id} on a case without final report fails
    patch_v1_res = client.patch(
        f"/api/v1/cases/{case.id}",
        headers=headers,
        json={"status": "CLOSED"}
    )
    assert patch_v1_res.status_code == 422
    assert "official final forensic report has not been generated" in patch_v1_res.json()["detail"].lower()

    # 2. Attempting to set status=CLOSED via legacy PATCH /cases/{id} also delegates and fails
    patch_legacy_res = client.patch(
        f"/api/cases/{case.id}",
        headers=headers,
        json={"status": "CLOSED"}
    )
    assert patch_legacy_res.status_code == 422
    assert "official final forensic report has not been generated" in patch_legacy_res.json()["detail"].lower()


def test_recovery_and_closure_case_isolation_and_idor(db_session):
    """Test 8: Cross-case IDOR protection: User A cannot close or recover Case B."""
    user_a, case_a, headers_a = create_user_and_case(db_session, "idor_cl_a")
    user_b, case_b, headers_b = create_user_and_case(db_session, "idor_cl_b")

    # User B tries to close Case A -> 403 Forbidden
    res_close = client.post(
        f"/api/v1/cases/{case_a.id}/close",
        headers=headers_b,
        json={"rationale": "Unauthorized closure attempt"}
    )
    assert res_close.status_code == 403

    # User B tries to recover Case A -> 403 Forbidden
    res_rec = client.post(
        f"/api/v1/cases/{case_a.id}/recover",
        headers=headers_b,
        json={"safe_reset_stale_tasks": True}
    )
    assert res_rec.status_code == 403


def test_recovery_prevents_reset_while_os_process_is_running(db_session, monkeypatch):
    """Test 9: Recovery strictly prevents resetting a task to READY while its previous forensic OS process is still running."""
    user, case, headers = create_user_and_case(db_session, "active_os_proc")
    log_audit_event(db=db_session, event_type="CASE_INIT", details="Init", case_id=case.id)

    run = InvestigationRun(
        id=str(uuid.uuid4()),
        case_id=case.id,
        cycle_number=1,
        current_stage="SECURE_EXECUTION",
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        created_by=user.name
    )
    db_session.add(run)

    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        objective="Active Process Safety Test Plan",
        created_by=user.name or user.email,
        status="ACTIVE"
    )
    db_session.add(plan)

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        run_id=run.id,
        task_key="task-volatility-active-os",
        task_type="FORENSIC_ANALYSIS",
        tool_id="volatility3",
        status="RUNNING",
        priority=1
    )
    db_session.add(task)

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case.id,
        plan_id=plan.id,
        task_id=task.id,
        tool_id="volatility3",
        scheduler_status="RUNNING"
    )
    db_session.add(req)

    # Simulated active OS process with verified start time
    active_pid = 888888
    active_start_time = 1710000000.5

    exec_rec = ForensicExecution(
        id=str(uuid.uuid4()),
        request_id=req.id,
        case_id=case.id,
        plan_id=plan.id,
        task_id=task.id,
        task_key=task.task_key,
        tool_id="volatility3",
        execution_status="RUNNING",
        pid=active_pid,
        process_start_time=active_start_time
    )
    db_session.add(exec_rec)
    db_session.commit()

    # Mock get_process_start_time to simulate the OS process matching the stored PID and start time
    def mock_get_process_start_time(pid):
        if pid == active_pid:
            return active_start_time
        return None

    monkeypatch.setattr("backend.app.services.recovery.get_process_start_time", mock_get_process_start_time)

    # Run recovery with safe_reset_stale_tasks=True
    res = client.post(f"/api/v1/cases/{case.id}/recover", headers=headers, json={"safe_reset_stale_tasks": True})
    assert res.status_code == 200
    data = res.json()

    # Verify recovery recognized the still-running process and refused to reset task or request
    assert len(data["recovery_details"]["still_running_executions"]) >= 1
    still_running = data["recovery_details"]["still_running_executions"][0]
    assert still_running["execution_id"] == exec_rec.id
    assert still_running["pid"] == active_pid
    assert "duplicate execution" in still_running["reason"].lower()

    # Verify database state was NOT reset to READY
    db_session.refresh(task)
    db_session.refresh(req)
    assert task.status == "RUNNING"
    assert req.scheduler_status == "RUNNING"

    # Now simulate the OS process finishing/terminating (returns None for PID)
    def mock_get_process_start_time_dead(pid):
        return None

    monkeypatch.setattr("backend.app.services.recovery.get_process_start_time", mock_get_process_start_time_dead)

    # Re-run recovery - now that process is confirmed dead and no output exists, it is safe to reset
    res2 = client.post(f"/api/v1/cases/{case.id}/recover", headers=headers, json={"safe_reset_stale_tasks": True})
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2["recovery_details"]["rescheduled_requests"]) >= 1

    db_session.refresh(task)
    db_session.refresh(req)
    assert task.status == "READY"
    assert req.scheduler_status == "READY"
