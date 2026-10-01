"""
ADFIR — Phase 2 / Step 9: Secure Forensic Execution Subsystem Tests

Comprehensive verification of:
1. READY-only execution enforcement (rejection of QUEUED, WAITING_RESOURCE, BLOCKED, etc.)
2. Invalid request and missing evidence rejection
3. Cross-case IDOR rejection (evidence case mismatch)
4. Evidence vault integrity verification (SHA-256 re-hashing)
5. Evidence tampering detection and execution blocking (custody violation logged)
6. Disabled and unavailable tool rejection
7. Disallowed binary rejection (bash, sh, powershell, python, etc.)
8. Dedicated isolated workspace creation, directory separation from vault, and 0o700 permissions
9. Path traversal and null byte rejection
10. Symlink escape rejection during output collection
11. Safe argv-only list construction (shell=False invariant)
12. Successful process execution, output discovery, SHA-256 hashing, and DB registration
13. Non-zero exit code capture and FAILED state assignment
14. Process timeout monitoring, safe multi-stage termination, and scheduler resource release
15. Process cancellation, authoritative PID identity verification, and resource release
16. Separate stdout and stderr capture into execution log artifacts
17. Complete execution provenance persistence and immutable audit event logging
18. Case authorization, RBAC, and IDOR isolation enforcement across all execution APIs
"""

import os
import sys
import time
import uuid
import shutil
import stat
import pytest
from pathlib import Path
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.models import (
    User,
    Case,
    CaseMember,
    EvidenceItem,
    InvestigationPlan,
    InvestigationTask,
    ToolDefinition,
    ToolSelectionRecord,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    AuditEvent,
    ChainOfCustodyEvent
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.strategy_engine import seed_forensic_capabilities
from backend.app.services.tool_selector import seed_default_tools
from backend.app.services.scheduler import ResourceAwareScheduler
from backend.app.services.execution import (
    ForensicExecutionService,
    ExecutionPathValidator,
    active_process_registry
)
from backend.app.services.integrity import calculate_sha256

client = TestClient(app)


# =============================================================================
# DATABASE & ENVIRONMENT FIXTURE
# =============================================================================

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_forensic_capabilities(db)
    seed_default_tools(db)

    # Clean up execution and scheduler tables for test isolation
    db.query(ExecutionOutput).delete()
    db.query(ForensicExecution).delete()
    db.query(AnalysisRequest).delete()
    db.commit()
    db.close()

    yield

    cleanup_db = SessionLocal()
    cleanup_db.query(ExecutionOutput).delete()
    cleanup_db.query(ForensicExecution).delete()
    cleanup_db.query(AnalysisRequest).delete()
    cleanup_db.commit()
    cleanup_db.close()


def create_test_user_and_case(db, user_suffix="1", case_suffix="1"):
    email = f"exec_lead_{user_suffix}_{uuid.uuid4().hex[:6]}@adfir.local"
    user = User(
        id=f"user-exec-{user_suffix}-{uuid.uuid4().hex[:6]}",
        email=email,
        name="Lead Execution Investigator",
        role="INVESTIGATOR",
        password_hash=hash_password("SecretPass123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    case = Case(
        id=f"case-exec-{case_suffix}-{uuid.uuid4().hex[:6]}",
        case_number=f"CAS-EXEC-{case_suffix}-{uuid.uuid4().hex[:4]}",
        name="Secure Execution Verification Case",
        objective="Verify secure execution with isolated workspaces and zero shell execution.",
        case_type="DATA_EXFILTRATION",
        priority="HIGH",
        status="OPEN",
        owner_id=user.id,
        created_by=user.id
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    member = CaseMember(
        id=str(uuid.uuid4()),
        case_id=case.id,
        user_id=user.id,
        role="PRIMARY_INVESTIGATOR"
    )
    db.add(member)
    db.commit()

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    secret_val = settings.ADFIR_INTERNAL_SECRET or "bootstrap-secret"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-ADFIR-Bootstrap-Secret": str(secret_val)
    }

    _ = (user.id, user.email, user.role, user.name, case.id, case.case_number)
    db.expunge_all()
    return user, case, headers


def create_test_evidence(db, case, filename="sample.dd", content=b"FORENSIC_RAW_TEST_EVIDENCE_DATA_12345"):
    """Creates a real test evidence file staged in vault directory."""
    ev_id = str(uuid.uuid4())
    vault_dir = settings.EVIDENCE_DIR / "vault" / case.id / ev_id
    vault_dir.mkdir(parents=True, exist_ok=True)
    ev_file = vault_dir / filename
    ev_file.write_bytes(content)

    sha256_hash, size_bytes = calculate_sha256(str(ev_file))

    evidence = EvidenceItem(
        id=ev_id,
        case_id=case.id,
        name=filename,
        original_path=str(ev_file),
        storage_path=str(ev_file),
        size_bytes=float(size_bytes),
        sha256=sha256_hash,
        integrity_status="VERIFIED",
        evidence_type="DISK_IMAGE",
        status="ANALYSIS_READY"
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence, ev_file


def create_ready_analysis_request(db, case, user, tool_id="test_safe_tool", tool_path=None):
    """Sets up a complete Plan -> Task -> ToolSelection -> READY AnalysisRequest chain."""
    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Execution Test Plan",
        strategy_summary="Test execution strategy",
        validation_status="VALIDATED",
        version=1,
        created_by=user.id
    )
    db.add(plan)
    db.commit()

    evidence, ev_file = create_test_evidence(db, case)

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_key=f"task-exec-{uuid.uuid4().hex[:4]}",
        sequence=1,
        capability_id="FILESYSTEM_ANALYSIS",
        evidence_ids=[evidence.id],
        agent_name="DiskAgent",
        priority_level="HIGH",
        priority_score=0.9,
        resource_requirements={"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100},
        status="READY"
    )
    db.add(task)
    db.commit()

    # Register safe tool definition if custom tool_path provided
    resolved_path = tool_path or shutil.which("sha256sum") or shutil.which("echo") or "/bin/echo"
    db_tool = db.query(ToolDefinition).filter(ToolDefinition.tool_id == tool_id).first()
    if not db_tool:
        db_tool = ToolDefinition(
            tool_id=tool_id,
            name=tool_id,
            display_name="Safe Test Forensic Tool",
            binary_name=Path(resolved_path).name,
            executable_path=resolved_path,
            platforms=["linux", "windows", "darwin"],
            supported_evidence=["disk_image"],
            supported_formats=["raw", "dd"],
            capabilities_json=["FILESYSTEM_ANALYSIS"],
            resource_requirements={"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100},
            enabled=True,
            is_available=True
        )
        db.add(db_tool)
        db.commit()
    else:
        db_tool.executable_path = resolved_path
        db_tool.binary_name = Path(resolved_path).name
        db_tool.enabled = True
        db_tool.is_available = True
        db.commit()


    sel = ToolSelectionRecord(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_id=task.id,
        task_key=task.task_key,
        capability_id=task.capability_id,
        evidence_id=evidence.id,
        selected_tool_id=tool_id,
        selection_status="SELECTED",
        availability_status="AVAILABLE",
        evidence_compatibility="COMPATIBLE",
        platform_compatibility="COMPATIBLE",
        resource_status="RESOURCE_OK",
        version_status="VERSION_OK",
        safety_status="SAFE",
        selection_rationale="Test selection"
    )
    db.add(sel)
    db.commit()

    req = ResourceAwareScheduler.create_analysis_request(
        db=db,
        plan_id=plan.id,
        task_key=task.task_key,
        actor_user=user,
        timeout_seconds=30
    )
    ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    db.refresh(req)
    assert req.scheduler_status == "READY", f"Expected READY, got {req.scheduler_status}"
    return req, evidence, plan, task


# =============================================================================
# 1. READY-ONLY EXECUTION ENFORCEMENT
# =============================================================================

def test_ready_only_execution_rejection():
    """Verify that only analysis requests in READY status can be executed."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "ready", "ready")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    # Change status to QUEUED
    req.scheduler_status = "QUEUED"
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "not in READY state" in str(excinfo.value)

    # Change status to WAITING_RESOURCE
    req.scheduler_status = "WAITING_RESOURCE"
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "not in READY state" in str(excinfo.value)

    # Change status to BLOCKED
    req.scheduler_status = "BLOCKED"
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "not in READY state" in str(excinfo.value)
    db.close()


# =============================================================================
# 2. INVALID REQUEST AND MISSING EVIDENCE REJECTION
# =============================================================================

def test_invalid_request_or_missing_evidence():
    """Verify rejection of nonexistent requests or missing evidence items."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "inval", "inval")

    # Nonexistent request
    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id="nonexistent-req-id", actor=user)
    assert "not found" in str(excinfo.value)

    # Request with missing evidence
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)
    req.evidence_id = "nonexistent-evidence-id"
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "referenced by request not found" in str(excinfo.value)
    db.close()


# =============================================================================
# 3. EVIDENCE CROSS-CASE IDOR REJECTION
# =============================================================================

def test_evidence_cross_case_idor_rejection():
    """Verify that execution is blocked if evidence belongs to a different case."""
    db = SessionLocal()
    user, case1, headers1 = create_test_user_and_case(db, "idor1", "idor1")
    _, case2, _ = create_test_user_and_case(db, "idor2", "idor2")

    req, evidence1, plan, task = create_ready_analysis_request(db, case1, user)
    evidence2, _ = create_test_evidence(db, case2, filename="case2.dd")

    # Tamper with request to point to evidence from case 2
    req.evidence_id = evidence2.id
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "does not belong to the same case" in str(excinfo.value)
    db.close()


# =============================================================================
# 4. EVIDENCE VAULT INTEGRITY VERIFICATION (SUCCESS)
# =============================================================================

def test_evidence_vault_integrity_verification_success():
    """Verify that valid evidence with intact SHA-256 passes pre-flight integrity gate."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "intok", "intok")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    ev_path = ForensicExecutionService.validate_evidence_integrity(db, evidence, user)
    assert ev_path.exists()
    assert ev_path.is_file()
    db.close()


# =============================================================================
# 5. EVIDENCE TAMPER DETECTION AND BLOCKING
# =============================================================================

def test_evidence_vault_integrity_tamper_blocked():
    """Verify that modified vault file triggers hash mismatch, fails integrity, and logs custody violation."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "tamper", "tamper")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    # Tamper with the evidence file on disk
    target_path = Path(evidence.storage_path)
    target_path.write_bytes(b"TAMPERED_MODIFIED_PAYLOAD_UNAUTHORIZED")

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "mismatch detected" in str(excinfo.value)

    # Verify evidence status locked to FAILED
    db.refresh(evidence)
    assert evidence.integrity_status == "FAILED"

    # Verify ChainOfCustodyEvent logged INTEGRITY_VIOLATION
    custody_ev = (
        db.query(ChainOfCustodyEvent)
        .filter(
            ChainOfCustodyEvent.evidence_id == evidence.id,
            ChainOfCustodyEvent.event_type == "INTEGRITY_VIOLATION"
        )
        .first()
    )
    assert custody_ev is not None
    assert "pre-execution integrity check failed" in custody_ev.description

    # Verify AuditEvent logged EXECUTION_INTEGRITY_FAILED
    audit_ev = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.case_id == case.id,
            AuditEvent.event_type == "EXECUTION_INTEGRITY_FAILED"
        )
        .first()
    )
    assert audit_ev is not None
    assert "SHA-256 tamper detected" in audit_ev.details
    db.close()


# =============================================================================
# 6. DISABLED AND UNAVAILABLE TOOL REJECTION
# =============================================================================

def test_disabled_or_unavailable_tool_rejection():
    """Verify that disabled or nonexistent tool executable is rejected before launch."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "distool", "distool")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    # Disable tool in registry
    tool_def = db.query(ToolDefinition).filter(ToolDefinition.tool_id == req.selected_tool_id).first()
    tool_def.enabled = False
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "disabled in the tool registry" in str(excinfo.value)

    # Nonexistent executable
    tool_def.enabled = True
    tool_def.executable_path = "/nonexistent/binary/path/fls_fake"
    db.commit()

    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
    assert "not found or not executable" in str(excinfo.value)
    db.close()


# =============================================================================
# 7. DISALLOWED BINARY REJECTION
# =============================================================================

def test_disallowed_binary_rejection():
    """Verify that forbidden shell/scripting binaries in DISALLOWED_BINARIES are strictly blocked."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "disbin", "disbin")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    tool_def = db.query(ToolDefinition).filter(ToolDefinition.tool_id == req.selected_tool_id).first()

    for forbidden in ("bash", "sh", "powershell", "python", "cmd"):
        tool_def.executable_path = forbidden
        tool_def.binary_name = forbidden
        db.commit()

        with pytest.raises(ValueError) as excinfo:
            ForensicExecutionService.start_execution(db=db, request_id=req.id, actor=user)
        assert "DISALLOWED_BINARIES" in str(excinfo.value)
    db.close()


# =============================================================================
# 8. DEDICATED ISOLATED WORKSPACE CREATION
# =============================================================================

def test_workspace_isolation_and_permissions():
    """Verify isolated workspace directory creation, separation from vault, and 0o700 permissions."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "wsiso", "wsiso")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    workspace = ForensicExecutionService.create_isolated_workspace(case.id, "test-exec-123")
    assert workspace.exists()
    assert (workspace / "outputs").exists()

    # Verify workspace is strictly NOT inside evidence vault
    vault_dir = settings.EVIDENCE_DIR.resolve()
    assert not workspace.resolve().is_relative_to(vault_dir)

    # Verify POSIX permissions 0o700
    if sys.platform != "win32":
        mode = oct(stat.S_IMODE(workspace.stat().st_mode))
        assert mode in ("0o700", "0700")

    shutil.rmtree(workspace, ignore_errors=True)
    db.close()


# =============================================================================
# 9. PATH TRAVERSAL AND NULL BYTE REJECTION
# =============================================================================

def test_path_traversal_and_null_byte_rejection():
    """Verify that path traversal attempts, null bytes, and shell metacharacters are rejected."""
    # 1. Null byte
    with pytest.raises(ValueError) as excinfo:
        ExecutionPathValidator.validate_safe_string("malicious\0string", "test_field")
    assert "Null byte detected" in str(excinfo.value)

    # 2. Shell metacharacters
    for char in (";", "|", "&", "`", "$", "\n", "\r"):
        with pytest.raises(ValueError) as excinfo:
            ExecutionPathValidator.validate_safe_string(f"test{char}injection", "test_field")
        assert "Illegal shell character" in str(excinfo.value)

    # 3. Path traversal escape
    base = Path("/tmp/adfir_safe_base")
    base.mkdir(parents=True, exist_ok=True)
    try:
        with pytest.raises(ValueError) as excinfo:
            ExecutionPathValidator.validate_input_path("/tmp/adfir_safe_base/../../etc/passwd", base_dir=base)
        assert "Path traversal detected" in str(excinfo.value)
    finally:
        shutil.rmtree(base, ignore_errors=True)


# =============================================================================
# 10. SYMLINK ESCAPE REJECTION
# =============================================================================

def test_symlink_escape_rejection(tmp_path):
    """Verify that output collection rejects symlinks escaping the workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.txt"
    secret_file.write_text("SENSITIVE_DATA")

    # Create symlink inside workspace pointing to secret_file outside
    symlink_file = workspace / "escape_link.txt"
    try:
        symlink_file.symlink_to(secret_file)
    except OSError:
        pytest.skip("Symlinks not supported on this environment")

    # Containment check must return False
    is_contained = ExecutionPathValidator.validate_workspace_path_containment(symlink_file, workspace)
    assert is_contained is False


# =============================================================================
# 11. ARGV-ONLY SHELL=FALSE EXECUTION
# =============================================================================

def test_argv_only_shell_false_execution():
    """Verify that build_safe_argv constructs a pure list without shell expansion."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "argv", "argv")
    req, evidence, plan, task = create_ready_analysis_request(db, case, user)

    ev_path = Path(evidence.storage_path)
    ws_path = Path("/tmp/test_workspace")

    # SleuthKit tool
    argv = ForensicExecutionService.build_safe_argv(
        executable_path="/usr/bin/fls",
        tool_id="sleuthkit_fls",
        evidence_path=ev_path,
        workspace_path=ws_path,
        custom_params={"offset": "2048"}
    )
    assert argv == ["/usr/bin/fls", "-r", "-p", "-o", "2048", str(ev_path.resolve())]

    # Shell injection in parameter must raise ValueError
    with pytest.raises(ValueError) as excinfo:
        ForensicExecutionService.build_safe_argv(
            executable_path="/usr/bin/fls",
            tool_id="sleuthkit_fls",
            evidence_path=ev_path,
            workspace_path=ws_path,
            custom_params={"offset": "2048; rm -rf /"}
        )
    assert "Illegal shell character" in str(excinfo.value)
    db.close()


# =============================================================================
# 12. SUCCESSFUL PROCESS EXECUTION AND OUTPUT REGISTRATION
# =============================================================================

def test_successful_execution_and_output_hashing(tmp_path):
    """Verify successful execution of safe binary, output file discovery, SHA-256 hashing, and DB registration."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "succ", "succ")

    # Create a safe test tool script that writes an output file to outputs/
    tool_bin = tmp_path / "test_forensic_tool.sh"
    tool_bin.write_text(
        "#!/bin/sh\n"
        "mkdir -p outputs\n"
        "echo 'DISCOVERED_ARTIFACT_DATA_TEST' > outputs/extracted_file.txt\n"
        "echo 'Tool stdout log message'\n"
        "exit 0\n"
    )
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="custom_test_tool", tool_path=str(tool_bin)
    )

    # Execute with wait=True (synchronous block)
    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    assert execution.execution_status == "COMPLETED"
    assert execution.exit_code == 0
    assert execution.duration_seconds is not None
    assert execution.output_count >= 1

    # Verify AnalysisRequest updated to COMPLETED and resources freed
    db.refresh(req)
    assert req.scheduler_status == "COMPLETED"
    assert req.allocated_resources == {}

    # Verify ExecutionOutput record in DB
    outputs = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).all()
    assert len(outputs) >= 1
    out_record = outputs[0]
    assert out_record.filename == "extracted_file.txt"
    assert len(out_record.sha256_hash) == 64
    assert out_record.size_bytes > 0
    assert Path(out_record.storage_path).exists()
    db.close()


# =============================================================================
# 13. NON-ZERO EXIT CODE MARKS FAILED
# =============================================================================

def test_non_zero_exit_code_marks_failed(tmp_path):
    """Verify tool exiting with non-zero exit code is recorded as FAILED (never COMPLETED)."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "fail", "fail")

    tool_bin = tmp_path / "test_failing_tool.sh"
    tool_bin.write_text(
        "#!/bin/sh\n"
        "echo 'Fatal forensic parsing error' >&2\n"
        "exit 2\n"
    )
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="failing_tool", tool_path=str(tool_bin)
    )

    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    assert execution.execution_status == "FAILED"
    assert execution.exit_code == 2
    assert "exited with non-zero code 2" in execution.failure_reason

    # Verify AnalysisRequest updated to FAILED and resources freed
    db.refresh(req)
    assert req.scheduler_status == "FAILED"
    assert req.allocated_resources == {}
    db.close()


# =============================================================================
# 14. TIMEOUT MONITORING AND RESOURCE RELEASE
# =============================================================================

def test_timeout_monitoring_and_resource_release(tmp_path):
    """Verify process exceeding timeout is terminated safely, marked TIMEOUT, and resources freed."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "tout", "tout")

    # Tool that sleeps for 10 seconds
    tool_bin = tmp_path / "test_sleep_tool.sh"
    tool_bin.write_text(
        "#!/bin/sh\n"
        "sleep 10\n"
        "exit 0\n"
    )
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="sleep_tool", tool_path=str(tool_bin)
    )

    # Set hard timeout to 1 second
    req.timeout_seconds = 1
    db.commit()

    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    assert execution.execution_status == "TIMEOUT"
    assert "exceeded timeout" in execution.failure_reason
    assert execution.exit_code == -1

    # Verify AnalysisRequest updated to TIMEOUT and resources released
    db.refresh(req)
    assert req.scheduler_status == "TIMEOUT"
    assert req.allocated_resources == {}

    # Verify AuditEvent logged EXECUTION_TIMEOUT
    audit_ev = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.case_id == case.id,
            AuditEvent.event_type == "EXECUTION_TIMEOUT"
        )
        .first()
    )
    assert audit_ev is not None
    db.close()


# =============================================================================
# 15. CANCELLATION AND SAFE PROCESS TERMINATION
# =============================================================================

def test_cancellation_and_resource_release(tmp_path):
    """Verify actively running execution can be cancelled safely and releases reservations."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "canc", "canc")

    tool_bin = tmp_path / "test_long_run_tool.sh"
    tool_bin.write_text(
        "#!/bin/sh\n"
        "sleep 30\n"
        "exit 0\n"
    )
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="long_tool", tool_path=str(tool_bin)
    )

    # Start in background thread (wait=False)
    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=False
    )

    # Allow worker thread to spin up process
    time.sleep(0.5)

    # Cancel execution
    cancelled = ForensicExecutionService.cancel_execution(
        db=db,
        execution_id=execution.id,
        actor=user,
        reason="Investigator manual abort"
    )

    assert cancelled.execution_status == "CANCELLED"
    assert cancelled.cancellation_reason == "Investigator manual abort"

    # Verify AnalysisRequest updated to CANCELLED and resources freed
    db.refresh(req)
    assert req.scheduler_status == "CANCELLED"
    assert req.allocated_resources == {}

    # Verify AuditEvent logged EXECUTION_CANCELLED
    audit_ev = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.case_id == case.id,
            AuditEvent.event_type == "EXECUTION_CANCELLED"
        )
        .first()
    )
    assert audit_ev is not None
    db.close()


# =============================================================================
# 16. STDOUT AND STDERR CAPTURE
# =============================================================================

def test_stdout_and_stderr_capture(tmp_path):
    """Verify separate capture of stdout and stderr streams into workspace log files."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "logs", "logs")

    tool_bin = tmp_path / "test_logging_tool.sh"
    tool_bin.write_text(
        "#!/bin/sh\n"
        "echo 'STANDARD_OUTPUT_FORENSIC_STREAM'\n"
        "echo 'STANDARD_ERROR_FORENSIC_WARNING' >&2\n"
        "exit 0\n"
    )
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="log_tool", tool_path=str(tool_bin)
    )

    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    # Verify stdout content
    stdout_res = ForensicExecutionService.get_stream_content(db, execution.id, "stdout")
    assert "STANDARD_OUTPUT_FORENSIC_STREAM" in stdout_res["content"]
    assert stdout_res["is_truncated"] is False

    # Verify stderr content
    stderr_res = ForensicExecutionService.get_stream_content(db, execution.id, "stderr")
    assert "STANDARD_ERROR_FORENSIC_WARNING" in stderr_res["content"]
    assert stderr_res["is_truncated"] is False
    db.close()


# =============================================================================
# 17. EXECUTION PROVENANCE AND AUDIT LOGGING
# =============================================================================

def test_execution_provenance_and_audit_logging(tmp_path):
    """Verify complete execution provenance persistence and immutable audit event trail."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "prov", "prov")

    tool_bin = tmp_path / "test_prov_tool.sh"
    tool_bin.write_text("#!/bin/sh\necho 'OK'\nexit 0\n")
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case, user, tool_id="prov_tool", tool_path=str(tool_bin)
    )

    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    # Provenance fields verification
    assert execution.request_id == req.id
    assert execution.case_id == case.id
    assert execution.task_id == task.id
    assert execution.task_key == task.task_key
    assert execution.evidence_id == evidence.id
    assert execution.tool_id == "prov_tool"
    assert len(execution.validated_argv) >= 1
    assert execution.host_platform in ("linux", "windows", "darwin")
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.duration_seconds is not None
    assert execution.exit_code == 0

    # Audit events sequence verification
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.case_id == case.id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "EXECUTION_ACCEPTED" in event_types
    assert "WORKSPACE_CREATED" in event_types
    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_COMPLETED" in event_types
    db.close()


# =============================================================================
# 18. CASE AUTHORIZATION AND IDOR ISOLATION APIS
# =============================================================================

def test_case_authorization_and_idor_isolation(tmp_path):
    """Verify that unauthorized users cannot launch, inspect, or cancel executions."""
    db = SessionLocal()
    user1, case1, headers1 = create_test_user_and_case(db, "auth1", "auth1")
    user2, case2, headers2 = create_test_user_and_case(db, "auth2", "auth2")

    tool_bin = tmp_path / "test_api_tool.sh"
    tool_bin.write_text("#!/bin/sh\necho 'API_OK'\nexit 0\n")
    tool_bin.chmod(tool_bin.stat().st_mode | stat.S_IEXEC)

    req, evidence, plan, task = create_ready_analysis_request(
        db, case1, user1, tool_id="api_tool", tool_path=str(tool_bin)
    )

    # 1. User 2 attempts to launch execution on Case 1's request -> 403 Forbidden
    resp = client.post(f"/api/v1/executions/requests/{req.id}/start", headers=headers2)
    assert resp.status_code == 403

    # 2. User 1 launches execution successfully
    launch_resp = client.post(
        f"/api/v1/executions/requests/{req.id}/start?wait=true",
        headers=headers1
    )
    assert launch_resp.status_code == 201
    exec_id = launch_resp.json()["id"]

    # 3. User 2 attempts to view execution details -> 403 Forbidden
    get_resp = client.get(f"/api/v1/executions/{exec_id}", headers=headers2)
    assert get_resp.status_code == 403

    # 4. User 2 attempts to view stdout -> 403 Forbidden
    out_resp = client.get(f"/api/v1/executions/{exec_id}/stdout", headers=headers2)
    assert out_resp.status_code == 403

    # 5. User 2 attempts to cancel execution -> 403 Forbidden
    canc_resp = client.post(f"/api/v1/executions/{exec_id}/cancel", headers=headers2)
    assert canc_resp.status_code == 403

    # 6. User 1 successfully views stdout
    user1_stdout = client.get(f"/api/v1/executions/{exec_id}/stdout", headers=headers1)
    assert user1_stdout.status_code == 200
    assert "API_OK" in user1_stdout.json()["content"]

    # 7. User 1 lists case executions
    list_resp = client.get(f"/api/v1/cases/{case1.id}/executions", headers=headers1)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1
    db.close()
