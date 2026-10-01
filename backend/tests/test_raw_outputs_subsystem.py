"""
ADFIR — Phase 2 / Step 10: Raw Forensic Outputs Subsystem Tests

Comprehensive verification of:
1. Tool output file registration with case/request/execution/task/tool provenance
2. stdout and stderr registration as separate uninterpreted raw artifacts
3. Cryptographic SHA-256 hash calculation and verification
4. Output integrity verification passing on intact artifacts
5. Output integrity verification detecting tampered artifact content
6. Output integrity verification detecting missing artifact files on disk
7. Duplicate output identity detection and overwrite prevention (OUTPUT_DUPLICATE_REJECTED)
8. Output storage containment in execution workspace and prohibition of vault storage
9. Path traversal and symlink escape rejection
10. Safe file permissions enforcement (0o600)
11. Failed execution output preservation with exit code and execution status
12. Output metadata and provenance retrieval
13. Output filtering by output_type (TOOL_OUTPUT, STDOUT, STDERR)
14. Raw output file download and streaming with path-traversal safety
15. Request-level and case-level raw output aggregation
16. Strict case authorization, RBAC, and IDOR protection across all endpoints
17. Complete audit trail generation for registration, hashing, integrity, and retrieval
18. Invariant: Raw forensic output is evidence-derived data, NOT a conclusion
"""

import os
import stat
import uuid
import shutil
import pytest
from pathlib import Path
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.core.database import SessionLocal
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
    AuditEvent
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.integrity import calculate_sha256
from backend.app.services.scheduler import ResourceAwareScheduler
from backend.app.services.execution import ForensicExecutionService
from backend.app.services.raw_outputs import (
    RawOutputsService,
    RawOutputsSecurityError
)

client = TestClient(app)


def create_test_user_and_case(db, username_prefix="output_usr", case_prefix="output_case"):
    """Creates a user and authorized case."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{username_prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Forensic Investigator {username_prefix}",
        organization="DFIR Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("Investigate@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-out-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing raw forensic output subsystem",
        created_by=user.name,
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

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-ADFIR-Bootstrap-Secret": settings.ADFIR_INTERNAL_SECRET or "bootstrap-secret"
    }

    return user, case, headers



def create_test_evidence(db, case, filename="disk.dd", content=b"RAW_EVIDENCE_FOR_OUTPUT_TESTS"):
    """Creates a real test evidence item in vault."""
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


def setup_execution_fixture(db, case, user, tool_script_content=None, tool_id="out_test_tool", exit_code=0):
    """Sets up a complete Plan -> Task -> Tool -> READY Request -> Execution run."""
    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Raw Output Test Plan",
        strategy_summary="Testing raw outputs collection",
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
        task_key=f"task-out-{uuid.uuid4().hex[:4]}",
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

    # Tool script creation
    script_dir = settings.DATA_DIR / "test_tools"
    script_dir.mkdir(parents=True, exist_ok=True)
    tool_script = script_dir / f"{tool_id}.sh"

    if tool_script_content is None:
        tool_script_content = (
            "#!/bin/sh\n"
            "mkdir -p outputs\n"
            "echo 'FORENSIC_RAW_OUTPUT_DATA_1' > outputs/artifact1.raw\n"
            "echo 'FORENSIC_RAW_OUTPUT_DATA_2' > outputs/artifact2.txt\n"
            "echo 'STANDARD_OUTPUT_MESSAGE_LINE_1'\n"
            "echo 'STANDARD_OUTPUT_MESSAGE_LINE_2'\n"
            ">&2 echo 'STANDARD_ERROR_DIAGNOSTIC_MESSAGE'\n"
            f"exit {exit_code}\n"
        )

    tool_script.write_text(tool_script_content)
    tool_script.chmod(tool_script.stat().st_mode | stat.S_IEXEC)

    db_tool = db.query(ToolDefinition).filter(ToolDefinition.tool_id == tool_id).first()
    if not db_tool:
        db_tool = ToolDefinition(
            tool_id=tool_id,
            name=tool_id,
            display_name="Output Test Tool",
            binary_name=tool_script.name,
            executable_path=str(tool_script),
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
        db_tool.executable_path = str(tool_script)
        db_tool.binary_name = tool_script.name
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
        selection_rationale="Output test selection"
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

    execution = ForensicExecutionService.start_execution(
        db=db,
        request_id=req.id,
        actor=user,
        wait=True
    )

    return user, case, evidence, plan, task, req, execution


# =============================================================================
# 1. OUTPUT REGISTRATION & PROVENANCE
# =============================================================================

def test_tool_outputs_and_logs_registered_with_full_provenance():
    """Verify tool outputs, stdout, and stderr are registered as separate raw artifacts with full provenance."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "prov", "prov")
    _, _, evidence, plan, task, req, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_prov_1"
    )

    assert execution.execution_status == "COMPLETED"
    assert execution.output_count >= 3 # 2 tool outputs + stdout + stderr

    # Query all outputs for this execution
    outputs = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).all()
    assert len(outputs) >= 4 # artifact1.raw, artifact2.txt, stdout.log, stderr.log

    output_types = {o.output_type for o in outputs}
    assert "TOOL_OUTPUT" in output_types
    assert "STDOUT" in output_types
    assert "STDERR" in output_types

    # Verify provenance associations on every registered output
    for o in outputs:
        assert o.case_id == case.id
        assert o.execution_id == execution.id
        assert o.request_id == req.id
        assert o.task_id == task.id
        assert o.evidence_id == evidence.id
        assert o.tool_id == execution.tool_id
        assert o.tool_version is not None
        assert o.size_bytes > 0
        assert len(o.sha256_hash) == 64
        assert o.exit_code == 0
        assert o.execution_status == "COMPLETED"
        assert Path(o.storage_path).exists()

        # Metadata JSON provenance check
        assert o.metadata_json["tool_id"] == execution.tool_id
        assert o.metadata_json["execution_id"] == execution.id
        assert o.metadata_json["task_key"] == task.task_key
        assert "extension" in o.metadata_json

    db.close()


# =============================================================================
# 2. SEPARATE STDOUT / STDERR ARTIFACT REGISTRATION
# =============================================================================

def test_stdout_and_stderr_registered_separately_without_interpretation():
    """Verify stdout and stderr logs are preserved verbatim as distinct uninterpreted raw artifacts."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "logs", "logs")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_logs_1"
    )

    stdout_rec = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "STDOUT"
    ).first()

    stderr_rec = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "STDERR"
    ).first()

    assert stdout_rec is not None
    assert stdout_rec.filename == "stdout.log"
    assert stdout_rec.mime_type == "text/plain"
    stdout_content = Path(stdout_rec.storage_path).read_text()
    assert "STANDARD_OUTPUT_MESSAGE_LINE_1" in stdout_content
    assert "STANDARD_OUTPUT_MESSAGE_LINE_2" in stdout_content

    assert stderr_rec is not None
    assert stderr_rec.filename == "stderr.log"
    assert stderr_rec.mime_type == "text/plain"
    stderr_content = Path(stderr_rec.storage_path).read_text()
    assert "STANDARD_ERROR_DIAGNOSTIC_MESSAGE" in stderr_content

    # Invariant: No findings or conclusions in stdout/stderr metadata
    assert "finding" not in stdout_rec.metadata_json
    assert "conclusion" not in stdout_rec.metadata_json

    db.close()


# =============================================================================
# 3. CRYPTOGRAPHIC INTEGRITY VERIFICATION (PASSED)
# =============================================================================

def test_output_integrity_verification_passed():
    """Verify cryptographic SHA-256 integrity verification passes for intact outputs."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "integ", "integ")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_integ_1"
    )

    tool_output = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "TOOL_OUTPUT"
    ).first()
    assert tool_output is not None

    res = RawOutputsService.verify_output_integrity(db, tool_output.id, actor=user)
    assert res["integrity_verified"] is True
    assert res["expected_sha256"] == tool_output.sha256_hash
    assert res["calculated_sha256"] == tool_output.sha256_hash
    assert res["size_bytes"] == tool_output.size_bytes

    # Verify audit event logged
    audit = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "OUTPUT_INTEGRITY_VERIFIED"
    ).first()
    assert audit is not None
    assert tool_output.id in audit.details

    db.close()


# =============================================================================
# 4. CRYPTOGRAPHIC INTEGRITY VERIFICATION (TAMPER DETECTED)
# =============================================================================

def test_output_integrity_verification_tamper_detected():
    """Verify cryptographic verification detects tampered raw output files on disk."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "tamper", "tamper")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_tamper_1"
    )

    tool_output = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "TOOL_OUTPUT"
    ).first()

    # Tamper with file content on disk
    fpath = Path(tool_output.storage_path)
    fpath.write_bytes(b"MALICIOUS_TAMPERED_OUTPUT_CONTENT")

    res = RawOutputsService.verify_output_integrity(db, tool_output.id, actor=user)
    assert res["integrity_verified"] is False
    assert res["expected_sha256"] == tool_output.sha256_hash
    assert res["calculated_sha256"] != tool_output.sha256_hash

    # Verify tampering audit event logged
    audit = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "OUTPUT_INTEGRITY_FAILED"
    ).first()
    assert audit is not None
    assert "FAILED" in audit.details

    db.close()


# =============================================================================
# 5. CRYPTOGRAPHIC INTEGRITY VERIFICATION (MISSING FILE)
# =============================================================================

def test_output_integrity_verification_missing_file():
    """Verify cryptographic verification detects deleted/missing raw output files."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "miss", "miss")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_miss_1"
    )

    tool_output = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "TOOL_OUTPUT"
    ).first()

    # Delete the output file from disk
    fpath = Path(tool_output.storage_path)
    fpath.unlink()

    res = RawOutputsService.verify_output_integrity(db, tool_output.id, actor=user)
    assert res["integrity_verified"] is False
    assert res["calculated_sha256"] == "MISSING"

    audit = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "OUTPUT_INTEGRITY_FAILED"
    ).first()
    assert audit is not None
    assert "missing" in audit.details.lower()

    db.close()


# =============================================================================
# 6. DUPLICATE OUTPUT IDENTITY & OVERWRITE PREVENTION
# =============================================================================

def test_duplicate_output_identity_and_overwrite_prevention():
    """Verify duplicate outputs are detected and never silently overwritten."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "dup", "dup")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_dup_1"
    )

    ws = Path(execution.workspace_path)
    existing_output = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.output_type == "TOOL_OUTPUT"
    ).first()

    # Attempt to re-register the exact same output file
    target_file = Path(existing_output.storage_path)
    rec, is_new = RawOutputsService.register_output(
        db=db,
        execution=execution,
        file_path=target_file,
        output_type="TOOL_OUTPUT",
        relative_path=existing_output.relative_path
    )

    assert is_new is False
    assert rec.id == existing_output.id

    # Verify duplicate rejection audit event
    audit = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "OUTPUT_DUPLICATE_REJECTED"
    ).first()
    assert audit is not None
    assert existing_output.filename in audit.details

    db.close()


# =============================================================================
# 7. PROHIBITION OF EVIDENCE VAULT OUTPUT STORAGE
# =============================================================================

def test_prohibition_of_evidence_vault_output_storage():
    """Verify that outputs can NEVER be registered inside or point into the evidence vault."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "vaultsec", "vaultsec")
    _, _, evidence, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_vsec_1"
    )

    vault_file = Path(evidence.storage_path)
    assert (settings.EVIDENCE_DIR / "vault") in vault_file.parents

    with pytest.raises(RawOutputsSecurityError) as excinfo:
        RawOutputsService.register_output(
            db=db,
            execution=execution,
            file_path=vault_file,
            output_type="TOOL_OUTPUT"
        )
    assert "evidence vault" in str(excinfo.value).lower()

    db.close()


# =============================================================================
# 8. PATH TRAVERSAL AND WORKSPACE ESCAPE REJECTION
# =============================================================================

def test_path_traversal_and_workspace_escape_rejection(tmp_path):
    """Verify that output paths with traversal tokens or escaping the workspace are rejected."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "trav", "trav")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_trav_1"
    )

    # File outside workspace
    outside_file = tmp_path / "outside_output.txt"
    outside_file.write_text("OUTSIDE")

    with pytest.raises(RawOutputsSecurityError) as excinfo:
        RawOutputsService.register_output(
            db=db,
            execution=execution,
            file_path=outside_file,
            output_type="TOOL_OUTPUT"
        )
    assert "escapes workspace" in str(excinfo.value).lower()

    # Null byte path
    with pytest.raises(RawOutputsSecurityError) as excinfo:
        RawOutputsService.validate_storage_path(
            Path("/tmp/test\x00escape"),
            Path(execution.workspace_path),
            case.id
        )
    assert "null byte" in str(excinfo.value).lower()

    db.close()


# =============================================================================
# 9. SAFE FILE PERMISSIONS ENFORCEMENT
# =============================================================================

def test_safe_file_permissions_enforced():
    """Verify output artifacts are restricted to 0o600 (read/write only by owner)."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "perm", "perm")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_perm_1"
    )

    outputs = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).all()
    for o in outputs:
        p = Path(o.storage_path)
        mode = p.stat().st_mode & 0o777
        # Strict POSIX permission: owner rw, others no access
        assert mode == 0o600 or (mode & 0o077 == 0), f"File {p} permissions ({oct(mode)}) not safe"

    db.close()


# =============================================================================
# 10. FAILED EXECUTION RAW OUTPUT PRESERVATION
# =============================================================================

def test_failed_execution_preserves_outputs_and_logs():
    """Verify non-zero exit code execution preserves tool outputs, stdout, stderr, and failure status."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "failout", "failout")

    fail_script = (
        "#!/bin/sh\n"
        "mkdir -p outputs\n"
        "echo 'PARTIAL_CRASH_ARTIFACT' > outputs/crash_dump.log\n"
        "echo 'Process crashing unexpectedly'\n"
        ">&2 echo 'Fatal error: memory corruption at 0xdeadbeef'\n"
        "exit 2\n"
    )

    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_script_content=fail_script, tool_id="tool_fail_1", exit_code=2
    )

    assert execution.execution_status == "FAILED"
    assert execution.exit_code == 2

    outputs = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).all()
    assert len(outputs) >= 3 # crash_dump.log, stdout.log, stderr.log

    for o in outputs:
        assert o.exit_code == 2
        assert o.execution_status == "FAILED"
        assert o.metadata_json["exit_code"] == 2
        assert o.metadata_json["execution_status"] == "FAILED"

    # Verify crash output is preserved and hashed
    crash_art = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.filename == "crash_dump.log"
    ).first()
    assert crash_art is not None
    assert crash_art.size_bytes > 0
    assert len(crash_art.sha256_hash) == 64

    db.close()


# =============================================================================
# 11. REST API: LIST EXECUTION OUTPUTS & FILTER BY TYPE
# =============================================================================

def test_api_list_execution_outputs_with_type_filter():
    """Verify GET /cases/{case_id}/executions/{execution_id}/outputs and output_type filter."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "apilist", "apilist")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_apilist_1"
    )

    # 1. List all outputs
    res = client.get(f"/api/v1/cases/{case.id}/executions/{execution.id}/outputs", headers=headers)
    assert res.status_code == 200
    all_outs = res.json()
    assert len(all_outs) >= 4

    # 2. Filter by TOOL_OUTPUT
    res_tool = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/outputs?output_type=TOOL_OUTPUT",
        headers=headers
    )
    assert res_tool.status_code == 200
    tool_outs = res_tool.json()
    assert len(tool_outs) >= 2
    assert all(o["output_type"] == "TOOL_OUTPUT" for o in tool_outs)

    # 3. Filter by STDOUT
    res_stdout = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/outputs?output_type=STDOUT",
        headers=headers
    )
    assert res_stdout.status_code == 200
    stdout_outs = res_stdout.json()
    assert len(stdout_outs) == 1
    assert stdout_outs[0]["output_type"] == "STDOUT"
    assert stdout_outs[0]["filename"] == "stdout.log"

    # 4. Filter by STDERR
    res_stderr = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/outputs?output_type=STDERR",
        headers=headers
    )
    assert res_stderr.status_code == 200
    stderr_outs = res_stderr.json()
    assert len(stderr_outs) == 1
    assert stderr_outs[0]["output_type"] == "STDERR"
    assert stderr_outs[0]["filename"] == "stderr.log"

    # 5. Invalid filter returns 400
    res_inv = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/outputs?output_type=INVALID_TYPE",
        headers=headers
    )
    assert res_inv.status_code == 400

    db.close()


# =============================================================================
# 12. REST API: OUTPUT METADATA & INTEGRITY ENDPOINTS
# =============================================================================

def test_api_get_output_metadata_and_integrity():
    """Verify GET /outputs/{output_id} and /outputs/{output_id}/integrity."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "apimeta", "apimeta")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_apimeta_1"
    )

    out = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).first()

    # Metadata endpoint
    res_meta = client.get(f"/api/v1/outputs/{out.id}", headers=headers)
    assert res_meta.status_code == 200
    data = res_meta.json()
    assert data["id"] == out.id
    assert data["filename"] == out.filename
    assert data["sha256_hash"] == out.sha256_hash
    assert data["size_bytes"] == out.size_bytes
    assert data["tool_id"] == execution.tool_id

    # Integrity verification endpoint
    res_integ = client.get(f"/api/v1/outputs/{out.id}/integrity", headers=headers)
    assert res_integ.status_code == 200
    integ_data = res_integ.json()
    assert integ_data["output_id"] == out.id
    assert integ_data["integrity_verified"] is True
    assert integ_data["expected_sha256"] == out.sha256_hash
    assert integ_data["calculated_sha256"] == out.sha256_hash

    # Non-existent output ID returns 404
    res_404 = client.get(f"/api/v1/outputs/{uuid.uuid4()}", headers=headers)
    assert res_404.status_code == 404

    db.close()


# =============================================================================
# 13. REST API: SECURE DOWNLOAD & STREAMING
# =============================================================================

def test_api_download_and_content_streaming():
    """Verify GET /outputs/{output_id}/download and /outputs/{output_id}/content."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "apidl", "apidl")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_apidl_1"
    )

    out = db.query(ExecutionOutput).filter(
        ExecutionOutput.execution_id == execution.id,
        ExecutionOutput.filename == "artifact1.raw"
    ).first()

    # Download endpoint
    res_dl = client.get(f"/api/v1/outputs/{out.id}/download", headers=headers)
    assert res_dl.status_code == 200
    assert "FORENSIC_RAW_OUTPUT_DATA_1" in res_dl.text

    # Content endpoint
    res_cnt = client.get(f"/api/v1/outputs/{out.id}/content", headers=headers)
    assert res_cnt.status_code == 200
    assert "FORENSIC_RAW_OUTPUT_DATA_1" in res_cnt.text

    # Verify retrieval audit event
    audit = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "OUTPUT_RETRIEVED"
    ).first()
    assert audit is not None
    assert out.id in audit.details

    db.close()


# =============================================================================
# 14. REST API: REQUEST-LEVEL & CASE-LEVEL AGGREGATION
# =============================================================================

def test_api_request_and_case_level_output_listing():
    """Verify GET /scheduler/requests/{request_id}/outputs and /cases/{case_id}/outputs."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "apiagg", "apiagg")
    _, _, _, _, _, req, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_apiagg_1"
    )

    # Request-level outputs
    res_req = client.get(f"/api/v1/scheduler/requests/{req.id}/outputs", headers=headers)
    assert res_req.status_code == 200
    req_outs = res_req.json()
    assert len(req_outs) >= 4

    # Case-level outputs
    res_case = client.get(f"/api/v1/cases/{case.id}/outputs", headers=headers)
    assert res_case.status_code == 200
    case_outs = res_case.json()
    assert len(case_outs) >= 4

    db.close()


# =============================================================================
# 15. CASE AUTHORIZATION & IDOR ISOLATION
# =============================================================================

def test_case_authorization_and_idor_isolation():
    """Verify unauthorized users cannot list, verify, or download outputs from other cases."""
    db = SessionLocal()
    user_a, case_a, headers_a = create_test_user_and_case(db, "user_a", "case_a")
    user_b, case_b, headers_b = create_test_user_and_case(db, "user_b", "case_b")

    _, _, _, _, _, _, exec_a = setup_execution_fixture(
        db, case_a, user_a, tool_id="tool_sec_a"
    )

    out_a = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == exec_a.id).first()

    # User B (not member of case A) cannot access User A's outputs -> 403 Forbidden
    res_list = client.get(
        f"/api/v1/cases/{case_a.id}/executions/{exec_a.id}/outputs",
        headers=headers_b
    )
    assert res_list.status_code == 403

    res_meta = client.get(f"/api/v1/outputs/{out_a.id}", headers=headers_b)
    assert res_meta.status_code == 403

    res_integ = client.get(f"/api/v1/outputs/{out_a.id}/integrity", headers=headers_b)
    assert res_integ.status_code == 403

    res_dl = client.get(f"/api/v1/outputs/{out_a.id}/download", headers=headers_b)
    assert res_dl.status_code == 403

    # Cross-case IDOR mismatch: case_b path with exec_a -> 400 Bad Request
    res_idor = client.get(
        f"/api/v1/cases/{case_b.id}/executions/{exec_a.id}/outputs",
        headers=headers_b
    )
    assert res_idor.status_code == 400

    # Unauthenticated request returns 401
    res_noauth = client.get(f"/api/v1/outputs/{out_a.id}")
    assert res_noauth.status_code == 401

    db.close()


# =============================================================================
# 16. INVARIANT: RAW OUTPUTS ARE NOT CONCLUSIONS
# =============================================================================

def test_invariant_raw_outputs_are_not_conclusions():
    """Verify raw output records contain evidence-derived data only and never analyst conclusions."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "inv", "inv")
    _, _, _, _, _, _, execution = setup_execution_fixture(
        db, case, user, tool_id="tool_inv_1"
    )

    outputs = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution.id).all()
    for o in outputs:
        # Must NOT possess finding severity, MITRE tactics, or analyst opinions
        meta = o.metadata_json or {}
        assert "severity" not in meta
        assert "mitre_attack" not in meta
        assert "malicious" not in meta
        assert "verdict" not in meta
        assert "recommendation" not in meta

    db.close()
