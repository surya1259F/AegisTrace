import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import Case, EvidenceItem, ToolExecution, ChainOfCustodyEvent
from backend.app.services.vault import (
    stage_evidence_to_vault,
    get_vault_dir,
    apply_os_read_only,
    remove_os_read_only,
    verify_os_read_only
)
from agents.disk.disk_agent import DiskAgent
from agents.memory.memory_agent import MemoryAgent
from agents.malware.malware_agent import MalwareAgent
from agents.log.log_agent import LogAgent

client = TestClient(app)

FIXTURE_MARKER = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "malware" / "test_marker_file.txt"
FIXTURE_CLEAN = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "malware" / "clean_file.txt"

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def _create_case(test_client: TestClient, name_prefix="Vault Test Case") -> str:
    res = test_client.post("/api/investigations/", json={
        "name": f"{name_prefix} {uuid.uuid4().hex[:6]}",
        "description": "Test case for evidence vault validation"
    })
    assert res.status_code == 201
    return res.json()["id"]

def _create_temp_evidence_file(content: bytes = b"FORENSIC_EVIDENCE_DATA_SAMPLE_12345", suffix: str = ".txt") -> str:
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name

def _cleanup_file(path_str: str):
    if path_str and os.path.exists(path_str):
        p = Path(path_str)
        remove_os_read_only(p)
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

# -----------------------------------------------------------------------------
# Test 1: Intake Creates Vault Copy
# -----------------------------------------------------------------------------
def test_intake_creates_vault_copy():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"INTAKE_VAULT_TEST_DATA", suffix=".bin")
    try:
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path,
            "notes": "Testing vault file creation"
        })
        assert intake_res.status_code == 201
        data = intake_res.json()
        storage_path = data["storage_path"]
        evidence_id = data["id"]

        assert storage_path is not None
        assert os.path.exists(storage_path)
        assert os.path.isfile(storage_path)
        assert f"/vault/{inv_id}/{evidence_id}/" in storage_path

        with open(storage_path, "rb") as f:
            vault_content = f.read()
        assert vault_content == b"INTAKE_VAULT_TEST_DATA"
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 2: Source and Vault Hashes Match
# -----------------------------------------------------------------------------
def test_source_and_vault_hashes_match():
    inv_id = _create_case(client)
    content = b"CRYPTOGRAPHIC_HASH_RECONCILIATION_VALIDATION"
    tmp_path = _create_temp_evidence_file(content=content, suffix=".raw")
    try:
        expected_hash = hashlib.sha256(content).hexdigest()

        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201
        data = intake_res.json()

        assert data["sha256"].lower() == expected_hash.lower()

        # Re-verify by calculating hash of vault copy on disk
        vault_path = data["storage_path"]
        with open(vault_path, "rb") as f:
            actual_vault_hash = hashlib.sha256(f.read()).hexdigest()

        assert actual_vault_hash.lower() == expected_hash.lower()
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 3: Database Records Vault Path in storage_path
# -----------------------------------------------------------------------------
def test_database_records_vault_path_in_storage_path():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"DB_STORAGE_PATH_RECORDING", suffix=".dd")
    try:
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201
        ev_id = intake_res.json()["id"]

        db = SessionLocal()
        try:
            ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
            assert ev is not None
            assert ev.storage_path is not None
            assert Path(ev.storage_path).is_absolute()
            assert ev.storage_path != ev.original_path
            assert f"vault/{inv_id}/{ev_id}" in ev.storage_path
        finally:
            db.close()
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 4: Original Path Retains Source Provenance
# -----------------------------------------------------------------------------
def test_original_path_retains_source_provenance():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"SOURCE_PROVENANCE_TRACKING", suffix=".img")
    try:
        expected_src = str(Path(tmp_path).resolve())
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201
        ev_id = intake_res.json()["id"]

        db = SessionLocal()
        try:
            ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
            assert ev is not None
            assert ev.original_path == expected_src
        finally:
            db.close()
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 5: Analysis Receives Storage Path (Vault Copy)
# -----------------------------------------------------------------------------
def test_analysis_receives_storage_path():
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_MARKER)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]
    vault_path = ev_data["storage_path"]
    original_path = ev_data["original_path"]

    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    assert scan_res.status_code == 200

    db = SessionLocal()
    try:
        execution = db.query(ToolExecution).filter_by(evidence_id=ev_id).order_by(ToolExecution.created_at.desc()).first()
        assert execution is not None
        # command_args must target the vault copy (storage_path), NOT original_path
        args_str = " ".join(execution.command_args)
        assert vault_path in args_str
        assert original_path not in args_str or vault_path == original_path
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 6: Vault Copy OS Read-Only Verified
# -----------------------------------------------------------------------------
def test_vault_copy_os_read_only_verified():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"READ_ONLY_OS_ENFORCEMENT", suffix=".bin")
    try:
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201
        ev_data = intake_res.json()
        assert ev_data["read_only_verified"] is True

        vault_path = Path(ev_data["storage_path"])
        assert verify_os_read_only(vault_path) is True

        # Actual write attempt must be denied by OS
        with pytest.raises(PermissionError):
            with open(vault_path, "ab") as f:
                f.write(b"ILLEGAL_WRITE_ATTEMPT")
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 7: Source Remains Unmodified During Intake
# -----------------------------------------------------------------------------
def test_source_remains_unmodified_during_intake():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"SOURCE_MUST_REMAIN_UNTOUCHED", suffix=".dat")
    try:
        src_p = Path(tmp_path)
        stat_before = src_p.stat()
        with open(tmp_path, "rb") as f:
            hash_before = hashlib.sha256(f.read()).hexdigest()

        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201

        stat_after = src_p.stat()
        with open(tmp_path, "rb") as f:
            hash_after = hashlib.sha256(f.read()).hexdigest()

        assert hash_before == hash_after
        assert stat_before.st_size == stat_after.st_size
        assert stat_before.st_mtime == stat_after.st_mtime
        # Original file permissions should remain writable by owner (not locked down)
        assert os.access(tmp_path, os.W_OK) is True
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 8: Pre-Analysis Tamper Detection Blocks Execution
# -----------------------------------------------------------------------------
def test_pre_analysis_tamper_detection_blocks_execution():
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_MARKER)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]
    vault_path = Path(ev_data["storage_path"])

    # Tamper with vault file bytes
    remove_os_read_only(vault_path)
    with open(vault_path, "ab") as f:
        f.write(b"\nMALICIOUS_TAMPERED_INJECTED_BYTES")
    apply_os_read_only(vault_path)

    # Attempt to execute analysis - must be blocked by pre-analysis gate
    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    assert scan_res.status_code == 422
    err_detail = scan_res.json()["detail"]
    assert "Evidence integrity compromised" in err_detail
    assert "hash mismatch" in err_detail.lower()

# -----------------------------------------------------------------------------
# Test 9: Tamper Updates Integrity Status to FAILED
# -----------------------------------------------------------------------------
def test_tamper_updates_integrity_status_to_failed():
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_MARKER)
    })
    assert intake_res.status_code == 201
    ev_id = intake_res.json()["id"]
    vault_path = Path(intake_res.json()["storage_path"])

    # Tamper with vault file
    remove_os_read_only(vault_path)
    with open(vault_path, "ab") as f:
        f.write(b"TAMPER")
    apply_os_read_only(vault_path)

    client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })

    db = SessionLocal()
    try:
        ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev is not None
        assert ev.integrity_status == "FAILED"
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 10: Tamper Appends Custody INTEGRITY_VIOLATION
# -----------------------------------------------------------------------------
def test_tamper_appends_custody_integrity_violation():
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_MARKER)
    })
    assert intake_res.status_code == 201
    ev_id = intake_res.json()["id"]
    vault_path = Path(intake_res.json()["storage_path"])

    remove_os_read_only(vault_path)
    with open(vault_path, "ab") as f:
        f.write(b"CORRUPT")
    apply_os_read_only(vault_path)

    client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })

    db = SessionLocal()
    try:
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).first()
        assert violation is not None
        assert "mismatch" in violation.description.lower()
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 11: Missing Vault File Blocks Analysis
# -----------------------------------------------------------------------------
def test_missing_vault_file_blocks_analysis():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"MISSING_FILE_TEST", suffix=".txt")
    try:
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path
        })
        assert intake_res.status_code == 201
        ev_id = intake_res.json()["id"]
        vault_path = Path(intake_res.json()["storage_path"])

        # Delete vault file completely
        remove_os_read_only(vault_path)
        vault_path.unlink()

        scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
            "evidence_id": ev_id,
            "rule_id": "adfir_test_rules"
        })
        assert scan_res.status_code == 422
        assert "not found in storage" in scan_res.json()["detail"].lower()

        db = SessionLocal()
        try:
            ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
            assert ev.integrity_status == "FAILED"
            violation = db.query(ChainOfCustodyEvent).filter_by(
                evidence_id=ev_id,
                event_type="INTEGRITY_VIOLATION"
            ).first()
            assert violation is not None
            assert "not found in storage" in violation.description.lower()
        finally:
            db.close()
    finally:
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 12: Post-Analysis Hash Verification Succeeds
# -----------------------------------------------------------------------------
def test_post_analysis_hash_verification_succeeds(monkeypatch):
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_CLEAN)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]

    from backend.app.api.endpoints.investigations import malware_agent
    monkeypatch.setattr(
        malware_agent,
        "analyze",
        lambda evidence_item, parameters=None: {
            "status": "SUCCESS",
            "findings": [],
            "provenance": {"tool": "yara", "version": "4.2.3"}
        }
    )

    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    assert scan_res.status_code == 200
    assert scan_res.json()["status"] == "SUCCESS"

    db = SessionLocal()
    try:
        post_event = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VERIFIED_POST_ANALYSIS"
        ).first()
        assert post_event is not None
        assert post_event.sha256.lower() == ev_data["sha256"].lower()
        assert "Zero bytes altered" in post_event.description
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 13: Simulated Tool Alteration Triggers Post-Analysis Failure
# -----------------------------------------------------------------------------
def test_simulated_tool_alteration_triggers_post_analysis_failure(monkeypatch):
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_CLEAN)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]
    vault_path = Path(ev_data["storage_path"])

    from backend.app.api.endpoints.investigations import malware_agent
    orig_analyze = malware_agent.analyze

    def mutating_analyze(evidence_item, parameters=None):
        result = orig_analyze(evidence_item, parameters)
        # Mutate vault copy during execution
        remove_os_read_only(vault_path)
        with open(vault_path, "ab") as f:
            f.write(b"\nUNAUTHORIZED_TOOL_SIDE_EFFECT_MUTATION")
        apply_os_read_only(vault_path)
        return result

    monkeypatch.setattr(malware_agent, "analyze", mutating_analyze)

    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    assert scan_res.status_code == 500
    assert "CRITICAL: Evidence was modified during analysis!" in scan_res.json()["detail"]

    db = SessionLocal()
    try:
        ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev.integrity_status == "FAILED"
        execution = db.query(ToolExecution).filter_by(evidence_id=ev_id).order_by(ToolExecution.created_at.desc()).first()
        assert execution.status == "FAILED"
        assert "modified during tool execution" in execution.error_message
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).order_by(ChainOfCustodyEvent.timestamp.desc()).first()
        assert violation is not None
        assert "Post-analysis tampering detected" in violation.description
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 14: Atomic Cleanup on Copy Failure
# -----------------------------------------------------------------------------
def test_atomic_cleanup_on_copy_failure(monkeypatch):
    tmp_path = _create_temp_evidence_file(content=b"ATOMIC_CLEANUP_TEST_CONTENT", suffix=".txt")
    test_case_id = f"atomic-test-{uuid.uuid4().hex[:6]}"
    test_ev_id = f"ev-{uuid.uuid4().hex[:6]}"
    vault_dir = get_vault_dir(test_case_id, test_ev_id)
    temp_path = vault_dir / f".tmp_{test_ev_id}.part"

    from backend.app.services import vault
    orig_open = open

    def failing_open(path, mode="r", *args, **kwargs):
        if str(temp_path) in str(path) and "wb" in mode:
            f = orig_open(path, mode, *args, **kwargs)
            f.write(b"PARTIAL_CONTENT_WRITTEN")
            f.flush()
            raise IOError("Simulated I/O failure mid-stream")
        return orig_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", failing_open)

    with pytest.raises(IOError, match="Simulated I/O failure mid-stream"):
        stage_evidence_to_vault(tmp_path, test_case_id, test_ev_id)

    # Verify temp .part file was deleted
    assert not temp_path.exists()

    _cleanup_file(tmp_path)
    if vault_dir.exists():
        shutil.rmtree(vault_dir, ignore_errors=True)

# -----------------------------------------------------------------------------
# Test 15: Specialist Agents Prioritize Vault Path (storage_path)
# -----------------------------------------------------------------------------
def test_specialist_agents_handle_vault_path():
    # Verify DiskAgent, MemoryAgent, MalwareAgent, and LogAgent
    # properly prioritize storage_path over original_path
    agents = [
        ("DiskAgent", DiskAgent(), "disk_image"),
        ("MemoryAgent", MemoryAgent(), "memory_dump"),
        ("MalwareAgent", MalwareAgent(), "executable"),
        ("LogAgent", LogAgent(), "log"),
    ]

    for name, agent, ev_type in agents:
        # Case A: storage_path provided with nonexistent dummy path -> error references storage_path
        ev_item_with_vault = {
            "investigation_id": "test-case-id",
            "id": "ev-id-1",
            "name": "sample.raw",
            "evidence_type": ev_type,
            "original_path": "/original/path/should/not/be/used/sample.raw",
            "storage_path": "/vault/managed/evidence/sample.raw"
        }
        res = agent.analyze(ev_item_with_vault)
        assert res["status"] in ["INVALID_EVIDENCE_PATH", "FAILED"], f"{name} failed status check"
        assert "/vault/managed/evidence/sample.raw" in res.get("error", ""), f"{name} did not reference storage_path"

        # Case B: Only original_path provided -> must reject un-vaulted evidence
        ev_item_fallback = {
            "investigation_id": "test-case-id",
            "id": "ev-id-2",
            "name": "sample.raw",
            "evidence_type": ev_type,
            "original_path": "/legacy/original/path/sample.raw"
        }
        res_fallback = agent.analyze(ev_item_fallback)
        assert res_fallback["status"] == "UNVAULTED_EVIDENCE_REJECTED", f"{name} should reject missing storage_path"
        assert "storage_path" in res_fallback.get("error", "").lower()

        # Case C: storage_path equals original_path -> must reject un-vaulted evidence
        ev_item_identical = {
            "investigation_id": "test-case-id",
            "id": "ev-id-3",
            "name": "sample.raw",
            "evidence_type": ev_type,
            "original_path": "/original/sample.raw",
            "storage_path": "/original/sample.raw"
        }
        res_identical = agent.analyze(ev_item_identical)
        assert res_identical["status"] == "UNVAULTED_EVIDENCE_REJECTED", f"{name} should reject identical paths"
        assert "storage_path matches original_path" in res_identical.get("error", "").lower()

# -----------------------------------------------------------------------------
# Test 16: P0-1 Post-Analysis Gate Runs on Tool Exception With Mutation
# -----------------------------------------------------------------------------
def test_post_analysis_gate_runs_on_tool_exception_with_mutation(monkeypatch):
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_CLEAN)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]
    vault_path = Path(ev_data["storage_path"])

    from backend.app.api.endpoints.investigations import malware_agent

    def exploding_mutating_analyze(evidence_item, parameters=None):
        # Mutate the vault file first
        remove_os_read_only(vault_path)
        with open(vault_path, "ab") as f:
            f.write(b"\nMALICIOUS_TOOL_TAMPER_AND_CRASH")
        apply_os_read_only(vault_path)
        # Then raise an exception
        raise RuntimeError("Tool crashed unexpectedly after tampering with evidence")

    monkeypatch.setattr(malware_agent, "analyze", exploding_mutating_analyze)

    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    # Cryptographic integrity violation MUST take precedence -> HTTP 500
    assert scan_res.status_code == 500
    assert "CRITICAL: Evidence was modified during analysis!" in scan_res.json()["detail"]

    db = SessionLocal()
    try:
        ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev.integrity_status == "FAILED"
        execution = db.query(ToolExecution).filter_by(evidence_id=ev_id).order_by(ToolExecution.created_at.desc()).first()
        assert execution.status == "FAILED"
        assert "modified during tool execution" in execution.error_message
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).order_by(ChainOfCustodyEvent.timestamp.desc()).first()
        assert violation is not None
        assert "Post-analysis tampering detected" in violation.description
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 17: P0-1 Post-Analysis Gate Runs on Tool Exception Without Mutation
# -----------------------------------------------------------------------------
def test_post_analysis_gate_runs_on_tool_exception_without_mutation(monkeypatch):
    inv_id = _create_case(client)
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_CLEAN)
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    ev_id = ev_data["id"]

    from backend.app.api.endpoints.investigations import malware_agent

    def exploding_clean_analyze(evidence_item, parameters=None):
        raise RuntimeError("Tool parsing failure on untampered evidence")

    monkeypatch.setattr(malware_agent, "analyze", exploding_clean_analyze)

    scan_res = client.post(f"/api/investigations/{inv_id}/analysis/malware", json={
        "evidence_id": ev_id,
        "rule_id": "adfir_test_rules"
    })
    # Integrity check succeeds, so original tool error is returned as status="FAILED" (HTTP 200)
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "FAILED"
    assert "Tool parsing failure on untampered evidence" in data["error"]

    db = SessionLocal()
    try:
        ev = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev.integrity_status == "VERIFIED"
        post_event = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VERIFIED_POST_ANALYSIS"
        ).order_by(ChainOfCustodyEvent.timestamp.desc()).first()
        assert post_event is not None
        assert "Zero bytes altered" in post_event.description
        execution = db.query(ToolExecution).filter_by(evidence_id=ev_id).order_by(ToolExecution.created_at.desc()).first()
        assert execution.status == "FAILED"
        assert "Tool parsing failure on untampered evidence" in execution.error_message
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Test 18: P0-2 Direct Analysis Blocked When storage_path Equals original_path
# -----------------------------------------------------------------------------
def test_analysis_blocked_when_storage_path_equals_original_path():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"UNVAULTED_EVIDENCE", suffix=".raw")
    db = SessionLocal()
    try:
        # Manually create legacy/unvaulted evidence item
        ev_id = str(uuid.uuid4())
        ev = EvidenceItem(
            id=ev_id,
            case_id=inv_id,
            name="unvaulted.raw",
            original_path=tmp_path,
            storage_path=tmp_path,  # storage_path == original_path
            evidence_type="disk_image",
            size_bytes=os.path.getsize(tmp_path),
            sha256="fakehash123",
            read_only_verified=False,
            integrity_status="UNVERIFIED"
        )
        db.add(ev)
        db.commit()

        scan_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={
            "evidence_id": ev_id
        })
        assert scan_res.status_code == 422
        assert "storage_path equals original_path" in scan_res.json()["detail"].lower()

        ev_refreshed = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev_refreshed.integrity_status == "FAILED"
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).first()
        assert violation is not None
    finally:
        db.close()
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 19: P0-2 Direct Analysis Blocked When storage_path is None
# -----------------------------------------------------------------------------
def test_analysis_blocked_when_storage_path_is_none():
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"NONE_STORAGE_PATH", suffix=".raw")
    db = SessionLocal()
    try:
        ev_id = str(uuid.uuid4())
        ev = EvidenceItem(
            id=ev_id,
            case_id=inv_id,
            name="missing_storage.raw",
            original_path=tmp_path,
            storage_path=None,
            evidence_type="disk_image",
            size_bytes=os.path.getsize(tmp_path),
            sha256="fakehash123",
            read_only_verified=False,
            integrity_status="UNVERIFIED"
        )
        db.add(ev)
        db.commit()

        scan_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={
            "evidence_id": ev_id
        })
        assert scan_res.status_code == 422
        assert "lacks a vault storage_path" in scan_res.json()["detail"].lower()

        ev_refreshed = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev_refreshed.integrity_status == "FAILED"
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).first()
        assert violation is not None
    finally:
        db.close()
        _cleanup_file(tmp_path)

# -----------------------------------------------------------------------------
# Test 20: P0-2 Direct Analysis Blocked When storage_path Outside Vault
# -----------------------------------------------------------------------------
def test_analysis_blocked_when_storage_path_outside_vault():
    inv_id = _create_case(client)
    tmp_orig = _create_temp_evidence_file(content=b"ORIGINAL_OUTSIDE", suffix=".raw")
    tmp_store = _create_temp_evidence_file(content=b"STORED_OUTSIDE", suffix=".raw")
    db = SessionLocal()
    try:
        ev_id = str(uuid.uuid4())
        ev = EvidenceItem(
            id=ev_id,
            case_id=inv_id,
            name="outside_vault.raw",
            original_path=tmp_orig,
            storage_path=tmp_store,  # outside vault
            evidence_type="disk_image",
            size_bytes=os.path.getsize(tmp_store),
            sha256="fakehash123",
            read_only_verified=False,
            integrity_status="UNVERIFIED"
        )
        db.add(ev)
        db.commit()

        scan_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={
            "evidence_id": ev_id
        })
        assert scan_res.status_code == 422
        assert "outside the managed evidence vault" in scan_res.json()["detail"].lower()

        ev_refreshed = db.query(EvidenceItem).filter_by(id=ev_id).first()
        assert ev_refreshed.integrity_status == "FAILED"
        violation = db.query(ChainOfCustodyEvent).filter_by(
            evidence_id=ev_id,
            event_type="INTEGRITY_VIOLATION"
        ).first()
        assert violation is not None
    finally:
        db.close()
        _cleanup_file(tmp_orig)
        _cleanup_file(tmp_store)

# -----------------------------------------------------------------------------
# Test 21: P1-3 Independent Vault Disk Re-Hash Mismatch Prevents Staging
# -----------------------------------------------------------------------------
def test_independent_vault_rehash_mismatch_prevents_staging(monkeypatch):
    tmp_path = _create_temp_evidence_file(content=b"INDEPENDENT_REHASH_TEST_DATA", suffix=".txt")
    test_case_id = f"rehash-case-{uuid.uuid4().hex[:6]}"
    test_ev_id = f"ev-{uuid.uuid4().hex[:6]}"
    vault_dir = get_vault_dir(test_case_id, test_ev_id)
    temp_part = vault_dir / f".tmp_{test_ev_id}.part"

    orig_open = open
    def mutating_open(path, mode="r", *args, **kwargs):
        if str(temp_part) in str(path) and "rb" in mode:
            # Corrupt the file on disk before it is re-read
            with orig_open(path, "wb") as corrupt_f:
                corrupt_f.write(b"CORRUPTED_DISK_DATA_DURING_STAGING")
        return orig_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mutating_open)

    with pytest.raises(IOError, match="Cryptographic integrity verification failed during vault acquisition"):
        stage_evidence_to_vault(tmp_path, test_case_id, test_ev_id)

    # Verify temp .part file was cleaned up and destination file was NOT created
    assert not temp_part.exists()
    final_target = vault_dir / Path(tmp_path).name
    assert not final_target.exists()

    _cleanup_file(tmp_path)
    if vault_dir.exists():
        shutil.rmtree(vault_dir, ignore_errors=True)

# -----------------------------------------------------------------------------
# Test 22: P1-3 Staging Failure Leaves Database Uncommitted
# -----------------------------------------------------------------------------
def test_staging_failure_leaves_database_uncommitted(monkeypatch):
    inv_id = _create_case(client)
    tmp_path = _create_temp_evidence_file(content=b"FAILED_STAGING_CONTENT", suffix=".txt")

    from backend.app.api.endpoints import investigations

    def failing_stage(source_path, case_id, evidence_id):
        raise IOError("Simulated disk write failure during vault acquisition")

    monkeypatch.setattr(investigations, "stage_evidence_to_vault", failing_stage)

    res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": tmp_path
    })
    assert res.status_code == 500
    assert "Simulated disk write failure" in res.json()["detail"]

    # Verify no evidence item or custody events exist in database for this path
    db = SessionLocal()
    try:
        ev = db.query(EvidenceItem).filter_by(case_id=inv_id, original_path=tmp_path).first()
        assert ev is None
        custody = db.query(ChainOfCustodyEvent).filter_by(case_id=inv_id).all()
        assert len(custody) == 0
    finally:
        db.close()
        _cleanup_file(tmp_path)


