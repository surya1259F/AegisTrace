"""
ADFIR — Phase 2 / Step 12: Artifact Normalization Subsystem Tests

Comprehensive verification of:
1. Common Artifact Schema & Entity Mapping
   - FILE (paths, filenames, extensions, inodes, sizes, hashes, timestamps)
   - PROCESS (pid, ppid, process_name, command_line, start_time)
   - NETWORK_CONNECTION (protocol, local/remote address & port, state, owner_pid)
   - EVENT (event_id, provider, channel, computer_name, event_timestamp)
   - MALWARE_MATCH (rule_name, target_file, matched_tags, matched_strings)
   - METADATA (target_file, mime_type, file_size, attributes)
   - GENERIC & UNSUPPORTED (unsupported recorded, not ignored)
2. Deterministic Entity Identity & Partial Identity
   - Canonical fingerprints match for identical entities
   - Insufficient data sets PARTIAL_IDENTITY without inventing data
   - Source-specific identity preserved alongside normalized identity
3. Multi-Source Deduplication
   - Same entity identity within a case increments occurrence_count
   - All contributing source artifact IDs are retained
   - Audit trail logged on deduplication
4. Cryptographic Integrity & Lineage
   - SHA-256 calculated over canonical representation
   - Integrity verified as VALID on pristine artifacts
   - Tamper detection detects modified representation
   - Missing disk file detected
   - Source structured artifact mismatch detected
5. Immutability
   - Raw forensic outputs and structured artifacts remain unmodified
   - Evidence vault strictly protected
6. Storage Isolation & Security
   - Stored in storage/normalized/cases/{case_id}/
   - Safe permissions (0o600 file, 0o700 dir)
   - Symlinks and vault storage forbidden
   - Path traversal prevented
7. REST API & RBAC / IDOR Protection
   - Execution batch normalization
   - Single artifact normalization
   - List, filter, detail, integrity, provenance, download endpoints
   - Cross-case authorization and IDOR containment
8. Strict Forensic Boundaries
   - Comparable data only: NO attack detection, NO severity, NO correlation, NO findings, NO conclusions
"""

import os
import json
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
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    AuditEvent
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.integrity import calculate_sha256
from backend.app.services.normalization import (
    ArtifactNormalizationService,
    NormalizedStorageManager,
    EntityNormalizer,
    EntityIdentityEngine,
    EntityType
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="norm_usr", case_prefix="norm_case"):
    """Creates a user and authorized case with unique case_number to prevent collisions."""
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

    cid = f"case-norm-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing artifact normalization subsystem",
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


def create_test_evidence(db, case, filename="disk.img"):
    """Creates a test evidence item in vault."""
    ev_id = str(uuid.uuid4())
    vault_dir = settings.EVIDENCE_DIR / "vault" / case.id / ev_id
    vault_dir.mkdir(parents=True, exist_ok=True)
    ev_file = vault_dir / filename
    ev_file.write_bytes(b"EVIDENCE_IMAGE_PAYLOAD_FOR_NORMALIZATION")

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
    return evidence


def create_execution_and_structured_artifacts(
    db,
    case,
    user,
    evidence,
    artifacts_spec: list
):
    """
    Sets up an execution, raw output, and structured artifacts based on artifacts_spec.
    Each spec item: {"artifact_type": ..., "source_reference": ..., "normalized_data": ..., "status": ...}
    """
    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Artifact Normalization Test Plan",
        strategy_summary="Strategy for testing normalization",
        validation_status="VALIDATED",
        version=1,
        created_by=user.id
    )
    db.add(plan)
    db.commit()

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case.id,
        plan_id=plan.id,
        evidence_id=evidence.id,
        task_key=f"task-{uuid.uuid4().hex[:4]}",
        capability_id="FORENSIC_ANALYSIS",
        selected_tool_id="test_forensic_tool",
        scheduler_status="COMPLETED"
    )
    db.add(req)
    db.commit()

    exec_id = str(uuid.uuid4())
    workspace_dir = settings.DATA_DIR / "workspaces" / case.id / exec_id
    workspace_dir.mkdir(parents=True, exist_ok=True)

    execution = ForensicExecution(
        id=exec_id,
        request_id=req.id,
        case_id=case.id,
        task_id=f"task-{uuid.uuid4().hex[:4]}",
        task_key=req.task_key,
        evidence_id=evidence.id,
        tool_id="test_forensic_tool",
        tool_version="2.0.0",
        executable_path="/bin/test_tool",
        validated_argv=["/bin/test_tool", "arg"],
        host_platform="linux",
        host_architecture="x86_64",
        execution_status="COMPLETED",
        workspace_path=str(workspace_dir),
        exit_code=0
    )
    db.add(execution)
    db.commit()

    raw_output = ExecutionOutput(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence.id,
        execution_id=execution.id,
        request_id=req.id,
        task_id=execution.task_id,
        tool_id=execution.tool_id,
        tool_version="2.0.0",
        output_type="TOOL_OUTPUT",
        filename="output.log",
        relative_path="outputs/output.log",
        storage_path=str(workspace_dir / "output.log"),
        size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        mime_type="text/plain",
        exit_code=0,
        execution_status="COMPLETED"
    )
    db.add(raw_output)
    db.commit()

    structured_artifacts = []
    for spec in artifacts_spec:
        art_id = str(uuid.uuid4())
        norm_data = spec.get("normalized_data", {})
        canon = json.dumps(norm_data, sort_keys=True, separators=(',', ':')).encode("utf-8")
        art_hash = calculate_sha256_bytes(canon)

        art_dir = settings.DATA_DIR / "storage" / "artifacts" / "cases" / case.id / execution.id
        art_dir.mkdir(parents=True, exist_ok=True)
        art_file = art_dir / f"{art_id}.json"
        art_file.write_text(json.dumps(norm_data), encoding="utf-8")

        sa = StructuredArtifact(
            id=art_id,
            case_id=case.id,
            evidence_id=evidence.id,
            execution_id=execution.id,
            raw_output_id=raw_output.id,
            request_id=req.id,
            task_id=execution.task_id,
            tool_id=execution.tool_id,
            tool_version=execution.tool_version,
            parser_name=spec.get("parser_name", "TestParser"),
            parser_version="1.0.0",
            artifact_type=spec.get("artifact_type", "FILESYSTEM_RECORD"),
            source_reference=spec.get("source_reference", f"ref:{art_id[:8]}"),
            normalized_data=norm_data,
            raw_record=spec.get("raw_record", "RAW RECORD LINE"),
            sha256_hash=art_hash,
            source_raw_output_hash=raw_output.sha256_hash,
            storage_path=str(art_file),
            extraction_status=spec.get("status", "EXTRACTED"),
            error_message=spec.get("error_message"),
            created_at=datetime.now(timezone.utc)
        )
        db.add(sa)
        structured_artifacts.append(sa)

    db.commit()
    for sa in structured_artifacts:
        db.refresh(sa)

    return execution, raw_output, structured_artifacts


def calculate_sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# =============================================================================
# TESTS
# =============================================================================

def test_entity_mapping_and_field_normalization(db_session):
    """
    Verifies that various structured artifact types (FILE, PROCESS, NETWORK, EVENT, etc.)
    are accurately mapped to standardized EntityTypes with consistent normalized fields.
    """
    user, case, _ = create_test_user_and_case(db_session, "mapper_usr", "mapper_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "fls:1024-128-3",
            "normalized_data": {
                "path": r"C:\Windows\System32\cmd.exe",
                "size_bytes": 289792,
                "file_type": "file",
                "inode": 1024,
                "is_deleted": False,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "modified_time": "2026-01-15T08:30:00Z"
            }
        },
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "process:448:svchost.exe",
            "normalized_data": {
                "pid": 448,
                "ppid": 612,
                "image_name": "svchost.exe",
                "command_line": "svchost.exe -k netsvcs",
                "start_time": "2026-01-15T08:00:00Z"
            }
        },
        {
            "artifact_type": "NETWORK_RECORD",
            "source_reference": "netscan:tcp:192.168.1.100:443",
            "normalized_data": {
                "proto": "TCP",
                "local_address": "192.168.1.100",
                "local_port": 49152,
                "foreign_address": "10.0.0.5",
                "foreign_port": 443,
                "state": "ESTABLISHED",
                "owner_pid": 448
            }
        },
        {
            "artifact_type": "EVENT_RECORD",
            "source_reference": "event:Security:4624",
            "normalized_data": {
                "event_id": 4624,
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer_name": "CORP-WS-01",
                "time_created": "2026-01-15T08:35:10Z"
            }
        },
        {
            "artifact_type": "MALWARE_MATCH",
            "source_reference": "yara:APT_Backdoor:sample.bin",
            "normalized_data": {
                "rule_name": "APT_Backdoor",
                "target_file": "/tmp/sample.bin",
                "matched_tags": ["apt", "trojan"],
                "matched_strings": ["$str1: evil_payload"]
            }
        },
        {
            "artifact_type": "METADATA_RECORD",
            "source_reference": "exiftool:sample.docx",
            "normalized_data": {
                "target_file": "/evidence/docs/report.docx",
                "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "file_size": 15420,
                "Author": "Attacker"
            }
        },
        {
            "artifact_type": "UNKNOWN_CUSTOM",
            "status": "UNSUPPORTED",
            "error_message": "Unsupported binary stream",
            "normalized_data": {"unsupported_binary": True}
        }
    ]

    execution, raw_out, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    result = ArtifactNormalizationService.normalize_execution_artifacts(
        db=db_session,
        execution_id=execution.id,
        case_id=case.id,
        actor_user=user
    )

    assert result["total_structured_artifacts"] == 7
    assert result["normalized_created_count"] == 7
    assert result["deduplicated_count"] == 0
    assert result["unsupported_count"] == 1

    norm_arts = result["normalized_artifacts"]
    types = {na.entity_type for na in norm_arts}
    assert EntityType.FILE in types
    assert EntityType.PROCESS in types
    assert EntityType.NETWORK_CONNECTION in types
    assert EntityType.EVENT in types
    assert EntityType.MALWARE_MATCH in types
    assert EntityType.METADATA in types
    assert EntityType.UNSUPPORTED in types

    # Inspect FILE entity
    file_entity = next(na for na in norm_arts if na.entity_type == EntityType.FILE)
    assert file_entity.normalized_fields["path"] == "C:/Windows/System32/cmd.exe"
    assert file_entity.normalized_fields["filename"] == "cmd.exe"
    assert file_entity.normalized_fields["extension"] == ".exe"
    assert file_entity.normalized_fields["size_bytes"] == 289792
    assert file_entity.entity_timestamp is not None
    assert file_entity.normalization_status == "NORMALIZED"

    # Inspect PROCESS entity
    proc_entity = next(na for na in norm_arts if na.entity_type == EntityType.PROCESS)
    assert proc_entity.normalized_fields["pid"] == 448
    assert proc_entity.normalized_fields["ppid"] == 612
    assert proc_entity.normalized_fields["process_name"] == "svchost.exe"

    # Inspect NETWORK entity
    net_entity = next(na for na in norm_arts if na.entity_type == EntityType.NETWORK_CONNECTION)
    assert net_entity.normalized_fields["protocol"] == "TCP"
    assert net_entity.normalized_fields["local_port"] == 49152
    assert net_entity.normalized_fields["remote_port"] == 443

    # Inspect UNSUPPORTED entity
    unsup_entity = next(na for na in norm_arts if na.entity_type == EntityType.UNSUPPORTED)
    assert unsup_entity.normalization_status == "UNSUPPORTED"
    assert "Unsupported binary stream" in unsup_entity.normalized_fields["unsupported_reason"]


def test_deterministic_entity_identity_and_partial_identity(db_session):
    """
    Verifies deterministic entity identity computation:
    - Same logical entity produces identical fingerprint.
    - Insufficient data is safely handled as PARTIAL_IDENTITY without hallucination.
    """
    user, case, _ = create_test_user_and_case(db_session, "ident_usr", "ident_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "tool_a:proc:100",
            "normalized_data": {"pid": 100, "image_name": "notepad.exe"}
        },
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "tool_b:proc:100",
            "normalized_data": {"pid": 100, "image_name": "notepad.exe", "extra_flag": "verbose"}
        },
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "tool_c:unknown_proc",
            "normalized_data": {"command_line": "--arg-only-no-pid-no-name"}
        }
    ]

    _, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    norm1, _ = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list[0], user)
    norm2_existing, is_new2 = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list[1], user)

    # Identical logical entities must have the exact same identity
    assert norm1.entity_identity == norm2_existing.entity_identity
    assert is_new2 is False  # Deduplicated!
    assert norm1.id == norm2_existing.id

    # Third has missing pid and process_name -> PARTIAL_IDENTITY
    norm3, is_new3 = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list[2], user)
    assert is_new3 is True
    assert norm3.normalization_status == "PARTIAL_IDENTITY"
    assert "process_partial:" in norm3.entity_identity or "process_" in norm3.entity_identity


def test_multi_source_deduplication(db_session):
    """
    Verifies that when multiple structured artifacts represent the same entity:
    - An existing NormalizedArtifact row is updated rather than duplicated.
    - occurrence_count is incremented.
    - All contributing source artifact IDs are preserved in contributing_source_artifact_ids.
    - Audit event is logged.
    """
    user, case, _ = create_test_user_and_case(db_session, "dedup_usr", "dedup_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "fls_pass1:101",
            "normalized_data": {"path": "/etc/shadow", "size_bytes": 1200}
        },
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "fls_pass2:101",
            "normalized_data": {"path": "/etc/shadow", "size_bytes": 1200}
        },
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "tar_scanner:shadow",
            "normalized_data": {"path": "/etc/shadow", "size_bytes": 1200}
        }
    ]

    execution, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    batch = ArtifactNormalizationService.normalize_execution_artifacts(
        db=db_session,
        execution_id=execution.id,
        case_id=case.id,
        actor_user=user
    )

    assert batch["total_structured_artifacts"] == 3
    assert batch["normalized_created_count"] == 1
    assert batch["deduplicated_count"] == 2

    # Query DB directly to verify only 1 normalized artifact exists
    all_normalized = (
        db_session.query(NormalizedArtifact)
        .filter(NormalizedArtifact.case_id == case.id)
        .all()
    )
    assert len(all_normalized) == 1
    target = all_normalized[0]
    assert target.occurrence_count == 3

    # Must preserve all 3 contributing structured artifact IDs
    assert len(target.contributing_source_artifact_ids) == 3
    for sa in sa_list:
        assert sa.id in target.contributing_source_artifact_ids

    # Verify audit events for deduplication
    audit_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.case_id == case.id, AuditEvent.event_type == "NORMALIZED_ARTIFACT_DEDUPLICATED")
        .all()
    )
    assert len(audit_events) == 2


def test_cryptographic_integrity_and_tamper_detection(db_session):
    """
    Verifies SHA-256 calculation, integrity verification, and tamper detection:
    - VALID on intact artifact.
    - TAMPERED when DB payload or disk content is modified.
    - FILE_MISSING when storage JSON file is deleted.
    - SOURCE_ARTIFACT_MISMATCH when source structured artifact hash changes.
    """
    user, case, _ = create_test_user_and_case(db_session, "integ_usr", "integ_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "EVENT_RECORD",
            "source_reference": "event:System:1074",
            "normalized_data": {
                "event_id": 1074,
                "provider": "USER32",
                "channel": "System",
                "computer_name": "DESKTOP-ABC"
            }
        }
    ]

    _, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    norm_art, is_new = ArtifactNormalizationService.normalize_structured_artifact(
        db=db_session,
        structured_art=sa_list[0],
        actor_user=user
    )
    assert is_new is True

    # 1. Verification on pristine artifact
    integ = ArtifactNormalizationService.verify_normalized_integrity(
        db=db_session,
        normalized_id=norm_art.id,
        case_id=case.id
    )
    assert integ["integrity_status"] == "VALID"
    assert integ["expected_sha256"] == norm_art.sha256_hash
    assert integ["calculated_sha256"] == norm_art.sha256_hash

    # 2. Tamper with DB normalized_fields
    orig_fields = dict(norm_art.normalized_fields)
    norm_art.normalized_fields = {"tampered": True}
    db_session.commit()

    tampered_integ = ArtifactNormalizationService.verify_normalized_integrity(
        db=db_session,
        normalized_id=norm_art.id,
        case_id=case.id
    )
    assert tampered_integ["integrity_status"] == "TAMPERED"

    # Restore fields
    norm_art.normalized_fields = orig_fields
    db_session.commit()

    # 3. Source artifact hash mismatch (source StructuredArtifact hash changed)
    orig_src_hash = sa_list[0].sha256_hash
    sa_list[0].sha256_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    db_session.commit()

    mismatch_integ = ArtifactNormalizationService.verify_normalized_integrity(
        db=db_session,
        normalized_id=norm_art.id,
        case_id=case.id
    )
    assert mismatch_integ["integrity_status"] == "SOURCE_ARTIFACT_MISMATCH"

    # Restore source hash
    sa_list[0].sha256_hash = orig_src_hash
    db_session.commit()

    # 4. File missing detection
    storage_path = Path(norm_art.storage_path)
    storage_backup = storage_path.read_bytes()
    storage_path.unlink()

    missing_integ = ArtifactNormalizationService.verify_normalized_integrity(
        db=db_session,
        normalized_id=norm_art.id,
        case_id=case.id
    )
    assert missing_integ["integrity_status"] == "FILE_MISSING"

    # Restore file
    storage_path.write_bytes(storage_backup)


def test_immutability_of_raw_outputs_and_structured_artifacts(db_session):
    """
    Verifies that normalizing structured artifacts never modifies the source
    StructuredArtifact or the source ExecutionOutput records, hashes, or files.
    """
    user, case, _ = create_test_user_and_case(db_session, "immut_usr", "immut_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "proc:1234",
            "normalized_data": {"pid": 1234, "image_name": "malware.exe"}
        }
    ]

    _, raw_out, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )
    source_sa = sa_list[0]

    raw_out_orig_hash = raw_out.sha256_hash
    raw_out_orig_size = raw_out.size_bytes
    sa_orig_hash = source_sa.sha256_hash
    sa_orig_data = json.dumps(source_sa.normalized_data, sort_keys=True)

    # Perform normalization
    ArtifactNormalizationService.normalize_structured_artifact(db_session, source_sa, user)

    # Refresh and assert unchanged
    db_session.refresh(raw_out)
    db_session.refresh(source_sa)

    assert raw_out.sha256_hash == raw_out_orig_hash
    assert raw_out.size_bytes == raw_out_orig_size
    assert source_sa.sha256_hash == sa_orig_hash
    assert json.dumps(source_sa.normalized_data, sort_keys=True) == sa_orig_data


def test_storage_isolation_and_security(db_session):
    """
    Verifies storage containment:
    - Path outside base directory is rejected.
    - Evidence vault paths are strictly rejected.
    - Symlinks are rejected.
    - Safe POSIX permissions (0o700 for directories, 0o600 for files) are set.
    """
    user, case, _ = create_test_user_and_case(db_session, "sec_usr", "sec_case")

    base_dir = NormalizedStorageManager.get_case_storage_dir(case.id)
    assert base_dir.exists()
    assert (base_dir.stat().st_mode & 0o777) == 0o700

    # Test writing a normalized file
    sample_payload = {"test": "payload"}
    norm_id = str(uuid.uuid4())
    out_file = NormalizedStorageManager.persist_normalized_file(case.id, norm_id, sample_payload)

    assert out_file.exists()
    assert (out_file.stat().st_mode & 0o777) == 0o600

    # Path traversal rejection
    traversal_path = base_dir.parent / "escape.json"
    with pytest.raises(ValueError, match="Path traversal detected"):
        NormalizedStorageManager.validate_storage_path(traversal_path, case.id)

    # Evidence vault rejection
    vault_path = settings.EVIDENCE_DIR / "vault" / case.id / "illegal.json"
    with pytest.raises(ValueError, match="CRITICAL: Normalized storage cannot be located inside evidence vault"):
        NormalizedStorageManager.validate_storage_path(vault_path, case.id)

    # Symlink rejection
    symlink_target = out_file
    symlink_file = base_dir / "symlink_test.json"
    try:
        os.symlink(symlink_target, symlink_file)
        with pytest.raises(ValueError, match="Symlink storage references strictly forbidden"):
            NormalizedStorageManager.validate_storage_path(symlink_file, case.id)
    finally:
        if symlink_file.is_symlink():
            symlink_file.unlink()


def test_api_normalize_execution_artifacts(db_session):
    """
    Tests POST /cases/{case_id}/executions/{execution_id}/normalize-artifacts endpoint.
    """
    user, case, headers = create_test_user_and_case(db_session, "api_exec_usr", "api_exec_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "fls:200",
            "normalized_data": {"path": "/var/log/syslog", "size_bytes": 4096}
        },
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "fls:201",
            "normalized_data": {"path": "/var/log/auth.log", "size_bytes": 2048}
        }
    ]

    execution, _, _ = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    res = client.post(
        f"/api/cases/{case.id}/executions/{execution.id}/normalize-artifacts",
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["execution_id"] == execution.id
    assert data["case_id"] == case.id
    assert data["total_structured_artifacts"] == 2
    assert data["normalized_created_count"] == 2
    assert len(data["normalized_artifacts"]) == 2


def test_api_normalize_single_structured_artifact(db_session):
    """
    Tests POST /cases/{case_id}/structured-artifacts/{artifact_id}/normalize endpoint.
    """
    user, case, headers = create_test_user_and_case(db_session, "api_single_usr", "api_single_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "pslist:777",
            "normalized_data": {"pid": 777, "image_name": "bash"}
        }
    ]

    _, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )
    sa = sa_list[0]

    res = client.post(
        f"/api/cases/{case.id}/structured-artifacts/{sa.id}/normalize",
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["entity_type"] == "PROCESS"
    assert data["source_artifact_id"] == sa.id
    assert data["occurrence_count"] == 1


def test_api_list_and_filter_normalized_artifacts(db_session):
    """
    Tests GET /cases/{case_id}/normalized-artifacts with filters and pagination.
    """
    user, case, headers = create_test_user_and_case(db_session, "api_list_usr", "api_list_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "f1",
            "normalized_data": {"path": "/boot/vmlinuz"}
        },
        {
            "artifact_type": "PROCESS_RECORD",
            "source_reference": "p1",
            "normalized_data": {"pid": 1, "image_name": "systemd"}
        }
    ]

    execution, _, _ = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )
    ArtifactNormalizationService.normalize_execution_artifacts(db_session, execution.id, case.id, user)

    # 1. List all
    res = client.get(f"/api/cases/{case.id}/normalized-artifacts", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 2

    # 2. Filter by entity_type=FILE
    res_file = client.get(f"/api/cases/{case.id}/normalized-artifacts?entity_type=FILE", headers=headers)
    assert res_file.status_code == 200
    items = res_file.json()
    assert len(items) == 1
    assert items[0]["entity_type"] == "FILE"

    # 3. Filter by non-existent type
    res_empty = client.get(f"/api/cases/{case.id}/normalized-artifacts?entity_type=MALWARE_MATCH", headers=headers)
    assert res_empty.status_code == 200
    assert len(res_empty.json()) == 0


def test_api_normalized_details_and_download(db_session):
    """
    Tests GET details, integrity, provenance, and download endpoints.
    """
    user, case, headers = create_test_user_and_case(db_session, "api_det_usr", "api_det_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "NETWORK_RECORD",
            "source_reference": "net:1",
            "normalized_data": {
                "proto": "UDP",
                "local_address": "0.0.0.0",
                "local_port": 53,
                "state": "LISTENING"
            }
        }
    ]

    execution, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )
    norm_art, _ = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list[0], user)

    # 1. Details endpoint
    res_det = client.get(f"/api/cases/{case.id}/normalized-artifacts/{norm_art.id}", headers=headers)
    assert res_det.status_code == 200
    det_data = res_det.json()
    assert det_data["id"] == norm_art.id
    assert det_data["entity_type"] == "NETWORK_CONNECTION"

    # 2. Integrity endpoint
    res_integ = client.get(f"/api/cases/{case.id}/normalized-artifacts/{norm_art.id}/integrity", headers=headers)
    assert res_integ.status_code == 200
    integ_data = res_integ.json()
    assert integ_data["integrity_status"] == "VALID"
    assert integ_data["expected_sha256"] == norm_art.sha256_hash

    # 3. Provenance endpoint
    res_prov = client.get(f"/api/cases/{case.id}/normalized-artifacts/{norm_art.id}/provenance", headers=headers)
    assert res_prov.status_code == 200
    prov_data = res_prov.json()
    assert prov_data["normalized_id"] == norm_art.id
    assert "traceability_chain" in prov_data
    chain = prov_data["traceability_chain"]
    assert any(f"EvidenceItem:{evidence.id}" in c for c in chain)
    assert any(f"ForensicExecution:{execution.id}" in c for c in chain)
    assert any(f"StructuredArtifact:{sa_list[0].id}" in c for c in chain)
    assert any(f"NormalizedArtifact:{norm_art.id}" in c for c in chain)

    # 4. Download endpoint
    res_dl = client.get(f"/api/cases/{case.id}/normalized-artifacts/{norm_art.id}/download", headers=headers)
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "application/json"
    downloaded_json = res_dl.json()
    assert downloaded_json["id"] == norm_art.id
    assert downloaded_json["entity_type"] == "NETWORK_CONNECTION"


def test_rbac_and_cross_case_idor_protection(db_session):
    """
    Verifies that unauthorized investigators cannot access or normalize artifacts
    belonging to another case.
    """
    user_a, case_a, headers_a = create_test_user_and_case(db_session, "user_a", "case_a")
    user_b, case_b, headers_b = create_test_user_and_case(db_session, "user_b", "case_b")

    evidence_a = create_test_evidence(db_session, case_a)
    specs_a = [
        {
            "artifact_type": "FILESYSTEM_RECORD",
            "source_reference": "confidential_file",
            "normalized_data": {"path": "/confidential/case_a.txt"}
        }
    ]

    exec_a, _, sa_list_a = create_execution_and_structured_artifacts(
        db_session, case_a, user_a, evidence_a, specs_a
    )
    norm_a, _ = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list_a[0], user_a)

    # 1. User B attempts to access Case A's normalized artifact list -> 403 Forbidden
    res_list = client.get(f"/api/cases/{case_a.id}/normalized-artifacts", headers=headers_b)
    assert res_list.status_code in [403, 404]

    # 2. User B attempts to get Case A's artifact details directly -> 403 Forbidden
    res_det = client.get(f"/api/cases/{case_a.id}/normalized-artifacts/{norm_a.id}", headers=headers_b)
    assert res_det.status_code in [403, 404]

    # 3. User B attempts to trigger normalization on Case A's execution -> 403 Forbidden
    res_norm = client.post(
        f"/api/cases/{case_a.id}/executions/{exec_a.id}/normalize-artifacts",
        headers=headers_b
    )
    assert res_norm.status_code in [403, 404]

    # 4. User B attempts IDOR parameter tampering (querying case_b URL with norm_a.id) -> 404 Not Found
    res_tamper = client.get(f"/api/cases/{case_b.id}/normalized-artifacts/{norm_a.id}", headers=headers_b)
    assert res_tamper.status_code == 404


def test_strict_forensic_boundaries_no_findings_no_conclusions(db_session):
    """
    Strict boundary test:
    Verifies that Step 12 produces ONLY normalized forensic entities and does NOT:
    - Create Finding records
    - Assign severity scores
    - Perform threat detection or IOC correlation
    - Infer maliciousness
    """
    user, case, _ = create_test_user_and_case(db_session, "boundary_usr", "boundary_case")
    evidence = create_test_evidence(db_session, case)

    specs = [
        {
            "artifact_type": "MALWARE_MATCH",
            "source_reference": "yara:ransomware",
            "normalized_data": {
                "rule_name": "Ransomware_LockBit",
                "target_file": "/tmp/payload.exe",
                "matched_tags": ["ransomware", "critical"],
                "matched_strings": ["$encrypt: .locked"]
            }
        }
    ]

    execution, _, sa_list = create_execution_and_structured_artifacts(
        db_session, case, user, evidence, specs
    )

    norm_art, _ = ArtifactNormalizationService.normalize_structured_artifact(db_session, sa_list[0], user)

    # 1. Verify entity is stored as MALWARE_MATCH without severity or verdict
    assert norm_art.entity_type == "MALWARE_MATCH"
    assert "severity" not in norm_art.normalized_fields
    assert "verdict" not in norm_art.normalized_fields
    assert "conclusion" not in norm_art.normalized_fields

    # 2. Verify NO Finding records were generated in DB
    from backend.app.models.models import Finding
    findings_count = db_session.query(Finding).filter(Finding.case_id == case.id).count()
    assert findings_count == 0
