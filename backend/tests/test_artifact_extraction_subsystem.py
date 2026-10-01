"""
ADFIR — Phase 2 / Step 11: Structured Artifact Extraction Subsystem Tests

Comprehensive verification of:
1. Parser Selection & Discovery across supported tools and formats
   - SleuthKit / fls -> FILESYSTEM_RECORD
   - EVTX logs -> EVENT_LOG_RECORD
   - YARA scans -> MALWARE_MATCH
   - Volatility pslist -> PROCESS_RECORD
   - Volatility netscan -> NETWORK_RECORD
   - ExifTool -> METADATA_RECORD
   - Generic structured text fallback
   - Unsupported raw output handled explicitly as UNSUPPORTED (never silently ignored)
2. Structured Artifact Model & Normalization
   - Field normalization preserves original raw records without inventing missing values
   - Foreign keys to Case, Evidence, Execution, RawOutput, Request, Task
3. Cryptographic Integrity & Lineage
   - SHA-256 calculated over canonical json representation of normalized artifact payload
   - Source raw-output SHA-256 preserved
   - Parser name and version recorded
   - Integrity verification passes on intact artifacts
   - Tamper detection detects modified payload
   - Missing storage file detected
4. Storage Separation & Permissions
   - Stored in storage/artifacts/cases/{case_id}/{execution_id}/
   - Safe permissions (0o600 file, 0o700 directory)
   - Evidence vault storage prohibited
   - Path traversal prevented
   - Raw forensic outputs remain strictly immutable (unmodified size, hash, content)
5. REST API Endpoints & RBAC / IDOR Protection
   - Trigger extraction for execution
   - Trigger extraction for single raw output
   - List artifacts for execution (with type & status filters)
   - List artifacts for evidence item
   - Get artifact details and download
   - Verify artifact integrity endpoint
   - Strict case authorization & cross-case IDOR isolation
6. Invariant Verification
   - Structured artifacts represent evidence-derived data, NOT findings or conclusions
   - No attack detection, no threat correlation, no LLM inferences
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
    InvestigationTask,
    ToolDefinition,
    ToolSelectionRecord,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    AuditEvent
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.integrity import calculate_sha256
from backend.app.services.raw_outputs import RawOutputsService
from backend.app.services.artifact_extraction import (
    ArtifactExtractionService,
    ArtifactStorageManager,
    parser_registry,
    FlsArtifactParser,
    EvtxArtifactParser,
    YaraArtifactParser,
    PsListArtifactParser,
    NetScanArtifactParser,
    ExifToolArtifactParser,
    GenericStructuredTextParser
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="art_usr", case_prefix="art_case"):

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

    cid = f"case-art-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",

        description="Testing structured artifact extraction subsystem",
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


def create_test_evidence(db, case, filename="disk.dd", content=b"RAW_DISK_EVIDENCE_FOR_ARTIFACTS"):
    """Creates a test evidence item in vault."""
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


def create_execution_with_raw_output(
    db,
    case,
    user,
    tool_id="test_tool",
    output_filename="output.txt",
    output_content="FORENSIC OUTPUT CONTENT",
    output_type="TOOL_OUTPUT"
):
    """Sets up an execution with a persisted raw execution output record and file."""
    evidence, _ = create_test_evidence(db, case)

    plan_id = str(uuid.uuid4())
    plan = InvestigationPlan(
        id=plan_id,
        case_id=case.id,
        title="Artifact Extraction Test Plan",
        strategy_summary="Plan for artifact extraction tests",
        validation_status="VALIDATED",
        version=1,
        created_by=user.id
    )
    db.add(plan)
    db.commit()

    req_id = str(uuid.uuid4())
    req = AnalysisRequest(
        id=req_id,
        case_id=case.id,
        plan_id=plan.id,
        evidence_id=evidence.id,
        task_key=f"task-{uuid.uuid4().hex[:4]}",
        capability_id="FORENSIC_ANALYSIS",
        selected_tool_id=tool_id,
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
        tool_id=tool_id,
        tool_version="1.0.0",
        executable_path="/bin/echo",
        validated_argv=["/bin/echo", "test"],
        host_platform="linux",
        host_architecture="x86_64",
        execution_status="COMPLETED",
        workspace_path=str(workspace_dir),
        exit_code=0
    )
    db.add(execution)
    db.commit()

    # Create raw output file
    out_dir = workspace_dir / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / output_filename
    out_file.write_text(output_content, encoding="utf-8")

    out_sha, out_size = calculate_sha256(str(out_file))

    raw_output = ExecutionOutput(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence.id,
        execution_id=execution.id,
        request_id=req.id,
        task_id=execution.task_id,
        tool_id=tool_id,
        tool_version="1.0.0",
        output_type=output_type,
        filename=output_filename,
        relative_path=f"outputs/{output_filename}",
        storage_path=str(out_file),
        size_bytes=out_size,
        sha256_hash=out_sha,
        mime_type="text/plain",
        exit_code=0,
        execution_status="COMPLETED"
    )
    db.add(raw_output)
    db.commit()
    db.refresh(raw_output)

    return execution, raw_output, evidence



# =============================================================================
# 1. PARSER REGISTRY SELECTION & DISCOVERY TESTS
# =============================================================================

def test_parser_selection_registry(db_session):
    """Verifies parser registry matches raw outputs based on tool, filename, and content."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "parse_sel", "parse_case")

    # 1. SleuthKit fls parser
    _, fls_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls_body.txt",
        output_content="r/r 1234-128-3: image.jpg\n"
    )
    parser = parser_registry.select_parser(fls_out, "r/r 1234-128-3: image.jpg")
    assert isinstance(parser, FlsArtifactParser)
    assert parser.artifact_type == "FILESYSTEM_RECORD"

    # 2. EVTX parser
    _, evtx_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="winevtx", output_filename="events.json",
        output_content='{"Event": {"System": {"EventID": 4624}}}\n'
    )
    parser = parser_registry.select_parser(evtx_out, '{"Event": {"System": {"EventID": 4624}}}')
    assert isinstance(parser, EvtxArtifactParser)
    assert parser.artifact_type == "EVENT_LOG_RECORD"

    # 3. YARA parser
    _, yara_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="yara", output_filename="scan.txt",
        output_content="malware_rule /path/to/malicious.bin\n"
    )
    parser = parser_registry.select_parser(yara_out, "malware_rule /path/to/malicious.bin")
    assert isinstance(parser, YaraArtifactParser)
    assert parser.artifact_type == "MALWARE_MATCH"

    # 4. PsList parser
    _, pslist_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="volatility_pslist", output_filename="pslist.txt",
        output_content="PID    PPID   ImageFileName\n4      0      System\n"
    )
    parser = parser_registry.select_parser(pslist_out, "PID    PPID   ImageFileName\n4      0      System")
    assert isinstance(parser, PsListArtifactParser)
    assert parser.artifact_type == "PROCESS_RECORD"

    # 5. NetScan parser
    _, netscan_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="volatility_netscan", output_filename="netscan.txt",
        output_content="Offset(P)  Proto  Local Address  Foreign Address  State  PID  Owner\n"
    )
    parser = parser_registry.select_parser(netscan_out, "Offset(P)  Proto  Local Address")
    assert isinstance(parser, NetScanArtifactParser)
    assert parser.artifact_type == "NETWORK_RECORD"

    # 6. ExifTool parser
    _, exif_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="exiftool", output_filename="metadata.json",
        output_content='[{"SourceFile": "test.jpg", "MIMEType": "image/jpeg"}]'
    )
    parser = parser_registry.select_parser(exif_out, '[{"SourceFile": "test.jpg"}]')
    assert isinstance(parser, ExifToolArtifactParser)
    assert parser.artifact_type == "METADATA_RECORD"

    # 7. Generic fallback for JSON
    _, generic_out, _ = create_execution_with_raw_output(
        db, case, user, tool_id="custom_tool", output_filename="custom.json",
        output_content='[{"key": "value"}]'
    )
    parser = parser_registry.select_parser(generic_out, '[{"key": "value"}]')
    assert isinstance(parser, GenericStructuredTextParser)


# =============================================================================
# 2. STRUCTURED ARTIFACT EXTRACTION & NORMALIZATION TESTS
# =============================================================================

def test_fls_filesystem_artifact_extraction(db_session):
    """Verifies SleuthKit fls parser extracts normalized filesystem records."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "fls_usr", "fls_case")

    fls_content = (
        "r/r 1024-128-3: user/docs/plan.pdf\n"
        "d/d * 2048-144-1: temp/deleted_folder\n"
        "r/r * 3096-128-4: secret/passwords.txt\n"
        "+ r/r 4096-128-1: system/config.ini\n"
    )

    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="bodyfile.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)

    assert len(artifacts) == 4
    for a in artifacts:
        assert a.case_id == case.id
        assert a.evidence_id == evidence.id
        assert a.execution_id == execution.id
        assert a.raw_output_id == raw_out.id
        assert a.artifact_type == "FILESYSTEM_RECORD"
        assert a.extraction_status == "EXTRACTED"
        assert a.parser_name == "FlsArtifactParser"
        assert a.sha256_hash is not None
        assert a.source_raw_output_hash == raw_out.sha256_hash

    # Check field normalization of deleted item
    deleted_art = [a for a in artifacts if "passwords.txt" in a.source_reference][0]
    norm = deleted_art.normalized_data
    assert norm["filename"] == "secret/passwords.txt"
    assert norm["inode"] == "3096-128-4"
    assert norm["is_deleted"] is True
    assert norm["file_type"] == "REGULAR_FILE"
    assert deleted_art.raw_record.strip() == "r/r * 3096-128-4: secret/passwords.txt"


def test_evtx_event_log_artifact_extraction(db_session):
    """Verifies EVTX parser extracts normalized event log records."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "evtx_usr", "evtx_case")

    evtx_json = (
        '{"Event": {"System": {"EventID": 4624, "TimeCreated": {"@SystemTime": "2026-09-20T12:00:00Z"}, "Computer": "DC01", "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"}, "Channel": "Security"}, "EventData": {"TargetUserName": "admin", "LogonType": 10, "IpAddress": "10.0.0.5"}}}\n'
        '{"Event": {"System": {"EventID": 4625, "TimeCreated": {"@SystemTime": "2026-09-20T12:05:00Z"}, "Computer": "DC01", "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"}, "Channel": "Security"}, "EventData": {"TargetUserName": "guest", "Status": "0xC000006D"}}}\n'
    )

    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="winevtx", output_filename="security_events.json",
        output_content=evtx_json
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)

    assert len(artifacts) == 2
    for a in artifacts:
        assert a.artifact_type == "EVENT_LOG_RECORD"
        assert a.extraction_status == "EXTRACTED"
        assert a.parser_name == "EvtxArtifactParser"

    art1 = artifacts[0]
    assert art1.normalized_data["event_id"] == 4624
    assert art1.normalized_data["timestamp"] == "2026-09-20T12:00:00Z"
    assert art1.normalized_data["computer"] == "DC01"
    assert art1.normalized_data["channel"] == "Security"
    assert art1.normalized_data["event_data"]["TargetUserName"] == "admin"


def test_yara_malware_match_artifact_extraction(db_session):
    """Verifies YARA parser extracts normalized malware match records."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "yara_usr", "yara_case")

    yara_output = (
        "rule_cobalt_strike /vault/evidence/sample1.exe\n"
        "rule_mimikatz [dump,credential_access] /vault/evidence/lsass_dump.dmp\n"
    )

    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="yara", output_filename="yara_results.txt",
        output_content=yara_output
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)

    assert len(artifacts) == 2
    assert artifacts[0].artifact_type == "MALWARE_MATCH"
    assert artifacts[0].normalized_data["rule_name"] == "rule_cobalt_strike"
    assert artifacts[0].normalized_data["target_path"] == "/vault/evidence/sample1.exe"

    assert artifacts[1].normalized_data["rule_name"] == "rule_mimikatz"
    assert "dump" in artifacts[1].normalized_data["tags"]
    assert "credential_access" in artifacts[1].normalized_data["tags"]


def test_volatility_pslist_and_netscan_extraction(db_session):
    """Verifies Volatility pslist and netscan parsers extract process and network records."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "vol_usr", "vol_case")

    # 1. Test pslist
    pslist_content = (
        "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\n"
        "4\t0\tSystem\t0xfa800100\t120\t0\t-\tFalse\t2026-09-20 08:00:00\t-\n"
        "1040\t4\tsmss.exe\t0xfa800200\t4\t45\t-\tFalse\t2026-09-20 08:00:01\t-\n"
    )

    exec_ps, raw_ps, _ = create_execution_with_raw_output(
        db, case, user, tool_id="volatility_pslist", output_filename="pslist.txt",
        output_content=pslist_content
    )

    ps_artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_ps, actor_user=user)
    assert len(ps_artifacts) == 2
    assert ps_artifacts[0].artifact_type == "PROCESS_RECORD"
    assert ps_artifacts[0].normalized_data["pid"] == 4
    assert ps_artifacts[0].normalized_data["ppid"] == 0
    assert ps_artifacts[0].normalized_data["image_name"] == "System"

    assert ps_artifacts[1].normalized_data["pid"] == 1040
    assert ps_artifacts[1].normalized_data["image_name"] == "smss.exe"

    # 2. Test netscan
    netscan_content = (
        "Offset(P)\tProto\tLocal Address\tForeign Address\tState\tPID\tOwner\tCreated\n"
        "0x1234\tTCPv4\t192.168.1.100:445\t0.0.0.0:0\tLISTENING\t4\tSystem\t2026-09-20 08:00:00\n"
        "0x5678\tTCPv4\t192.168.1.100:49152\t198.51.100.1:443\tESTABLISHED\t1040\tsmss.exe\t2026-09-20 08:01:00\n"
    )

    exec_net, raw_net, _ = create_execution_with_raw_output(
        db, case, user, tool_id="volatility_netscan", output_filename="netscan.txt",
        output_content=netscan_content
    )

    net_artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_net, actor_user=user)
    assert len(net_artifacts) == 2
    assert net_artifacts[0].artifact_type == "NETWORK_RECORD"
    assert net_artifacts[0].normalized_data["protocol"] == "TCPv4"
    assert net_artifacts[0].normalized_data["local_address"] == "192.168.1.100:445"
    assert net_artifacts[0].normalized_data["state"] == "LISTENING"
    assert net_artifacts[0].normalized_data["pid"] == 4

    assert net_artifacts[1].normalized_data["state"] == "ESTABLISHED"
    assert net_artifacts[1].normalized_data["foreign_address"] == "198.51.100.1:443"


def test_exiftool_metadata_artifact_extraction(db_session):
    """Verifies ExifTool parser extracts metadata records from JSON output."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "exif_usr", "exif_case")

    exif_json = json.dumps([
        {
            "SourceFile": "/evidence/photo1.jpg",
            "FileType": "JPEG",
            "MIMEType": "image/jpeg",
            "ImageWidth": 1920,
            "ImageHeight": 1080,
            "CreateDate": "2026:01:15 14:30:00"
        }
    ])

    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="exiftool", output_filename="exif.json",
        output_content=exif_json
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type == "METADATA_RECORD"
    assert art.normalized_data["file_type"] == "JPEG"
    assert art.normalized_data["mime_type"] == "image/jpeg"
    assert art.normalized_data["metadata"]["ImageWidth"] == 1920


# =============================================================================
# 3. UNSUPPORTED OUTPUT HANDLING TESTS
# =============================================================================

def test_unsupported_output_recorded_explicitly(db_session):
    """
    CRITICAL REQUIREMENT:
    Unsupported outputs must be recorded as UNSUPPORTED, NEVER silently dropped.
    """
    db = db_session
    user, case, _ = create_test_user_and_case(db, "unsup_usr", "unsup_case")

    raw_blob = "RANDOM_UNPARSEABLE_PROPRIETARY_BINARY_DUMP_xyz12345"

    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="unknown_closed_source_tool",
        output_filename="firmware.bin",
        output_content=raw_blob
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)

    assert len(artifacts) == 1
    unsupported = artifacts[0]
    assert unsupported.extraction_status == "UNSUPPORTED"
    assert unsupported.artifact_type == "UNSUPPORTED_OUTPUT"
    assert unsupported.parser_name == "UNSUPPORTED"
    assert unsupported.error_message is not None
    assert "No compatible parser registered" in unsupported.error_message
    assert unsupported.sha256_hash is not None
    assert unsupported.source_raw_output_hash == raw_out.sha256_hash

    # Audit event should be recorded
    audit = (
        db.query(AuditEvent)
        .filter(AuditEvent.case_id == case.id, AuditEvent.event_type == "ARTIFACT_EXTRACTION_UNSUPPORTED")
        .first()
    )
    assert audit is not None


# =============================================================================
# 4. CRYPTOGRAPHIC INTEGRITY & PROVENANCE TESTS
# =============================================================================

def test_artifact_integrity_verification_passed(db_session):
    """Verifies that an intact artifact passes cryptographic SHA-256 and lineage check."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "integ_usr", "integ_case")

    fls_content = "r/r 100-128-1: test.txt\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art = artifacts[0]

    integ = ArtifactExtractionService.verify_artifact_integrity(db=db, artifact_id=art.id, case_id=case.id)
    assert integ["integrity_status"] == "VALID"
    assert integ["expected_sha256"] == art.sha256_hash
    assert integ["calculated_sha256"] == art.sha256_hash
    assert integ["source_raw_output_hash"] == raw_out.sha256_hash
    assert integ["raw_output_current_hash"] == raw_out.sha256_hash
    assert integ["provenance_chain"]["case_id"] == case.id
    assert integ["provenance_chain"]["execution_id"] == execution.id
    assert integ["provenance_chain"]["raw_output_id"] == raw_out.id


def test_artifact_integrity_tamper_detected(db_session):
    """Verifies that modifying artifact normalized data triggers TAMPERED status."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "tamper_usr", "tamper_case")

    fls_content = "r/r 100-128-1: original.txt\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art = artifacts[0]

    # Tamper with normalized payload in DB without recomputing hash
    tampered_data = dict(art.normalized_data)
    tampered_data["filename"] = "TAMPERED_FILENAME.exe"
    art.normalized_data = tampered_data
    db.commit()

    integ = ArtifactExtractionService.verify_artifact_integrity(db=db, artifact_id=art.id, case_id=case.id)
    assert integ["integrity_status"] == "TAMPERED"
    assert integ["calculated_sha256"] != integ["expected_sha256"]


def test_artifact_integrity_missing_storage_file(db_session):
    """Verifies that deleting an artifact file on disk triggers FILE_MISSING status."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "miss_usr", "miss_case")

    fls_content = "r/r 100-128-1: file.txt\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art = artifacts[0]
    assert art.storage_path is not None

    # Remove storage file
    p = Path(art.storage_path)
    if p.exists():
        p.unlink()

    integ = ArtifactExtractionService.verify_artifact_integrity(db=db, artifact_id=art.id, case_id=case.id)
    assert integ["integrity_status"] == "FILE_MISSING"


# =============================================================================
# 5. STORAGE SEPARATION, PERMISSIONS, AND RAW IMMUTABILITY TESTS
# =============================================================================

def test_storage_separation_and_permissions(db_session):
    """
    Verifies that structured artifacts are stored separately from raw outputs,
    with strict 0o600 / 0o700 permissions.
    """
    db = db_session
    user, case, _ = create_test_user_and_case(db, "store_usr", "store_case")

    fls_content = "r/r 100-128-1: file.txt\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art = artifacts[0]
    art_path = Path(art.storage_path)

    # 1. Location check
    assert "storage/artifacts/cases" in str(art_path)
    assert art_path.exists()

    # 2. File permission check: 0o600
    file_mode = stat.S_IMODE(art_path.stat().st_mode)
    assert file_mode == 0o600

    # 3. Directory permission check: 0o700
    dir_mode = stat.S_IMODE(art_path.parent.stat().st_mode)
    assert dir_mode == 0o700


def test_prohibition_of_vault_storage(db_session):
    """Verifies that attempting to locate artifact storage inside evidence vault raises error."""
    db = db_session
    user, case, _ = create_test_user_and_case(db, "vault_chk", "vault_case")

    vault_path = settings.EVIDENCE_DIR / "vault" / case.id / "illegal_artifact.json"
    with pytest.raises(ValueError, match="CRITICAL: Artifact storage cannot be located inside evidence vault"):
        ArtifactStorageManager.validate_storage_path(vault_path, case.id, "exec-123")


def test_raw_output_immutability(db_session):
    """
    CRITICAL REQUIREMENT:
    Raw forensic outputs must NEVER be modified by artifact extraction.
    Size, hash, and content must remain strictly identical.
    """
    db = db_session
    user, case, _ = create_test_user_and_case(db, "immut_usr", "immut_case")

    content = "r/r 500-128-1: immutability_test.log\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="immut.txt",
        output_content=content
    )

    raw_path = Path(raw_out.storage_path)
    initial_bytes = raw_path.read_bytes()
    initial_sha = raw_out.sha256_hash
    initial_size = raw_out.size_bytes

    # Run extraction
    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    assert len(artifacts) >= 1

    # Verify raw output is completely untouched
    assert raw_path.read_bytes() == initial_bytes
    current_sha, current_size = calculate_sha256(str(raw_path))
    assert current_sha == initial_sha
    assert current_size == initial_size


# =============================================================================
# 6. REST API ENDPOINTS & RBAC / IDOR TESTS
# =============================================================================

def test_api_trigger_execution_extraction_and_list(db_session):
    """Verifies POST extraction and GET listing on an execution."""
    db = db_session
    user, case, headers = create_test_user_and_case(db, "api_exec", "api_case")

    fls_content = "r/r 100-128-1: file1.txt\nr/r 101-128-1: file2.txt\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    # 1. Trigger extraction via API
    extract_resp = client.post(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/extract-artifacts",
        headers=headers
    )
    assert extract_resp.status_code == 200
    batch = extract_resp.json()
    assert batch["execution_id"] == execution.id
    assert batch["extracted_artifacts_count"] == 2
    assert len(batch["artifacts"]) == 2

    # 2. List execution artifacts via API
    list_resp = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/artifacts",
        headers=headers
    )
    assert list_resp.status_code == 200
    arts = list_resp.json()
    assert len(arts) == 2
    assert arts[0]["artifact_type"] == "FILESYSTEM_RECORD"

    # 3. Filter by type
    filter_resp = client.get(
        f"/api/v1/cases/{case.id}/executions/{execution.id}/artifacts?artifact_type=EVENT_LOG_RECORD",
        headers=headers
    )
    assert filter_resp.status_code == 200
    assert len(filter_resp.json()) == 0


def test_api_evidence_level_artifacts_and_details(db_session):
    """Verifies GET evidence artifacts, artifact details, and integrity check."""
    db = db_session
    user, case, headers = create_test_user_and_case(db, "api_ev", "api_case")

    yara_content = "threat_rule /vault/file.bin\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="yara", output_filename="scan.txt",
        output_content=yara_content
    )

    # Extract
    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art_id = artifacts[0].id

    # 1. Evidence-level listing
    ev_resp = client.get(
        f"/api/v1/cases/{case.id}/evidence/{evidence.id}/artifacts",
        headers=headers
    )
    assert ev_resp.status_code == 200
    ev_arts = ev_resp.json()
    assert len(ev_arts) == 1
    assert ev_arts[0]["id"] == art_id

    # 2. Artifact details
    detail_resp = client.get(
        f"/api/v1/cases/{case.id}/artifacts/{art_id}",
        headers=headers
    )
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == art_id
    assert detail["artifact_type"] == "MALWARE_MATCH"
    assert detail["normalized_data"]["rule_name"] == "threat_rule"

    # 3. Artifact integrity check endpoint
    integ_resp = client.get(
        f"/api/v1/cases/{case.id}/artifacts/{art_id}/integrity",
        headers=headers
    )
    assert integ_resp.status_code == 200
    integ = integ_resp.json()
    assert integ["integrity_status"] == "VALID"
    assert integ["artifact_id"] == art_id

    # 4. Download artifact file endpoint
    dl_resp = client.get(
        f"/api/v1/cases/{case.id}/artifacts/{art_id}/download",
        headers=headers
    )
    assert dl_resp.status_code == 200
    payload = dl_resp.json()
    assert payload["id"] == art_id
    assert payload["artifact_type"] == "MALWARE_MATCH"


def test_case_authorization_and_idor_isolation(db_session):
    """
    CRITICAL REQUIREMENT:
    Prevents cross-case IDOR leakage. User A cannot view or extract User B's artifacts.
    """
    db = db_session
    user_a, case_a, headers_a = create_test_user_and_case(db, "usr_a", "case_a")
    user_b, case_b, headers_b = create_test_user_and_case(db, "usr_b", "case_b")

    fls_content = "r/r 100-128-1: sensitive_case_a.txt\n"
    exec_a, raw_a, ev_a = create_execution_with_raw_output(
        db, case_a, user_a, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts_a = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_a, actor_user=user_a)
    art_a = artifacts_a[0]

    # User B attempts to access Case A's execution artifacts -> 403 Forbidden
    resp = client.get(
        f"/api/v1/cases/{case_a.id}/executions/{exec_a.id}/artifacts",
        headers=headers_b
    )
    assert resp.status_code == 403

    # User B attempts to access Case A's artifact detail directly -> 403 Forbidden
    resp = client.get(
        f"/api/v1/cases/{case_a.id}/artifacts/{art_a.id}",
        headers=headers_b
    )
    assert resp.status_code == 403

    # User B attempts to download Case A's artifact file -> 403 Forbidden
    resp = client.get(
        f"/api/v1/cases/{case_a.id}/artifacts/{art_a.id}/download",
        headers=headers_b
    )
    assert resp.status_code == 403

    # IDOR check: Attempting to query Case A's artifact under Case B's path -> 404
    resp = client.get(
        f"/api/v1/cases/{case_b.id}/artifacts/{art_a.id}",
        headers=headers_b
    )
    assert resp.status_code == 404

    # Unauthenticated request -> 401 Unauthorized
    resp = client.get(
        f"/api/v1/cases/{case_a.id}/artifacts/{art_a.id}"
    )
    assert resp.status_code == 401


# =============================================================================
# 7. INVARIANT BOUNDARY TESTS
# =============================================================================

def test_strict_boundary_invariants(db_session):
    """
    CRITICAL INVARIANT:
    Structured forensic artifacts represent evidence-derived data, NOT findings or conclusions.
    DO NOT: detect attacks, correlate artifacts, infer attacker behavior, generate findings.
    """
    db = db_session
    user, case, _ = create_test_user_and_case(db, "invar_usr", "invar_case")

    fls_content = "r/r 100-128-1: malware_dropper.exe\n"
    execution, raw_out, evidence = create_execution_with_raw_output(
        db, case, user, tool_id="fls", output_filename="fls.txt",
        output_content=fls_content
    )

    artifacts = ArtifactExtractionService.extract_from_output(db=db, raw_output=raw_out, actor_user=user)
    art = artifacts[0]

    # Verify no conclusion fields exist
    forbidden_keys = [
        "finding", "finding_type", "attack_technique", "threat_actor",
        "verdict", "conclusion", "llm_summary", "correlation_score",
        "severity", "confidence_level"
    ]
    for key in forbidden_keys:
        assert key not in art.normalized_data, f"Forbidden interpretation key '{key}' found in artifact!"

    # Type must be pure data record
    assert art.artifact_type in [
        "FILESYSTEM_RECORD", "EVENT_LOG_RECORD", "MALWARE_MATCH",
        "PROCESS_RECORD", "NETWORK_RECORD", "METADATA_RECORD", "GENERIC_RECORD"
    ]
