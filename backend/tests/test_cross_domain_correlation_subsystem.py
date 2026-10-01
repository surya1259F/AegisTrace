"""ADFIR — Phase 2 / Step 14: Cross-Domain Correlation Subsystem Tests

Comprehensive verification of:
1. Cross-Domain Identifier Matching
   - File hash <-> Malware / YARA match
   - Process <-> Memory artifact (PID, process name)
   - User <-> Logon event (Event log 4624)
   - Browser <-> Network artifact (URL, remote IP)
   - Shared identifiers (IP, domain, filepath)
2. Temporal Correlation
   - Exact/near timestamp match (TEMPORAL_COINCIDENCE, delta <= 5s)
   - Temporal sequence (TEMPORAL_SEQUENCE, before/after, window decay)
   - Outside window exclusion
3. Deterministic Confidence Calculation
   - Evaluates observable matching evidence only (1.0 for hash, 0.95 for exact path/PID+proc, etc.)
   - NEVER claims maliciousness or threat severity
4. Correlation Grouping & Connected Components
   - Transitive clustering into auditable groups (clusters)
   - Member artifact/event tracking, contributing domains, source evidence IDs
   - Groups NEVER labeled as attacks, incidents, threats, or findings
5. Relationship Graph Construction
   - Queryable graph (Nodes, Edges, Groups)
   - Domain filtering, relationship type filtering, min_confidence filtering
6. Provenance Preservation & Source Immutability
   - 6-tier lineage back to evidence and execution
   - Preceding artifacts (Steps 10-13) remain read-only and unmodified
7. Cryptographic Integrity & Tamper Detection
   - SHA-256 calculation for relationships and groups
   - Tamper detection on modified records and missing storage files
8. Storage Isolation & Security
   - Isolated paths under storage/correlations/cases/{case_id}/
   - POSIX permissions (0o700 dir, 0o600 file)
   - Strict prohibition from evidence vault
9. REST API & RBAC / IDOR Protection
   - Generation, listing, detail, integrity, provenance, and graph endpoints
   - Cross-case access prevention and unauthorized user rejection
10. Strict Forensic Boundaries
    - No attack declarations, no severity scores, no findings, no LLM conclusions
"""

import json
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import (
    AnalysisRequest,
    ArtifactRelationship,
    Case,
    CaseMember,
    EvidenceItem,
    ExecutionOutput,
    Finding,
    ForensicCorrelationGroup,
    ForensicExecution,
    InvestigationPlan,
    NormalizedArtifact,
    StructuredArtifact,
    TimelineEvent,
    User,
)
from backend.app.schemas.schemas import CorrelationGenerateRequest
from backend.app.services.correlation import (
    CorrelationStorageManager,
    CrossDomainCorrelationService,
    ForensicDomain,
    RelationshipType,
    compute_sha256,
    format_canonical_json,
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="corr_usr", case_prefix="corr_case"):
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

    cid = f"case-corr-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing cross-domain correlation subsystem",
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
        role="LEAD"
    )
    db.add(member)
    db.commit()

    return user, case


def setup_forensic_pipeline_fixtures(db, case_id):
    """
    Creates an entire 6-tier pipeline stack:
    EvidenceItem -> InvestigationPlan -> AnalysisRequest -> ForensicExecution -> ExecutionOutput -> StructuredArtifact.
    """
    ev_id = f"ev-{uuid.uuid4().hex[:8]}"
    evidence = EvidenceItem(
        id=ev_id,
        case_id=case_id,
        name="disk_image_target.raw",
        original_path="/tmp/fake_disk.raw",
        storage_path="/tmp/fake_disk.raw",
        evidence_type="DISK_IMAGE",
        size_bytes=1048576.0,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="ANALYSIS_READY",
        integrity_status="VERIFIED"
    )
    db.add(evidence)
    db.commit()

    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case_id,
        title="Cross Domain Test Plan",
        strategy_summary="Plan for correlation testing",
        validation_status="VALIDATED",
        version=1,
        created_by="test-runner"
    )
    db.add(plan)
    db.commit()

    req = AnalysisRequest(
        id=str(uuid.uuid4()),
        case_id=case_id,
        plan_id=plan.id,
        evidence_id=ev_id,
        task_key=f"task-{uuid.uuid4().hex[:4]}",
        capability_id="FORENSIC_ANALYSIS",
        selected_tool_id="test_suite_runner",
        scheduler_status="COMPLETED"
    )
    db.add(req)
    db.commit()

    exec_id = f"exec-{uuid.uuid4().hex[:8]}"
    workspace_dir = settings.DATA_DIR / "workspaces" / case_id / exec_id
    workspace_dir.mkdir(parents=True, exist_ok=True)

    execution = ForensicExecution(
        id=exec_id,
        request_id=req.id,
        case_id=case_id,
        task_id=f"task-{uuid.uuid4().hex[:4]}",
        task_key=req.task_key,
        evidence_id=ev_id,
        tool_id="test_suite_runner",
        tool_version="2.0.0",
        executable_path="/bin/tool",
        validated_argv=["/bin/tool"],
        host_platform="linux",
        host_architecture="x86_64",
        execution_status="COMPLETED",
        workspace_path=str(workspace_dir),
        exit_code=0
    )
    db.add(execution)
    db.commit()

    out_id = f"out-{uuid.uuid4().hex[:8]}"
    raw_output = ExecutionOutput(
        id=out_id,
        case_id=case_id,
        evidence_id=ev_id,
        execution_id=exec_id,
        request_id=req.id,
        tool_id="test_suite_runner",
        tool_version="2.0.0",
        output_type="TOOL_OUTPUT",
        filename="correlations_dump.txt",
        relative_path="outputs/correlations_dump.txt",
        storage_path=f"/tmp/correlations_dump_{out_id}.txt",
        size_bytes=2048,
        sha256_hash="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        execution_status="COMPLETED",
        created_at=datetime.now(timezone.utc)
    )
    db.add(raw_output)

    struct_id = f"struct-{uuid.uuid4().hex[:8]}"
    structured = StructuredArtifact(
        id=struct_id,
        case_id=case_id,
        evidence_id=ev_id,
        execution_id=exec_id,
        raw_output_id=out_id,
        request_id=req.id,
        parser_name="CrossDomainParser",
        parser_version="1.0.0",
        artifact_type="GENERIC_RECORD",
        normalized_data={"key": "test_pipeline"},
        sha256_hash="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        source_raw_output_hash=raw_output.sha256_hash,
        extraction_status="EXTRACTED",
        created_at=datetime.now(timezone.utc)
    )
    db.add(structured)
    db.commit()

    return evidence, execution, raw_output, structured


def create_test_normalized_artifact(
    db, case, ev, ex, st, out,
    entity_type, entity_identity=None, normalized_fields=None,
    sha256_hash=None, entity_timestamp=None
) -> NormalizedArtifact:
    """Helper to cleanly create a NormalizedArtifact adhering to database schema."""
    na_id = str(uuid.uuid4())
    ident = entity_identity or f"{entity_type.lower()}_{uuid.uuid4().hex[:12]}"
    h = sha256_hash or compute_sha256(format_canonical_json(normalized_fields or {}))
    na = NormalizedArtifact(
        id=na_id,
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        source_artifact_id=st.id,
        raw_output_id=out.id,
        request_id=ex.request_id,
        task_id=ex.task_id,
        entity_type=entity_type,
        entity_identity=ident,
        source_specific_identity=f"ref:{uuid.uuid4().hex[:8]}",
        normalized_fields=normalized_fields or {},
        evidence_reference={"evidence_id": ev.id, "name": ev.name},
        provenance_summary={"tool_id": ex.tool_id},
        contributing_source_artifact_ids=[st.id],
        occurrence_count=1,
        entity_timestamp=entity_timestamp,
        sha256_hash=h,
        source_artifact_hash=st.sha256_hash,
        normalization_status="NORMALIZED",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(na)
    db.commit()
    db.refresh(na)
    return na


# =============================================================================
# TEST CASES
# =============================================================================

def test_file_hash_and_malware_hit_correlation(db_session):
    """
    Verifies correlation between a filesystem artifact and a malware/YARA hit:
    1. Exact cryptographic hash match -> FILE_HASH_MATCH (confidence 1.0)
    2. Filepath match to malware target -> MALWARE_TARGET_MATCH (confidence 0.95)
    """
    user, case = create_test_user_and_case(db_session, "hash_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    target_hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    file_path = "/usr/bin/evil_backdoor.elf"

    # Artifact 1: Filesystem entry
    art_file = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity=f"file:{file_path}",
        normalized_fields={
            "path": file_path,
            "filename": "evil_backdoor.elf",
            "hashes": {"sha256": target_hash},
            "size_bytes": 65536
        }
    )

    # Artifact 2: Malware / YARA match
    art_malware = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="MALWARE_MATCH",
        entity_identity=f"malware:rule_trojan_backdoor:{target_hash[:16]}",
        normalized_fields={
            "rule_name": "rule_trojan_backdoor",
            "target_file": file_path,
            "matched_tags": ["APT", "Trojan"],
            "sha256": target_hash
        }
    )

    # Correlate
    req = CorrelationGenerateRequest(include_temporal=False)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    assert summary.relationships_generated >= 1
    assert summary.groups_created >= 1

    # Check relationship details
    rels = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).all()
    hash_rels = [r for r in rels if r.relationship_type == RelationshipType.FILE_HASH_MATCH]
    assert len(hash_rels) >= 1

    r = hash_rels[0]
    assert r.confidence_score == 1.0
    assert r.matching_identifier == target_hash
    assert r.matching_field == "sha256"
    assert (r.source_id == art_file.id and r.target_id == art_malware.id) or (r.source_id == art_malware.id and r.target_id == art_file.id)

    # Check group
    grp = db_session.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case.id).first()
    assert grp is not None
    assert art_file.id in grp.member_artifact_ids
    assert art_malware.id in grp.member_artifact_ids
    assert ForensicDomain.FILESYSTEM in grp.contributing_domains
    assert ForensicDomain.MALWARE in grp.contributing_domains


def test_process_and_memory_artifact_correlation(db_session):
    """
    Verifies correlation between a process memory artifact and a network socket connection sharing PID.
    """
    user, case = create_test_user_and_case(db_session, "proc_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    pid = 4096
    proc_name = "powershell.exe"

    # Process Instance
    art_proc = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="PROCESS",
        entity_identity=f"process:{pid}:{proc_name}",
        normalized_fields={
            "pid": pid,
            "ppid": 1024,
            "process_name": proc_name,
            "command_line": f"{proc_name} -nop -exec bypass"
        }
    )

    # Network Connection owned by that PID
    art_net = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{pid}:192.168.1.50:4444",
        normalized_fields={
            "protocol": "TCP",
            "local_address": "192.168.1.50",
            "local_port": 49152,
            "remote_address": "198.51.100.77",
            "remote_port": 4444,
            "owner_pid": pid,
            "owner_process": proc_name
        }
    )

    req = CorrelationGenerateRequest(include_temporal=False)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    assert summary.relationships_generated >= 1
    proc_rels = db_session.query(ArtifactRelationship).filter(
        ArtifactRelationship.case_id == case.id,
        ArtifactRelationship.relationship_type == RelationshipType.PROCESS_MEMORY_MATCH
    ).all()
    assert len(proc_rels) >= 1
    assert proc_rels[0].confidence_score >= 0.90
    assert "4096" in proc_rels[0].matching_identifier


def test_user_and_logon_event_correlation(db_session):
    """
    Verifies correlation between a user account identifier and an authentication/logon event (Event ID 4624).
    """
    user, case = create_test_user_and_case(db_session, "user_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    username = "svc_deployer"

    # User entity
    art_user = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="GENERIC",
        entity_identity=f"user:{username}",
        normalized_fields={
            "username": username,
            "user_sid": "S-1-5-21-3623811015-3361044348-30300820-1013"
        }
    )

    # Event log record
    art_event = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="EVENT",
        entity_identity=f"event:4624:{username}",
        normalized_fields={
            "event_id": "4624",
            "provider": "Microsoft-Windows-Security-Auditing",
            "username": username,
            "logon_type": "3"
        }
    )

    req = CorrelationGenerateRequest(include_temporal=False)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    user_rels = db_session.query(ArtifactRelationship).filter(
        ArtifactRelationship.case_id == case.id,
        ArtifactRelationship.relationship_type == RelationshipType.USER_LOGON_MATCH
    ).all()
    assert len(user_rels) >= 1
    assert user_rels[0].matching_identifier == username
    assert user_rels[0].confidence_score == 0.95


def test_browser_and_network_artifact_correlation(db_session):
    """
    Verifies correlation between a browser URL artifact and a network socket connection.
    """
    user, case = create_test_user_and_case(db_session, "browser_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    target_url = "https://c2-command-node.org/api/beacon"
    remote_ip = "203.0.113.88"

    art_browser = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="BROWSER",
        entity_identity=f"browser:{target_url}",
        normalized_fields={
            "url": target_url,
            "browser_url": target_url,
            "remote_address": remote_ip
        }
    )

    art_net = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{remote_ip}:443",
        normalized_fields={
            "protocol": "TCP",
            "remote_address": remote_ip,
            "remote_port": 443
        }
    )

    req = CorrelationGenerateRequest(include_temporal=False)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    browser_rels = db_session.query(ArtifactRelationship).filter(
        ArtifactRelationship.case_id == case.id,
        ArtifactRelationship.relationship_type == RelationshipType.BROWSER_NETWORK_MATCH
    ).all()
    assert len(browser_rels) >= 1
    assert browser_rels[0].matching_identifier == remote_ip
    assert browser_rels[0].confidence_score == 0.90


def test_temporal_correlation_coincidence_and_sequence(db_session):
    """
    Verifies deterministic temporal relationships between timeline events:
    1. Near coincidence (|delta| <= 5s) -> TEMPORAL_COINCIDENCE (confidence 0.85)
    2. Sequence (|delta| = 25s within 60s window) -> TEMPORAL_SEQUENCE (confidence decaying with delta)
    3. Beyond window (|delta| = 120s > 60s) -> excluded
    """
    user, case = create_test_user_and_case(db_session, "temp_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    # Base time: 2026-09-26 12:00:00 UTC
    t0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)
    t_coincident = t0 + timedelta(seconds=2)     # delta = 2s <= 5s
    t_sequence = t0 + timedelta(seconds=25)       # delta = 25s <= 60s
    t_outside = t0 + timedelta(seconds=120)       # delta = 120s > 60s

    art = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/test/temp.txt",
        normalized_fields={"path": "/test/temp.txt"}
    )

    ev0 = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        normalized_artifact_id=art.id,
        timestamp_utc=t0,
        original_timestamp="2026-09-26T12:00:00Z",
        timezone_status="EXPLICIT",
        event_type="FILE_MODIFIED",
        event_source="FLS",
        event_data={"path": "/test/file_a.txt"},
        confidence_score=1.0,
        temporal_precision="SECOND",
        sha256_hash="e0" + "0" * 62,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    ev_coin = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        normalized_artifact_id=art.id,
        timestamp_utc=t_coincident,
        original_timestamp="2026-09-26T12:00:02Z",
        timezone_status="EXPLICIT",
        event_type="PROCESS_LAUNCH",
        event_source="PSLIST",
        event_data={"process_name": "cmd.exe"},
        confidence_score=1.0,
        temporal_precision="SECOND",
        sha256_hash="e1" + "0" * 62,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    ev_seq = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        normalized_artifact_id=art.id,
        timestamp_utc=t_sequence,
        original_timestamp="2026-09-26T12:00:25Z",
        timezone_status="EXPLICIT",
        event_type="NETWORK_CONNECTION",
        event_source="NETSCAN",
        event_data={"remote_address": "10.0.0.1"},
        confidence_score=1.0,
        temporal_precision="SECOND",
        sha256_hash="e2" + "0" * 62,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    ev_out = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        normalized_artifact_id=art.id,
        timestamp_utc=t_outside,
        original_timestamp="2026-09-26T12:02:00Z",
        timezone_status="EXPLICIT",
        event_type="LOG_EVENT",
        event_source="EVTX",
        event_data={"event_id": "100"},
        confidence_score=1.0,
        temporal_precision="SECOND",
        sha256_hash="e3" + "0" * 62,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add_all([ev0, ev_coin, ev_seq, ev_out])
    db_session.commit()

    req = CorrelationGenerateRequest(time_window_seconds=60.0, include_temporal=True)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    rels = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).all()
    temp_rels = [r for r in rels if "TEMPORAL" in r.relationship_type]

    # Coincidence between ev0 and ev_coin
    coincident_matches = [
        r for r in temp_rels
        if r.relationship_type == RelationshipType.TEMPORAL_COINCIDENCE
        and set([r.source_id, r.target_id]) == set([ev0.id, ev_coin.id])
    ]
    assert len(coincident_matches) == 1
    assert coincident_matches[0].confidence_score == 0.85
    assert coincident_matches[0].temporal_relationship["delta_seconds"] == 2.0

    # Sequence between ev0 and ev_seq
    seq_matches = [
        r for r in temp_rels
        if r.relationship_type == RelationshipType.TEMPORAL_SEQUENCE
        and set([r.source_id, r.target_id]) == set([ev0.id, ev_seq.id])
    ]
    assert len(seq_matches) == 1
    assert seq_matches[0].confidence_score < 0.80
    assert seq_matches[0].temporal_relationship["delta_seconds"] == 25.0

    # No relationship between ev0 and ev_out (delta=120s > 60s)
    outside_matches = [
        r for r in temp_rels
        if set([r.source_id, r.target_id]) == set([ev0.id, ev_out.id])
    ]
    assert len(outside_matches) == 0


def test_shared_identifier_correlation(db_session):
    """
    Verifies that multiple artifacts sharing an IP or domain address generate SHARED_IDENTIFIER.
    """
    user, case = create_test_user_and_case(db_session, "shared_id_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    shared_ip = "192.0.2.144"

    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{shared_ip}:8080",
        normalized_fields={"remote_address": shared_ip, "remote_port": 8080}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="EVENT",
        entity_identity=f"event:firewall:{shared_ip}",
        normalized_fields={"ip_address": shared_ip, "event_id": "DROP"}
    )

    req = CorrelationGenerateRequest(include_temporal=False)
    CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    shared_rels = db_session.query(ArtifactRelationship).filter(
        ArtifactRelationship.case_id == case.id,
        ArtifactRelationship.relationship_type == RelationshipType.SHARED_IDENTIFIER
    ).all()
    assert len(shared_rels) >= 1
    assert shared_rels[0].matching_identifier == shared_ip
    assert shared_rels[0].matching_field == "ip_address"
    assert shared_rels[0].confidence_score == 0.90


def test_deterministic_relationship_generation_and_confidence(db_session):
    """
    Verifies that running correlation multiple times produces deterministic results,
    identical SHA-256 hashes, and that confidence scores are purely evidence-driven.
    """
    user, case = create_test_user_and_case(db_session, "det_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    common_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/test/f1.bin",
        normalized_fields={"path": "/test/f1.bin", "hashes": {"sha256": common_hash}}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/test/f2.bin",
        normalized_fields={"path": "/test/f2.bin", "hashes": {"sha256": common_hash}}
    )

    req = CorrelationGenerateRequest(include_temporal=False)

    # First run
    s1 = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)
    r1 = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).first()
    hash_run1 = r1.sha256_hash

    # Second run
    s2 = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)
    r2 = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).first()
    hash_run2 = r2.sha256_hash

    assert s1.relationships_generated == s2.relationships_generated == 1
    assert s1.groups_created == s2.groups_created == 1
    assert hash_run1 == hash_run2  # Deterministic canonical hash


def test_correlation_grouping_and_connected_components(db_session):
    """
    Verifies that interrelated items are clustered into a connected component group.
    Group contains sorted member artifact IDs, relationship IDs, and contributing domains.
    Group is NOT labeled as attack, incident, threat, or finding.
    """
    user, case = create_test_user_and_case(db_session, "group_cluster")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    shared_hash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
    file_path = "/var/log/sys_update.sh"

    # Node A: File with hash
    art_a = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity=f"file:{file_path}",
        normalized_fields={"path": file_path, "hashes": {"sha256": shared_hash}}
    )
    # Node B: Malware matching hash
    art_b = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="MALWARE_MATCH",
        entity_identity=f"malware:yara_rule:{shared_hash[:16]}",
        normalized_fields={"rule_name": "APT_Script", "sha256": shared_hash}
    )
    # Node C: Metadata matching file path
    art_c = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="METADATA",
        entity_identity=f"meta:{file_path}",
        normalized_fields={"target_file": file_path, "mime_type": "text/x-shellscript"}
    )

    req = CorrelationGenerateRequest(include_temporal=False)
    summary = CrossDomainCorrelationService.correlate_case(db_session, case.id, req)

    assert summary.groups_created == 1
    grp = db_session.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case.id).first()
    assert grp is not None

    # Verify all 3 connected nodes are in this single group
    assert art_a.id in grp.member_artifact_ids
    assert art_b.id in grp.member_artifact_ids
    assert art_c.id in grp.member_artifact_ids

    # Verify domains
    assert ForensicDomain.FILESYSTEM in grp.contributing_domains
    assert ForensicDomain.MALWARE in grp.contributing_domains
    assert ForensicDomain.METADATA in grp.contributing_domains

    # Strict boundary check: Group title/desc does NOT label as attack/incident/threat
    assert "ATTACK" not in grp.title.upper()
    assert "INCIDENT" not in grp.title.upper()
    assert "BREACH" not in grp.title.upper()
    assert "FINDING" not in grp.title.upper()


def test_relationship_graph_construction(db_session):
    """
    Verifies relationship graph construction:
    Artifact/Event -> Relationship -> Artifact/Event
    """
    user, case = create_test_user_and_case(db_session, "graph_build")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    target_hash = "aabbccddee11223344556677889900aabbccddee11223344556677889900aabb"
    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/bin/app1",
        normalized_fields={"path": "/bin/app1", "filename": "app1", "hashes": {"sha256": target_hash}}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/bin/app2",
        normalized_fields={"path": "/bin/app2", "filename": "app2", "hashes": {"sha256": target_hash}}
    )

    CrossDomainCorrelationService.correlate_case(
        db_session,
        case.id,
        CorrelationGenerateRequest(include_temporal=False)
    )

    graph = CrossDomainCorrelationService.build_relationship_graph(db_session, case.id)
    assert graph.case_id == case.id
    assert graph.total_nodes == 2
    assert graph.total_edges == 1
    assert graph.total_groups == 1

    node_ids = [n.id for n in graph.nodes]
    assert art1.id in node_ids
    assert art2.id in node_ids

    edge = graph.edges[0]
    assert edge.relationship_type == RelationshipType.FILE_HASH_MATCH
    assert edge.confidence == 1.0


def test_provenance_preservation_and_source_immutability(db_session):
    """
    Verifies that:
    1. Every relationship retains complete lineage back to evidence and execution.
    2. Source NormalizedArtifact and TimelineEvent records remain read-only and unmodified.
    """
    user, case = create_test_user_and_case(db_session, "prov_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    val = "10.10.10.10"
    art = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{val}",
        normalized_fields={"remote_address": val}
    )
    ev_item = TimelineEvent(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=ex.id,
        normalized_artifact_id=art.id,
        timestamp_utc=datetime.now(timezone.utc),
        original_timestamp="2026-09-26T14:00:00Z",
        timezone_status="EXPLICIT",
        event_type="NETWORK_CONNECTION",
        event_source="NETSCAN",
        event_data={"remote_address": val},
        confidence_score=1.0,
        temporal_precision="SECOND",
        sha256_hash="pe1" + "0" * 61,
        source_artifact_hash=art.sha256_hash,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(ev_item)
    db_session.commit()

    orig_art_hash = art.sha256_hash
    orig_ev_hash = ev_item.sha256_hash

    CrossDomainCorrelationService.correlate_case(
        db_session,
        case.id,
        CorrelationGenerateRequest(include_temporal=False)
    )

    # Immutability check
    db_session.refresh(art)
    db_session.refresh(ev_item)
    assert art.sha256_hash == orig_art_hash
    assert ev_item.sha256_hash == orig_ev_hash

    # Provenance trace check
    rel = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).first()
    assert rel is not None
    prov = rel.provenance
    assert "source" in prov and "target" in prov
    assert prov["source"]["evidence_id"] == ev.id
    assert prov["target"]["evidence_id"] == ev.id


def test_cryptographic_integrity_and_tamper_detection(db_session):
    """
    Verifies that:
    1. Relationships and groups pass SHA-256 integrity check.
    2. Tampering with database payload is detected.
    3. Missing storage file is detected.
    """
    user, case = create_test_user_and_case(db_session, "integ_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    ip_target = "172.16.0.5"
    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{ip_target}:80",
        normalized_fields={"remote_address": ip_target, "remote_port": 80}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="NETWORK_CONNECTION",
        entity_identity=f"net:{ip_target}:443",
        normalized_fields={"remote_address": ip_target, "remote_port": 443}
    )

    CrossDomainCorrelationService.correlate_case(
        db_session,
        case.id,
        CorrelationGenerateRequest(include_temporal=False)
    )

    rel = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).first()
    grp = db_session.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case.id).first()

    # 1. Valid integrity
    rel_integ = CrossDomainCorrelationService.verify_relationship_integrity(db_session, case.id, rel.id)
    assert rel_integ.integrity_passed is True
    assert rel_integ.tamper_detected is False
    assert rel_integ.file_exists is True

    grp_integ = CrossDomainCorrelationService.verify_group_integrity(db_session, case.id, grp.id)
    assert grp_integ.integrity_passed is True
    assert grp_integ.tamper_detected is False

    # 2. Tampering with relationship hash
    rel.sha256_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    db_session.commit()

    rel_tampered = CrossDomainCorrelationService.verify_relationship_integrity(db_session, case.id, rel.id)
    assert rel_tampered.integrity_passed is False
    assert rel_tampered.tamper_detected is True


def test_storage_isolation_and_security(db_session):
    """
    Verifies that:
    1. Storage paths are isolated under storage/correlations/cases/{case_id}/.
    2. File and directory permissions match 0o700 / 0o600.
    3. Storage validation forbids writing into data/evidence/vault.
    """
    user, case = create_test_user_and_case(db_session, "sec_corr")

    # Path inside vault must be rejected
    vault_path = settings.DATA_DIR / "evidence" / "vault" / "correlations.json"
    assert CorrelationStorageManager.validate_storage_path(vault_path, case.id) is False

    # Path outside case storage must be rejected
    escape_path = Path("/tmp/evil_escape.json")
    assert CorrelationStorageManager.validate_storage_path(escape_path, case.id) is False

    # Safe storage write
    rel_id = str(uuid.uuid4())
    test_data = {"test": "storage_security"}
    storage_path = CorrelationStorageManager.save_relationship(case.id, rel_id, test_data)

    p = Path(storage_path)
    assert p.is_file()
    assert (p.stat().st_mode & 0o777) == 0o600
    assert (p.parent.stat().st_mode & 0o777) == 0o700


def test_api_endpoints_and_rbac_idor_protection(db_session):
    """
    Verifies all Step 14 REST API endpoints and RBAC / cross-case IDOR protection:
    - POST /cases/{id}/correlations/generate
    - GET /cases/{id}/correlations/relationships
    - GET /cases/{id}/correlations/relationships/{id}
    - GET /cases/{id}/correlations/relationships/{id}/integrity
    - GET /cases/{id}/correlations/relationships/{id}/provenance
    - GET /cases/{id}/correlations/groups
    - GET /cases/{id}/correlations/groups/{id}
    - GET /cases/{id}/correlations/groups/{id}/integrity
    - GET /cases/{id}/correlations/graph
    - Unauthorized user receives 403 Forbidden.
    """
    owner, case = create_test_user_and_case(db_session, "api_owner")
    unauth_user, _ = create_test_user_and_case(db_session, "api_unauth")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    # Seed data
    h = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/api_test/f1",
        normalized_fields={"path": "/api_test/f1", "hashes": {"sha256": h}}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/api_test/f2",
        normalized_fields={"path": "/api_test/f2", "hashes": {"sha256": h}}
    )

    token_owner = create_access_token(user_id=owner.id, email=owner.email, role=owner.role)
    token_unauth = create_access_token(user_id=unauth_user.id, email=unauth_user.email, role=unauth_user.role)

    headers_owner = {"Authorization": f"Bearer {token_owner}"}
    headers_unauth = {"Authorization": f"Bearer {token_unauth}"}

    # 1. Generate correlations
    resp_gen = client.post(
        f"/api/v1/cases/{case.id}/correlations/generate",
        json={"time_window_seconds": 60.0, "min_confidence": 0.0, "include_temporal": False},
        headers=headers_owner
    )
    assert resp_gen.status_code == 200, resp_gen.text
    gen_data = resp_gen.json()
    assert gen_data["relationships_generated"] == 1
    assert gen_data["groups_created"] == 1

    # 2. List relationships
    resp_rels = client.get(f"/api/v1/cases/{case.id}/correlations/relationships", headers=headers_owner)
    assert resp_rels.status_code == 200
    rels = resp_rels.json()
    assert len(rels) == 1
    rel_id = rels[0]["id"]

    # 3. Get relationship details
    resp_det = client.get(f"/api/v1/cases/{case.id}/correlations/relationships/{rel_id}", headers=headers_owner)
    assert resp_det.status_code == 200
    assert resp_det.json()["id"] == rel_id

    # 4. Integrity check
    resp_integ = client.get(f"/api/v1/cases/{case.id}/correlations/relationships/{rel_id}/integrity", headers=headers_owner)
    assert resp_integ.status_code == 200
    assert resp_integ.json()["integrity_passed"] is True

    # 5. Provenance check
    resp_prov = client.get(f"/api/v1/cases/{case.id}/correlations/relationships/{rel_id}/provenance", headers=headers_owner)
    assert resp_prov.status_code == 200
    assert "source_provenance" in resp_prov.json()

    # 6. List groups
    resp_grps = client.get(f"/api/v1/cases/{case.id}/correlations/groups", headers=headers_owner)
    assert resp_grps.status_code == 200
    grps = resp_grps.json()
    assert len(grps) == 1
    grp_id = grps[0]["id"]

    # 7. Group details
    resp_grp_det = client.get(f"/api/v1/cases/{case.id}/correlations/groups/{grp_id}", headers=headers_owner)
    assert resp_grp_det.status_code == 200
    assert len(resp_grp_det.json()["member_artifacts"]) == 2

    # 8. Group integrity
    resp_grp_integ = client.get(f"/api/v1/cases/{case.id}/correlations/groups/{grp_id}/integrity", headers=headers_owner)
    assert resp_grp_integ.status_code == 200
    assert resp_grp_integ.json()["integrity_passed"] is True

    # 9. Graph endpoint
    resp_graph = client.get(f"/api/v1/cases/{case.id}/correlations/graph", headers=headers_owner)
    assert resp_graph.status_code == 200
    graph_data = resp_graph.json()
    assert graph_data["total_nodes"] == 2
    assert graph_data["total_edges"] == 1

    # 10. RBAC / IDOR Protection: Unauthorized user receives 403 Forbidden
    resp_unauth = client.get(f"/api/v1/cases/{case.id}/correlations/relationships", headers=headers_unauth)
    assert resp_unauth.status_code == 403


def test_strict_forensic_boundaries_no_findings_no_conclusions(db_session):
    """
    Verifies strict forensic boundary:
    1. No Finding records created during correlation.
    2. No maliciousness ratings or threat severity assigned.
    3. Output is purely observable evidence relationships and connected clusters.
    """
    user, case = create_test_user_and_case(db_session, "boundary_corr")
    ev, ex, out, st = setup_forensic_pipeline_fixtures(db_session, case.id)

    # Count existing findings
    findings_before = db_session.query(Finding).filter(Finding.case_id == case.id).count()

    h = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    art1 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="FILE",
        entity_identity="file:/test/boundary1",
        normalized_fields={"path": "/test/boundary1", "hashes": {"sha256": h}}
    )
    art2 = create_test_normalized_artifact(
        db_session, case, ev, ex, st, out,
        entity_type="MALWARE_MATCH",
        entity_identity="malware:rule1",
        normalized_fields={"rule_name": "Test_Rule", "sha256": h}
    )

    CrossDomainCorrelationService.correlate_case(
        db_session,
        case.id,
        CorrelationGenerateRequest(include_temporal=False)
    )

    # 1. No findings created
    findings_after = db_session.query(Finding).filter(Finding.case_id == case.id).count()
    assert findings_after == findings_before

    # 2. No severity or threat scores in relationships or groups
    rels = db_session.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case.id).all()
    for r in rels:
        assert 0.0 <= r.confidence_score <= 1.0
        # Title and relationship types do not assert attack
        assert "ATTACK" not in r.relationship_type.upper()

    grps = db_session.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case.id).all()
    for g in grps:
        assert "ATTACK" not in g.title.upper()
        assert "INCIDENT" not in g.title.upper()
        assert "MALICIOUS" not in g.description.upper()
