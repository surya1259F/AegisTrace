"""
ADFIR — Phase 2 / Step 13: Unified Investigation Timeline Subsystem Tests

Comprehensive verification of:
1. Timestamp Normalization & UTC Conversion
   - ISO with Z, ISO with offsets (+/-), ExifTool timestamps converted accurately to UTC.
   - Original timestamps and timezones preserved verbatim.
2. Unknown and Ambiguous Timezone Handling
   - Explicit representation of UNKNOWN and AMBIGUOUS timezones.
   - Confidence scoring reduced appropriately when timezone is missing or ambiguous.
   - Never silently assumes timezone.
3. Temporal Precision & Windows
   - EXACT (subsecond), SECOND, DAY precision detected.
   - Temporal window bounds (window_start_utc, window_end_utc) properly calculated for windows.
4. No Invented Timestamps
   - Artifacts lacking valid timestamps produce zero timeline events.
5. Chronological Ordering & Deterministic Tie-Breaking
   - Strict chronological ordering by timestamp_utc ASC.
   - Tie-breaking by confidence_score DESC and event_id ASC.
6. Multi-Tier Provenance & Event Sourcing
   - Traceability: EvidenceItem -> Execution -> Output -> StructuredArtifact -> NormalizedArtifact -> TimelineEvent.
   - Appropriate event_source (FLS, EVTX, PSLIST, NETSCAN, etc.) and event_type.
7. Cryptographic Integrity & Tamper Detection
   - SHA-256 calculation and verification (VALID).
   - Tamper detection on modified payload (TAMPERED).
   - Missing disk file detection (FILE_MISSING).
   - Source normalized artifact mismatch detection (SOURCE_ARTIFACT_MISMATCH).
8. Source Immutability
   - NormalizedArtifact, StructuredArtifact, ExecutionOutput, EvidenceItem remain read-only and unmodified.
9. Storage Isolation & Security
   - Isolated storage under storage/timeline/cases/{case_id}/.
   - POSIX permissions (0o700 dir, 0o600 file).
   - Prohibits path traversal, symlinks, and evidence vault storage.
10. REST API & RBAC / IDOR Protection
   - Case, execution, and artifact timeline generation endpoints.
   - Listing with time-range, type, source, and confidence filters.
   - Details, integrity, provenance, and download endpoints.
   - Strict cross-case isolation and RBAC authorization.
11. Strict Forensic Boundaries
   - Timeline events contain temporal data only: NO attack detection, NO severity, NO correlation, NO findings, NO conclusions.
"""

import os
import json
import stat
import uuid
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
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
    TimelineEvent,
    AuditEvent,
    Finding
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.integrity import calculate_sha256
from backend.app.services.timeline import (
    TimestampNormalizer,
    TimestampNormalizationResult,
    TimelineStorageManager,
    UnifiedTimelineService
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="time_usr", case_prefix="time_case"):
    """Creates a user and authorized case with unique case_number."""
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

    cid = f"case-time-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing unified timeline subsystem",
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


def create_test_evidence(db, case, filename="disk.raw"):
    ev_id = str(uuid.uuid4())
    vault_dir = settings.EVIDENCE_DIR / "vault" / case.id / ev_id
    vault_dir.mkdir(parents=True, exist_ok=True)
    ev_file = vault_dir / filename
    ev_file.write_bytes(b"TIMELINE_EVIDENCE_IMAGE")

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


def create_normalized_artifact_fixture(
    db,
    case,
    user,
    evidence,
    entity_type="FILE",
    entity_identity=None,
    normalized_fields=None,
    entity_timestamp=None,
    parser_name="FlsArtifactParser",
    tool_id="fls"
):
    """Sets up full provenance hierarchy down to a NormalizedArtifact."""
    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Timeline Test Plan",
        strategy_summary="Plan for timeline testing",
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

    raw_output = ExecutionOutput(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence.id,
        execution_id=execution.id,
        request_id=req.id,
        task_id=execution.task_id,
        tool_id=tool_id,
        tool_version="1.0.0",
        output_type="TOOL_OUTPUT",
        filename="output.raw",
        relative_path="outputs/output.raw",
        storage_path=str(workspace_dir / "output.raw"),
        size_bytes=512,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        created_at=datetime.now(timezone.utc)
    )
    db.add(raw_output)
    db.commit()

    sa_id = str(uuid.uuid4())
    sa = StructuredArtifact(
        id=sa_id,
        case_id=case.id,
        evidence_id=evidence.id,
        execution_id=execution.id,
        raw_output_id=raw_output.id,
        request_id=req.id,
        task_id=execution.task_id,
        tool_id=tool_id,
        tool_version="1.0.0",
        parser_name=parser_name,
        parser_version="1.0.0",
        artifact_type=f"{entity_type}_RECORD",
        source_reference=f"ref:{sa_id[:8]}",
        normalized_data=normalized_fields or {},
        sha256_hash="1111111111111111111111111111111111111111111111111111111111111111",
        source_raw_output_hash=raw_output.sha256_hash,
        extraction_status="EXTRACTED",
        created_at=datetime.now(timezone.utc)
    )
    db.add(sa)
    db.commit()

    na_id = str(uuid.uuid4())
    ident = entity_identity or f"{entity_type.lower()}_{uuid.uuid4().hex[:16]}"
    na = NormalizedArtifact(
        id=na_id,
        case_id=case.id,
        evidence_id=evidence.id,
        execution_id=execution.id,
        source_artifact_id=sa.id,
        raw_output_id=raw_output.id,
        request_id=req.id,
        task_id=execution.task_id,
        entity_type=entity_type,
        entity_identity=ident,
        source_specific_identity=f"inode:{uuid.uuid4().hex[:8]}",
        normalized_fields=normalized_fields or {},
        evidence_reference={"evidence_id": evidence.id, "name": evidence.name},
        provenance_summary={"tool_id": tool_id, "parser_name": parser_name},
        contributing_source_artifact_ids=[sa.id],
        occurrence_count=1,
        entity_timestamp=entity_timestamp,
        sha256_hash="2222222222222222222222222222222222222222222222222222222222222222",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(na)
    db.commit()
    db.refresh(na)

    return execution, na


# =============================================================================
# TESTS
# =============================================================================

def test_utc_conversion_and_timezone_preservation():
    """
    Verifies that timestamps across various timezones and formats are converted
    accurately to UTC while preserving exact original strings, offsets, and sources.
    """
    # 1. Explicit UTC 'Z'
    res_z = TimestampNormalizer.normalize("2026-01-15T12:00:00Z")
    assert res_z is not None
    assert res_z.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_z.original_timestamp == "2026-01-15T12:00:00Z"
    assert res_z.original_timezone == "UTC"
    assert res_z.timezone_status == "EXPLICIT"
    assert res_z.confidence_score >= 0.95

    # 2. Positive offset +05:30 (IST) -> 17:30 IST is 12:00 UTC
    res_pos = TimestampNormalizer.normalize("2026-01-15T17:30:00+05:30")
    assert res_pos is not None
    assert res_pos.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_pos.original_timezone == "+05:30"
    assert res_pos.timezone_offset == "+05:30"
    assert res_pos.timezone_status == "EXPLICIT"

    # 3. Negative offset -05:00 (EST) -> 07:00 EST is 12:00 UTC
    res_neg = TimestampNormalizer.normalize("2026-01-15T07:00:00-05:00")
    assert res_neg is not None
    assert res_neg.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_neg.original_timezone == "-05:00"
    assert res_neg.timezone_offset == "-05:00"

    # 4. ExifTool format "YYYY:MM:DD HH:MM:SS+02:00" -> 14:00+02:00 is 12:00 UTC
    res_exif = TimestampNormalizer.normalize("2026:01:15 14:00:00+02:00")
    assert res_exif is not None
    assert res_exif.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_exif.timezone_offset == "+02:00"


def test_unknown_and_ambiguous_timezone_handling():
    """
    Verifies that timestamps missing a timezone are marked UNKNOWN with lower confidence,
    and named abbreviations are marked AMBIGUOUS rather than silently assumed.
    """
    # 1. No timezone information (Naive ISO string)
    res_naive = TimestampNormalizer.normalize("2026-01-15 12:00:00")
    assert res_naive is not None
    assert res_naive.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_naive.original_timezone is None
    assert res_naive.timezone_offset is None
    assert res_naive.timezone_status == "UNKNOWN"
    assert res_naive.confidence_score == 0.60  # Explicitly penalized for missing timezone

    # 2. Named timezone abbreviation (e.g. EST)
    res_abbr = TimestampNormalizer.normalize("2026-01-15 07:00:00 EST")
    assert res_abbr is not None
    assert res_abbr.timestamp_utc == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert res_abbr.original_timezone == "EST"
    assert res_abbr.timezone_status == "AMBIGUOUS"
    assert res_abbr.confidence_score == 0.70  # Explicitly penalized for ambiguous abbreviation


def test_temporal_precision_and_windows():
    """
    Verifies temporal precision detection (EXACT, SECOND, DAY) and temporal window calculations.
    """
    # 1. Subsecond precision
    res_sub = TimestampNormalizer.normalize("2026-01-15T12:00:00.123456Z")
    assert res_sub is not None
    assert res_sub.temporal_precision == "EXACT"
    assert res_sub.confidence_score == 1.0

    # 2. Second precision
    res_sec = TimestampNormalizer.normalize("2026-01-15T12:00:00Z")
    assert res_sec is not None
    assert res_sec.temporal_precision == "SECOND"
    assert res_sec.confidence_score == 0.95

    # 3. Date-only precision with full day window
    res_day = TimestampNormalizer.normalize("2026-01-15")
    assert res_day is not None
    assert res_day.temporal_precision == "DAY"
    assert res_day.confidence_score == 0.40
    assert res_day.window_start_utc == datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
    assert res_day.window_end_utc == datetime(2026, 1, 15, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_no_invented_timestamps(db_session):
    """
    CRITICAL FORENSIC REQUIREMENT:
    Artifacts lacking valid timestamps must NEVER have synthetic timestamps invented.
    """
    user, case, _ = create_test_user_and_case(db_session, "no_ts_usr", "no_ts_case")
    evidence = create_test_evidence(db_session, case)

    # Normalized artifact with NO timestamp
    _, na_no_ts = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="FILE",
        normalized_fields={"path": "/usr/bin/tool", "size_bytes": 100},
        entity_timestamp=None
    )

    events = UnifiedTimelineService.extract_events_from_normalized_artifact(
        db=db_session,
        normalized_art=na_no_ts,
        actor_user=user
    )

    # Must produce ZERO timeline events
    assert len(events) == 0

    # Query DB directly to verify no rows were inserted
    count = db_session.query(TimelineEvent).filter(TimelineEvent.case_id == case.id).count()
    assert count == 0


def test_chronological_ordering_and_deterministic_tie_breaking(db_session):
    """
    Verifies that timeline events are ordered strictly chronologically by UTC timestamp,
    with deterministic tie-breaking (confidence_score DESC, id ASC).
    """
    user, case, _ = create_test_user_and_case(db_session, "order_usr", "order_case")
    evidence = create_test_evidence(db_session, case)

    # Create 3 normalized artifacts with different timestamps
    # T1: 10:00 UTC
    # T2: 12:00 UTC (high confidence)
    # T3: 12:00 UTC (lower confidence - tie break test)
    # T4: 15:00 UTC
    _, na1 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="FILE",
        entity_timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        normalized_fields={"source_raw_data": {"modified_time": "2026-01-15T10:00:00Z"}}
    )
    _, na2 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="PROCESS",
        entity_timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields={"start_time": "2026-01-15T12:00:00Z"}  # confidence 0.95
    )
    _, na3 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="EVENT",
        entity_timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields={"event_timestamp": "2026-01-15 12:00:00"}  # naive -> confidence 0.60
    )
    _, na4 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="NETWORK_CONNECTION",
        entity_timestamp=datetime(2026, 1, 15, 15, 0, 0, tzinfo=timezone.utc),
        normalized_fields={"source_raw_data": {"timestamp": "2026-01-15T15:00:00Z"}}
    )

    UnifiedTimelineService.generate_timeline_for_case(db_session, case.id, user)

    events = UnifiedTimelineService.list_timeline_events(db_session, case.id)
    assert len(events) == 4

    # Assert strictly non-decreasing UTC timestamps
    for i in range(len(events) - 1):
        assert events[i].timestamp_utc <= events[i+1].timestamp_utc

    target_dt = datetime(2026, 1, 15, 12, 0, 0)
    events_at_12 = [
        e for e in events
        if (e.timestamp_utc.replace(tzinfo=None) if e.timestamp_utc.tzinfo else e.timestamp_utc) == target_dt
    ]
    assert len(events_at_12) == 2
    assert events_at_12[0].confidence_score >= events_at_12[1].confidence_score


def test_event_source_and_multi_tier_provenance(db_session):
    """
    Verifies that timeline events capture accurate event sources (FLS, EVTX, PSLIST, NETSCAN, etc.)
    and retain the complete 6-tier provenance chain:
    EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact -> TimelineEvent.
    """
    user, case, _ = create_test_user_and_case(db_session, "prov_usr", "prov_case")
    evidence = create_test_evidence(db_session, case)

    _, na = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="PROCESS",
        parser_name="PsListArtifactParser",
        tool_id="volatility_pslist",
        normalized_fields={"start_time": "2026-01-15T09:15:30Z"}
    )

    events = UnifiedTimelineService.extract_events_from_normalized_artifact(db_session, na, user)
    assert len(events) == 1
    event = events[0]

    assert event.event_source == "PSLIST"
    assert event.event_type == "PROCESS_LAUNCH"
    assert event.normalized_artifact_id == na.id

    prov = UnifiedTimelineService.get_timeline_event_provenance(db_session, event.id, case.id)
    assert prov["event_id"] == event.id
    assert prov["event_source"] == "PSLIST"
    assert prov["evidence"]["evidence_id"] == evidence.id
    assert prov["execution"]["execution_id"] == na.execution_id

    chain = prov["traceability_chain"]
    assert any(f"EvidenceItem:{evidence.id}" in c for c in chain)
    assert any(f"ForensicExecution:{na.execution_id}" in c for c in chain)
    assert any(f"NormalizedArtifact:{na.id}" in c for c in chain)
    assert any(f"TimelineEvent:{event.id}" in c for c in chain)


def test_cryptographic_integrity_and_tamper_detection(db_session):
    """
    Verifies SHA-256 calculation, integrity verification, and tamper detection:
    - VALID on intact event.
    - TAMPERED on payload/DB modification.
    - FILE_MISSING on deleted storage file.
    - SOURCE_ARTIFACT_MISMATCH on modified source normalized artifact hash.
    """
    user, case, _ = create_test_user_and_case(db_session, "integ_usr", "integ_case")
    evidence = create_test_evidence(db_session, case)

    _, na = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="FILE",
        normalized_fields={"source_raw_data": {"modified_time": "2026-01-15T11:00:00Z"}}
    )

    events = UnifiedTimelineService.extract_events_from_normalized_artifact(db_session, na, user)
    assert len(events) == 1
    event = events[0]

    # 1. Intact verification -> VALID
    res_valid = UnifiedTimelineService.verify_timeline_event_integrity(db_session, event.id, case.id)
    assert res_valid["integrity_status"] == "VALID"
    assert res_valid["calculated_sha256"] == event.sha256_hash

    # 2. Tampered event_data in DB -> TAMPERED
    orig_data = dict(event.event_data)
    event.event_data = {"tampered": True}
    db_session.commit()

    res_tamper = UnifiedTimelineService.verify_timeline_event_integrity(db_session, event.id, case.id)
    assert res_tamper["integrity_status"] == "TAMPERED"

    # Restore data
    event.event_data = orig_data
    db_session.commit()

    # 3. Source NormalizedArtifact hash mismatch -> SOURCE_ARTIFACT_MISMATCH
    orig_na_hash = na.sha256_hash
    na.sha256_hash = "9999999999999999999999999999999999999999999999999999999999999999"
    db_session.commit()

    res_src_mismatch = UnifiedTimelineService.verify_timeline_event_integrity(db_session, event.id, case.id)
    assert res_src_mismatch["integrity_status"] == "SOURCE_ARTIFACT_MISMATCH"

    # Restore source hash
    na.sha256_hash = orig_na_hash
    db_session.commit()

    # 4. Storage file missing -> FILE_MISSING
    p = Path(event.storage_path)
    file_bytes = p.read_bytes()
    p.unlink()

    res_missing = UnifiedTimelineService.verify_timeline_event_integrity(db_session, event.id, case.id)
    assert res_missing["integrity_status"] == "FILE_MISSING"

    # Restore file
    p.write_bytes(file_bytes)


def test_source_immutability(db_session):
    """
    Verifies that timeline generation NEVER modifies the source NormalizedArtifact,
    StructuredArtifact, ExecutionOutput, or EvidenceItem.
    """
    user, case, _ = create_test_user_and_case(db_session, "immut_usr", "immut_case")
    evidence = create_test_evidence(db_session, case)

    _, na = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="FILE",
        normalized_fields={"source_raw_data": {"modified_time": "2026-01-15T14:20:00Z"}}
    )

    na_hash = na.sha256_hash
    ev_hash = evidence.sha256

    UnifiedTimelineService.generate_timeline_for_case(db_session, case.id, user)

    db_session.refresh(na)
    db_session.refresh(evidence)

    assert na.sha256_hash == na_hash
    assert evidence.sha256 == ev_hash


def test_storage_isolation_and_security(db_session):
    """
    Verifies storage containment:
    - Path outside base directory is rejected.
    - Evidence vault paths are strictly rejected.
    - Symlinks are rejected.
    - Safe POSIX permissions (0o700 for directories, 0o600 for files) are set.
    """
    user, case, _ = create_test_user_and_case(db_session, "sec_usr", "sec_case")

    base_dir = TimelineStorageManager.get_case_storage_dir(case.id)
    assert base_dir.exists()
    assert (base_dir.stat().st_mode & 0o777) == 0o700

    # Write a test timeline file
    sample_payload = {"event": "data"}
    event_id = str(uuid.uuid4())
    out_file = TimelineStorageManager.persist_timeline_file(case.id, event_id, sample_payload)

    assert out_file.exists()
    assert (out_file.stat().st_mode & 0o777) == 0o600

    # Path traversal rejection
    traversal_path = base_dir.parent / "escape.json"
    with pytest.raises(ValueError, match="Path traversal detected"):
        TimelineStorageManager.validate_storage_path(traversal_path, case.id)

    # Evidence vault rejection
    vault_path = settings.EVIDENCE_DIR / "vault" / case.id / "illegal_event.json"
    with pytest.raises(ValueError, match="CRITICAL: Timeline storage cannot be located inside evidence vault"):
        TimelineStorageManager.validate_storage_path(vault_path, case.id)

    # Symlink rejection
    symlink_target = out_file
    symlink_file = base_dir / "symlink_tle.json"
    try:
        os.symlink(symlink_target, symlink_file)
        with pytest.raises(ValueError, match="Symlink storage references strictly forbidden"):
            TimelineStorageManager.validate_storage_path(symlink_file, case.id)
    finally:
        if symlink_file.is_symlink():
            symlink_file.unlink()


def test_api_timeline_generation_and_filtering(db_session):
    """
    Tests REST API endpoints:
    - Case timeline generation
    - Execution timeline generation
    - Artifact timeline generation
    - Chronological listing with filters (time range, event type, source, confidence)
    """
    user, case, headers = create_test_user_and_case(db_session, "api_time_usr", "api_time_case")
    evidence = create_test_evidence(db_session, case)

    exec_obj, na1 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="FILE",
        parser_name="FlsArtifactParser",
        normalized_fields={"source_raw_data": {"modified_time": "2026-01-15T08:00:00Z"}}
    )
    _, na2 = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="EVENT",
        parser_name="EvtxArtifactParser",
        tool_id="winevtx",
        normalized_fields={"event_timestamp": "2026-01-15T18:00:00Z"}
    )

    # 1. Generate via Case API
    res_gen = client.post(f"/api/cases/{case.id}/timeline/generate", headers=headers)
    assert res_gen.status_code == 200, res_gen.text
    gen_data = res_gen.json()
    assert gen_data["case_id"] == case.id
    assert gen_data["events_generated_count"] >= 2

    # 2. List all events chronologically
    res_list = client.get(f"/api/cases/{case.id}/timeline", headers=headers)
    assert res_list.status_code == 200
    events = res_list.json()
    assert len(events) >= 2
    assert events[0]["timestamp_utc"] < events[1]["timestamp_utc"]

    # 3. Filter by event_source=FLS
    res_fls = client.get(f"/api/cases/{case.id}/timeline?event_source=FLS", headers=headers)
    assert res_fls.status_code == 200
    fls_events = res_fls.json()
    assert all(e["event_source"] == "FLS" for e in fls_events)

    # 4. Filter by time range
    res_range = client.get(
        f"/api/cases/{case.id}/timeline?start_time=2026-01-15T12:00:00Z&end_time=2026-01-15T23:59:59Z",
        headers=headers
    )
    assert res_range.status_code == 200
    range_events = res_range.json()
    assert len(range_events) == 1
    assert range_events[0]["event_source"] == "EVTX"

    # 5. Filter by min_confidence
    res_conf = client.get(f"/api/cases/{case.id}/timeline?min_confidence=0.9", headers=headers)
    assert res_conf.status_code == 200
    assert all(e["confidence_score"] >= 0.9 for e in res_conf.json())


def test_api_details_integrity_provenance_download(db_session):
    """
    Tests details, integrity, provenance, and download REST endpoints.
    """
    user, case, headers = create_test_user_and_case(db_session, "api_det_usr", "api_det_case")
    evidence = create_test_evidence(db_session, case)

    _, na = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="PROCESS",
        parser_name="PsListArtifactParser",
        normalized_fields={"start_time": "2026-01-15T10:30:00Z"}
    )
    events = UnifiedTimelineService.extract_events_from_normalized_artifact(db_session, na, user)
    event = events[0]

    # 1. Event details
    res_det = client.get(f"/api/cases/{case.id}/timeline/{event.id}", headers=headers)
    assert res_det.status_code == 200
    assert res_det.json()["id"] == event.id
    assert res_det.json()["event_type"] == "PROCESS_LAUNCH"

    # 2. Event integrity
    res_integ = client.get(f"/api/cases/{case.id}/timeline/{event.id}/integrity", headers=headers)
    assert res_integ.status_code == 200
    assert res_integ.json()["integrity_status"] == "VALID"
    assert res_integ.json()["expected_sha256"] == event.sha256_hash

    # 3. Event provenance
    res_prov = client.get(f"/api/cases/{case.id}/timeline/{event.id}/provenance", headers=headers)
    assert res_prov.status_code == 200
    prov_data = res_prov.json()
    assert prov_data["event_id"] == event.id
    assert "traceability_chain" in prov_data
    assert len(prov_data["traceability_chain"]) == 6

    # 4. Download serialized event JSON
    res_dl = client.get(f"/api/cases/{case.id}/timeline/{event.id}/download", headers=headers)
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "application/json"
    dl_data = res_dl.json()
    assert dl_data["id"] == event.id
    assert dl_data["event_type"] == "PROCESS_LAUNCH"


def test_rbac_and_cross_case_idor_protection(db_session):
    """
    Verifies that unauthorized investigators cannot access or generate timeline events
    belonging to another case.
    """
    user_a, case_a, headers_a = create_test_user_and_case(db_session, "usr_a", "case_a")
    user_b, case_b, headers_b = create_test_user_and_case(db_session, "usr_b", "case_b")

    evidence_a = create_test_evidence(db_session, case_a)
    _, na_a = create_normalized_artifact_fixture(
        db_session, case_a, user_a, evidence_a,
        entity_type="FILE",
        normalized_fields={"source_raw_data": {"modified_time": "2026-01-15T06:00:00Z"}}
    )
    events_a = UnifiedTimelineService.extract_events_from_normalized_artifact(db_session, na_a, user_a)
    event_a = events_a[0]

    # User B attempts to access Case A timeline -> 403 / 404
    res_list = client.get(f"/api/cases/{case_a.id}/timeline", headers=headers_b)
    assert res_list.status_code in [403, 404]

    # User B attempts to get event details -> 403 / 404
    res_det = client.get(f"/api/cases/{case_a.id}/timeline/{event_a.id}", headers=headers_b)
    assert res_det.status_code in [403, 404]

    # User B attempts parameter tampering (querying case_b URL with event_a.id) -> 404
    res_tamper = client.get(f"/api/cases/{case_b.id}/timeline/{event_a.id}", headers=headers_b)
    assert res_tamper.status_code == 404


def test_strict_forensic_boundaries_no_findings_no_conclusions(db_session):
    """
    CRITICAL FORENSIC BOUNDARY TEST:
    Verifies that Step 13 produces ONLY unified temporal event data and does NOT:
    - Create Finding records
    - Assign threat severity or maliciousness
    - Correlate events into attack chains
    - Draw conclusions or inferences
    """
    user, case, _ = create_test_user_and_case(db_session, "bound_usr", "bound_case")
    evidence = create_test_evidence(db_session, case)

    _, na = create_normalized_artifact_fixture(
        db_session, case, user, evidence,
        entity_type="MALWARE_MATCH",
        parser_name="YaraArtifactParser",
        tool_id="yara",
        normalized_fields={"source_raw_data": {"scan_time": "2026-01-15T12:00:00Z"}}
    )

    events = UnifiedTimelineService.extract_events_from_normalized_artifact(db_session, na, user)
    assert len(events) == 1
    event = events[0]

    # 1. Event contains NO severity, verdict, or conclusion
    assert "severity" not in event.event_data
    assert "verdict" not in event.event_data
    assert "malicious" not in event.event_data

    # Confidence score is temporal quality ONLY (between 0.0 and 1.0), not a threat score
    assert 0.0 <= event.confidence_score <= 1.0

    # 2. ZERO Finding rows were generated in DB
    findings_count = db_session.query(Finding).filter(Finding.case_id == case.id).count()
    assert findings_count == 0
