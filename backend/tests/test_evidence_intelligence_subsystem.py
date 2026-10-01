import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.models.models import User, Case, EvidenceItem, EvidenceIntelligence, ChainOfCustodyEvent
from backend.app.services.intelligence import EvidenceIntelligenceEngine
from backend.app.services.integrity import calculate_sha256

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def test_users(db_session: Session):
    user1 = User(
        id="user-intel-1",
        email="analyst1@dfir.org",
        name="Analyst One",
        organization="Unit A",
        role="INVESTIGATOR",
        password_hash=hash_password("Password123!")
    )
    user2 = User(
        id="user-intel-2",
        email="analyst2@other.org",
        name="Analyst Two",
        organization="Unit B",
        role="INVESTIGATOR",
        password_hash=hash_password("Password123!")
    )
    db_session.add(user1)
    db_session.add(user2)
    db_session.commit()
    return user1, user2

@pytest.fixture(scope="function")
def auth_headers(test_users):
    user1, _ = test_users
    token = create_access_token(user1.id, user1.email, user1.role)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def test_case(db_session: Session, test_users):
    user1, _ = test_users
    c = Case(
        id="case-intel-100",
        case_number="CASE-INTEL-100",
        name="Evidence Intelligence Test Case",
        created_by=user1.email,
        owner_id=user1.id,
        status="OPEN"
    )
    db_session.add(c)
    db_session.commit()
    return c


# =====================================================================
# 1. Deterministic Header & Signature Engine Tests
# =====================================================================

def test_inspect_magic_header_pe32(tmp_path: Path):
    pe_file = tmp_path / "sample.exe"
    header = bytearray(512)
    header[0:2] = b"MZ"
    header[0x3c:0x40] = (0x80).to_bytes(4, "little") # PE offset at 0x80
    header[0x80:0x84] = b"PE\x00\x00"
    header[0x84:0x86] = (0x8664).to_bytes(2, "little") # x86_64 machine code
    pe_file.write_bytes(header)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(pe_file)
    (
        status, conf, basis, mime, platform, p_basis, p_conf, arch, fs, fs_ver, fs_basis, fs_status,
        part_type, partitions, characteristics, metadata, tags
    ) = EvidenceIntelligenceEngine.inspect_full_profile(pe_file, classification, subtype, fmt, conf_num)

    assert classification == "PE_EXECUTABLE"
    assert fmt == "PE64_EXECUTABLE"
    assert platform == "WINDOWS"
    assert arch == "x86_64"
    assert status == "MATCH"
    assert "EXECUTABLE_BINARY" in characteristics


def test_inspect_magic_header_elf64(tmp_path: Path):
    elf_file = tmp_path / "sample.elf"
    header = bytearray(256)
    header[0:4] = b"\x7fELF"
    header[4] = 2 # 64-bit
    header[5] = 1 # Little endian
    header[18:20] = (0x3E).to_bytes(2, "little") # x86_64
    elf_file.write_bytes(header)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(elf_file)
    (
        status, conf, basis, mime, platform, p_basis, p_conf, arch, fs, fs_ver, fs_basis, fs_status,
        part_type, partitions, characteristics, metadata, tags
    ) = EvidenceIntelligenceEngine.inspect_full_profile(elf_file, classification, subtype, fmt, conf_num)

    assert classification == "ELF_EXECUTABLE"
    assert fmt == "ELF64_EXECUTABLE"
    assert platform == "LINUX"
    assert arch == "x86_64"
    assert status == "MATCH"


def test_inspect_magic_header_evtx(tmp_path: Path):
    evtx_file = tmp_path / "Security.evtx"
    header = b"ElfFile\x00" + b"\x00" * 500
    evtx_file.write_bytes(header)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(evtx_file)
    (status, conf, basis, mime, platform, *_rest) = EvidenceIntelligenceEngine.inspect_full_profile(evtx_file, classification, subtype, fmt, conf_num)

    assert classification == "WINDOWS_EVENT_LOG"
    assert subtype == "evtx"
    assert fmt == "WINDOWS_EVENT_LOG_V2"
    assert platform == "WINDOWS"
    assert status == "MATCH"


def test_inspect_magic_header_sqlite_browser(tmp_path: Path):
    sqlite_file = tmp_path / "places.sqlite"
    header = b"SQLite format 3\x00" + b"\x00" * 500
    sqlite_file.write_bytes(header)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(sqlite_file)

    assert classification == "BROWSER_ARTIFACT"
    assert subtype == "browser_db"
    assert fmt == "SQLITE_V3_BROWSER_DB"


# =====================================================================
# 2. Extension Mismatch Engine Tests
# =====================================================================

def test_extension_mismatch_detection(tmp_path: Path):
    mismatch_file = tmp_path / "Security.evtx"
    mismatch_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 500)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(mismatch_file)
    (
        status, conf, basis, mime, platform, p_basis, p_conf, arch, fs, fs_ver, fs_basis, fs_status,
        part_type, partitions, characteristics, metadata, tags
    ) = EvidenceIntelligenceEngine.inspect_full_profile(mismatch_file, classification, subtype, fmt, conf_num)

    assert classification == "SQLITE_DATABASE"
    assert status == "MISMATCH"
    assert "EXTENSION MISMATCH ALERT" in basis
    assert "EXTENSION_MISMATCH_ALERT" in characteristics

    tag_names = [t.tag for t in tags]
    assert "extension_mismatch" in tag_names


# =====================================================================
# 3. Filesystem & Partition Table Detection Tests
# =====================================================================

def test_filesystem_ntfs_and_mbr_detection(tmp_path: Path):
    disk_file = tmp_path / "disk.img"
    header = bytearray(4096)
    header[3:11] = b"NTFS    "
    header[510:512] = b"\x55\xaa"
    header[446 + 4] = 0x07
    header[446 + 8: 446 + 12] = (2048).to_bytes(4, "little")
    header[446 + 12: 446 + 16] = (204800).to_bytes(4, "little")
    disk_file.write_bytes(header)

    source_kind, classification, subtype, fmt, conf_num, signals = EvidenceIntelligenceEngine.inspect_magic_header(disk_file)
    (
        status, conf, basis, mime, platform, p_basis, p_conf, arch, fs, fs_ver, fs_basis, fs_status,
        part_type, partitions, characteristics, metadata, tags
    ) = EvidenceIntelligenceEngine.inspect_full_profile(disk_file, classification, subtype, fmt, conf_num)

    assert fs == "NTFS"
    assert fs_status == "DETECTED"
    assert part_type == "MBR"
    assert len(partitions) == 1
    assert partitions[0].filesystem == "NTFS/exFAT"
    assert partitions[0].start_sector == 2048


# =====================================================================
# 4. Pre-Intelligence Integrity Gate & Profile Persistence Tests
# =====================================================================

def test_analyze_and_store_profile_success(db_session: Session, test_case: Case, test_users, tmp_path: Path):
    user1, _ = test_users
    # Create sample evidence file
    sample_path = tmp_path / "sample_log.evtx"
    sample_path.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
    sha256, _ = calculate_sha256(str(sample_path))

    ev = EvidenceItem(
        id="ev-intel-001",
        case_id=test_case.id,
        name="sample_log.evtx",
        original_path=str(sample_path),
        storage_path=str(sample_path),
        evidence_type="WINDOWS_EVENT_LOG",
        size_bytes=len(sample_path.read_bytes()),
        sha256=sha256,
        status="REGISTERED",
        integrity_status="VERIFIED"
    )
    db_session.add(ev)
    db_session.commit()

    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db_session, ev, user1)

    assert profile is not None
    assert profile.evidence_id == ev.id
    assert profile.classification == "WINDOWS_EVENT_LOG"
    assert profile.detected_format == "WINDOWS_EVENT_LOG_V2"
    assert profile.platform_hint == "WINDOWS"
    assert profile.analysis_version == 1
    assert profile.evidence_sha256_verified == sha256

    # Verify custody event recorded
    custody_events = db_session.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.evidence_id == ev.id).all()
    assert any(e.event_type == "EVIDENCE_INTELLIGENCE_GENERATED" for e in custody_events)


def test_integrity_gate_blocks_tampered_evidence(db_session: Session, test_case: Case, test_users, tmp_path: Path):
    user1, _ = test_users
    sample_path = tmp_path / "tampered.evtx"
    sample_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)
    original_sha256, _ = calculate_sha256(str(sample_path))

    ev = EvidenceItem(
        id="ev-intel-tampered",
        case_id=test_case.id,
        name="tampered.evtx",
        original_path=str(sample_path),
        storage_path=str(sample_path),
        evidence_type="WINDOWS_EVENT_LOG",
        size_bytes=508,
        sha256=original_sha256,
        status="REGISTERED",
        integrity_status="VERIFIED"
    )
    db_session.add(ev)
    db_session.commit()

    # Tamper with file content
    sample_path.write_bytes(b"TAMPERED CONTENT " + b"\x00" * 500)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        EvidenceIntelligenceEngine.analyze_and_store_profile(db_session, ev, user1)

    assert exc_info.value.status_code == 422
    assert "hash mismatch" in str(exc_info.value.detail).lower()

    db_session.refresh(ev)
    assert ev.integrity_status == "INTEGRITY_MISMATCH"

    # Verify custody block event recorded
    custody = db_session.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.evidence_id == ev.id).all()
    assert any(c.event_type == "EVIDENCE_INTELLIGENCE_INTEGRITY_BLOCKED" for c in custody)


def test_idempotency_and_versioning(db_session: Session, test_case: Case, test_users, tmp_path: Path):
    user1, _ = test_users
    sample_path = tmp_path / "version_test.bin"
    sample_path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 500)
    sha256, _ = calculate_sha256(str(sample_path))

    ev = EvidenceItem(
        id="ev-intel-ver",
        case_id=test_case.id,
        name="version_test.bin",
        original_path=str(sample_path),
        storage_path=str(sample_path),
        evidence_type="SQLITE_DATABASE",
        size_bytes=516,
        sha256=sha256
    )
    db_session.add(ev)
    db_session.commit()

    # Initial analysis -> version 1
    prof1 = EvidenceIntelligenceEngine.analyze_and_store_profile(db_session, ev, user1, force_refresh=False)
    assert prof1.analysis_version == 1

    # Second fetch without force -> returns existing version 1
    prof2 = EvidenceIntelligenceEngine.analyze_and_store_profile(db_session, ev, user1, force_refresh=False)
    assert prof2.analysis_version == 1

    # Force refresh -> increments version to 2
    prof3 = EvidenceIntelligenceEngine.analyze_and_store_profile(db_session, ev, user1, force_refresh=True)
    assert prof3.analysis_version == 2


# =====================================================================
# 5. REST API Integration Tests
# =====================================================================

def test_api_get_and_refresh_intelligence(db_session: Session, tmp_path: Path):
    import uuid
    client = TestClient(app)

    email = f"analyst_api_{uuid.uuid4().hex[:6]}@dfir.org"
    signup_res = client.post("/api/v1/auth/signup", json={"email": email, "name": "API Analyst", "password": "Password123!"})
    assert signup_res.status_code == 201
    login_res = client.post("/api/v1/auth/login", json={"email": email, "password": "Password123!"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    case_res = client.post("/api/v1/cases/", json={"name": "API Test Case", "case_number": f"CASE-API-{uuid.uuid4().hex[:6]}"}, headers=headers)
    assert case_res.status_code in (200, 201)
    case_data = case_res.json()
    case_id = case_data["id"]

    sample_path = tmp_path / "api_sample.evtx"
    sample_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)
    sha256, _ = calculate_sha256(str(sample_path))

    ev = EvidenceItem(
        id=f"ev-api-{uuid.uuid4().hex[:6]}",
        case_id=case_id,
        name="api_sample.evtx",
        original_path=str(sample_path),
        storage_path=str(sample_path),
        evidence_type="WINDOWS_EVENT_LOG",
        size_bytes=508,
        sha256=sha256
    )
    db_session.add(ev)
    db_session.commit()

    # GET Intelligence
    resp = client.get(f"/api/v1/evidence/{ev.id}/intelligence", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["evidence_id"] == ev.id
    assert data["intelligence"]["classification"] == "WINDOWS_EVENT_LOG"

    # GET Profile
    prof_resp = client.get(f"/api/v1/evidence/{ev.id}/intelligence/profile", headers=headers)
    assert prof_resp.status_code == 200
    prof_data = prof_resp.json()
    assert prof_data["detected_format"] == "WINDOWS_EVENT_LOG_V2"
    assert prof_data["analysis_version"] == 1

    # GET Tags
    tags_resp = client.get(f"/api/v1/evidence/{ev.id}/intelligence/tags", headers=headers)
    assert tags_resp.status_code == 200
    tags_data = tags_resp.json()
    assert len(tags_data) > 0

    # POST Refresh
    ref_resp = client.post(f"/api/v1/evidence/{ev.id}/intelligence/refresh", headers=headers)
    assert ref_resp.status_code == 200
