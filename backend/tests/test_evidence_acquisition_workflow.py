import os
import json
import shutil
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, ensure_evidence_acquisition_schema
from backend.app.models.models import User, Case, CaseMember, EvidenceItem, EvidenceAcquisition, ChainOfCustodyEvent
from backend.app.core.security import create_access_token
from backend.app.services.acquisition import (
    ingest_single_file_evidence,
    ingest_directory_evidence,
    validate_acquisition_source,
    AcquisitionError,
    DuplicateEvidenceError,
)
from backend.app.services.custody import verify_custody_chain

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    from backend.app.core.config import settings
    settings.JWT_SECRET_KEY = "adfir-test-jwt-secret-key-production-hardening-32bytes"
    app.dependency_overrides.clear()
    Base.metadata.create_all(bind=engine)
    ensure_evidence_acquisition_schema(engine)
    yield
    app.dependency_overrides.clear()

@pytest.fixture
def test_context():
    import uuid
    db = SessionLocal()
    email = f"intake_test_{uuid.uuid4().hex[:6]}@adfir.local"
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        name="Intake Test User",
        organization="DFIR Unit",
        role="INVESTIGATOR",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    c = Case(
        id=str(uuid.uuid4()),
        case_number=f"INTAKE-CASE-{uuid.uuid4().hex[:8]}",
        name="Evidence Intake Acceptance Case",
        objective="Validate evidence intake subsystem",
        owner_id=user.id,
        created_by=user.id,
        workspace_state="READY"
    )
    db.add(c)
    db.commit()

    m = CaseMember(
        case_id=c.id,
        user_id=user.id,
        role="PRIMARY_INVESTIGATOR"
    )
    db.add(m)
    db.commit()

    yield user, headers, c
    db.close()

def test_single_file_ingestion_and_vault(test_context):
    user, _, test_case = test_context
    db = SessionLocal()

    # Create temporary evidence file
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(b"ElfFile\x00" + b"\x00" * 512) # EVTX magic header
        tmp_path = tmp.name

    try:
        item = ingest_single_file_evidence(
            db=db,
            case_id=test_case.id,
            source_path=tmp_path,
            actor_id=user.id,
            actor_name=user.name,
            acquisition_type="EVTX",
            notes="Acceptance test EVTX ingest"
        )

        assert item is not None
        assert item.id is not None
        assert item.case_id == test_case.id
        assert item.status == "ANALYSIS_READY"
        assert item.intake_status == "INTAKE_COMPLETE"
        assert item.integrity_status == "VERIFIED"
        assert item.source_kind == "EVENT_LOG"
        assert item.evidence_type == "WINDOWS_EVENT_LOG"
        assert item.read_only_verified is True
        assert Path(item.storage_path).exists()
        assert item.sha256 is not None
        assert len(item.sha256) == 64

        # Verify custody chain for this evidence item
        is_valid, tampered_id, msg, count = verify_custody_chain(db, item.id)
        assert is_valid is True
        assert count >= 5
    finally:
        db.close()
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def test_directory_ingestion_and_manifest(test_context):
    user, _, test_case = test_context
    db = SessionLocal()

    tmp_dir = tempfile.mkdtemp(prefix="adfir_intake_dir_")
    try:
        sub_dir = Path(tmp_dir) / "subfolder"
        sub_dir.mkdir(parents=True, exist_ok=True)

        f1 = Path(tmp_dir) / "sample1.txt"
        f1.write_text("Evidence file 1 content")

        f2 = sub_dir / "sample2.bin"
        f2.write_bytes(b"\x00\x01\x02\x03\x04\x05")

        acq, manifest = ingest_directory_evidence(
            db=db,
            case_id=test_case.id,
            source_path=tmp_dir,
            actor_id=user.id,
            actor_name=user.name,
            notes="Acceptance test directory acquisition"
        )

        assert acq is not None
        assert acq.status == "COMPLETED"
        assert acq.total_files == 2
        assert acq.successful_files == 2
        assert acq.failed_files == 0
        assert acq.manifest_hash is not None
        assert manifest["total_files"] == 2
        assert len(manifest["files"]) == 2

        # Verify items linked to parent acquisition
        items = db.query(EvidenceItem).filter(EvidenceItem.parent_acquisition_id == acq.id).all()
        assert len(items) == 2
        for it in items:
            assert it.status == "ANALYSIS_READY"
            assert it.read_only_verified is True

    finally:
        db.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)

def test_duplicate_evidence_rejection(test_context):
    user, _, test_case = test_context
    db = SessionLocal()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"IDENTICAL_EVIDENCE_PAYLOAD_1234567890")
        tmp_path = tmp.name

    try:
        item1 = ingest_single_file_evidence(
            db=db,
            case_id=test_case.id,
            source_path=tmp_path,
            actor_id=user.id,
            actor_name=user.name
        )
        assert item1 is not None

        # Attempt duplicate ingestion in same case
        with pytest.raises(DuplicateEvidenceError):
            ingest_single_file_evidence(
                db=db,
                case_id=test_case.id,
                source_path=tmp_path,
                actor_id=user.id,
                actor_name=user.name
            )

    finally:
        db.close()
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def test_preflight_validation():
    # Non-existent path
    is_valid, err_msg, _ = validate_acquisition_source("/non/existent/path/evidence.raw")
    assert is_valid is False
    assert "does not exist" in err_msg

    # Null byte path
    is_valid, err_msg, _ = validate_acquisition_source("/some/path\x00/file.txt")
    assert is_valid is False
    assert "null bytes" in err_msg

def test_custody_chain_tamper_detection(test_context):
    user, _, test_case = test_context
    db = SessionLocal()

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"Custody tamper test file")
        tmp_path = tmp.name

    try:
        item = ingest_single_file_evidence(
            db=db,
            case_id=test_case.id,
            source_path=tmp_path,
            actor_id=user.id,
            actor_name=user.name
        )

        # Baseline check passes
        is_valid, _, _, _ = verify_custody_chain(db, item.id)
        assert is_valid is True

        # Tamper with an event in database
        event = db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.evidence_id == item.id).first()
        event.event_hash = "TAMPERED_HASH_1234567890abcdef"
        db.commit()

        # Check tamper detection
        is_valid, tampered_id, msg, count = verify_custody_chain(db, item.id)
        assert is_valid is False
        assert tampered_id == event.id
        assert "tampered" in msg or "broken" in msg

    finally:
        db.close()
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def test_api_acquisition_endpoints(test_context):
    user, headers, test_case = test_context
    print(f"DEBUG: user.id={user.id}, user.email={user.email}, case.id={test_case.id}, case.owner_id={test_case.owner_id}, case.created_by={test_case.created_by}")

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"API Evidence acquisition content test")
        tmp_path = tmp.name

    try:
        # Check GET case first
        case_resp = client.get(f"/api/v1/cases/{test_case.id}", headers=headers)
        print("DEBUG GET CASE RESP:", case_resp.status_code, case_resp.json() if case_resp.status_code != 200 else "OK")

        # POST acquisition via REST API
        resp = client.post(
            f"/api/v1/evidence/cases/{test_case.id}/acquisitions",
            json={
                "source_path": tmp_path,
                "acquisition_type": "SINGLE_FILE",
                "notes": "API test single file"
            },
            headers=headers
        )
        if resp.status_code != 200:
            print("DEBUG POST ACQUISITION RESP:", resp.status_code, resp.json())
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] is not None
        assert data["status"] == "ANALYSIS_READY"
        evidence_id = data["id"]

        # GET custody chain verification
        v_resp = client.get(
            f"/api/v1/evidence/{evidence_id}/custody/verify",
            headers=headers
        )
        assert v_resp.status_code == 200
        v_data = v_resp.json()
        assert v_data["chain_valid"] is True
        assert v_data["total_events"] >= 5

    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
