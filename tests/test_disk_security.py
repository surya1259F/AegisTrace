import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from backend.app.main import app
from backend.app.core.database import Base, engine
from tests.fixtures.disk.create_synthetic_disk import create_synthetic_disk_image

client = TestClient(app)
FIXTURE_DISK = Path(__file__).resolve().parent / "fixtures" / "disk" / "synthetic_disk.img"

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    create_synthetic_disk_image(FIXTURE_DISK)
    yield

def test_cross_investigation_evidence_access_rejected():
    # Case A
    inv_a = client.post("/api/investigations/", json={"name": "Case A"}).json()["id"]
    ev_a = client.post(f"/api/investigations/{inv_a}/evidence/intake", json={"path": str(FIXTURE_DISK)}).json()["id"]

    # Case B
    inv_b = client.post("/api/investigations/", json={"name": "Case B"}).json()["id"]

    # Attempt to analyze Case A's evidence under Case B's endpoint
    bad_res = client.post(f"/api/investigations/{inv_b}/analysis/disk", json={
        "evidence_id": ev_a,
        "recursive": True
    })
    assert bad_res.status_code == 404
    assert "not found" in bad_res.json()["detail"].lower()

def test_nonexistent_investigation_rejected():
    bad_res = client.post("/api/investigations/fake-inv-uuid/analysis/disk", json={
        "evidence_id": "fake-ev-uuid"
    })
    assert bad_res.status_code == 404

def test_nonexistent_evidence_rejected():
    inv_id = client.post("/api/investigations/", json={"name": "Valid Case"}).json()["id"]
    bad_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={
        "evidence_id": "fake-ev-uuid"
    })
    assert bad_res.status_code == 404

def test_evidence_source_file_immutability():
    initial_stat = FIXTURE_DISK.stat()
    
    inv_id = client.post("/api/investigations/", json={"name": "Immutability Test Case"}).json()["id"]
    ev_id = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={"path": str(FIXTURE_DISK)}).json()["id"]
    
    # Run analysis
    analysis_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={"evidence_id": ev_id})
    assert analysis_res.status_code == 200

    post_stat = FIXTURE_DISK.stat()
    assert initial_stat.st_mtime == post_stat.st_mtime
    assert initial_stat.st_size == post_stat.st_size
