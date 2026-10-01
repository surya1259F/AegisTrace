import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine

client = TestClient(app)
SAMPLE_XML_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "log" / "sample_security_events.xml"

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_cross_investigation_log_access_rejected():
    # Case A
    inv_a = client.post("/api/investigations/", json={"name": "Log Case A"}).json()["id"]
    ev_a = client.post(f"/api/investigations/{inv_a}/evidence/intake", json={"path": str(SAMPLE_XML_FIXTURE)}).json()["id"]

    # Case B
    inv_b = client.post("/api/investigations/", json={"name": "Log Case B"}).json()["id"]

    # Attempt to analyze Case A evidence from Case B endpoint
    bad_res = client.post(f"/api/investigations/{inv_b}/analysis/log", json={
        "evidence_id": ev_a
    })
    assert bad_res.status_code == 404
    assert "not found" in bad_res.json()["detail"].lower()

def test_nonexistent_investigation_rejected():
    res = client.post("/api/investigations/nonexistent-inv-id/analysis/log", json={
        "evidence_id": "dummy-ev-id"
    })
    assert res.status_code == 404

def test_evidence_source_file_immutability():
    original_mtime = SAMPLE_XML_FIXTURE.stat().st_mtime
    original_size = SAMPLE_XML_FIXTURE.stat().st_size

    inv = client.post("/api/investigations/", json={"name": "Immutability Case"}).json()["id"]
    ev = client.post(f"/api/investigations/{inv}/evidence/intake", json={"path": str(SAMPLE_XML_FIXTURE)}).json()["id"]

    res = client.post(f"/api/investigations/{inv}/analysis/log", json={"evidence_id": ev})
    assert res.status_code == 200

    new_mtime = SAMPLE_XML_FIXTURE.stat().st_mtime
    new_size = SAMPLE_XML_FIXTURE.stat().st_size

    assert original_mtime == new_mtime
    assert original_size == new_size
