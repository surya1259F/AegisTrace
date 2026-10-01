import pytest
import tempfile
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_cross_investigation_memory_access_rejected():
    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        # Case A
        inv_a = client.post("/api/investigations/", json={"name": "Memory Case A"}).json()["id"]
        ev_a = client.post(f"/api/investigations/{inv_a}/evidence/intake", json={"path": tf.name}).json()["id"]

        # Case B
        inv_b = client.post("/api/investigations/", json={"name": "Memory Case B"}).json()["id"]

        # Attempt to analyze Case A evidence from Case B
        bad_res = client.post(f"/api/investigations/{inv_b}/analysis/memory", json={
            "evidence_id": ev_a,
            "plugin": "windows.pslist"
        })
        assert bad_res.status_code == 404
        assert "not found" in bad_res.json()["detail"].lower()

def test_disallowed_volatility_plugin_rejected_via_api():
    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        inv = client.post("/api/investigations/", json={"name": "Plugin Test Case"}).json()["id"]
        ev = client.post(f"/api/investigations/{inv}/evidence/intake", json={"path": tf.name}).json()["id"]

        res = client.post(f"/api/investigations/{inv}/analysis/memory", json={
            "evidence_id": ev,
            "plugin": "arbitrary_custom_plugin_eval"
        })
        # Should be handled gracefully with PLUGIN_UNAVAILABLE status or rejected
        assert res.status_code == 200
        assert res.json()["status"] == "PLUGIN_UNAVAILABLE"

def test_null_byte_in_plugin_rejected():
    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        inv = client.post("/api/investigations/", json={"name": "Null Byte Test Case"}).json()["id"]
        ev = client.post(f"/api/investigations/{inv}/evidence/intake", json={"path": tf.name}).json()["id"]

        # Regex validator rejects null byte pattern in plugin name
        res = client.post(f"/api/investigations/{inv}/analysis/memory", json={
            "evidence_id": ev,
            "plugin": "windows.pslist\0bad"
        })
        assert res.status_code == 422
