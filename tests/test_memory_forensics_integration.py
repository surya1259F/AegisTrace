import pytest
import tempfile
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from backend.app.main import app
from backend.app.core.database import Base, engine
from backend.app.api.endpoints.investigations import memory_agent
from forensic_tools.registry import ToolExecutionResult
from tests.test_memory_parsers import SAMPLE_PSLIST_OUTPUT

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_memory_forensics_vertical_slice_pipeline(monkeypatch):
    """
    Validates end-to-end memory forensics workflow:
    Investigation -> Memory Evidence -> Memory Analysis -> Artifacts -> Findings -> Verification -> Report.
    """
    # 1. Create Investigation
    inv_res = client.post("/api/investigations/", json={
        "name": "Memory Forensics Vertical Slice Case",
        "description": "Validates Volatility 3 pslist/netscan parser, provenance, and verification."
    })
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Ingest Memory Dump
    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        tf.write(b"SYNTHETIC_MEMORY_IMAGE_HEADER_BLOCK_0000000000000000")
        tf.flush()

        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tf.name,
            "notes": "Acquired physical RAM dump"
        })
        assert intake_res.status_code == 201
        ev_id = intake_res.json()["id"]

        # Mock the Volatility 3 execution adapter to return valid parsed memory output
        mock_exec = ToolExecutionResult(
            tool_name="volatility3",
            success=True,
            return_code=0,
            stdout=SAMPLE_PSLIST_OUTPUT,
            stderr="",
            execution_time_ms=850.0,
            evidence_path=tf.name,
            tool_version="2.28.0"
        )
        monkeypatch.setattr(memory_agent.adapter, "execute_plugin", MagicMock(return_value=mock_exec))

        # 3. Execute Memory Analysis (windows.pslist)
        analysis_res = client.post(f"/api/investigations/{inv_id}/analysis/memory", json={
            "evidence_id": ev_id,
            "plugin": "windows.pslist"
        })
        assert analysis_res.status_code == 200
        ana_data = analysis_res.json()
        assert ana_data["status"] == "SUCCESS"
        assert ana_data["artifacts_count"] == 5
        assert ana_data["findings_count"] == 1
        assert ana_data["raw_output_reference"] is not None

        # 4. Query Artifacts
        art_res = client.get(f"/api/investigations/{inv_id}/artifacts")
        assert art_res.status_code == 200
        artifacts = art_res.json()
        assert len(artifacts) == 5
        assert any(a["path"] == "mimikatz.exe" for a in artifacts)

        # 5. Query Findings
        find_res = client.get(f"/api/investigations/{inv_id}/findings")
        assert find_res.status_code == 200
        findings = find_res.json()
        assert len(findings) == 1
        assert "mimikatz.exe" in findings[0]["title"]
        assert findings[0]["evidence_reference"] == "pid:1420"

        # 6. Execute Correlation
        corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
        assert corr_res.status_code == 200

        # 7. Verify Findings
        ver_res = client.post(f"/api/investigations/{inv_id}/verify")
        assert ver_res.status_code == 200
        ver_list = ver_res.json()
        assert len(ver_list) >= 1
        assert all(v["verification_status"] == "SUPPORTED" for v in ver_list)

        # 8. Mandatory Investigator Decision Gate
        dec_res = client.post(
            f"/api/investigations/{inv_id}/decisions",
            json={
                "decision": "CONFIRM",
                "rationale": "Memory artifact injection verified and confirmed.",
                "investigator_name": "Lead DFIR Investigator"
            }
        )
        assert dec_res.status_code == 201

        # 8. Generate Investigation Report
        rep_res = client.post(f"/api/investigations/{inv_id}/report")
        assert rep_res.status_code == 200
        report = rep_res.json()
        assert "ADFIR DIGITAL FORENSIC INVESTIGATION REPORT" in report["full_report_markdown"]
        assert "mimikatz.exe" in report["full_report_markdown"]
