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

def test_log_forensics_vertical_slice_pipeline():
    """
    LOG FORENSICS VERTICAL SLICE INTEGRATION TEST:
    Executes full pipeline: Investigation -> Intake -> LogAgent Analysis ->
    Structured Artifacts -> Candidate Findings -> Correlation -> Verification -> Court-Ready Report.
    """
    # 1. Create Investigation
    inv_res = client.post("/api/investigations/", json={
        "name": "Windows Event Log Forensics Case",
        "description": "Validation of Security Event Log artifact extraction and verification."
    })
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Intake Log Evidence
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(SAMPLE_XML_FIXTURE),
        "notes": "Exported Security Event Log"
    })
    assert intake_res.status_code == 201
    ev_id = intake_res.json()["id"]

    # 3. Execute Log Analysis
    analysis_res = client.post(f"/api/investigations/{inv_id}/analysis/log", json={
        "evidence_id": ev_id,
        "max_records": 5000
    })
    assert analysis_res.status_code == 200
    data = analysis_res.json()
    assert data["status"] == "SUCCESS"
    assert data["artifacts_count"] == 5
    assert data["findings_count"] >= 4

    # 4. Verify Artifacts in Database
    art_res = client.get(f"/api/investigations/{inv_id}/artifacts")
    assert art_res.status_code == 200
    artifacts = art_res.json()
    assert len(artifacts) == 5

    # 5. Verify Findings in Database
    find_res = client.get(f"/api/investigations/{inv_id}/findings")
    assert find_res.status_code == 200
    findings = find_res.json()
    assert len(findings) >= 4

    # 6. Execute Correlation
    corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
    assert corr_res.status_code == 200

    # 7. Execute Verification
    ver_res = client.post(f"/api/investigations/{inv_id}/verify")
    assert ver_res.status_code == 200
    ver_list = ver_res.json()
    assert len(ver_list) >= 4
    assert all(v["verification_status"] == "SUPPORTED" for v in ver_list)

    # 8. Mandatory Investigator Decision Gate
    dec_res = client.post(
        f"/api/investigations/{inv_id}/decisions",
        json={
            "decision": "CONFIRM",
            "rationale": "Log forensics authentication anomaly findings confirmed.",
            "investigator_name": "Lead DFIR Investigator"
        }
    )
    assert dec_res.status_code == 201

    # 9. Generate Report
    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 200
    report_data = rep_res.json()
    assert "ADFIR DIGITAL FORENSIC INVESTIGATION REPORT" in report_data["full_report_markdown"]
    assert "Event 4625" in report_data["full_report_markdown"] or "Logon" in report_data["full_report_markdown"]
