import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine
import os
import uuid

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["application"] == "ADFIR"
    assert data["version"] == "0.1.0"

def test_system_status_endpoint():
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    assert data["application"] == "ADFIR"
    assert "forensic_tools" in data
    assert "logical_cpus" in data

def test_complete_evidence_investigation_pipeline():
    # 1. Create Investigation
    inv_name = f"Incident Response {uuid.uuid4().hex[:6]}"
    create_res = client.post("/api/investigations/", json={
        "name": inv_name,
        "description": "Suspected intrusion on finance workstation."
    })
    assert create_res.status_code == 201
    inv_data = create_res.json()
    inv_id = inv_data["id"]

    # 2. Intake Synthetic Evidence
    fixture_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-evidence.txt"))
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": fixture_path,
        "notes": "Acquired synthetic disk artifact"
    })
    assert intake_res.status_code == 201
    ev_data = intake_res.json()
    evidence_id = ev_data["id"]
    assert len(ev_data["sha256"]) == 64
    assert ev_data["integrity_status"] == "VERIFIED"

    # 3. Verify Chain of Custody Log
    custody_res = client.get(f"/api/investigations/{inv_id}/custody")
    assert custody_res.status_code == 200
    custody_events = custody_res.json()
    assert len(custody_events) >= 1
    assert custody_events[0]["event_type"] == "EVIDENCE_REGISTERED"

    # 4. Generate Autonomous Investigation Plan
    plan_res = client.post(f"/api/investigations/{inv_id}/plan")
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert len(plan_data["steps"]) >= 1

    # 5. Record Structured Findings
    f1_res = client.post(f"/api/investigations/{inv_id}/findings", json={
        "evidence_id": evidence_id,
        "agent": "DiskAgent",
        "tool": "SleuthKit",
        "finding_type": "filesystem_artifact",
        "title": "Suspicious Executable in Temp Directory",
        "description": "Found powershell.exe script drop at inode 14920 connecting to 198.51.100.45",
        "confidence": 0.95,
        "evidence_reference": "inode:14920"
    })
    assert f1_res.status_code == 201

    f2_res = client.post(f"/api/investigations/{inv_id}/findings", json={
        "evidence_id": evidence_id,
        "agent": "MalwareAgent",
        "tool": "YARA",
        "finding_type": "malware_signature",
        "title": "CobaltStrike Beacon Rule Match",
        "description": "Matched beacon payload pattern on file at inode 14920 with IP 198.51.100.45",
        "confidence": 0.98,
        "evidence_reference": "inode:14920"
    })
    assert f2_res.status_code == 201

    # 6. Execute Correlation
    corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
    assert corr_res.status_code == 200
    corr_data = corr_res.json()
    assert len(corr_data) >= 1

    # 7. Execute Verification
    ver_res = client.post(f"/api/investigations/{inv_id}/verify")
    assert ver_res.status_code == 200
    ver_data = ver_res.json()
    assert len(ver_data) == 2
    assert all(v["verification_status"] == "SUPPORTED" for v in ver_data)

    # 8. Mandatory Investigator Decision Gate
    dec_res = client.post(
        f"/api/investigations/{inv_id}/decisions",
        json={
            "decision": "CONFIRM",
            "rationale": "Forensic findings verified and confirmed for official report synthesis.",
            "investigator_name": "Lead DFIR Investigator"
        }
    )
    assert dec_res.status_code == 201

    # 9. Generate 19-Section Court-Ready Investigation Report
    report_res = client.post(f"/api/investigations/{inv_id}/report")
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert "ADFIR DIGITAL FORENSIC INVESTIGATION REPORT" in report_data["full_report_markdown"]
    assert "1. Executive Summary" in report_data["full_report_markdown"]
    assert "19. Appendix" in report_data["full_report_markdown"]
    assert "[FACT]" in report_data["full_report_markdown"]
    assert report_data["findings_count"] == 2
    assert report_data["evidence_count"] == 1
