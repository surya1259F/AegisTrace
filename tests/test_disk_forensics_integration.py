import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import Investigation, Evidence, Artifact, Finding
from tests.fixtures.disk.create_synthetic_disk import create_synthetic_disk_image

client = TestClient(app)
FIXTURE_DISK = Path(__file__).resolve().parent / "fixtures" / "disk" / "synthetic_disk.img"

@pytest.fixture(autouse=True)
def setup_db_and_fixture():
    Base.metadata.create_all(bind=engine)
    create_synthetic_disk_image(FIXTURE_DISK)
    yield

def test_end_to_end_disk_forensics_pipeline():
    # 1. Create Investigation
    create_res = client.post("/api/investigations/", json={
        "name": "Disk Forensics Production Verification",
        "description": "Validates real SleuthKit execution, artifact extraction, and verification."
    })
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    # 2. Ingest Synthetic Disk Image
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": str(FIXTURE_DISK),
        "notes": "Synthetic 1MB FAT test disk"
    })
    assert intake_res.status_code == 201
    evidence_id = intake_res.json()["id"]

    # 3. Execute Disk Analysis via SleuthKit
    analysis_res = client.post(f"/api/investigations/{inv_id}/analysis/disk", json={
        "evidence_id": evidence_id,
        "recursive": True,
        "include_deleted": True
    })
    assert analysis_res.status_code == 200
    ana_data = analysis_res.json()
    assert ana_data["status"] == "SUCCESS"
    assert ana_data["artifacts_count"] >= 3
    assert ana_data["findings_count"] >= 1
    assert ana_data["raw_output_reference"] is not None

    # 4. Verify Artifacts in Database
    artifacts_res = client.get(f"/api/investigations/{inv_id}/artifacts")
    assert artifacts_res.status_code == 200
    artifacts = artifacts_res.json()
    assert len(artifacts) >= 3
    artifact_paths = [a["path"] for a in artifacts]
    assert "NORMAL.TXT" in artifact_paths

    # 5. Verify Findings in Database
    findings_res = client.get(f"/api/investigations/{inv_id}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) >= 1
    assert any("Deleted Filesystem Entry" in f["title"] for f in findings)

    # 6. Execute Correlation
    corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
    assert corr_res.status_code == 200

    # 7. Execute Verification
    ver_res = client.post(f"/api/investigations/{inv_id}/verify")
    assert ver_res.status_code == 200
    ver_results = ver_res.json()
    assert len(ver_results) >= 1
    assert all(v["verification_status"] == "SUPPORTED" for v in ver_results)

    # 8. Mandatory Investigator Decision Gate
    dec_res = client.post(
        f"/api/investigations/{inv_id}/decisions",
        json={
            "decision": "CONFIRM",
            "rationale": "Disk forensics findings verified and confirmed for official report synthesis.",
            "investigator_name": "Lead DFIR Investigator"
        }
    )
    assert dec_res.status_code == 201

    # 9. Generate 19-Section Report
    report_res = client.post(f"/api/investigations/{inv_id}/report")
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert "ADFIR DIGITAL FORENSIC INVESTIGATION REPORT" in report_data["full_report_markdown"]
    assert "7. Forensic Findings" in report_data["full_report_markdown"]
    assert "Deleted Filesystem Entry" in report_data["full_report_markdown"]
