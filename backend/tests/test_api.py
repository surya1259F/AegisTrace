import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine
import tempfile
import os
import uuid

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_health():
    res = client.get("/api/v1/system/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"

def test_system_info():
    res = client.get("/api/v1/system/info")
    assert res.status_code == 200
    data = res.json()
    assert "forensic_tools" in data
    assert "volatility3" in data["forensic_tools"]

def test_end_to_end_forensic_pipeline():
    case_num = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    # 1. Create a Case
    case_payload = {
        "case_number": case_num,
        "title": "Suspected Ransomware & C2 Incident",
        "description": "Host workstation showed abnormal memory usage and outbound beaconing.",
        "investigator": "Lead Investigator Alice"
    }
    case_res = client.post("/api/v1/cases/", json=case_payload)
    assert case_res.status_code in (200, 201)
    case_data = case_res.json()
    case_id = case_data["id"]
    assert case_data["case_number"] == case_num

    # 2. Ingest Evidence (Create temporary simulated memory and disk image files)
    with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tmp_mem:
        tmp_mem.write(b"MOCK_MEMORY_HEADER_POWERSHELL_BEACONING_PAYLOAD")
        mem_path = tmp_mem.name

    with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as tmp_disk:
        tmp_disk.write(b"MOCK_DISK_IMAGE_MALICIOUS_PS1_SCRIPT")
        disk_path = tmp_disk.name

    try:
        # Ingest Memory Evidence
        ev_mem_res = client.post("/api/v1/evidence/intake", json={
            "case_id": case_id,
            "file_path": mem_path,
            "evidence_type": "MEMORY_DUMP",
            "acquisition_notes": "RAM capture from infected endpoint"
        })
        assert ev_mem_res.status_code in (200, 201)
        mem_evidence = ev_mem_res.json()
        assert mem_evidence["evidence_type"] == "MEMORY_DUMP"
        assert len(mem_evidence["sha256_hash"]) == 64

        # Ingest Disk Evidence
        ev_disk_res = client.post("/api/v1/evidence/intake", json={
            "case_id": case_id,
            "file_path": disk_path,
            "evidence_type": "DISK_IMAGE",
            "acquisition_notes": "Forensic disk clone"
        })
        assert ev_disk_res.status_code in (200, 201)

        # 3. Autonomous Investigation Planner
        plan_res = client.post(f"/api/v1/investigation/plan/{case_id}")
        assert plan_res.status_code == 200
        plan_data = plan_res.json()
        assert len(plan_data["planned_tasks"]) >= 3
        assert "MemoryAgent" in [t["agent_name"] for t in plan_data["planned_tasks"]]
        assert "DiskAgent" in [t["agent_name"] for t in plan_data["planned_tasks"]]

        # 4. Record Structured Findings (Simulated specialist agent outputs)
        f1_res = client.post("/api/v1/investigation/findings", json={
            "case_id": case_id,
            "evidence_id": mem_evidence["id"],
            "source_tool": "Volatility3",
            "agent_type": "MemoryAgent",
            "category": "Process",
            "title": "Hidden PowerShell Execution (PID 4920)",
            "details": {
                "process_name": "powershell.exe",
                "pid": 4920,
                "ppid": 1040,
                "command_line": "powershell.exe -enc SQBFAFgA...",
                "ip_address": "198.51.100.45"
            },
            "confidence_score": 0.98,
            "mitre_techniques": ["T1059.001", "T1055"]
        })
        assert f1_res.status_code == 200

        f2_res = client.post("/api/v1/investigation/findings", json={
            "case_id": case_id,
            "evidence_id": mem_evidence["id"],
            "source_tool": "Volatility3",
            "agent_type": "NetworkAgent",
            "category": "Network",
            "title": "Outbound C2 Connection to 198.51.100.45:443",
            "details": {
                "ip_address": "198.51.100.45",
                "port": 443,
                "protocol": "TCP",
                "process_name": "powershell.exe"
            },
            "confidence_score": 0.95,
            "mitre_techniques": ["T1071.001"]
        })
        assert f2_res.status_code == 200

        # 5. Correlation Engine
        corr_res = client.post(f"/api/v1/investigation/correlate/{case_id}")
        assert corr_res.status_code == 200
        corr_data = corr_res.json()
        assert len(corr_data["correlated_events"]) > 0

        # 6. Verification Engine
        ver_res = client.post(f"/api/v1/investigation/verify/{case_id}")
        assert ver_res.status_code == 200
        ver_data = ver_res.json()
        assert len(ver_data["verification_results"]) == 2
        assert all(v["verified"] for v in ver_data["verification_results"])

        # Mandatory Investigator Decision Gate
        dec_res = client.post(
            f"/api/cases/{case_id}/decisions",
            json={
                "decision": "CONFIRM",
                "rationale": "Verified multi-artifact correlation confirmed.",
                "investigator_name": "Lead DFIR Investigator"
            }
        )
        assert dec_res.status_code == 201

        # 7. Generate Investigation Report
        rep_res = client.post(f"/api/v1/reports/generate/{case_id}")
        assert rep_res.status_code == 200
        rep_data = rep_res.json()
        assert "Investigation Report" in rep_data["title"]
        assert len(rep_data["indicators_of_compromise"]) >= 1
        assert "198.51.100.45" in rep_data["full_report_markdown"]
        assert "powershell.exe" in rep_data["full_report_markdown"]

    finally:
        if os.path.exists(mem_path):
            os.remove(mem_path)
        if os.path.exists(disk_path):
            os.remove(disk_path)
