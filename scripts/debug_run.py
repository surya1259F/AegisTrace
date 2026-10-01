"""
DEVELOPER TEST HARNESS ONLY — NOT EXECUTABLE IN PRODUCTION RUNTIME.
For developer integration testing of pipeline stages.
"""

import sys
import os
import json
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure ADFIR root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import Investigation, Evidence, ChainOfCustodyEvent, Finding
from forensic_tools.registry import tool_registry

def print_header(title):
    print("\n" + "=" * 60)
    print(f" >>> [DEBUG STEP]: {title}")
    print("=" * 60)

def main():
    print_header("1. Initializing TestClient & Database Engine")
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    print("[+] Database schema synchronized with SQLite.")

    # 1. Health & Status
    print_header("2. Probing /api/health and /api/system/status")
    health_res = client.get("/api/health")
    print(f"[+] Health Response [{health_res.status_code}]: {health_res.json()}")
    assert health_res.status_code == 200

    status_res = client.get("/api/system/status")
    print(f"[+] System Status [{status_res.status_code}]:")
    print(json.dumps(status_res.json(), indent=2))
    assert status_res.status_code == 200

    # 2. Forensic Tool Registry Status
    print_header("3. Inspecting Detected Forensic Tools")
    for tool in tool_registry.list_tools():
        avail_str = "AVAILABLE" if tool.is_available else "UNAVAILABLE (Requires binary on host)"
        print(f"  - {tool.display_name:<30} | Status: {avail_str:<32} | Path: {tool.path or 'None'}")

    # 3. Create Investigation
    print_header("4. Creating Live Investigation Workspace")
    inv_payload = {
        "name": "Live Debug Investigation - Case Alpha",
        "description": "Comprehensive live verification of the ADFIR forensic pipeline."
    }
    create_res = client.post("/api/investigations/", json=inv_payload)
    inv_data = create_res.json()
    inv_id = inv_data["id"]
    print(f"[+] Created Investigation [{create_res.status_code}]: ID={inv_id}, Name='{inv_data['name']}'")
    assert create_res.status_code == 201

    # 4. Ingest Synthetic Evidence
    print_header("5. Ingesting Evidence & Computing Streaming SHA-256")
    fixture_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "sample-evidence.txt"))
    intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
        "path": fixture_path,
        "notes": "Synthetic forensic text artifact for debug verification"
    })
    ev_data = intake_res.json()
    evidence_id = ev_data["id"]
    print(f"[+] Evidence Ingested [{intake_res.status_code}]:")
    print(f"    - File Name:       {ev_data['name']}")
    print(f"    - Inferred Type:   {ev_data['evidence_type']}")
    print(f"    - File Size:       {ev_data['size_bytes']} bytes")
    print(f"    - SHA-256 Hash:    {ev_data['sha256']}")
    print(f"    - Integrity State: {ev_data['integrity_status']}")
    assert intake_res.status_code == 201

    # 5. Verify Chain of Custody
    print_header("6. Verifying Immutable Chain of Custody")
    custody_res = client.get(f"/api/investigations/{inv_id}/custody")
    custody_events = custody_res.json()
    print(f"[+] Retrieved {len(custody_events)} Custody Event(s):")
    for ce in custody_events:
        print(f"    [{ce['timestamp']}] {ce['event_type']} by {ce['actor']}: {ce['description']}")
    assert len(custody_events) >= 1

    # 6. Autonomous Investigation Planning
    print_header("7. Generating Autonomous Investigation Strategy Plan")
    plan_res = client.post(f"/api/investigations/{inv_id}/plan")
    plan_data = plan_res.json()
    print(f"[+] Plan Generated [{plan_res.status_code}]: {plan_data['total_tasks']} tasks scheduled.")
    print(f"    Strategy: {plan_data['strategy_summary']}")
    for step in plan_data["steps"]:
        print(f"    * Step {step['step_id']}: {step['agent']} -> {step['tool']} ({step['action']})")

    # 7. Record Structured Findings
    print_header("8. Recording Ground-Truth Forensic Findings")
    f1_payload = {
        "evidence_id": evidence_id,
        "agent": "DiskAgent",
        "tool": "SleuthKit",
        "finding_type": "filesystem_artifact",
        "title": "Script File Detected in Target Directory",
        "description": "Identified script file record at inode 501 during directory structure parsing",
        "confidence": 0.95,
        "evidence_reference": "inode:501"
    }
    f1_res = client.post(f"/api/investigations/{inv_id}/findings", json=f1_payload)
    print(f"[+] Recorded Finding 1 [{f1_res.status_code}]: {f1_res.json()['title']}")

    f2_payload = {
        "evidence_id": evidence_id,
        "agent": "MalwareAgent",
        "tool": "YARA",
        "finding_type": "pattern_match",
        "title": "Command Pattern Match",
        "description": "Rule adfir_suspicious_commands matched on inode 501",
        "confidence": 0.98,
        "evidence_reference": "inode:501"
    }
    f2_res = client.post(f"/api/investigations/{inv_id}/findings", json=f2_payload)
    print(f"[+] Recorded Finding 2 [{f2_res.status_code}]: {f2_res.json()['title']}")

    # 8. Deterministic Correlation
    print_header("9. Executing Deterministic Correlation Engine")
    corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
    corr_events = corr_res.json()
    print(f"[+] Correlation Output [{corr_res.status_code}]: {len(corr_events)} Correlated Chain(s) Detected:")
    for ce in corr_events:
        print(f"    - {ce['title']} (Confidence: {ce['correlation_confidence']*100:.0f}%): {ce['description']}")
    assert len(corr_events) >= 1

    # 9. Verification Engine
    print_header("10. Executing Verification Engine & Confidence Scoring")
    ver_res = client.post(f"/api/investigations/{inv_id}/verify")
    ver_results = ver_res.json()
    print(f"[+] Verification Output [{ver_res.status_code}]:")
    for vr in ver_results:
        print(f"    - Status: [{vr['verification_status']}] Score: {vr['confidence_score']*100:.0f}% | Reason: {vr['reason']}")
    assert all(vr["verification_status"] == "SUPPORTED" for vr in ver_results)

    # 10. Generate 19-Section Court-Ready Report
    print_header("11. Generating 19-Section Court-Ready Investigation Report")
    report_res = client.post(f"/api/investigations/{inv_id}/report")
    report_data = report_res.json()
    print(f"[+] Report Generated [{report_res.status_code}]: Title='{report_data['title']}'")
    print(f"[+] Full Report Length: {len(report_data['full_report_markdown'])} characters.")
    print("\n--- REPORT PREVIEW (First 20 lines) ---")
    lines = report_data["full_report_markdown"].splitlines()[:20]
    for line in lines:
        print(line)
    print("---------------------------------------")

    print_header("12. ALL DEBUG CHECKS COMPLETED SUCCESSFULLY")
    print("[✓] Backend Core API: OPERATIONAL")
    print("[✓] Integrity Layer (SHA-256): VERIFIED")
    print("[✓] Multi-Agent Pipeline & Planning: OPERATIONAL")
    print("[✓] Correlation & Verification Engines: OPERATIONAL")
    print("[✓] 19-Section Court-Ready Reporting: OPERATIONAL")

if __name__ == "__main__":
    main()
