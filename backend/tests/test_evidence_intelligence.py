import os
import sys
import time
import socket
import secrets
import hashlib
import subprocess
import pytest
import httpx
from pathlib import Path

from backend.app.services.intelligence import EvidenceIntelligenceEngine, ResourceProfile

DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist" / "adfir-backend"
EXECUTABLE = DIST_DIR / ("adfir-backend.exe" if sys.platform.startswith("win") else "adfir-backend")

def test_magic_header_detection_evtx(tmp_path):
    evtx_file = tmp_path / "sample_sec.evtx"
    evtx_file.write_bytes(b"ElfFile\x00" + b"\x00" * 512)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-1", "sample_sec.evtx", str(evtx_file))
    assert intel.evidence_type == "WINDOWS_EVENT_LOG"
    assert intel.source_kind == "EVENT_LOG"
    assert intel.detected_format == "WINDOWS_EVENT_LOG_V2"
    assert intel.platform_hint == "WINDOWS"
    assert intel.confidence == 1.0

def test_magic_header_detection_sqlite(tmp_path):
    sqlite_file = tmp_path / "history.sqlite"
    sqlite_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 512)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-2", "history.sqlite", str(sqlite_file))
    assert intel.evidence_type == "BROWSER_ARTIFACT"
    assert intel.source_kind == "BROWSER_DB"
    assert intel.detected_format == "SQLITE_V3_BROWSER_DB"
    assert intel.confidence == 1.0

def test_magic_header_detection_pe_executable(tmp_path):
    pe_file = tmp_path / "malicious.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 512)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-3", "malicious.exe", str(pe_file))
    assert intel.evidence_type == "PE_EXECUTABLE"
    assert intel.source_kind == "MALWARE_SAMPLE"
    assert intel.detected_format == "PE32_EXECUTABLE"
    assert intel.platform_hint == "WINDOWS"
    assert intel.confidence >= 0.9

def test_magic_header_detection_elf_executable(tmp_path):
    elf_file = tmp_path / "backdoor_daemon"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 512)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-4", "backdoor_daemon", str(elf_file))
    assert intel.evidence_type == "ELF_EXECUTABLE"
    assert intel.source_kind == "MALWARE_SAMPLE"
    assert intel.detected_format == "ELF_EXECUTABLE"
    assert intel.platform_hint == "LINUX"
    assert intel.confidence >= 0.9

def test_magic_header_detection_zip_archive(tmp_path):
    zip_file = tmp_path / "evidence_vault.zip"
    zip_file.write_bytes(b"PK\x03\x04" + b"\x00" * 512)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-5", "evidence_vault.zip", str(zip_file))
    assert intel.evidence_type == "ARCHIVE"
    assert intel.source_kind == "ARCHIVE"
    assert intel.detected_format == "ZIP_CONTAINER"
    assert intel.confidence >= 0.9

def test_magic_header_detection_unknown_binary(tmp_path):
    bin_file = tmp_path / "raw_stream.dat"
    bin_file.write_bytes(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 100)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-6", "raw_stream.dat", str(bin_file))
    assert intel.evidence_type == "UNKNOWN"
    assert intel.source_kind == "UNKNOWN"
    assert intel.detected_format == "UNKNOWN_BINARY_STREAM"
    assert intel.confidence == 0.2
    assert len(intel.limitations) >= 1

def test_tool_mapping_and_resource_profile(tmp_path):
    large_file = tmp_path / "disk.raw"
    large_file.write_bytes(b"\x00" * 1024 * 1024)
    intel = EvidenceIntelligenceEngine.analyze_evidence("ev-7", "disk.raw", str(large_file))
    assert intel.resource_profile.expected_cpu_class == "LOW"
    assert intel.resource_profile.risk_level == "LOW"

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_evidence_intake_verify_and_intelligence_api(tmp_path):
    assert EXECUTABLE.exists(), "Packaged backend executable must exist."

    custom_data_dir = tmp_path / "intel_smoke_data"
    custom_data_dir.mkdir(parents=True, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    bootstrap_secret = secrets.token_hex(32)

    env = os.environ.copy()
    env["ADFIR_PORT"] = str(port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret
    env["ADFIR_DATA_DIR"] = str(custom_data_dir)

    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    base_url = f"http://127.0.0.1:{port}"
    client = httpx.Client(timeout=5.0)

    try:
        # Readiness loop
        ready = False
        for _ in range(60):
            try:
                r = client.get(f"{base_url}/api/v1/system/health")
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.3)

        assert ready, f"Backend failed readiness check on port {port}"

        base_headers = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret}

        # User Signup & Login
        u_email = f"intel_analyst_{secrets.token_hex(4)}@adfir.local"
        u_pass = "SecurePass123!#"
        client.post(
            f"{base_url}/api/v1/auth/signup",
            headers=base_headers,
            json={"email": u_email, "password": u_pass, "name": "Intelligence Analyst"}
        )
        res_login = client.post(
            f"{base_url}/api/v1/auth/login",
            headers=base_headers,
            json={"email": u_email, "password": u_pass}
        )
        auth_headers = {**base_headers, "Authorization": f"Bearer {res_login.json()['access_token']}"}

        # Case Creation
        res_case = client.post(
            f"{base_url}/api/cases/",
            headers=auth_headers,
            json={"name": "Evidence Intelligence Test Case", "description": "Automated test case"}
        )
        case_id = res_case.json()["id"]

        # Intake EVTX Evidence File
        sample_evtx = tmp_path / "SecurityLogs.evtx"
        evtx_bytes = b"ElfFile\x00" + secrets.token_bytes(1024)
        sample_evtx.write_bytes(evtx_bytes)
        expected_sha256 = hashlib.sha256(evtx_bytes).hexdigest()

        res_ev = client.post(
            f"{base_url}/api/cases/{case_id}/evidence/intake",
            headers=auth_headers,
            json={"path": str(sample_evtx), "notes": "EVTX Log Evidence Intake"}
        )
        assert res_ev.status_code == 201
        ev_data = res_ev.json()
        ev_id = ev_data["id"]

        assert ev_data["evidence_type"] == "WINDOWS_EVENT_LOG"
        assert ev_data["source_kind"] == "EVENT_LOG"
        assert ev_data["detected_format"] == "WINDOWS_EVENT_LOG_V2"
        assert ev_data["sha256"] == expected_sha256
        assert ev_data["integrity_status"] == "VERIFIED"

        # Verify Evidence Intelligence Endpoint
        res_intel = client.get(f"{base_url}/api/cases/{case_id}/evidence/{ev_id}/intelligence", headers=auth_headers)
        assert res_intel.status_code == 200
        intel_res = res_intel.json()["intelligence"]
        assert intel_res["evidence_type"] == "WINDOWS_EVENT_LOG"
        assert len(intel_res["recommended_tools"]) >= 1

        # Verify Integrity Verification Endpoint
        res_verify = client.post(f"{base_url}/api/cases/{case_id}/evidence/{ev_id}/verify", headers=auth_headers)
        assert res_verify.status_code == 200
        verify_data = res_verify.json()
        assert verify_data["integrity_status"] == "VERIFIED"
        assert verify_data["current_sha256"] == expected_sha256

        # Verify Custody Records Endpoint
        res_cust = client.get(f"{base_url}/api/cases/{case_id}/evidence/{ev_id}/custody", headers=auth_headers)
        assert res_cust.status_code == 200
        custody_list = res_cust.json()
        assert len(custody_list) >= 2 # REGISTERED and INTEGRITY_VERIFIED

        # Verify Intelligence Refresh Endpoint
        res_refresh = client.post(f"{base_url}/api/cases/{case_id}/evidence/{ev_id}/intelligence/refresh", headers=auth_headers)
        assert res_refresh.status_code == 200
        assert res_refresh.json()["intelligence"]["evidence_type"] == "WINDOWS_EVENT_LOG"

        # Clean Shutdown
        client.post(f"{base_url}/api/v1/system/shutdown", headers=base_headers)
        proc.wait(timeout=5.0)

    finally:
        client.close()
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

