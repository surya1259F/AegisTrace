import os
import sys
import time
import json
import uuid
import shutil
import subprocess
import tempfile
import secrets
from pathlib import Path
import pytest
import httpx

EXECUTABLE = Path(__file__).resolve().parent.parent.parent / "dist" / "adfir-backend" / "adfir-backend"


@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_production_gui_evidence_workflow_complete(tmp_path):
    """
    Complete real production workflow test for Gap 2 acceptance:
    1. Spawns actual packaged PyInstaller backend executable.
    2. Performs user signup & authentication.
    3. Creates a case.
    4. Ingests evidence file.
    5. Verifies preserved evidence location in persistent ADFIR_DATA_DIR (not /tmp).
    6. Verifies source & preserved SHA-256 hashes match.
    7. Verifies integrity check returns VERIFIED.
    8. Verifies immutable chain-of-custody event log.
    9. Verifies Evidence Intelligence Engine output (source_kind, tools, analysis families, resource profile).
    10. Tampers with controlled vault copy -> verifies tamper detection & INTEGRITY_VIOLATION custody log.
    11. Restores evidence, restarts backend process -> verifies restart persistence of cases, evidence & intelligence.
    12. Security validation: verifies 403 Forbidden on unauthorized user cross-access & rejection of path traversal.
    """
    assert EXECUTABLE.exists(), f"Packaged backend executable missing at {EXECUTABLE}"

    data_dir = Path(__file__).resolve().parent.parent.parent / ".adfir_prod_test_data"
    if data_dir.exists():
        shutil.rmtree(data_dir, ignore_errors=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    port = 39800 + (os.getpid() % 1000)
    bootstrap_secret = secrets.token_hex(32)

    env = os.environ.copy()
    env["ADFIR_DATA_DIR"] = str(data_dir)
    env["ADFIR_PORT"] = str(port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret

    # 1. Launch packaged backend executable
    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    client = httpx.Client(timeout=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Poll readiness
        ready = False
        for _ in range(30):
            try:
                r = client.get(f"{base_url}/api/v1/system/health")
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.3)

        if not ready:
            proc.terminate()
            outs, errs = proc.communicate(timeout=2.0)
            assert False, f"Packaged backend failed readiness check. Out: {outs}, Err: {errs}"

        bootstrap_headers = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret}

        # 2. Authenticate Investigator User
        user_email = f"investigator_{uuid.uuid4().hex[:6]}@adfir.local"
        password = "SecureInvestigatorPassword123!"

        signup_res = client.post(f"{base_url}/api/v1/auth/signup", headers=bootstrap_headers, json={
            "email": user_email,
            "password": password,
            "name": "Lead Forensic Investigator"
        })
        assert signup_res.status_code == 201, f"Signup failed: {signup_res.status_code} {signup_res.text}"

        login_res = client.post(f"{base_url}/api/v1/auth/login", headers=bootstrap_headers, json={
            "email": user_email,
            "password": password
        })
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "X-ADFIR-Bootstrap-Secret": bootstrap_secret
        }

        # 3. Create Case
        case_res = client.post(f"{base_url}/api/v1/cases/", headers=headers, json={
            "title": "Acceptance Test Investigation",
            "description": "Evidence Acquisition & Intelligence Gap 2 Validation",
            "case_number": f"CASE-GAP2-{uuid.uuid4().hex[:6].upper()}"
        })
        assert case_res.status_code in (200, 201), f"Create case failed: {case_res.status_code} {case_res.text}"
        case_id = case_res.json()["id"]

        # 4. Ingest Controlled Evidence File
        fixture_file = tmp_path / "host_evidence_sample.evtx"
        # Write realistic EVTX header bytes (ElfFile\x00)
        evtx_header = b"ElfFile\x00" + b"\x00" * 504 + b"FORENSIC_SECURITY_LOG_EVENT_RECORDS"
        fixture_file.write_bytes(evtx_header)
        import hashlib
        expected_sha = hashlib.sha256(evtx_header).hexdigest()

        intake_res = client.post(f"{base_url}/api/v1/evidence/intake", headers=headers, json={
            "case_id": case_id,
            "file_path": str(fixture_file),
            "acquisition_notes": "Captured domain controller security event log"
        })
        assert intake_res.status_code == 201
        evidence = intake_res.json()
        ev_id = evidence["id"]

        # 5. Verify preserved evidence exists in persistent ADFIR_DATA_DIR (not /tmp)
        vault_path = Path(evidence["storage_path"]).resolve()
        assert str(data_dir.resolve()) in str(vault_path), f"Evidence vault path '{vault_path}' is outside ADFIR_DATA_DIR '{data_dir}'"
        assert not str(vault_path).startswith("/tmp"), "Evidence stored in prohibited /tmp directory!"
        assert vault_path.exists(), "Preserved evidence file does not exist on disk!"

        # 6. Verify source & preserved hashes match
        preserved_hash = hashlib.sha256(vault_path.read_bytes()).hexdigest()
        assert preserved_hash.lower() == expected_sha.lower()

        # 7. Request Integrity Verification
        verify_res = client.post(f"{base_url}/api/v1/evidence/{ev_id}/verify", headers=headers)
        assert verify_res.status_code == 200
        ver_data = verify_res.json()
        assert ver_data["integrity_status"] == "VERIFIED"
        assert ver_data["read_only_verified"] is True

        # 8. Retrieve Custody History
        custody_res = client.get(f"{base_url}/api/v1/evidence/{ev_id}/custody", headers=headers)
        assert custody_res.status_code == 200
        custody_events = custody_res.json()
        event_types = [e["event_type"] for e in custody_events]
        assert "EVIDENCE_REGISTERED" in event_types
        assert "INTEGRITY_VERIFIED" in event_types or "INTEGRITY_VERIFIED_PRE_ANALYSIS" in event_types

        # 9. Evidence Intelligence Verification
        intel_res = client.get(f"{base_url}/api/v1/evidence/{ev_id}/intelligence", headers=headers)
        assert intel_res.status_code == 200
        res_json = intel_res.json()
        intel = res_json.get("intelligence", res_json)
        assert intel["source_kind"] == "EVENT_LOG"
        assert intel["detected_format"] == "WINDOWS_EVENT_LOG_V2"
        assert len(intel["recommended_tools"]) >= 1
        assert len(intel["recommended_analysis_families"]) >= 1
        assert "expected_cpu_class" in intel["resource_profile"] or "cpu" in intel["resource_profile"]
        assert "expected_memory_class" in intel["resource_profile"] or "ram" in intel["resource_profile"]
        assert intel.get("engine_version") == "1.0.0" or intel.get("provenance", {}).get("engine_version") == "1.0.0"

        # 10. Tamper Detection Test on Controlled Vault Copy ONLY
        # Remove read-only lock temporarily to simulate malicious tampering
        os.chmod(vault_path, 0o644)
        original_vault_bytes = vault_path.read_bytes()
        tampered_content = b"TAMPERED_MALICIOUS_LOG_DATA_BLOCK"
        vault_path.write_bytes(tampered_content)
        os.chmod(vault_path, 0o444)

        # Run integrity verification on tampered file
        tamper_verify_res = client.post(f"{base_url}/api/v1/evidence/{ev_id}/verify", headers=headers)
        assert tamper_verify_res.status_code == 200
        tamper_ver = tamper_verify_res.json()
        assert tamper_ver["integrity_status"] in ("VERIFICATION_FAILED", "INTEGRITY_MISMATCH")

        # Check custody log for INTEGRITY_VIOLATION / INTEGRITY_MISMATCH event
        tamper_custody_res = client.get(f"{base_url}/api/v1/evidence/{ev_id}/custody", headers=headers)
        tamper_events = [e["event_type"] for e in tamper_custody_res.json()]
        assert "INTEGRITY_VIOLATION" in tamper_events or "INTEGRITY_MISMATCH" in tamper_events

        # Restore original vault content
        os.chmod(vault_path, 0o644)
        vault_path.write_bytes(original_vault_bytes)
        os.chmod(vault_path, 0o444)

        # 11. Security Authorization & Path Traversal Validation
        # Second user signup
        user2_res = client.post(f"{base_url}/api/v1/auth/signup", headers=bootstrap_headers, json={
            "email": f"unauthorized_{uuid.uuid4().hex[:6]}@adfir.local",
            "password": password,
            "name": "Unauthorized User"
        })
        user2_token = client.post(f"{base_url}/api/v1/auth/login", headers=bootstrap_headers, json={
            "email": user2_res.json()["email"],
            "password": password
        }).json()["access_token"]
        user2_headers = {
            "Authorization": f"Bearer {user2_token}",
            "X-ADFIR-Bootstrap-Secret": bootstrap_secret
        }

        # Second user attempt to access case -> 403 Forbidden
        unauth_res = client.get(f"{base_url}/api/v1/cases/{case_id}", headers=user2_headers)
        assert unauth_res.status_code == 403

        # Path traversal intake rejection -> 400 Bad Request
        traversal_res = client.post(f"{base_url}/api/v1/evidence/intake", headers=headers, json={
            "case_id": case_id,
            "file_path": "../../../nonexistent_path_traversal_target.txt"
        })
        assert traversal_res.status_code == 400

        # 12. Restart Backend Process & Verify Data Persistence
        client.post(f"{base_url}/api/v1/system/shutdown", headers=bootstrap_headers)
        proc.wait(timeout=5.0)

        # Relaunch process against same persistent ADFIR_DATA_DIR
        port2 = port + 1
        env2 = env.copy()
        env2["ADFIR_PORT"] = str(port2)
        base_url2 = f"http://127.0.0.1:{port2}"

        proc2 = subprocess.Popen(
            [str(EXECUTABLE)],
            env=env2,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            ready2 = False
            for _ in range(30):
                try:
                    r = client.get(f"{base_url2}/api/v1/system/health")
                    if r.status_code == 200:
                        ready2 = True
                        break
                except Exception:
                    time.sleep(0.3)

            if not ready2:
                proc2.terminate()
                outs2, errs2 = proc2.communicate(timeout=2.0)
                assert False, f"Restarted backend failed readiness check. Out: {outs2}, Err: {errs2}"

            # Re-verify authentication & case persistence
            re_login = client.post(f"{base_url2}/api/v1/auth/login", headers=bootstrap_headers, json={
                "email": user_email,
                "password": password
            })
            assert re_login.status_code == 200
            re_token = re_login.json()["access_token"]
            re_headers = {
                "Authorization": f"Bearer {re_token}",
                "X-ADFIR-Bootstrap-Secret": bootstrap_secret
            }

            # Verify case survived restart
            re_case = client.get(f"{base_url2}/api/v1/cases/{case_id}", headers=re_headers)
            assert re_case.status_code == 200, f"Get case failed on restart: {re_case.status_code} {re_case.text}"
            assert re_case.json()["id"] == case_id

            # Verify evidence & intelligence survived restart
            re_evidence = client.get(f"{base_url2}/api/v1/evidence/{ev_id}", headers=re_headers)
            assert re_evidence.status_code == 200
            assert re_evidence.json()["sha256"] == expected_sha

            re_intel = client.get(f"{base_url2}/api/v1/evidence/{ev_id}/intelligence", headers=re_headers)
            assert re_intel.status_code == 200
            re_intel_dict = re_intel.json()
            re_intel_obj = re_intel_dict.get("intelligence", re_intel_dict)
            assert re_intel_obj["source_kind"] == "EVENT_LOG"

        finally:
            try:
                client.post(f"{base_url2}/api/v1/system/shutdown", headers=bootstrap_headers)
                proc2.wait(timeout=5.0)
            except Exception:
                if proc2.poll() is None:
                    proc2.terminate()

    finally:
        if proc.poll() is None:
            proc.terminate()
        client.close()
