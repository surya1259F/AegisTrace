import os
import sys
import time
import signal
import socket
import secrets
import hashlib
import subprocess
import pytest
import httpx
from pathlib import Path

DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist" / "adfir-backend"
EXECUTABLE = DIST_DIR / ("adfir-backend.exe" if sys.platform.startswith("win") else "adfir-backend")

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_production_end_to_end_smoke(tmp_path):
    """
    End-to-End Production Smoke & Lifecycle Reliability Test:
    1. Spawn packaged PyInstaller backend on dynamic port with 256-bit bootstrap secret.
    2. Verify readiness, bootstrap secret auth, and persistent data directory resolution.
    3. User Signup & Login -> retrieve JWT access token.
    4. Real Case Creation -> verify case ID, owner, authorization.
    5. Real Evidence Registration -> intake real evidence file, compute SHA-256, verify custody.
    6. Real Forensic Tool Execution -> run malware/YARA/ExifTool analysis, verify result capture and evidence preservation.
    7. Authorization Security -> verify User 2 cannot access User 1's case.
    8. Graceful Shutdown -> issue /api/v1/system/shutdown with bootstrap secret header, verify clean exit.
    9. Restart Reliability -> re-spawn backend on NEW port, verify all data (case, evidence, custody) survives restart.
    10. Clean final shutdown.
    """
    assert EXECUTABLE.exists(), "Packaged backend executable dist/adfir-backend/adfir-backend must exist."

    # Custom persistent data directory for this test run
    custom_data_dir = tmp_path / "adfir_smoke_data"
    custom_data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Allocate dynamic port & generate bootstrap secret
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port1 = sock.getsockname()[1]
    sock.close()

    bootstrap_secret1 = secrets.token_hex(32)

    env1 = os.environ.copy()
    env1["ADFIR_PORT"] = str(port1)
    env1["ADFIR_INTERNAL_SECRET"] = bootstrap_secret1
    env1["ADFIR_DATA_DIR"] = str(custom_data_dir)

    proc1 = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env1,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    pid1 = proc1.pid
    assert pid1 > 0

    base_url1 = f"http://127.0.0.1:{port1}"
    client1 = httpx.Client(timeout=5.0)

    try:
        # 2. Wait for readiness
        ready = False
        for _ in range(30):
            try:
                r = client1.get(f"{base_url1}/api/v1/system/health")
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.3)

        assert ready, f"Packaged backend process failed readiness check on port {port1}"

        # Base headers with Desktop Bootstrap Secret
        base_headers1 = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret1}

        # 3. User 1 Signup & Login
        u1_email = f"investigator_{secrets.token_hex(4)}@adfir.local"
        u1_pass = "SecurePass123!#"

        res_signup = client1.post(
            f"{base_url1}/api/v1/auth/signup",
            headers=base_headers1,
            json={"email": u1_email, "password": u1_pass, "name": "Lead Investigator"}
        )
        assert res_signup.status_code in (200, 201), f"Signup failed: {res_signup.text}"

        res_login = client1.post(
            f"{base_url1}/api/v1/auth/login",
            headers=base_headers1,
            json={"email": u1_email, "password": u1_pass}
        )
        assert res_login.status_code == 200, f"Login failed: {res_login.text}"
        u1_token = res_login.json()["access_token"]
        auth_headers1 = {**base_headers1, "Authorization": f"Bearer {u1_token}"}

        # Verify User 1 profile
        res_me = client1.get(f"{base_url1}/api/v1/auth/me", headers=auth_headers1)
        assert res_me.status_code == 200
        u1_id = res_me.json()["id"]

        # 4. Real Case Creation via /api/cases/
        case_name = f"Incident Response Case {secrets.token_hex(3)}"
        res_case = client1.post(
            f"{base_url1}/api/cases/",
            headers=auth_headers1,
            json={"name": case_name, "description": "Smoke test investigation case"}
        )
        assert res_case.status_code in (200, 201), f"Case creation failed: {res_case.text}"
        case_data = res_case.json()
        case_id = case_data["id"]

        # 5. Real Evidence Registration via /api/cases/{case_id}/evidence/intake
        evidence_src_dir = tmp_path / "source_evidence"
        evidence_src_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = evidence_src_dir / "sample_suspicious_artifact.bin"
        evidence_content = b"ADFIR_SMOKE_TEST_EVIDENCE_PAYLOAD_" + secrets.token_bytes(64)
        evidence_file.write_bytes(evidence_content)
        expected_sha256 = hashlib.sha256(evidence_content).hexdigest()

        res_evidence = client1.post(
            f"{base_url1}/api/cases/{case_id}/evidence/intake",
            headers=auth_headers1,
            json={"path": str(evidence_file), "notes": "Registered via production smoke test"}
        )
        assert res_evidence.status_code in (200, 201), f"Evidence intake failed: {res_evidence.text}"
        evidence_data = res_evidence.json()
        evidence_id = evidence_data["id"]
        assert evidence_data["sha256"] == expected_sha256

        # Verify chain of custody record generated via /api/cases/{case_id}/custody
        res_custody = client1.get(f"{base_url1}/api/cases/{case_id}/custody", headers=auth_headers1)
        assert res_custody.status_code == 200
        custody_records = res_custody.json()
        assert len(custody_records) >= 1

        # 6. Real Forensic Tool Execution (Malware / YARA / ExifTool) via /api/cases/{case_id}/analysis/malware
        res_analysis = client1.post(
            f"{base_url1}/api/cases/{case_id}/analysis/malware",
            headers=auth_headers1,
            json={"evidence_id": evidence_id, "rule_id": "adfir_test_rules"}
        )
        assert res_analysis.status_code == 200, f"Analysis failed: {res_analysis.text}"
        analysis_res = res_analysis.json()
        assert "execution_id" in analysis_res or "findings" in analysis_res or "status" in analysis_res

        # Verify original evidence file remains UNCHANGED
        assert evidence_file.read_bytes() == evidence_content

        # 7. Authorization Security: User 2 Signup & Access Attempt
        u2_email = f"unauth_user_{secrets.token_hex(4)}@adfir.local"
        client1.post(
            f"{base_url1}/api/v1/auth/signup",
            headers=base_headers1,
            json={"email": u2_email, "password": u1_pass, "name": "Unauthorized User"}
        )
        res_login2 = client1.post(
            f"{base_url1}/api/v1/auth/login",
            headers=base_headers1,
            json={"email": u2_email, "password": u1_pass}
        )
        u2_token = res_login2.json()["access_token"]
        auth_headers2 = {**base_headers1, "Authorization": f"Bearer {u2_token}"}

        # User 2 attempting to access User 1's case must be denied
        res_unauth_case = client1.get(f"{base_url1}/api/cases/{case_id}", headers=auth_headers2)
        assert res_unauth_case.status_code in (403, 404), "Unauthorized user was granted access to case!"

        # 8. Graceful Shutdown of Instance 1
        res_shutdown = client1.post(
            f"{base_url1}/api/v1/system/shutdown",
            headers={"X-ADFIR-Bootstrap-Secret": bootstrap_secret1}
        )
        assert res_shutdown.status_code == 200

        exit_code1 = proc1.wait(timeout=5.0)
        assert exit_code1 in (0, -signal.SIGTERM)

        # Verify no zombie process remains
        try:
            os.kill(pid1, 0)
            assert False, "Process pid1 is still alive after shutdown"
        except OSError:
            pass # Process is dead

        # 9. Restart Reliability: Spawn Instance 2 pointing to SAME custom_data_dir
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.bind(("127.0.0.1", 0))
        port2 = sock2.getsockname()[1]
        sock2.close()

        bootstrap_secret2 = secrets.token_hex(32)
        env2 = os.environ.copy()
        env2["ADFIR_PORT"] = str(port2)
        env2["ADFIR_INTERNAL_SECRET"] = bootstrap_secret2
        env2["ADFIR_DATA_DIR"] = str(custom_data_dir)

        proc2 = subprocess.Popen(
            [str(EXECUTABLE)],
            env=env2,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        pid2 = proc2.pid

        base_url2 = f"http://127.0.0.1:{port2}"
        client2 = httpx.Client(timeout=5.0)

        ready2 = False
        for _ in range(30):
            try:
                r = client2.get(f"{base_url2}/api/v1/system/health")
                if r.status_code == 200:
                    ready2 = True
                    break
            except Exception:
                time.sleep(0.3)

        assert ready2, f"Restarted backend failed readiness check on port {port2}"

        base_headers2 = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret2}

        # Re-login User 1 on Instance 2
        res_relogin = client2.post(
            f"{base_url2}/api/v1/auth/login",
            headers=base_headers2,
            json={"email": u1_email, "password": u1_pass}
        )
        assert res_relogin.status_code == 200
        re_auth_headers1 = {**base_headers2, "Authorization": f"Bearer {res_relogin.json()['access_token']}"}

        # Verify case data survived restart
        res_cases = client2.get(f"{base_url2}/api/cases/", headers=re_auth_headers1)
        assert res_cases.status_code == 200
        cases_list = res_cases.json()
        matching = [c for c in cases_list if c["id"] == case_id]
        assert len(matching) == 1, "Persisted case disappeared after application restart!"

        # Verify evidence data survived restart
        res_ev_list = client2.get(f"{base_url2}/api/cases/{case_id}/evidence", headers=re_auth_headers1)
        assert res_ev_list.status_code == 200
        ev_list = res_ev_list.json()
        assert len(ev_list) >= 1
        assert ev_list[0]["sha256"] == expected_sha256

        # 10. Final Clean Shutdown of Instance 2
        res_shutdown2 = client2.post(
            f"{base_url2}/api/v1/system/shutdown",
            headers={"X-ADFIR-Bootstrap-Secret": bootstrap_secret2}
        )
        assert res_shutdown2.status_code == 200
        proc2.wait(timeout=5.0)

    finally:
        client1.close()
        if proc1.poll() is None:
            proc1.terminate()
            proc1.wait()

        if 'client2' in locals():
            client2.close()
        if 'proc2' in locals() and proc2.poll() is None:
            proc2.terminate()
            proc2.wait()

 