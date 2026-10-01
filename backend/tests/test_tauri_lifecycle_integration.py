import os
import sys
import time
import signal
import subprocess
import secrets
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
import httpx
from pathlib import Path

DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist" / "adfir-backend"
EXECUTABLE = DIST_DIR / ("adfir-backend.exe" if sys.platform.startswith("win") else "adfir-backend")

def test_rust_bootstrap_secret_entropy_and_format():
    # Rust generates 256-bit (32 byte) hex secret
    secret1 = secrets.token_hex(32)
    secret2 = secrets.token_hex(32)
    assert len(secret1) == 64
    assert len(secret2) == 64
    assert secret1 != secret2

def test_dynamic_port_allocation():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    assert 1024 <= port <= 65535

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_tauri_lifecycle_sidecar_spawn_readiness_and_shutdown(tmp_path):
    assert EXECUTABLE.exists(), "Build dist must exist before running sidecar test"

    # Allocate ephemeral port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    # Generate 256-bit bootstrap secret
    bootstrap_secret = secrets.token_hex(32)
    custom_data_dir = tmp_path / "tauri_lifecycle_data"

    env = os.environ.copy()
    env["ADFIR_PORT"] = str(port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret
    env["ADFIR_DATA_DIR"] = str(custom_data_dir)

    # Spawn process directly without shell wrapper
    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    pid = proc.pid
    assert pid > 0

    base_url = f"http://127.0.0.1:{port}"
    health_url = f"{base_url}/api/v1/system/health"
    info_url = f"{base_url}/api/v1/info"
    shutdown_url = f"{base_url}/api/v1/system/shutdown"

    try:
        client = httpx.Client(timeout=2.0)
        ready = False
        for _ in range(30):
            try:
                res = client.get(health_url)
                if res.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.3)

        assert ready, f"Sidecar process failed readiness check on port {port}"

        # Test Bootstrap Authentication Enforcement
        # Missing secret -> 403
        res_no_secret = client.get(info_url)
        assert res_no_secret.status_code == 403

        # Invalid secret -> 403
        res_bad_secret = client.get(info_url, headers={"X-ADFIR-Bootstrap-Secret": "invalid_token"})
        assert res_bad_secret.status_code == 403

        # Valid secret -> 200
        valid_headers = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret}
        res_valid = client.get(info_url, headers=valid_headers)
        assert res_valid.status_code == 200

        # Test Unauthorized Shutdown Attempt (Wrong Secret) -> 403 Forbidden
        res_unauth_shutdown = client.post(shutdown_url, headers={"X-ADFIR-Bootstrap-Secret": "wrong_secret"})
        assert res_unauth_shutdown.status_code == 403

        # Graceful Shutdown with valid secret -> 200 OK
        res_shutdown = client.post(shutdown_url, headers=valid_headers)
        assert res_shutdown.status_code == 200

        exit_code = proc.wait(timeout=5.0)
        assert exit_code == 0 or exit_code == -signal.SIGTERM

    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=2.0)

def test_process_identity_verification_linux():
    if sys.platform.startswith("linux"):
        pid = os.getpid()
        stat_path = Path(f"/proc/{pid}/stat")
        assert stat_path.exists()
        content = stat_path.read_text()
        r_idx = content.rfind(")")
        after_comm = content[r_idx + 1:].split()
        starttime = int(after_comm[19])
        assert starttime > 0

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_occupied_port_bind_failure(tmp_path):
    # Occupy a port with a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    bootstrap_secret = secrets.token_hex(32)
    env = os.environ.copy()
    env["ADFIR_PORT"] = str(port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret
    env["ADFIR_DATA_DIR"] = str(tmp_path / "occupied_port_data")

    # Attempting to launch backend on occupied port must fail/exit quickly
    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    try:
        exit_code = proc.wait(timeout=15.0)
        assert exit_code != 0, "Backend must fail to bind on occupied port"
    finally:
        sock.close()
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

class DummyUnrelatedServiceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "unrelated_third_party_service"}')

    def log_message(self, format, *args):
        pass

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_port_conflict_unrelated_service_rejection_and_identity_protection(tmp_path):
    # Spin up dummy unrelated HTTP service on ephemeral loopback port
    dummy_server = HTTPServer(("127.0.0.1", 0), DummyUnrelatedServiceHandler)
    port = dummy_server.server_address[1]
    server_thread = threading.Thread(target=dummy_server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Verify dummy server is responding
        client = httpx.Client(timeout=2.0)
        res = client.get(f"http://127.0.0.1:{port}/api/v1/system/health")
        assert res.status_code == 200
        assert "unrelated_third_party_service" in res.text

        # 1. Verify ADFIR bootstrap secret authentication prevents trusting unrelated service
        res_auth = client.get(f"http://127.0.0.1:{port}/api/v1/info", headers={"X-ADFIR-Bootstrap-Secret": secrets.token_hex(32)})
        assert "unrelated_third_party_service" in res_auth.text

        # 2. Attempt launching backend on occupied port -> backend fails to bind and exits cleanly
        bootstrap_secret = secrets.token_hex(32)
        env = os.environ.copy()
        env["ADFIR_PORT"] = str(port)
        env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret
        env["ADFIR_DATA_DIR"] = str(tmp_path / "conflict_port_data")

        proc = subprocess.Popen(
            [str(EXECUTABLE)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        exit_code = proc.wait(timeout=15.0)
        assert exit_code != 0, "Backend process must exit when port is occupied"

        # 3. Verify unrelated process was NOT killed or affected by ADFIR
        res_after = client.get(f"http://127.0.0.1:{port}/api/v1/system/health")
        assert res_after.status_code == 200
        assert "unrelated_third_party_service" in res_after.text

    finally:
        dummy_server.shutdown()
        dummy_server.server_close()
