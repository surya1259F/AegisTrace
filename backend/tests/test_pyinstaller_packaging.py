import os
import sys
import time
import signal
import subprocess
import shutil
import pytest
import httpx
from pathlib import Path

# Absolute path to the compiled PyInstaller executable directory
DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist" / "adfir-backend"
EXECUTABLE = DIST_DIR / ("adfir-backend.exe" if sys.platform.startswith("win") else "adfir-backend")

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_pyinstaller_executable_exists():
    assert EXECUTABLE.exists(), f"PyInstaller executable not found at {EXECUTABLE}"
    assert os.access(EXECUTABLE, os.X_OK), f"File at {EXECUTABLE} is not executable"

# =============================================================================
# DATA PATH RESOLUTION TESTS
# =============================================================================

def test_path_resolution_dev_vs_frozen_mode(tmp_path, monkeypatch):
    from backend.app.core.config import Settings, get_user_data_dir

    # Scenario 1: Development mode without ADFIR_DATA_DIR
    monkeypatch.delenv("ADFIR_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    s_dev = Settings()
    assert s_dev.DATA_DIR == s_dev.BASE_DIR / "data"
    assert s_dev.DATABASE_URL == f"sqlite:///{s_dev.BASE_DIR / 'adfir.db'}"

    # Scenario 2: Explicit ADFIR_DATA_DIR overrides everything
    custom_dir = tmp_path / "explicit_override"
    monkeypatch.setenv("ADFIR_DATA_DIR", str(custom_dir))
    s_explicit = Settings()
    assert s_explicit.DATA_DIR == custom_dir.resolve()
    assert s_explicit.DATABASE_URL == f"sqlite:///{custom_dir.resolve() / 'adfir.db'}"

    # Scenario 3: Frozen mode without ADFIR_DATA_DIR MUST use external get_user_data_dir()
    monkeypatch.delenv("ADFIR_DATA_DIR", raising=False)
    fake_meipass = tmp_path / "fake_pyinstaller_bundle"
    fake_meipass.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(fake_meipass), raising=False)
    
    # Isolate XDG_DATA_HOME so test does not pollute developer home directory
    fake_user_data = tmp_path / "user_home_data"
    monkeypatch.setenv("XDG_DATA_HOME", str(fake_user_data))

    s_frozen = Settings()
    expected_user_dir = (fake_user_data / "adfir").resolve()
    assert s_frozen.DATA_DIR == expected_user_dir
    assert s_frozen.DATABASE_URL == f"sqlite:///{expected_user_dir / 'adfir.db'}"

    # CRITICAL SECURITY ASSERTION: DATA_DIR and DATABASE_URL MUST NOT BE INSIDE _MEIPASS
    assert not str(s_frozen.DATA_DIR).startswith(str(fake_meipass))
    assert not str(s_frozen.DATABASE_URL).startswith(str(fake_meipass))

# =============================================================================
# PACKAGED RUNTIME SCENARIO A: EXPLICIT ADFIR_DATA_DIR
# =============================================================================

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_packaged_executable_scenario_a_explicit_data_dir(tmp_path):
    assert EXECUTABLE.exists(), "Build must be completed before runtime test"

    custom_data_dir = tmp_path / "packaged_explicit_data"
    custom_port = 55432
    bootstrap_secret = "packaged_explicit_bootstrap_secret_999"

    env = os.environ.copy()
    env["ADFIR_DATA_DIR"] = str(custom_data_dir)
    env["ADFIR_PORT"] = str(custom_port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret

    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    base_url = f"http://127.0.0.1:{custom_port}"
    health_url = f"{base_url}/api/v1/system/health"
    info_url = f"{base_url}/api/v1/info"
    cases_url = f"{base_url}/api/v1/cases/"
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

        assert ready, f"Packaged backend failed to start on port {custom_port}. Process poll: {proc.poll()}"

        valid_headers = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret}
        res_valid = client.get(info_url, headers=valid_headers)
        assert res_valid.status_code == 200

        # Assert data created under explicit data directory
        assert custom_data_dir.exists()
        assert (custom_data_dir / "adfir.db").exists() or (custom_data_dir / "evidence").exists()

        res_shutdown = client.post(shutdown_url, headers=valid_headers)
        assert res_shutdown.status_code == 200
        proc.wait(timeout=5.0)

    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=2.0)

# =============================================================================
# PACKAGED RUNTIME SCENARIO B: NO ADFIR_DATA_DIR (DEFAULT USER DATA DIR)
# =============================================================================

@pytest.mark.skipif(not EXECUTABLE.exists(), reason="Packaged binary dist/adfir-backend does not exist")
def test_packaged_executable_scenario_b_no_data_dir(tmp_path):
    assert EXECUTABLE.exists(), "Build must be completed before runtime test"

    isolated_user_data = tmp_path / "isolated_user_share"
    custom_port = 55433
    bootstrap_secret = "packaged_scenario_b_secret_888"

    env = os.environ.copy()
    env.pop("ADFIR_DATA_DIR", None)
    env["XDG_DATA_HOME"] = str(isolated_user_data)
    env["ADFIR_PORT"] = str(custom_port)
    env["ADFIR_INTERNAL_SECRET"] = bootstrap_secret

    proc = subprocess.Popen(
        [str(EXECUTABLE)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    base_url = f"http://127.0.0.1:{custom_port}"
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

        assert ready, f"Packaged backend failed in Scenario B on port {custom_port}."

        valid_headers = {"X-ADFIR-Bootstrap-Secret": bootstrap_secret}
        res_valid = client.get(info_url, headers=valid_headers)
        assert res_valid.status_code == 200

        # CRITICAL VALIDATION: Verify mutable data was created under isolated XDG_DATA_HOME/adfir
        target_adfir_dir = isolated_user_data / "adfir"
        assert target_adfir_dir.exists()
        assert (target_adfir_dir / "adfir.db").exists()

        # CRITICAL VALIDATION: Verify NO mutable data was created in dist/adfir-backend
        bundle_db = DIST_DIR / "adfir.db"
        assert not bundle_db.exists(), f"Mutable database {bundle_db} was illegally created inside PyInstaller bundle!"

        res_shutdown = client.post(shutdown_url, headers=valid_headers)
        assert res_shutdown.status_code == 200
        proc.wait(timeout=5.0)

    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=2.0)
