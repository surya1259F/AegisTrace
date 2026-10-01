import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app, get_allowed_origins
from backend.app.core.config import Settings, get_backend_port, validate_port

client = TestClient(app)

# =============================================================================
# 1. DATA PATH TESTS (1-5)
# =============================================================================

def test_default_development_path_works(monkeypatch):
    monkeypatch.delenv("ADFIR_DATA_DIR", raising=False)
    s = Settings()
    assert s.DATA_DIR == s.BASE_DIR / "data"
    assert s.EVIDENCE_DIR == s.BASE_DIR / "data" / "evidence"
    assert s.CASES_DIR == s.BASE_DIR / "data" / "cases"
    assert s.REPORTS_DIR == s.BASE_DIR / "data" / "reports"
    assert s.LOGS_DIR == s.BASE_DIR / "data" / "logs"

def test_adfir_data_dir_overrides_data_root(tmp_path, monkeypatch):
    custom_dir = tmp_path / "custom_dfir_workspace"
    monkeypatch.setenv("ADFIR_DATA_DIR", str(custom_dir))
    s = Settings()
    assert s.DATA_DIR == custom_dir.resolve()
    assert s.DATA_DIR.exists()

def test_database_resolves_under_data_root(tmp_path, monkeypatch):
    custom_dir = tmp_path / "custom_data_db"
    monkeypatch.setenv("ADFIR_DATA_DIR", str(custom_dir))
    s = Settings()
    assert s.DATABASE_URL == f"sqlite:///{custom_dir.resolve() / 'adfir.db'}"

def test_evidence_path_resolves_under_data_root(tmp_path, monkeypatch):
    custom_dir = tmp_path / "custom_evidence_workspace"
    monkeypatch.setenv("ADFIR_DATA_DIR", str(custom_dir))
    s = Settings()
    assert s.EVIDENCE_DIR == (custom_dir / "evidence").resolve()
    assert s.EVIDENCE_DIR.exists()

def test_reports_path_resolves_under_data_root(tmp_path, monkeypatch):
    custom_dir = tmp_path / "custom_reports_workspace"
    monkeypatch.setenv("ADFIR_DATA_DIR", str(custom_dir))
    s = Settings()
    assert s.REPORTS_DIR == (custom_dir / "reports").resolve()
    assert s.REPORTS_DIR.exists()

# =============================================================================
# 2. PORT TESTS (6-10)
# =============================================================================

def test_default_port_behavior(monkeypatch):
    monkeypatch.delenv("ADFIR_PORT", raising=False)
    assert get_backend_port() == 8000

def test_valid_adfir_port(monkeypatch):
    monkeypatch.setenv("ADFIR_PORT", "54219")
    assert get_backend_port() == 54219

def test_invalid_non_numeric_port(monkeypatch):
    monkeypatch.setenv("ADFIR_PORT", "not_a_number")
    with pytest.raises(ValueError, match="must be an integer"):
        get_backend_port()

def test_invalid_out_of_range_port(monkeypatch):
    monkeypatch.setenv("ADFIR_PORT", "70000")
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        get_backend_port()
    
    monkeypatch.setenv("ADFIR_PORT", "-5")
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        get_backend_port()

def test_host_remains_127001():
    # Verify main script binds strictly to 127.0.0.1 loopback
    import inspect
    import backend.app.main as main_mod
    src = inspect.getsource(main_mod)
    assert 'host="127.0.0.1"' in src
    assert 'host="0.0.0.0"' not in src

# =============================================================================
# 3. BOOTSTRAP SECRET TESTS (11-16)
# =============================================================================

def test_desktop_mode_without_bootstrap_header_returns_403(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "super_secret_test_token_123")
    res = client.get("/api/v1/cases")
    assert res.status_code == 403
    assert "Invalid or missing desktop bootstrap secret" in res.json()["detail"]

def test_desktop_mode_with_wrong_secret_returns_403(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "super_secret_test_token_123")
    headers = {"X-ADFIR-Bootstrap-Secret": "wrong_secret_token"}
    res = client.get("/api/v1/cases", headers=headers)
    assert res.status_code == 403
    assert "Invalid or missing desktop bootstrap secret" in res.json()["detail"]

def test_desktop_mode_with_correct_secret_passes_bootstrap_layer(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "super_secret_test_token_123")
    headers = {"X-ADFIR-Bootstrap-Secret": "super_secret_test_token_123"}
    # Hits health endpoint or system info with correct bootstrap secret
    res = client.get("/api/v1/info", headers=headers)
    assert res.status_code == 200

def test_comparison_does_not_expose_secret(monkeypatch):
    secret = "sensitive_desktop_bootstrap_secret_999"
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", secret)
    headers = {"X-ADFIR-Bootstrap-Secret": "bad_guess"}
    res = client.get("/api/v1/cases", headers=headers)
    assert res.status_code == 403
    assert secret not in res.text
    assert "bad_guess" not in res.text

def test_secret_is_not_logged(monkeypatch, caplog):
    secret = "secret_to_never_log_456"
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", secret)
    headers = {"X-ADFIR-Bootstrap-Secret": "invalid_attempt"}
    client.get("/api/v1/cases", headers=headers)
    for record in caplog.records:
        assert secret not in record.getMessage()

def test_development_mode_without_secret_preserves_existing_behavior(monkeypatch):
    monkeypatch.delenv("ADFIR_INTERNAL_SECRET", raising=False)
    # Health and system info work without bootstrap header in dev mode
    res = client.get("/api/v1/info")
    assert res.status_code == 200

# =============================================================================
# 4. JWT & BOOTSTRAP SEPARATION TESTS (17-19)
# =============================================================================

def test_valid_bootstrap_secret_plus_missing_jwt_fails_401(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "valid_bootstrap_secret")
    headers = {"X-ADFIR-Bootstrap-Secret": "valid_bootstrap_secret"}
    # Temporarily remove auto-authentication override to verify raw JWT check
    from backend.app.core.security import get_current_user, get_current_active_user
    old_user = app.dependency_overrides.pop(get_current_user, None)
    old_active = app.dependency_overrides.pop(get_current_active_user, None)
    try:
        res = client.get("/api/v1/cases", headers=headers)
        assert res.status_code == 401
    finally:
        if old_user:
            app.dependency_overrides[get_current_user] = old_user
        if old_active:
            app.dependency_overrides[get_current_active_user] = old_active

def test_valid_jwt_plus_missing_bootstrap_secret_fails_403(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "valid_bootstrap_secret")
    # Provide Authorization header but omit X-ADFIR-Bootstrap-Secret
    headers = {"Authorization": "Bearer fake_user_jwt"}
    res = client.get("/api/v1/cases", headers=headers)
    assert res.status_code == 403

def test_bootstrap_secret_cannot_impersonate_user(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "valid_bootstrap_secret")
    headers = {"X-ADFIR-Bootstrap-Secret": "valid_bootstrap_secret"}
    from backend.app.core.security import get_current_user, get_current_active_user
    old_user = app.dependency_overrides.pop(get_current_user, None)
    old_active = app.dependency_overrides.pop(get_current_active_user, None)
    try:
        res = client.get("/api/v1/cases", headers=headers)
        assert res.status_code == 401
        assert "Authentication credentials were not provided" in res.json()["detail"]
    finally:
        if old_user:
            app.dependency_overrides[get_current_user] = old_user
        if old_active:
            app.dependency_overrides[get_current_active_user] = old_active

# =============================================================================
# 5. SHUTDOWN ENDPOINT TESTS (20-24)
# =============================================================================

def test_shutdown_requires_bootstrap_secret(monkeypatch):
    monkeypatch.delenv("ADFIR_INTERNAL_SECRET", raising=False)
    # In dev mode without secret, shutdown is 400 Bad Request
    res = client.post("/api/v1/system/shutdown")
    assert res.status_code == 400

    # In desktop mode without header, shutdown is 403 Forbidden
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "test_shutdown_secret")
    res = client.post("/api/v1/system/shutdown")
    assert res.status_code == 403

def test_jwt_alone_cannot_shutdown(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "test_shutdown_secret")
    headers = {"Authorization": "Bearer fake_user_jwt"}
    res = client.post("/api/v1/system/shutdown", headers=headers)
    assert res.status_code == 403

def test_arbitrary_pid_cannot_be_supplied(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "test_shutdown_secret")
    headers = {"X-ADFIR-Bootstrap-Secret": "test_shutdown_secret"}
    # Post body with arbitrary PID must be ignored (endpoint takes no client PID parameter)
    res = client.post("/api/v1/system/shutdown", json={"pid": 12345}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SHUTTING_DOWN"
    assert data["pid"] == os.getpid()

def test_shutdown_mechanism_targets_current_backend_application(monkeypatch):
    monkeypatch.setenv("ADFIR_INTERNAL_SECRET", "test_shutdown_secret")
    headers = {"X-ADFIR-Bootstrap-Secret": "test_shutdown_secret"}
    res = client.post("/api/v1/system/shutdown", headers=headers)
    assert res.status_code == 200
    assert res.json()["pid"] == os.getpid()

def test_shutdown_does_not_execute_shell_commands():
    import inspect
    import backend.app.api.v1.endpoints.system as sys_mod
    src = inspect.getsource(sys_mod.shutdown_backend)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "shell" not in src
    assert "os.kill" in src

# =============================================================================
# 6. CORS TESTS (25-27)
# =============================================================================

def test_wildcard_credentials_configuration_is_removed():
    import inspect
    import backend.app.main as main_mod
    src = inspect.getsource(main_mod)
    assert 'allow_origins=["*"]' not in src

def test_required_development_origin_works():
    origins = get_allowed_origins()
    assert "http://localhost:5173" in origins
    assert "http://127.0.0.1:5173" in origins
    assert "tauri://localhost" in origins

def test_unauthorized_arbitrary_origin_not_granted_credentialed_access():
    res = client.options("/api/v1/info", headers={
        "Origin": "https://malicious-attacker.com",
        "Access-Control-Request-Method": "GET"
    })
    # CORSMiddleware should not reflect malicious origin
    assert res.headers.get("access-control-allow-origin") != "https://malicious-attacker.com"
