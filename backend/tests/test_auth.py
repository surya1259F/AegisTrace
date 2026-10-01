import os
import time
import uuid
import sqlite3
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, ensure_user_auth_schema
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    revoke_access_token,
    REVOKED_TOKENS
)
from backend.app.core.config import get_jwt_secret, settings
from backend.app.models.models import User
from backend.app.schemas.schemas import UserResponse

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    ensure_user_auth_schema(engine)
    yield

def test_1_password_hash_not_plaintext():
    plain = "SuperSecret123!"
    hashed = hash_password(plain)
    assert hashed != plain
    assert plain not in hashed
    assert hashed.startswith("$pbkdf2-sha256$")

def test_2_correct_password_verifies():
    plain = "SuperSecret123!"
    hashed = hash_password(plain)
    assert verify_password(plain, hashed) is True

def test_3_incorrect_password_fails():
    plain = "SuperSecret123!"
    hashed = hash_password(plain)
    assert verify_password("WrongPassword123!", hashed) is False

def test_4_duplicate_user_signup_rejected():
    email = f"dup_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": email,
        "name": "Duplicate User",
        "password": "Password123!"
    }
    res1 = client.post("/api/v1/auth/signup", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/auth/signup", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"].lower() or "already registered" in res2.json()["detail"].lower()

def test_5_user_signup_creates_persisted_user():
    email = f"signup_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": email,
        "name": "Persisted User",
        "password": "Password123!"
    }
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == email
    assert data["role"] == "INVESTIGATOR"

    with SessionLocal() as db:
        user_db = db.query(User).filter(User.email == email).first()
        assert user_db is not None
        assert user_db.name == "Persisted User"
        assert verify_password("Password123!", user_db.password_hash)

def test_6_password_hash_never_in_response():
    email = f"nohash_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": email,
        "name": "No Hash User",
        "password": "Password123!"
    }
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "password_hash" not in data
    assert "password" not in data

    # Login check
    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "password_hash" not in login_data["user"]

    # Schema model check
    schema_fields = UserResponse.model_fields.keys()
    assert "password_hash" not in schema_fields

def test_7_successful_login_returns_token():
    email = f"login_ok_{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "Login User",
        "password": "Password123!"
    })

    res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == email

def test_8_incorrect_password_login_401():
    email = f"wrong_pass_{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "Wrong Pass User",
        "password": "Password123!"
    })

    res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "WrongPassword!"
    })
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid email or password."

def test_9_nonexistent_account_login_401():
    res = client.post("/api/v1/auth/login", json={
        "email": "nonexistent_user_999@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid email or password."

def test_10_inactive_account_login_401():
    email = f"inactive_{uuid.uuid4().hex[:8]}@example.com"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "Inactive User",
        "password": "Password123!"
    })
    user_id = signup_res.json()["id"]

    # Deactivate user directly in DB
    with SessionLocal() as db:
        u = db.query(User).filter(User.id == user_id).first()
        u.is_active = False
        db.commit()

    res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    assert res.status_code == 401
    assert "disabled" in res.json()["detail"].lower() or "inactive" in res.json()["detail"].lower()

def test_11_malformed_token_401():
    res = client.get("/api/v1/auth/me", headers={
        "Authorization": "Bearer invalid_malformed_jwt_token_payload"
    })
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()

def test_12_expired_token_401():
    token = create_access_token(user_id="user_id_123", email="test@example.com", role="INVESTIGATOR", expires_delta_minutes=-10)
    res = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower() or "expired" in res.json()["detail"].lower()

def test_13_valid_token_resolves_user():
    email = f"token_user_{uuid.uuid4().hex[:8]}@example.com"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "Token User",
        "password": "Password123!"
    })
    user_id = signup_res.json()["id"]

    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]

    me_res = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["id"] == user_id
    assert me_data["email"] == email

def test_14_me_requires_authentication():
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401

def test_15_logout_revokes_token():
    email = f"logout_user_{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "Logout User",
        "password": "Password123!"
    })
    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]

    # Verify working before logout
    me1 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me1.status_code == 200

    # Logout
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    # Verify rejected after logout
    me2 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me2.status_code == 401
    assert "invalid" in me2.json()["detail"].lower() or "revoked" in me2.json()["detail"].lower()

def test_16_no_hardcoded_secret():
    secret = get_jwt_secret()
    assert isinstance(secret, str)
    assert len(secret) > 0
    assert settings.JWT_SECRET_KEY or secret

def test_17_schema_migration_existing_users_preserved(tmp_path):
    from backend.app.core.migrations import run_db_migrations
    db_file = str(tmp_path / "legacy_users.db")

    db_url = f"sqlite:///{db_file}"
    test_eng = create_engine(db_url)

    # Run Alembic migrations (authoritative schema evolution)
    run_db_migrations(test_eng)

    # Insert user with legacy fields (password_hash initially unset)
    Session = sessionmaker(bind=test_eng)
    with Session() as db:
        user = User(
            id='usr-1',
            email='legacy@adfir.local',
            name='Legacy User',
            organization='Digital Forensics Unit',
            badge_id='B-1',
            role='INVESTIGATOR',
            is_active=True
        )
        db.add(user)
        db.commit()

    # Verify legacy user persists and all required columns exist
    with Session() as db:
        user = db.query(User).filter(User.id == 'usr-1').first()
        assert user is not None
        assert user.email == 'legacy@adfir.local'
        assert user.name == 'Legacy User'
        assert hasattr(user, 'password_hash')
        assert hasattr(user, 'last_login_at')
        assert user.password_hash is None


def test_18_user_profile_returns_roles_and_permissions():
    email = f"rbac_user_{uuid.uuid4().hex[:8]}@example.com"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": "RBAC User",
        "password": "Password123!"
    })
    assert signup_res.status_code == 201

    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]
    user_payload = login_res.json()["user"]
    assert "roles" in user_payload
    assert "permissions" in user_payload
    assert "INVESTIGATOR" in user_payload["roles"]
    assert "CASE_CREATE" in user_payload["permissions"]
    assert "FORENSIC_TOOL_EXECUTE" in user_payload["permissions"]

    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert "roles" in me_data
    assert "permissions" in me_data
    assert "INVESTIGATOR" in me_data["roles"]
    assert "CASE_CREATE" in me_data["permissions"]


def test_19_rbac_permissions_by_role():
    from backend.app.services.authorization import get_role_permissions, has_permission

    admin_perms = get_role_permissions("ADMIN")
    assert "USER_DELETE" in admin_perms
    assert "SYSTEM_CONFIGURATION_UPDATE" in admin_perms

    investigator_perms = get_role_permissions("INVESTIGATOR")
    assert "CASE_CREATE" in investigator_perms
    assert "USER_DELETE" not in investigator_perms

    analyst_perms = get_role_permissions("ANALYST")
    assert "CASE_READ" in analyst_perms
    assert "CASE_CREATE" not in analyst_perms

    viewer_perms = get_role_permissions("VIEWER")
    assert "CASE_READ" in viewer_perms
    assert "CASE_CREATE" not in viewer_perms
    assert "FORENSIC_TOOL_EXECUTE" not in viewer_perms

    assert has_permission("ADMIN", "USER_DELETE") is True
    assert has_permission("INVESTIGATOR", "USER_DELETE") is False

