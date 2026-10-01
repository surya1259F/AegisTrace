import os
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.core.database import Base, engine, SessionLocal, ensure_user_auth_schema
from backend.app.core.security import create_access_token, hash_password
from backend.app.models.models import User, AuditEvent

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    settings.JWT_SECRET_KEY = "adfir-test-jwt-secret-key-production-hardening-32bytes"
    Base.metadata.create_all(bind=engine)
    ensure_user_auth_schema(engine)
    yield

def get_auth_headers(token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    secret = os.getenv("ADFIR_INTERNAL_SECRET") or settings.ADFIR_INTERNAL_SECRET
    if secret and secret.strip():
        headers["X-ADFIR-Bootstrap-Secret"] = secret.strip()
    return headers

def helper_create_user(email, name, role="INVESTIGATOR", org="Digital Forensics Unit", is_active=True, badge_id="B123"):
    with SessionLocal() as db:
        user = User(
            id=f"usr-{uuid.uuid4().hex[:8]}",
            email=email.lower().strip(),
            name=name,
            organization=org,
            badge_id=badge_id,
            role=role,
            is_active=is_active,
            password_hash=hash_password("Password123!"),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        token = create_access_token(user_id=user.id, email=user.email, role=user.role)
        return user.id, token, user.email

def test_admin_can_list_all_users():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_{uuid.uuid4().hex[:6]}@adfir.local", "System Admin", role="ADMIN", org="HQ Org"
    )
    user2_id, _, _ = helper_create_user(
        f"inv1_{uuid.uuid4().hex[:6]}@adfir.local", "Inv One", role="INVESTIGATOR", org="HQ Org"
    )
    user3_id, _, _ = helper_create_user(
        f"inv2_{uuid.uuid4().hex[:6]}@adfir.local", "Inv Two", role="INVESTIGATOR", org="Other Org"
    )

    res = client.get(
        "/api/v1/users/",
        headers=get_auth_headers(admin_token)
    )
    assert res.status_code == 200
    users = res.json()
    listed_ids = [u["id"] for u in users]
    assert admin_id in listed_ids
    assert user2_id in listed_ids
    assert user3_id in listed_ids

def test_non_admin_listing_scoped_to_organization():
    inv1_id, inv1_token, _ = helper_create_user(
        f"inv_scope1_{uuid.uuid4().hex[:6]}@adfir.local", "Org 1 Inv", role="INVESTIGATOR", org="Org One"
    )
    inv2_id, _, _ = helper_create_user(
        f"inv_scope2_{uuid.uuid4().hex[:6]}@adfir.local", "Org 1 Peer", role="INVESTIGATOR", org="Org One"
    )
    other_org_id, _, _ = helper_create_user(
        f"inv_other_{uuid.uuid4().hex[:6]}@adfir.local", "Org 2 Inv", role="INVESTIGATOR", org="Org Two"
    )

    res = client.get(
        "/api/v1/users/",
        headers=get_auth_headers(inv1_token)
    )
    assert res.status_code == 200
    users = res.json()
    listed_ids = [u["id"] for u in users]
    assert inv1_id in listed_ids
    assert inv2_id in listed_ids
    assert other_org_id not in listed_ids

def test_admin_create_user_success():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_create_{uuid.uuid4().hex[:6]}@adfir.local", "Admin User", role="ADMIN"
    )
    new_email = f"new_created_{uuid.uuid4().hex[:6]}@adfir.local"

    res = client.post(
        "/api/v1/users/",
        json={
            "email": new_email,
            "password": "Password123!",
            "name": "Newly Created Analyst",
            "organization": "Cyber Crimes Unit",
            "role": "ANALYST",
            "badge_id": "CCU-99",
        },
        headers=get_auth_headers(admin_token)
    )
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == new_email
    assert data["role"] == "ANALYST"
    assert data["organization"] == "Cyber Crimes Unit"

    # Audit log verification
    with SessionLocal() as db:
        log = db.query(AuditEvent).filter(
            AuditEvent.event_type == "USER_CREATED",
            AuditEvent.details.like(f"%{new_email}%")
        ).first()
        assert log is not None
        assert new_email in log.details

def test_non_admin_create_user_prohibited():
    inv_id, inv_token, _ = helper_create_user(
        f"inv_nocreate_{uuid.uuid4().hex[:6]}@adfir.local", "Inv User", role="INVESTIGATOR"
    )

    res = client.post(
        "/api/v1/users/",
        json={
            "email": f"fail_create_{uuid.uuid4().hex[:6]}@adfir.local",
            "password": "Password123!",
            "name": "Failed User",
            "role": "ANALYST",
        },
        headers=get_auth_headers(inv_token)
    )
    assert res.status_code == 403

def test_org_admin_create_user_scoped_to_own_organization():
    org_admin_id, org_admin_token, _ = helper_create_user(
        f"org_admin_{uuid.uuid4().hex[:6]}@adfir.local", "Org Admin", role="ORG_ADMIN", org="Unit Alpha"
    )
    new_email = f"unit_member_{uuid.uuid4().hex[:6]}@adfir.local"

    res = client.post(
        "/api/v1/users/",
        json={
            "email": new_email,
            "password": "Password123!",
            "name": "Unit Member",
            "organization": "Unit Beta",  # Requesting different org
            "role": "INVESTIGATOR",
        },
        headers=get_auth_headers(org_admin_token)
    )
    assert res.status_code == 201
    data = res.json()
    # Scoped to ORG_ADMIN's organization automatically
    assert data["organization"] == "Unit Alpha"

def test_cross_org_user_get_idor_prevention():
    inv1_id, inv1_token, _ = helper_create_user(
        f"inv_idor1_{uuid.uuid4().hex[:6]}@adfir.local", "Inv Org 1", role="INVESTIGATOR", org="Org Alpha"
    )
    inv2_id, _, _ = helper_create_user(
        f"inv_idor2_{uuid.uuid4().hex[:6]}@adfir.local", "Inv Org 2", role="INVESTIGATOR", org="Org Beta"
    )

    # Inv1 attempting to fetch details of Inv2 from another organization
    res = client.get(
        f"/api/v1/users/{inv2_id}",
        headers=get_auth_headers(inv1_token)
    )
    assert res.status_code == 403

def test_prevent_self_role_modification():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_selfrole_{uuid.uuid4().hex[:6]}@adfir.local", "Self Admin", role="ADMIN"
    )

    # Admin attempting to demote self
    res = client.patch(
        f"/api/v1/users/{admin_id}",
        json={"role": "INVESTIGATOR"},
        headers=get_auth_headers(admin_token)
    )
    assert res.status_code == 400
    assert "cannot alter their own global application role" in res.json()["detail"].lower() or "prohibited" in res.json()["detail"].lower()

def test_prevent_self_disabling():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_selfdis_{uuid.uuid4().hex[:6]}@adfir.local", "Self Disable Admin", role="ADMIN"
    )

    res = client.post(
        f"/api/v1/users/{admin_id}/disable",
        headers=get_auth_headers(admin_token)
    )
    assert res.status_code == 400
    assert "cannot disable your own account" in res.json()["detail"].lower() or "prohibited" in res.json()["detail"].lower()

def test_enable_and_disable_user_workflow():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_toggle_{uuid.uuid4().hex[:6]}@adfir.local", "Toggle Admin", role="ADMIN"
    )
    target_id, target_token, target_email = helper_create_user(
        f"target_toggle_{uuid.uuid4().hex[:6]}@adfir.local", "Target Inv", role="INVESTIGATOR"
    )

    # Disable target user
    res_dis = client.post(
        f"/api/v1/users/{target_id}/disable",
        headers=get_auth_headers(admin_token)
    )
    assert res_dis.status_code == 200
    assert res_dis.json()["is_active"] is False

    # Disabled user login attempt fails
    login_fail = client.post("/api/v1/auth/login", json={"email": target_email, "password": "Password123!"})
    assert login_fail.status_code == 401
    assert "disabled" in login_fail.json()["detail"].lower()

    # Enable target user
    res_en = client.post(
        f"/api/v1/users/{target_id}/enable",
        headers=get_auth_headers(admin_token)
    )
    assert res_en.status_code == 200
    assert res_en.json()["is_active"] is True

    # Login succeeds now
    login_ok = client.post("/api/v1/auth/login", json={"email": target_email, "password": "Password123!"})
    assert login_ok.status_code == 200

def test_soft_deactivate_user_preserves_db_record():
    admin_id, admin_token, _ = helper_create_user(
        f"admin_deact_{uuid.uuid4().hex[:6]}@adfir.local", "Deact Admin", role="ADMIN"
    )
    target_id, _, _ = helper_create_user(
        f"target_deact_{uuid.uuid4().hex[:6]}@adfir.local", "Deact Target", role="INVESTIGATOR"
    )

    res_del = client.delete(
        f"/api/v1/users/{target_id}",
        headers=get_auth_headers(admin_token)
    )
    assert res_del.status_code == 200

    # User DB record must still exist (is_active=False) for audit / forensic history
    with SessionLocal() as db:
        user = db.query(User).filter(User.id == target_id).first()
        assert user is not None
        assert user.is_active is False

def test_user_self_profile_update():
    user_id, token, _ = helper_create_user(
        f"self_prof_{uuid.uuid4().hex[:6]}@adfir.local", "Original Name", role="INVESTIGATOR", badge_id="OLD-1"
    )

    res = client.patch(
        "/api/v1/auth/me",
        json={"name": "Updated Self Name", "badge_id": "NEW-77"},
        headers=get_auth_headers(token)
    )
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "Updated Self Name"
    assert data["badge_id"] == "NEW-77"
    assert data["role"] == "INVESTIGATOR"  # Role remains unchanged
