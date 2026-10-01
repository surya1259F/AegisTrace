import os
import uuid
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.core.database import Base, engine, SessionLocal, ensure_case_auth_schema, ensure_user_auth_schema
from backend.app.models.models import User, Case, CaseMember, AuditEvent
from backend.app.services.workspace import validate_case_id

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    settings.JWT_SECRET_KEY = "adfir-test-jwt-secret-key-production-hardening-32bytes"
    Base.metadata.create_all(bind=engine)
    ensure_user_auth_schema(engine)
    ensure_case_auth_schema(engine)
    with SessionLocal() as db:
        db.query(CaseMember).delete()
        db.query(Case).delete()
        db.query(User).delete()
        db.commit()
    yield


def create_test_user(email_prefix: str, name: str = "Test User", role: str = "INVESTIGATOR"):
    email = f"{email_prefix}_{uuid.uuid4().hex[:8]}@adfir.local"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": name,
        "password": "Password123!"
    })
    user_data = signup_res.json()

    if role != "INVESTIGATOR":
        with SessionLocal() as db:
            u = db.query(User).filter(User.id == user_data["id"]).first()
            if u:
                u.role = role
                db.commit()

    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return user_data["id"], email, headers


def test_create_case_full_workflow(tmp_path, monkeypatch):
    monkeypatch.setenv("ADFIR_DATA_DIR", str(tmp_path))
    
    user_id, email, headers = create_test_user("inv_lead", "Lead Investigator", role="INVESTIGATOR")

    # Create case
    case_payload = {
        "title": "Operation Apex Cyber Intrusion",
        "case_number": "CASE-2026-APEX",
        "description": "APT intrusion investigation into domain controller",
        "objective": "Determine initial access vector, scope lateral movement, and isolate compromised hosts",
        "case_type": "INCIDENT_RESPONSE",
        "priority": "HIGH",
        "case_permissions": {
            "view_case": True,
            "add_evidence": True,
            "run_investigation": True,
            "export_report": True
        }
    }
    
    resp = client.post("/api/v1/cases/", json=case_payload, headers=headers)
    assert resp.status_code in (200, 201)
    data = resp.json()

    assert data["case_number"] == "CASE-2026-APEX"
    assert data["title"] == "Operation Apex Cyber Intrusion"
    assert data["objective"] == case_payload["objective"]
    assert data["case_type"] == "INCIDENT_RESPONSE"
    assert data["priority"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["workspace_state"] == "READY"
    assert data["owner_id"] == user_id
    assert data["created_by"] == email
    
    # Workspace verification on disk
    ws_path = Path(data["workspace_path"])
    assert ws_path.exists()
    assert (ws_path / "case_metadata.json").exists()
    for subdir in ["evidence", "forensic_outputs", "analysis", "findings", "reports", "logs", "tmp"]:
        assert (ws_path / subdir).is_dir()

    # Workspace status endpoint check
    ws_status_resp = client.get(f"/api/v1/cases/{data['id']}/workspace/status", headers=headers)
    assert ws_status_resp.status_code == 200
    ws_status = ws_status_resp.json()
    assert ws_status["is_ready"] is True
    assert ws_status["metadata_present"] is True


def test_case_path_traversal_protection():
    with pytest.raises(Exception):
        validate_case_id("../sys/kernel")
        
    with pytest.raises(Exception):
        validate_case_id("case_id/../../etc/passwd")

    with pytest.raises(Exception):
        validate_case_id("case\0id")


def test_case_member_management_and_owner_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("ADFIR_DATA_DIR", str(tmp_path))
    
    owner_id, owner_email, headers1 = create_test_user("case_owner", "Case Owner", role="INVESTIGATOR")
    user2_id, user2_email, headers2 = create_test_user("analyst_john", "John Analyst", role="ANALYST")

    # Create case
    case_data = client.post("/api/v1/cases/", json={"title": "Member Admin Test Case"}, headers=headers1).json()
    case_id = case_data["id"]

    # Add member
    add_resp = client.post(f"/api/v1/cases/{case_id}/members", json={
        "user_id": user2_id,
        "role": "ANALYST"
    }, headers=headers1)
    assert add_resp.status_code == 201
    assert add_resp.json()["email"] == user2_email
    assert add_resp.json()["role"] == "ANALYST"

    # List members
    members_resp = client.get(f"/api/v1/cases/{case_id}/members", headers=headers1)
    assert members_resp.status_code == 200
    members_list = members_resp.json()
    assert len(members_list) == 2

    # Update member role
    patch_resp = client.patch(f"/api/v1/cases/{case_id}/members/{user2_id}", json={"role": "CASE_ADMIN"}, headers=headers1)
    assert patch_resp.status_code == 200
    assert patch_resp.json()["role"] == "CASE_ADMIN"

    # Try to delete owner (MUST BE BLOCKED)
    del_owner_resp = client.delete(f"/api/v1/cases/{case_id}/members/{owner_id}", headers=headers1)
    assert del_owner_resp.status_code == 400
    assert "Cannot remove the owner" in del_owner_resp.json()["detail"]

    # Remove member user2
    del_resp = client.delete(f"/api/v1/cases/{case_id}/members/{user2_id}", headers=headers1)
    assert del_resp.status_code == 200

    # Verify members count is back to 1
    members_resp2 = client.get(f"/api/v1/cases/{case_id}/members", headers=headers1)
    assert len(members_resp2.json()) == 1


def test_case_legal_status_transitions(tmp_path, monkeypatch):
    monkeypatch.setenv("ADFIR_DATA_DIR", str(tmp_path))

    mgr_id, mgr_email, headers = create_test_user("status_mgr", "Status Manager", role="INVESTIGATOR")

    case_data = client.post("/api/v1/cases/", json={"title": "Status Transition Case"}, headers=headers).json()
    case_id = case_data["id"]

    # Direct PATCH to CLOSED without passing closure checks must be rejected
    patch_close = client.patch(f"/api/v1/cases/{case_id}", json={"status": "CLOSED"}, headers=headers)
    assert patch_close.status_code == 422
    assert "official final forensic report has not been generated" in patch_close.json()["detail"].lower()

    # Invalid status transition
    patch_invalid = client.patch(f"/api/v1/cases/{case_id}", json={"status": "INVALID_STATE"}, headers=headers)
    assert patch_invalid.status_code == 400


def test_case_authorization_idor_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("ADFIR_DATA_DIR", str(tmp_path))

    # User 1
    u1_id, u1_email, headers1 = create_test_user("user1", "User One", role="INVESTIGATOR")

    # User 2
    u2_id, u2_email, headers2 = create_test_user("user2", "User Two", role="INVESTIGATOR")

    # User 1 creates case
    case1 = client.post("/api/v1/cases/", json={"title": "User 1 Secret Case"}, headers=headers1).json()

    # User 2 attempts to get User 1's case (IDOR attempt)
    get_resp = client.get(f"/api/v1/cases/{case1['id']}", headers=headers2)
    assert get_resp.status_code == 403

    # User 2 attempts to modify User 1's case permissions
    patch_resp = client.patch(f"/api/v1/cases/{case1['id']}/permissions", json={"permissions": {"view_case": False}}, headers=headers2)
    assert patch_resp.status_code == 403
