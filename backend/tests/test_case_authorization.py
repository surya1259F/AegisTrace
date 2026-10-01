import os
import uuid
import pytest
import sqlite3
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, ensure_user_auth_schema, ensure_case_auth_schema
from backend.app.core.security import create_access_token
from backend.app.models.models import User, Case, CaseMember, EvidenceItem, Finding, Report, ToolExecution, AuditEvent
from backend.app.services.authorization import ensure_case_member

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    ensure_user_auth_schema(engine)
    ensure_case_auth_schema(engine)
    yield

def create_test_user(email_prefix: str, name: str = "Test User"):
    email = f"{email_prefix}_{uuid.uuid4().hex[:8]}@adfir.local"
    signup_res = client.post("/api/v1/auth/signup", json={
        "email": email,
        "name": name,
        "password": "Password123!"
    })
    user_data = signup_res.json()

    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return user_data["id"], email, headers

# -----------------------------------------------------------------------------
# Tests 1-5: Authentication & Case Authorization Semantics
# -----------------------------------------------------------------------------

def test_1_unauthenticated_case_access_returns_401():
    # Unauthenticated GET /api/cases/
    res1 = client.get("/api/cases/")
    assert res1.status_code == 401

    # Unauthenticated POST /api/cases/
    res2 = client.post("/api/cases/", json={"name": "Unauth Case"})
    assert res2.status_code == 401

    # Unauthenticated GET /api/cases/some-uuid
    res3 = client.get(f"/api/cases/{uuid.uuid4()}")
    assert res3.status_code == 401

def test_2_authenticated_owner_allowed():
    user_id, email, headers = create_test_user("owner_user", "Owner User")
    case_res = client.post("/api/cases/", json={"name": "Owner Case"}, headers=headers)
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # Owner can get case details
    get_res = client.get(f"/api/cases/{case_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == case_id

def test_3_authenticated_active_member_allowed():
    owner_id, owner_email, owner_headers = create_test_user("owner3", "Owner Three")
    member_id, member_email, member_headers = create_test_user("member3", "Member Three")

    case_res = client.post("/api/cases/", json={"name": "Shared Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    # Owner adds member
    add_res = client.post(f"/api/cases/{case_id}/members", json={"user_id": member_id, "role": "COLLABORATOR"}, headers=owner_headers)
    assert add_res.status_code == 201

    # Active member can get case details
    get_res = client.get(f"/api/cases/{case_id}", headers=member_headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == case_id

def test_4_authenticated_non_member_gets_403():
    owner_id, owner_email, owner_headers = create_test_user("owner4", "Owner Four")
    other_id, other_email, other_headers = create_test_user("other4", "Other User")

    case_res = client.post("/api/cases/", json={"name": "Private Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    # Non-member attempts to access owner's case -> 403 Forbidden
    get_res = client.get(f"/api/cases/{case_id}", headers=other_headers)
    assert get_res.status_code == 403
    assert "not authorized" in get_res.json()["detail"].lower()

def test_5_inactive_user_gets_401():
    user_id, email, headers = create_test_user("inactive5", "Inactive Five")
    token = headers["Authorization"].split()[1]

    # Deactivate user in DB
    with SessionLocal() as db:
        u = db.query(User).filter(User.id == user_id).first()
        u.is_active = False
        db.commit()

    res = client.get("/api/cases/", headers=headers)
    assert res.status_code == 401

# -----------------------------------------------------------------------------
# Tests 6-10: Provenance & Identity Binding
# -----------------------------------------------------------------------------

def test_6_case_creation_requires_auth_and_binds_creator():
    res = client.post("/api/cases/", json={"name": "Auth Case"})
    assert res.status_code == 401

    user_id, email, headers = create_test_user("creator6", "Creator Six")
    res_auth = client.post("/api/cases/", json={"name": "Auth Case"}, headers=headers)
    assert res_auth.status_code == 201
    c_data = res_auth.json()

    with SessionLocal() as db:
        c_db = db.query(Case).filter(Case.id == c_data["id"]).first()
        assert c_db.owner_id == user_id
        assert c_db.created_by == email

def test_7_forged_created_by_cannot_change_ownership():
    user_id, email, headers = create_test_user("real_user7", "Real User")
    forged_target = f"forged_user_{uuid.uuid4().hex[:6]}"

    res = client.post("/api/cases/", json={
        "name": "Forged Case",
        "created_by": forged_target,
        "investigator": forged_target
    }, headers=headers)
    assert res.status_code == 201
    c_data = res.json()

    with SessionLocal() as db:
        c_db = db.query(Case).filter(Case.id == c_data["id"]).first()
        assert c_db.owner_id == user_id
        assert c_db.created_by == email
        assert c_db.created_by != forged_target

def test_8_investigator_name_cannot_impersonate():
    user_id, email, headers = create_test_user("dec_user8", "Alice Investigator")

    case_res = client.post("/api/cases/", json={"name": "Decision Case"}, headers=headers)
    case_id = case_res.json()["id"]

    # Attempt to post decision claiming to be "Bob Investigator"
    dec_res = client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "Verified evidence analysis.",
        "investigator_name": "Bob Investigator"
    }, headers=headers)
    assert dec_res.status_code == 201

    with SessionLocal() as db:
        dec_db = db.query(AuditEvent).filter(AuditEvent.case_id == case_id, AuditEvent.event_type == "DECISION_RECORDED").first()
        assert dec_db is not None
        assert dec_db.actor_id == user_id
        assert dec_db.actor_name == "Alice Investigator"

def test_9_audit_actor_derives_from_authenticated_user():
    user_id, email, headers = create_test_user("audit9", "Audit User")
    case_res = client.post("/api/cases/", json={"name": "Audit Case"}, headers=headers)
    case_id = case_res.json()["id"]

    with SessionLocal() as db:
        event = db.query(AuditEvent).filter(AuditEvent.case_id == case_id, AuditEvent.event_type == "CASE_CREATED").first()
        assert event is not None
        assert event.actor_id == user_id
        assert event.actor_name == "Audit User"

def test_10_arbitrary_uuid_cannot_bypass_authorization():
    u1_id, u1_email, u1_headers = create_test_user("user10_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user10_b", "User B")

    c1 = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B passes Case A's exact UUID -> 403 Forbidden
    res = client.get(f"/api/cases/{c1}", headers=u2_headers)
    assert res.status_code == 403

# -----------------------------------------------------------------------------
# Tests 11-16: IDOR Protection Across Indirect Resources
# -----------------------------------------------------------------------------

def test_11_indirect_evidence_idor_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user11_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user11_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]
    c2_id = client.post("/api/cases/", json={"name": "Case B"}, headers=u2_headers).json()["id"]

    # Create dummy evidence under Case A
    with SessionLocal() as db:
        ev = EvidenceItem(
            id=str(uuid.uuid4()),
            case_id=c1_id,
            name="dump.dmp",
            original_path="/tmp/dump.dmp",
            storage_path="/tmp/dump.dmp",
            evidence_type="memory_dump",
            size_bytes=100.0,
            sha256="abc",
            integrity_status="VERIFIED"
        )
        db.add(ev)
        db.commit()
        ev_id = ev.id

    # User B tries to run analysis on Case B using User A's evidence_id -> 404/400 (not found in Case B)
    res = client.post(f"/api/cases/{c2_id}/analysis/memory", json={
        "evidence_id": ev_id,
        "plugin": "windows.info"
    }, headers=u2_headers)
    assert res.status_code in (400, 404)

def test_12_indirect_finding_idor_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user12_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user12_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B attempts to fetch findings for Case A -> 403
    res_get = client.get(f"/api/v1/investigation/findings/{c1_id}", headers=u2_headers)
    assert res_get.status_code == 403

    # User B attempts to post finding to Case A -> 403
    res_post = client.post("/api/v1/investigation/findings", json={
        "case_id": c1_id,
        "title": "Forged Finding",
        "agent": "TestAgent",
        "tool": "TestTool"
    }, headers=u2_headers)
    assert res_post.status_code == 403

def test_13_indirect_report_idor_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user13_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user13_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B attempts to fetch report for Case A -> 403
    res = client.get(f"/api/v1/reports/case/{c1_id}", headers=u2_headers)
    assert res.status_code == 403

def test_14_indirect_execution_idor_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user14_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user14_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B attempts to list executions for Case A -> 403
    res = client.get(f"/api/cases/{c1_id}/executions", headers=u2_headers)
    assert res.status_code == 403

def test_15_indirect_plantask_idor_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user15_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user15_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B attempts to execute plan for Case A -> 403
    res = client.post(f"/api/cases/{c1_id}/plan/execute", headers=u2_headers)
    assert res.status_code == 403

def test_16_unauthorized_case_mutation_blocked():
    u1_id, u1_email, u1_headers = create_test_user("user16_a", "User A")
    u2_id, u2_email, u2_headers = create_test_user("user16_b", "User B")

    c1_id = client.post("/api/cases/", json={"name": "Case A"}, headers=u1_headers).json()["id"]

    # User B attempts PATCH -> 403
    res1 = client.patch(f"/api/cases/{c1_id}", json={"name": "Hacked Name"}, headers=u2_headers)
    assert res1.status_code == 403

    # User B attempts close -> 403
    res2 = client.post(f"/api/cases/{c1_id}/close", headers=u2_headers)
    assert res2.status_code == 403

    # User B attempts archive -> 403
    res3 = client.post(f"/api/cases/{c1_id}/archive", headers=u2_headers)
    assert res3.status_code == 403

def test_17_authorized_mutation_works():
    u1_id, u1_email, u1_headers = create_test_user("user17_a", "User A")
    c1_id = client.post("/api/cases/", json={"name": "Original Name"}, headers=u1_headers).json()["id"]

    patch_res = client.patch(f"/api/cases/{c1_id}", json={"name": "Updated Name"}, headers=u1_headers)
    assert patch_res.status_code == 200
    assert patch_res.json()["title"] == "Updated Name"

def test_18_nonexistent_case_returns_404():
    u1_id, u1_email, u1_headers = create_test_user("user18", "User 18")
    fake_id = str(uuid.uuid4())

    res = client.get(f"/api/cases/{fake_id}", headers=u1_headers)
    assert res.status_code == 404

def test_19_legacy_unowned_case_policy_enforcement():
    u1_id, u1_email, u1_headers = create_test_user("legacy_user", "Legacy Test User")
    legacy_id = str(uuid.uuid4())

    # Create legacy unowned case in DB
    with SessionLocal() as db:
        leg_case = Case(
            id=legacy_id,
            case_number=f"CASE-LEGACY-{uuid.uuid4().hex[:6].upper()}",
            name="Legacy Unowned Case",
            created_by="local-investigator",
            owner_id=None,
            status="OPEN"
        )
        db.add(leg_case)
        db.commit()

    # User without explicit membership gets 403 Forbidden
    res_unauth = client.get(f"/api/cases/{legacy_id}", headers=u1_headers)
    assert res_unauth.status_code == 403

    # Adding explicit membership allows access
    with SessionLocal() as db:
        ensure_case_member(case_id=legacy_id, user_id=u1_id, db=db, role="COLLABORATOR")

    res_auth = client.get(f"/api/cases/{legacy_id}", headers=u1_headers)
    assert res_auth.status_code == 200
    assert res_auth.json()["id"] == legacy_id


# -----------------------------------------------------------------------------
# Phase 5 Hardened Authorization & Security Semantics Tests (Tests 20-28)
# -----------------------------------------------------------------------------

def test_20_owner_and_case_admin_can_add_member():
    owner_id, owner_email, owner_headers = create_test_user("owner20", "Owner Twenty")
    u2_id, u2_email, u2_headers = create_test_user("user20_b", "User Twenty B")

    case_res = client.post("/api/cases/", json={"name": "Member Admin Case"}, headers=owner_headers)
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # Owner adds User B as COLLABORATOR
    add_res = client.post(f"/api/cases/{case_id}/members", json={"user_id": u2_id, "role": "COLLABORATOR"}, headers=owner_headers)
    assert add_res.status_code == 201
    assert add_res.json()["role"] == "COLLABORATOR"

def test_21_ordinary_member_cannot_add_member():
    owner_id, owner_email, owner_headers = create_test_user("owner21", "Owner 21")
    member_id, member_email, member_headers = create_test_user("member21", "Ordinary Member 21")
    target_id, target_email, target_headers = create_test_user("target21", "Target User 21")

    case_res = client.post("/api/cases/", json={"name": "Ordinary Member Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    # Owner adds member as ordinary COLLABORATOR
    client.post(f"/api/cases/{case_id}/members", json={"user_id": member_id, "role": "COLLABORATOR"}, headers=owner_headers)

    # Ordinary COLLABORATOR attempts to add target user -> 403 Forbidden
    add_attempt = client.post(f"/api/cases/{case_id}/members", json={"user_id": target_id, "role": "COLLABORATOR"}, headers=member_headers)
    assert add_attempt.status_code == 403
    assert "administrator" in add_attempt.json()["detail"].lower() or "denied" in add_attempt.json()["detail"].lower()

def test_22_ordinary_member_cannot_promote_self_or_others():
    owner_id, owner_email, owner_headers = create_test_user("owner22", "Owner 22")
    member_id, member_email, member_headers = create_test_user("member22", "Ordinary Member 22")

    case_res = client.post("/api/cases/", json={"name": "Promotion Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    client.post(f"/api/cases/{case_id}/members", json={"user_id": member_id, "role": "COLLABORATOR"}, headers=owner_headers)

    # Ordinary member attempts self-promotion to PRIMARY_INVESTIGATOR -> 403 Forbidden
    promote_attempt = client.post(f"/api/cases/{case_id}/members", json={"user_id": member_id, "role": "PRIMARY_INVESTIGATOR"}, headers=member_headers)
    assert promote_attempt.status_code == 403

def test_23_ordinary_member_cannot_remove_member():
    owner_id, owner_email, owner_headers = create_test_user("owner23", "Owner 23")
    m1_id, m1_email, m1_headers = create_test_user("m1_23", "Member One 23")
    m2_id, m2_email, m2_headers = create_test_user("m2_23", "Member Two 23")

    case_res = client.post("/api/cases/", json={"name": "Remove Test Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    client.post(f"/api/cases/{case_id}/members", json={"user_id": m1_id, "role": "COLLABORATOR"}, headers=owner_headers)
    client.post(f"/api/cases/{case_id}/members", json={"user_id": m2_id, "role": "COLLABORATOR"}, headers=owner_headers)

    # Ordinary member m1 attempts to remove m2 -> 403 Forbidden
    remove_attempt = client.delete(f"/api/cases/{case_id}/members/{m2_id}", headers=m1_headers)
    assert remove_attempt.status_code == 403

def test_24_owner_can_remove_member():
    owner_id, owner_email, owner_headers = create_test_user("owner24", "Owner 24")
    m1_id, m1_email, m1_headers = create_test_user("m1_24", "Member 24")

    case_res = client.post("/api/cases/", json={"name": "Owner Remove Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    client.post(f"/api/cases/{case_id}/members", json={"user_id": m1_id, "role": "COLLABORATOR"}, headers=owner_headers)

    # Owner removes member -> 200 OK
    remove_res = client.delete(f"/api/cases/{case_id}/members/{m1_id}", headers=owner_headers)
    assert remove_res.status_code == 200

def test_25_user_cannot_grant_self_global_admin():
    owner_id, owner_email, owner_headers = create_test_user("owner25", "Owner 25")
    u1_id, u1_email, u1_headers = create_test_user("u1_25", "User 25")

    case_res = client.post("/api/cases/", json={"name": "Global Admin Boundary Case"}, headers=owner_headers)
    case_id = case_res.json()["id"]

    # Owner adds u1 passing role = "ADMIN"
    add_res = client.post(f"/api/cases/{case_id}/members", json={"user_id": u1_id, "role": "ADMIN"}, headers=owner_headers)
    assert add_res.status_code == 201
    assert add_res.json()["role"] == "CASE_ADMIN"

    # Verify u1's global User.role is still INVESTIGATOR
    with SessionLocal() as db:
        u = db.query(User).filter(User.id == u1_id).first()
        assert u.role == "INVESTIGATOR"
        assert u.role != "ADMIN"

def test_26_cross_case_member_manipulation_denied():
    o1_id, o1_email, o1_headers = create_test_user("o1_26", "Owner 26 A")
    o2_id, o2_email, o2_headers = create_test_user("o2_26", "Owner 26 B")
    target_id, target_email, target_headers = create_test_user("t_26", "Target 26")

    c1_id = client.post("/api/cases/", json={"name": "Case A 26"}, headers=o1_headers).json()["id"]
    c2_id = client.post("/api/cases/", json={"name": "Case B 26"}, headers=o2_headers).json()["id"]

    # Owner 2 tries to add member to Case 1 -> 403 Forbidden
    res = client.post(f"/api/cases/{c1_id}/members", json={"user_id": target_id, "role": "COLLABORATOR"}, headers=o2_headers)
    assert res.status_code == 403

def test_27_nonexistent_and_unauthorized_indirect_resource_semantics():
    u1_id, u1_email, u1_headers = create_test_user("u1_27", "User 27 A")
    u2_id, u2_email, u2_headers = create_test_user("u2_27", "User 27 B")

    c1_id = client.post("/api/cases/", json={"name": "Case A 27"}, headers=u1_headers).json()["id"]

    # Add evidence under Case A
    with SessionLocal() as db:
        ev = EvidenceItem(
            id=str(uuid.uuid4()),
            case_id=c1_id,
            name="dump.dmp",
            original_path="/tmp/dump.dmp",
            storage_path="/tmp/dump.dmp",
            evidence_type="memory_dump",
            size_bytes=100.0,
            sha256="abc",
            integrity_status="VERIFIED"
        )
        db.add(ev)
        db.commit()
        ev_id = ev.id

    # Nonexistent evidence ID under Case A -> 404 Not Found
    fake_ev_id = str(uuid.uuid4())
    res_fake = client.post(f"/api/cases/{c1_id}/analysis/memory", json={
        "evidence_id": fake_ev_id,
        "plugin": "windows.info"
    }, headers=u1_headers)
    assert res_fake.status_code == 404

    # Unauthorized evidence ID from another case (or accessed by unauthorized user) -> 404 Not Found
    c2_id = client.post("/api/cases/", json={"name": "Case B 27"}, headers=u2_headers).json()["id"]
    res_cross = client.post(f"/api/cases/{c2_id}/analysis/memory", json={
        "evidence_id": ev_id,
        "plugin": "windows.info"
    }, headers=u2_headers)
    assert res_cross.status_code == 404

def test_28_member_enumeration_protection():
    o1_id, o1_email, o1_headers = create_test_user("o1_28", "Owner 28")
    c1_id = client.post("/api/cases/", json={"name": "Case 28"}, headers=o1_headers).json()["id"]

    fake_user_id = str(uuid.uuid4())
    res = client.post(f"/api/cases/{c1_id}/members", json={"user_id": fake_user_id, "role": "COLLABORATOR"}, headers=o1_headers)
    assert res.status_code == 404
    assert res.json()["detail"] == "User not found"

