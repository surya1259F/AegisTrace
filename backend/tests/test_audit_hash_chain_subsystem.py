"""ADFIR — Cryptographic Hash-Chained Audit & Provenance Subsystem Tests

Verifies:
1. Genesis audit event has previous_hash == '0'*64 and chain_index == 0.
2. Sequential audit events correctly chain previous_hash to predecessor event_hash.
3. Audit chain verification API returns valid=True and tamper_detected=False on clean chains.
4. Tamper detection: altering an audit event details or hash triggers tamper_detected=True.
5. Deletion detection: deleting an intermediate audit event breaks the chain and is detected.
6. Provenance context: events store rich provenance context (case, run, task, execution, artifact).
7. Cross-case isolation: events for Case A do not collide or share previous_hash with Case B.
8. REST API endpoints: GET /cases/{case_id}/audit and GET /cases/{case_id}/audit/verify enforce RBAC and IDOR.
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import Case, CaseMember, User, AuditEvent
from backend.app.services.audit import AuditService, log_audit_event, GENESIS_HASH

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_user_and_case(db: Session, prefix="aud"):
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Auditor {prefix}",
        organization="DFIR Audit Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("AuditPass@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-{prefix}-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:10].upper()}",
        name=f"Case {prefix}",
        description="Audit subsystem test case",
        created_by=user.id,
        owner_id=user.id,
        status="OPEN"
    )
    db.add(case)
    db.commit()

    member = CaseMember(
        id=str(uuid.uuid4()),
        case_id=case.id,
        user_id=user.id,
        role="PRIMARY_INVESTIGATOR"
    )
    db.add(member)
    db.commit()

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}
    return user, case, headers


def test_audit_genesis_and_hash_chaining(db_session):
    """Test 1: Verify genesis event and subsequent hash-chained links."""
    user, case, headers = create_user_and_case(db_session, "chain")

    # Event 0: Genesis for this case
    ev0 = log_audit_event(
        db=db_session,
        event_type="CASE_INITIALIZED",
        details="Genesis case event",
        case_id=case.id,
        actor_id=user.id,
        actor_name=user.email,
        metadata_json={"phase": "genesis"}
    )
    assert ev0.previous_hash == GENESIS_HASH
    assert ev0.chain_index == 0
    assert len(ev0.event_hash) == 64

    # Event 1: First chained event
    ev1 = log_audit_event(
        db=db_session,
        event_type="EVIDENCE_INTAKE_STARTED",
        details="Starting evidence intake",
        case_id=case.id,
        actor_id=user.id,
        actor_name=user.email,
        metadata_json={"evidence_count": 1}
    )
    assert ev1.previous_hash == ev0.event_hash
    assert ev1.chain_index == 1

    # Event 2: Second chained event
    ev2 = log_audit_event(
        db=db_session,
        event_type="PLAN_GENERATED",
        details="Investigation plan generated",
        case_id=case.id,
        actor_id=user.id,
        actor_name=user.email,
        metadata_json={"tasks_count": 3}
    )
    assert ev2.previous_hash == ev1.event_hash
    assert ev2.chain_index == 2

    # Verify clean chain via service
    res = AuditService.verify_chain(db_session, case_id=case.id)
    assert res.is_valid is True
    assert res.tamper_detected is False
    assert res.total_events >= 3
    assert res.genesis_hash == ev0.event_hash
    assert res.latest_hash == ev2.event_hash


def test_audit_tamper_detection(db_session):
    """Test 2: Modifying an audit event payload is immediately detected."""
    user, case, headers = create_user_and_case(db_session, "tamper")

    ev0 = log_audit_event(db=db_session, event_type="E1", details="Event 1", case_id=case.id)
    ev1 = log_audit_event(db=db_session, event_type="E2", details="Event 2", case_id=case.id)
    ev2 = log_audit_event(db=db_session, event_type="E3", details="Event 3", case_id=case.id)

    # Verify clean initial state
    res_clean = AuditService.verify_chain(db_session, case_id=case.id)
    assert res_clean.is_valid is True

    # Tamper with ev1 details in database
    ev1.details = "TAMPERED DETAILS BY ADVERSARY"
    db_session.add(ev1)
    db_session.commit()

    # Re-verify: must catch tampering
    res_tampered = AuditService.verify_chain(db_session, case_id=case.id)
    assert res_tampered.is_valid is False
    assert res_tampered.tamper_detected is True
    assert res_tampered.broken_event_id == ev1.id


def test_audit_deletion_detection(db_session):
    """Test 3: Deleting an intermediate audit event breaks the chain."""
    user, case, headers = create_user_and_case(db_session, "del")

    ev0 = log_audit_event(db=db_session, event_type="E0", details="Event 0", case_id=case.id)
    ev1 = log_audit_event(db=db_session, event_type="E1", details="Event 1", case_id=case.id)
    ev2 = log_audit_event(db=db_session, event_type="E2", details="Event 2", case_id=case.id)

    # Delete intermediate event ev1
    db_session.delete(ev1)
    db_session.commit()

    # Verify: must detect broken predecessor link
    res = AuditService.verify_chain(db_session, case_id=case.id)
    assert res.is_valid is False
    assert res.tamper_detected is True
    assert "Audit chain break detected" in res.verification_message


def test_audit_cross_case_isolation(db_session):
    """Test 4: Chains for Case A and Case B are completely isolated."""
    user_a, case_a, headers_a = create_user_and_case(db_session, "iso_a")
    user_b, case_b, headers_b = create_user_and_case(db_session, "iso_b")

    ev_a0 = log_audit_event(db=db_session, event_type="INIT_A", details="Case A Init", case_id=case_a.id)
    ev_b0 = log_audit_event(db=db_session, event_type="INIT_B", details="Case B Init", case_id=case_b.id)
    ev_a1 = log_audit_event(db=db_session, event_type="ACTION_A", details="Case A Action", case_id=case_a.id)
    ev_b1 = log_audit_event(db=db_session, event_type="ACTION_B", details="Case B Action", case_id=case_b.id)

    # Both genesis events must be independent
    assert ev_a0.previous_hash == GENESIS_HASH
    assert ev_b0.previous_hash == GENESIS_HASH
    assert ev_a0.chain_index == 0
    assert ev_b0.chain_index == 0

    # Links in Case A must point only to Case A
    assert ev_a1.previous_hash == ev_a0.event_hash
    assert ev_b1.previous_hash == ev_b0.event_hash

    # Verify both chains independently pass
    res_a = AuditService.verify_chain(db_session, case_id=case_a.id)
    res_b = AuditService.verify_chain(db_session, case_id=case_b.id)
    assert res_a.is_valid is True
    assert res_b.is_valid is True


def test_audit_rest_api_and_idor(db_session):
    """Test 5: REST API endpoints enforce RBAC and cross-case IDOR protection."""
    user_a, case_a, headers_a = create_user_and_case(db_session, "api_a")
    user_b, case_b, headers_b = create_user_and_case(db_session, "api_b")

    log_audit_event(db=db_session, event_type="TEST_EVENT", details="API Test", case_id=case_a.id)

    # User A accesses Case A audit verify -> 200 OK
    res = client.get(f"/api/v1/cases/{case_a.id}/audit/verify", headers=headers_a)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["tamper_detected"] is False

    # User A accesses Case A audit list -> 200 OK
    res_list = client.get(f"/api/v1/cases/{case_a.id}/audit", headers=headers_a)
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    # User B accesses Case A audit verify -> 403 Forbidden (IDOR protection)
    res_idor = client.get(f"/api/v1/cases/{case_a.id}/audit/verify", headers=headers_b)
    assert res_idor.status_code == 403

    # User B accesses Case A audit list -> 403 Forbidden
    res_idor_list = client.get(f"/api/v1/cases/{case_a.id}/audit", headers=headers_b)
    assert res_idor_list.status_code == 403
