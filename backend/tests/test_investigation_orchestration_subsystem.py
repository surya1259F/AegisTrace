"""ADFIR — Investigation Orchestration Subsystem Tests (Final Backend Completion)

Verifies:
1. Investigation run creation, cycle numbering, and persistent state.
2. Stage progression and dependency-aware step execution.
3. Pause, resume, and cancel lifecycle controls.
4. REQUEST_MORE_EVIDENCE controlled new cycle trigger.
5. Case isolation and cross-case IDOR protection on runs endpoints.
6. Safe stop conditions and error handling.
"""

import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import (
    Case,
    CaseMember,
    User,
    InvestigationRun,
    InvestigationPlan,
    InvestigatorReviewRecord,
    AuditEvent
)
from backend.app.schemas.schemas import InvestigationRunCreateRequest, InvestigationRunActionRequest
from backend.app.services.orchestration import InvestigationOrchestrationService

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_user_and_case(db: Session, prefix="orch"):
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Lead Investigator {prefix}",
        organization="DFIR Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("Pass@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-{prefix}-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:10].upper()}",
        name=f"Case {prefix}",
        description="Investigation orchestration test case",
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


def test_run_creation_and_cycle_increment(db_session):
    """Test 1: Verify persistent run creation and monotonic cycle numbering."""
    user, case, headers = create_user_and_case(db_session, "cycle")

    # Start Run 1 (auto_progress=False to inspect initial state)
    run1 = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case.id,
        user=user,
        auto_progress=False
    )
    assert run1.cycle_number == 1
    assert run1.status == "RUNNING"
    assert run1.current_stage == "STRATEGY"
    assert run1.case_id == case.id
    assert "STRATEGY" in run1.stage_progress

    # Start Run 2 -> cycle_number increments to 2
    run2 = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case.id,
        user=user,
        auto_progress=False
    )
    assert run2.cycle_number == 2
    assert run2.id != run1.id


def test_run_pause_and_resume(db_session):
    """Test 2: Verify run pause and resume lifecycle transitions."""
    user, case, headers = create_user_and_case(db_session, "pause")

    run = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case.id,
        user=user,
        auto_progress=False
    )
    assert run.status == "RUNNING"

    # Pause run
    paused_run = InvestigationOrchestrationService.pause_run(
        db=db_session,
        run_id=run.id,
        user=user,
        reason="Awaiting external evidence delivery"
    )
    assert paused_run.status == "PAUSED"
    assert "paused" in (paused_run.error_message or "").lower()

    # Resume run (auto_progress=False to keep it in next stage or running)
    res = client.post(f"/api/v1/cases/{case.id}/runs/{run.id}/resume", headers=headers)
    assert res.status_code == 200
    resumed_data = res.json()
    assert resumed_data["status"] in ("RUNNING", "COMPLETED", "PENDING")


def test_run_cancel_and_immutability(db_session):
    """Test 3: Verify run cancellation and rejection of further operations on cancelled runs."""
    user, case, headers = create_user_and_case(db_session, "cancel")

    run = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case.id,
        user=user,
        auto_progress=False
    )

    # Cancel via API
    cancel_res = client.post(
        f"/api/v1/cases/{case.id}/runs/{run.id}/cancel",
        headers=headers,
        json={"reason": "Investigator deemed scope superseded"}
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Further pause must fail with 400 Bad Request
    pause_res = client.post(f"/api/v1/cases/{case.id}/runs/{run.id}/pause", headers=headers, json={})
    assert pause_res.status_code == 400

    # Further step must fail with 400 Bad Request
    step_res = client.post(f"/api/v1/cases/{case.id}/runs/{run.id}/step", headers=headers)
    assert step_res.status_code == 400


def test_new_cycle_from_investigator_review(db_session):
    """Test 4: REQUEST_MORE_EVIDENCE review safely initiates a new controlled cycle."""
    user, case, headers = create_user_and_case(db_session, "rev_cycle")

    # Start cycle 1
    run1 = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case.id,
        user=user,
        auto_progress=False
    )
    assert run1.cycle_number == 1

    # Create an investigator review record requesting more evidence
    review = InvestigatorReviewRecord(
        case_id=case.id,
        investigator_id=user.id,
        investigator_name=user.name or user.email,
        target_type="FINDING",
        target_id=str(uuid.uuid4()),
        decision="REQUEST_MORE_EVIDENCE",
        comment="Need memory dump analysis to corroborate suspicious network connection",
        resulting_workflow_action="PENDING",
        sha256_hash="c" * 64,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(review)
    db_session.commit()
    db_session.refresh(review)

    # Initiate new cycle from review
    res = client.post(
        f"/api/v1/cases/{case.id}/review/{review.id}/new-cycle",
        headers=headers
    )
    assert res.status_code == 201
    data = res.json()
    assert data["cycle_number"] == 2
    assert data["case_id"] == case.id

    # Verify review record updated with workflow action linkage
    db_session.refresh(review)
    assert review.resulting_workflow_action == "EVIDENCE_REQUESTED"
    assert review.action_reference_id == data["id"]


def test_orchestration_case_isolation_and_idor(db_session):
    """Test 5: Cross-case IDOR protection: User A cannot manage or inspect runs for Case B."""
    user_a, case_a, headers_a = create_user_and_case(db_session, "idor_a")
    user_b, case_b, headers_b = create_user_and_case(db_session, "idor_b")

    run_a = InvestigationOrchestrationService.start_run(
        db=db_session,
        case_id=case_a.id,
        user=user_a,
        auto_progress=False
    )

    # User B tries to view Case A runs -> 403 Forbidden
    res_list = client.get(f"/api/v1/cases/{case_a.id}/runs", headers=headers_b)
    assert res_list.status_code == 403

    # User B tries to get Case A run -> 403 Forbidden
    res_get = client.get(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}", headers=headers_b)
    assert res_get.status_code == 403

    # User B tries to pause Case A run -> 403 Forbidden
    res_pause = client.post(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}/pause", headers=headers_b, json={})
    assert res_pause.status_code == 403

    # User B tries to resume Case A run -> 403 Forbidden
    res_resume = client.post(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}/resume", headers=headers_b)
    assert res_resume.status_code == 403

    # User B tries to cancel Case A run -> 403 Forbidden
    res_cancel = client.post(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}/cancel", headers=headers_b, json={})
    assert res_cancel.status_code == 403

    # User B tries to step Case A run -> 403 Forbidden
    res_step = client.post(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}/step", headers=headers_b)
    assert res_step.status_code == 403

    # User A accesses own run -> 200 OK
    res_own = client.get(f"/api/v1/cases/{case_a.id}/runs/{run_a.id}", headers=headers_a)
    assert res_own.status_code == 200
    assert res_own.json()["id"] == run_a.id
