import pytest
import uuid

from sqlalchemy.orm import Session
from fastapi import Depends
from backend.app.main import app
from backend.app.core.security import get_current_user, get_current_active_user
from backend.app.core.database import get_db
from backend.app.models.models import User

TEST_USER_ID = "00000000-0000-0000-0000-000000000001"
TEST_USER_EMAIL = "test-investigator@adfir.local"

@pytest.fixture(autouse=True)
def auto_authenticate_tests(request):
    """
    Autouse fixture that supplies an authenticated test user for functional,
    vault, correlation, execution, and specialist agent tests.
    Leaves security/auth tests (test_auth, test_case_authorization) un-overridden
    so explicit 401/403 security assertions are rigorously verified.
    """
    module_name = request.module.__name__ if request.module else ""
    excluded_modules = [
        "test_auth",
        "test_case_authorization",
        "test_user_administration",
        "test_ai_api",
        "test_case_creation_workflow",
        "test_investigation_strategy_engine",
        "test_tool_selection",
        "test_scheduler",
        "test_secure_execution",
        "test_raw_outputs",
        "test_artifact_extraction",
        "test_artifact_normalization",
        "test_unified_timeline",
        "test_cross_domain_correlation",
        "test_deterministic_findings",
        "test_specialist_agent",
        "test_governance_gate",
        "test_ai_reasoning",
        "test_investigator_review",
        "test_final_forensic_report",
        "test_audit_hash_chain",
        "test_investigation_orchestration",
        "test_recovery_and_case_closure",
        "test_full_investigation_lifecycle_e2e",
    ]
    if any(ex in module_name for ex in excluded_modules):
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_active_user, None)
        yield
    else:

        def override_get_current_user(db: Session = Depends(get_db)) -> User:
            user = db.query(User).filter(User.id == TEST_USER_ID).first()
            if not user:
                user = User(
                    id=TEST_USER_ID,
                    email=TEST_USER_EMAIL,
                    name="Default Test Investigator",
                    is_active=True,
                    password_hash="test_hash"
                )
                db.add(user)
                try:
                    db.commit()
                    db.refresh(user)
                except Exception:
                    db.rollback()
                    user = db.query(User).filter(User.id == TEST_USER_ID).first()
            return user

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        yield
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture(autouse=True)
def cleanup_active_scheduler_state():
    """
    Cleans up any leftover active scheduler requests before and after each test
    to guarantee test isolation and prevent resource exhaustion.
    """
    from backend.app.core.database import SessionLocal
    from backend.app.models.models import AnalysisRequest
    db = SessionLocal()
    try:
        active = db.query(AnalysisRequest).filter(AnalysisRequest.scheduler_status.in_(["READY", "RUNNING"])).all()
        for r in active:
            r.scheduler_status = "COMPLETED"
        if active:
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        active = db.query(AnalysisRequest).filter(AnalysisRequest.scheduler_status.in_(["READY", "RUNNING"])).all()
        for r in active:
            r.scheduler_status = "COMPLETED"
        if active:
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


