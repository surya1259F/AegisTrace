from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import AuditEvent, User
from backend.app.schemas.schemas import AuditEventResponse
from backend.app.services.authorization import get_authorized_case, get_user_cases

router = APIRouter()

@router.get("/audit", response_model=List[AuditEventResponse])
def get_audit_trail(
    case_id: Optional[str] = Query(None, description="Filter audit events by case ID"),
    event_type: Optional[str] = Query(None, description="Filter audit events by event type"),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns the authoritative, append-only security and investigation audit trail for authorized cases.
    """
    query = db.query(AuditEvent)

    if case_id:
        # Verify user is authorized for the specific case
        authorized_case = get_authorized_case(case_id, db, current_user)
        query = query.filter(AuditEvent.case_id == authorized_case.id)
    else:
        # Restrict audit events to cases authorized for current_user
        user_cases = get_user_cases(db, current_user)
        auth_case_ids = [c.id for c in user_cases]
        query = query.filter(AuditEvent.case_id.in_(auth_case_ids))

    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)

    return query.order_by(AuditEvent.timestamp.desc()).limit(limit).all()
