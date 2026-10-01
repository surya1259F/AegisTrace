"""ADFIR — Cryptographic Audit Trail REST API Endpoints (Final Backend Completion)

Provides endpoints to:
- Verify hash-chained cryptographic integrity from genesis to head
- Retrieve immutable audit trail events for an authorized case
- Guarantee cross-case tenant isolation and prevent IDOR
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import AuditEvent, User
from backend.app.schemas.schemas import AuditEventResponse, AuditChainVerificationResponse
from backend.app.services.authorization import get_authorized_case
from backend.app.services.audit import AuditService

logger = logging.getLogger("ADFIR_AUDIT_API")

router = APIRouter()


@router.get(
    "/cases/{case_id}/audit/verify",
    response_model=AuditChainVerificationResponse,
    status_code=status.HTTP_200_OK
)
def verify_case_audit_chain(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies the cryptographic hash-chained audit trail for an authorized case.
    Re-computes every link from genesis to head and detects any tamper or deletion.
    """
    case = get_authorized_case(case_id, db, current_user)
    return AuditService.verify_chain(db=db, case_id=case.id)


@router.get(
    "/cases/{case_id}/audit",
    response_model=List[AuditEventResponse],
    status_code=status.HTTP_200_OK
)
def get_case_audit_events(
    case_id: str,
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns the immutable, chronological audit trail for the authorized case.
    Enforces strict IDOR protection.
    """
    case = get_authorized_case(case_id, db, current_user)
    query = db.query(AuditEvent).filter(AuditEvent.case_id == case.id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)

    events = query.order_by(AuditEvent.chain_index.asc(), AuditEvent.timestamp.asc()).limit(limit).all()
    return events
