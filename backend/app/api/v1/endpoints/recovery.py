"""ADFIR — Investigation Recovery REST API Endpoints (Final Backend Completion)

Provides endpoints to:
- Recover case state, stale runs, and interrupted tasks deterministically
- Preserve valid forensic outputs without duplicate re-execution
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    RecoveryRequest,
    RecoveryResponse,
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.recovery import InvestigationRecoveryService

logger = logging.getLogger("ADFIR_RECOVERY_API")

router = APIRouter()


@router.post(
    "/{case_id}/recover",
    response_model=RecoveryResponse,
    status_code=status.HTTP_200_OK
)
def recover_case(
    case_id: str,
    recovery_req: Optional[RecoveryRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Scans persistent storage, recovers interrupted runs and tasks safely,
    preserves completed executions whose output hashes remain intact,
    and ensures still-running processes are not duplicated.
    """
    case = get_authorized_case(case_id, db, current_user)
    force = recovery_req.force if recovery_req else False
    safe_reset = recovery_req.safe_reset_stale_tasks if recovery_req else True

    return InvestigationRecoveryService.recover_case(
        db=db,
        case_id=case.id,
        user=current_user,
        force=force,
        safe_reset_stale_tasks=safe_reset
    )
