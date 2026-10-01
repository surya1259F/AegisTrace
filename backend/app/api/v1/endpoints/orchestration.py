"""ADFIR — Investigation Orchestration REST API Endpoints (Final Backend Completion)

Provides endpoints to:
- Start/trigger full investigation pipeline runs
- Inspect run details, stage progress, and task statuses
- Pause, resume, and cancel active investigation runs
- Step execution manually stage-by-stage
- Initiate a new controlled investigation cycle from an investigator's REQUEST_MORE_EVIDENCE review
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    InvestigationRunResponse,
    InvestigationRunCreateRequest,
    InvestigationRunActionRequest
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.orchestration import InvestigationOrchestrationService

logger = logging.getLogger("ADFIR_ORCHESTRATION_API")

router = APIRouter()


@router.post(
    "/cases/{case_id}/runs/start",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_201_CREATED
)
def start_investigation_run(
    case_id: str,
    request_data: Optional[InvestigationRunCreateRequest] = None,
    auto_progress: bool = Query(default=True, description="Whether to progress through stages automatically"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Starts a new persistent investigation run for the authorized case.
    Coordinates the full pipeline: Strategy -> Capability Selection -> Scheduler ->
    Governance -> Secure Execution -> Raw Outputs -> Artifact Extraction -> Normalization ->
    Timeline -> Correlation -> Findings -> Specialist Agents -> AI Reasoning -> Review.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.start_run(
        db=db,
        case_id=case.id,
        user=current_user,
        request_data=request_data,
        auto_progress=auto_progress
    )


@router.get(
    "/cases/{case_id}/runs",
    response_model=List[InvestigationRunResponse],
    status_code=status.HTTP_200_OK
)
def list_investigation_runs(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Lists all historical and active investigation runs for the case."""
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.list_runs(
        db=db,
        case_id=case.id,
        user=current_user
    )


@router.get(
    "/cases/{case_id}/runs/{run_id}",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_200_OK
)
def get_investigation_run(
    case_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Retrieves detailed state, current stage, and progress for a specific investigation run."""
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.get_run(
        db=db,
        case_id=case.id,
        run_id=run_id,
        user=current_user
    )


@router.post(
    "/cases/{case_id}/runs/{run_id}/pause",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_200_OK
)
def pause_investigation_run(
    case_id: str,
    run_id: str,
    action_req: Optional[InvestigationRunActionRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Pauses an active investigation run."""
    case = get_authorized_case(case_id, db, current_user)
    reason = action_req.reason if action_req else None
    return InvestigationOrchestrationService.pause_run(
        db=db,
        run_id=run_id,
        user=current_user,
        reason=reason
    )


@router.post(
    "/cases/{case_id}/runs/{run_id}/resume",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_200_OK
)
def resume_investigation_run(
    case_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Resumes a paused or interrupted investigation run."""
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.resume_run(
        db=db,
        run_id=run_id,
        user=current_user
    )


@router.post(
    "/cases/{case_id}/runs/{run_id}/cancel",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_200_OK
)
def cancel_investigation_run(
    case_id: str,
    run_id: str,
    action_req: Optional[InvestigationRunActionRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Cancels an active or pending investigation run safely."""
    case = get_authorized_case(case_id, db, current_user)
    reason = action_req.reason if action_req else None
    return InvestigationOrchestrationService.cancel_run(
        db=db,
        run_id=run_id,
        user=current_user,
        reason=reason
    )


@router.post(
    "/cases/{case_id}/runs/{run_id}/step",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_200_OK
)
def step_investigation_run(
    case_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Executes the next stage of the investigation pipeline synchronously."""
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.execute_next_stage(
        db=db,
        run_id=run_id,
        user=current_user
    )


@router.post(
    "/cases/{case_id}/review/{review_id}/new-cycle",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_201_CREATED
)
def initiate_new_cycle_from_review(
    case_id: str,
    review_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Creates a new controlled investigation cycle downstream of an investigator's
    REQUEST_MORE_EVIDENCE decision, safely re-entering the pipeline.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigationOrchestrationService.initiate_new_cycle_from_review(
        db=db,
        case_id=case.id,
        review_id=review_id,
        user=current_user
    )
