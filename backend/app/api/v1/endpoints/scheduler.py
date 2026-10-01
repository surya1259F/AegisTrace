"""
ADFIR — Resource-Aware Scheduler API Endpoints (Phase 2 / Step 8)

Case-scoped, RBAC-authorized REST endpoints for creating analysis requests,
batch-scheduling plans, tracking queue status, canceling jobs, and retrying failed tasks.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    Case,
    InvestigationPlan,
    InvestigationTask,
    AnalysisRequest,
    User
)
from backend.app.schemas.schemas import (
    AnalysisRequestCreate,
    AnalysisRequestResponse,
    SchedulerPlanBatchResponse,
    SchedulerStatusResponse,
    SchedulerEvaluationResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.scheduler import (
    ResourceAwareScheduler,
    SchedulerResourceTracker,
    SchedulerRetryManager
)

router = APIRouter()


@router.post("/scheduler/requests", response_model=AnalysisRequestResponse, status_code=status.HTTP_201_CREATED)
def create_analysis_request(
    payload: AnalysisRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Creates a single persistent analysis job from a validated Step 7 Tool Selection.
    Enforces case authorization and duplicate request prevention.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == payload.plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    try:
        job = ResourceAwareScheduler.create_analysis_request(
            db=db,
            plan_id=payload.plan_id,
            task_key=payload.task_key,
            actor_user=current_user,
            timeout_seconds=payload.timeout_seconds,
            custom_retry_policy=payload.retry_policy
        )
        return job
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create analysis request: {str(e)}")


@router.post("/investigation-plans/{plan_id}/schedule", response_model=SchedulerPlanBatchResponse)
def schedule_investigation_plan(
    plan_id: str,
    timeout_override: Optional[int] = Query(None, ge=10, le=86400),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Enqueues all eligible tasks of an investigation plan with valid Step 7 tool selections.
    Promotes eligible root tasks to READY and reserves scheduler-level resources.
    Enforces case authorization.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    try:
        batch_summary = ResourceAwareScheduler.schedule_plan(
            db=db,
            plan_id=plan.id,
            actor_user=current_user,
            timeout_override=timeout_override
        )
        return SchedulerPlanBatchResponse(**batch_summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to schedule investigation plan: {str(e)}")


@router.get("/scheduler/requests/{request_id}", response_model=AnalysisRequestResponse)
def get_analysis_request_details(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a specific AnalysisRequest.
    Enforces RBAC case authorization to prevent IDOR.
    """
    req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Analysis request not found")

    get_authorized_case(req.case_id, db, current_user)
    return req


@router.get("/cases/{case_id}/scheduler/requests", response_model=List[AnalysisRequestResponse])
def list_analysis_requests_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all analysis requests associated with an authorized case.
    """
    case = get_authorized_case(case_id, db, current_user)
    requests = (
        db.query(AnalysisRequest)
        .filter(AnalysisRequest.case_id == case.id)
        .order_by(AnalysisRequest.queued_at.desc())
        .all()
    )
    return requests


@router.get("/scheduler/queue", response_model=List[AnalysisRequestResponse])
def get_scheduler_queue(
    status_filter: Optional[str] = Query(None, alias="status"),
    plan_id: Optional[str] = Query(None),
    case_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves queued and active jobs, optionally filtered by status, plan, or case.
    Enforces authorization on specified cases.
    """
    if case_id:
        get_authorized_case(case_id, db, current_user)

    query = db.query(AnalysisRequest)

    if case_id:
        query = query.filter(AnalysisRequest.case_id == case_id)
    if plan_id:
        query = query.filter(AnalysisRequest.plan_id == plan_id)
    if status_filter:
        query = query.filter(AnalysisRequest.scheduler_status == status_filter.upper())

    jobs = query.order_by(
        AnalysisRequest.priority_score.desc(),
        AnalysisRequest.queued_at.asc()
    ).all()
    return jobs


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
def get_scheduler_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns real-time metrics on host capacity, active resource allocations,
    and job queue breakdown.
    """
    status_data = SchedulerResourceTracker.get_scheduler_status(db)
    return SchedulerStatusResponse(**status_data)


@router.post("/scheduler/requests/{request_id}/cancel", response_model=AnalysisRequestResponse)
def cancel_analysis_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Cancels a queued, waiting, or ready analysis job, releases reserved resources,
    and updates dependent tasks.
    Enforces case authorization.
    """
    req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Analysis request not found")

    get_authorized_case(req.case_id, db, current_user)

    try:
        updated = ResourceAwareScheduler.cancel_job(db, req.id, current_user)
        return updated
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel analysis request: {str(e)}")


@router.post("/scheduler/requests/{request_id}/retry", response_model=AnalysisRequestResponse)
def retry_failed_analysis_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Schedules an eligible failed or timed-out job for retry according to its retry policy.
    Enforces case authorization.
    """
    req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Analysis request not found")

    get_authorized_case(req.case_id, db, current_user)

    can_r, reason = SchedulerRetryManager.can_retry(req)
    if not can_r:
        raise HTTPException(status_code=400, detail=f"Cannot retry job: {reason}")

    success = SchedulerRetryManager.schedule_retry(db, req, current_user)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to schedule retry for job")

    # Trigger evaluation pass
    ResourceAwareScheduler.evaluate_queue(db, plan_id=req.plan_id)
    db.refresh(req)
    return req


@router.post("/scheduler/evaluate", response_model=SchedulerEvaluationResponse)
def trigger_scheduler_evaluation(
    plan_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Manually triggers a scheduler queue evaluation cycle.
    Evaluates timeouts, dependencies, and promotes eligible jobs to READY.
    """
    if plan_id:
        plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
        if plan:
            get_authorized_case(plan.case_id, db, current_user)

    result = ResourceAwareScheduler.evaluate_queue(db, plan_id=plan_id)
    return SchedulerEvaluationResponse(**result)
