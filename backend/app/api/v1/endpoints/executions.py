"""
ADFIR — Secure Forensic Execution API Endpoints (Phase 2 / Step 9)

Case-scoped, RBAC-authorized REST endpoints for starting READY analysis requests,
monitoring execution progress, viewing stdout/stderr log artifacts,
listing verified outputs with SHA-256 hashes, and safely cancelling running executions.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    User
)
from backend.app.schemas.schemas import (
    ForensicExecutionResponse,
    ExecutionOutputResponse,
    ExecutionStartRequest,
    ExecutionStatusResponse,
    ExecutionCancelRequest,
    ExecutionArtifactContentResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.execution import ForensicExecutionService

router = APIRouter()


@router.post(
    "/executions/requests/{request_id}/start",
    response_model=ForensicExecutionResponse,
    status_code=status.HTTP_201_CREATED
)
def start_execution(
    request_id: str,
    payload: Optional[ExecutionStartRequest] = None,
    wait: bool = Query(False, description="If True, blocks until process finishes"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Starts secure forensic execution for a READY analysis request.
    Verifies evidence vault integrity, tool availability, and safe argv before launch.
    """
    req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Analysis request not found")

    get_authorized_case(req.case_id, db, current_user)

    custom_params = payload.custom_parameters if payload else {}

    try:
        execution = ForensicExecutionService.start_execution(
            db=db,
            request_id=request_id,
            actor=current_user,
            custom_parameters=custom_params,
            wait=wait
        )
        return execution
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Execution launch failure: {str(ex)}"
        )


@router.get("/executions/{execution_id}", response_model=ForensicExecutionResponse)
def get_execution_details(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full execution details and provenance for an execution record.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)
    return execution


@router.get("/executions/{execution_id}/status", response_model=ExecutionStatusResponse)
def get_execution_status(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lightweight status polling endpoint for tracking process completion and exit code.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)

    return ExecutionStatusResponse(
        execution_id=execution.id,
        request_id=execution.request_id,
        execution_status=execution.execution_status,
        exit_code=execution.exit_code,
        pid=execution.pid,
        duration_seconds=execution.duration_seconds,
        output_count=execution.output_count
    )


@router.get("/executions/{execution_id}/outputs", response_model=List[ExecutionOutputResponse])
def list_execution_outputs(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all verified output artifacts generated inside the isolated workspace.
    Includes file sizes and cryptographic SHA-256 hashes.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)

    outputs = (
        db.query(ExecutionOutput)
        .filter(ExecutionOutput.execution_id == execution_id)
        .order_by(ExecutionOutput.created_at.asc())
        .all()
    )
    return outputs


@router.get("/executions/{execution_id}/stdout", response_model=ExecutionArtifactContentResponse)
def get_execution_stdout(
    execution_id: str,
    max_bytes: Optional[int] = Query(None, ge=1024, le=10 * 1024 * 1024),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves bounded standard output captured from the forensic tool execution.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)

    return ForensicExecutionService.get_stream_content(
        db=db,
        execution_id=execution_id,
        stream_type="stdout",
        max_bytes=max_bytes
    )


@router.get("/executions/{execution_id}/stderr", response_model=ExecutionArtifactContentResponse)
def get_execution_stderr(
    execution_id: str,
    max_bytes: Optional[int] = Query(None, ge=1024, le=10 * 1024 * 1024),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves bounded standard error captured from the forensic tool execution.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)

    return ForensicExecutionService.get_stream_content(
        db=db,
        execution_id=execution_id,
        stream_type="stderr",
        max_bytes=max_bytes
    )


@router.post("/executions/{execution_id}/cancel", response_model=ForensicExecutionResponse)
def cancel_execution(
    execution_id: str,
    payload: Optional[ExecutionCancelRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Safely cancels an actively running execution.
    Verifies process identity, terminates subprocess, releases scheduler reservations,
    and logs immutable audit event.
    """
    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Forensic execution not found")

    get_authorized_case(execution.case_id, db, current_user)

    reason = payload.reason if payload else "Cancelled by investigator"
    try:
        updated = ForensicExecutionService.cancel_execution(
            db=db,
            execution_id=execution_id,
            actor=current_user,
            reason=reason
        )
        return updated
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cancellation failure: {str(ex)}"
        )


@router.get("/cases/{case_id}/executions", response_model=List[ForensicExecutionResponse])
def list_case_executions(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all forensic executions conducted under a specific case.
    """
    get_authorized_case(case_id, db, current_user)

    executions = (
        db.query(ForensicExecution)
        .filter(ForensicExecution.case_id == case_id)
        .order_by(ForensicExecution.created_at.desc())
        .all()
    )
    return executions
