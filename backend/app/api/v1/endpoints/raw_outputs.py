"""
ADFIR — Raw Forensic Outputs API Endpoints (Phase 2 / Step 10)

Case-scoped, RBAC-authorized REST endpoints for:
- Listing raw outputs for an execution, request, or case (with optional output_type filter)
- Retrieving output metadata and cryptographic SHA-256 hashes
- Verifying raw output integrity against disk storage
- Securely downloading / streaming raw forensic output artifacts (symlink & traversal safe)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    ForensicExecution,
    AnalysisRequest,
    ExecutionOutput,
    Case,
    User
)
from backend.app.schemas.schemas import (
    ExecutionOutputResponse,
    OutputIntegrityResponse
)
from backend.app.services.authorization import get_authorized_case, validate_case_access
from backend.app.services.raw_outputs import (
    RawOutputsService,
    RawOutputsSecurityError,
    VALID_OUTPUT_TYPES
)

router = APIRouter()


@router.get("/cases/{case_id}/executions/{execution_id}/outputs", response_model=List[ExecutionOutputResponse])
def list_case_execution_outputs(
    case_id: str,
    execution_id: str,
    output_type: Optional[str] = Query(None, description="Filter by output type: TOOL_OUTPUT, STDOUT, STDERR, LOG"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all raw outputs produced by an execution under a specific case.
    Strictly verifies case authorization and prevents IDOR cross-case leakage.
    """
    get_authorized_case(case_id, db, current_user)

    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic execution not found")

    if execution.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution does not belong to specified case")

    if output_type and output_type.upper() not in VALID_OUTPUT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid output_type '{output_type}'. Supported: {sorted(list(VALID_OUTPUT_TYPES))}"
        )

    return RawOutputsService.list_execution_outputs(
        db=db,
        execution_id=execution_id,
        actor=current_user,
        output_type=output_type
    )


@router.get("/scheduler/requests/{request_id}/outputs", response_model=List[ExecutionOutputResponse])
def list_request_outputs(
    request_id: str,
    output_type: Optional[str] = Query(None, description="Filter by output type: TOOL_OUTPUT, STDOUT, STDERR, LOG"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all raw outputs produced for an analysis request across all its executions.
    """
    req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis request not found")

    get_authorized_case(req.case_id, db, current_user)

    if output_type and output_type.upper() not in VALID_OUTPUT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid output_type '{output_type}'. Supported: {sorted(list(VALID_OUTPUT_TYPES))}"
        )

    return RawOutputsService.list_request_outputs(
        db=db,
        request_id=request_id,
        actor=current_user,
        output_type=output_type
    )


@router.get("/cases/{case_id}/outputs", response_model=List[ExecutionOutputResponse])
def list_case_outputs(
    case_id: str,
    output_type: Optional[str] = Query(None, description="Filter by output type: TOOL_OUTPUT, STDOUT, STDERR, LOG"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all raw forensic output artifacts produced for an entire case.
    """
    get_authorized_case(case_id, db, current_user)

    if output_type and output_type.upper() not in VALID_OUTPUT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid output_type '{output_type}'. Supported: {sorted(list(VALID_OUTPUT_TYPES))}"
        )

    return RawOutputsService.list_case_outputs(
        db=db,
        case_id=case_id,
        actor=current_user,
        output_type=output_type
    )


@router.get("/outputs/{output_id}", response_model=ExecutionOutputResponse)
def get_output_metadata(
    output_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves detailed metadata, hash, and provenance for a single raw forensic output artifact.
    """
    try:
        return RawOutputsService.get_output_metadata(db=db, output_id=output_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/outputs/{output_id}/integrity", response_model=OutputIntegrityResponse)
def verify_output_integrity(
    output_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Cryptographically verifies the raw output file on disk against its stored SHA-256 hash.
    Detects tampering or missing output artifacts without modifying state.
    """
    try:
        res = RawOutputsService.verify_output_integrity(db=db, output_id=output_id, actor=current_user)
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/outputs/{output_id}/download")
def download_output_file(
    output_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Safely downloads a raw forensic output artifact as a file attachment.
    Enforces RBAC case authorization and workspace boundary containment.
    """
    try:
        fpath, filename, mime_type = RawOutputsService.get_output_file_stream(
            db=db,
            output_id=output_id,
            actor=current_user
        )
        return FileResponse(
            path=str(fpath),
            filename=filename,
            media_type=mime_type
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RawOutputsSecurityError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get("/outputs/{output_id}/content")
def view_output_content(
    output_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inline streaming view for raw forensic output content (logs or text artifacts).
    """
    return download_output_file(output_id=output_id, db=db, current_user=current_user)
