"""
ADFIR — Structured Forensic Artifacts API Endpoints (Phase 2 / Step 11)

Case-scoped, RBAC-authorized REST endpoints for:
- Extracting structured forensic artifacts from Step 10 raw outputs
- Listing structured artifacts for executions or evidence items
- Inspecting normalized artifact details, provenance, and schemas
- Cryptographically verifying artifact integrity and raw output lineage
- Securely downloading serialized artifact JSON payloads
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    ForensicExecution,
    ExecutionOutput,
    EvidenceItem,
    StructuredArtifact,
    User
)
from backend.app.schemas.schemas import (
    StructuredArtifactResponse,
    ArtifactIntegrityResponse,
    ArtifactExtractionBatchResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.artifact_extraction import (
    ArtifactExtractionService,
    ArtifactStorageManager
)

router = APIRouter()


@router.post(
    "/cases/{case_id}/executions/{execution_id}/extract-artifacts",
    response_model=ArtifactExtractionBatchResponse,
    status_code=status.HTTP_200_OK
)
def extract_artifacts_for_execution(
    case_id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Triggers extraction of structured forensic artifacts from all raw outputs produced by an execution.
    Unsupported outputs are recorded as UNSUPPORTED, never silently dropped.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic execution not found")

    if execution.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution does not belong to specified case")

    extracted = ArtifactExtractionService.extract_for_execution(
        db=db,
        execution_id=execution_id,
        case_id=case_id,
        actor_user=current_user
    )

    total_outputs = (
        db.query(ExecutionOutput)
        .filter(ExecutionOutput.execution_id == execution_id, ExecutionOutput.case_id == case_id)
        .count()
    )

    unsupported_count = sum(1 for a in extracted if a.extraction_status == "UNSUPPORTED")
    extracted_count = sum(1 for a in extracted if a.extraction_status == "EXTRACTED")

    return ArtifactExtractionBatchResponse(
        execution_id=execution_id,
        total_raw_outputs=total_outputs,
        processed_outputs=len({a.raw_output_id for a in extracted}),
        extracted_artifacts_count=extracted_count,
        unsupported_outputs_count=unsupported_count,
        artifacts=extracted
    )


@router.post(
    "/cases/{case_id}/raw-outputs/{output_id}/extract-artifacts",
    response_model=List[StructuredArtifactResponse],
    status_code=status.HTTP_200_OK
)
def extract_artifacts_from_raw_output(
    case_id: str,
    output_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Extracts structured artifacts from a specific raw output artifact.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    raw_output = db.query(ExecutionOutput).filter(ExecutionOutput.id == output_id).first()
    if not raw_output:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Raw execution output not found")

    if raw_output.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Raw output does not belong to specified case")

    try:
        return ArtifactExtractionService.extract_from_output(
            db=db,
            raw_output=raw_output,
            actor_user=current_user
        )
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Extraction failed: {ex}")


@router.get(
    "/cases/{case_id}/executions/{execution_id}/artifacts",
    response_model=List[StructuredArtifactResponse]
)
def list_execution_artifacts(
    case_id: str,
    execution_id: str,
    artifact_type: Optional[str] = Query(None, description="Filter by artifact type (e.g. FILESYSTEM_RECORD, PROCESS_RECORD)"),
    extraction_status: Optional[str] = Query(None, description="Filter by status: EXTRACTED, UNSUPPORTED, PARSE_ERROR"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists structured forensic artifacts produced by an execution.
    """
    get_authorized_case(case_id, db, current_user)

    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic execution not found")

    if execution.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution does not belong to specified case")

    return ArtifactExtractionService.list_execution_artifacts(
        db=db,
        execution_id=execution_id,
        case_id=case_id,
        artifact_type=artifact_type,
        extraction_status=extraction_status,
        skip=skip,
        limit=limit
    )


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/artifacts",
    response_model=List[StructuredArtifactResponse]
)
def list_evidence_artifacts(
    case_id: str,
    evidence_id: str,
    artifact_type: Optional[str] = Query(None, description="Filter by artifact type"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all structured forensic artifacts derived from a specific piece of evidence across all executions.
    """
    get_authorized_case(case_id, db, current_user)

    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")

    if evidence.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Evidence does not belong to specified case")

    return ArtifactExtractionService.list_evidence_artifacts(
        db=db,
        evidence_id=evidence_id,
        case_id=case_id,
        artifact_type=artifact_type,
        skip=skip,
        limit=limit
    )


@router.get(
    "/cases/{case_id}/artifacts/{artifact_id}",
    response_model=StructuredArtifactResponse
)
def get_artifact_details(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a structured forensic artifact including normalized payload and provenance references.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return ArtifactExtractionService.get_artifact_details(db=db, artifact_id=artifact_id, case_id=case_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/artifacts/{artifact_id}/integrity",
    response_model=ArtifactIntegrityResponse
)
def verify_artifact_integrity(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic integrity of a structured artifact and checks provenance back to the source raw output.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return ArtifactExtractionService.verify_artifact_integrity(db=db, artifact_id=artifact_id, case_id=case_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/artifacts/{artifact_id}/download"
)
def download_artifact_file(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Downloads the serialized JSON payload of the structured artifact.
    Enforces path isolation and case containment.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        art = ArtifactExtractionService.get_artifact_details(db=db, artifact_id=artifact_id, case_id=case_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    if not art.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact storage path is not defined")

    file_path = Path(art.storage_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file does not exist on disk")

    try:
        ArtifactStorageManager.validate_storage_path(file_path, case_id, art.execution_id)
    except Exception as sec_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied: {sec_err}")

    return FileResponse(
        path=str(file_path),
        filename=f"artifact_{art.artifact_type.lower()}_{art.id[:8]}.json",
        media_type="application/json"
    )
