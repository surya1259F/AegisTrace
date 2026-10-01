"""
ADFIR — Normalized Forensic Artifacts API Endpoints (Phase 2 / Step 12)

Case-scoped, RBAC-authorized REST endpoints for:
- Normalizing structured artifacts from executions or single structured artifacts
- Listing normalized artifacts for cases with filters
- Inspecting normalized artifact details, provenance, and schemas
- Cryptographically verifying normalized artifact integrity and source lineage
- Securely downloading serialized normalized artifact JSON payloads
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
    StructuredArtifact,
    NormalizedArtifact,
    User
)
from backend.app.schemas.schemas import (
    NormalizedArtifactResponse,
    NormalizedIntegrityResponse,
    NormalizedProvenanceResponse,
    NormalizationBatchResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.normalization import (
    ArtifactNormalizationService,
    NormalizedStorageManager
)

router = APIRouter()


@router.post(
    "/cases/{case_id}/executions/{execution_id}/normalize-artifacts",
    response_model=NormalizationBatchResponse,
    status_code=status.HTTP_200_OK
)
def normalize_execution_artifacts(
    case_id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Normalizes all structured artifacts produced by an execution into standard NormalizedArtifacts.
    Performs deterministic deduplication while retaining references to all contributing source artifacts.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic execution not found")

    if execution.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution does not belong to specified case")

    result = ArtifactNormalizationService.normalize_execution_artifacts(
        db=db,
        execution_id=execution_id,
        case_id=case_id,
        actor_user=current_user
    )

    return NormalizationBatchResponse(**result)


@router.post(
    "/cases/{case_id}/structured-artifacts/{artifact_id}/normalize",
    response_model=NormalizedArtifactResponse,
    status_code=status.HTTP_200_OK
)
def normalize_single_artifact(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Normalizes a single structured artifact into a NormalizedArtifact.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    sa = db.query(StructuredArtifact).filter(StructuredArtifact.id == artifact_id).first()
    if not sa:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Structured artifact not found")

    if sa.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Structured artifact does not belong to specified case")

    norm_art, _ = ArtifactNormalizationService.normalize_structured_artifact(
        db=db,
        structured_art=sa,
        actor_user=current_user
    )

    return norm_art


@router.get(
    "/cases/{case_id}/normalized-artifacts",
    response_model=List[NormalizedArtifactResponse]
)
def list_normalized_artifacts(
    case_id: str,
    entity_type: Optional[str] = Query(None, description="Filter by entity type (FILE, PROCESS, NETWORK_CONNECTION, EVENT, etc.)"),
    normalization_status: Optional[str] = Query(None, description="Filter by status: NORMALIZED, PARTIAL_IDENTITY, UNSUPPORTED"),
    execution_id: Optional[str] = Query(None, description="Filter by execution ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists normalized forensic artifacts for a case with filtering and pagination.
    """
    get_authorized_case(case_id, db, current_user)

    return ArtifactNormalizationService.list_normalized_artifacts(
        db=db,
        case_id=case_id,
        entity_type=entity_type,
        normalization_status=normalization_status,
        execution_id=execution_id,
        skip=skip,
        limit=limit
    )


@router.get(
    "/cases/{case_id}/normalized-artifacts/{artifact_id}",
    response_model=NormalizedArtifactResponse
)
def get_normalized_artifact_details(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a normalized forensic artifact including normalized payload and multi-source references.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return ArtifactNormalizationService.get_normalized_artifact(
            db=db,
            normalized_id=artifact_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/normalized-artifacts/{artifact_id}/integrity",
    response_model=NormalizedIntegrityResponse
)
def verify_normalized_integrity(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic integrity of a normalized artifact and checks lineage back to source structured artifact.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return ArtifactNormalizationService.verify_normalized_integrity(
            db=db,
            normalized_id=artifact_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/normalized-artifacts/{artifact_id}/provenance",
    response_model=NormalizedProvenanceResponse
)
def get_normalized_provenance(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects full multi-tier provenance and traceability chain for a normalized artifact.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return ArtifactNormalizationService.get_normalized_provenance(
            db=db,
            normalized_id=artifact_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/normalized-artifacts/{artifact_id}/download"
)
def download_normalized_file(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Downloads the serialized JSON file of the normalized artifact.
    Enforces path containment and vault isolation.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        art = ArtifactNormalizationService.get_normalized_artifact(
            db=db,
            normalized_id=artifact_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    if not art.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Normalized artifact storage path not defined")

    file_path = Path(art.storage_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Normalized artifact file does not exist on disk")

    try:
        NormalizedStorageManager.validate_storage_path(file_path, case_id)
    except Exception as sec_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied: {sec_err}")

    return FileResponse(
        path=str(file_path),
        filename=f"normalized_{art.entity_type.lower()}_{art.id[:8]}.json",
        media_type="application/json"
    )
