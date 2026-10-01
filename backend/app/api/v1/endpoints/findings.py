"""ADFIR — Deterministic Findings API Endpoints (Phase 2 / Step 15)

Case-scoped, RBAC-authorized REST endpoints for:
- Generating deterministic findings from observable evidence & Step 14 correlations
- Querying and filtering findings by severity, type, evidence, and confidence
- Inspecting detailed finding provenance, supporting evidence, and cryptographic SHA-256 integrity
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    DeterministicFindingResponse,
    FindingGenerateRequest,
    FindingIntegrityResponse,
    FindingProvenanceResponse,
    FindingSupportingEvidenceResponse,
    FindingSummaryResponse,
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.findings import DeterministicFindingsService

router = APIRouter()


@router.post(
    "/cases/{case_id}/findings/generate",
    response_model=FindingSummaryResponse,
    status_code=status.HTTP_200_OK
)
def generate_findings_for_case(
    case_id: str,
    request: Optional[FindingGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generates evidence-grounded findings from Steps 12-14 before any AI reasoning.
    Enforces case authorization and RBAC boundaries.
    """
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    if request is None:
        request = FindingGenerateRequest()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db,
        case_id=case_id,
        request=request
    )
    return summary


@router.get(
    "/cases/{case_id}/findings",
    response_model=List[DeterministicFindingResponse],
    status_code=status.HTTP_200_OK
)
def list_findings(
    case_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    evidence_id: Optional[str] = Query(None, description="Filter by supporting evidence ID"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    start_time: Optional[datetime] = Query(None, description="Filter findings created after this timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter findings created before this timestamp"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists deterministic findings for a case with multi-criteria filtering.
    """
    get_authorized_case(case_id, db, current_user)

    records = DeterministicFindingsService.list_findings(
        db=db,
        case_id=case_id,
        severity=severity,
        finding_type=finding_type,
        evidence_id=evidence_id,
        min_confidence=min_confidence,
        start_time=start_time,
        end_time=end_time,
        skip=skip,
        limit=limit
    )
    return [DeterministicFindingResponse.model_validate(r) for r in records]


@router.get(
    "/cases/{case_id}/findings/{finding_id}",
    response_model=DeterministicFindingResponse,
    status_code=status.HTTP_200_OK
)
def get_finding_details(
    case_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a specific deterministic finding.
    """
    get_authorized_case(case_id, db, current_user)

    finding = DeterministicFindingsService.get_finding_by_id(db, case_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in case '{case_id}'"
        )
    return DeterministicFindingResponse.model_validate(finding)


@router.get(
    "/cases/{case_id}/findings/{finding_id}/supporting-evidence",
    response_model=FindingSupportingEvidenceResponse,
    status_code=status.HTTP_200_OK
)
def get_finding_supporting_evidence(
    case_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves all underlying artifacts, events, relationships, groups, and evidence items
    that ground this finding.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return DeterministicFindingsService.get_supporting_evidence(db, case_id, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/findings/{finding_id}/provenance",
    response_model=FindingProvenanceResponse,
    status_code=status.HTTP_200_OK
)
def get_finding_provenance(
    case_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Reconstructs the full 7-tier provenance tree linking the finding back to physical evidence.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return DeterministicFindingsService.get_provenance(db, case_id, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/findings/{finding_id}/integrity",
    response_model=FindingIntegrityResponse,
    status_code=status.HTTP_200_OK
)
def verify_finding_integrity(
    case_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Cryptographically verifies SHA-256 integrity of the finding and its disk storage.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return DeterministicFindingsService.verify_integrity(db, case_id, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
