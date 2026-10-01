"""
ADFIR — Investigator Review REST API Endpoints (Phase 2 / Step 19)

Provides secure, auditable, and RBAC-governed endpoints for human-in-the-loop review:
- Inspect reviewable evidence, deterministic findings, and classified AI reasoning claims
- Submit immutable investigator review decisions (ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE)
- Verify cryptographic SHA-256 integrity and detect tampering of review records
- Trace multi-tier forensic provenance back to raw tool outputs and evidence vault
- Submit controlled REQUEST_MORE_EVIDENCE workflow re-entering the standard analysis pipeline
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    InvestigatorReviewCreateRequest,
    InvestigatorReviewResponse,
    InvestigatorReviewIntegrityResponse,
    RequestMoreEvidenceRequest,
    RequestMoreEvidenceResponse,
    ReviewItemsResponse,
    ClaimProvenanceResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.investigator_review import InvestigatorReviewService

logger = logging.getLogger("ADFIR_REVIEW_API")

router = APIRouter()


@router.get(
    "/cases/{case_id}/review/items",
    response_model=ReviewItemsResponse,
    status_code=status.HTTP_200_OK
)
def get_case_review_items(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves all reviewable items for an authorized case:
    - Evidence items with verification integrity & chain of custody
    - Deterministic findings with verified supporting artifacts
    - AI reasoning records with FACT / INFERENCE / UNVERIFIED classifications
    - Existing review decisions and progress summary
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.get_review_items(db, case, current_user)


@router.post(
    "/cases/{case_id}/review/decisions",
    response_model=InvestigatorReviewResponse,
    status_code=status.HTTP_201_CREATED
)
def submit_review_decision(
    case_id: str,
    payload: InvestigatorReviewCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Records an investigator review decision (ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE).
    Strict Invariant: The original finding or AI reasoning record is NEVER modified or overwritten.
    Persists tamper-detectable SHA-256 hash and audit trace.
    """
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)
    return InvestigatorReviewService.submit_decision(db, case, current_user, payload)


@router.get(
    "/cases/{case_id}/review/decisions",
    response_model=List[InvestigatorReviewResponse],
    status_code=status.HTTP_200_OK
)
@router.get(
    "/cases/{case_id}/reviews",
    response_model=List[InvestigatorReviewResponse],
    status_code=status.HTTP_200_OK
)
def list_review_decisions(
    case_id: str,
    target_id: Optional[str] = Query(None, description="Filter by target finding/reasoning ID"),
    decision: Optional[str] = Query(None, description="Filter by decision: ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists past review decisions and audit records for an authorized case.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.list_reviews(db, case.id, target_id=target_id, decision=decision)


@router.get(
    "/cases/{case_id}/review/decisions/{review_id}",
    response_model=InvestigatorReviewResponse,
    status_code=status.HTTP_200_OK
)
@router.get(
    "/cases/{case_id}/reviews/{review_id}",
    response_model=InvestigatorReviewResponse,
    status_code=status.HTTP_200_OK
)
def get_review_decision(
    case_id: str,
    review_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves a specific review record by ID. Enforces strict case authorization (IDOR protection).
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.get_review(db, case.id, review_id)


@router.get(
    "/cases/{case_id}/review/decisions/{review_id}/integrity",
    response_model=InvestigatorReviewIntegrityResponse,
    status_code=status.HTTP_200_OK
)
@router.get(
    "/cases/{case_id}/reviews/{review_id}/integrity",
    response_model=InvestigatorReviewIntegrityResponse,
    status_code=status.HTTP_200_OK
)
def verify_review_integrity(
    case_id: str,
    review_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Performs real-time cryptographic SHA-256 verification of the review record.
    Detects any database or filesystem tampering.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.verify_integrity(db, case.id, review_id)


@router.get(
    "/cases/{case_id}/review/provenance/{target_id}",
    response_model=ClaimProvenanceResponse,
    status_code=status.HTTP_200_OK
)
def get_claim_provenance(
    case_id: str,
    target_id: str,
    target_type: Optional[str] = Query(None, description="Optional target type hint: FINDING, AI_REASONING"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Traces complete forensic lineage from the claim/finding back through
    supporting artifacts, raw tool execution outputs, and source evidence items.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.get_claim_provenance(db, case.id, target_id, target_type)


@router.post(
    "/cases/{case_id}/review/request-more-evidence",
    response_model=RequestMoreEvidenceResponse,
    status_code=status.HTTP_201_CREATED
)
def request_more_evidence(
    case_id: str,
    payload: RequestMoreEvidenceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Human-in-the-loop investigation directive to request further evidence.
    Passes through Governance Gate and queues an AnalysisRequest in the Scheduler,
    seamlessly re-entering the standard analysis pipeline without creating an out-of-band path.
    """
    case = get_authorized_case(case_id, db, current_user)
    return InvestigatorReviewService.request_more_evidence(db, case, current_user, payload)
