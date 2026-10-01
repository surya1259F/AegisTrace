"""
ADFIR — Governance Gate API Endpoints (Phase 2 / Step 17)

Case-scoped, RBAC-authorized REST endpoints for:
- Evaluating governance policy on actions and agent requests
- Listing and inspecting persistent governance decisions
- Approving or rejecting high-risk actions
- Performing multi-point verification of evidence, raw outputs, and artifacts
- Inspecting verification status and contradiction reports
- Inspecting immutable, hash-chained governance audit trails
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    GovernanceEvaluateRequest,
    GovernanceDecisionResponse,
    GovernanceApprovalRequest,
    GovernanceRejectionRequest,
    EvidenceVerifyRequest,
    EvidenceVerificationResponse,
    GovernanceAuditEventResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.governance import GovernanceGateService

router = APIRouter()


@router.post(
    "/cases/{case_id}/governance/evaluate",
    response_model=GovernanceDecisionResponse,
    status_code=status.HTTP_201_CREATED
)
def evaluate_governance(
    case_id: str,
    payload: GovernanceEvaluateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Evaluates policy for a proposed action or agent request within an authorized case.
    Returns a persistent decision with risk level and approval requirement.
    """
    get_authorized_case(case_id, db, current_user)
    decision = GovernanceGateService.evaluate_governance(
        db=db,
        case_id=case_id,
        action_type=payload.action_type,
        requesting_agent=payload.requesting_agent,
        target_resource_type=payload.target_resource_type,
        target_resource_id=payload.target_resource_id,
        parameters=payload.parameters,
        input_references=payload.input_references,
        content_payload=payload.content_payload,
        user=current_user
    )
    return decision


@router.get(
    "/cases/{case_id}/governance/decisions",
    response_model=List[GovernanceDecisionResponse],
    status_code=status.HTTP_200_OK
)
def list_governance_decisions(
    case_id: str,
    decision_type: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    approval_status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists recorded governance decisions for a case, with optional filtering.
    """
    get_authorized_case(case_id, db, current_user)
    return GovernanceGateService.list_decisions(
        db=db,
        case_id=case_id,
        decision_type=decision_type,
        risk_level=risk_level,
        approval_status=approval_status
    )


@router.get(
    "/cases/{case_id}/governance/decisions/{decision_id}",
    response_model=GovernanceDecisionResponse,
    status_code=status.HTTP_200_OK
)
def get_governance_decision(
    case_id: str,
    decision_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects a specific governance decision by ID.
    """
    get_authorized_case(case_id, db, current_user)
    decision = GovernanceGateService.get_decision(db, decision_id)
    if not decision or decision.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance decision '{decision_id}' not found in case '{case_id}'."
        )
    return decision


@router.post(
    "/cases/{case_id}/governance/decisions/{decision_id}/approve",
    response_model=GovernanceDecisionResponse,
    status_code=status.HTTP_200_OK
)
def approve_governance_decision(
    case_id: str,
    decision_id: str,
    payload: GovernanceApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Explicitly approves a pending high-risk action decision.
    """
    get_authorized_case(case_id, db, current_user)
    decision = GovernanceGateService.get_decision(db, decision_id)
    if not decision or decision.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance decision '{decision_id}' not found in case '{case_id}'."
        )
    try:
        return GovernanceGateService.approve_decision(
            db=db,
            decision_id=decision_id,
            user=current_user,
            notes=payload.notes
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/cases/{case_id}/governance/decisions/{decision_id}/reject",
    response_model=GovernanceDecisionResponse,
    status_code=status.HTTP_200_OK
)
def reject_governance_decision(
    case_id: str,
    decision_id: str,
    payload: GovernanceRejectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Explicitly rejects a pending governance decision.
    """
    get_authorized_case(case_id, db, current_user)
    decision = GovernanceGateService.get_decision(db, decision_id)
    if not decision or decision.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance decision '{decision_id}' not found in case '{case_id}'."
        )
    try:
        return GovernanceGateService.reject_decision(
            db=db,
            decision_id=decision_id,
            user=current_user,
            reason=payload.reason
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/cases/{case_id}/governance/verify",
    response_model=EvidenceVerificationResponse,
    status_code=status.HTTP_201_CREATED
)
def verify_evidence_or_artifact(
    case_id: str,
    payload: EvidenceVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Conducts forensic verification on an evidence item, raw output, structured artifact,
    or normalized artifact, checking integrity, lineage, and contradictions.
    """
    get_authorized_case(case_id, db, current_user)
    try:
        return GovernanceGateService.verify_target(
            db=db,
            case_id=case_id,
            target_type=payload.target_type,
            target_id=payload.target_id,
            notes=payload.notes,
            user=current_user
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/cases/{case_id}/governance/verifications",
    response_model=List[EvidenceVerificationResponse],
    status_code=status.HTTP_200_OK
)
def list_verifications(
    case_id: str,
    target_type: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists verification records for a case.
    """
    get_authorized_case(case_id, db, current_user)
    return GovernanceGateService.list_verifications(
        db=db,
        case_id=case_id,
        target_type=target_type,
        status=status_filter
    )


@router.get(
    "/cases/{case_id}/governance/verifications/{verification_id}",
    response_model=EvidenceVerificationResponse,
    status_code=status.HTTP_200_OK
)
def get_verification_details(
    case_id: str,
    verification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects detailed verification results including lineage and contradiction details.
    """
    get_authorized_case(case_id, db, current_user)
    ver = GovernanceGateService.get_verification(db, verification_id)
    if not ver or ver.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification record '{verification_id}' not found in case '{case_id}'."
        )
    return ver


@router.get(
    "/cases/{case_id}/governance/audit",
    response_model=List[GovernanceAuditEventResponse],
    status_code=status.HTTP_200_OK
)
def list_governance_audit_events(
    case_id: str,
    decision_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves the immutable, hash-chained audit events for the case or a specific decision.
    """
    get_authorized_case(case_id, db, current_user)
    return GovernanceGateService.list_audit_events(
        db=db,
        case_id=case_id,
        decision_id=decision_id
    )


@router.get(
    "/cases/{case_id}/governance/decisions/{decision_id}/audit",
    response_model=List[GovernanceAuditEventResponse],
    status_code=status.HTTP_200_OK
)
def get_decision_audit_trail(
    case_id: str,
    decision_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects the audit trail for a specific governance decision.
    """
    get_authorized_case(case_id, db, current_user)
    return GovernanceGateService.list_audit_events(
        db=db,
        case_id=case_id,
        decision_id=decision_id
    )
