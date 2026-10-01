"""
ADFIR — Specialist Agent Layer API Endpoints (Phase 2 / Step 16)

Case-scoped, RBAC-authorized REST endpoints for:
- Listing and inspecting registered specialist agents and their capabilities
- Toggling agent availability (enable/disable)
- Creating and scheduling structured agent analysis requests
- Executing agent analyses and retrieving grounded observations
- Gating capability requests through Step 7 registry validation
- Inspecting 7-tier provenance and verifying cryptographic SHA-256 integrity
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    User,
    AgentAnalysisRequestRecord,
    AgentAnalysisResultRecord,
    AgentCapabilityRequestRecord
)
from backend.app.schemas.schemas import (
    SpecialistAgentResponse,
    AgentToggleRequest,
    AgentAnalysisRequestCreate,
    AgentAnalysisRequestResponse,
    AgentAnalysisResultResponse,
    AgentCapabilityRequestCreate,
    AgentCapabilityRequestResponse,
    AgentIntegrityCheckResponse,
    AgentProvenanceTraceResponse,
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.agents import SpecialistAgentService

router = APIRouter()


@router.get(
    "/cases/{case_id}/agents",
    response_model=List[SpecialistAgentResponse],
    status_code=status.HTTP_200_OK
)
def list_specialist_agents(
    case_id: str,
    enabled_only: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all registered specialist forensic agents with their capabilities,
    domains, artifact types, and safety profiles.
    """
    get_authorized_case(case_id, db, current_user)
    return SpecialistAgentService.list_agents(db=db, enabled_only=enabled_only)


@router.get(
    "/cases/{case_id}/agents/{agent_id}",
    response_model=SpecialistAgentResponse,
    status_code=status.HTTP_200_OK
)
def get_specialist_agent(
    case_id: str,
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects a specific specialist agent definition.
    """
    get_authorized_case(case_id, db, current_user)
    agent = SpecialistAgentService.get_agent(db=db, agent_id=agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Specialist agent '{agent_id}' not found."
        )
    return agent


@router.post(
    "/cases/{case_id}/agents/{agent_id}/toggle",
    response_model=SpecialistAgentResponse,
    status_code=status.HTTP_200_OK
)
def toggle_specialist_agent(
    case_id: str,
    agent_id: str,
    request: AgentToggleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Enables or disables a specialist agent.
    """
    get_authorized_case(case_id, db, current_user)
    try:
        agent = SpecialistAgentService.toggle_agent(
            db=db,
            agent_id=agent_id,
            is_enabled=request.is_enabled,
            user=current_user
        )
        return agent
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/cases/{case_id}/agents/analysis-requests",
    response_model=AgentAnalysisRequestResponse,
    status_code=status.HTTP_201_CREATED
)
def create_analysis_request(
    case_id: str,
    request: AgentAnalysisRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Creates an auditable agent analysis request within a case.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)
    try:
        record = SpecialistAgentService.create_analysis_request(
            db=db,
            case_id=case_id,
            agent_id=request.agent_id,
            analysis_objective=request.analysis_objective,
            evidence_id=request.evidence_id,
            input_references=request.input_references,
            user=current_user
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/cases/{case_id}/agents/analysis-requests",
    response_model=List[AgentAnalysisRequestResponse],
    status_code=status.HTTP_200_OK
)
def list_analysis_requests(
    case_id: str,
    agent_id: Optional[str] = Query(default=None),
    lifecycle_state: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all agent analysis requests for a case.
    """
    get_authorized_case(case_id, db, current_user)
    query = db.query(AgentAnalysisRequestRecord).filter(
        AgentAnalysisRequestRecord.case_id == case_id
    )
    if agent_id:
        query = query.filter(AgentAnalysisRequestRecord.agent_id == agent_id)
    if lifecycle_state:
        query = query.filter(AgentAnalysisRequestRecord.lifecycle_state == lifecycle_state)
    return query.order_by(AgentAnalysisRequestRecord.created_at.desc()).all()


@router.get(
    "/cases/{case_id}/agents/analysis-requests/{request_id}",
    response_model=AgentAnalysisRequestResponse,
    status_code=status.HTTP_200_OK
)
def get_analysis_request(
    case_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects an analysis request.
    """
    get_authorized_case(case_id, db, current_user)
    req = db.query(AgentAnalysisRequestRecord).filter(
        AgentAnalysisRequestRecord.id == request_id,
        AgentAnalysisRequestRecord.case_id == case_id
    ).first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis request '{request_id}' not found."
        )
    return req


@router.post(
    "/cases/{case_id}/agents/analysis-requests/{request_id}/execute",
    response_model=AgentAnalysisResultResponse,
    status_code=status.HTTP_200_OK
)
def execute_analysis_request(
    case_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Triggers deterministic structured execution of an analysis request.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)
    # Ensure request belongs to case
    req = db.query(AgentAnalysisRequestRecord).filter(
        AgentAnalysisRequestRecord.id == request_id,
        AgentAnalysisRequestRecord.case_id == case_id
    ).first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis request '{request_id}' not found in case '{case_id}'."
        )

    try:
        result = SpecialistAgentService.execute_analysis(
            db=db,
            request_id=request_id,
            user=current_user
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis execution failed: {str(e)}"
        )


@router.get(
    "/cases/{case_id}/agents/analysis-results",
    response_model=List[AgentAnalysisResultResponse],
    status_code=status.HTTP_200_OK
)
def list_analysis_results(
    case_id: str,
    agent_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all agent analysis results for a case.
    """
    get_authorized_case(case_id, db, current_user)
    query = db.query(AgentAnalysisResultRecord).filter(
        AgentAnalysisResultRecord.case_id == case_id
    )
    if agent_id:
        query = query.filter(AgentAnalysisResultRecord.agent_id == agent_id)
    return query.order_by(AgentAnalysisResultRecord.created_at.desc()).all()


@router.post(
    "/cases/{case_id}/agents/capability-requests",
    response_model=AgentCapabilityRequestResponse,
    status_code=status.HTTP_201_CREATED
)
def submit_capability_request(
    case_id: str,
    request_id: str,
    agent_id: str,
    request: AgentCapabilityRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Submits a gated capability request on behalf of an agent.
    Validates against the Step 7 capability registry and rejects arbitrary commands.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)
    try:
        cap_record = SpecialistAgentService.submit_capability_request(
            db=db,
            case_id=case_id,
            agent_id=agent_id,
            request_id=request_id,
            capability_id=request.capability_id,
            evidence_id=request.evidence_id,
            parameters=request.parameters,
            rationale=request.rationale,
            priority=request.priority,
            user=current_user
        )
        return cap_record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/cases/{case_id}/agents/capability-requests",
    response_model=List[AgentCapabilityRequestResponse],
    status_code=status.HTTP_200_OK
)
def list_capability_requests(
    case_id: str,
    validation_status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists capability requests for a case.
    """
    get_authorized_case(case_id, db, current_user)
    query = db.query(AgentCapabilityRequestRecord).filter(
        AgentCapabilityRequestRecord.case_id == case_id
    )
    if validation_status:
        query = query.filter(AgentCapabilityRequestRecord.validation_status == validation_status)
    return query.order_by(AgentCapabilityRequestRecord.created_at.desc()).all()


@router.get(
    "/cases/{case_id}/agents/analysis-results/{result_id}/integrity",
    response_model=AgentIntegrityCheckResponse,
    status_code=status.HTTP_200_OK
)
def verify_result_integrity(
    case_id: str,
    result_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic SHA-256 integrity of an agent analysis result.
    """
    get_authorized_case(case_id, db, current_user)
    try:
        check = SpecialistAgentService.verify_result_integrity(db=db, result_id=result_id)
        return check
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/agents/analysis-requests/{request_id}/provenance",
    response_model=AgentProvenanceTraceResponse,
    status_code=status.HTTP_200_OK
)
def get_analysis_provenance_trace(
    case_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full 7-tier provenance trace for an agent analysis request.
    """
    get_authorized_case(case_id, db, current_user)
    try:
        trace = SpecialistAgentService.get_provenance_trace(db=db, request_id=request_id)
        return trace
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
