"""
ADFIR — AI Reasoning Layer & Copilot API Endpoints (Phase 2 / Step 18)

Governed AI reasoning downstream of verified forensic structure.
Endpoints for:
- AI provider configuration, removal, and health status
- Provider connection testing without secret leakage
- Governed reasoning creation with FACT / INFERENCE / UNVERIFIED classification
- Retrieval of reasoning records and classified insights
- Cryptographic SHA-256 integrity verification and tamper detection
- Lineage, governance, and citation provenance inspection
- Backward-compatible Copilot endpoints
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import User, AIReasoningRecord
from backend.app.schemas.schemas import (
    CopilotQueryRequest,
    ExplainFindingRequest,
    ProviderTestRequest,
    ProviderTestResponse,
    EgressPolicy,
    AIProviderConfigRequest,
    AIProviderConfigResponse,
    AIProviderConnectionTestRequest,
    AIProviderConnectionTestResponse,
    AIReasoningRequest,
    AIReasoningResponse,
    AIStatementItem,
    AIReasoningIntegrityResponse,
    AIReasoningProvenanceResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.ai_copilot import (
    AICopilotResponse,
    AIExplanationResponse,
    run_copilot_query,
    explain_case_finding
)
from backend.app.services.ai_provider import (
    ProviderRequest,
    ProviderError,
    get_ai_adapter
)
from backend.app.services.ai_reasoning import (
    AIReasoningService,
    mask_credential,
    decrypt_credential
)
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_AI_API")

router = APIRouter()

EXTERNAL_PROVIDERS = {"openai", "anthropic", "google", "gemini"}


def _resolve_effective_provider(requested_provider: Optional[str], egress_policy: EgressPolicy) -> str:
    p_clean = (requested_provider or "local_stub").lower().strip()
    if egress_policy in (EgressPolicy.LOCAL_ONLY, EgressPolicy.EXTERNAL_PROVIDER_BLOCKED):
        if p_clean in EXTERNAL_PROVIDERS:
            logger.info(f"Egress policy {egress_policy.value} blocked external provider '{p_clean}'. Redirecting to local_stub.")
            return "local_stub"
    return p_clean


# =============================================================================
# 1. AI PROVIDER CONFIGURATION & STATUS ENDPOINTS
# =============================================================================

@router.post("/provider/config", response_model=AIProviderConfigResponse, status_code=status.HTTP_200_OK)
@router.post("/ai/provider/config", response_model=AIProviderConfigResponse, status_code=status.HTTP_200_OK)
def configure_provider(
    payload: AIProviderConfigRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Configures or updates the LLM provider and securely encrypts credentials.
    API keys are never logged or returned in plaintext.
    """
    rec = AIReasoningService.configure_provider(db, current_user, payload)
    return AIProviderConfigResponse(
        id=rec.id,
        provider=rec.provider,
        model=rec.model,
        endpoint=rec.endpoint,
        has_api_key=bool(rec.api_key_encrypted),
        masked_api_key=mask_credential(decrypt_credential(rec.api_key_encrypted)),
        is_enabled=rec.is_enabled,
        status=rec.status,
        last_tested_at=rec.last_tested_at,
        last_test_status=rec.last_test_status,
        created_at=rec.created_at,
        updated_at=rec.updated_at
    )


@router.get("/provider/config", response_model=AIProviderConfigResponse)
@router.get("/ai/provider/config", response_model=AIProviderConfigResponse)
def get_provider_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves current user's provider configuration with masked API key.
    """
    rec = AIReasoningService.get_provider_config(db, current_user)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No AI provider configured.")
    return AIProviderConfigResponse(
        id=rec.id,
        provider=rec.provider,
        model=rec.model,
        endpoint=rec.endpoint,
        has_api_key=bool(rec.api_key_encrypted),
        masked_api_key=mask_credential(decrypt_credential(rec.api_key_encrypted)),
        is_enabled=rec.is_enabled,
        status=rec.status,
        last_tested_at=rec.last_tested_at,
        last_test_status=rec.last_test_status,
        created_at=rec.created_at,
        updated_at=rec.updated_at
    )


@router.delete("/provider/config", status_code=status.HTTP_200_OK)
@router.delete("/ai/provider/config", status_code=status.HTTP_200_OK)
def remove_provider_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Removes stored provider configuration and encrypted credentials.
    """
    removed = AIReasoningService.remove_provider_config(db, current_user)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No AI provider configuration found to remove.")
    return {"status": "SUCCESS", "message": "AI provider configuration and credentials removed successfully."}


@router.get("/provider/status")
@router.get("/ai/provider/status")
def get_provider_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns current provider health and operational status.
    """
    rec = AIReasoningService.get_provider_config(db, current_user)
    if not rec:
        return {
            "status": "UNCONFIGURED",
            "provider": "local_stub",
            "model": "adfir-deterministic-engine",
            "is_enabled": False,
            "has_api_key": False,
            "fallback_available": True
        }
    return {
        "status": rec.status,
        "provider": rec.provider,
        "model": rec.model,
        "is_enabled": rec.is_enabled,
        "has_api_key": bool(rec.api_key_encrypted),
        "last_tested_at": rec.last_tested_at.isoformat() if rec.last_tested_at else None,
        "last_test_status": rec.last_test_status,
        "fallback_available": True
    }


@router.post("/provider/test-connection", response_model=AIProviderConnectionTestResponse)
@router.post("/ai/provider/test-connection", response_model=AIProviderConnectionTestResponse)
async def test_provider_connection_endpoint(
    request: Optional[AIProviderConnectionTestRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Tests provider connectivity and authentication without leaking credentials.
    """
    return await AIReasoningService.test_connection(db, current_user, request)


# Legacy provider test endpoint compatibility
@router.post("/provider/test", response_model=ProviderTestResponse)
@router.post("/ai/provider/test", response_model=ProviderTestResponse)
async def provider_test_endpoint(
    request: ProviderTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    p_clean = request.provider.lower().strip()
    if not p_clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider name is required.")

    status_str = "SUCCESS"
    details_str = "Local stub provider is available."
    model_str = request.model or "adfir-deterministic-engine"

    if p_clean not in ("local_stub", "none"):
        try:
            adapter = get_ai_adapter(p_clean)
            target_model = request.model or adapter.default_model
            test_req = ProviderRequest(
                provider=adapter.provider_id,
                model=target_model,
                prompt="ADFIR connectivity test check.",
                api_key=request.api_key,
                base_url=request.base_url
            )
            resp = await adapter.generate(test_req)
            status_str = "SUCCESS"
            details_str = f"Provider connection verified. Response generated successfully."
            model_str = target_model
        except Exception as e:
            status_str = "FAILED"
            details_str = f"Provider test failed: {ProviderError._sanitize(str(e))}"
            model_str = request.model or "unknown"

    log_audit_event(
        db=db,
        event_type="AI_PROVIDER_TEST",
        details=f"AI provider connectivity test for '{p_clean}' (status: {status_str})",
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={
            "provider": p_clean,
            "model": model_str,
            "status": status_str
        }
    )

    return ProviderTestResponse(
        provider=p_clean,
        model=model_str,
        status=status_str,
        details=details_str
    )


# =============================================================================
# 2. GOVERNED AI REASONING ENDPOINTS
# =============================================================================

@router.post("/cases/{case_id}/reason", response_model=AIReasoningResponse, status_code=status.HTTP_201_CREATED)
@router.post("/cases/{case_id}/ai/reason", response_model=AIReasoningResponse, status_code=status.HTTP_201_CREATED)
async def create_reasoning_request(
    case_id: str,
    payload: AIReasoningRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Initiates governed AI reasoning over verified structured forensic data.
    Enforces Governance Gate, prompt injection checks, and citation verification.
    """
    case = get_authorized_case(case_id, db, current_user)
    return await AIReasoningService.reason(db, case, current_user, payload)


@router.get("/cases/{case_id}/reasoning", response_model=List[AIReasoningResponse])
@router.get("/cases/{case_id}/ai/reasoning", response_model=List[AIReasoningResponse])
def list_reasoning_records(
    case_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists historical reasoning records for an authorized case.
    """
    case = get_authorized_case(case_id, db, current_user)
    records = db.query(AIReasoningRecord).filter(
        AIReasoningRecord.case_id == case.id
    ).order_by(AIReasoningRecord.created_at.desc()).offset(offset).limit(limit).all()

    return [
        AIReasoningResponse(
            id=r.id,
            case_id=r.case_id,
            objective=r.objective,
            status=r.status,
            execution_mode=r.execution_mode,
            provider=r.provider,
            model=r.model,
            governance_decision_id=r.governance_decision_id,
            input_references=r.input_references or {},
            raw_evidence_egress_blocked=r.raw_evidence_egress_blocked,
            egress_approved=r.egress_approved,
            statements=[AIStatementItem(**s) for s in (r.statements or [])],
            citations_verified=r.citations_verified,
            summary=r.summary,
            provenance=r.provenance or {},
            reasoning_metadata=r.reasoning_metadata or {},
            sha256_hash=r.sha256_hash,
            created_at=r.created_at,
            completed_at=r.completed_at
        ) for r in records
    ]


@router.get("/cases/{case_id}/reasoning/{reasoning_id}", response_model=AIReasoningResponse)
@router.get("/cases/{case_id}/ai/reasoning/{reasoning_id}", response_model=AIReasoningResponse)
def get_reasoning_record(
    case_id: str,
    reasoning_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a specific AI reasoning record including classified statements.
    """
    case = get_authorized_case(case_id, db, current_user)
    rec = db.query(AIReasoningRecord).filter(
        AIReasoningRecord.id == reasoning_id,
        AIReasoningRecord.case_id == case.id
    ).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI reasoning record not found.")

    return AIReasoningResponse(
        id=rec.id,
        case_id=rec.case_id,
        objective=rec.objective,
        status=rec.status,
        execution_mode=rec.execution_mode,
        provider=rec.provider,
        model=rec.model,
        governance_decision_id=rec.governance_decision_id,
        input_references=rec.input_references or {},
        raw_evidence_egress_blocked=rec.raw_evidence_egress_blocked,
        egress_approved=rec.egress_approved,
        statements=[AIStatementItem(**s) for s in (rec.statements or [])],
        citations_verified=rec.citations_verified,
        summary=rec.summary,
        provenance=rec.provenance or {},
        reasoning_metadata=rec.reasoning_metadata or {},
        sha256_hash=rec.sha256_hash,
        created_at=rec.created_at,
        completed_at=rec.completed_at
    )


@router.get("/cases/{case_id}/reasoning/{reasoning_id}/integrity", response_model=AIReasoningIntegrityResponse)
@router.get("/cases/{case_id}/ai/reasoning/{reasoning_id}/integrity", response_model=AIReasoningIntegrityResponse)
def get_reasoning_integrity(
    case_id: str,
    reasoning_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies SHA-256 integrity hash of generated reasoning statements.
    Detects tampering or unauthorized modification.
    """
    get_authorized_case(case_id, db, current_user)
    return AIReasoningService.verify_integrity(db, case_id, reasoning_id)


@router.get("/cases/{case_id}/reasoning/{reasoning_id}/provenance", response_model=AIReasoningProvenanceResponse)
@router.get("/cases/{case_id}/ai/reasoning/{reasoning_id}/provenance", response_model=AIReasoningProvenanceResponse)
def get_reasoning_provenance(
    case_id: str,
    reasoning_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects complete provenance, Governance Gate linkage, and input references.
    """
    case = get_authorized_case(case_id, db, current_user)
    rec = db.query(AIReasoningRecord).filter(
        AIReasoningRecord.id == reasoning_id,
        AIReasoningRecord.case_id == case.id
    ).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI reasoning record not found.")

    return AIReasoningProvenanceResponse(
        reasoning_id=rec.id,
        case_id=rec.case_id,
        governance_decision_id=rec.governance_decision_id,
        provider=rec.provider,
        model=rec.model,
        execution_mode=rec.execution_mode,
        input_references=rec.input_references or {},
        statements_count=len(rec.statements or []),
        raw_evidence_egress_blocked=rec.raw_evidence_egress_blocked,
        sha256_hash=rec.sha256_hash,
        created_at=rec.created_at
    )


# =============================================================================
# 3. LEGACY COPILOT ENDPOINTS (BACKWARD COMPATIBILITY)
# =============================================================================

@router.post("/copilot", response_model=AICopilotResponse)
@router.post("/ai/copilot", response_model=AICopilotResponse)
async def copilot_query_endpoint(
    request: CopilotQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(request.case_id, db, current_user)
    effective_provider = _resolve_effective_provider(request.provider, request.egress_policy)

    res = await run_copilot_query(
        case_id=case.id,
        query=request.query,
        db=db,
        provider=effective_provider,
        model=request.model,
        api_key=request.api_key,
        base_url=request.base_url
    )

    log_audit_event(
        db=db,
        event_type="AI_COPILOT_QUERY",
        details=f"AI Copilot query executed for case {case.id} using provider {res.provider}",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={
            "provider": res.provider,
            "model": res.model,
            "execution_mode": res.execution_mode,
            "fallback_used": res.fallback_used,
            "claims_count": len(res.claims)
        }
    )
    return res


@router.post("/explain-finding", response_model=AIExplanationResponse)
@router.post("/ai/explain-finding", response_model=AIExplanationResponse)
async def explain_finding_endpoint(
    request: ExplainFindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(request.case_id, db, current_user)
    effective_provider = _resolve_effective_provider(request.provider, request.egress_policy)

    res = await explain_case_finding(
        case_id=case.id,
        finding_id=request.finding_id,
        db=db,
        provider=effective_provider,
        model=request.model,
        api_key=request.api_key,
        base_url=request.base_url
    )

    log_audit_event(
        db=db,
        event_type="AI_EXPLAIN_FINDING",
        details=f"AI finding explanation for finding {request.finding_id} in case {case.id}",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={
            "finding_id": request.finding_id,
            "provider": res.provider,
            "model": res.model
        }
    )
    return res
