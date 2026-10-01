import uuid
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.models import (
    Case,
    EvidenceItem,
    ChainOfCustodyEvent,
    Finding,
    ExecutionArtifact,
    ToolExecution,
    InvestigatorDecision,
    Report,
    AuditEvent,
    CorrelationGroup,
    InvestigationPlan
)
from backend.app.schemas.schemas import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    InvestigationCreate,
    InvestigationResponse,
    EvidenceIntakeRequest,
    EvidenceResponse,
    EvidenceVerificationResponse,
    EvidenceIntelligenceResponse,
    CustodyRecord,
    FindingCreate,
    FindingResponse,
    ArtifactResponse,
    DiskAnalysisRequest,
    DiskAnalysisResponse,
    MemoryAnalysisRequest,
    MemoryAnalysisResponse,
    MalwareAnalysisRequest,
    MalwareAnalysisResponse,
    LogAnalysisRequest,
    LogAnalysisResponse,
    YaraRuleResponse,
    PlanTaskStep,
    InvestigationPlanResponse,
    PlanExecutionResponse,
    CorrelatedGroupResponse,
    VerificationResultResponse,
    InvestigatorDecisionCreate,
    InvestigatorDecisionResponse,
    ReportResponse,
    TaskCancelResponse,
    ToolExecutionResponse,
    CaseMemberAddRequest,
    CaseMemberResponse
)
from backend.app.core.security import get_current_active_user, SecurityValidator
from backend.app.models.models import CaseMember, User
from backend.app.services.authorization import get_authorized_case, get_user_cases, ensure_case_member, require_case_admin, is_case_admin, validate_case_member_role
from backend.app.services.integrity import calculate_sha256
from backend.app.services.audit import log_audit_event
from backend.app.services.custody import record_custody_event
from backend.app.services.vault import stage_evidence_to_vault, validate_vault_storage_path
from backend.app.services.case_closure import check_case_not_closed, CaseClosureService
from agents.disk.disk_agent import DiskAgent
from agents.memory.memory_agent import MemoryAgent
from agents.malware.malware_agent import MalwareAgent
from agents.log.log_agent import LogAgent
from forensic_tools.yara.rules_manager import yara_rule_repo
from investigation.planner.planner import InvestigationPlanner
from investigation.orchestrator.orchestrator import InvestigationOrchestrator
from investigation.correlation.engine import CorrelationEngine
from investigation.verification.engine import VerificationEngine
from investigation.reporting.generator import ReportGenerator

router = APIRouter()

disk_agent = DiskAgent()
memory_agent = MemoryAgent()
malware_agent = MalwareAgent()
log_agent = LogAgent()
planner_service = InvestigationPlanner()
orchestrator_service = InvestigationOrchestrator(
    disk_agent=disk_agent,
    memory_agent=memory_agent,
    malware_agent=malware_agent,
    log_agent=log_agent,
    planner=planner_service
)
correlation_service = CorrelationEngine()
verification_service = VerificationEngine()
report_generator_service = ReportGenerator()

def _populate_counts(case: Case, db: Session) -> CaseResponse:
    ev_count = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).count()
    f_count = db.query(Finding).filter(Finding.case_id == case.id).count()
    art_count = db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == case.id).count()
    return CaseResponse(
        id=case.id,
        case_number=case.case_number,
        name=case.name,
        description=case.description,
        status=case.status,
        created_by=case.created_by,
        created_at=case.created_at,
        updated_at=case.updated_at,
        evidence_count=ev_count,
        findings_count=f_count,
        artifacts_count=art_count
    )

def _validate_case_and_evidence(case_id: str, evidence_id: str, db: Session, current_user: User = None) -> tuple[Case, EvidenceItem]:
    if current_user:
        case = get_authorized_case(case_id, db, current_user)
    else:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found.")

    check_case_not_closed(case)

    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    if evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found in this case.")

    # Mandatory Pre-Analysis Integrity Gate: Verify vault path validity and cryptographic SHA-256 hash
    is_valid_vault, err_msg = validate_vault_storage_path(evidence.storage_path, evidence.original_path)
    if not is_valid_vault:
        evidence.integrity_status = "FAILED"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VIOLATION",
            description=f"Pre-analysis gate failed: {err_msg}",
            source_path=evidence.original_path,
            destination_path=evidence.storage_path
        )
        log_audit_event(
            db=db,
            case_id=case.id,
            event_type="EVIDENCE_INTEGRITY_VIOLATION",
            details=f"Pre-analysis gate failed for evidence '{evidence.name}' (ID {evidence.id}): {err_msg}"
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Evidence integrity compromised: {err_msg}"
        )

    target_path = str(Path(evidence.storage_path).resolve())

    try:
        current_hash, _ = calculate_sha256(target_path)
    except Exception as e:
        evidence.integrity_status = "FAILED"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Evidence integrity compromised: Failed to hash evidence file: {str(e)}"
        )

    if current_hash.lower() != evidence.sha256.lower():
        evidence.integrity_status = "FAILED"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VIOLATION",
            description=f"Pre-analysis cryptographic hash mismatch for '{evidence.name}'. Baseline: {evidence.sha256}, Current: {current_hash}",
            source_path=evidence.original_path,
            destination_path=evidence.storage_path,
            sha256=current_hash
        )
        log_audit_event(
            db=db,
            case_id=case.id,
            event_type="EVIDENCE_INTEGRITY_VIOLATION",
            details=f"Pre-analysis hash mismatch for evidence '{evidence.name}' (ID {evidence.id}). Baseline: {evidence.sha256}, Current: {current_hash}."
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Evidence integrity compromised: Cryptographic SHA-256 hash mismatch. Baseline: {evidence.sha256}, Current: {current_hash}."
        )

    record_custody_event(
        db=db,
        case_id=case.id,
        evidence_id=evidence.id,
        event_type="INTEGRITY_VERIFIED_PRE_ANALYSIS",
        description=f"Pre-analysis cryptographic integrity verified for '{evidence.name}' (SHA-256: {current_hash}).",
        destination_path=target_path,
        sha256=current_hash
    )

    return case, evidence

def _enforce_post_analysis_gate(case: Case, evidence: EvidenceItem, target_path: str, execution: ToolExecution, db: Session):
    """
    Mandatory Post-Analysis Cryptographic Integrity Gate:
    Re-verifies the evidence hash to prove that tool execution did not alter a single byte.
    """
    post_hash, _ = calculate_sha256(target_path)
    if post_hash.lower() != evidence.sha256.lower():
        evidence.integrity_status = "FAILED"
        execution.status = "FAILED"
        execution.error_message = "Post-analysis integrity check failed: Evidence modified during tool execution."
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VIOLATION",
            description=f"CRITICAL: Post-analysis tampering detected! Hash changed from {evidence.sha256} to {post_hash} during tool execution.",
            destination_path=target_path,
            sha256=post_hash
        )
        log_audit_event(
            db=db,
            case_id=case.id,
            event_type="EVIDENCE_INTEGRITY_VIOLATION",
            details=f"Post-analysis hash mismatch for evidence '{evidence.name}' (ID {evidence.id}). Baseline: {evidence.sha256}, Post-Execution: {post_hash}."
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CRITICAL: Evidence was modified during analysis! Baseline: {evidence.sha256}, Post-Execution: {post_hash}."
        )

    record_custody_event(
        db=db,
        case_id=case.id,
        evidence_id=evidence.id,
        event_type="INTEGRITY_VERIFIED_POST_ANALYSIS",
        description=f"Post-analysis cryptographic integrity confirmed for '{evidence.name}' (SHA-256: {post_hash}). Zero bytes altered.",
        destination_path=target_path,
        sha256=post_hash
    )

# -----------------------------------------------------------------------------
# Case Management Endpoints
# -----------------------------------------------------------------------------

@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case_num = case_in.case_number or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    new_case = Case(
        name=case_in.name or case_in.title or f"Case {case_num}",
        description=case_in.description,
        case_number=case_num,
        owner_id=current_user.id,
        created_by=current_user.email,
        status="OPEN"
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Automatically record creator as PRIMARY_INVESTIGATOR CaseMember
    ensure_case_member(case_id=new_case.id, user_id=current_user.id, db=db, role="PRIMARY_INVESTIGATOR")

    log_audit_event(
        db=db,
        case_id=new_case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CASE_CREATED",
        details=f"Case '{new_case.name}' initialized with ID {new_case.id} (Number: {case_num})"
    )

    return _populate_counts(new_case, db)

@router.get("/", response_model=List[CaseResponse])
def get_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cases = get_user_cases(db, current_user)
    return [_populate_counts(c, db) for c in cases]

@router.get("/{id}", response_model=CaseResponse)
def get_case(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return _populate_counts(case, db)

@router.patch("/{id}", response_model=CaseResponse)
def update_case(
    id: str,
    case_in: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed, CaseClosureService
    from backend.app.schemas.schemas import CaseClosureRequest
    check_case_not_closed(case)

    if case_in.name is not None:
        case.name = case_in.name
    if case_in.description is not None:
        case.description = case_in.description
    if case_in.status is not None:
        new_status = case_in.status.upper().strip()
        if new_status == "CLOSED":
            CaseClosureService.validate_and_close_case(
                db=db,
                case_id=case.id,
                user=current_user,
                request_data=CaseClosureRequest(rationale=f"Case closed by {current_user.email} via legacy case management API")
            )
            return _populate_counts(case, db)
        elif new_status == "ARCHIVED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active cases cannot be directly archived. The case must first be formally closed."
            )
        else:
            case.status = new_status

    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(case)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CASE_UPDATED",
        details=f"Case metadata updated. Status: {case.status}"
    )

    return _populate_counts(case, db)

@router.post("/{id}/close", response_model=CaseResponse)
def close_case(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    from backend.app.services.case_closure import CaseClosureService
    from backend.app.schemas.schemas import CaseClosureRequest
    CaseClosureService.validate_and_close_case(
        db=db,
        case_id=case.id,
        user=current_user,
        request_data=CaseClosureRequest(rationale=f"Case closed by {current_user.email} via legacy case management API")
    )
    return _populate_counts(case, db)

@router.post("/{id}/archive", response_model=CaseResponse)
def archive_case(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    if case.status != "CLOSED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active cases cannot be directly archived. The case must first be formally closed."
        )

    case.status = "ARCHIVED"
    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(case)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CASE_ARCHIVED",
        details=f"Case '{case.name}' moved to immutable long-term archive."
    )
    return _populate_counts(case, db)

@router.get("/{id}/members", response_model=List[CaseMemberResponse])
def get_case_members(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(CaseMember).filter(CaseMember.case_id == case.id).all()

@router.post("/{id}/members", response_model=CaseMemberResponse, status_code=status.HTTP_201_CREATED)
def add_case_member(
    id: str,
    member_in: CaseMemberAddRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)
    require_case_admin(case, db, current_user)

    target_user = db.query(User).filter(User.id == member_in.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    member = ensure_case_member(case_id=case.id, user_id=target_user.id, db=db, role=member_in.role or "COLLABORATOR")

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CASE_MEMBER_ADDED",
        details=f"User '{target_user.email}' added to case '{case.name}' as {member.role}."
    )
    return member

@router.delete("/{id}/members/{user_id}")
def remove_case_member(
    id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)
    require_case_admin(case, db, current_user)

    member = db.query(CaseMember).filter(CaseMember.case_id == case.id, CaseMember.user_id == user_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Case member not found")

    db.delete(member)
    db.commit()

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CASE_MEMBER_REMOVED",
        details=f"User ID '{user_id}' removed from case '{case.name}'."
    )
    return {"status": "success", "message": f"Member {user_id} removed from case {case.id}"}

# -----------------------------------------------------------------------------
# Evidence Ingestion & Custody Endpoints
# -----------------------------------------------------------------------------

@router.post("/{id}/evidence/intake", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
@router.post("/{id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
def intake_evidence(
    id: str,
    intake_in: EvidenceIntakeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    try:
        norm_path = SecurityValidator.validate_file_path(intake_in.path, allow_nonexistent=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid evidence path: {str(e)}")

    if not os.path.exists(norm_path):
        raise HTTPException(status_code=400, detail=f"Evidence file does not exist at path: {norm_path}")

    filename = os.path.basename(norm_path)
    evidence_id = str(uuid.uuid4())

    # 1. Stage evidence to managed vault (stream copy + independent SHA-256 disk re-read verification)
    try:
        stage_res = stage_evidence_to_vault(source_path=norm_path, case_id=case.id, evidence_id=evidence_id)
    except Exception as e:
        status_code = 500 if isinstance(e, IOError) else 400
        raise HTTPException(status_code=status_code, detail=f"Evidence vault staging failed: {str(e)}")

    # 2. Execute Evidence Intelligence Analysis
    from backend.app.services.intelligence import EvidenceIntelligenceEngine
    vault_file_path = stage_res.storage_path or stage_res.original_path
    intel_payload = EvidenceIntelligenceEngine.analyze_evidence(
        evidence_id=evidence_id,
        evidence_name=filename,
        file_path=vault_file_path
    )
    intel_dict = intel_payload.model_dump()

    meta_dict = {
        "extension": os.path.splitext(filename)[1].lower(),
        "is_read_only": stage_res.read_only_verified,
        "notes": intake_in.notes,
        "vault_path": stage_res.storage_path
    }

    evidence = EvidenceItem(
        id=evidence_id,
        case_id=case.id,
        name=filename,
        original_path=stage_res.original_path,
        storage_path=stage_res.storage_path,
        evidence_type=intel_payload.evidence_type,
        evidence_subtype=intel_payload.evidence_subtype,
        source_kind=intel_payload.source_kind,
        acquisition_method="INVESTIGATOR_IMPORT",
        detected_format=intel_payload.detected_format,
        platform_hint=intel_payload.platform_hint,
        size_bytes=float(stage_res.size_bytes),
        sha256=stage_res.sha256,
        status="REGISTERED",
        intake_status="INTAKE_COMPLETE",
        integrity_status="VERIFIED",
        read_only_verified=stage_res.read_only_verified,
        notes=intake_in.notes,
        metadata_json=meta_dict,
        intelligence_json=intel_dict,
        created_by=current_user.email
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    # 3. Record append-only chain of custody event
    record_custody_event(
        db=db,
        case_id=case.id,
        evidence_id=evidence.id,
        event_type="EVIDENCE_REGISTERED",
        actor=current_user.name or current_user.email,
        actor_id=current_user.id,
        description=f"Evidence file '{filename}' ({intel_payload.source_kind}/{intel_payload.evidence_type}) ingested, preserved in vault, and cryptographically verified (SHA-256: {stage_res.sha256})",
        source_path=stage_res.original_path,
        destination_path=stage_res.storage_path,
        sha256=stage_res.sha256,
        metadata_json={
            "size_bytes": stage_res.size_bytes,
            "evidence_type": intel_payload.evidence_type,
            "source_kind": intel_payload.source_kind,
            "detected_format": intel_payload.detected_format,
            "read_only_verified": stage_res.read_only_verified,
            "notes": intake_in.notes
        }
    )

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="EVIDENCE_REGISTERED",
        details=f"Evidence '{filename}' ({intel_payload.evidence_type}, {stage_res.size_bytes} bytes) staged to vault for case {case.id}. SHA-256: {stage_res.sha256}"
    )

    return evidence

@router.get("/{id}/evidence", response_model=List[EvidenceResponse])
def get_evidence(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()

@router.get("/{id}/evidence/{evidence_id}", response_model=EvidenceResponse)
def get_single_evidence(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    evidence = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id, EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found in case {id}")
    return evidence

@router.post("/{id}/evidence/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def verify_evidence_integrity(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    evidence = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id, EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found in case {id}")

    target_path = evidence.storage_path or evidence.original_path
    if not target_path or not os.path.exists(target_path):
        evidence.integrity_status = "MISSING"
        evidence.status = "INTEGRITY_WARNING"
        evidence.error_message = f"Preserved evidence file not found at path: {target_path}"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_MISMATCH",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"CRITICAL: Evidence file missing from storage path: {target_path}",
            sha256=evidence.sha256
        )
        return EvidenceVerificationResponse(
            evidence_id=evidence.id,
            integrity_status="MISSING",
            expected_sha256=evidence.sha256,
            current_sha256="",
            read_only_verified=False,
            verified_at=datetime.now(timezone.utc),
            message=f"Preserved evidence file missing from storage: {target_path}"
        )

    # Calculate current streaming SHA-256 hash
    from backend.app.services.integrity import calculate_sha256
    current_sha256, _ = calculate_sha256(target_path)
    is_valid = (current_sha256.lower() == evidence.sha256.lower())

    from backend.app.services.vault import verify_os_read_only
    ro_verified = verify_os_read_only(Path(target_path))

    if is_valid:
        evidence.integrity_status = "VERIFIED"
        evidence.read_only_verified = ro_verified
        evidence.error_message = None
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VERIFIED",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"Cryptographic SHA-256 integrity re-verified successfully for '{evidence.name}' (SHA-256: {current_sha256})",
            destination_path=target_path,
            sha256=current_sha256
        )
        msg = f"Evidence integrity verified successfully. SHA-256: {current_sha256}"
    else:
        evidence.integrity_status = "INTEGRITY_MISMATCH"
        evidence.status = "INTEGRITY_WARNING"
        evidence.error_message = f"Integrity mismatch detected! Baseline SHA-256: {evidence.sha256}, Current: {current_sha256}"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_MISMATCH",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"CRITICAL: Cryptographic SHA-256 mismatch detected for '{evidence.name}'! Baseline: {evidence.sha256}, Current: {current_sha256}",
            destination_path=target_path,
            sha256=current_sha256
        )
        msg = f"CRITICAL: Evidence hash mismatch! Baseline: {evidence.sha256}, Current: {current_sha256}"

    return EvidenceVerificationResponse(
        evidence_id=evidence.id,
        integrity_status=evidence.integrity_status,
        expected_sha256=evidence.sha256,
        current_sha256=current_sha256,
        read_only_verified=ro_verified,
        verified_at=datetime.now(timezone.utc),
        message=msg
    )

@router.get("/{id}/custody", response_model=List[CustodyRecord])
def get_case_custody(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.case_id == case.id).order_by(ChainOfCustodyEvent.timestamp.asc()).all()

@router.get("/{id}/evidence/{evidence_id}/custody", response_model=List[CustodyRecord])
def get_evidence_custody(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    evidence = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id, EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found in case {id}")
    return db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.case_id == case.id, ChainOfCustodyEvent.evidence_id == evidence.id).order_by(ChainOfCustodyEvent.timestamp.asc()).all()

@router.get("/{id}/evidence/{evidence_id}/intelligence", response_model=EvidenceIntelligenceResponse)
def get_evidence_intelligence(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    evidence = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id, EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found in case {id}")

    if evidence.intelligence_json and isinstance(evidence.intelligence_json, dict):
        return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=evidence.intelligence_json)

    # Fallback to dynamic intelligence analysis if not pre-cached
    from backend.app.services.intelligence import EvidenceIntelligenceEngine
    target_path = evidence.storage_path or evidence.original_path
    intel = EvidenceIntelligenceEngine.analyze_evidence(evidence.id, evidence.name, target_path)
    intel_dict = intel.model_dump()
    evidence.intelligence_json = intel_dict
    db.commit()
    return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=intel_dict)

@router.post("/{id}/evidence/{evidence_id}/intelligence/refresh", response_model=EvidenceIntelligenceResponse)
def refresh_evidence_intelligence(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    evidence = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id, EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found in case {id}")

    from backend.app.services.intelligence import EvidenceIntelligenceEngine
    target_path = evidence.storage_path or evidence.original_path
    intel = EvidenceIntelligenceEngine.analyze_evidence(evidence.id, evidence.name, target_path)
    intel_dict = intel.model_dump()

    evidence.evidence_type = intel.evidence_type
    evidence.evidence_subtype = intel.evidence_subtype
    evidence.source_kind = intel.source_kind
    evidence.detected_format = intel.detected_format
    evidence.platform_hint = intel.platform_hint
    evidence.intelligence_json = intel_dict
    db.commit()

    return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=intel_dict)

# -----------------------------------------------------------------------------
# Forensic Specialist Execution Endpoints
# -----------------------------------------------------------------------------

@router.post("/{id}/analysis/disk", response_model=DiskAnalysisResponse)
def run_disk_analysis(
    id: str,
    req: DiskAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case, evidence = _validate_case_and_evidence(id, req.evidence_id, db, current_user)
    target_path = str(Path(evidence.storage_path).resolve())

    execution = ToolExecution(
        case_id=case.id,
        evidence_id=evidence.id,
        tool_id="sleuthkit_fls",
        command_args=["fls", "-r", "-p", target_path],
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        operator_id=current_user.id
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="TOOL_EXECUTION_STARTED",
        details=f"Started DiskAgent execution (The Sleuth Kit) against evidence '{evidence.name}'"
    )

    ev_dict = {
        "id": evidence.id,
        "investigation_id": id,
        "name": evidence.name,
        "original_path": evidence.original_path,
        "storage_path": target_path,
        "evidence_type": evidence.evidence_type,
        "sha256": evidence.sha256
    }

    tool_exc = None
    res = None
    try:
        res = disk_agent.analyze(
            evidence_item=ev_dict,
            parameters={
                "recursive": req.recursive,
                "include_deleted": req.include_deleted,
                "offset_sectors": req.offset_sectors,
                "timeout_seconds": req.timeout_seconds
            }
        )
    except Exception as e:
        tool_exc = e

    # Mandatory Post-Analysis Cryptographic Integrity Gate:
    # Must execute whenever tool execution was initiated
    try:
        _enforce_post_analysis_gate(case, evidence, target_path, execution, db)
    except HTTPException as integrity_err:
        # Cryptographic integrity failure takes absolute precedence
        raise integrity_err

    # If post-analysis check verified file is unchanged, check if tool raised an exception
    if tool_exc is not None:
        execution.status = "FAILED"
        execution.error_message = str(tool_exc)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return DiskAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(tool_exc),
            artifacts=[],
            findings=[]
        )

    try:
        artifact_objs = []
        for art in res.get("artifacts", []):
            artifact_db = ExecutionArtifact(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="DiskAgent",
                tool="SleuthKit",
                artifact_type=art.get("artifact_type", "filesystem_entry"),
                source_reference=art.get("source_reference", f"inode:{art.get('inode', 'unknown')}"),
                path=art.get("path"),
                inode=art.get("inode"),
                size_bytes=art.get("size_bytes"),
                is_deleted=art.get("is_deleted", False),
                metadata_json=art.get("metadata_json", {}),
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(artifact_db)
            artifact_objs.append(artifact_db)

        finding_objs = []
        for find in res.get("findings", []):
            find_db = Finding(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                artifact_id=artifact_objs[0].id if artifact_objs else None,
                agent="DiskAgent",
                tool="SleuthKit",
                finding_type=find.get("finding_type", "filesystem_artifact"),
                title=find.get("title", "Disk Artifact Discovered"),
                description=find.get("description", ""),
                severity=find.get("severity", "MEDIUM"),
                classification="FACT",
                confidence=find.get("confidence"),
                timestamp=datetime.now(timezone.utc),
                evidence_reference=find.get("evidence_reference"),
                verification_status="UNVERIFIED",
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(find_db)
            finding_objs.append(find_db)

        status_str = res.get("status", "SUCCESS")
        execution.status = "COMPLETED" if status_str == "SUCCESS" else status_str
        execution.exit_code = 0 if status_str == "SUCCESS" else 1
        execution.completed_at = datetime.now(timezone.utc)
        execution.execution_time_ms = res.get("execution_time_ms", 0.0)
        execution.stdout_path = res.get("raw_output_reference")
        db.commit()

        return DiskAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status=status_str,
            execution_id=execution.id,
            artifacts_count=len(artifact_objs),
            findings_count=len(finding_objs),
            execution_time_ms=res.get("execution_time_ms", 0.0),
            tool_version=res.get("tool_version", "The Sleuth Kit"),
            raw_output_reference=res.get("raw_output_reference"),
            error=res.get("error"),
            artifacts=[ArtifactResponse.model_validate(a) for a in artifact_objs],
            findings=[FindingResponse.model_validate(f) for f in finding_objs]
        )
    except Exception as e:
        execution.status = "FAILED"
        execution.error_message = str(e)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return DiskAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(e),
            artifacts=[],
            findings=[]
        )

@router.post("/{id}/analysis/memory", response_model=MemoryAnalysisResponse)
def run_memory_analysis(
    id: str,
    req: MemoryAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case, evidence = _validate_case_and_evidence(id, req.evidence_id, db, current_user)
    target_path = str(Path(evidence.storage_path).resolve())

    execution = ToolExecution(
        case_id=case.id,
        evidence_id=evidence.id,
        tool_id="volatility3",
        command_args=["vol", "-f", target_path, req.plugin],
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        operator_id=current_user.id
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="TOOL_EXECUTION_STARTED",
        details=f"Started MemoryAgent execution (Volatility 3: {req.plugin}) against evidence '{evidence.name}'"
    )

    ev_dict = {
        "id": evidence.id,
        "investigation_id": id,
        "name": evidence.name,
        "original_path": evidence.original_path,
        "storage_path": target_path,
        "evidence_type": evidence.evidence_type,
        "sha256": evidence.sha256
    }

    tool_exc = None
    res = None
    try:
        res = memory_agent.analyze(
            evidence_item=ev_dict,
            parameters={"plugin": req.plugin, "timeout_seconds": req.timeout_seconds}
        )
    except Exception as e:
        tool_exc = e

    # Mandatory Post-Analysis Cryptographic Integrity Gate:
    # Must execute whenever tool execution was initiated
    try:
        _enforce_post_analysis_gate(case, evidence, target_path, execution, db)
    except HTTPException as integrity_err:
        # Cryptographic integrity failure takes absolute precedence
        raise integrity_err

    # If post-analysis check verified file is unchanged, check if tool raised an exception
    if tool_exc is not None:
        execution.status = "FAILED"
        execution.error_message = str(tool_exc)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return MemoryAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            plugin=req.plugin,
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(tool_exc),
            artifacts=[],
            findings=[]
        )

    try:
        artifact_objs = []
        for art in res.get("artifacts", []):
            artifact_db = ExecutionArtifact(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="MemoryAgent",
                tool="Volatility3",
                artifact_type=art.get("artifact_type", "memory_process"),
                source_reference=art.get("source_reference", "memory_offset"),
                path=art.get("path"),
                size_bytes=art.get("size_bytes"),
                is_deleted=False,
                metadata_json=art.get("metadata_json", {}),
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(artifact_db)
            artifact_objs.append(artifact_db)

        finding_objs = []
        for find in res.get("findings", []):
            find_db = Finding(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="MemoryAgent",
                tool="Volatility3",
                finding_type=find.get("finding_type", "process_artifact"),
                title=find.get("title", "Memory Anomaly Discovered"),
                description=find.get("description", ""),
                severity=find.get("severity", "HIGH"),
                classification="FACT",
                confidence=find.get("confidence"),
                timestamp=datetime.now(timezone.utc),
                evidence_reference=find.get("evidence_reference"),
                verification_status="UNVERIFIED",
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(find_db)
            finding_objs.append(find_db)

        status_str = res.get("status", "SUCCESS")
        execution.status = "COMPLETED" if status_str == "SUCCESS" else status_str
        execution.exit_code = 0 if status_str == "SUCCESS" else 1
        execution.completed_at = datetime.now(timezone.utc)
        execution.execution_time_ms = res.get("execution_time_ms", 0.0)
        execution.stdout_path = res.get("raw_output_reference")
        db.commit()

        return MemoryAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status=status_str,
            plugin=req.plugin,
            execution_id=execution.id,
            artifacts_count=len(artifact_objs),
            findings_count=len(finding_objs),
            execution_time_ms=res.get("execution_time_ms", 0.0),
            tool_version=res.get("tool_version", "Volatility 3"),
            raw_output_reference=res.get("raw_output_reference"),
            error=res.get("error"),
            artifacts=[ArtifactResponse.model_validate(a) for a in artifact_objs],
            findings=[FindingResponse.model_validate(f) for f in finding_objs]
        )
    except Exception as e:
        execution.status = "FAILED"
        execution.error_message = str(e)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return MemoryAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            plugin=req.plugin,
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(e),
            artifacts=[],
            findings=[]
        )

@router.post("/{id}/analysis/malware", response_model=MalwareAnalysisResponse)
def run_malware_analysis(
    id: str,
    req: MalwareAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case, evidence = _validate_case_and_evidence(id, req.evidence_id, db, current_user)
    target_path = str(Path(evidence.storage_path).resolve())

    # Disallowed rule validation
    if not yara_rule_repo.get_rule(req.rule_id):
        raise HTTPException(status_code=400, detail=f"YARA rule '{req.rule_id}' is not in the approved rule repository.")

    execution = ToolExecution(
        case_id=case.id,
        evidence_id=evidence.id,
        tool_id="yara",
        command_args=["yara", req.rule_id, target_path],
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        operator_id=current_user.id
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="TOOL_EXECUTION_STARTED",
        details=f"Started MalwareAgent execution (YARA: {req.rule_id}) against evidence '{evidence.name}'"
    )

    ev_dict = {
        "id": evidence.id,
        "investigation_id": id,
        "name": evidence.name,
        "original_path": evidence.original_path,
        "storage_path": target_path,
        "evidence_type": evidence.evidence_type,
        "sha256": evidence.sha256
    }

    tool_exc = None
    res = None
    try:
        res = malware_agent.analyze(
            evidence_item=ev_dict,
            parameters={"rule_id": req.rule_id, "timeout_seconds": req.timeout_seconds}
        )
    except Exception as e:
        tool_exc = e

    # Mandatory Post-Analysis Cryptographic Integrity Gate:
    # Must execute whenever tool execution was initiated
    try:
        _enforce_post_analysis_gate(case, evidence, target_path, execution, db)
    except HTTPException as integrity_err:
        # Cryptographic integrity failure takes absolute precedence
        raise integrity_err

    # If post-analysis check verified file is unchanged, check if tool raised an exception
    if tool_exc is not None:
        execution.status = "FAILED"
        execution.error_message = str(tool_exc)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return MalwareAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            rule_id=req.rule_id,
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(tool_exc),
            artifacts=[],
            findings=[]
        )

    try:
        artifact_objs = []
        for art in res.get("artifacts", []):
            artifact_db = ExecutionArtifact(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="MalwareAgent",
                tool="YARA",
                artifact_type=art.get("artifact_type", "signature_match"),
                source_reference=art.get("source_reference", req.rule_id),
                path=art.get("path"),
                size_bytes=art.get("size_bytes"),
                is_deleted=False,
                metadata_json=art.get("metadata_json", {}),
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(artifact_db)
            artifact_objs.append(artifact_db)

        finding_objs = []
        for find in res.get("findings", []):
            find_db = Finding(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="MalwareAgent",
                tool="YARA",
                finding_type=find.get("finding_type", "malware_signature"),
                title=find.get("title", "Malware Signature Matched"),
                description=find.get("description", ""),
                severity=find.get("severity", "CRITICAL"),
                classification="FACT",
                confidence=find.get("confidence"),
                timestamp=datetime.now(timezone.utc),
                evidence_reference=find.get("evidence_reference"),
                verification_status="UNVERIFIED",
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(find_db)
            finding_objs.append(find_db)

        status_str = res.get("status", "SUCCESS")
        execution.status = "COMPLETED" if status_str == "SUCCESS" else status_str
        execution.exit_code = 0 if status_str == "SUCCESS" else 1
        execution.completed_at = datetime.now(timezone.utc)
        execution.execution_time_ms = res.get("execution_time_ms", 0.0)
        execution.stdout_path = res.get("raw_output_reference")
        db.commit()

        return MalwareAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status=status_str,
            rule_id=req.rule_id,
            rule_sha256=res.get("rule_sha256"),
            execution_id=execution.id,
            artifacts_count=len(artifact_objs),
            findings_count=len(finding_objs),
            execution_time_ms=res.get("execution_time_ms", 0.0),
            tool_version=res.get("tool_version", "YARA"),
            raw_output_reference=res.get("raw_output_reference"),
            error=res.get("error"),
            artifacts=[ArtifactResponse.model_validate(a) for a in artifact_objs],
            findings=[FindingResponse.model_validate(f) for f in finding_objs]
        )
    except Exception as e:
        execution.status = "FAILED"
        execution.error_message = str(e)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return MalwareAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            rule_id=req.rule_id,
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(e),
            artifacts=[],
            findings=[]
        )

@router.post("/{id}/analysis/log", response_model=LogAnalysisResponse)
def run_log_analysis(
    id: str,
    req: LogAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case, evidence = _validate_case_and_evidence(id, req.evidence_id, db, current_user)
    target_path = str(Path(evidence.storage_path).resolve())

    execution = ToolExecution(
        case_id=case.id,
        evidence_id=evidence.id,
        tool_id="python_evtx",
        command_args=["python-evtx", target_path, str(req.max_records)],
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
        operator_id=current_user.id
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="TOOL_EXECUTION_STARTED",
        details=f"Started LogAgent execution (python-evtx) against evidence '{evidence.name}'"
    )

    ev_dict = {
        "id": evidence.id,
        "investigation_id": id,
        "name": evidence.name,
        "original_path": evidence.original_path,
        "storage_path": target_path,
        "evidence_type": evidence.evidence_type,
        "sha256": evidence.sha256
    }

    tool_exc = None
    res = None
    try:
        res = log_agent.analyze(
            evidence_item=ev_dict,
            parameters={"max_records": req.max_records, "timeout_seconds": req.timeout_seconds}
        )
    except Exception as e:
        tool_exc = e

    # Mandatory Post-Analysis Cryptographic Integrity Gate:
    # Must execute whenever tool execution was initiated
    try:
        _enforce_post_analysis_gate(case, evidence, target_path, execution, db)
    except HTTPException as integrity_err:
        # Cryptographic integrity failure takes absolute precedence
        raise integrity_err

    # If post-analysis check verified file is unchanged, check if tool raised an exception
    if tool_exc is not None:
        execution.status = "FAILED"
        execution.error_message = str(tool_exc)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return LogAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(tool_exc),
            artifacts=[],
            findings=[]
        )

    try:
        artifact_objs = []
        for art in res.get("artifacts", []):
            artifact_db = ExecutionArtifact(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="LogAgent",
                tool="python-evtx",
                artifact_type=art.get("artifact_type", "event_log"),
                source_reference=art.get("source_reference", "event_record"),
                path=art.get("path"),
                size_bytes=art.get("size_bytes"),
                is_deleted=False,
                metadata_json=art.get("metadata_json", {}),
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(artifact_db)
            artifact_objs.append(artifact_db)

        finding_objs = []
        for find in res.get("findings", []):
            find_db = Finding(
                case_id=id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent="LogAgent",
                tool="python-evtx",
                finding_type=find.get("finding_type", "log_event"),
                title=find.get("title", "Security Log Event"),
                description=find.get("description", ""),
                severity=find.get("severity", "MEDIUM"),
                classification="FACT",
                confidence=find.get("confidence"),
                timestamp=datetime.now(timezone.utc),
                evidence_reference=find.get("evidence_reference"),
                verification_status="UNVERIFIED",
                raw_output_reference=res.get("raw_output_reference")
            )
            db.add(find_db)
            finding_objs.append(find_db)

        status_str = res.get("status", "SUCCESS")
        execution.status = "COMPLETED" if status_str == "SUCCESS" else status_str
        execution.exit_code = 0 if status_str == "SUCCESS" else 1
        execution.completed_at = datetime.now(timezone.utc)
        execution.execution_time_ms = res.get("execution_time_ms", 0.0)
        execution.stdout_path = res.get("raw_output_reference")
        db.commit()

        return LogAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status=status_str,
            execution_id=execution.id,
            artifacts_count=len(artifact_objs),
            findings_count=len(finding_objs),
            execution_time_ms=res.get("execution_time_ms", 0.0),
            tool_version=res.get("tool_version", "python-evtx 0.8.1"),
            raw_output_reference=res.get("raw_output_reference"),
            error=res.get("error"),
            artifacts=[ArtifactResponse.model_validate(a) for a in artifact_objs],
            findings=[FindingResponse.model_validate(f) for f in finding_objs]
        )
    except Exception as e:
        execution.status = "FAILED"
        execution.error_message = str(e)
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()
        return LogAnalysisResponse(
            investigation_id=id,
            evidence_id=evidence.id,
            status="FAILED",
            execution_id=execution.id,
            artifacts_count=0,
            findings_count=0,
            execution_time_ms=0.0,
            error=str(e),
            artifacts=[],
            findings=[]
        )

@router.get("/system/yara-rules", response_model=List[YaraRuleResponse])
def list_yara_rules():
    rules = yara_rule_repo.list_rules()
    return [YaraRuleResponse(**r) for r in rules]

@router.get("/{id}/artifacts", response_model=List[ArtifactResponse])
def get_artifacts(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == case.id).all()

# -----------------------------------------------------------------------------
# Autonomous Planning and Orchestration
# -----------------------------------------------------------------------------

@router.post("/{id}/plan", response_model=InvestigationPlanResponse)
def plan_investigation(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    ev_dicts = [
        {"id": e.id, "name": e.name, "evidence_type": e.evidence_type, "source_kind": e.source_kind, "size_bytes": e.size_bytes}
        for e in evidence_items
    ]

    plan_dict = planner_service.plan(investigation_id=case.id, evidence_items=ev_dicts)

    # Deactivate older plans for this case
    db.query(InvestigationPlan).filter(InvestigationPlan.case_id == case.id).update({"is_active": False})

    new_plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title=f"Autonomous Plan for Case {case.case_number}",
        strategy_summary=plan_dict.get("strategy_summary"),
        tasks=plan_dict.get("tasks", []),
        status="PLANNED",
        version=1,
        is_active=True
    )
    db.add(new_plan)
    db.commit()
    db.refresh(new_plan)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="PLAN_CREATED",
        details=f"Autonomous investigation plan '{new_plan.id}' generated with {len(new_plan.tasks or [])} task(s)."
    )

    return InvestigationPlanResponse(
        id=new_plan.id,
        investigation_id=new_plan.case_id,
        case_id=new_plan.case_id,
        strategy_summary=new_plan.strategy_summary,
        tasks=new_plan.tasks or [],
        steps=new_plan.tasks or [],
        total_tasks=len(new_plan.tasks or []),
        status=new_plan.status,
        version=new_plan.version,
        created_at=new_plan.created_at,
        completed_at=new_plan.completed_at
    )

@router.get("/{id}/plan", response_model=InvestigationPlanResponse)
def get_investigation_plan(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)

    plan = (
        db.query(InvestigationPlan)
        .filter(InvestigationPlan.case_id == case.id, InvestigationPlan.is_active == True)
        .order_by(InvestigationPlan.created_at.desc())
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="No active investigation plan found for this case.")

    return InvestigationPlanResponse(
        id=plan.id,
        investigation_id=plan.case_id,
        case_id=plan.case_id,
        strategy_summary=plan.strategy_summary,
        tasks=plan.tasks or [],
        steps=plan.tasks or [],
        total_tasks=len(plan.tasks or []),
        status=plan.status,
        version=plan.version,
        created_at=plan.created_at,
        completed_at=plan.completed_at
    )

@router.post("/{id}/plan/execute", response_model=PlanExecutionResponse)
def execute_investigation_plan(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    try:
        exec_summary = orchestrator_service.execute_plan(case_id=case.id, db=db)
        return PlanExecutionResponse(**exec_summary)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))

@router.get("/{id}/tasks", response_model=List[PlanTaskStep])
def get_investigation_tasks(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)

    plan = (
        db.query(InvestigationPlan)
        .filter(InvestigationPlan.case_id == case.id, InvestigationPlan.is_active == True)
        .order_by(InvestigationPlan.created_at.desc())
        .first()
    )
    if not plan:
        return []
    return [PlanTaskStep(**t) for t in (plan.tasks or [])]

# -----------------------------------------------------------------------------
# Findings, Correlation, and Verification
# -----------------------------------------------------------------------------

@router.post("/{id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
    id: str,
    find_in: FindingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    finding = Finding(
        case_id=case.id,
        evidence_id=find_in.evidence_id,
        execution_id=find_in.execution_id,
        artifact_id=find_in.artifact_id,
        agent=find_in.agent,
        tool=find_in.tool,
        finding_type=find_in.finding_type,
        title=find_in.title,
        description=find_in.description,
        severity=find_in.severity or "MEDIUM",
        classification=find_in.classification or "FACT",
        confidence=find_in.confidence,
        timestamp=find_in.timestamp or datetime.now(timezone.utc),
        evidence_reference=find_in.evidence_reference,
        raw_output_reference=find_in.raw_output_reference,
        verification_status="UNVERIFIED"
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="FINDING_CREATED",
        details=f"Finding '{finding.title}' ({finding.finding_type}) registered with ID {finding.id}"
    )

    return finding

@router.get("/{id}/findings", response_model=List[FindingResponse])
def get_findings(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(Finding).filter(Finding.case_id == case.id).all()

@router.post("/{id}/correlate", response_model=List[CorrelatedGroupResponse])
def correlate_findings(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    artifacts = db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == case.id).all()

    finding_dicts = [
        {
            "id": f.id,
            "evidence_id": f.evidence_id,
            "artifact_id": f.artifact_id,
            "title": f.title,
            "description": f.description,
            "evidence_reference": f.evidence_reference,
            "tool": f.tool,
            "agent": f.agent,
            "details": f.details
        }
        for f in findings
    ]
    artifact_dicts = [
        {
            "id": a.id,
            "evidence_id": a.evidence_id,
            "tool": a.tool,
            "agent": a.agent,
            "artifact_type": a.artifact_type,
            "source_reference": a.source_reference,
            "path": a.path,
            "inode": a.inode,
            "metadata_json": a.metadata_json or {}
        }
        for a in artifacts
    ]

    corr_results = correlation_service.correlate_findings(finding_dicts, artifact_dicts)

    # Deterministic persistence and deduplication
    existing_groups = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).all()
    existing_map = {(eg.dimension, eg.correlated_entity): eg for eg in existing_groups}
    active_keys = set()

    for res in corr_results:
        key = (res["dimension"], res["correlated_entity"])
        active_keys.add(key)
        if key in existing_map:
            eg = existing_map[key]
            eg.rule = res.get("rule")
            eg.title = res["title"]
            eg.description = res["description"]
            eg.tools_involved = res["tools_involved"]
            eg.supporting_finding_ids = res["supporting_finding_ids"]
            eg.supporting_artifact_ids = res["supporting_artifact_ids"]
            eg.supporting_evidence_ids = res["supporting_evidence_ids"]
            eg.correlation_confidence = res["correlation_confidence"]
        else:
            new_grp = CorrelationGroup(
                case_id=case.id,
                dimension=res["dimension"],
                rule=res.get("rule"),
                correlated_entity=res["correlated_entity"],
                title=res["title"],
                description=res["description"],
                tools_involved=res["tools_involved"],
                supporting_finding_ids=res["supporting_finding_ids"],
                supporting_artifact_ids=res["supporting_artifact_ids"],
                supporting_evidence_ids=res["supporting_evidence_ids"],
                correlation_confidence=res["correlation_confidence"],
                created_at=datetime.now(timezone.utc)
            )
            db.add(new_grp)

    # Clean up any stale groups that are no longer supported
    for eg in existing_groups:
        if (eg.dimension, eg.correlated_entity) not in active_keys:
            db.delete(eg)

    db.commit()

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CORRELATION_EXECUTED",
        details=f"Deterministic correlation completed for case '{case.id}'. Persisted {len(corr_results)} correlation group(s) across {len(findings)} findings and {len(artifacts)} artifacts."
    )

    persisted = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).order_by(CorrelationGroup.created_at.asc()).all()
    return [CorrelatedGroupResponse.model_validate(g) for g in persisted]

@router.get("/{id}/correlations", response_model=List[CorrelatedGroupResponse])
@router.get("/{id}/correlate", response_model=List[CorrelatedGroupResponse])
def get_correlations(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    persisted = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).order_by(CorrelationGroup.created_at.asc()).all()
    return [CorrelatedGroupResponse.model_validate(g) for g in persisted]

@router.post("/{id}/verify", response_model=List[VerificationResultResponse])
def verify_findings(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    finding_dicts = [
        {
            "id": f.id,
            "evidence_id": f.evidence_id,
            "artifact_id": f.artifact_id,
            "execution_id": f.execution_id,
            "title": f.title,
            "description": f.description,
            "evidence_reference": f.evidence_reference,
            "tool": f.tool,
            "agent": f.agent,
            "confidence": f.confidence,
            "raw_output_reference": f.raw_output_reference,
        }
        for f in findings
    ]

    ver_results = verification_service.verify_findings(finding_dicts)

    # Update database models with verification status
    status_map = {v["finding_id"]: v["verification_status"] for v in ver_results if v.get("finding_id")}
    for f in findings:
        if f.id in status_map:
            f.verification_status = status_map[f.id]

    db.commit()

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="FINDING_VERIFIED",
        details=f"Ground-Truth verification executed across {len(findings)} findings."
    )

    return [
        VerificationResultResponse(
            finding_id=v.get("finding_id"),
            verification_status=v.get("verification_status", "UNVERIFIED"),
            confidence_score=v.get("confidence_score"),
            reason=v.get("reason", "Verification assessment completed.")
        )
        for v in ver_results
    ]

# -----------------------------------------------------------------------------
# Mandatory Investigator Decision Gate
# -----------------------------------------------------------------------------

@router.post("/{id}/decisions", response_model=InvestigatorDecisionResponse, status_code=status.HTTP_201_CREATED)
def record_decision(
    id: str,
    dec_in: InvestigatorDecisionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)

    investigator_name = current_user.name or current_user.email

    decision = InvestigatorDecision(
        case_id=case.id,
        investigator_id=current_user.id,
        investigator_name=investigator_name,
        decision=dec_in.decision,
        rationale=dec_in.rationale,
        finding_ids=dec_in.finding_ids,
        evidence_ids=dec_in.evidence_ids
    )
    db.add(decision)
    db.commit()
    db.refresh(decision)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=investigator_name,
        event_type="DECISION_RECORDED",
        details=f"Official decision '{decision.decision}' signed by investigator '{investigator_name}'. Rationale: {decision.rationale}"
    )

    return decision

@router.get("/{id}/decisions", response_model=List[InvestigatorDecisionResponse])
def get_decisions(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case.id).order_by(InvestigatorDecision.timestamp.desc()).all()

# -----------------------------------------------------------------------------
# Strictly Gated Court-Oriented Report Generation
# -----------------------------------------------------------------------------

@router.post("/{id}/report", response_model=ReportResponse)
@router.post("/{id}/reports", response_model=ReportResponse)
def generate_report(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)

    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    custody_events = db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.case_id == case.id).all()
    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    latest_decision = db.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case.id).order_by(InvestigatorDecision.timestamp.desc()).first()

    # Mandatory Investigator Decision Gate: Report generation strictly requires an explicit CONFIRM decision
    if not latest_decision:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Report generation blocked: Mandatory investigator decision required before report synthesis."
        )

    if latest_decision.decision != "CONFIRM":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Report generation blocked by mandatory forensic gate: Current investigator decision is {latest_decision.decision}."
        )

    case_dict = {"id": case.id, "name": case.name, "description": case.description, "status": case.status}
    ev_dicts = [
        {"id": e.id, "name": e.name, "evidence_type": e.evidence_type, "size_bytes": e.size_bytes, "sha256": e.sha256, "integrity_status": e.integrity_status}
        for e in evidence_items
    ]
    custody_dicts = [
        {"timestamp": c.timestamp.isoformat(), "event_type": c.event_type, "actor": c.actor, "description": c.description, "sha256": c.sha256}
        for c in custody_events
    ]
    finding_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "agent": f.agent,
            "tool": f.tool,
            "finding_type": f.finding_type,
            "description": f.description,
            "confidence": f.confidence,
            "evidence_reference": f.evidence_reference,
            "verification_status": f.verification_status,
            "created_at": f.created_at.isoformat()
        }
        for f in findings
    ]

    # Mandatory Correlation State Gate:
    # Official reports MUST consume persisted correlation state. Report generation must NOT execute correlation on the fly.
    correlation_event = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "CORRELATION_EXECUTED"
    ).order_by(AuditEvent.timestamp.desc()).first()
    persisted_corr = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).all()

    if findings:
        if not correlation_event and not persisted_corr:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Report generation blocked: Forensic correlation has not been executed for this investigation. Correlation must be explicitly executed and reviewed before report synthesis."
            )
        if correlation_event:
            latest_finding = max(findings, key=lambda f: f.created_at)
            if latest_finding.created_at > correlation_event.timestamp:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Report generation blocked: New findings have been added since the last correlation execution. Correlation must be re-executed for the current investigation state."
                )

    correlated = [
        {
            "title": c.title,
            "description": c.description,
            "dimension": c.dimension,
            "rule": c.rule,
            "correlated_entity": c.correlated_entity,
            "tools_involved": c.tools_involved,
            "supporting_finding_ids": c.supporting_finding_ids,
            "correlation_confidence": c.correlation_confidence
        }
        for c in persisted_corr
    ]

    report_result = report_generator_service.generate_report(
        investigation=case_dict,
        evidence_items=ev_dicts,
        custody_events=custody_dicts,
        findings=finding_dicts,
        correlated_events=correlated
    )

    full_md = report_result["full_report_markdown"]
    rep_hash = hashlib.sha256(full_md.encode("utf-8")).hexdigest()

    saved_report = Report(
        case_id=case.id,
        decision_id=latest_decision.id,
        title=report_result["title"],
        executive_summary=report_result["executive_summary"],
        findings_count=report_result["findings_count"],
        evidence_count=report_result["evidence_count"],
        full_report_markdown=full_md,
        report_hash=rep_hash,
        generated_by=latest_decision.investigator_name or current_user.name or current_user.email,
        status="OFFICIAL_FINAL"
    )
    db.add(saved_report)
    db.commit()
    db.refresh(saved_report)

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="REPORT_GENERATED",
        details=f"Official court-oriented report synthesized with {len(finding_dicts)} findings. SHA-256: {rep_hash[:16]}..."
    )

    return ReportResponse(
        id=saved_report.id,
        case_id=case.id,
        title=saved_report.title,
        investigation_id=case.id,
        executive_summary=saved_report.executive_summary,
        findings_count=saved_report.findings_count,
        evidence_count=saved_report.evidence_count,
        full_report_markdown=saved_report.full_report_markdown,
        report_hash=rep_hash,
        status=saved_report.status,
        generated_by=saved_report.generated_by,
        generated_at=saved_report.generated_at.isoformat()
    )

@router.get("/{id}/reports", response_model=List[ReportResponse])
def get_case_reports(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)

    reports = db.query(Report).filter(Report.case_id == case.id).order_by(Report.generated_at.desc()).all()
    return [
        ReportResponse(
            id=r.id,
            case_id=r.case_id,
            title=r.title,
            investigation_id=r.case_id,
            executive_summary=r.executive_summary,
            findings_count=r.findings_count,
            evidence_count=r.evidence_count,
            full_report_markdown=r.full_report_markdown,
            report_hash=r.report_hash,
            status=r.status,
            generated_by=r.generated_by,
            generated_at=r.generated_at.isoformat()
        )
        for r in reports
    ]

@router.post("/{id}/tasks/{task_id}/cancel", response_model=TaskCancelResponse)
def cancel_investigation_task(
    id: str,
    task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    check_case_not_closed(case)
    try:
        res = orchestrator_service.cancel_task(case_id=case.id, task_id=task_id, db=db)
        return TaskCancelResponse(**res)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{id}/executions/{execution_id}", response_model=ToolExecutionResponse)
def get_tool_execution(
    id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    exec_rec = (
        db.query(ToolExecution)
        .filter(ToolExecution.id == execution_id, ToolExecution.case_id == case.id)
        .first()
    )
    if not exec_rec:
        raise HTTPException(status_code=404, detail="Tool execution record not found.")
    return exec_rec

@router.get("/{id}/executions", response_model=List[ToolExecutionResponse])
def list_tool_executions(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(id, db, current_user)
    return db.query(ToolExecution).filter(ToolExecution.case_id == case.id).all()
