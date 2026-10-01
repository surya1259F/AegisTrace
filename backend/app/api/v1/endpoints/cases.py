import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import Case, CaseMember, EvidenceItem, Finding, ExecutionArtifact, User
from backend.app.schemas.schemas import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseMemberCreateRequest,
    CaseMemberUpdateRequest,
    CaseMemberResponse,
    CaseClosureResponse,
    CasePermissionUpdateRequest,
    WorkspaceInitResponse,
    InvestigatorDecisionCreate,
    InvestigatorDecisionResponse,
)
from backend.app.services.authorization import (
    get_authorized_case,
    get_user_cases,
    ensure_case_member,
    is_case_admin,
    require_case_admin,
    validate_case_member_role,
)
from backend.app.services.workspace import initialize_case_workspace, get_workspace_status
from backend.app.services.audit import log_audit_event

router = APIRouter()

DEFAULT_CASE_PERMISSIONS = {
    "view_case": True,
    "edit_case_details": True,
    "manage_members": True,
    "manage_case_settings": True,
    "add_evidence": True,
    "run_investigation": True,
    "view_findings": True,
    "export_report": True,
}


def _build_case_response(c: Case, db: Session) -> CaseResponse:
    ev_count = db.query(EvidenceItem).filter(EvidenceItem.case_id == c.id).count()
    findings_count = db.query(Finding).filter(Finding.case_id == c.id).count()
    artifacts_count = db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == c.id).count()
    members_count = db.query(CaseMember).filter(CaseMember.case_id == c.id).count()

    return CaseResponse(
        id=c.id,
        case_number=c.case_number,
        name=c.name,
        title=c.name,
        description=c.description,
        objective=c.objective,
        case_type=c.case_type or "GENERAL_INVESTIGATION",
        priority=c.priority or "MEDIUM",
        status=c.status or "OPEN",
        workspace_state=c.workspace_state or "NOT_INITIALIZED",
        workspace_path=c.workspace_path,
        case_permissions=c.case_permissions or DEFAULT_CASE_PERMISSIONS,
        owner_id=c.owner_id,
        created_by=c.created_by,
        investigator=c.created_by,
        created_at=c.created_at,
        updated_at=c.updated_at,
        closed_at=c.closed_at,
        evidence_count=ev_count,
        findings_count=findings_count,
        artifacts_count=artifacts_count,
        members_count=members_count,
    )


@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    if case_in.case_number:
        db_case = db.query(Case).filter(Case.case_number == case_in.case_number).first()
        if db_case:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Case number already exists")

    case_num = case_in.case_number or f"CASE-{uuid.uuid4().hex[:8].upper()}"
    case_name = case_in.title or case_in.name or f"Case {case_num}"
    perms = case_in.case_permissions or DEFAULT_CASE_PERMISSIONS

    new_case = Case(
        id=str(uuid.uuid4()),
        case_number=case_num,
        name=case_name,
        description=case_in.description,
        objective=case_in.objective,
        case_type=case_in.case_type or "GENERAL_INVESTIGATION",
        priority=case_in.priority or "MEDIUM",
        owner_id=current_user.id,
        created_by=current_user.email,
        status="OPEN",
        workspace_state="NOT_INITIALIZED",
        case_permissions=perms,
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Automatically add case creator as Primary Investigator CaseMember
    ensure_case_member(case_id=new_case.id, user_id=current_user.id, db=db, role="PRIMARY_INVESTIGATOR")

    # Add initial members if provided
    if case_in.members:
        for m_req in case_in.members:
            m_user = None
            if m_req.user_id:
                m_user = db.query(User).filter(User.id == m_req.user_id).first()
            elif m_req.email:
                m_user = db.query(User).filter(User.email == m_req.email).first()
            if m_user and m_user.id != current_user.id:
                ensure_case_member(case_id=new_case.id, user_id=m_user.id, db=db, role=m_req.role)

    # Initialize workspace automatically
    initialize_case_workspace(new_case, db=db, actor_id=current_user.id, actor_name=current_user.name or current_user.email)

    # Audit log
    log_audit_event(
        db=db,
        event_type="CASE_CREATED",
        details=f"Case '{new_case.case_number}' ({new_case.name}) created by {current_user.email}",
        case_id=new_case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        metadata_json={
            "case_number": new_case.case_number,
            "case_type": new_case.case_type,
            "priority": new_case.priority,
            "workspace_path": new_case.workspace_path
        }
    )

    return _build_case_response(new_case, db)


@router.get("/", response_model=List[CaseResponse])
@router.get("", response_model=List[CaseResponse])
def list_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cases = get_user_cases(db, current_user)
    return [_build_case_response(c, db) for c in cases]


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return _build_case_response(case, db)


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: str,
    case_in: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed, CaseClosureService
    from backend.app.schemas.schemas import CaseClosureRequest
    check_case_not_closed(case)

    changes = []
    if case_in.name is not None or case_in.title is not None:
        new_name = case_in.title or case_in.name
        case.name = new_name
        changes.append("name")
    if case_in.description is not None:
        case.description = case_in.description
        changes.append("description")
    if case_in.objective is not None:
        case.objective = case_in.objective
        changes.append("objective")
    if case_in.case_type is not None:
        case.case_type = case_in.case_type
        changes.append("case_type")
    if case_in.priority is not None:
        case.priority = case_in.priority
        changes.append("priority")
    if case_in.case_permissions is not None:
        updated_perms = dict(case.case_permissions or DEFAULT_CASE_PERMISSIONS)
        updated_perms.update(case_in.case_permissions)
        case.case_permissions = updated_perms
        changes.append("case_permissions")

    if case_in.status is not None:
        new_status = case_in.status.upper().strip()
        valid_statuses = {"DRAFT", "OPEN", "CLOSED", "ARCHIVED"}
        if new_status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid case status '{case_in.status}'. Valid statuses: {sorted(list(valid_statuses))}"
            )
        if new_status == "CLOSED":
            # Delegate directly to authoritative CaseClosureService
            CaseClosureService.validate_and_close_case(
                db=db,
                case_id=case.id,
                user=current_user,
                request_data=CaseClosureRequest(rationale=f"Case closed by {current_user.email} via case management API")
            )
            return _build_case_response(case, db)
        elif new_status == "ARCHIVED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active cases cannot be directly archived. The case must first be formally closed."
            )
        else:
            old_status = case.status
            case.status = new_status
            changes.append(f"status({old_status}->{new_status})")

    case.updated_at = datetime.now(timezone.utc)
    db.add(case)
    db.commit()
    db.refresh(case)

    if changes:
        log_audit_event(
            db=db,
            event_type="CASE_UPDATED",
            details=f"Case '{case.case_number}' updated by {current_user.email}: {', '.join(changes)}",
            case_id=case.id,
            actor_id=current_user.id,
            actor_name=current_user.email,
            metadata_json={"changed_fields": changes}
        )

    return _build_case_response(case, db)


@router.post("/{case_id}/workspace/initialize", response_model=WorkspaceInitResponse)
def initialize_workspace_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)
    res = initialize_case_workspace(case, db, actor_id=current_user.id, actor_name=current_user.email)
    return WorkspaceInitResponse(
        case_id=res["case_id"],
        workspace_state=res["workspace_state"],
        workspace_path=res["workspace_path"],
        subdirectories=res["subdirectories"],
        initialized_at=res["initialized_at"]
    )


@router.get("/{case_id}/workspace/status")
def get_workspace_status_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return get_workspace_status(case)


@router.get("/{case_id}/members", response_model=List[CaseMemberResponse])
def list_case_members(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    members = db.query(CaseMember).filter(CaseMember.case_id == case.id).all()
    results = []
    for m in members:
        u = db.query(User).filter(User.id == m.user_id).first()
        results.append(CaseMemberResponse(
            id=m.id,
            case_id=m.case_id,
            user_id=m.user_id,
            role=m.role,
            added_at=m.added_at,
            email=u.email if u else None,
            name=u.name if u else None
        ))
    return results


@router.post("/{case_id}/members", response_model=CaseMemberResponse, status_code=status.HTTP_201_CREATED)
def add_case_member(
    case_id: str,
    member_in: CaseMemberCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    target_user = None
    if member_in.user_id:
        target_user = db.query(User).filter(User.id == member_in.user_id).first()
    elif member_in.email:
        target_user = db.query(User).filter(User.email == member_in.email).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check for existing membership
    existing = db.query(CaseMember).filter(
        CaseMember.case_id == case.id,
        CaseMember.user_id == target_user.id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User '{target_user.email}' is already a member of this case."
        )

    clean_role = validate_case_member_role(member_in.role)
    new_member = ensure_case_member(case_id=case.id, user_id=target_user.id, db=db, role=clean_role)

    log_audit_event(
        db=db,
        event_type="CASE_MEMBER_ADDED",
        details=f"User '{target_user.email}' added to case '{case.case_number}' as role '{clean_role}' by {current_user.email}",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={"added_user_id": target_user.id, "added_user_email": target_user.email, "role": clean_role}
    )

    return CaseMemberResponse(
        id=new_member.id,
        case_id=new_member.case_id,
        user_id=new_member.user_id,
        role=new_member.role,
        added_at=new_member.added_at,
        email=target_user.email,
        name=target_user.name
    )


@router.patch("/{case_id}/members/{user_id}", response_model=CaseMemberResponse)
def update_case_member(
    case_id: str,
    user_id: str,
    member_in: CaseMemberUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    member = db.query(CaseMember).filter(
        CaseMember.case_id == case.id,
        CaseMember.user_id == user_id
    ).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case member not found.")

    clean_role = validate_case_member_role(member_in.role)
    member.role = clean_role
    db.commit()
    db.refresh(member)

    target_user = db.query(User).filter(User.id == user_id).first()

    log_audit_event(
        db=db,
        event_type="CASE_MEMBER_UPDATED",
        details=f"Role for user '{target_user.email if target_user else user_id}' updated to '{clean_role}' in case '{case.case_number}'",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email
    )

    return CaseMemberResponse(
        id=member.id,
        case_id=member.case_id,
        user_id=member.user_id,
        role=member.role,
        added_at=member.added_at,
        email=target_user.email if target_user else None,
        name=target_user.name if target_user else None
    )


@router.delete("/{case_id}/members/{user_id}", status_code=status.HTTP_200_OK)
def remove_case_member(
    case_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    if case.owner_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the owner of the case."
        )

    member = db.query(CaseMember).filter(
        CaseMember.case_id == case.id,
        CaseMember.user_id == user_id
    ).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case member not found.")

    target_user = db.query(User).filter(User.id == user_id).first()
    target_email = target_user.email if target_user else user_id

    db.delete(member)
    db.commit()

    log_audit_event(
        db=db,
        event_type="CASE_MEMBER_REMOVED",
        details=f"User '{target_email}' removed from case '{case.case_number}' by {current_user.email}",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={"removed_user_id": user_id, "removed_user_email": target_email}
    )

    return {"detail": f"User '{target_email}' successfully removed from case."}


@router.get("/{case_id}/permissions")
def get_case_permissions(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return case.case_permissions or DEFAULT_CASE_PERMISSIONS


@router.patch("/{case_id}/permissions")
def update_case_permissions(
    case_id: str,
    perms_in: CasePermissionUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    current_perms = dict(case.case_permissions or DEFAULT_CASE_PERMISSIONS)
    current_perms.update(perms_in.permissions)
    case.case_permissions = current_perms
    db.commit()

    log_audit_event(
        db=db,
        event_type="CASE_PERMISSIONS_UPDATED",
        details=f"Case permissions updated for case '{case.case_number}' by {current_user.email}",
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.email,
        metadata_json={"updated_permissions": perms_in.permissions}
    )

    return case.case_permissions


@router.post("/{case_id}/evidence/intake", status_code=status.HTTP_201_CREATED)
def intake_case_evidence(
    case_id: str,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    from backend.app.api.v1.endpoints.evidence import intake_evidence
    from backend.app.schemas.schemas import EvidenceIntakeRequest
    intake_req = EvidenceIntakeRequest(
        case_id=case.id,
        file_path=payload.get("file_path") or payload.get("path"),
        evidence_type=payload.get("evidence_type")
    )
    return intake_evidence(payload=intake_req, db=db, current_user=current_user)


@router.post("/{case_id}/close", response_model=CaseClosureResponse)
def close_case_endpoint(
    case_id: str,
    payload: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
    from backend.app.services.case_closure import CaseClosureService
    from backend.app.schemas.schemas import CaseClosureRequest
    rationale = (payload or {}).get("rationale") or f"Case closed by {current_user.email} via case management API"
    return CaseClosureService.validate_and_close_case(
        db=db,
        case_id=case.id,
        user=current_user,
        request_data=CaseClosureRequest(rationale=rationale)
    )


@router.post("/{case_id}/archive", response_model=CaseResponse)
def archive_case_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    require_case_admin(case, db, current_user)
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
        actor_name=current_user.email,
        event_type="CASE_ARCHIVED",
        details=f"Case '{case.name}' moved to immutable long-term archive."
    )
    return _build_case_response(case, db)


# -----------------------------------------------------------------------------
# Case Decisions & Execution Compatibility Routes
# -----------------------------------------------------------------------------

@router.post("/{case_id}/decisions", response_model=InvestigatorDecisionResponse, status_code=status.HTTP_201_CREATED)
def record_case_decision_compat(
    case_id: str,
    dec_in: InvestigatorDecisionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.app.models.models import InvestigatorDecision
    from backend.app.services.case_closure import check_case_not_closed

    case = get_authorized_case(case_id, db, current_user)
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


@router.get("/{case_id}/decisions", response_model=List[InvestigatorDecisionResponse])
def get_case_decisions_compat(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.app.models.models import InvestigatorDecision
    case = get_authorized_case(case_id, db, current_user)
    return db.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case.id).all()


@router.get("/{case_id}/executions")
def list_case_executions_compat(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.app.models.models import ToolExecution, ForensicExecution
    case = get_authorized_case(case_id, db, current_user)
    fe_list = (
        db.query(ForensicExecution)
        .filter(ForensicExecution.case_id == case.id)
        .order_by(ForensicExecution.created_at.desc())
        .all()
    )
    if fe_list:
        return fe_list
    return db.query(ToolExecution).filter(ToolExecution.case_id == case.id).all()


@router.get("/{case_id}/executions/{execution_id}")
def get_case_execution_compat(
    case_id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.app.models.models import ToolExecution, ForensicExecution
    case = get_authorized_case(case_id, db, current_user)
    fe = (
        db.query(ForensicExecution)
        .filter(ForensicExecution.id == execution_id, ForensicExecution.case_id == case.id)
        .first()
    )
    if fe:
        return fe
    exec_rec = (
        db.query(ToolExecution)
        .filter(ToolExecution.id == execution_id, ToolExecution.case_id == case.id)
        .first()
    )
    if not exec_rec:
        raise HTTPException(status_code=404, detail="Execution record not found.")
    return exec_rec


@router.post("/{case_id}/plan/execute")
def execute_case_plan_compat(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    from backend.app.api.endpoints.investigations import orchestrator_service
    try:
        return orchestrator_service.execute_plan(case_id=case.id, db=db)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))
