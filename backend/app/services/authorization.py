from typing import List, Optional, Dict, Set
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.models.models import Case, CaseMember, User
from backend.app.core.security import get_current_active_user

# Master Granular Permissions Matrix
PERMISSIONS_BY_ROLE: Dict[str, List[str]] = {
    "ADMIN": [
        "USER_READ", "USER_CREATE", "USER_UPDATE", "USER_DISABLE", "USER_DELETE",
        "ROLE_READ", "ROLE_CREATE", "ROLE_UPDATE", "ROLE_DELETE",
        "CASE_CREATE", "CASE_READ", "CASE_UPDATE", "CASE_DELETE",
        "EVIDENCE_IMPORT", "EVIDENCE_READ", "EVIDENCE_HASH",
        "CHAIN_OF_CUSTODY_READ", "CHAIN_OF_CUSTODY_UPDATE",
        "INVESTIGATION_CREATE", "INVESTIGATION_READ", "INVESTIGATION_EXECUTE", "INVESTIGATION_STOP",
        "FORENSIC_TOOL_EXECUTE",
        "AGENT_EXECUTE", "AGENT_READ",
        "REPORT_CREATE", "REPORT_READ", "REPORT_EXPORT",
        "AUDIT_LOG_READ",
        "SYSTEM_CONFIGURATION_READ", "SYSTEM_CONFIGURATION_UPDATE"
    ],
    "ADMINISTRATOR": [
        "USER_READ", "USER_CREATE", "USER_UPDATE", "USER_DISABLE", "USER_DELETE",
        "ROLE_READ", "ROLE_CREATE", "ROLE_UPDATE", "ROLE_DELETE",
        "CASE_CREATE", "CASE_READ", "CASE_UPDATE", "CASE_DELETE",
        "EVIDENCE_IMPORT", "EVIDENCE_READ", "EVIDENCE_HASH",
        "CHAIN_OF_CUSTODY_READ", "CHAIN_OF_CUSTODY_UPDATE",
        "INVESTIGATION_CREATE", "INVESTIGATION_READ", "INVESTIGATION_EXECUTE", "INVESTIGATION_STOP",
        "FORENSIC_TOOL_EXECUTE",
        "AGENT_EXECUTE", "AGENT_READ",
        "REPORT_CREATE", "REPORT_READ", "REPORT_EXPORT",
        "AUDIT_LOG_READ",
        "SYSTEM_CONFIGURATION_READ", "SYSTEM_CONFIGURATION_UPDATE"
    ],
    "ORG_ADMIN": [
        "USER_READ", "USER_CREATE", "USER_UPDATE", "USER_DISABLE", "USER_DELETE",
        "ROLE_READ",
        "CASE_CREATE", "CASE_READ", "CASE_UPDATE", "CASE_DELETE",
        "EVIDENCE_IMPORT", "EVIDENCE_READ", "EVIDENCE_HASH",
        "CHAIN_OF_CUSTODY_READ", "CHAIN_OF_CUSTODY_UPDATE",
        "INVESTIGATION_CREATE", "INVESTIGATION_READ", "INVESTIGATION_EXECUTE", "INVESTIGATION_STOP",
        "FORENSIC_TOOL_EXECUTE",
        "AGENT_EXECUTE", "AGENT_READ",
        "REPORT_CREATE", "REPORT_READ", "REPORT_EXPORT",
        "AUDIT_LOG_READ",
        "SYSTEM_CONFIGURATION_READ"
    ],
    "INVESTIGATOR": [
        "USER_READ",
        "CASE_CREATE", "CASE_READ", "CASE_UPDATE", "CASE_DELETE",
        "EVIDENCE_IMPORT", "EVIDENCE_READ", "EVIDENCE_HASH",
        "CHAIN_OF_CUSTODY_READ", "CHAIN_OF_CUSTODY_UPDATE",
        "INVESTIGATION_CREATE", "INVESTIGATION_READ", "INVESTIGATION_EXECUTE", "INVESTIGATION_STOP",
        "FORENSIC_TOOL_EXECUTE",
        "AGENT_EXECUTE", "AGENT_READ",
        "REPORT_CREATE", "REPORT_READ", "REPORT_EXPORT",
        "AUDIT_LOG_READ",
        "SYSTEM_CONFIGURATION_READ"
    ],
    "ANALYST": [
        "USER_READ",
        "CASE_READ",
        "EVIDENCE_READ",
        "CHAIN_OF_CUSTODY_READ",
        "INVESTIGATION_READ", "INVESTIGATION_EXECUTE",
        "FORENSIC_TOOL_EXECUTE",
        "AGENT_EXECUTE", "AGENT_READ",
        "REPORT_CREATE", "REPORT_READ", "REPORT_EXPORT",
        "AUDIT_LOG_READ"
    ],
    "VIEWER": [
        "USER_READ",
        "CASE_READ",
        "EVIDENCE_READ",
        "CHAIN_OF_CUSTODY_READ",
        "INVESTIGATION_READ",
        "AGENT_READ",
        "REPORT_READ"
    ]
}


def get_role_permissions(role: str) -> List[str]:
    """
    Returns the list of granular permissions associated with a role.
    Defaults to VIEWER permissions if role is unknown.
    """
    if not role:
        return list(PERMISSIONS_BY_ROLE["VIEWER"])
    role_upper = role.upper().strip()
    return list(PERMISSIONS_BY_ROLE.get(role_upper, PERMISSIONS_BY_ROLE["VIEWER"]))


def has_permission(user_role: str, permission: str) -> bool:
    """
    Checks if a given user role possesses a specific granular permission.
    """
    perms = get_role_permissions(user_role)
    return permission in perms


def require_permission(permission: str):
    """
    FastAPI dependency enforcing that current_user has the specified granular permission.
    """
    def _permission_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if not has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Missing required permission '{permission}'."
            )
        return current_user
    return _permission_checker


def require_role(allowed_roles: List[str]):
    """
    FastAPI dependency enforcing that current_user has one of the allowed global roles.
    ADMIN is always authorized.
    """
    def _role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        user_role = (current_user.role or "").upper().strip()
        cleaned_allowed = [r.upper().strip() for r in allowed_roles]
        if user_role not in cleaned_allowed and user_role not in ("ADMIN", "ADMINISTRATOR"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: User role '{user_role}' is not in allowed roles {allowed_roles}."
            )
        return current_user
    return _role_checker


def get_authorized_case(case_id: str, db: Session, current_user: User) -> Case:
    """
    Retrieves a case by ID and verifies that current_user is either the owner or an active CaseMember.
    Raises HTTP 404 if case does not exist.
    Raises HTTP 403 if user is not authorized.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found."
        )

    # Check ownership
    is_owner = (
        (case.owner_id and case.owner_id == current_user.id)
        or (case.created_by == current_user.id)
        or (case.created_by == current_user.email)
        or (current_user.role in ("ADMIN", "ADMINISTRATOR"))
    )

    # Check membership
    is_member = (
        db.query(CaseMember)
        .filter(CaseMember.case_id == case_id, CaseMember.user_id == current_user.id)
        .first() is not None
    )

    if not (is_owner or is_member):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not authorized to access this case."
        )

    return case


def validate_case_access(first_arg, second_arg, current_user: Optional[User] = None) -> Case:
    """
    Validates case access for current_user.
    Supports both signatures:
      (case_id: str, db: Session, current_user: User)
      (db: Session, case_id: str, current_user: Optional[User])
    """
    if isinstance(first_arg, str):
        case_id = first_arg
        db = second_arg
    else:
        db = first_arg
        case_id = second_arg

    if current_user is None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
        return case
    return get_authorized_case(case_id=case_id, db=db, current_user=current_user)



def get_user_cases(db: Session, current_user: User) -> List[Case]:
    """
    Returns all cases that current_user owns or is an active CaseMember of.
    Global ADMIN users have access to all cases.
    """
    if current_user.role in ("ADMIN", "ADMINISTRATOR"):
        return db.query(Case).order_by(Case.created_at.desc()).all()

    member_case_ids = (
        db.query(CaseMember.case_id)
        .filter(CaseMember.user_id == current_user.id)
        .subquery()
    )

    return (
        db.query(Case)
        .filter(
            or_(
                Case.owner_id == current_user.id,
                Case.created_by == current_user.id,
                Case.created_by == current_user.email,
                Case.id.in_(member_case_ids)
            )
        )
        .order_by(Case.created_at.desc())
        .all()
    )


def validate_indirect_resource_case(resource_case_id: str, expected_case_id: str, resource_name: str = "Resource"):
    """
    Verifies that an indirect resource's owning case_id matches the target authorized case_id.
    Prevents IDOR via indirect resource identifiers.
    """
    if resource_case_id != expected_case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource_name} not found in this case."
        )


VALID_CASE_MEMBER_ROLES = {
    "PRIMARY_INVESTIGATOR",
    "CASE_ADMIN",
    "INVESTIGATOR",
    "ANALYST",
    "COLLABORATOR",
    "VIEWER",
}


def validate_case_member_role(role: Optional[str]) -> str:
    """
    Sanitizes and validates requested CaseMember role.
    Converts 'ADMIN' to 'CASE_ADMIN' so global user roles are never conflated with case roles.
    Defaults to 'COLLABORATOR' if empty or invalid.
    """
    if not role:
        return "COLLABORATOR"
    role_upper = role.upper().strip()
    if role_upper == "ADMIN":
        return "CASE_ADMIN"
    if role_upper in VALID_CASE_MEMBER_ROLES:
        return role_upper
    return "COLLABORATOR"


def is_case_admin(case: Case, db: Session, current_user: User) -> bool:
    """
    Returns True if current_user has case administration privileges for the specified case.
    Authorized case administrators include:
    - Global application ADMIN (current_user.role in ('ADMIN', 'ADMINISTRATOR'))
    - Case Owner (case.owner_id == current_user.id or case.created_by in (current_user.id, current_user.email))
    - CaseMember with role in ('PRIMARY_INVESTIGATOR', 'CASE_ADMIN')
    """
    if getattr(current_user, "role", None) in ("ADMIN", "ADMINISTRATOR"):
        return True

    is_owner = (
        (case.owner_id and case.owner_id == current_user.id)
        or (case.created_by == current_user.id)
        or (case.created_by == current_user.email)
    )
    if is_owner:
        return True

    member = (
        db.query(CaseMember)
        .filter(CaseMember.case_id == case.id, CaseMember.user_id == current_user.id)
        .first()
    )
    if member and member.role in ("PRIMARY_INVESTIGATOR", "CASE_ADMIN"):
        return True

    return False


def require_case_admin(case: Case, db: Session, current_user: User):
    """
    Raises HTTP 403 Forbidden if current_user is not an authorized case administrator or case owner.
    """
    if not is_case_admin(case, db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Only case owner or authorized case administrator can perform member administration."
        )


def ensure_case_member(case_id: str, user_id: str, db: Session, role: str = "PRIMARY_INVESTIGATOR") -> CaseMember:
    """
    Ensures a CaseMember record exists for the given user_id and case_id.
    Updates role if member already exists.
    """
    clean_role = validate_case_member_role(role)
    member = (
        db.query(CaseMember)
        .filter(CaseMember.case_id == case_id, CaseMember.user_id == user_id)
        .first()
    )
    if not member:
        member = CaseMember(
            case_id=case_id,
            user_id=user_id,
            role=clean_role
        )
        db.add(member)
    else:
        member.role = clean_role
    db.commit()
    db.refresh(member)
    return member


