from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import (
    hash_password,
    get_current_active_user,
)
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    UserResponse,
    UserAdminCreateRequest,
    UserAdminUpdateRequest,
)
from backend.app.services.authorization import (
    require_permission,
    require_role,
    VALID_CASE_MEMBER_ROLES,
)
from backend.app.services.audit import log_audit_event

router = APIRouter()

VALID_GLOBAL_ROLES = {"ADMIN", "ADMINISTRATOR", "ORG_ADMIN", "INVESTIGATOR", "ANALYST", "VIEWER"}


def _verify_organization_boundary(target_user: User, current_user: User):
    """
    Enforces Organization isolation: non-ADMIN users may only access/manage users within their own Organization.
    Global ADMIN users bypass organization boundaries.
    """
    if current_user.role in ("ADMIN", "ADMINISTRATOR"):
        return

    if target_user.organization != current_user.organization:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cannot access user in a different organization."
        )


@router.get("", response_model=List[UserResponse], status_code=status.HTTP_200_OK)
@router.get("/", response_model=List[UserResponse], status_code=status.HTTP_200_OK)
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_READ"))
):
    """
    Lists users. Global ADMIN retrieves all users across organizations.
    Non-ADMIN users receive users scoped exclusively to their own Organization.
    """
    if current_user.role in ("ADMIN", "ADMINISTRATOR"):
        return db.query(User).order_by(User.name.asc()).all()

    return db.query(User).filter(User.organization == current_user.organization).order_by(User.name.asc()).all()


@router.get("/{user_id}", response_model=UserResponse, status_code=status.HTTP_200_OK)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_READ"))
):
    """
    Retrieves details for a specific user. Enforces Organization isolation boundary for non-ADMIN actors.
    """
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    _verify_organization_boundary(target, current_user)
    return target


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    req: UserAdminCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_CREATE"))
):
    """
    Administratively provisions a new user account.
    Validates email format, password complexity, role allowlist, and organization boundary.
    """
    email_clean = req.email.lower().strip() if req.email else ""
    if not email_clean or "@" not in email_clean or "." not in email_clean:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A valid email address is required."
        )

    if not req.password or len(req.password) < settings.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long."
        )

    existing = db.query(User).filter(User.email == email_clean).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists."
        )

    requested_role = (req.role or "INVESTIGATOR").upper().strip()
    if requested_role not in VALID_GLOBAL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid global role '{req.role}'. Must be one of {sorted(list(VALID_GLOBAL_ROLES))}."
        )

    # Prevent non-ADMIN users from creating global ADMIN accounts
    if requested_role in ("ADMIN", "ADMINISTRATOR") and current_user.role not in ("ADMIN", "ADMINISTRATOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Only a global administrator can create administrator accounts."
        )

    # Organization scoping
    if current_user.role in ("ADMIN", "ADMINISTRATOR"):
        target_org = req.organization.strip() if req.organization else current_user.organization
    else:
        target_org = current_user.organization

    pwd_hash = hash_password(req.password)
    new_user = User(
        email=email_clean,
        name=req.name.strip(),
        organization=target_org,
        badge_id=req.badge_id.strip() if req.badge_id else None,
        role=requested_role,
        is_active=True,
        password_hash=pwd_hash,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_CREATED",
        details=f"Admin '{current_user.email}' created user account '{new_user.email}' with role '{new_user.role}' in org '{new_user.organization}'.",
    )

    return new_user


@router.patch("/{user_id}", response_model=UserResponse, status_code=status.HTTP_200_OK)
def update_user(
    user_id: str,
    req: UserAdminUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_UPDATE"))
):
    """
    Administratively updates user profile, organization, role, or active status.
    Enforces Organization boundary and privilege escalation protections.
    """
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    _verify_organization_boundary(target, current_user)

    # 1. Name update
    if req.name is not None and req.name.strip():
        target.name = req.name.strip()

    # 2. Badge ID update
    if req.badge_id is not None:
        target.badge_id = req.badge_id.strip() if req.badge_id else None

    # 3. Organization update
    if req.organization is not None and req.organization.strip():
        new_org = req.organization.strip()
        if current_user.role not in ("ADMIN", "ADMINISTRATOR") and new_org != current_user.organization:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Only a global administrator can change user organization assignment."
            )
        if target.organization != new_org:
            old_org = target.organization
            target.organization = new_org
            log_audit_event(
                db=db,
                case_id=None,
                event_type="ORGANIZATION_CHANGED",
                details=f"User '{target.email}' organization changed from '{old_org}' to '{new_org}' by '{current_user.email}'.",
            )

    # 4. Role update
    if req.role is not None and req.role.strip():
        new_role = req.role.upper().strip()
        if new_role not in VALID_GLOBAL_ROLES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid global role '{req.role}'."
            )

        # Prevent non-ADMIN users from promoting anyone to ADMIN
        if new_role in ("ADMIN", "ADMINISTRATOR") and current_user.role not in ("ADMIN", "ADMINISTRATOR"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Only global administrators can grant administrator role."
            )

        # Prevent self-demotion or self-escalation if modifying self
        if current_user.id == target.id and target.role != new_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Self role modification is prohibited. Users cannot alter their own global application role."
            )

        if target.role != new_role:
            old_role = target.role
            target.role = new_role
            log_audit_event(
                db=db,
                case_id=None,
                event_type="ROLE_CHANGED",
                details=f"User '{target.email}' role changed from '{old_role}' to '{new_role}' by '{current_user.email}'.",
            )

    # 5. Account active status update
    if req.is_active is not None:
        if current_user.id == target.id and not req.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Self-disabling is prohibited."
            )
        if target.is_active != req.is_active:
            target.is_active = req.is_active
            status_str = "ENABLED" if req.is_active else "DISABLED"
            log_audit_event(
                db=db,
                case_id=None,
                event_type=f"USER_{status_str}",
                details=f"User account '{target.email}' set to {status_str} by '{current_user.email}'.",
            )

    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_UPDATED",
        details=f"User account '{target.email}' updated by '{current_user.email}'.",
    )

    return target


@router.post("/{user_id}/enable", response_model=UserResponse, status_code=status.HTTP_200_OK)
def enable_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_DISABLE"))
):
    """
    Enables a disabled user account.
    """
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    _verify_organization_boundary(target, current_user)

    target.is_active = True
    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_ENABLED",
        details=f"User account '{target.email}' enabled by '{current_user.email}'.",
    )

    return target


@router.post("/{user_id}/disable", response_model=UserResponse, status_code=status.HTTP_200_OK)
def disable_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_DISABLE"))
):
    """
    Disables an active user account. Prevents self-disabling.
    """
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-disabling is prohibited."
        )

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    _verify_organization_boundary(target, current_user)

    target.is_active = False
    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_DISABLED",
        details=f"User account '{target.email}' disabled by '{current_user.email}'.",
    )

    return target


@router.delete("/{user_id}", response_model=UserResponse, status_code=status.HTTP_200_OK)
def deactivate_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("USER_DELETE"))
):
    """
    Soft-deactivates a user account while strictly preserving all historical audit, case, evidence, and custody records.
    Prevent hard deletion of forensic history. Rejects self-deactivation.
    """
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-deactivation is prohibited."
        )

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    _verify_organization_boundary(target, current_user)

    target.is_active = False
    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_DEACTIVATED",
        details=f"User account '{target.email}' deactivated by '{current_user.email}'. Historical audit & forensic records preserved.",
    )

    return target
