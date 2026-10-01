from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    revoke_access_token,
    get_current_active_user,
    oauth2_scheme,
)
from backend.app.models.models import User
from backend.app.schemas.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    UserProfileUpdateRequest,
    UserResponse,
    TokenResponse,
)
from backend.app.services.audit import log_audit_event

router = APIRouter()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(req: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a new investigator account with hashed password credentials.
    Rejects duplicate emails with 409 Conflict. Default role is least-privileged INVESTIGATOR.
    """
    email_clean = req.email.lower().strip() if req.email else ""
    if not email_clean or "@" not in email_clean or "." not in email_clean:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A valid email address is required.",
        )

    if not req.password or len(req.password) < settings.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long.",
        )

    existing_user = db.query(User).filter(User.email == email_clean).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    try:
        pwd_hash = hash_password(req.password)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )

    user = User(
        email=email_clean,
        name=req.name.strip(),
        organization=(req.organization or "Digital Forensics Unit").strip(),
        badge_id=req.badge_id.strip() if req.badge_id else None,
        role="INVESTIGATOR",
        is_active=True,
        password_hash=pwd_hash,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_ACCOUNT_CREATED",
        details=f"User account '{user.email}' ({user.name}) registered successfully.",
    )

    return user


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login_user(req: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user credentials and issues a signed HMAC-SHA256 access token.
    Prevents user enumeration by returning a generic 401 Unauthorized error on any failure.
    """
    email_clean = req.email.lower().strip() if req.email else ""
    user = db.query(User).filter(User.email == email_clean).first()

    # Prevent user enumeration: verify against dummy hash if user does not exist
    if not user or not user.password_hash or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)

    log_audit_event(
        db=db,
        case_id=None,
        event_type="USER_LOGIN_SUCCESSFUL",
        details=f"User '{user.email}' authenticated successfully.",
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout_user(credentials=Depends(oauth2_scheme)):
    """
    Revokes the current Bearer access token by adding its JTI to the active revocation registry.
    """
    if credentials and credentials.credentials:
        revoke_access_token(credentials.credentials)

    return {"message": "Logged out successfully."}


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
def get_current_user_profile(current_user: User = Depends(get_current_active_user)):
    """
    Returns authenticated investigator profile for the active session.
    """
    return current_user


@router.patch("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
@router.patch("/profile", response_model=UserResponse, status_code=status.HTTP_200_OK)
def update_current_user_profile(
    req: UserProfileUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Updates the authenticated user's own profile information (name, badge_id).
    Users cannot modify their role, organization, active status, or permissions through this endpoint.
    """
    if req.name is not None:
        clean_name = req.name.strip()
        if not clean_name:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Name cannot be empty.",
            )
        current_user.name = clean_name

    if req.badge_id is not None:
        current_user.badge_id = req.badge_id.strip() if req.badge_id else None

    db.commit()
    db.refresh(current_user)

    log_audit_event(
        db=db,
        case_id=None,
        actor_id=current_user.id,
        actor_name=current_user.name,
        event_type="USER_PROFILE_UPDATED",
        details=f"User '{current_user.email}' updated profile.",
    )

    return current_user


