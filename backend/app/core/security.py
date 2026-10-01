import os
import re
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.app.core.config import settings

logger = logging.getLogger("ADFIR_AUDIT")
logger.setLevel(logging.INFO)

_LOGGER_INITIALIZED = False


def _ensure_security_logger() -> logging.Logger:
    global _LOGGER_INITIALIZED

    if _LOGGER_INITIALIZED:
        return logger

    audit_log_path = settings.LOGS_DIR / "security_audit.log"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        '[%(asctime)s UTC] [%(levelname)s] %(message)s'
    )

    existing_file_handlers = [
        h for h in logger.handlers
        if isinstance(h, logging.FileHandler)
        and Path(getattr(h, "baseFilename", "")).resolve()
        == audit_log_path.resolve()
    ]

    if not existing_file_handlers:
        handler = logging.FileHandler(str(audit_log_path))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    _LOGGER_INITIALIZED = True
    return logger

class SecurityValidator:
    """
    Core security validation routines to guarantee evidence safety and platform hardening.
    """

    @staticmethod
    def validate_file_path(untrusted_path: str, allow_nonexistent: bool = False) -> str:
        """
        Validates file path for null bytes, directory traversal, and existence.
        Returns canonicalized string path.
        """
        if not untrusted_path or not isinstance(untrusted_path, str):
            raise ValueError("Path must be a non-empty string.")

        if "\0" in untrusted_path:
            raise ValueError("Null bytes are prohibited in file paths.")

        # Reject path traversal patterns
        parts = untrusted_path.replace("\\", "/").split("/")
        if ".." in parts or untrusted_path.startswith(".."):
            raise ValueError("Path traversal patterns ('..') are prohibited.")

        # Resolve real path
        real_path = os.path.abspath(untrusted_path)

        if not allow_nonexistent and not os.path.exists(real_path):
            raise FileNotFoundError(f"Path does not exist: {real_path}")

        return real_path

    @staticmethod
    def validate_and_canonicalize_path(untrusted_path: str) -> Path:
        """
        Validates that a path is safe and points to a real file.
        Rejects path traversal, null bytes, and non-existent paths.
        """
        validated_str = SecurityValidator.validate_file_path(untrusted_path, allow_nonexistent=False)
        canonical = Path(validated_str)

        if not canonical.is_file():
            AuditLogger.log_event("INVALID_PATH_REJECTED", {"path": str(canonical), "reason": "Target is not a regular file"})
            raise ValueError(f"Path is not a regular file: {canonical}")

        return canonical

    @staticmethod
    def detect_evidence_type(path: Path) -> str:
        """
        Maps file extensions to standard forensic evidence categories.
        """
        ext = path.suffix.lower()
        name = path.name.lower()

        if ext in [".e01", ".e02", ".dd", ".img", ".raw", ".vmdk", ".vhd", ".qcow2"]:
            if "mem" in name:
                return "memory_dump"
            return "disk_image"
        elif ext in [".dmp", ".vmem"] or ("mem" in name and ext in [".bin", ".raw"]):
            return "memory_dump"
        elif ext in [".pcap", ".pcapng", ".cap"]:
            return "network_capture"
        elif ext in [".evtx", ".log", ".txt", ".csv", ".json", ".audit"] or "syslog" in name:
            return "log"
        elif ext in [".zip", ".tar", ".gz", ".7z", ".bz2"]:
            return "archive"
        elif ext in [".pdf", ".docx", ".xlsx", ".pptx", ".odt"]:
            return "document"
        elif path.is_dir():
            return "directory"
        return "unknown"

class AuditLogger:
    """
    Immutable structured audit logging for forensic actions and security events.
    """

    @staticmethod
    def log_event(event_type: str, details: Dict[str, Any], actor: str = "NOT_RECORDED"):
        now_utc = datetime.now(timezone.utc).isoformat()
        log_msg = f"EVENT={event_type} | ACTOR={actor} | DETAILS={details}"
        _ensure_security_logger().info(log_msg)


# =============================================================================
# Password Hashing & Authentication Routines
# =============================================================================

import secrets
import hashlib
import hmac
import uuid
import base64
import json
from datetime import timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from backend.app.core.config import settings, get_jwt_secret
from backend.app.core.database import get_db
from backend.app.models.models import User

REVOKED_TOKENS = set()


def hash_password(password: str) -> str:
    """
    Hashes password using PBKDF2-HMAC-SHA256 with 210,000 iterations and a 16-byte random salt.
    Format: $pbkdf2-sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password or len(password) < settings.PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long.")

    salt = secrets.token_bytes(16)
    iterations = 210000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"$pbkdf2-sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verifies plain password against stored PBKDF2-HMAC-SHA256 hash using constant-time comparison.
    """
    if not plain_password or not password_hash or not isinstance(password_hash, str) or not password_hash.startswith("$pbkdf2-sha256$"):
        return False

    try:
        parts = password_hash.split("$")
        if len(parts) != 5:
            return False
        iterations = int(parts[2])
        salt = bytes.fromhex(parts[3])
        expected_dk = bytes.fromhex(parts[4])

        actual_dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual_dk, expected_dk)
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str, expires_delta_minutes: Optional[int] = None) -> str:
    """
    Creates an HMAC-SHA256 signed JSON Web Token containing user identity claims.
    """
    delta = expires_delta_minutes if expires_delta_minutes is not None else settings.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    exp = int((now + timedelta(minutes=delta)).timestamp())
    iat = int(now.timestamp())
    jti = str(uuid.uuid4())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": exp,
        "iat": iat,
        "jti": jti,
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        get_jwt_secret().encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    return f"{signing_input}.{sig_b64}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies token signature, expiration, format, and revocation status.
    Fast path: checks in-memory REVOKED_TOKENS set.
    Fallback path: checks revoked_tokens DB table (handles post-restart cache miss).
    """
    if not token or not isinstance(token, str):
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts

    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        get_jwt_secret().encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256
    ).digest()

    def _b64_decode(s: str) -> bytes:
        padding = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)

    try:
        actual_sig = _b64_decode(sig_b64)
        if not hmac.compare_digest(actual_sig, expected_sig):
            return None

        payload_bytes = _b64_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        exp = payload.get("exp")
        if not exp or datetime.now(timezone.utc).timestamp() >= exp:
            return None

        jti = payload.get("jti")
        if jti:
            # Fast path: in-memory set
            if jti in REVOKED_TOKENS:
                return None
            # Fallback path: DB check for post-restart cache miss
            try:
                from backend.app.models.models import RevokedToken
                from backend.app.core.database import SessionLocal

                with SessionLocal() as _db:
                    db_revoked = (
                        _db.query(RevokedToken)
                        .filter(RevokedToken.jti == jti)
                        .first()
                    )

                    if db_revoked:
                        # Warm the in-memory cache to avoid repeat DB hits.
                        REVOKED_TOKENS.add(jti)
                        return None

            except Exception as exc:
                _ensure_security_logger().error(
                    "Persistent token revocation check failed; "
                    "rejecting token because authentication cannot be "
                    "safely verified: %s",
                    exc,
                )
                return None

        return payload
    except Exception:
        return None


def revoke_access_token(token: str) -> bool:
    """
    Revokes an access token by adding its JTI to the in-memory revocation registry
    AND persisting it to the database for durability across restarts.
    """
    payload = verify_access_token(token)
    if payload and payload.get("jti"):
        jti = payload["jti"]
        REVOKED_TOKENS.add(jti)
        # Persist to DB (graceful: if DB unavailable, in-memory revocation still works)
        try:
            from backend.app.models.models import RevokedToken
            from backend.app.core.database import SessionLocal
            from datetime import datetime, timezone
            with SessionLocal() as _db:
                existing = _db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
                if not existing:
                    _db.add(RevokedToken(jti=jti, revoked_at=datetime.now(timezone.utc)))
                    _db.commit()
        except Exception as _exc:
            _ensure_security_logger().warning(f"Could not persist token revocation to DB (in-memory revocation still active): {_exc}")
        return True
    return False


# =============================================================================
# FastAPI Security Dependencies
# =============================================================================

oauth2_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts Bearer token, verifies signature & expiration, and resolves User from database.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Verifies that authenticated user account is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user
