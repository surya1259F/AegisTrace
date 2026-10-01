import os
import json
import re
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.models import Case
from backend.app.services.audit import log_audit_event

STANDARD_SUBDIRECTORIES = [
    "evidence",
    "forensic_outputs",
    "analysis",
    "findings",
    "reports",
    "logs",
    "tmp",
]

def validate_case_id(case_id: str) -> str:
    """
    Validates case_id against path traversal attacks and illegal characters.
    """
    if not case_id or not isinstance(case_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case ID: case ID cannot be empty."
        )
    
    clean_id = case_id.strip()
    # Ensure no path traversal tokens or invalid file system chars
    if ".." in clean_id or "/" in clean_id or "\\" in clean_id or "\0" in clean_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case ID: path traversal or invalid characters detected."
        )
    
    if not re.match(r"^[A-Za-z0-9_\-]+$", clean_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case ID: contains disallowed characters."
        )
        
    return clean_id


def get_base_data_dir() -> Path:
    """
    Returns the root data directory configured via environment variable ADFIR_DATA_DIR
    or defaults to settings.DATA_DIR.
    """
    from backend.app.core.config import settings
    data_dir_env = os.environ.get("ADFIR_DATA_DIR")
    if data_dir_env:
        return Path(data_dir_env).resolve()
    return settings.DATA_DIR


def get_case_workspace_path(case_id: str) -> Path:
    """
    Returns the absolute path to the case workspace directory.
    Enforces path traversal safety.
    """
    clean_id = validate_case_id(case_id)
    base_dir = get_base_data_dir()
    case_path = (base_dir / "cases" / clean_id).resolve()
    
    # Ensure workspace directory is strictly within base cases directory
    cases_root = (base_dir / "cases").resolve()
    if not str(case_path).startswith(str(cases_root)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security error: Case workspace path traversal detected."
        )
        
    return case_path


def initialize_case_workspace(case: Case, db: Session, actor_id: str = None, actor_name: str = "system") -> Dict[str, Any]:
    """
    Initializes a deterministic, isolated workspace for the given Case on local disk.
    Creates all required subdirectories and case_metadata.json.
    Updates case.workspace_state and case.workspace_path in DB.
    Logs an audit event.
    """
    workspace_path = get_case_workspace_path(case.id)
    workspace_path.mkdir(parents=True, exist_ok=True)
    
    for subdir in STANDARD_SUBDIRECTORIES:
        (workspace_path / subdir).mkdir(parents=True, exist_ok=True)
        
    metadata = {
        "case_id": case.id,
        "case_number": case.case_number,
        "name": case.name,
        "title": case.title or case.name,
        "objective": case.objective,
        "case_type": case.case_type or "GENERAL_INVESTIGATION",
        "priority": case.priority or "MEDIUM",
        "status": case.status or "OPEN",
        "owner_id": case.owner_id,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "workspace_state": "READY",
        "initialized_at": datetime.now(timezone.utc).isoformat(),
        "subdirectories": STANDARD_SUBDIRECTORIES,
    }
    
    metadata_file = workspace_path / "case_metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    case.workspace_state = "READY"
    case.workspace_path = str(workspace_path)
    db.add(case)
    db.commit()
    db.refresh(case)
    
    log_audit_event(
        db=db,
        event_type="CASE_WORKSPACE_INITIALIZED",
        details=f"Workspace initialized for case '{case.case_number}' at path '{workspace_path}'",
        case_id=case.id,
        actor_id=actor_id or case.owner_id,
        actor_name=actor_name or case.created_by or "system",
        metadata_json={
            "workspace_path": str(workspace_path),
            "subdirectories": STANDARD_SUBDIRECTORIES
        }
    )
    
    return {
        "case_id": case.id,
        "workspace_state": "READY",
        "workspace_path": str(workspace_path),
        "subdirectories": STANDARD_SUBDIRECTORIES,
        "initialized_at": metadata["initialized_at"],
    }


def get_workspace_status(case: Case) -> Dict[str, Any]:
    """
    Inspects disk structure to verify workspace status.
    """
    if not case.workspace_path:
        return {
            "case_id": case.id,
            "workspace_state": case.workspace_state or "NOT_INITIALIZED",
            "workspace_path": None,
            "exists": False,
            "subdirectories_present": [],
            "metadata_present": False,
        }
        
    path = Path(case.workspace_path)
    exists = path.exists() and path.is_dir()
    present_dirs = []
    metadata_present = False
    
    if exists:
        metadata_present = (path / "case_metadata.json").exists()
        for subdir in STANDARD_SUBDIRECTORIES:
            if (path / subdir).exists() and (path / subdir).is_dir():
                present_dirs.append(subdir)
                
    is_fully_valid = exists and metadata_present and len(present_dirs) == len(STANDARD_SUBDIRECTORIES)
    computed_state = "READY" if is_fully_valid else ("PARTIAL" if exists else "NOT_INITIALIZED")
    
    return {
        "case_id": case.id,
        "workspace_state": case.workspace_state or computed_state,
        "workspace_path": str(path),
        "exists": exists,
        "subdirectories_present": present_dirs,
        "metadata_present": metadata_present,
        "is_ready": is_fully_valid
    }
