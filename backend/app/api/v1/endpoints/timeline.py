"""
ADFIR — Unified Investigation Timeline API Endpoints (Phase 2 / Step 13)

Case-scoped, RBAC-authorized REST endpoints for:
- Generating unified UTC timeline events from normalized artifacts
- Listing and querying timeline events chronologically with multi-criteria filtering
- Inspecting timeline event details, cryptographic integrity, and end-to-end provenance
- Securely downloading serialized timeline event JSON payloads
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path
from datetime import datetime

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    ForensicExecution,
    NormalizedArtifact,
    TimelineEvent,
    User
)
from backend.app.schemas.schemas import (
    TimelineEventResponse,
    TimelineIntegrityResponse,
    TimelineProvenanceResponse,
    TimelineBatchResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.timeline import (
    UnifiedTimelineService,
    TimelineStorageManager
)

router = APIRouter()


@router.post(
    "/cases/{case_id}/timeline/generate",
    response_model=TimelineBatchResponse,
    status_code=status.HTTP_200_OK
)
def generate_timeline_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generates unified UTC timeline events for all normalized artifacts in the case.
    Preserves exact original timestamps and timezones without inventing missing timestamps.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    result = UnifiedTimelineService.generate_timeline_for_case(
        db=db,
        case_id=case_id,
        actor_user=current_user
    )

    return TimelineBatchResponse(**result)


@router.post(
    "/cases/{case_id}/executions/{execution_id}/timeline/generate",
    response_model=TimelineBatchResponse,
    status_code=status.HTTP_200_OK
)
def generate_timeline_for_execution(
    case_id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generates unified UTC timeline events for all normalized artifacts produced by a specific execution.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic execution not found")

    if execution.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution does not belong to specified case")

    result = UnifiedTimelineService.generate_timeline_for_execution(
        db=db,
        execution_id=execution_id,
        case_id=case_id,
        actor_user=current_user
    )

    return TimelineBatchResponse(**result)


@router.post(
    "/cases/{case_id}/normalized-artifacts/{artifact_id}/timeline",
    response_model=List[TimelineEventResponse],
    status_code=status.HTTP_200_OK
)
def generate_timeline_for_artifact(
    case_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generates timeline events for a specific normalized artifact.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    na = db.query(NormalizedArtifact).filter(NormalizedArtifact.id == artifact_id).first()
    if not na:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Normalized artifact not found")

    if na.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Normalized artifact does not belong to specified case")

    events = UnifiedTimelineService.extract_events_from_normalized_artifact(
        db=db,
        normalized_art=na,
        actor_user=current_user
    )

    return events


@router.get(
    "/cases/{case_id}/timeline",
    response_model=List[TimelineEventResponse]
)
def list_timeline_events(
    case_id: str,
    start_time: Optional[datetime] = Query(None, description="Filter events after or at this UTC datetime"),
    end_time: Optional[datetime] = Query(None, description="Filter events before or at this UTC datetime"),
    event_type: Optional[str] = Query(None, description="Filter by event type (e.g. FILE_MODIFIED, PROCESS_LAUNCH)"),
    event_source: Optional[str] = Query(None, description="Filter by event source (e.g. FLS, EVTX, PSLIST)"),
    evidence_id: Optional[str] = Query(None, description="Filter by source evidence item ID"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists timeline events chronologically sorted by UTC timestamp with deterministic tie-breaking.
    Supports filtering by time range, event type, source, evidence, and confidence.
    """
    get_authorized_case(case_id, db, current_user)

    return UnifiedTimelineService.list_timeline_events(
        db=db,
        case_id=case_id,
        start_time=start_time,
        end_time=end_time,
        event_type=event_type,
        event_source=event_source,
        evidence_id=evidence_id,
        min_confidence=min_confidence,
        skip=skip,
        limit=limit
    )


@router.get(
    "/cases/{case_id}/timeline/{event_id}",
    response_model=TimelineEventResponse
)
def get_timeline_event_details(
    case_id: str,
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a timeline event.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return UnifiedTimelineService.get_timeline_event(
            db=db,
            event_id=event_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/timeline/{event_id}/integrity",
    response_model=TimelineIntegrityResponse
)
def verify_timeline_event_integrity(
    case_id: str,
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic SHA-256 integrity and lineage back to source normalized artifact.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return UnifiedTimelineService.verify_timeline_event_integrity(
            db=db,
            event_id=event_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/timeline/{event_id}/provenance",
    response_model=TimelineProvenanceResponse
)
def get_timeline_event_provenance(
    case_id: str,
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects full multi-tier provenance chain:
    EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact -> TimelineEvent.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return UnifiedTimelineService.get_timeline_event_provenance(
            db=db,
            event_id=event_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/timeline/{event_id}/download"
)
def download_timeline_event_file(
    case_id: str,
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Downloads the serialized JSON file of the timeline event.
    Enforces path containment and evidence vault isolation.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        event = UnifiedTimelineService.get_timeline_event(
            db=db,
            event_id=event_id,
            case_id=case_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    if not event.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Timeline event storage path not defined")

    file_path = Path(event.storage_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Timeline event file does not exist on disk")

    try:
        TimelineStorageManager.validate_storage_path(file_path, case_id)
    except Exception as sec_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied: {sec_err}")

    return FileResponse(
        path=str(file_path),
        filename=f"timeline_{event.event_type.lower()}_{event.id[:8]}.json",
        media_type="application/json"
    )
