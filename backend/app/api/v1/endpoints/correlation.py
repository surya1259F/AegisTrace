"""ADFIR — Cross-Domain Correlation API Endpoints (Phase 2 / Step 14)

Case-scoped, RBAC-authorized REST endpoints for:
- Generating cross-domain relationships and deterministic correlation groups
- Listing and filtering relationships
- Retrieving relationship details, cryptographic integrity, and provenance
- Listing and querying correlation groups and member details
- Querying relationship graphs for visualization and traversal
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    ArtifactRelationship,
    ForensicCorrelationGroup,
    NormalizedArtifact,
    TimelineEvent,
    User,
)
from backend.app.schemas.schemas import (
    CorrelationGenerateRequest,
    CorrelationGraphResponse,
    CorrelationGroupDetailResponse,
    CorrelationGroupResponse,
    CorrelationSummaryResponse,
    GroupIntegrityResponse,
    RelationshipIntegrityResponse,
    RelationshipProvenanceResponse,
    RelationshipResponse,
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.correlation import (
    CrossDomainCorrelationService,
    CorrelationStorageManager,
)

router = APIRouter()


@router.post(
    "/cases/{case_id}/correlations/generate",
    response_model=CorrelationSummaryResponse,
    status_code=status.HTTP_200_OK
)
def generate_correlations_for_case(
    case_id: str,
    request: Optional[CorrelationGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Connects related normalized artifacts and timeline events across forensic domains
    and produces auditable correlation groups and relationships.
    Strictly evidence-based; does not declare attacks, threats, or findings.
    """
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)

    if request is None:
        request = CorrelationGenerateRequest()

    summary = CrossDomainCorrelationService.correlate_case(
        db=db,
        case_id=case_id,
        request=request
    )
    return summary


@router.get(
    "/cases/{case_id}/correlations/relationships",
    response_model=List[RelationshipResponse],
    status_code=status.HTTP_200_OK
)
def list_relationships(
    case_id: str,
    relationship_type: Optional[str] = Query(None, description="Filter by relationship type"),
    domain: Optional[str] = Query(None, description="Filter by source or target domain"),
    evidence_id: Optional[str] = Query(None, description="Filter by contributing evidence ID"),
    group_id: Optional[str] = Query(None, description="Filter by correlation group ID"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists evidence-derived relationships for a case with multi-criteria filtering.
    """
    get_authorized_case(case_id, db, current_user)

    query = db.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case_id)

    if relationship_type:
        query = query.filter(ArtifactRelationship.relationship_type == relationship_type)
    if group_id:
        query = query.filter(ArtifactRelationship.group_id == group_id)
    if min_confidence is not None:
        query = query.filter(ArtifactRelationship.confidence_score >= min_confidence)

    # Order deterministically
    query = query.order_by(ArtifactRelationship.confidence_score.desc(), ArtifactRelationship.id.asc())

    records = query.all()

    # In-memory filter for domain and evidence_id (stored in JSON / fields)
    if domain:
        dom = domain.upper()
        records = [
            r for r in records
            if r.source_domain == dom or r.target_domain == dom
        ]

    if evidence_id:
        records = [
            r for r in records
            if evidence_id in (r.evidence_ids or [])
        ]

    paginated = records[skip : skip + limit]
    return [RelationshipResponse.model_validate(r) for r in paginated]


@router.get(
    "/cases/{case_id}/correlations/relationships/{relationship_id}",
    response_model=RelationshipResponse,
    status_code=status.HTTP_200_OK
)
def get_relationship_details(
    case_id: str,
    relationship_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details for a specific artifact relationship.
    """
    get_authorized_case(case_id, db, current_user)

    rel = (
        db.query(ArtifactRelationship)
        .filter(ArtifactRelationship.case_id == case_id, ArtifactRelationship.id == relationship_id)
        .first()
    )
    if not rel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")

    return RelationshipResponse.model_validate(rel)


@router.get(
    "/cases/{case_id}/correlations/relationships/{relationship_id}/integrity",
    response_model=RelationshipIntegrityResponse,
    status_code=status.HTTP_200_OK
)
def verify_relationship_integrity(
    case_id: str,
    relationship_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic SHA-256 integrity and file consistency for a relationship.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return CrossDomainCorrelationService.verify_relationship_integrity(
            db=db,
            case_id=case_id,
            relationship_id=relationship_id
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")


@router.get(
    "/cases/{case_id}/correlations/relationships/{relationship_id}/provenance",
    response_model=RelationshipProvenanceResponse,
    status_code=status.HTTP_200_OK
)
def get_relationship_provenance(
    case_id: str,
    relationship_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Inspects end-to-end cryptographic provenance of both source and target in a relationship.
    """
    get_authorized_case(case_id, db, current_user)

    rel = (
        db.query(ArtifactRelationship)
        .filter(ArtifactRelationship.case_id == case_id, ArtifactRelationship.id == relationship_id)
        .first()
    )
    if not rel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")

    prov = rel.provenance or {}
    return RelationshipProvenanceResponse(
        relationship_id=rel.id,
        case_id=rel.case_id,
        relationship_type=rel.relationship_type,
        matching_identifier=rel.matching_identifier,
        matching_field=rel.matching_field,
        confidence_score=rel.confidence_score,
        evidence_ids=rel.evidence_ids or [],
        source_id=rel.source_id,
        source_type=rel.source_type,
        source_domain=rel.source_domain,
        source_provenance=prov.get("source", {}),
        target_id=rel.target_id,
        target_type=rel.target_type,
        target_domain=rel.target_domain,
        target_provenance=prov.get("target", {}),
        temporal_relationship=rel.temporal_relationship,
        created_at=rel.created_at,
    )


@router.get(
    "/cases/{case_id}/correlations/groups",
    response_model=List[CorrelationGroupResponse],
    status_code=status.HTTP_200_OK
)
def list_correlation_groups(
    case_id: str,
    domain: Optional[str] = Query(None, description="Filter by contributing domain"),
    evidence_id: Optional[str] = Query(None, description="Filter by contributing evidence ID"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists deterministic correlation groups for a case.
    """
    get_authorized_case(case_id, db, current_user)

    query = db.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case_id)

    if min_confidence is not None:
        query = query.filter(ForensicCorrelationGroup.confidence_score >= min_confidence)

    query = query.order_by(ForensicCorrelationGroup.confidence_score.desc(), ForensicCorrelationGroup.id.asc())
    groups = query.all()

    if domain:
        dom = domain.upper()
        groups = [
            g for g in groups
            if dom in [d.upper() for d in (g.contributing_domains or [])]
        ]

    if evidence_id:
        groups = [
            g for g in groups
            if evidence_id in (g.source_evidence_ids or [])
        ]

    paginated = groups[skip : skip + limit]
    return [CorrelationGroupResponse.model_validate(g) for g in paginated]


@router.get(
    "/cases/{case_id}/correlations/groups/{group_id}",
    response_model=CorrelationGroupDetailResponse,
    status_code=status.HTTP_200_OK
)
def get_correlation_group_details(
    case_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details for a correlation group including member artifacts, events, and relationships.
    """
    get_authorized_case(case_id, db, current_user)

    grp = (
        db.query(ForensicCorrelationGroup)
        .filter(ForensicCorrelationGroup.case_id == case_id, ForensicCorrelationGroup.id == group_id)
        .first()
    )
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation group not found")

    # Fetch member artifacts
    member_arts = []
    if grp.member_artifact_ids:
        arts = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.case_id == case_id, NormalizedArtifact.id.in_(grp.member_artifact_ids))
            .all()
        )
        member_arts = [
            {
                "id": a.id,
                "entity_type": a.entity_type,
                "entity_identity": a.entity_identity,
                "evidence_id": a.evidence_id,
                "normalized_fields": a.normalized_fields or {},
                "sha256_hash": a.sha256_hash,
            }
            for a in arts
        ]

    # Fetch member timeline events
    member_evs = []
    if grp.member_event_ids:
        evs = (
            db.query(TimelineEvent)
            .filter(TimelineEvent.case_id == case_id, TimelineEvent.id.in_(grp.member_event_ids))
            .all()
        )
        member_evs = [
            {
                "id": e.id,
                "event_type": e.event_type,
                "event_source": e.event_source,
                "timestamp_utc": e.timestamp_utc.isoformat() if e.timestamp_utc else None,
                "evidence_id": e.evidence_id,
                "confidence_score": e.confidence_score,
                "sha256_hash": e.sha256_hash,
            }
            for e in evs
        ]

    # Fetch relationships in this group
    rels = (
        db.query(ArtifactRelationship)
        .filter(ArtifactRelationship.case_id == case_id, ArtifactRelationship.group_id == group_id)
        .all()
    )

    base_resp = CorrelationGroupResponse.model_validate(grp).model_dump()
    return CorrelationGroupDetailResponse(
        **base_resp,
        member_artifacts=member_arts,
        member_events=member_evs,
        relationships=[RelationshipResponse.model_validate(r) for r in rels],
    )


@router.get(
    "/cases/{case_id}/correlations/groups/{group_id}/integrity",
    response_model=GroupIntegrityResponse,
    status_code=status.HTTP_200_OK
)
def verify_group_integrity(
    case_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifies cryptographic SHA-256 integrity and file consistency for a correlation group.
    """
    get_authorized_case(case_id, db, current_user)

    try:
        return CrossDomainCorrelationService.verify_group_integrity(
            db=db,
            case_id=case_id,
            group_id=group_id
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation group not found")


@router.get(
    "/cases/{case_id}/correlations/graph",
    response_model=CorrelationGraphResponse,
    status_code=status.HTTP_200_OK
)
def get_correlation_graph(
    case_id: str,
    group_id: Optional[str] = Query(None, description="Filter by correlation group ID"),
    relationship_type: Optional[str] = Query(None, description="Filter by relationship type"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    evidence_id: Optional[str] = Query(None, description="Filter by evidence ID"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves queryable relationship graph data:
    Artifact/Event -> Relationship -> Artifact/Event.
    """
    get_authorized_case(case_id, db, current_user)

    return CrossDomainCorrelationService.build_relationship_graph(
        db=db,
        case_id=case_id,
        group_id=group_id,
        relationship_type=relationship_type,
        domain=domain,
        evidence_id=evidence_id,
        min_confidence=min_confidence,
    )
