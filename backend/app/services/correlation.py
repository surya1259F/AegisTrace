"""ADFIR Cross-Domain Correlation Subsystem (Phase 2 / Step 14)

Connects related normalized artifacts (Step 12) and timeline events (Step 13)
across forensic domains and produces auditable correlation groups and relationship graphs.

STRICT FORENSIC BOUNDARIES:
- Produces evidence-derived relationships and deterministic correlation groups only.
- NEVER declares an attack, breach, or compromise.
- NEVER infers attacker behavior, intent, or tactics.
- NEVER generates findings, conclusions, or incident severity ratings.
- NEVER invokes LLM reasoning or heuristic speculation.
- NEVER modifies source artifacts (Evidence, Outputs, Structured, Normalized, Timeline).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    ArtifactRelationship,
    ForensicCorrelationGroup,
    NormalizedArtifact,
    TimelineEvent,
    EvidenceItem,
    ForensicExecution,
    StructuredArtifact,
    ExecutionOutput,
)
from backend.app.schemas.schemas import (
    CorrelationGenerateRequest,
    CorrelationGraphEdge,
    CorrelationGraphNode,
    CorrelationGraphResponse,
    CorrelationGroupDetailResponse,
    CorrelationGroupResponse,
    CorrelationSummaryResponse,
    GroupIntegrityResponse,
    RelationshipIntegrityResponse,
    RelationshipProvenanceResponse,
    RelationshipResponse,
)

logger = logging.getLogger("ADFIR_CORRELATION")


# =============================================================================
# 1. DOMAIN CONSTANTS & HELPERS
# =============================================================================

class ForensicDomain:
    FILESYSTEM = "FILESYSTEM"
    MEMORY = "MEMORY"
    NETWORK = "NETWORK"
    MALWARE = "MALWARE"
    LOGS = "LOGS"
    METADATA = "METADATA"
    BROWSER = "BROWSER"
    GENERIC = "GENERIC"


class RelationshipType:
    FILE_HASH_MATCH = "FILE_HASH_MATCH"
    MALWARE_TARGET_MATCH = "MALWARE_TARGET_MATCH"
    PROCESS_MEMORY_MATCH = "PROCESS_MEMORY_MATCH"
    USER_LOGON_MATCH = "USER_LOGON_MATCH"
    BROWSER_NETWORK_MATCH = "BROWSER_NETWORK_MATCH"
    SHARED_IDENTIFIER = "SHARED_IDENTIFIER"
    TEMPORAL_COINCIDENCE = "TEMPORAL_COINCIDENCE"
    TEMPORAL_SEQUENCE = "TEMPORAL_SEQUENCE"
    OVERLAPPING_WINDOW = "OVERLAPPING_WINDOW"


def infer_domain(entity_type_or_source: str) -> str:
    val = (entity_type_or_source or "").upper()
    if any(k in val for k in ["FILE", "FLS", "FILESYSTEM", "MFT"]):
        return ForensicDomain.FILESYSTEM
    elif any(k in val for k in ["PROCESS", "PSLIST", "MEMORY", "VOLATILITY"]):
        return ForensicDomain.MEMORY
    elif any(k in val for k in ["NET", "NETSCAN", "SOCKET", "TCP", "UDP", "CONNECTION"]):
        return ForensicDomain.NETWORK
    elif any(k in val for k in ["MALWARE", "YARA", "SIGNATURE", "THREAT"]):
        return ForensicDomain.MALWARE
    elif any(k in val for k in ["LOG", "EVTX", "EVENT"]):
        return ForensicDomain.LOGS
    elif any(k in val for k in ["METADATA", "EXIFTOOL"]):
        return ForensicDomain.METADATA
    elif any(k in val for k in ["BROWSER", "HISTORY", "URL"]):
        return ForensicDomain.BROWSER
    return ForensicDomain.GENERIC


def format_canonical_json(data: Any) -> str:
    """Deterministic JSON serialization with sorted keys and no whitespace."""
    def _default(obj):
        if isinstance(obj, datetime):
            if obj.tzinfo is not None:
                obj = obj.astimezone(timezone.utc)
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return str(obj)

    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=_default)


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


# =============================================================================
# 2. CORRELATION STORAGE MANAGER
# =============================================================================

class CorrelationStorageManager:
    """
    Manages dedicated disk storage for serialized correlation records.
    Enforces case isolation, safe permissions (0o700 dir, 0o600 file),
    path traversal prevention, and strict prohibition from the evidence vault.
    """

    @classmethod
    def get_case_storage_dir(cls, case_id: str) -> Path:
        base_dir = settings.DATA_DIR / "storage" / "correlations" / "cases" / case_id
        base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass
        return base_dir

    @classmethod
    def get_relationships_dir(cls, case_id: str) -> Path:
        rel_dir = cls.get_case_storage_dir(case_id) / "relationships"
        rel_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(rel_dir, 0o700)
        except Exception:
            pass
        return rel_dir

    @classmethod
    def get_groups_dir(cls, case_id: str) -> Path:
        grp_dir = cls.get_case_storage_dir(case_id) / "groups"
        grp_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(grp_dir, 0o700)
        except Exception:
            pass
        return grp_dir

    @classmethod
    def validate_storage_path(cls, candidate_path: Path, case_id: str) -> bool:
        canonical = candidate_path.resolve()
        case_dir = cls.get_case_storage_dir(case_id).resolve()

        # Reject path traversal / escaping case dir
        try:
            canonical.relative_to(case_dir)
        except ValueError:
            return False

        # Strictly forbid writing into evidence vault
        vault_dir = (settings.DATA_DIR / "evidence" / "vault").resolve()
        try:
            canonical.relative_to(vault_dir)
            return False  # Inside vault is forbidden
        except ValueError:
            pass

        return True

    @classmethod
    def save_relationship(cls, case_id: str, rel_id: str, data: Dict[str, Any]) -> str:
        rel_dir = cls.get_relationships_dir(case_id)
        file_path = rel_dir / f"{rel_id}.json"

        if not cls.validate_storage_path(file_path, case_id):
            raise PermissionError(f"Storage path validation failed for relationship: {file_path}")

        canonical_content = format_canonical_json(data)
        file_path.write_text(canonical_content, encoding="utf-8")
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass
        return str(file_path)

    @classmethod
    def save_group(cls, case_id: str, group_id: str, data: Dict[str, Any]) -> str:
        grp_dir = cls.get_groups_dir(case_id)
        file_path = grp_dir / f"{group_id}.json"

        if not cls.validate_storage_path(file_path, case_id):
            raise PermissionError(f"Storage path validation failed for correlation group: {file_path}")

        canonical_content = format_canonical_json(data)
        file_path.write_text(canonical_content, encoding="utf-8")
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass
        return str(file_path)

    @classmethod
    def read_relationship(cls, storage_path: str, case_id: str) -> Dict[str, Any]:
        p = Path(storage_path)
        if not cls.validate_storage_path(p, case_id):
            raise PermissionError("Path validation failed")
        if not p.is_file():
            raise FileNotFoundError(f"Relationship file not found: {storage_path}")
        return json.loads(p.read_text(encoding="utf-8"))

    @classmethod
    def read_group(cls, storage_path: str, case_id: str) -> Dict[str, Any]:
        p = Path(storage_path)
        if not cls.validate_storage_path(p, case_id):
            raise PermissionError("Path validation failed")
        if not p.is_file():
            raise FileNotFoundError(f"Group file not found: {storage_path}")
        return json.loads(p.read_text(encoding="utf-8"))


# =============================================================================
# 3. IDENTIFIER EXTRACTION & MATCHING ENGINE
# =============================================================================

@dataclass
class ExtractedEntityProfile:
    item_id: str
    item_type: str  # NORMALIZED_ARTIFACT, TIMELINE_EVENT
    domain: str
    entity_type: str
    evidence_id: Optional[str]
    execution_id: Optional[str]
    hashes: Dict[str, str]  # sha256, md5, sha1
    paths: Set[str]
    filenames: Set[str]
    pids: Set[int]
    process_names: Set[str]
    ips: Set[str]
    domains: Set[str]
    urls: Set[str]
    usernames: Set[str]
    timestamp_utc: Optional[datetime]
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    temporal_precision: Optional[str]
    confidence_score: float
    raw_payload: Dict[str, Any]


class IdentifierExtractor:
    """
    Extracts normalized, comparable identifiers across NormalizedArtifact and TimelineEvent records.
    Never invents identifiers when fields are absent.
    """

    @classmethod
    def from_normalized_artifact(cls, art: NormalizedArtifact) -> ExtractedEntityProfile:
        norm = art.normalized_fields or {}
        raw = norm.get("source_raw_data") or {}
        domain = infer_domain(art.entity_type)

        hashes: Dict[str, str] = {}
        for h_key in ["sha256", "md5", "sha1"]:
            h_val = (norm.get("hashes") or {}).get(h_key) or raw.get(h_key) or norm.get(h_key)
            if h_val and isinstance(h_val, str) and len(h_val) >= 32:
                hashes[h_key] = h_val.lower().strip()

        paths: Set[str] = set()
        filenames: Set[str] = set()
        for p_key in ["path", "filepath", "target_file", "file_path", "filename"]:
            val = norm.get(p_key) or raw.get(p_key)
            if val and isinstance(val, str) and val.strip():
                clean_p = val.replace("\\", "/").strip()
                paths.add(clean_p)
                base = os.path.basename(clean_p)
                if base:
                    filenames.add(base.lower())

        pids: Set[int] = set()
        for pid_key in ["pid", "owner_pid", "ppid"]:
            val = norm.get(pid_key) or raw.get(pid_key)
            if val is not None:
                try:
                    pids.add(int(val))
                except (ValueError, TypeError):
                    pass

        proc_names: Set[str] = set()
        for p_key in ["process_name", "owner_process", "image_name", "name"]:
            val = norm.get(p_key) or raw.get(p_key)
            if val and isinstance(val, str) and val.strip():
                proc_names.add(val.strip().lower())

        ips: Set[str] = set()
        for ip_key in ["remote_address", "local_address", "ip_address", "foreign_address", "ip"]:
            val = norm.get(ip_key) or raw.get(ip_key)
            if val and isinstance(val, str) and val.strip():
                clean_ip = val.strip()
                if clean_ip not in ["127.0.0.1", "::1", "0.0.0.0"]:
                    ips.add(clean_ip)

        doms: Set[str] = set()
        for d_key in ["domain", "computer_name", "host", "hostname"]:
            val = norm.get(d_key) or raw.get(d_key)
            if val and isinstance(val, str) and val.strip():
                doms.add(val.strip().lower())

        urls: Set[str] = set()
        for u_key in ["url", "browser_url", "uri"]:
            val = norm.get(u_key) or raw.get(u_key)
            if val and isinstance(val, str) and val.strip():
                urls.add(val.strip().lower())

        users: Set[str] = set()
        for u_key in ["username", "user", "user_sid", "target_user", "account"]:
            val = norm.get(u_key) or raw.get(u_key)
            if val and isinstance(val, str) and val.strip():
                users.add(val.strip().lower())

        ts = None
        ts_raw = norm.get("event_timestamp") or norm.get("modified_time") or norm.get("start_time")
        if isinstance(ts_raw, str):
            from backend.app.services.timeline import TimestampNormalizer
            parsed = TimestampNormalizer.normalize(ts_raw)
            if parsed:
                ts = parsed.timestamp_utc

        return ExtractedEntityProfile(
            item_id=art.id,
            item_type="NORMALIZED_ARTIFACT",
            domain=domain,
            entity_type=art.entity_type,
            evidence_id=art.evidence_id,
            execution_id=art.execution_id,
            hashes=hashes,
            paths=paths,
            filenames=filenames,
            pids=pids,
            process_names=proc_names,
            ips=ips,
            domains=doms,
            urls=urls,
            usernames=users,
            timestamp_utc=ts,
            window_start=ts,
            window_end=ts,
            temporal_precision="SECOND" if ts else None,
            confidence_score=1.0,
            raw_payload=norm,
        )

    @classmethod
    def from_timeline_event(cls, ev: TimelineEvent) -> ExtractedEntityProfile:
        domain = infer_domain(ev.event_source or ev.event_type)
        data = ev.event_data or {}
        raw = data.get("source_raw_data") or {}

        hashes: Dict[str, str] = {}
        for h_key in ["sha256", "md5", "sha1"]:
            h_val = (data.get("hashes") or {}).get(h_key) or raw.get(h_key) or data.get(h_key)
            if h_val and isinstance(h_val, str) and len(h_val) >= 32:
                hashes[h_key] = h_val.lower().strip()

        paths: Set[str] = set()
        filenames: Set[str] = set()
        for p_key in ["path", "filepath", "target_file", "file_path", "filename"]:
            val = data.get(p_key) or raw.get(p_key)
            if val and isinstance(val, str) and val.strip():
                clean_p = val.replace("\\", "/").strip()
                paths.add(clean_p)
                base = os.path.basename(clean_p)
                if base:
                    filenames.add(base.lower())

        pids: Set[int] = set()
        for pid_key in ["pid", "owner_pid", "ppid"]:
            val = data.get(pid_key) or raw.get(pid_key)
            if val is not None:
                try:
                    pids.add(int(val))
                except (ValueError, TypeError):
                    pass

        proc_names: Set[str] = set()
        for p_key in ["process_name", "owner_process", "image_name", "name"]:
            val = data.get(p_key) or raw.get(p_key)
            if val and isinstance(val, str) and val.strip():
                proc_names.add(val.strip().lower())

        ips: Set[str] = set()
        for ip_key in ["remote_address", "local_address", "ip_address", "foreign_address", "ip"]:
            val = data.get(ip_key) or raw.get(ip_key)
            if val and isinstance(val, str) and val.strip():
                clean_ip = val.strip()
                if clean_ip not in ["127.0.0.1", "::1", "0.0.0.0"]:
                    ips.add(clean_ip)

        doms: Set[str] = set()
        for d_key in ["domain", "computer_name", "host", "hostname"]:
            val = data.get(d_key) or raw.get(d_key)
            if val and isinstance(val, str) and val.strip():
                doms.add(val.strip().lower())

        urls: Set[str] = set()
        for u_key in ["url", "browser_url", "uri"]:
            val = data.get(u_key) or raw.get(u_key)
            if val and isinstance(val, str) and val.strip():
                urls.add(val.strip().lower())

        users: Set[str] = set()
        for u_key in ["username", "user", "user_sid", "target_user", "account"]:
            val = data.get(u_key) or raw.get(u_key)
            if val and isinstance(val, str) and val.strip():
                users.add(val.strip().lower())

        return ExtractedEntityProfile(
            item_id=ev.id,
            item_type="TIMELINE_EVENT",
            domain=domain,
            entity_type=ev.event_type,
            evidence_id=ev.evidence_id,
            execution_id=ev.execution_id,
            hashes=hashes,
            paths=paths,
            filenames=filenames,
            pids=pids,
            process_names=proc_names,
            ips=ips,
            domains=doms,
            urls=urls,
            usernames=users,
            timestamp_utc=ev.timestamp_utc,
            window_start=ev.window_start_utc or ev.timestamp_utc,
            window_end=ev.window_end_utc or ev.timestamp_utc,
            temporal_precision=ev.temporal_precision,
            confidence_score=ev.confidence_score,
            raw_payload=data,
        )


@dataclass
class CandidateRelationship:
    source: ExtractedEntityProfile
    target: ExtractedEntityProfile
    relationship_type: str
    matching_identifier: Optional[str]
    matching_field: Optional[str]
    temporal_relationship: Optional[Dict[str, Any]]
    confidence_score: float
    evidence_ids: List[str]


# =============================================================================
# 4. CROSS-DOMAIN CORRELATION SERVICE
# =============================================================================

class CrossDomainCorrelationService:
    """
    Orchestrates cross-domain correlation across Step 12 NormalizedArtifacts
    and Step 13 TimelineEvents.
    Generates auditable relationships, correlation groups, and queryable relationship graphs.
    """

    @classmethod
    def correlate_case(
        cls,
        db: Session,
        case_id: str,
        request: CorrelationGenerateRequest
    ) -> CorrelationSummaryResponse:
        """
        Executes complete deterministic cross-domain correlation for a case.
        """
        # 1. Fetch normalized artifacts and timeline events
        normalized_records = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.case_id == case_id)
            .all()
        )
        timeline_records = (
            db.query(TimelineEvent)
            .filter(TimelineEvent.case_id == case_id)
            .all()
        )

        # 2. Extract profiles
        profiles: Dict[str, ExtractedEntityProfile] = {}
        for art in normalized_records:
            prof = IdentifierExtractor.from_normalized_artifact(art)
            profiles[prof.item_id] = prof

        for ev in timeline_records:
            prof = IdentifierExtractor.from_timeline_event(ev)
            profiles[prof.item_id] = prof

        profile_list = list(profiles.values())

        # 3. Match cross-domain identifiers
        candidate_rels = cls._find_identifier_matches(profile_list)

        # 4. Temporal correlation if enabled
        if request.include_temporal:
            temporal_rels = cls._find_temporal_matches(
                profile_list,
                window_seconds=request.time_window_seconds
            )
            candidate_rels.extend(temporal_rels)

        # Filter by min_confidence
        candidate_rels = [
            r for r in candidate_rels
            if r.confidence_score >= request.min_confidence
        ]

        # Deduplicate relationships across identical (source, target, relationship_type)
        deduped_rels = cls._deduplicate_candidate_relationships(candidate_rels)

        # 5. Connected components clustering for correlation groups
        groups_data = cls._build_correlation_groups(deduped_rels, profiles)

        # 6. Clear previous correlations for this case to maintain deterministic freshness
        db.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case_id).delete(synchronize_session=False)
        db.query(ForensicCorrelationGroup).filter(ForensicCorrelationGroup.case_id == case_id).delete(synchronize_session=False)
        db.flush()

        # 7. Pre-generate relationship IDs to establish deterministic group hashes
        rel_ids = [str(uuid.uuid4()) for _ in deduped_rels]

        # 8. Persist ForensicCorrelationGroup records
        created_groups: List[ForensicCorrelationGroup] = []
        group_id_map: Dict[int, ForensicCorrelationGroup] = {}  # rel_idx -> group_model

        for g_dict in groups_data:
            grp_id = str(uuid.uuid4())
            grp_rel_ids = sorted([rel_ids[idx] for idx in g_dict["relationship_indexes"]])

            canonical_payload = {
                "case_id": case_id,
                "title": g_dict["title"],
                "description": g_dict["description"],
                "member_artifact_ids": sorted(g_dict["member_artifact_ids"]),
                "member_event_ids": sorted(g_dict["member_event_ids"]),
                "relationship_ids": grp_rel_ids,
                "contributing_domains": sorted(g_dict["contributing_domains"]),
                "source_evidence_ids": sorted(g_dict["source_evidence_ids"]),
                "confidence_score": round(g_dict["confidence_score"], 3),
            }
            canonical_str = format_canonical_json(canonical_payload)
            grp_hash = compute_sha256(canonical_str)

            # Isolated disk storage
            storage_path = CorrelationStorageManager.save_group(
                case_id,
                grp_id,
                {**canonical_payload, "id": grp_id, "sha256_hash": grp_hash}
            )

            grp_model = ForensicCorrelationGroup(
                id=grp_id,
                case_id=case_id,
                title=g_dict["title"],
                description=g_dict["description"],
                member_artifact_ids=canonical_payload["member_artifact_ids"],
                member_event_ids=canonical_payload["member_event_ids"],
                relationship_ids=grp_rel_ids,
                contributing_domains=canonical_payload["contributing_domains"],
                source_evidence_ids=canonical_payload["source_evidence_ids"],
                confidence_score=canonical_payload["confidence_score"],
                provenance=g_dict.get("provenance", {}),
                sha256_hash=grp_hash,
                storage_path=storage_path,
                created_at=datetime.now(timezone.utc),
            )
            db.add(grp_model)
            created_groups.append(grp_model)

            for rel_idx in g_dict["relationship_indexes"]:
                group_id_map[rel_idx] = grp_model

        db.flush()

        # 9. Persist ArtifactRelationship records
        created_rels: List[ArtifactRelationship] = []
        for idx, r_data in enumerate(deduped_rels):
            rel_id = rel_ids[idx]
            assigned_group = group_id_map.get(idx)
            group_id = assigned_group.id if assigned_group else None

            # Trace provenance
            source_prov = cls._resolve_provenance(db, r_data.source)
            target_prov = cls._resolve_provenance(db, r_data.target)
            prov_payload = {
                "source": source_prov,
                "target": target_prov,
            }

            canonical_payload = {
                "case_id": case_id,
                "source_id": r_data.source.item_id,
                "source_type": r_data.source.item_type,
                "source_domain": r_data.source.domain,
                "target_id": r_data.target.item_id,
                "target_type": r_data.target.item_type,
                "target_domain": r_data.target.domain,
                "relationship_type": r_data.relationship_type,
                "matching_identifier": r_data.matching_identifier,
                "matching_field": r_data.matching_field,
                "temporal_relationship": r_data.temporal_relationship,
                "confidence_score": round(r_data.confidence_score, 3),
                "evidence_ids": sorted(list(set(r_data.evidence_ids))),
            }
            canonical_str = format_canonical_json(canonical_payload)
            rel_hash = compute_sha256(canonical_str)

            # Isolated disk storage
            storage_path = CorrelationStorageManager.save_relationship(
                case_id,
                rel_id,
                {**canonical_payload, "id": rel_id, "group_id": group_id, "sha256_hash": rel_hash, "provenance": prov_payload}
            )

            rel_model = ArtifactRelationship(
                id=rel_id,
                case_id=case_id,
                group_id=group_id,
                source_id=r_data.source.item_id,
                source_type=r_data.source.item_type,
                source_domain=r_data.source.domain,
                target_id=r_data.target.item_id,
                target_type=r_data.target.item_type,
                target_domain=r_data.target.domain,
                relationship_type=r_data.relationship_type,
                matching_identifier=r_data.matching_identifier,
                matching_field=r_data.matching_field,
                temporal_relationship=r_data.temporal_relationship,
                confidence_score=canonical_payload["confidence_score"],
                evidence_ids=canonical_payload["evidence_ids"],
                provenance=prov_payload,
                sha256_hash=rel_hash,
                storage_path=storage_path,
                created_at=datetime.now(timezone.utc),
            )
            db.add(rel_model)
            created_rels.append(rel_model)

        db.commit()

        # Unique correlated node count
        correlated_nodes: Set[str] = set()
        for r in created_rels:
            correlated_nodes.add(r.source_id)
            correlated_nodes.add(r.target_id)

        return CorrelationSummaryResponse(
            case_id=case_id,
            relationships_generated=len(created_rels),
            groups_created=len(created_groups),
            total_nodes_correlated=len(correlated_nodes),
            relationships=[RelationshipResponse.model_validate(r) for r in created_rels],
            groups=[CorrelationGroupResponse.model_validate(g) for g in created_groups],
            execution_timestamp=datetime.now(timezone.utc),
        )

    # -------------------------------------------------------------------------
    # IDENTIFIER MATCHING IMPLEMENTATION
    # -------------------------------------------------------------------------

    @classmethod
    def _find_identifier_matches(
        cls,
        profiles: List[ExtractedEntityProfile]
    ) -> List[CandidateRelationship]:
        """
        Discovers deterministic cross-domain identifier relationships.
        """
        results: List[CandidateRelationship] = []

        # Indexing for deterministic O(N) candidate generation
        hash_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        path_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        filename_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        pid_index: Dict[int, List[ExtractedEntityProfile]] = defaultdict(list)
        proc_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        ip_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        domain_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        url_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)
        user_index: Dict[str, List[ExtractedEntityProfile]] = defaultdict(list)

        for p in profiles:
            for h in p.hashes.values():
                hash_index[h].append(p)
            for path in p.paths:
                path_index[path].append(p)
            for fn in p.filenames:
                filename_index[fn].append(p)
            for pid in p.pids:
                pid_index[pid].append(p)
            for proc in p.process_names:
                proc_index[proc].append(p)
            for ip in p.ips:
                ip_index[ip].append(p)
            for dom in p.domains:
                domain_index[dom].append(p)
            for u in p.urls:
                url_index[u].append(p)
            for usr in p.usernames:
                user_index[usr].append(p)

        def _make_pair(a: ExtractedEntityProfile, b: ExtractedEntityProfile) -> Tuple[ExtractedEntityProfile, ExtractedEntityProfile]:
            # Deterministic ordering so a.item_id < b.item_id
            return (a, b) if a.item_id < b.item_id else (b, a)

        def _ev_ids(a: ExtractedEntityProfile, b: ExtractedEntityProfile) -> List[str]:
            evs = []
            if a.evidence_id:
                evs.append(a.evidence_id)
            if b.evidence_id and b.evidence_id not in evs:
                evs.append(b.evidence_id)
            return evs

        # 1. Cryptographic Hash Matches (File Hash <-> Malware/YARA hit or shared hash)
        for h_val, members in hash_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    # File <-> Malware check
                    is_malware_file = (
                        (src.domain == ForensicDomain.MALWARE and tgt.domain in [ForensicDomain.FILESYSTEM, ForensicDomain.METADATA])
                        or (tgt.domain == ForensicDomain.MALWARE and src.domain in [ForensicDomain.FILESYSTEM, ForensicDomain.METADATA])
                    )
                    rel_type = RelationshipType.FILE_HASH_MATCH
                    conf = 1.0  # Cryptographic hash identity

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=rel_type,
                        matching_identifier=h_val,
                        matching_field="sha256" if len(h_val) == 64 else ("md5" if len(h_val) == 32 else "hash"),
                        temporal_relationship=None,
                        confidence_score=conf,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        # 2. File Path <-> Malware Target Match
        for path_val, members in path_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    is_malware_target = (
                        (src.domain == ForensicDomain.MALWARE and tgt.domain in [ForensicDomain.FILESYSTEM, ForensicDomain.METADATA])
                        or (tgt.domain == ForensicDomain.MALWARE and src.domain in [ForensicDomain.FILESYSTEM, ForensicDomain.METADATA])
                    )
                    if is_malware_target:
                        results.append(CandidateRelationship(
                            source=src,
                            target=tgt,
                            relationship_type=RelationshipType.MALWARE_TARGET_MATCH,
                            matching_identifier=path_val,
                            matching_field="target_file",
                            temporal_relationship=None,
                            confidence_score=0.95,
                            evidence_ids=_ev_ids(src, tgt),
                        ))
                    else:
                        results.append(CandidateRelationship(
                            source=src,
                            target=tgt,
                            relationship_type=RelationshipType.SHARED_IDENTIFIER,
                            matching_identifier=path_val,
                            matching_field="filepath",
                            temporal_relationship=None,
                            confidence_score=0.90,
                            evidence_ids=_ev_ids(src, tgt),
                        ))

        # 3. Process <-> Memory Artifact (PID and/or process name matching)
        for pid_val, members in pid_index.items():
            if len(members) < 2 or pid_val <= 0:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    # Check if matching process name too
                    shared_procs = src.process_names.intersection(tgt.process_names)
                    if shared_procs:
                        conf = 0.95
                        id_val = f"PID {pid_val} ({list(shared_procs)[0]})"
                    else:
                        conf = 0.90
                        id_val = f"PID {pid_val}"

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=RelationshipType.PROCESS_MEMORY_MATCH,
                        matching_identifier=id_val,
                        matching_field="pid",
                        temporal_relationship=None,
                        confidence_score=conf,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        # 4. User <-> Logon Event
        for user_val, members in user_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    is_logon = (
                        (src.domain == ForensicDomain.LOGS or tgt.domain == ForensicDomain.LOGS)
                        and any("4624" in str(x) or "4625" in str(x) or "logon" in str(x).lower()
                                for x in [src.entity_type, tgt.entity_type, src.raw_payload, tgt.raw_payload])
                    )
                    rel_type = RelationshipType.USER_LOGON_MATCH if is_logon else RelationshipType.SHARED_IDENTIFIER
                    conf = 0.95 if is_logon else 0.85

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=rel_type,
                        matching_identifier=user_val,
                        matching_field="username",
                        temporal_relationship=None,
                        confidence_score=conf,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        # 5. Browser <-> Network Artifact
        for u_val, members in url_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    is_browser_net = (
                        (src.domain == ForensicDomain.BROWSER and tgt.domain == ForensicDomain.NETWORK)
                        or (tgt.domain == ForensicDomain.BROWSER and src.domain == ForensicDomain.NETWORK)
                    )
                    rel_type = RelationshipType.BROWSER_NETWORK_MATCH if is_browser_net else RelationshipType.SHARED_IDENTIFIER
                    conf = 0.95

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=rel_type,
                        matching_identifier=u_val,
                        matching_field="url",
                        temporal_relationship=None,
                        confidence_score=conf,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        # 6. Shared Network IP Addresses
        for ip_val, members in ip_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    is_browser_net = (
                        (src.domain == ForensicDomain.BROWSER and tgt.domain == ForensicDomain.NETWORK)
                        or (tgt.domain == ForensicDomain.BROWSER and src.domain == ForensicDomain.NETWORK)
                    )
                    rel_type = RelationshipType.BROWSER_NETWORK_MATCH if is_browser_net else RelationshipType.SHARED_IDENTIFIER

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=rel_type,
                        matching_identifier=ip_val,
                        matching_field="ip_address",
                        temporal_relationship=None,
                        confidence_score=0.90,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        # 7. Shared Domains / Hostnames
        for dom_val, members in domain_index.items():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    src, tgt = _make_pair(members[i], members[j])
                    if src.item_id == tgt.item_id:
                        continue

                    results.append(CandidateRelationship(
                        source=src,
                        target=tgt,
                        relationship_type=RelationshipType.SHARED_IDENTIFIER,
                        matching_identifier=dom_val,
                        matching_field="domain",
                        temporal_relationship=None,
                        confidence_score=0.85,
                        evidence_ids=_ev_ids(src, tgt),
                    ))

        return results

    # -------------------------------------------------------------------------
    # TEMPORAL CORRELATION IMPLEMENTATION
    # -------------------------------------------------------------------------

    @classmethod
    def _find_temporal_matches(
        cls,
        profiles: List[ExtractedEntityProfile],
        window_seconds: float = 60.0
    ) -> List[CandidateRelationship]:
        """
        Discovers deterministic temporal relationships within window_seconds.
        Preserves UTC timestamps and source temporal precision.
        """
        results: List[CandidateRelationship] = []

        # Filter profiles with valid UTC timestamps
        timestamped = [p for p in profiles if p.timestamp_utc is not None]
        # Sort chronologically
        timestamped.sort(key=lambda p: (p.timestamp_utc, p.item_id))

        def _make_pair(a: ExtractedEntityProfile, b: ExtractedEntityProfile) -> Tuple[ExtractedEntityProfile, ExtractedEntityProfile]:
            return (a, b) if a.item_id < b.item_id else (b, a)

        def _ev_ids(a: ExtractedEntityProfile, b: ExtractedEntityProfile) -> List[str]:
            evs = []
            if a.evidence_id:
                evs.append(a.evidence_id)
            if b.evidence_id and b.evidence_id not in evs:
                evs.append(b.evidence_id)
            return evs

        # Sliding window comparison
        n = len(timestamped)
        for i in range(n):
            p1 = timestamped[i]
            t1 = p1.timestamp_utc

            for j in range(i + 1, n):
                p2 = timestamped[j]
                t2 = p2.timestamp_utc

                delta = abs((t2 - t1).total_seconds())
                if delta > window_seconds:
                    # Beyond window, since sorted chronologically, break inner loop
                    break

                src, tgt = _make_pair(p1, p2)
                if src.item_id == tgt.item_id:
                    continue

                # 1. Exact/Near Coincidence (<= 5s)
                if delta <= 5.0:
                    rel_type = RelationshipType.TEMPORAL_COINCIDENCE
                    conf = 0.85
                    temp_meta = {
                        "type": "COINCIDENT",
                        "delta_seconds": round(delta, 3),
                        "source_utc": t1.isoformat(),
                        "target_utc": t2.isoformat(),
                    }
                else:
                    rel_type = RelationshipType.TEMPORAL_SEQUENCE
                    direction = "BEFORE" if t1 < t2 else "AFTER"
                    # Linear decay from 0.80 down to 0.55 across window
                    conf = round(max(0.55, 0.80 - (delta / window_seconds) * 0.25), 3)
                    temp_meta = {
                        "type": direction,
                        "delta_seconds": round(delta, 3),
                        "source_utc": t1.isoformat(),
                        "target_utc": t2.isoformat(),
                    }

                # 2. Window overlap check if uncertainty windows exist
                if p1.window_start and p1.window_end and p2.window_start and p2.window_end:
                    overlap_start = max(p1.window_start, p2.window_start)
                    overlap_end = min(p1.window_end, p2.window_end)
                    if overlap_start <= overlap_end:
                        overlap_dur = (overlap_end - overlap_start).total_seconds()
                        if overlap_dur > 0:
                            temp_meta["window_overlap_seconds"] = round(overlap_dur, 3)

                results.append(CandidateRelationship(
                    source=src,
                    target=tgt,
                    relationship_type=rel_type,
                    matching_identifier=f"delta_{round(delta, 1)}s",
                    matching_field="timestamp_utc",
                    temporal_relationship=temp_meta,
                    confidence_score=conf,
                    evidence_ids=_ev_ids(src, tgt),
                ))

        return results

    # -------------------------------------------------------------------------
    # DEDUPLICATION & GROUPING IMPLEMENTATION
    # -------------------------------------------------------------------------

    @classmethod
    def _deduplicate_candidate_relationships(
        cls,
        candidates: List[CandidateRelationship]
    ) -> List[CandidateRelationship]:
        """
        Deduplicates candidate relationships across identical (source.item_id, target.item_id, relationship_type).
        Retains candidate with highest confidence score.
        """
        best_by_key: Dict[Tuple[str, str, str], CandidateRelationship] = {}

        for c in candidates:
            k = (c.source.item_id, c.target.item_id, c.relationship_type)
            if k not in best_by_key or c.confidence_score > best_by_key[k].confidence_score:
                best_by_key[k] = c

        return list(best_by_key.values())

    @classmethod
    def _build_correlation_groups(
        cls,
        relationships: List[CandidateRelationship],
        profiles: Dict[str, ExtractedEntityProfile]
    ) -> List[Dict[str, Any]]:
        """
        Computes deterministic connected components to form correlation groups.
        Each group contains >= 2 correlated items.
        NEVER labels groups as attacks, incidents, threats, or findings.
        """
        adj: Dict[str, Set[str]] = defaultdict(set)
        edge_map: Dict[Tuple[str, str], List[int]] = defaultdict(list)

        for idx, r in enumerate(relationships):
            u, v = r.source.item_id, r.target.item_id
            adj[u].add(v)
            adj[v].add(u)
            edge_map[(u, v)].append(idx)
            edge_map[(v, u)].append(idx)

        visited: Set[str] = set()
        groups: List[Dict[str, Any]] = []

        # Deterministic sorting of node IDs
        all_nodes = sorted(list(adj.keys()))

        for start_node in all_nodes:
            if start_node in visited:
                continue

            # BFS traversal
            comp_nodes: List[str] = []
            queue = deque([start_node])
            visited.add(start_node)

            while queue:
                curr = queue.popleft()
                comp_nodes.append(curr)

                for neighbor in sorted(list(adj[curr])):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if len(comp_nodes) < 2:
                continue

            # Collect member artifacts, events, relationship indexes
            member_artifact_ids: Set[str] = set()
            member_event_ids: Set[str] = set()
            contributing_domains: Set[str] = set()
            source_ev_ids: Set[str] = set()
            rel_indexes: Set[int] = set()

            for n_id in comp_nodes:
                prof = profiles.get(n_id)
                if prof:
                    if prof.item_type == "NORMALIZED_ARTIFACT":
                        member_artifact_ids.add(prof.item_id)
                    else:
                        member_event_ids.add(prof.item_id)
                    contributing_domains.add(prof.domain)
                    if prof.evidence_id:
                        source_ev_ids.add(prof.evidence_id)

            for i in range(len(comp_nodes)):
                for j in range(i + 1, len(comp_nodes)):
                    u, v = comp_nodes[i], comp_nodes[j]
                    for r_idx in edge_map.get((u, v), []):
                        rel_indexes.add(r_idx)

            if not rel_indexes:
                continue

            # Aggregate confidence
            conf_scores = [relationships[idx].confidence_score for idx in rel_indexes]
            avg_conf = sum(conf_scores) / len(conf_scores) if conf_scores else 1.0

            # Deterministic, non-judgmental title
            domain_summary = "/".join(sorted(list(contributing_domains)))
            sample_rel = relationships[list(rel_indexes)[0]]
            match_id = sample_rel.matching_identifier or ""
            if len(match_id) > 24:
                match_id = match_id[:24] + "..."

            title = f"Correlation Group: {domain_summary} ({match_id or sample_rel.relationship_type})"
            desc = (
                f"Deterministic correlation cluster connecting {len(member_artifact_ids)} artifacts "
                f"and {len(member_event_ids)} timeline events across {len(contributing_domains)} forensic domains "
                f"({domain_summary}) with {len(rel_indexes)} relationships."
            )

            groups.append({
                "title": title,
                "description": desc,
                "member_artifact_ids": sorted(list(member_artifact_ids)),
                "member_event_ids": sorted(list(member_event_ids)),
                "relationship_ids": [],  # Will be populated with UUIDs upon persist
                "relationship_indexes": sorted(list(rel_indexes)),
                "contributing_domains": sorted(list(contributing_domains)),
                "source_evidence_ids": sorted(list(source_ev_ids)),
                "confidence_score": round(avg_conf, 3),
                "provenance": {
                    "contributing_domains": sorted(list(contributing_domains)),
                    "total_members": len(comp_nodes),
                    "relationship_types": sorted(list(set(relationships[idx].relationship_type for idx in rel_indexes)))
                }
            })

        return groups

    # -------------------------------------------------------------------------
    # PROVENANCE & GRAPH RETRIEVAL
    # -------------------------------------------------------------------------

    @classmethod
    def _resolve_provenance(
        cls,
        db: Session,
        prof: ExtractedEntityProfile
    ) -> Dict[str, Any]:
        """
        Reconstructs the full cryptographic lineage back to evidence and execution.
        """
        prov: Dict[str, Any] = {
            "item_id": prof.item_id,
            "item_type": prof.item_type,
            "domain": prof.domain,
            "entity_type": prof.entity_type,
            "evidence_id": prof.evidence_id,
            "execution_id": prof.execution_id,
        }

        if prof.item_type == "NORMALIZED_ARTIFACT":
            art = db.query(NormalizedArtifact).filter(NormalizedArtifact.id == prof.item_id).first()
            if art:
                prov.update({
                    "sha256_hash": art.sha256_hash,
                    "source_artifact_id": art.source_artifact_id,
                    "source_artifact_hash": art.source_artifact_hash,
                    "raw_output_id": art.raw_output_id,
                })
        elif prof.item_type == "TIMELINE_EVENT":
            ev = db.query(TimelineEvent).filter(TimelineEvent.id == prof.item_id).first()
            if ev:
                prov.update({
                    "sha256_hash": ev.sha256_hash,
                    "source_artifact_hash": ev.source_artifact_hash,
                    "normalized_artifact_id": ev.normalized_artifact_id,
                    "structured_artifact_id": ev.structured_artifact_id,
                })

        return prov

    @classmethod
    def build_relationship_graph(
        cls,
        db: Session,
        case_id: str,
        group_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        domain: Optional[str] = None,
        evidence_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> CorrelationGraphResponse:
        """
        Builds a queryable graph representation:
        Artifact/Event -> Relationship -> Artifact/Event
        """
        query = db.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case_id)

        if group_id:
            query = query.filter(ArtifactRelationship.group_id == group_id)
        if relationship_type:
            query = query.filter(ArtifactRelationship.relationship_type == relationship_type)
        if min_confidence is not None:
            query = query.filter(ArtifactRelationship.confidence_score >= min_confidence)

        relationships = query.all()

        # Domain filter on relationships
        if domain:
            dom = domain.upper()
            relationships = [
                r for r in relationships
                if r.source_domain == dom or r.target_domain == dom
            ]

        # Evidence filter
        if evidence_id:
            relationships = [
                r for r in relationships
                if evidence_id in (r.evidence_ids or [])
            ]

        # Collect unique participating node IDs
        node_ids: Set[str] = set()
        for r in relationships:
            node_ids.add(r.source_id)
            node_ids.add(r.target_id)

        # Retrieve nodes from database
        nodes_dict: Dict[str, CorrelationGraphNode] = {}

        if node_ids:
            norm_arts = (
                db.query(NormalizedArtifact)
                .filter(NormalizedArtifact.case_id == case_id, NormalizedArtifact.id.in_(list(node_ids)))
                .all()
            )
            for art in norm_arts:
                label = (
                    (art.normalized_fields or {}).get("filename")
                    or (art.normalized_fields or {}).get("process_name")
                    or art.entity_identity
                    or f"{art.entity_type}:{art.id[:8]}"
                )
                nodes_dict[art.id] = CorrelationGraphNode(
                    id=art.id,
                    node_type="NORMALIZED_ARTIFACT",
                    domain=infer_domain(art.entity_type),
                    entity_type=art.entity_type,
                    label=str(label),
                    confidence=1.0,
                    evidence_id=art.evidence_id,
                    group_ids=[],
                    provenance={"sha256": art.sha256_hash, "execution_id": art.execution_id},
                    metadata=art.normalized_fields or {},
                )

            events = (
                db.query(TimelineEvent)
                .filter(TimelineEvent.case_id == case_id, TimelineEvent.id.in_(list(node_ids)))
                .all()
            )
            for ev in events:
                label = f"{ev.event_type} ({ev.timestamp_utc.strftime('%H:%M:%S') if ev.timestamp_utc else ''})"
                nodes_dict[ev.id] = CorrelationGraphNode(
                    id=ev.id,
                    node_type="TIMELINE_EVENT",
                    domain=infer_domain(ev.event_source or ev.event_type),
                    entity_type=ev.event_type,
                    label=label,
                    confidence=ev.confidence_score,
                    evidence_id=ev.evidence_id,
                    group_ids=[],
                    provenance={"sha256": ev.sha256_hash, "timestamp_utc": ev.timestamp_utc.isoformat()},
                    metadata=ev.event_data or {},
                )

        # Associate group IDs with nodes
        for r in relationships:
            if r.group_id:
                if r.source_id in nodes_dict and r.group_id not in nodes_dict[r.source_id].group_ids:
                    nodes_dict[r.source_id].group_ids.append(r.group_id)
                if r.target_id in nodes_dict and r.group_id not in nodes_dict[r.target_id].group_ids:
                    nodes_dict[r.target_id].group_ids.append(r.group_id)

        edges = [
            CorrelationGraphEdge(
                id=r.id,
                source=r.source_id,
                target=r.target_id,
                relationship_type=r.relationship_type,
                matching_identifier=r.matching_identifier,
                matching_field=r.matching_field,
                temporal_relationship=r.temporal_relationship,
                confidence=r.confidence_score,
                group_id=r.group_id,
            )
            for r in relationships
        ]

        # Retrieve groups
        active_group_ids = set(r.group_id for r in relationships if r.group_id)
        groups = []
        if active_group_ids:
            grp_models = (
                db.query(ForensicCorrelationGroup)
                .filter(ForensicCorrelationGroup.id.in_(list(active_group_ids)))
                .all()
            )
            groups = [CorrelationGroupResponse.model_validate(g) for g in grp_models]

        return CorrelationGraphResponse(
            case_id=case_id,
            nodes=list(nodes_dict.values()),
            edges=edges,
            groups=groups,
            total_nodes=len(nodes_dict),
            total_edges=len(edges),
            total_groups=len(groups),
        )

    # -------------------------------------------------------------------------
    # INTEGRITY CHECKS
    # -------------------------------------------------------------------------

    @classmethod
    def verify_relationship_integrity(
        cls,
        db: Session,
        case_id: str,
        relationship_id: str
    ) -> RelationshipIntegrityResponse:
        rel = (
            db.query(ArtifactRelationship)
            .filter(ArtifactRelationship.case_id == case_id, ArtifactRelationship.id == relationship_id)
            .first()
        )
        if not rel:
            raise KeyError(f"Relationship {relationship_id} not found in case {case_id}")

        canonical_payload = {
            "case_id": rel.case_id,
            "source_id": rel.source_id,
            "source_type": rel.source_type,
            "source_domain": rel.source_domain,
            "target_id": rel.target_id,
            "target_type": rel.target_type,
            "target_domain": rel.target_domain,
            "relationship_type": rel.relationship_type,
            "matching_identifier": rel.matching_identifier,
            "matching_field": rel.matching_field,
            "temporal_relationship": rel.temporal_relationship,
            "confidence_score": round(rel.confidence_score, 3),
            "evidence_ids": sorted(list(set(rel.evidence_ids or []))),
        }
        recalculated_hash = compute_sha256(format_canonical_json(canonical_payload))

        file_exists = False
        if rel.storage_path and os.path.exists(rel.storage_path):
            file_exists = True

        tamper_detected = (recalculated_hash != rel.sha256_hash) or not file_exists
        integrity_passed = not tamper_detected

        return RelationshipIntegrityResponse(
            relationship_id=rel.id,
            relationship_type=rel.relationship_type,
            stored_sha256=rel.sha256_hash,
            computed_sha256=recalculated_hash,
            integrity_passed=integrity_passed,
            file_exists=file_exists,
            tamper_detected=tamper_detected,
            storage_path=rel.storage_path,
            checked_at=datetime.now(timezone.utc),
        )

    @classmethod
    def verify_group_integrity(
        cls,
        db: Session,
        case_id: str,
        group_id: str
    ) -> GroupIntegrityResponse:
        grp = (
            db.query(ForensicCorrelationGroup)
            .filter(ForensicCorrelationGroup.case_id == case_id, ForensicCorrelationGroup.id == group_id)
            .first()
        )
        if not grp:
            raise KeyError(f"Group {group_id} not found in case {case_id}")

        canonical_payload = {
            "case_id": grp.case_id,
            "title": grp.title,
            "description": grp.description,
            "member_artifact_ids": sorted(grp.member_artifact_ids or []),
            "member_event_ids": sorted(grp.member_event_ids or []),
            "relationship_ids": sorted(grp.relationship_ids or []),
            "contributing_domains": sorted(grp.contributing_domains or []),
            "source_evidence_ids": sorted(grp.source_evidence_ids or []),
            "confidence_score": round(grp.confidence_score, 3),
        }
        recalculated_hash = compute_sha256(format_canonical_json(canonical_payload))

        file_exists = False
        if grp.storage_path and os.path.exists(grp.storage_path):
            file_exists = True

        tamper_detected = (recalculated_hash != grp.sha256_hash) or not file_exists
        integrity_passed = not tamper_detected

        return GroupIntegrityResponse(
            group_id=grp.id,
            title=grp.title,
            stored_sha256=grp.sha256_hash,
            computed_sha256=recalculated_hash,
            integrity_passed=integrity_passed,
            file_exists=file_exists,
            tamper_detected=tamper_detected,
            storage_path=grp.storage_path,
            checked_at=datetime.now(timezone.utc),
        )
