"""
ADFIR — Artifact Normalization Subsystem (Phase 2 / Step 12)

Normalizes Step 11 structured artifacts (StructuredArtifact) into a common,
tool-agnostic representation (NormalizedArtifact) so forensic artifacts from
different tools and domains can be compared safely.

Strict forensic boundaries:
- Normalized artifacts represent standardized evidence-derived data, NOT conclusions or findings.
- DO NOT: correlate unrelated entities, infer attacker behavior, detect attacks,
  calculate severity, generate findings, generate conclusions, or use LLM reasoning.
- DO NOT modify Step 10 raw outputs, Step 11 structured artifacts, or the evidence vault.
- Deterministic entity identity without inventing missing values.
- Multi-source deduplication preserving all contributing source artifact references and provenance.
- Complete cryptographic integrity (SHA-256) and traceability:
  EvidenceItem -> AnalysisRequest -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact.
"""

import os
import re
import json
import uuid
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    ForensicExecution,
    ExecutionOutput,
    EvidenceItem,
    StructuredArtifact,
    NormalizedArtifact,
    AnalysisRequest,
    AuditEvent,
    User
)
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_ARTIFACT_NORMALIZATION")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# 1. ENTITY NORMALIZATION ENGINE
# =============================================================================

class EntityType:
    FILE = "FILE"
    PROCESS = "PROCESS"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    EVENT = "EVENT"
    MALWARE_MATCH = "MALWARE_MATCH"
    METADATA = "METADATA"
    GENERIC = "GENERIC"
    UNSUPPORTED = "UNSUPPORTED"


class EntityNormalizer:
    """
    Standardizes parser-specific structured artifact fields into a consistent
    normalized schema per entity type without losing source attributes.
    Does NOT invent missing values.
    """

    @classmethod
    def map_entity_type(cls, artifact_type: str, extraction_status: str) -> str:
        if extraction_status == "UNSUPPORTED":
            return EntityType.UNSUPPORTED

        atype = (artifact_type or "").upper()
        if "FILE" in atype or atype == "FILESYSTEM_RECORD":
            return EntityType.FILE
        elif "PROCESS" in atype:
            return EntityType.PROCESS
        elif "NET" in atype or atype == "NETWORK_RECORD":
            return EntityType.NETWORK_CONNECTION
        elif "EVENT" in atype:
            return EntityType.EVENT
        elif "MALWARE" in atype or "YARA" in atype or atype == "MALWARE_MATCH":
            return EntityType.MALWARE_MATCH
        elif "METADATA" in atype:
            return EntityType.METADATA
        elif atype == "GENERIC_RECORD":
            return EntityType.GENERIC
        return EntityType.GENERIC

    @classmethod
    def normalize_fields(
        cls,
        entity_type: str,
        structured_art: StructuredArtifact
    ) -> Tuple[Dict[str, Any], Optional[datetime]]:
        """
        Normalizes structured fields and attempts to extract an entity timestamp if available.
        Preserves original raw data in 'source_raw_data'.
        """
        data = structured_art.normalized_data or {}
        norm: Dict[str, Any] = {"source_raw_data": data}
        entity_ts: Optional[datetime] = None

        if entity_type == EntityType.FILE:
            raw_path = data.get("path") or data.get("file_path") or data.get("name") or ""
            norm_path = raw_path.replace("\\", "/").strip() if raw_path else None
            filename = os.path.basename(norm_path) if norm_path else None
            ext = os.path.splitext(filename)[1].lower() if filename and "." in filename else None

            norm.update({
                "path": norm_path,
                "filename": filename,
                "extension": ext,
                "size_bytes": data.get("size_bytes") or data.get("file_size"),
                "file_type": data.get("file_type") or ("directory" if data.get("is_directory") else "file"),
                "is_deleted": bool(data.get("is_deleted")),
                "inode_or_mft": str(data.get("inode")) if data.get("inode") is not None else None,
                "hashes": {
                    k: v for k, v in data.items()
                    if k in ["md5", "sha1", "sha256"] and v
                }
            })

            # Check timestamps
            ts_str = data.get("modified_time") or data.get("created_time") or data.get("timestamp")
            if ts_str:
                entity_ts = cls._parse_iso_timestamp(ts_str)

        elif entity_type == EntityType.PROCESS:
            pid = data.get("pid")
            try:
                pid = int(pid) if pid is not None else None
            except Exception:
                pid = None

            ppid = data.get("ppid")
            try:
                ppid = int(ppid) if ppid is not None else None
            except Exception:
                ppid = None

            img_name = data.get("image_name") or data.get("process_name") or data.get("name")
            norm.update({
                "pid": pid,
                "ppid": ppid,
                "process_name": img_name.strip() if img_name else None,
                "command_line": data.get("command_line") or data.get("cmdline"),
                "start_time": data.get("start_time") or data.get("create_time"),
            })

            start_str = norm.get("start_time")
            if start_str:
                entity_ts = cls._parse_iso_timestamp(start_str)

        elif entity_type == EntityType.NETWORK_CONNECTION:
            proto = (data.get("proto") or data.get("protocol") or "").upper()
            local_addr = data.get("local_address") or data.get("local_ip")
            local_port = data.get("local_port")
            try:
                local_port = int(local_port) if local_port is not None else None
            except Exception:
                pass

            remote_addr = data.get("foreign_address") or data.get("remote_address") or data.get("remote_ip")
            remote_port = data.get("foreign_port") or data.get("remote_port")
            try:
                remote_port = int(remote_port) if remote_port is not None else None
            except Exception:
                pass

            owner_pid = data.get("owner_pid") or data.get("pid")
            try:
                owner_pid = int(owner_pid) if owner_pid is not None else None
            except Exception:
                pass

            norm.update({
                "protocol": proto or "UNKNOWN",
                "local_address": str(local_addr) if local_addr is not None else None,
                "local_port": local_port,
                "remote_address": str(remote_addr) if remote_addr is not None else None,
                "remote_port": remote_port,
                "state": (data.get("state") or "UNKNOWN").upper(),
                "owner_pid": owner_pid,
                "owner_process": data.get("owner_process") or data.get("image_name"),
            })

        elif entity_type == EntityType.EVENT:
            event_id = data.get("event_id") or data.get("id")
            norm.update({
                "event_id": str(event_id) if event_id is not None else None,
                "provider": data.get("provider") or data.get("source"),
                "channel": data.get("channel"),
                "computer_name": data.get("computer_name") or data.get("computer"),
                "event_timestamp": data.get("time_created") or data.get("timestamp"),
            })
            if norm.get("event_timestamp"):
                entity_ts = cls._parse_iso_timestamp(norm["event_timestamp"])

        elif entity_type == EntityType.MALWARE_MATCH:
            norm.update({
                "rule_name": data.get("rule_name") or data.get("rule"),
                "target_file": data.get("target_file") or data.get("file"),
                "matched_tags": data.get("matched_tags") or data.get("tags") or [],
                "matched_strings": data.get("matched_strings") or data.get("strings") or [],
            })

        elif entity_type == EntityType.METADATA:
            norm.update({
                "target_file": data.get("target_file") or data.get("file") or data.get("SourceFile"),
                "mime_type": data.get("mime_type") or data.get("MIMEType"),
                "file_size": data.get("file_size") or data.get("FileSize"),
                "metadata_attributes": {
                    k: v for k, v in data.items()
                    if k not in ["target_file", "file", "SourceFile", "source_raw_data"]
                }
            })

        elif entity_type == EntityType.UNSUPPORTED:
            norm.update({
                "unsupported_reason": structured_art.error_message or "Tool output format unsupported for structured extraction",
                "raw_record": structured_art.raw_record
            })

        else:  # GENERIC
            norm.update({
                "generic_payload": data,
                "source_reference": structured_art.source_reference
            })

        return norm, entity_ts

    @classmethod
    def _parse_iso_timestamp(cls, ts_str: Any) -> Optional[datetime]:
        if not ts_str or not isinstance(ts_str, str):
            return None
        # Clean string
        cleaned = ts_str.strip().rstrip("Z")
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None


# =============================================================================
# 2. ENTITY IDENTITY ENGINE
# =============================================================================

class EntityIdentityEngine:
    """
    Computes deterministic identity for entities using canonical key attributes.
    Preserves source-specific identity alongside normalized identity.
    Handles insufficient data gracefully by marking PARTIAL_IDENTITY.
    """

    @classmethod
    def compute_identity(
        cls,
        entity_type: str,
        norm_fields: Dict[str, Any],
        structured_art: StructuredArtifact
    ) -> Tuple[str, Optional[str], str]:
        """
        Returns:
            (entity_identity, source_specific_identity, normalization_status)
        """
        source_id = structured_art.source_reference or f"artifact:{structured_art.id}"

        if entity_type == EntityType.UNSUPPORTED:
            identity = f"unsupported_{structured_art.id[:16]}"
            return identity, source_id, "UNSUPPORTED"

        if entity_type == EntityType.FILE:
            path = norm_fields.get("path")
            sha256 = (norm_fields.get("hashes") or {}).get("sha256")
            if path:
                canonical = f"file:{path.lower()}"
                status = "NORMALIZED"
            elif sha256:
                canonical = f"file_sha256:{sha256.lower()}"
                status = "NORMALIZED"
            else:
                canonical = f"file_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        elif entity_type == EntityType.PROCESS:
            pid = norm_fields.get("pid")
            name = norm_fields.get("process_name")
            if pid is not None and name:
                canonical = f"process:{pid}:{name.lower()}"
                status = "NORMALIZED"
            elif pid is not None:
                canonical = f"process_pid:{pid}"
                status = "NORMALIZED"
            elif name:
                canonical = f"process_name:{name.lower()}"
                status = "NORMALIZED"
            else:
                canonical = f"process_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        elif entity_type == EntityType.NETWORK_CONNECTION:
            proto = norm_fields.get("protocol") or "UNKNOWN"
            loc_ip = norm_fields.get("local_address")
            loc_port = norm_fields.get("local_port")
            rem_ip = norm_fields.get("remote_address")
            rem_port = norm_fields.get("remote_port")

            if loc_ip and loc_port is not None and rem_ip and rem_port is not None:
                canonical = f"net:{proto}:{loc_ip}:{loc_port}->{rem_ip}:{rem_port}"
                status = "NORMALIZED"
            elif loc_ip and loc_port is not None:
                canonical = f"net:{proto}:{loc_ip}:{loc_port}"
                status = "NORMALIZED"
            elif rem_ip and rem_port is not None:
                canonical = f"net:{proto}:->{rem_ip}:{rem_port}"
                status = "NORMALIZED"
            else:
                canonical = f"net_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        elif entity_type == EntityType.EVENT:
            event_id = norm_fields.get("event_id")
            channel = norm_fields.get("channel") or norm_fields.get("provider") or ""
            ts = norm_fields.get("event_timestamp") or ""
            if event_id:
                canonical = f"event:{channel}:{event_id}:{ts}"
                status = "NORMALIZED"
            else:
                canonical = f"event_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        elif entity_type == EntityType.MALWARE_MATCH:
            rule = norm_fields.get("rule_name")
            target = norm_fields.get("target_file") or ""
            if rule:
                canonical = f"malware:{rule}:{target.lower()}"
                status = "NORMALIZED"
            else:
                canonical = f"malware_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        elif entity_type == EntityType.METADATA:
            target = norm_fields.get("target_file")
            if target:
                canonical = f"metadata:{target.lower()}"
                status = "NORMALIZED"
            else:
                canonical = f"metadata_partial:{structured_art.id}"
                status = "PARTIAL_IDENTITY"

        else:  # GENERIC
            canonical = f"generic:{structured_art.id}"
            status = "NORMALIZED"

        # Deterministic fingerprint from canonical identity string
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
        entity_identity = f"{entity_type.lower()}_{digest}"

        return entity_identity, source_id, status


# =============================================================================
# 3. NORMALIZED STORAGE MANAGER
# =============================================================================

class NormalizedStorageManager:
    """
    Manages dedicated disk storage for normalized artifacts.
    Enforces strict path containment, safe permissions (0o700 / 0o600),
    and absolute prohibition from the evidence vault.
    """

    @classmethod
    def get_case_storage_dir(cls, case_id: str) -> Path:
        base_dir = settings.DATA_DIR / "storage" / "normalized" / "cases" / case_id
        base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass
        return base_dir

    @classmethod
    def validate_storage_path(cls, candidate_path: Path, case_id: str) -> bool:
        canonical = candidate_path.resolve()
        base_dir = (settings.DATA_DIR / "storage" / "normalized" / "cases" / case_id).resolve()

        vault_candidates = [
            settings.EVIDENCE_DIR.resolve(),
            (settings.EVIDENCE_DIR / "vault").resolve()
        ]
        for v in vault_candidates:
            if canonical == v or canonical.is_relative_to(v):
                raise ValueError(f"CRITICAL: Normalized storage cannot be located inside evidence vault: {canonical}")

        if not canonical.is_relative_to(base_dir):
            raise ValueError(f"Path traversal detected: {candidate_path} outside base {base_dir}")

        if candidate_path.is_symlink():
            raise ValueError(f"Symlink storage references strictly forbidden: {candidate_path}")

        return True

    @classmethod
    def persist_normalized_file(
        cls,
        case_id: str,
        normalized_id: str,
        payload: Dict[str, Any]
    ) -> Path:
        out_dir = cls.get_case_storage_dir(case_id)
        out_file = out_dir / f"{normalized_id}.json"
        cls.validate_storage_path(out_file, case_id)

        canonical_json = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
        out_file.write_text(canonical_json, encoding="utf-8")

        try:
            os.chmod(out_file, 0o600)
        except Exception:
            pass

        return out_file

    @classmethod
    def read_normalized_file(cls, case_id: str, normalized_id: str) -> Dict[str, Any]:
        out_dir = cls.get_case_storage_dir(case_id)
        file_path = out_dir / f"{normalized_id}.json"
        cls.validate_storage_path(file_path, case_id)
        if not file_path.exists():
            raise FileNotFoundError(f"Normalized artifact file not found: {file_path}")
        return json.loads(file_path.read_text(encoding="utf-8"))


# =============================================================================
# 4. ARTIFACT NORMALIZATION SERVICE
# =============================================================================

class ArtifactNormalizationService:
    """
    Core service converting Step 11 structured artifacts into common NormalizedArtifact models.
    Provides deterministic entity identity, multi-source deduplication, provenance chaining,
    and cryptographic SHA-256 integrity verification.
    """

    @classmethod
    def _build_evidence_reference(cls, db: Session, evidence_id: Optional[str], case_id: str) -> Dict[str, Any]:
        if not evidence_id:
            return {
                "evidence_id": None,
                "case_id": case_id,
                "evidence_name": "UNKNOWN",
                "evidence_type": "UNKNOWN",
                "source_kind": "UNKNOWN",
                "sha256_hash": None,
                "storage_location": None,
            }
        ev = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id, EvidenceItem.case_id == case_id).first()
        if not ev:
            return {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "evidence_name": "UNKNOWN",
                "evidence_type": "UNKNOWN",
                "source_kind": "UNKNOWN",
                "sha256_hash": None,
                "storage_location": None,
            }
        return {
            "evidence_id": ev.id,
            "case_id": ev.case_id,
            "evidence_name": ev.name,
            "evidence_type": ev.evidence_type,
            "source_kind": getattr(ev, "source_kind", None) or "UNKNOWN",
            "sha256_hash": ev.sha256_hash,
            "storage_location": getattr(ev, "stored_location", None) or getattr(ev, "file_path", None),
        }

    @classmethod
    def _compute_canonical_hash(
        cls,
        case_id: str,
        entity_type: str,
        entity_identity: str,
        normalized_fields: Dict[str, Any],
        evidence_reference: Dict[str, Any],
        provenance_summary: Dict[str, Any],
        contributing_source_artifact_ids: List[str],
        occurrence_count: int,
        source_artifact_hash: str
    ) -> str:
        canonical_dict = {
            "case_id": case_id,
            "entity_type": entity_type,
            "entity_identity": entity_identity,
            "normalized_fields": normalized_fields,
            "evidence_reference": evidence_reference,
            "provenance_summary": provenance_summary,
            "contributing_source_artifact_ids": sorted(contributing_source_artifact_ids),
            "occurrence_count": occurrence_count,
            "source_artifact_hash": source_artifact_hash,
        }
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':')).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def normalize_structured_artifact(
        cls,
        db: Session,
        structured_art: StructuredArtifact,
        actor_user: Optional[User] = None
    ) -> Tuple[NormalizedArtifact, bool]:
        """
        Normalizes a single Step 11 StructuredArtifact into a NormalizedArtifact.
        Handles deduplication within the same case:
        If an entity with the same (case_id, entity_identity) exists:
          - Retains all contributing source artifact IDs in contributing_source_artifact_ids
          - Increments occurrence_count
          - Updates stored hash and disk payload
          - Returns (existing_art, False)
        Otherwise:
          - Creates new NormalizedArtifact
          - Returns (new_art, True)
        """
        case_id = structured_art.case_id
        entity_type = EntityNormalizer.map_entity_type(
            structured_art.artifact_type,
            structured_art.extraction_status
        )
        norm_fields, entity_ts = EntityNormalizer.normalize_fields(entity_type, structured_art)
        entity_identity, source_specific_id, norm_status = EntityIdentityEngine.compute_identity(
            entity_type=entity_type,
            norm_fields=norm_fields,
            structured_art=structured_art
        )

        evidence_ref = cls._build_evidence_reference(db, structured_art.evidence_id, case_id)
        provenance_summary = {
            "tool_id": structured_art.tool_id,
            "tool_version": structured_art.tool_version,
            "parser_name": structured_art.parser_name,
            "parser_version": structured_art.parser_version,
            "raw_output_id": structured_art.raw_output_id,
            "source_artifact_id": structured_art.id,
            "extraction_status": structured_art.extraction_status,
        }

        # Check for existing normalized entity in this case for deterministic deduplication
        existing = (
            db.query(NormalizedArtifact)
            .filter(
                NormalizedArtifact.case_id == case_id,
                NormalizedArtifact.entity_identity == entity_identity
            )
            .first()
        )

        now = utc_now()

        if existing:
            # Multi-source deduplication: preserve all contributing source artifacts
            src_list = list(existing.contributing_source_artifact_ids or [])
            if structured_art.id not in src_list:
                src_list.append(structured_art.id)
            existing.contributing_source_artifact_ids = src_list
            existing.occurrence_count += 1
            existing.updated_at = now

            # Recompute canonical hash with updated contributors and count
            new_hash = cls._compute_canonical_hash(
                case_id=case_id,
                entity_type=existing.entity_type,
                entity_identity=existing.entity_identity,
                normalized_fields=existing.normalized_fields,
                evidence_reference=existing.evidence_reference,
                provenance_summary=existing.provenance_summary,
                contributing_source_artifact_ids=src_list,
                occurrence_count=existing.occurrence_count,
                source_artifact_hash=existing.source_artifact_hash
            )
            existing.sha256_hash = new_hash

            # Update persisted disk file
            payload = {
                "id": existing.id,
                "case_id": existing.case_id,
                "evidence_id": existing.evidence_id,
                "execution_id": existing.execution_id,
                "entity_type": existing.entity_type,
                "entity_identity": existing.entity_identity,
                "source_specific_identity": existing.source_specific_identity,
                "normalized_fields": existing.normalized_fields,
                "evidence_reference": existing.evidence_reference,
                "provenance_summary": existing.provenance_summary,
                "contributing_source_artifact_ids": src_list,
                "occurrence_count": existing.occurrence_count,
                "sha256_hash": new_hash,
                "source_artifact_hash": existing.source_artifact_hash,
                "normalization_status": existing.normalization_status,
                "updated_at": now.isoformat(),
            }
            NormalizedStorageManager.persist_normalized_file(case_id, existing.id, payload)

            db.commit()
            db.refresh(existing)

            log_audit_event(
                db=db,
                event_type="NORMALIZED_ARTIFACT_DEDUPLICATED",
                case_id=case_id,
                actor_id=actor_user.id if actor_user else "system",
                actor_name=actor_user.name if actor_user else "system",
                details=f"Deduplicated entity '{entity_identity}' with source artifact {structured_art.id}. Total occurrences: {existing.occurrence_count}"
            )
            return existing, False

        # Create new normalized artifact
        norm_id = str(uuid.uuid4())
        contributing_ids = [structured_art.id]
        occurrence_count = 1

        norm_hash = cls._compute_canonical_hash(
            case_id=case_id,
            entity_type=entity_type,
            entity_identity=entity_identity,
            normalized_fields=norm_fields,
            evidence_reference=evidence_ref,
            provenance_summary=provenance_summary,
            contributing_source_artifact_ids=contributing_ids,
            occurrence_count=occurrence_count,
            source_artifact_hash=structured_art.sha256_hash
        )

        disk_payload = {
            "id": norm_id,
            "case_id": case_id,
            "evidence_id": structured_art.evidence_id,
            "execution_id": structured_art.execution_id,
            "entity_type": entity_type,
            "entity_identity": entity_identity,
            "source_specific_identity": source_specific_id,
            "normalized_fields": norm_fields,
            "evidence_reference": evidence_ref,
            "provenance_summary": provenance_summary,
            "contributing_source_artifact_ids": contributing_ids,
            "occurrence_count": occurrence_count,
            "sha256_hash": norm_hash,
            "source_artifact_hash": structured_art.sha256_hash,
            "normalization_status": norm_status,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        storage_file = NormalizedStorageManager.persist_normalized_file(case_id, norm_id, disk_payload)

        new_norm = NormalizedArtifact(
            id=norm_id,
            case_id=case_id,
            evidence_id=structured_art.evidence_id,
            execution_id=structured_art.execution_id,
            source_artifact_id=structured_art.id,
            raw_output_id=structured_art.raw_output_id,
            request_id=structured_art.request_id,
            task_id=structured_art.task_id,
            entity_type=entity_type,
            entity_identity=entity_identity,
            source_specific_identity=source_specific_id,
            normalized_fields=norm_fields,
            evidence_reference=evidence_ref,
            provenance_summary=provenance_summary,
            contributing_source_artifact_ids=contributing_ids,
            occurrence_count=occurrence_count,
            entity_timestamp=entity_ts,
            sha256_hash=norm_hash,
            source_artifact_hash=structured_art.sha256_hash,
            storage_path=str(storage_file),
            normalization_status=norm_status,
            error_message=structured_art.error_message if norm_status == "UNSUPPORTED" else None,
            created_at=now,
            updated_at=now
        )
        db.add(new_norm)
        db.commit()
        db.refresh(new_norm)

        log_audit_event(
            db=db,
            event_type="NORMALIZED_ARTIFACT_CREATED",
            case_id=case_id,
            actor_id=actor_user.id if actor_user else "system",
            actor_name=actor_user.name if actor_user else "system",
            details=f"Normalized entity '{entity_identity}' of type {entity_type} from structured artifact {structured_art.id}"
        )
        return new_norm, True

    @classmethod
    def normalize_execution_artifacts(
        cls,
        db: Session,
        execution_id: str,
        case_id: str,
        actor_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Normalizes all structured artifacts belonging to an execution.
        """
        artifacts = (
            db.query(StructuredArtifact)
            .filter(
                StructuredArtifact.execution_id == execution_id,
                StructuredArtifact.case_id == case_id
            )
            .order_by(StructuredArtifact.created_at.asc())
            .all()
        )

        created_count = 0
        dedup_count = 0
        unsupported_count = 0
        results: List[NormalizedArtifact] = []

        for sa in artifacts:
            norm_art, is_new = cls.normalize_structured_artifact(
                db=db,
                structured_art=sa,
                actor_user=actor_user
            )
            if is_new:
                created_count += 1
                if norm_art.normalization_status == "UNSUPPORTED":
                    unsupported_count += 1
            else:
                dedup_count += 1
            results.append(norm_art)

        return {
            "execution_id": execution_id,
            "case_id": case_id,
            "total_structured_artifacts": len(artifacts),
            "processed_count": len(artifacts),
            "normalized_created_count": created_count,
            "deduplicated_count": dedup_count,
            "unsupported_count": unsupported_count,
            "normalized_artifacts": results
        }

    @classmethod
    def list_normalized_artifacts(
        cls,
        db: Session,
        case_id: str,
        entity_type: Optional[str] = None,
        normalization_status: Optional[str] = None,
        execution_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[NormalizedArtifact]:
        query = db.query(NormalizedArtifact).filter(NormalizedArtifact.case_id == case_id)
        if entity_type:
            query = query.filter(NormalizedArtifact.entity_type == entity_type)
        if normalization_status:
            query = query.filter(NormalizedArtifact.normalization_status == normalization_status)
        if execution_id:
            query = query.filter(NormalizedArtifact.execution_id == execution_id)

        return query.order_by(NormalizedArtifact.created_at.asc()).offset(skip).limit(limit).all()

    @classmethod
    def get_normalized_artifact(
        cls,
        db: Session,
        normalized_id: str,
        case_id: str
    ) -> NormalizedArtifact:
        art = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.id == normalized_id, NormalizedArtifact.case_id == case_id)
            .first()
        )
        if not art:
            raise ValueError(f"NormalizedArtifact '{normalized_id}' not found for case '{case_id}'")
        return art

    @classmethod
    def verify_normalized_integrity(
        cls,
        db: Session,
        normalized_id: str,
        case_id: str
    ) -> Dict[str, Any]:
        """
        Cryptographically verifies normalized artifact integrity and source structured artifact lineage.
        """
        art = cls.get_normalized_artifact(db, normalized_id, case_id)

        calc_hash = cls._compute_canonical_hash(
            case_id=art.case_id,
            entity_type=art.entity_type,
            entity_identity=art.entity_identity,
            normalized_fields=art.normalized_fields or {},
            evidence_reference=art.evidence_reference or {},
            provenance_summary=art.provenance_summary or {},
            contributing_source_artifact_ids=art.contributing_source_artifact_ids or [],
            occurrence_count=art.occurrence_count,
            source_artifact_hash=art.source_artifact_hash
        )

        disk_ok = True
        if art.storage_path:
            p = Path(art.storage_path)
            if not p.exists():
                disk_ok = False

        source_art = (
            db.query(StructuredArtifact)
            .filter(StructuredArtifact.id == art.source_artifact_id, StructuredArtifact.case_id == case_id)
            .first()
        )
        source_art_hash = source_art.sha256_hash if source_art else None
        source_match = (source_art_hash == art.source_artifact_hash) if source_art else False

        if not disk_ok and art.storage_path:
            status = "FILE_MISSING"
        elif calc_hash != art.sha256_hash:
            status = "TAMPERED"
        elif not source_match:
            status = "SOURCE_ARTIFACT_MISMATCH"
        else:
            status = "VALID"

        provenance = {
            "case_id": art.case_id,
            "evidence_id": art.evidence_id,
            "execution_id": art.execution_id,
            "source_artifact_id": art.source_artifact_id,
            "raw_output_id": art.raw_output_id,
            "request_id": art.request_id,
            "task_id": art.task_id,
            "contributing_source_artifact_ids": art.contributing_source_artifact_ids,
            "provenance_summary": art.provenance_summary,
            "normalization_status": art.normalization_status,
        }

        return {
            "normalized_id": art.id,
            "entity_type": art.entity_type,
            "entity_identity": art.entity_identity,
            "expected_sha256": art.sha256_hash,
            "calculated_sha256": calc_hash,
            "source_artifact_hash": art.source_artifact_hash,
            "source_artifact_current_hash": source_art_hash,
            "integrity_status": status,
            "provenance_chain": provenance,
            "checked_at": utc_now()
        }

    @classmethod
    def get_normalized_provenance(
        cls,
        db: Session,
        normalized_id: str,
        case_id: str
    ) -> Dict[str, Any]:
        """
        Reconstructs full multi-tier forensic provenance chain:
        EvidenceItem -> AnalysisRequest -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact
        """
        art = cls.get_normalized_artifact(db, normalized_id, case_id)

        evidence_info = art.evidence_reference or {}
        exec_model = db.query(ForensicExecution).filter(ForensicExecution.id == art.execution_id).first()
        execution_info = {
            "execution_id": art.execution_id,
            "tool_id": exec_model.tool_id if exec_model else (art.provenance_summary or {}).get("tool_id"),
            "tool_version": exec_model.tool_version if exec_model else (art.provenance_summary or {}).get("tool_version"),
            "execution_status": exec_model.execution_status if exec_model else "UNKNOWN",
            "exit_code": exec_model.exit_code if exec_model else None,
            "started_at": exec_model.started_at.isoformat() if exec_model and exec_model.started_at else None,
            "completed_at": exec_model.completed_at.isoformat() if exec_model and exec_model.completed_at else None,
        }

        raw_out = db.query(ExecutionOutput).filter(ExecutionOutput.id == art.raw_output_id).first() if art.raw_output_id else None
        raw_output_info = {
            "raw_output_id": raw_out.id,
            "filename": raw_out.filename,
            "output_type": raw_out.output_type,
            "sha256_hash": raw_out.sha256_hash,
        } if raw_out else None

        source_art = db.query(StructuredArtifact).filter(StructuredArtifact.id == art.source_artifact_id).first()
        source_art_info = {
            "source_artifact_id": source_art.id if source_art else art.source_artifact_id,
            "artifact_type": source_art.artifact_type if source_art else "UNKNOWN",
            "parser_name": source_art.parser_name if source_art else (art.provenance_summary or {}).get("parser_name"),
            "parser_version": source_art.parser_version if source_art else (art.provenance_summary or {}).get("parser_version"),
            "sha256_hash": source_art.sha256_hash if source_art else art.source_artifact_hash,
            "extraction_status": source_art.extraction_status if source_art else "UNKNOWN",
        }

        parser_info = {
            "parser_name": (art.provenance_summary or {}).get("parser_name", "UNKNOWN"),
            "parser_version": (art.provenance_summary or {}).get("parser_version", "1.0.0"),
            "tool_id": (art.provenance_summary or {}).get("tool_id"),
            "tool_version": (art.provenance_summary or {}).get("tool_version"),
        }

        chain = [
            f"EvidenceItem:{evidence_info.get('evidence_id') or 'NONE'}",
            f"AnalysisRequest:{art.request_id or 'NONE'}",
            f"ForensicExecution:{art.execution_id}",
            f"ExecutionOutput:{art.raw_output_id or 'NONE'}",
            f"StructuredArtifact:{art.source_artifact_id}",
            f"NormalizedArtifact:{art.id}"
        ]

        return {
            "normalized_id": art.id,
            "case_id": art.case_id,
            "entity_type": art.entity_type,
            "entity_identity": art.entity_identity,
            "occurrence_count": art.occurrence_count,
            "contributing_source_artifact_ids": art.contributing_source_artifact_ids or [art.source_artifact_id],
            "evidence": evidence_info,
            "execution": execution_info,
            "raw_output": raw_output_info,
            "source_artifact": source_art_info,
            "parser_info": parser_info,
            "traceability_chain": chain,
            "created_at": art.created_at,
            "updated_at": art.updated_at,
        }
