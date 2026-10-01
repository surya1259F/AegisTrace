"""
ADFIR — Unified Investigation Timeline Subsystem (Phase 2 / Step 13)

Converts timestamped normalized artifacts (NormalizedArtifact) into a unified,
chronologically ordered UTC investigation timeline (TimelineEvent).

Strict forensic boundaries:
- Timeline events represent ordered, trustworthy evidence-derived temporal data.
- DO NOT: infer attacker behavior, correlate events into attack chains, detect attacks,
  assign threat severity, generate findings, generate conclusions, or use LLM reasoning.
- DO NOT modify source artifacts (Evidence, Execution, Raw Output, Structured Artifact, Normalized Artifact).
- Never invent timestamps: artifacts without valid temporal data are excluded.
- Never silently assume a timezone: unknown or ambiguous timezones are explicitly recorded
  with reduced confidence scoring.
- End-to-end cryptographic lineage (SHA-256):
  EvidenceItem -> AnalysisRequest -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact -> TimelineEvent.
"""

import os
import re
import json
import uuid
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc

from backend.app.core.config import settings
from backend.app.models.models import (
    ForensicExecution,
    ExecutionOutput,
    EvidenceItem,
    StructuredArtifact,
    NormalizedArtifact,
    TimelineEvent,
    AuditEvent,
    User
)
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_UNIFIED_TIMELINE")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# 1. TIMESTAMP NORMALIZER & TEMPORAL PRECISION ENGINE
# =============================================================================

@dataclass
class TimestampNormalizationResult:
    timestamp_utc: datetime
    original_timestamp: str
    original_timezone: Optional[str]
    timezone_offset: Optional[str]
    timezone_source: Optional[str]
    timezone_status: str  # EXPLICIT, AMBIGUOUS, UNKNOWN
    temporal_precision: str  # EXACT, SECOND, MINUTE, HOUR, DAY, UNKNOWN
    confidence_score: float  # 0.0 - 1.0 (temporal quality and provenance only)
    window_start_utc: Optional[datetime]
    window_end_utc: Optional[datetime]


class TimestampNormalizer:
    """
    Forensic timestamp normalization engine.
    Converts valid timestamps to UTC, preserves exact original strings and offsets,
    identifies temporal precision, and assigns deterministic confidence scores.
    NEVER silently assumes a timezone.
    """

    # Common timezone abbreviation offsets (hours)
    TZ_ABBREVIATIONS = {
        "UTC": 0, "GMT": 0, "Z": 0,
        "EST": -5, "EDT": -4,
        "CST": -6, "CDT": -5,
        "MST": -7, "MDT": -6,
        "PST": -8, "PDT": -7,
        "BST": 1, "CET": 1, "CEST": 2,
        "IST": 5.5, "JST": 9, "AEST": 10, "AEDT": 11
    }

    # Regex patterns
    OFFSET_PATTERN = re.compile(r"([+-])(\d{2}):?(\d{2})$")
    NAMED_TZ_PATTERN = re.compile(r"\b([A-Z]{3,4})\b$")
    EXIF_PATTERN = re.compile(r"^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([+-]\d{2}:?\d{2}|Z))?$")

    @classmethod
    def normalize(cls, raw_val: Any, default_context_tz: Optional[str] = None) -> Optional[TimestampNormalizationResult]:
        """
        Parses raw timestamp into a normalized UTC representation.
        Returns None if input is empty, null, or unparseable. (Never invent timestamps).
        """
        if raw_val is None:
            return None

        # 1. Direct Python datetime
        if isinstance(raw_val, datetime):
            raw_str = raw_val.isoformat()
            if raw_val.tzinfo is not None:
                utc_dt = raw_val.astimezone(timezone.utc)
                offset_sec = raw_val.utcoffset().total_seconds() if raw_val.utcoffset() else 0
                sign = "+" if offset_sec >= 0 else "-"
                hh = int(abs(offset_sec) // 3600)
                mm = int((abs(offset_sec) % 3600) // 60)
                offset_str = f"{sign}{hh:02d}:{mm:02d}"
                return TimestampNormalizationResult(
                    timestamp_utc=utc_dt,
                    original_timestamp=raw_str,
                    original_timezone=str(raw_val.tzinfo),
                    timezone_offset=offset_str,
                    timezone_source="PYTHON_DATETIME_TZ",
                    timezone_status="EXPLICIT",
                    temporal_precision="EXACT" if raw_val.microsecond > 0 else "SECOND",
                    confidence_score=1.0 if raw_val.microsecond > 0 else 0.95,
                    window_start_utc=utc_dt,
                    window_end_utc=utc_dt
                )
            else:
                # Naive datetime: no timezone information
                utc_dt = raw_val.replace(tzinfo=timezone.utc)
                return TimestampNormalizationResult(
                    timestamp_utc=utc_dt,
                    original_timestamp=raw_str,
                    original_timezone=None,
                    timezone_offset=None,
                    timezone_source="MISSING",
                    timezone_status="UNKNOWN",
                    temporal_precision="EXACT" if raw_val.microsecond > 0 else "SECOND",
                    confidence_score=0.6,
                    window_start_utc=utc_dt,
                    window_end_utc=utc_dt
                )

        # 2. Numeric epoch (integer or float)
        if isinstance(raw_val, (int, float)):
            # Epoch is UTC by definition
            epoch_val = float(raw_val)
            if epoch_val <= 0:
                return None
            try:
                # Check for millisecond epoch (> 100 billion)
                is_ms = epoch_val > 1e11
                sec_val = epoch_val / 1000.0 if is_ms else epoch_val
                utc_dt = datetime.fromtimestamp(sec_val, tz=timezone.utc)
                precision = "EXACT" if (is_ms or (sec_val % 1 > 0)) else "SECOND"
                return TimestampNormalizationResult(
                    timestamp_utc=utc_dt,
                    original_timestamp=str(raw_val),
                    original_timezone="UTC",
                    timezone_offset="+00:00",
                    timezone_source="POSIX_EPOCH_UTC",
                    timezone_status="EXPLICIT",
                    temporal_precision=precision,
                    confidence_score=0.95 if precision == "EXACT" else 0.90,
                    window_start_utc=utc_dt,
                    window_end_utc=utc_dt
                )
            except (OverflowError, ValueError, OSError):
                return None

        # 3. String timestamp
        if not isinstance(raw_val, str):
            return None

        raw_str = raw_val.strip()
        if not raw_str or raw_str.lower() in ["none", "null", "unknown", "0", "0000-00-00", "0000:00:00 00:00:00"]:
            return None

        # Handle ExifTool formatted timestamp: "YYYY:MM:DD HH:MM:SS"
        exif_match = cls.EXIF_PATTERN.match(raw_str)
        if exif_match:
            y, m, d, hh, mm, ss, frac, tz_suffix = exif_match.groups()
            reconstructed = f"{y}-{m}-{d}T{hh}:{mm}:{ss}"
            if frac:
                reconstructed += f".{frac}"
            if tz_suffix:
                reconstructed += tz_suffix
            raw_str = reconstructed

        # Check for explicit numeric offset (+HH:MM or -HH:MM or Z)
        tz_status = "UNKNOWN"
        orig_tz: Optional[str] = None
        tz_offset_str: Optional[str] = None
        tz_source: Optional[str] = None
        has_subsecond = "." in raw_str

        # Check trailing 'Z'
        if raw_str.endswith("Z") or raw_str.endswith("z"):
            tz_status = "EXPLICIT"
            orig_tz = "UTC"
            tz_offset_str = "+00:00"
            tz_source = "EXPLICIT_UTC_Z"
        else:
            # Check numeric offset +HH:MM
            offset_m = cls.OFFSET_PATTERN.search(raw_str)
            if offset_m:
                sign, oh, om = offset_m.groups()
                tz_status = "EXPLICIT"
                orig_tz = f"{sign}{oh}:{om}"
                tz_offset_str = f"{sign}{oh}:{om}"
                tz_source = "EXPLICIT_ISO_OFFSET"
            else:
                # Check named timezone abbreviation (EST, PST, IST...)
                named_m = cls.NAMED_TZ_PATTERN.search(raw_str)
                if named_m:
                    tz_abbr = named_m.group(1)
                    if tz_abbr in cls.TZ_ABBREVIATIONS:
                        tz_status = "AMBIGUOUS"
                        orig_tz = tz_abbr
                        offset_hours = cls.TZ_ABBREVIATIONS[tz_abbr]
                        sign = "+" if offset_hours >= 0 else "-"
                        oh = int(abs(offset_hours))
                        om = int((abs(offset_hours) % 1) * 60)
                        tz_offset_str = f"{sign}{oh:02d}:{om:02d}"
                        tz_source = "NAMED_ABBREVIATION"
                        # Strip abbreviation for ISO parsing
                        raw_str = raw_str[:named_m.start()].strip()

        # Parse using datetime.fromisoformat
        parsed_dt: Optional[datetime] = None
        precision = "SECOND"
        cleaned_iso = raw_str.replace(" ", "T")

        # Check for date-only: "YYYY-MM-DD"
        if re.match(r"^\d{4}-\d{2}-\d{2}$", raw_str):
            try:
                d_obj = datetime.strptime(raw_str, "%Y-%m-%d")
                utc_dt = d_obj.replace(tzinfo=timezone.utc)
                win_start = utc_dt
                win_end = utc_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
                return TimestampNormalizationResult(
                    timestamp_utc=utc_dt,
                    original_timestamp=str(raw_val),
                    original_timezone=None,
                    timezone_offset=None,
                    timezone_source="DATE_ONLY",
                    timezone_status="UNKNOWN",
                    temporal_precision="DAY",
                    confidence_score=0.40,
                    window_start_utc=win_start,
                    window_end_utc=win_end
                )
            except Exception:
                return None

        # Standard ISO parsing
        try:
            parsed_dt = datetime.fromisoformat(cleaned_iso)
        except Exception:
            # Fallback patterns
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ):
                try:
                    parsed_dt = datetime.strptime(cleaned_iso, fmt)
                    break
                except Exception:
                    continue

        if not parsed_dt:
            return None

        # Convert to UTC
        if parsed_dt.tzinfo is not None:
            utc_dt = parsed_dt.astimezone(timezone.utc)
        elif tz_offset_str:
            # Apply identified offset
            sign_val = 1 if tz_offset_str[0] == "+" else -1
            parts = tz_offset_str[1:].split(":")
            oh = int(parts[0])
            om = int(parts[1]) if len(parts) > 1 else 0
            offset_td = timedelta(hours=oh, minutes=om) * sign_val
            tz_obj = timezone(offset_td)
            utc_dt = parsed_dt.replace(tzinfo=tz_obj).astimezone(timezone.utc)
        else:
            # No timezone specified: explicitly record UNKNOWN and convert assuming UTC
            tz_status = "UNKNOWN"
            tz_source = "ASSUMED_UTC_NO_OFFSET"
            utc_dt = parsed_dt.replace(tzinfo=timezone.utc)

        # Precision detection
        if parsed_dt.microsecond > 0 or has_subsecond:
            precision = "EXACT"
        else:
            precision = "SECOND"

        # Deterministic confidence score calculation based strictly on temporal quality/provenance
        if tz_status == "EXPLICIT":
            conf = 1.0 if precision == "EXACT" else 0.95
        elif tz_status == "AMBIGUOUS":
            conf = 0.70
        else:  # UNKNOWN
            conf = 0.60

        # Temporal windows
        win_start = utc_dt
        win_end = utc_dt

        return TimestampNormalizationResult(
            timestamp_utc=utc_dt,
            original_timestamp=str(raw_val),
            original_timezone=orig_tz,
            timezone_offset=tz_offset_str,
            timezone_source=tz_source,
            timezone_status=tz_status,
            temporal_precision=precision,
            confidence_score=conf,
            window_start_utc=win_start,
            window_end_utc=win_end
        )


# =============================================================================
# 2. TIMELINE STORAGE MANAGER
# =============================================================================

class TimelineStorageManager:
    """
    Manages dedicated disk storage for serialized timeline events.
    Enforces case isolation, safe permissions (0o700 dir, 0o600 file),
    path traversal prevention, and prohibition from the evidence vault.
    """

    @classmethod
    def get_case_storage_dir(cls, case_id: str) -> Path:
        base_dir = settings.DATA_DIR / "storage" / "timeline" / "cases" / case_id
        base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass
        return base_dir

    @classmethod
    def validate_storage_path(cls, candidate_path: Path, case_id: str) -> bool:
        canonical = candidate_path.resolve()
        base_dir = (settings.DATA_DIR / "storage" / "timeline" / "cases" / case_id).resolve()

        vault_candidates = [
            settings.EVIDENCE_DIR.resolve(),
            (settings.EVIDENCE_DIR / "vault").resolve()
        ]
        for v in vault_candidates:
            if canonical == v or canonical.is_relative_to(v):
                raise ValueError(f"CRITICAL: Timeline storage cannot be located inside evidence vault: {canonical}")

        if not canonical.is_relative_to(base_dir):
            raise ValueError(f"Path traversal detected: {candidate_path} outside base {base_dir}")

        if candidate_path.is_symlink():
            raise ValueError(f"Symlink storage references strictly forbidden: {candidate_path}")

        return True

    @classmethod
    def persist_timeline_file(cls, case_id: str, event_id: str, payload: Dict[str, Any]) -> Path:
        out_dir = cls.get_case_storage_dir(case_id)
        out_file = out_dir / f"{event_id}.json"
        cls.validate_storage_path(out_file, case_id)

        canonical_json = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
        out_file.write_text(canonical_json, encoding="utf-8")

        try:
            os.chmod(out_file, 0o600)
        except Exception:
            pass

        return out_file

    @classmethod
    def read_timeline_file(cls, case_id: str, event_id: str) -> Dict[str, Any]:
        out_dir = cls.get_case_storage_dir(case_id)
        file_path = out_dir / f"{event_id}.json"
        cls.validate_storage_path(file_path, case_id)
        if not file_path.exists():
            raise FileNotFoundError(f"Timeline event file not found: {file_path}")
        return json.loads(file_path.read_text(encoding="utf-8"))


# =============================================================================
# 3. UNIFIED TIMELINE SERVICE
# =============================================================================

class UnifiedTimelineService:
    """
    Core service converting timestamped normalized artifacts into a unified UTC investigation timeline.
    Enforces UTC conversion, timezone preservation, deterministic confidence scoring,
    chronological ordering with tie-breaking, storage isolation, and cryptographic integrity.
    """

    @classmethod
    def _format_utc_canonical(cls, dt: datetime) -> str:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + (f".{dt.microsecond:06d}" if dt.microsecond else "") + "Z"

    @classmethod
    def _compute_canonical_event_hash(
        cls,
        case_id: str,
        event_id: str,
        timestamp_utc: datetime,
        original_timestamp: str,
        original_timezone: Optional[str],
        timezone_offset: Optional[str],
        timezone_source: Optional[str],
        timezone_status: str,
        event_type: str,
        event_source: str,
        normalized_artifact_id: str,
        structured_artifact_id: Optional[str],
        evidence_id: Optional[str],
        execution_id: str,
        event_data: Dict[str, Any],
        confidence_score: float,
        temporal_precision: str,
        source_artifact_hash: str
    ) -> str:
        canonical_dict = {
            "case_id": case_id,
            "confidence_score": round(confidence_score, 4),
            "event_data": event_data,
            "event_id": event_id,
            "event_source": event_source,
            "event_type": event_type,
            "evidence_id": evidence_id,
            "execution_id": execution_id,
            "normalized_artifact_id": normalized_artifact_id,
            "original_timestamp": original_timestamp,
            "original_timezone": original_timezone,
            "source_artifact_hash": source_artifact_hash,
            "structured_artifact_id": structured_artifact_id,
            "temporal_precision": temporal_precision,
            "timestamp_utc": cls._format_utc_canonical(timestamp_utc),
            "timezone_offset": timezone_offset,
            "timezone_source": timezone_source,
            "timezone_status": timezone_status,
        }
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':')).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def _extract_source_name(cls, na: NormalizedArtifact) -> str:
        prov = na.provenance_summary or {}
        p_name = (prov.get("parser_name") or "").lower()
        t_id = (prov.get("tool_id") or "").lower()

        if "evtx" in p_name or "evtx" in t_id:
            return "EVTX"
        elif "pslist" in p_name or "pslist" in t_id:
            return "PSLIST"
        elif "netscan" in p_name or "netscan" in t_id:
            return "NETSCAN"
        elif "yara" in p_name or "yara" in t_id:
            return "YARA"
        elif "exif" in p_name or "exif" in t_id:
            return "EXIFTOOL"
        elif "fls" in p_name or "fls" in t_id:
            return "FLS"
        elif na.entity_type == "FILE":
            return "FILESYSTEM"
        elif na.entity_type == "PROCESS":
            return "PROCESS"
        elif na.entity_type == "NETWORK_CONNECTION":
            return "NETWORK"
        elif na.entity_type == "EVENT":
            return "EVENT_LOG"
        return "GENERIC"

    @classmethod
    def extract_events_from_normalized_artifact(
        cls,
        db: Session,
        normalized_art: NormalizedArtifact,
        actor_user: Optional[User] = None
    ) -> List[TimelineEvent]:
        """
        Converts a single NormalizedArtifact into one or more TimelineEvents based on its temporal attributes.
        Returns empty list if artifact contains no timestamp. (Never invents timestamps).
        """
        case_id = normalized_art.case_id
        fields = normalized_art.normalized_fields or {}
        source_name = cls._extract_source_name(normalized_art)
        created_events: List[TimelineEvent] = []

        # Find candidate timestamps in normalized artifact
        candidates: List[Tuple[str, Any]] = []

        # Inspect normalized_fields by entity type first
        if normalized_art.entity_type == "FILE":
            raw_data = fields.get("source_raw_data") or {}
            if "modified_time" in raw_data:
                candidates.append(("FILE_MODIFIED", raw_data["modified_time"]))
            if "created_time" in raw_data:
                candidates.append(("FILE_CREATED", raw_data["created_time"]))
            if "accessed_time" in raw_data:
                candidates.append(("FILE_ACCESSED", raw_data["accessed_time"]))
            if not candidates and "timestamp" in raw_data:
                candidates.append(("FILE_TIMESTAMP", raw_data["timestamp"]))

        elif normalized_art.entity_type == "PROCESS":
            if fields.get("start_time"):
                candidates.append(("PROCESS_LAUNCH", fields["start_time"]))
            raw_data = fields.get("source_raw_data") or {}
            if raw_data.get("exit_time"):
                candidates.append(("PROCESS_TERMINATION", raw_data["exit_time"]))

        elif normalized_art.entity_type == "NETWORK_CONNECTION":
            raw_data = fields.get("source_raw_data") or {}
            ts = raw_data.get("timestamp") or raw_data.get("created_time")
            if ts:
                candidates.append(("NETWORK_CONNECTION", ts))

        elif normalized_art.entity_type == "EVENT":
            ts = fields.get("event_timestamp") or (fields.get("source_raw_data") or {}).get("time_created")
            if ts:
                candidates.append(("EVENT_LOG", ts))

        elif normalized_art.entity_type == "MALWARE_MATCH":
            raw_data = fields.get("source_raw_data") or {}
            ts = raw_data.get("scan_time") or raw_data.get("timestamp")
            if ts:
                candidates.append(("MALWARE_DISCOVERY", ts))

        elif normalized_art.entity_type == "METADATA":
            raw_data = fields.get("source_raw_data") or {}
            for k in ["DateTimeOriginal", "CreateDate", "ModifyDate", "FileModifyDate"]:
                if raw_data.get(k):
                    candidates.append((f"METADATA_{k.upper()}", raw_data[k]))

        # Fallback to entity_timestamp ONLY IF NO candidates were found
        if not candidates and normalized_art.entity_timestamp is not None:
            candidates.append((f"{normalized_art.entity_type}_EVENT", normalized_art.entity_timestamp))

        # Check existing events for this normalized artifact to avoid re-creating duplicates
        existing_event_keys = {
            (ev.event_type, ev.original_timestamp)
            for ev in db.query(TimelineEvent).filter(
                TimelineEvent.case_id == case_id,
                TimelineEvent.normalized_artifact_id == normalized_art.id
            ).all()
        }

        # Deduplicate candidates within the artifact
        seen_candidates = set()

        for ev_type, raw_ts in candidates:
            norm_ts = TimestampNormalizer.normalize(raw_ts)
            if not norm_ts:
                continue

            cand_key = (ev_type, norm_ts.original_timestamp)
            if cand_key in seen_candidates or cand_key in existing_event_keys:
                continue
            seen_candidates.add(cand_key)

            event_id = str(uuid.uuid4())
            event_data = {
                "entity_type": normalized_art.entity_type,
                "entity_identity": normalized_art.entity_identity,
                "source_specific_identity": normalized_art.source_specific_identity,
                "normalized_fields": fields,
                "evidence_reference": normalized_art.evidence_reference,
            }

            # Normalize datetime to naive UTC for consistent SQLite storage
            stored_utc = norm_ts.timestamp_utc.astimezone(timezone.utc).replace(tzinfo=None) if norm_ts.timestamp_utc.tzinfo else norm_ts.timestamp_utc
            win_start = norm_ts.window_start_utc.astimezone(timezone.utc).replace(tzinfo=None) if norm_ts.window_start_utc and norm_ts.window_start_utc.tzinfo else norm_ts.window_start_utc
            win_end = norm_ts.window_end_utc.astimezone(timezone.utc).replace(tzinfo=None) if norm_ts.window_end_utc and norm_ts.window_end_utc.tzinfo else norm_ts.window_end_utc

            event_hash = cls._compute_canonical_event_hash(
                case_id=case_id,
                event_id=event_id,
                timestamp_utc=stored_utc,
                original_timestamp=norm_ts.original_timestamp,
                original_timezone=norm_ts.original_timezone,
                timezone_offset=norm_ts.timezone_offset,
                timezone_source=norm_ts.timezone_source,
                timezone_status=norm_ts.timezone_status,
                event_type=ev_type,
                event_source=source_name,
                normalized_artifact_id=normalized_art.id,
                structured_artifact_id=normalized_art.source_artifact_id,
                evidence_id=normalized_art.evidence_id,
                execution_id=normalized_art.execution_id,
                event_data=event_data,
                confidence_score=norm_ts.confidence_score,
                temporal_precision=norm_ts.temporal_precision,
                source_artifact_hash=normalized_art.sha256_hash
            )

            disk_payload = {
                "id": event_id,
                "case_id": case_id,
                "timestamp_utc": cls._format_utc_canonical(stored_utc),
                "original_timestamp": norm_ts.original_timestamp,
                "original_timezone": norm_ts.original_timezone,
                "timezone_offset": norm_ts.timezone_offset,
                "timezone_source": norm_ts.timezone_source,
                "timezone_status": norm_ts.timezone_status,
                "event_type": ev_type,
                "event_source": source_name,
                "normalized_artifact_id": normalized_art.id,
                "structured_artifact_id": normalized_art.source_artifact_id,
                "evidence_id": normalized_art.evidence_id,
                "execution_id": normalized_art.execution_id,
                "event_data": event_data,
                "confidence_score": norm_ts.confidence_score,
                "temporal_precision": norm_ts.temporal_precision,
                "window_start_utc": cls._format_utc_canonical(win_start) if win_start else None,
                "window_end_utc": cls._format_utc_canonical(win_end) if win_end else None,
                "sha256_hash": event_hash,
                "source_artifact_hash": normalized_art.sha256_hash,
                "created_at": utc_now().isoformat(),
            }
            storage_file = TimelineStorageManager.persist_timeline_file(case_id, event_id, disk_payload)

            tle = TimelineEvent(
                id=event_id,
                case_id=case_id,
                evidence_id=normalized_art.evidence_id,
                execution_id=normalized_art.execution_id,
                normalized_artifact_id=normalized_art.id,
                structured_artifact_id=normalized_art.source_artifact_id,
                timestamp_utc=stored_utc,
                original_timestamp=norm_ts.original_timestamp,
                original_timezone=norm_ts.original_timezone,
                timezone_offset=norm_ts.timezone_offset,
                timezone_source=norm_ts.timezone_source,
                timezone_status=norm_ts.timezone_status,
                event_type=ev_type,
                event_source=source_name,
                event_data=event_data,
                confidence_score=norm_ts.confidence_score,
                temporal_precision=norm_ts.temporal_precision,
                window_start_utc=win_start,
                window_end_utc=win_end,
                sha256_hash=event_hash,
                source_artifact_hash=normalized_art.sha256_hash,
                storage_path=str(storage_file),
                created_at=utc_now()
            )
            db.add(tle)
            created_events.append(tle)

        if created_events:
            db.commit()
            for ev in created_events:
                db.refresh(ev)

            log_audit_event(
                db=db,
                event_type="TIMELINE_EVENTS_GENERATED",
                case_id=case_id,
                actor_id=actor_user.id if actor_user else "system",
                actor_name=actor_user.name if actor_user else "system",
                details=f"Generated {len(created_events)} timeline event(s) from normalized artifact {normalized_art.id}"
            )

        return created_events

    @classmethod
    def generate_timeline_for_execution(
        cls,
        db: Session,
        execution_id: str,
        case_id: str,
        actor_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Generates timeline events for all normalized artifacts belonging to an execution.
        """
        norm_arts = (
            db.query(NormalizedArtifact)
            .filter(
                NormalizedArtifact.execution_id == execution_id,
                NormalizedArtifact.case_id == case_id
            )
            .order_by(NormalizedArtifact.created_at.asc())
            .all()
        )

        all_events: List[TimelineEvent] = []
        skipped_count = 0

        for na in norm_arts:
            events = cls.extract_events_from_normalized_artifact(db, na, actor_user)
            if events:
                all_events.extend(events)
            else:
                skipped_count += 1

        # Sort all generated events deterministically
        all_events.sort(key=lambda e: (e.timestamp_utc, -e.confidence_score, e.id))

        return {
            "case_id": case_id,
            "execution_id": execution_id,
            "total_normalized_artifacts": len(norm_arts),
            "processed_count": len(norm_arts),
            "events_generated_count": len(all_events),
            "skipped_count": skipped_count,
            "events": all_events
        }

    @classmethod
    def generate_timeline_for_case(
        cls,
        db: Session,
        case_id: str,
        actor_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Generates timeline events for all normalized artifacts across the entire case.
        """
        norm_arts = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.case_id == case_id)
            .order_by(NormalizedArtifact.created_at.asc())
            .all()
        )

        all_events: List[TimelineEvent] = []
        skipped_count = 0

        for na in norm_arts:
            events = cls.extract_events_from_normalized_artifact(db, na, actor_user)
            if events:
                all_events.extend(events)
            else:
                skipped_count += 1

        # Sort all generated events deterministically
        all_events.sort(key=lambda e: (e.timestamp_utc, -e.confidence_score, e.id))

        return {
            "case_id": case_id,
            "execution_id": None,
            "total_normalized_artifacts": len(norm_arts),
            "processed_count": len(norm_arts),
            "events_generated_count": len(all_events),
            "skipped_count": skipped_count,
            "events": all_events
        }

    @classmethod
    def list_timeline_events(
        cls,
        db: Session,
        case_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[str] = None,
        event_source: Optional[str] = None,
        evidence_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[TimelineEvent]:
        """
        Queries timeline events sorted chronologically by UTC timestamp with deterministic tie-breaking.
        """
        query = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id)

        if start_time:
            st = start_time.astimezone(timezone.utc).replace(tzinfo=None) if start_time.tzinfo else start_time
            query = query.filter(TimelineEvent.timestamp_utc >= st)
        if end_time:
            et = end_time.astimezone(timezone.utc).replace(tzinfo=None) if end_time.tzinfo else end_time
            query = query.filter(TimelineEvent.timestamp_utc <= et)
        if event_type:
            query = query.filter(TimelineEvent.event_type == event_type)
        if event_source:
            query = query.filter(TimelineEvent.event_source == event_source)
        if evidence_id:
            query = query.filter(TimelineEvent.evidence_id == evidence_id)
        if min_confidence is not None:
            query = query.filter(TimelineEvent.confidence_score >= min_confidence)

        # Deterministic sorting: timestamp_utc ASC, confidence_score DESC, id ASC
        return (
            query.order_by(
                asc(TimelineEvent.timestamp_utc),
                desc(TimelineEvent.confidence_score),
                asc(TimelineEvent.id)
            )
            .offset(skip)
            .limit(limit)
            .all()
        )

    @classmethod
    def get_timeline_event(cls, db: Session, event_id: str, case_id: str) -> TimelineEvent:
        event = (
            db.query(TimelineEvent)
            .filter(TimelineEvent.id == event_id, TimelineEvent.case_id == case_id)
            .first()
        )
        if not event:
            raise ValueError(f"TimelineEvent '{event_id}' not found for case '{case_id}'")
        return event

    @classmethod
    def verify_timeline_event_integrity(
        cls,
        db: Session,
        event_id: str,
        case_id: str
    ) -> Dict[str, Any]:
        """
        Cryptographically verifies timeline event integrity and source normalized artifact lineage.
        """
        ev = cls.get_timeline_event(db, event_id, case_id)

        calc_hash = cls._compute_canonical_event_hash(
            case_id=ev.case_id,
            event_id=ev.id,
            timestamp_utc=ev.timestamp_utc,
            original_timestamp=ev.original_timestamp,
            original_timezone=ev.original_timezone,
            timezone_offset=ev.timezone_offset,
            timezone_source=ev.timezone_source,
            timezone_status=ev.timezone_status,
            event_type=ev.event_type,
            event_source=ev.event_source,
            normalized_artifact_id=ev.normalized_artifact_id,
            structured_artifact_id=ev.structured_artifact_id,
            evidence_id=ev.evidence_id,
            execution_id=ev.execution_id,
            event_data=ev.event_data or {},
            confidence_score=ev.confidence_score,
            temporal_precision=ev.temporal_precision,
            source_artifact_hash=ev.source_artifact_hash
        )

        disk_ok = True
        if ev.storage_path:
            p = Path(ev.storage_path)
            if not p.exists():
                disk_ok = False

        source_na = (
            db.query(NormalizedArtifact)
            .filter(
                NormalizedArtifact.id == ev.normalized_artifact_id,
                NormalizedArtifact.case_id == case_id
            )
            .first()
        )
        source_hash = source_na.sha256_hash if source_na else None
        source_match = (source_hash == ev.source_artifact_hash) if source_na else False

        if not disk_ok and ev.storage_path:
            status = "FILE_MISSING"
        elif calc_hash != ev.sha256_hash:
            status = "TAMPERED"
        elif not source_match:
            status = "SOURCE_ARTIFACT_MISMATCH"
        else:
            status = "VALID"

        provenance = {
            "case_id": ev.case_id,
            "evidence_id": ev.evidence_id,
            "execution_id": ev.execution_id,
            "normalized_artifact_id": ev.normalized_artifact_id,
            "structured_artifact_id": ev.structured_artifact_id,
            "event_type": ev.event_type,
            "event_source": ev.event_source,
            "timestamp_utc": ev.timestamp_utc.isoformat(),
            "original_timestamp": ev.original_timestamp,
            "temporal_precision": ev.temporal_precision,
            "confidence_score": ev.confidence_score,
        }

        return {
            "event_id": ev.id,
            "event_type": ev.event_type,
            "timestamp_utc": ev.timestamp_utc,
            "expected_sha256": ev.sha256_hash,
            "calculated_sha256": calc_hash,
            "source_artifact_hash": ev.source_artifact_hash,
            "source_artifact_current_hash": source_hash,
            "integrity_status": status,
            "provenance_chain": provenance,
            "checked_at": utc_now()
        }

    @classmethod
    def get_timeline_event_provenance(
        cls,
        db: Session,
        event_id: str,
        case_id: str
    ) -> Dict[str, Any]:
        """
        Reconstructs complete multi-tier forensic provenance chain:
        EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact -> TimelineEvent
        """
        ev = cls.get_timeline_event(db, event_id, case_id)

        na = db.query(NormalizedArtifact).filter(NormalizedArtifact.id == ev.normalized_artifact_id).first()
        sa = db.query(StructuredArtifact).filter(StructuredArtifact.id == ev.structured_artifact_id).first() if ev.structured_artifact_id else None
        fe = db.query(ForensicExecution).filter(ForensicExecution.id == ev.execution_id).first()
        item = db.query(EvidenceItem).filter(EvidenceItem.id == ev.evidence_id).first() if ev.evidence_id else None
        raw_out = db.query(ExecutionOutput).filter(ExecutionOutput.id == na.raw_output_id).first() if na and na.raw_output_id else None

        evidence_info = {
            "evidence_id": item.id if item else ev.evidence_id,
            "name": item.name if item else "UNKNOWN",
            "evidence_type": item.evidence_type if item else "UNKNOWN",
            "sha256_hash": item.sha256 if item else None,
        }

        execution_info = {
            "execution_id": fe.id if fe else ev.execution_id,
            "tool_id": fe.tool_id if fe else None,
            "tool_version": fe.tool_version if fe else None,
            "execution_status": fe.execution_status if fe else "UNKNOWN",
            "exit_code": fe.exit_code if fe else None,
        }

        raw_output_info = {
            "raw_output_id": raw_out.id,
            "filename": raw_out.filename,
            "output_type": raw_out.output_type,
            "sha256_hash": raw_out.sha256_hash,
        } if raw_out else None

        structured_artifact_info = {
            "structured_artifact_id": sa.id,
            "artifact_type": sa.artifact_type,
            "parser_name": sa.parser_name,
            "parser_version": sa.parser_version,
            "sha256_hash": sa.sha256_hash,
        } if sa else None

        normalized_artifact_info = {
            "normalized_artifact_id": na.id if na else ev.normalized_artifact_id,
            "entity_type": na.entity_type if na else "UNKNOWN",
            "entity_identity": na.entity_identity if na else "UNKNOWN",
            "occurrence_count": na.occurrence_count if na else 1,
            "sha256_hash": na.sha256_hash if na else ev.source_artifact_hash,
        }

        tz_meta = {
            "original_timestamp": ev.original_timestamp,
            "original_timezone": ev.original_timezone,
            "timezone_offset": ev.timezone_offset,
            "timezone_source": ev.timezone_source,
            "timezone_status": ev.timezone_status,
        }

        chain = [
            f"EvidenceItem:{ev.evidence_id or 'NONE'}",
            f"ForensicExecution:{ev.execution_id}",
            f"ExecutionOutput:{raw_out.id if raw_out else 'NONE'}",
            f"StructuredArtifact:{ev.structured_artifact_id or 'NONE'}",
            f"NormalizedArtifact:{ev.normalized_artifact_id}",
            f"TimelineEvent:{ev.id}"
        ]

        return {
            "event_id": ev.id,
            "case_id": ev.case_id,
            "event_type": ev.event_type,
            "event_source": ev.event_source,
            "timestamp_utc": ev.timestamp_utc,
            "original_timestamp": ev.original_timestamp,
            "timezone_metadata": tz_meta,
            "confidence_score": ev.confidence_score,
            "temporal_precision": ev.temporal_precision,
            "evidence": evidence_info,
            "execution": execution_info,
            "raw_output": raw_output_info,
            "structured_artifact": structured_artifact_info,
            "normalized_artifact": normalized_artifact_info,
            "traceability_chain": chain,
            "created_at": ev.created_at,
        }
