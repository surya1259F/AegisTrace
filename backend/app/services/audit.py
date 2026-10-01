"""ADFIR — Cryptographic Hash-Chained Audit Subsystem (Final Backend Completion)

Extends the audit subsystem with:
- Previous-hash linkage and monotonic chain index.
- Full provenance context tracing (case_id, run_id, task_id, execution_id, evidence_id, output_id, artifact_id, finding_id, review_id, report_id).
- Audit chain integrity verification and tamper detection.
- Append-only immutability.
- Multi-tenant case isolation.
"""

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.models.models import AuditEvent, Case
from backend.app.schemas.schemas import AuditChainVerificationResponse

logger = logging.getLogger("ADFIR_AUDIT")

GENESIS_HASH = "0" * 64
_audit_lock = threading.Lock()


def canonical_timestamp_iso(ts: Any) -> str:
    """
    Produces a deterministic canonical ISO-8601 UTC string:
    YYYY-MM-DDTHH:MM:SS.ffffffZ
    Normalizes both naive and aware datetimes, strings, etc.
    """
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return ts
    if not isinstance(ts, datetime):
        return str(ts)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_audit_hash(
    chain_index: int,
    previous_hash: str,
    timestamp_iso: str,
    event_type: str,
    case_id: Optional[str],
    actor_name: str,
    details: str,
    metadata_json: Dict[str, Any],
    provenance_context: Dict[str, Any]
) -> str:
    """Computes deterministic SHA-256 hash for a chained audit record."""
    meta_str = json.dumps(metadata_json or {}, sort_keys=True)
    prov_str = json.dumps(provenance_context or {}, sort_keys=True)
    raw_payload = (
        f"{chain_index}|{previous_hash}|{timestamp_iso}|{event_type}|"
        f"{case_id or ''}|{actor_name}|{details}|{meta_str}|{prov_str}"
    )
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()


def compute_legacy_audit_hash(
    timestamp_iso: str,
    event_type: str,
    case_id: Optional[str],
    actor_name: str,
    details: str,
    metadata_json: Dict[str, Any]
) -> str:
    """Legacy pre-Step-21 hash computation."""
    meta_str = json.dumps(metadata_json or {}, sort_keys=True)
    raw_payload = f"{timestamp_iso}|{event_type}|{case_id or ''}|{actor_name}|{details}|{meta_str}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()


class AuditService:
    """
    Core service managing append-only, tamper-detectable, hash-chained audit events.
    """

    @classmethod
    def log_event(
        cls,
        db: Session,
        event_type: str,
        details: str,
        case_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_name: str = "NOT_RECORDED",
        metadata_json: Optional[Dict[str, Any]] = None,
        provenance_context: Optional[Dict[str, Any]] = None,
        ip_address: str = "127.0.0.1"
    ) -> AuditEvent:
        """
        Appends a cryptographically hash-chained audit event.
        """
        with _audit_lock:
            now = datetime.now(timezone.utc)
            meta = metadata_json or {}
            prov = provenance_context or {}

            # Determine last event in chain for this case (or system)
            query = db.query(AuditEvent)
            if case_id:
                query = query.filter(AuditEvent.case_id == case_id)
            else:
                query = query.filter(AuditEvent.case_id.is_(None))

            last_event = query.order_by(AuditEvent.chain_index.desc(), AuditEvent.timestamp.desc(), AuditEvent.id.desc()).first()

            if last_event:
                previous_hash = last_event.event_hash or GENESIS_HASH
                chain_index = (last_event.chain_index + 1) if last_event.chain_index is not None else 1
            else:
                previous_hash = GENESIS_HASH
                chain_index = 0

            ts_iso = canonical_timestamp_iso(now)
            event_hash = compute_audit_hash(
                chain_index=chain_index,
                previous_hash=previous_hash,
                timestamp_iso=ts_iso,
                event_type=event_type,
                case_id=case_id,
                actor_name=actor_name,
                details=details,
                metadata_json=meta,
                provenance_context=prov
            )

            event = AuditEvent(
                case_id=case_id,
                actor_id=actor_id,
                actor_name=actor_name,
                event_type=event_type,
                details=details,
                metadata_json=meta,
                provenance_context=prov,
                ip_address=ip_address,
                timestamp=now,
                event_hash=event_hash,
                previous_hash=previous_hash,
                chain_index=chain_index
            )
            db.add(event)
            db.commit()
            db.refresh(event)

            logger.info(f"[AUDIT] [{event_type}] Case: {case_id} | Index: {chain_index} | Actor: {actor_name} | {details}")
            return event

    @classmethod
    def verify_chain(
        cls,
        db: Session,
        case_id: Optional[str] = None
    ) -> AuditChainVerificationResponse:
        """
        Walks the audit chain for a case (or system) from genesis to head,
        verifying cryptographic hash integrity and previous_hash linkage.
        Detects database mutations, row deletions, or content tampering.
        """
        now = datetime.now(timezone.utc)
        query = db.query(AuditEvent)
        if case_id:
            query = query.filter(AuditEvent.case_id == case_id)
        else:
            query = query.filter(AuditEvent.case_id.is_(None))

        events = query.order_by(AuditEvent.chain_index.asc(), AuditEvent.timestamp.asc(), AuditEvent.id.asc()).all()

        if not events:
            return AuditChainVerificationResponse(
                case_id=case_id,
                total_events=0,
                is_valid=True,
                tamper_detected=False,
                verification_message="Audit chain is empty; no events recorded.",
                genesis_hash=None,
                latest_hash=None,
                verified_at=now
            )

        for i, ev in enumerate(events):
            # 1. Verify previous_hash linkage
            if i == 0:
                expected_prev = GENESIS_HASH
                # Genesis event can have previous_hash == GENESIS_HASH or None for legacy
                if ev.previous_hash and ev.previous_hash != GENESIS_HASH and ev.chain_index == 0:
                    return AuditChainVerificationResponse(
                        case_id=case_id,
                        total_events=len(events),
                        is_valid=False,
                        tamper_detected=True,
                        broken_link_index=0,
                        broken_event_id=ev.id,
                        verification_message=f"Genesis audit event {ev.id} has invalid previous_hash '{ev.previous_hash}'.",
                        genesis_hash=events[0].event_hash,
                        latest_hash=events[-1].event_hash,
                        verified_at=now
                    )
            else:
                prev_ev = events[i - 1]
                if ev.previous_hash is not None and prev_ev.event_hash is not None:
                    if ev.previous_hash != prev_ev.event_hash:
                        return AuditChainVerificationResponse(
                            case_id=case_id,
                            total_events=len(events),
                            is_valid=False,
                            tamper_detected=True,
                            broken_link_index=i,
                            broken_event_id=ev.id,
                            verification_message=(
                                f"Audit chain break detected at index {i} (Event {ev.id}): "
                                f"previous_hash '{ev.previous_hash}' != predecessor hash '{prev_ev.event_hash}'."
                            ),
                            genesis_hash=events[0].event_hash,
                            latest_hash=events[-1].event_hash,
                            verified_at=now
                        )

            # 2. Verify payload hash integrity
            ts_iso = canonical_timestamp_iso(ev.timestamp)
            if ev.previous_hash is not None and ev.chain_index is not None:
                expected_hash = compute_audit_hash(
                    chain_index=ev.chain_index,
                    previous_hash=ev.previous_hash,
                    timestamp_iso=ts_iso,
                    event_type=ev.event_type,
                    case_id=ev.case_id,
                    actor_name=ev.actor_name,
                    details=ev.details,
                    metadata_json=ev.metadata_json or {},
                    provenance_context=ev.provenance_context or {}
                )
            else:
                expected_hash = compute_legacy_audit_hash(
                    timestamp_iso=ts_iso,
                    event_type=ev.event_type,
                    case_id=ev.case_id,
                    actor_name=ev.actor_name,
                    details=ev.details,
                    metadata_json=ev.metadata_json or {}
                )

            if ev.event_hash and ev.event_hash != expected_hash:
                return AuditChainVerificationResponse(
                    case_id=case_id,
                    total_events=len(events),
                    is_valid=False,
                    tamper_detected=True,
                    broken_link_index=i,
                    broken_event_id=ev.id,
                    verification_message=(
                        f"Tamper detected in audit event {ev.id} at index {i}: "
                        f"stored hash '{ev.event_hash}' != recomputed hash '{expected_hash}'."
                    ),
                    genesis_hash=events[0].event_hash,
                    latest_hash=events[-1].event_hash,
                    verified_at=now
                )

        return AuditChainVerificationResponse(
            case_id=case_id,
            total_events=len(events),
            is_valid=True,
            tamper_detected=False,
            verification_message=f"Audit chain verified successfully ({len(events)} events intact).",
            genesis_hash=events[0].event_hash,
            latest_hash=events[-1].event_hash,
            verified_at=now
        )

    @classmethod
    def list_events(
        cls,
        db: Session,
        case_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEvent]:
        query = db.query(AuditEvent)
        if case_id:
            query = query.filter(AuditEvent.case_id == case_id)
        if event_type:
            query = query.filter(AuditEvent.event_type == event_type)
        return query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).offset(offset).limit(limit).all()


# Backward-compatible global helper function
def log_audit_event(
    db: Session,
    event_type: str,
    details: str,
    case_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_name: str = "NOT_RECORDED",
    metadata_json: Optional[Dict[str, Any]] = None,
    ip_address: str = "127.0.0.1",
    provenance_context: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """
    Appends an immutable security audit event to the cryptographically chained audit log.
    """
    return AuditService.log_event(
        db=db,
        event_type=event_type,
        details=details,
        case_id=case_id,
        actor_id=actor_id,
        actor_name=actor_name,
        metadata_json=metadata_json,
        provenance_context=provenance_context,
        ip_address=ip_address
    )
