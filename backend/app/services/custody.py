import hashlib
import json
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.models.models import ChainOfCustodyEvent

logger = logging.getLogger("ADFIR_CUSTODY")

def _format_custody_ts(dt: datetime) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def record_custody_event(
    db: Session,
    case_id: str,
    evidence_id: str,
    event_type: str,
    description: str,
    actor: str = "NOT_RECORDED",
    actor_id: str = "NOT_RECORDED",
    source_path: str = None,
    destination_path: str = None,
    sha256: str = None,
    metadata_json: dict = None
) -> ChainOfCustodyEvent:
    """
    Appends an immutable chain of custody record with cryptographic chaining.
    """
    now = datetime.now(timezone.utc)
    meta = metadata_json or {}
    ts_str = _format_custody_ts(now)

    # Get the previous custody event for cryptographic chaining
    last_event = (
        db.query(ChainOfCustodyEvent)
        .filter(ChainOfCustodyEvent.evidence_id == evidence_id)
        .order_by(ChainOfCustodyEvent.timestamp.desc())
        .first()
    )
    prev_hash = last_event.event_hash if last_event and last_event.event_hash else "GENESIS_BLOCK"

    # Compute current event hash
    raw_block = f"{prev_hash}|{ts_str}|{case_id}|{evidence_id}|{event_type}|{sha256 or ''}|{description}|{json.dumps(meta, sort_keys=True)}"
    event_hash = hashlib.sha256(raw_block.encode("utf-8")).hexdigest()

    event = ChainOfCustodyEvent(
        case_id=case_id,
        evidence_id=evidence_id,
        actor=actor,
        actor_id=actor_id,
        event_type=event_type,
        timestamp=now,
        description=description,
        source_path=source_path,
        destination_path=destination_path,
        sha256=sha256,
        metadata_json=meta,
        previous_event_hash=prev_hash,
        event_hash=event_hash
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    logger.info(f"[CHAIN_OF_CUSTODY] Evidence: {evidence_id} | Type: {event_type} | Block Hash: {event_hash[:16]}...")
    return event

def verify_custody_chain(db: Session, evidence_id: str) -> Tuple[bool, Optional[str], str, int]:
    """
    Verifies the cryptographic hash-chain integrity of all custody events for a given evidence item.
    Returns: (is_valid, tampered_event_id, error_message, total_events_checked)
    """
    events = (
        db.query(ChainOfCustodyEvent)
        .filter(ChainOfCustodyEvent.evidence_id == evidence_id)
        .order_by(ChainOfCustodyEvent.timestamp.asc())
        .all()
    )

    if not events:
        return True, None, "No chain of custody events recorded.", 0

    expected_prev = "GENESIS_BLOCK"
    for idx, event in enumerate(events):
        if event.previous_event_hash != expected_prev:
            msg = f"Chain link broken at event #{idx+1} ({event.id}): recorded previous hash '{event.previous_event_hash}' does not match expected previous hash '{expected_prev}'."
            logger.warning(f"[CUSTODY_INTEGRITY_FAILURE] {msg}")
            return False, event.id, msg, idx + 1

        # Re-verify hash calculation if timestamp and raw block structure match
        meta = event.metadata_json or {}
        ts_str = _format_custody_ts(event.timestamp)
        raw_block = f"{event.previous_event_hash}|{ts_str}|{event.case_id}|{event.evidence_id}|{event.event_type}|{event.sha256 or ''}|{event.description}|{json.dumps(meta, sort_keys=True)}"
        recalculated_hash = hashlib.sha256(raw_block.encode("utf-8")).hexdigest()

        if event.event_hash and event.event_hash.lower() != recalculated_hash.lower():
            msg = f"Event content tampered at event #{idx+1} ({event.id}): stored hash '{event.event_hash}' does not match recalculated hash '{recalculated_hash}'."
            logger.warning(f"[CUSTODY_INTEGRITY_FAILURE] {msg}")
            return False, event.id, msg, idx + 1

        expected_prev = event.event_hash

    return True, None, f"Chain of custody verified intact across {len(events)} events.", len(events)

