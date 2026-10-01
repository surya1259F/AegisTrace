import os
import sys
import json
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import EvidenceItem, EvidenceAcquisition, Case, ChainOfCustodyEvent
from backend.app.services.vault import stage_evidence_to_vault, get_vault_dir, apply_os_read_only, verify_os_read_only
from backend.app.services.custody import record_custody_event
from backend.app.services.intelligence import EvidenceIntelligenceEngine

logger = logging.getLogger("ADFIR_ACQUISITION")

class AcquisitionError(Exception):
    pass

class DuplicateEvidenceError(AcquisitionError):
    def __init__(self, message: str, existing_evidence: EvidenceItem):
        super().__init__(message)
        self.existing_evidence = existing_evidence

def validate_acquisition_source(source_path: str, acquisition_type: str = "SINGLE_FILE") -> Tuple[bool, str, Dict[str, Any]]:
    """
    Performs rigorous pre-flight validation on evidence acquisition target:
    1. Rejects path traversal, null bytes, non-existent paths.
    2. Enforces resource limits (max file size, max directory size, max file count, max depth).
    3. Verifies free disk space in storage vault.
    Returns: (is_valid, error_message, stats_dict)
    """
    if not source_path or "\x00" in str(source_path):
        return False, "Invalid source path containing null bytes or empty string.", {}

    src = Path(source_path).resolve()
    if not src.exists():
        return False, f"Source evidence path does not exist: {source_path}", {}

    if not os.access(src, os.R_OK):
        return False, f"Source evidence path is not readable (Permission Denied): {source_path}", {}

    # Check symlink safety
    if src.is_symlink():
        real_target = src.resolve()
        if not real_target.exists():
            return False, f"Source path is a broken symlink pointing to {real_target}", {}

    stats = {"total_files": 0, "total_bytes": 0, "max_depth": 0}

    if src.is_file():
        file_size = src.stat().st_size
        if file_size > settings.MAX_EVIDENCE_FILE_SIZE_BYTES:
            max_gb = settings.MAX_EVIDENCE_FILE_SIZE_BYTES / (1024 ** 3)
            return False, f"File size ({file_size} bytes) exceeds maximum allowed limit of {max_gb:.1f} GB.", {}
        stats["total_files"] = 1
        stats["total_bytes"] = file_size

    elif src.is_dir():
        file_count = 0
        total_bytes = 0
        max_depth_found = 0
        base_depth = len(src.parts)

        for root, dirs, files in os.walk(src, followlinks=False):
            current_path = Path(root)
            depth = len(current_path.parts) - base_depth
            if depth > max_depth_found:
                max_depth_found = depth

            if depth > settings.MAX_DIRECTORY_RECURSION_DEPTH:
                return False, f"Directory structure exceeds maximum recursion depth limit ({settings.MAX_DIRECTORY_RECURSION_DEPTH}).", {}

            for f in files:
                file_path = current_path / f
                if file_path.is_symlink():
                    continue
                file_count += 1
                if file_count > settings.MAX_DIRECTORY_FILE_COUNT:
                    return False, f"Directory file count exceeds maximum allowed limit of {settings.MAX_DIRECTORY_FILE_COUNT} files.", {}
                
                try:
                    f_size = file_path.stat().st_size
                    total_bytes += f_size
                except Exception:
                    pass

                if total_bytes > settings.MAX_DIRECTORY_ACQUISITION_SIZE_BYTES:
                    max_dir_gb = settings.MAX_DIRECTORY_ACQUISITION_SIZE_BYTES / (1024 ** 3)
                    return False, f"Directory size exceeds maximum allowed limit of {max_dir_gb:.1f} GB.", {}

        stats["total_files"] = file_count
        stats["total_bytes"] = total_bytes
        stats["max_depth"] = max_depth_found
    else:
        return False, f"Source path is neither a regular file nor a directory: {source_path}", {}

    # Verify target disk free space
    vault_base = settings.EVIDENCE_DIR / "vault"
    vault_base.mkdir(parents=True, exist_ok=True)
    try:
        free_bytes = shutil.disk_usage(vault_base).free
        required_bytes = stats["total_bytes"] + settings.MIN_FREE_DISK_SPACE_BYTES
        if free_bytes < required_bytes:
            req_gb = required_bytes / (1024 ** 3)
            free_gb = free_bytes / (1024 ** 3)
            return False, f"Insufficient disk space in vault storage. Required: {req_gb:.2f} GB, Available: {free_gb:.2f} GB.", {}
    except Exception as e:
        logger.warning(f"Could not check disk usage: {e}")

    return True, "", stats

def check_duplicate_evidence(db: Session, case_id: str, sha256_hash: str) -> Optional[EvidenceItem]:
    """
    Checks if identical evidence (same SHA-256) already exists within the target case.
    """
    if not sha256_hash:
        return None
    return (
        db.query(EvidenceItem)
        .filter(
            EvidenceItem.case_id == case_id,
            EvidenceItem.sha256 == sha256_hash.lower(),
            EvidenceItem.status != "ARCHIVED"
        )
        .first()
    )

def ingest_single_file_evidence(
    db: Session,
    case_id: str,
    source_path: str,
    actor_id: str = "NOT_RECORDED",
    actor_name: str = "NOT_RECORDED",
    evidence_type_override: Optional[str] = None,
    acquisition_type: str = "SINGLE_FILE",
    notes: Optional[str] = None,
    parent_acquisition_id: Optional[str] = None
) -> EvidenceItem:
    """
    Ingests a single file into the managed evidence vault with complete hash verification,
    magic byte format detection, duplicate detection, and hash-chained custody logging.
    """
    # 1. Pre-flight validation
    is_valid, err_msg, stats = validate_acquisition_source(source_path, acquisition_type)
    if not is_valid:
        raise AcquisitionError(f"Pre-flight acquisition validation failed: {err_msg}")

    src_path = Path(source_path).resolve()
    temp_ev_id = f"ev-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    # 2. Stage into vault (computes SHA256 & copies safely)
    staging = stage_evidence_to_vault(str(src_path), case_id, temp_ev_id)

    # 3. Duplicate check in target case
    duplicate = check_duplicate_evidence(db, case_id, staging.sha256)
    if duplicate:
        # Clean up staged vault copy if duplicate
        vault_file = Path(staging.storage_path)
        if vault_file.exists():
            from backend.app.services.vault import remove_os_read_only
            remove_os_read_only(vault_file)
            vault_file.unlink(missing_ok=True)
            if vault_file.parent.exists() and not list(vault_file.parent.iterdir()):
                vault_file.parent.rmdir()
        raise DuplicateEvidenceError(
            f"Evidence with SHA-256 ({staging.sha256}) already exists in case {case_id} as item '{duplicate.name}' ({duplicate.id}).",
            existing_evidence=duplicate
        )

    # 4. Deterministic magic byte signature inspection
    source_kind, detected_ev_type, ev_subtype, detected_fmt, conf, signals = EvidenceIntelligenceEngine.inspect_magic_header(src_path)
    final_ev_type = evidence_type_override or detected_ev_type or "GENERIC_BINARY"

    # Map acquisition type to source_kind if specialized
    if acquisition_type == "DISK_IMAGE":
        source_kind = "DISK_IMAGE"
        final_ev_type = final_ev_type if final_ev_type != "GENERIC_BINARY" else "DISK_IMAGE"
    elif acquisition_type == "MEMORY_DUMP":
        source_kind = "MEMORY_DUMP"
        final_ev_type = final_ev_type if final_ev_type != "GENERIC_BINARY" else "MEMORY_DUMP"
    elif acquisition_type == "EVTX":
        source_kind = "EVENT_LOG"
        final_ev_type = final_ev_type if final_ev_type != "GENERIC_BINARY" else "WINDOWS_EVENT_LOG"
    elif acquisition_type == "BROWSER":
        source_kind = "BROWSER_DB"
        final_ev_type = final_ev_type if final_ev_type != "GENERIC_BINARY" else "BROWSER_ARTIFACT"
    elif acquisition_type == "PCAP":
        source_kind = "FILE"
        final_ev_type = final_ev_type if final_ev_type != "GENERIC_BINARY" else "GENERIC_BINARY"

    # 5. Create database EvidenceItem record
    item = EvidenceItem(
        case_id=case_id,
        parent_acquisition_id=parent_acquisition_id,
        name=src_path.name,
        original_path=str(src_path),
        storage_path=staging.storage_path,
        evidence_type=final_ev_type,
        evidence_subtype=ev_subtype,
        source_kind=source_kind,
        acquisition_method="FORENSIC_ACQUISITION" if acquisition_type != "SINGLE_FILE" else "INVESTIGATOR_IMPORT",
        detected_format=detected_fmt,
        size_bytes=float(staging.size_bytes),
        sha256=staging.sha256,
        status="ANALYSIS_READY",
        intake_status="INTAKE_COMPLETE",
        integrity_status="VERIFIED",
        read_only_verified=staging.read_only_verified,
        notes=notes,
        created_by=actor_name,
        metadata_json={
            "staged_at": datetime.now(timezone.utc).isoformat(),
            "acquisition_type": acquisition_type,
            "detection_confidence": conf,
            "detection_signals": signals
        }
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    # 6. Record append-only hash-chained chain of custody events
    record_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=item.id,
        event_type="EVIDENCE_SELECTED",
        description=f"Evidence selected for intake: '{src_path.name}'",
        actor=actor_name,
        actor_id=actor_id,
        source_path=str(src_path)
    )

    record_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=item.id,
        event_type="EVIDENCE_VALIDATED",
        description=f"Pre-flight validation passed. Format detected: {detected_fmt}",
        actor=actor_name,
        actor_id=actor_id,
        source_path=str(src_path),
        metadata_json={"detected_format": detected_fmt, "magic_confidence": conf}
    )

    record_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=item.id,
        event_type="EVIDENCE_STORED",
        description=f"Stored in vault with OS read-only permissions at {staging.storage_path}",
        actor=actor_name,
        actor_id=actor_id,
        source_path=str(src_path),
        destination_path=staging.storage_path,
        sha256=staging.sha256,
        metadata_json={"read_only_verified": staging.read_only_verified, "size_bytes": staging.size_bytes}
    )

    record_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=item.id,
        event_type="EVIDENCE_INTEGRITY_VERIFIED",
        description=f"Independent vault SHA-256 hash verified: {staging.sha256}",
        actor=actor_name,
        actor_id=actor_id,
        sha256=staging.sha256
    )

    record_custody_event(
        db=db,
        case_id=case_id,
        evidence_id=item.id,
        event_type="EVIDENCE_READY",
        description=f"Evidence item '{item.name}' verified and marked ANALYSIS_READY.",
        actor=actor_name,
        actor_id=actor_id,
        sha256=staging.sha256
    )

    logger.info(f"Single file evidence intake complete: ID={item.id}, Name={item.name}, Hash={item.sha256[:16]}...")
    return item

def ingest_directory_evidence(
    db: Session,
    case_id: str,
    source_path: str,
    actor_id: str = "NOT_RECORDED",
    actor_name: str = "NOT_RECORDED",
    notes: Optional[str] = None
) -> Tuple[EvidenceAcquisition, Dict[str, Any]]:
    """
    Ingests an entire directory recursively:
    1. Validates source directory structure and limits.
    2. Creates an EvidenceAcquisition tracking record.
    3. Recursively ingests each file into the vault as an EvidenceItem linked via parent_acquisition_id.
    4. Constructs a comprehensive manifest JSON with SHA-256 for all ingested files.
    5. Saves and secures the manifest file.
    """
    is_valid, err_msg, stats = validate_acquisition_source(source_path, "DIRECTORY")
    if not is_valid:
        raise AcquisitionError(f"Pre-flight directory validation failed: {err_msg}")

    src_dir = Path(source_path).resolve()

    # Create acquisition record
    acq = EvidenceAcquisition(
        case_id=case_id,
        acquisition_type="DIRECTORY",
        source_path=str(src_dir),
        total_files=stats.get("total_files", 0),
        total_bytes=stats.get("total_bytes", 0),
        successful_files=0,
        failed_files=0,
        status="IN_PROGRESS",
        created_by_id=actor_id if "-" in actor_id and len(actor_id) == 36 else None
    )
    db.add(acq)
    db.commit()
    db.refresh(acq)

    manifest_files = []
    success_count = 0
    fail_count = 0
    processed_bytes = 0

    for root, dirs, files in os.walk(src_dir, followlinks=False):
        for f in files:
            file_path = Path(root) / f
            if file_path.is_symlink():
                continue
            
            rel_path = str(file_path.relative_to(src_dir))
            try:
                item = ingest_single_file_evidence(
                    db=db,
                    case_id=case_id,
                    source_path=str(file_path),
                    actor_id=actor_id,
                    actor_name=actor_name,
                    notes=f"Directory intake item from {rel_path}",
                    parent_acquisition_id=acq.id
                )
                success_count += 1
                processed_bytes += int(item.size_bytes)
                manifest_files.append({
                    "evidence_id": item.id,
                    "relative_path": rel_path,
                    "original_path": str(file_path),
                    "storage_path": item.storage_path,
                    "size_bytes": item.size_bytes,
                    "sha256": item.sha256,
                    "source_kind": item.source_kind,
                    "evidence_type": item.evidence_type,
                    "detected_format": item.detected_format,
                    "status": "VERIFIED"
                })
            except DuplicateEvidenceError as dup_err:
                # Same-case duplicate file inside directory: link existing item
                fail_count += 1
                existing = dup_err.existing_evidence
                manifest_files.append({
                    "evidence_id": existing.id,
                    "relative_path": rel_path,
                    "original_path": str(file_path),
                    "storage_path": existing.storage_path,
                    "size_bytes": existing.size_bytes,
                    "sha256": existing.sha256,
                    "source_kind": existing.source_kind,
                    "evidence_type": existing.evidence_type,
                    "detected_format": existing.detected_format,
                    "status": "DUPLICATE_SKIPPED"
                })
            except Exception as e:
                fail_count += 1
                logger.error(f"Failed to ingest directory file '{file_path}': {e}")
                manifest_files.append({
                    "relative_path": rel_path,
                    "original_path": str(file_path),
                    "error": str(e),
                    "status": "FAILED"
                })

    # Build manifest JSON and calculate manifest SHA-256
    manifest_data = {
        "acquisition_id": acq.id,
        "case_id": case_id,
        "source_path": str(src_dir),
        "total_files": stats.get("total_files", 0),
        "successful_files": success_count,
        "failed_files": fail_count,
        "total_bytes": processed_bytes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files
    }

    manifest_json_str = json.dumps(manifest_data, indent=2, sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_json_str.encode("utf-8")).hexdigest()

    # Save manifest.json in acquisitions directory
    acq_dir = settings.EVIDENCE_DIR / "vault" / case_id / "acquisitions" / acq.id
    acq_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = acq_dir / "manifest.json"

    with open(manifest_file, "w", encoding="utf-8") as mf:
        mf.write(manifest_json_str)

    apply_os_read_only(manifest_file)

    # Update acquisition status
    acq.manifest_hash = manifest_hash
    acq.successful_files = success_count
    acq.failed_files = fail_count
    acq.total_bytes = processed_bytes
    acq.status = "COMPLETED" if fail_count == 0 else ("PARTIAL" if success_count > 0 else "FAILED")
    db.commit()
    db.refresh(acq)

    logger.info(f"Directory evidence acquisition complete: ID={acq.id}, Total={stats['total_files']}, Success={success_count}, Fail={fail_count}, Manifest Hash={manifest_hash[:16]}...")
    return acq, manifest_data

