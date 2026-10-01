import hashlib
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from backend.app.core.config import settings
from backend.app.services.integrity import CHUNK_SIZE_8MB, calculate_sha256

@dataclass
class VaultStagingResult:
    storage_path: str
    original_path: str
    sha256: str
    size_bytes: int
    read_only_verified: bool

def sanitize_evidence_filename(filename: str) -> str:
    """
    Sanitizes evidence filename for secure, portable storage across POSIX and Windows.
    Preserves base extension while removing dangerous path traversal or shell characters.
    """
    name = Path(filename).name
    sanitized = re.sub(r"[^\w\.\-\_]", "_", name)
    return sanitized or "evidence.bin"

def get_vault_dir(case_id: str, evidence_id: str) -> Path:
    """
    Generates a secure, case-scoped, and collision-free vault directory for an evidence item.
    """
    # Strict validation of IDs as UUIDs/hex tokens to reject path traversal attempts
    safe_case = re.sub(r"[^\w\-]", "", str(case_id))
    safe_evidence = re.sub(r"[^\w\-]", "", str(evidence_id))
    return settings.EVIDENCE_DIR / "vault" / safe_case / safe_evidence

def apply_os_read_only(file_path: Path) -> bool:
    """
    Applies OS-level read-only protection to the vault copy.
    Linux/macOS: chmod 0o444 (read-only for all).
    Windows: Set FILE_ATTRIBUTE_READONLY and chmod S_IREAD.
    Returns True if successfully applied, False otherwise.
    """
    p = Path(file_path)
    if not p.exists():
        return False

    try:
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(p.resolve()), 0x01) # FILE_ATTRIBUTE_READONLY
            except Exception:
                pass
            os.chmod(p, stat.S_IREAD)
        else:
            # POSIX read-only (user, group, others read only)
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return True
    except Exception:
        return False

def remove_os_read_only(file_path: Path) -> bool:
    """
    Removes read-only protection (used during teardown/cleanup).
    """
    p = Path(file_path)
    if not p.exists():
        return False
    try:
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(p.resolve()), 0x80) # FILE_ATTRIBUTE_NORMAL
            except Exception:
                pass
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        else:
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        return True
    except Exception:
        return False

def verify_os_read_only(file_path: Path) -> bool:
    """
    Verifies whether write access to the file is actually denied by the host OS.
    """
    p = Path(file_path)
    if not p.exists():
        return False
    # If os.W_OK is False, write permission is denied
    return not os.access(p, os.W_OK)

def validate_vault_storage_path(storage_path: Optional[str], original_path: Optional[str]) -> Tuple[bool, str]:
    """
    Validates that storage_path meets strict forensic vault requirements:
    1. Must exist and not be empty.
    2. Must resolve to an existing regular file.
    3. Must NOT equal original_path (un-vaulted legacy fallback prohibited).
    4. Must reside inside the managed ADFIR evidence vault directory.
    Returns: (is_valid, error_message)
    """
    if not storage_path or not str(storage_path).strip():
        return False, "Evidence item lacks a vault storage_path. Analysis against un-vaulted evidence is prohibited. Evidence must be re-ingested into the managed forensic vault."

    target = Path(storage_path).resolve()
    if not target.exists() or not target.is_file():
        return False, f"Evidence vault file not found in storage: {storage_path}. Evidence must be re-ingested into the managed forensic vault."

    if original_path:
        orig = Path(original_path).resolve()
        if target == orig:
            return False, "Evidence storage_path equals original_path (un-vaulted legacy evidence). Direct analysis against original evidence is prohibited. Evidence must be re-ingested into the managed forensic vault."

    vault_base = (settings.EVIDENCE_DIR / "vault").resolve()
    if vault_base != target and vault_base not in target.parents:
        return False, f"Evidence storage_path '{storage_path}' is outside the managed evidence vault ({vault_base}). Evidence must be re-ingested into the managed forensic vault."

    return True, ""

def reverify_evidence_hash(evidence_path: str, expected_hash: str) -> Tuple[bool, str]:
    """
    Recalculates SHA-256 for an evidence file and compares with expected baseline hash.
    Returns: (is_valid, current_hash)
    """
    p = Path(evidence_path)
    if not p.exists() or not p.is_file():
        return False, ""
    current_hash, _ = calculate_sha256(str(p.resolve()))
    return (current_hash.lower() == expected_hash.strip().lower()), current_hash

def stage_evidence_to_vault(source_path: str, case_id: str, evidence_id: str) -> VaultStagingResult:
    """
    Safely copies an ingested evidence file into the case-scoped evidence vault:
    1. Verifies source file readability and accessibility.
    2. Checks free disk space on vault filesystem.
    3. Stream-copies source to a temporary part file while computing acquisition SHA-256.
    4. Flushes and closes temporary destination.
    5. Independently calculates SHA-256 by RE-READING the completed temporary vault file from disk.
    6. Reconciles source acquisition hash and independent vault disk hash.
    7. Verifies byte count.
    8. Atomically renames part file to final destination.
    9. Applies OS-level read-only permissions to the vault copy.
    10. Verifies actual OS read-only status.
    11. Rolls back and deletes any partial files on failure.
    """
    src = Path(source_path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Source evidence file does not exist: {source_path}")
    if not src.is_file():
        raise ValueError(f"Source evidence is not a regular file: {source_path}")
    if not os.access(src, os.R_OK):
        raise PermissionError(f"Source evidence is not readable: {source_path}")

    source_size = src.stat().st_size
    vault_dir = get_vault_dir(case_id, evidence_id)
    vault_dir.mkdir(parents=True, exist_ok=True)

    # Pre-flight disk space verification (source size + 10MB margin)
    try:
        free_space = shutil.disk_usage(vault_dir).free
        if free_space < (source_size + 10 * 1024 * 1024):
            raise IOError(f"Insufficient disk space in evidence vault. Required: {source_size}, Available: {free_space}")
    except Exception as e:
        if isinstance(e, IOError):
            raise
        # If disk_usage check is unsupported on a virtual mount, proceed with copy

    safe_name = sanitize_evidence_filename(src.name)
    target_path = vault_dir / safe_name
    temp_path = vault_dir / f".tmp_{evidence_id}.part"

    if temp_path.exists():
        temp_path.unlink(missing_ok=True)

    # If target already exists and is read-only, ensure we can overwrite or replace safely
    if target_path.exists():
        remove_os_read_only(target_path)
        target_path.unlink(missing_ok=True)

    source_hasher = hashlib.sha256()
    total_written = 0

    try:
        # Stream copy to temporary vault file and compute acquisition SHA-256 over bytes read
        with open(src, "rb") as f_src, open(temp_path, "wb") as f_dst:
            while chunk := f_src.read(CHUNK_SIZE_8MB):
                source_hasher.update(chunk)
                f_dst.write(chunk)
                total_written += len(chunk)

        src_hash = source_hasher.hexdigest()

        # Independently calculate SHA-256 by RE-READING the completed temporary vault file from disk
        vault_hasher = hashlib.sha256()
        vault_bytes_read = 0
        with open(temp_path, "rb") as f_vault:
            while chunk := f_vault.read(CHUNK_SIZE_8MB):
                vault_hasher.update(chunk)
                vault_bytes_read += len(chunk)

        dst_hash = vault_hasher.hexdigest()

        # Compare independent vault disk hash with source acquisition hash
        if src_hash.lower() != dst_hash.lower():
            temp_path.unlink(missing_ok=True)
            raise IOError(f"Cryptographic integrity verification failed during vault acquisition: source SHA-256 ({src_hash}) does not match independent vault disk SHA-256 ({dst_hash})")

        # Verify byte count
        if total_written != source_size or vault_bytes_read != source_size:
            temp_path.unlink(missing_ok=True)
            raise IOError(f"Evidence copy truncated: Expected {source_size} bytes, wrote {total_written} bytes, re-read {vault_bytes_read} bytes.")

        # Atomic move to final destination
        temp_path.replace(target_path)

        # Apply OS-level read-only protection
        apply_os_read_only(target_path)
        is_ro_verified = verify_os_read_only(target_path)

        return VaultStagingResult(
            storage_path=str(target_path.resolve()),
            original_path=str(src),
            sha256=src_hash,
            size_bytes=total_written,
            read_only_verified=is_ro_verified
        )
    except Exception:
        # Atomic cleanup on any copy/verification failure
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise

