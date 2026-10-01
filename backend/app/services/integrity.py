import hashlib
import os
from pathlib import Path
from typing import Dict, Any, Tuple

# 8 MiB streaming chunk size
CHUNK_SIZE_8MB = 8 * 1024 * 1024

def calculate_sha256(file_path: str) -> Tuple[str, int]:
    """
    Calculates SHA-256 hash using streaming reads in 8 MiB chunks.
    Ensures large forensic disk/memory images never exhaust RAM.
    Rejects nonexistent or inaccessible files.
    """
    path = Path(file_path).resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {file_path}")
    
    if not path.is_file():
        raise ValueError(f"Evidence path is not a regular file: {file_path}")
    
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Evidence file is not readable: {file_path}")

    hasher = hashlib.sha256()
    total_bytes = 0

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE_8MB):
            hasher.update(chunk)
            total_bytes += len(chunk)

    return hasher.hexdigest(), total_bytes

def verify_sha256(file_path: str, expected_hash: str) -> Dict[str, Any]:
    """
    Re-hashes the file and verifies cryptographic integrity against the expected hash.
    """
    actual_hash, _ = calculate_sha256(file_path)
    is_valid = (actual_hash.lower() == expected_hash.strip().lower())

    return {
        "valid": is_valid,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash
    }
