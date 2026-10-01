import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

class EvidenceIntegrityEngine:
    """
    Computes cryptographic hashes (SHA-256, MD5) and records verifiable chain of custody.
    Integrity is the absolute prerequisite before any agent or tool touches evidence.
    """

    @staticmethod
    def calculate_hashes(file_path: str, chunk_size: int = 65536) -> Tuple[str, str, int]:
        """
        Calculates SHA-256 and MD5 hashes in streaming chunks to support large disk/memory images.
        Returns: (sha256_hash, md5_hash, file_size_bytes)
        """
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        total_size = 0

        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
                md5.update(chunk)
                total_size += len(chunk)

        return sha256.hexdigest(), md5.hexdigest(), total_size

    @staticmethod
    def detect_evidence_type(file_path: str) -> str:
        """
        Infers evidence category from headers/extensions:
        - DISK_IMAGE (E01, raw, dd, img, vmdk, vhd)
        - MEMORY_DUMP (raw, dmp, vmem, crash)
        - NETWORK_PCAP (pcap, pcapng, cap)
        - LOG_FILE (evtx, log, json, syslog, csv)
        - BROWSER_DATA (sqlite, db, History, Places)
        """
        path = Path(file_path)
        ext = path.suffix.lower()
        name = path.name.lower()

        if ext in [".e01", ".dd", ".img", ".vmdk", ".vhd", ".qcow2"]:
            return "DISK_IMAGE"
        elif ext in [".dmp", ".vmem"] or ("mem" in name and ext in [".raw", ".bin"]):
            return "MEMORY_DUMP"
        elif ext in [".pcap", ".pcapng", ".cap"]:
            return "NETWORK_PCAP"
        elif ext in [".evtx", ".log", ".jsonl", ".audit"] or "syslog" in name:
            return "LOG_FILE"
        elif ext in [".sqlite", ".db"] or name in ["history", "cookies", "web data", "places.sqlite"]:
            return "BROWSER_DATA"
        elif ext in [".raw", ".bin"]:
            return "DISK_IMAGE"
        return "GENERIC_EVIDENCE"

    @staticmethod
    def create_custody_entry(action: str, actor: str, hash_val: str, notes: str = "") -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "actor": actor,
            "hash_snapshot": hash_val,
            "notes": notes
        }
