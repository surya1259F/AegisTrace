import os
import sys
import re
import math
import struct
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.models import EvidenceItem, EvidenceIntelligence, User
from backend.app.services.integrity import calculate_sha256
from backend.app.services.custody import record_custody_event
from forensic_tools.registry import tool_registry

ENGINE_VERSION = "1.0.0"

class ResourceProfile(BaseModel):
    estimated_input_size_bytes: int
    expected_cpu_class: str = "LOW" # LOW, MEDIUM, HIGH, VERY_HIGH
    expected_memory_class: str = "LOW" # LOW, MEDIUM, HIGH, VERY_HIGH
    expected_storage_class: str = "LOW" # LOW, MEDIUM, HIGH, VERY_HIGH
    expected_duration_class: str = "LOW" # LOW, MEDIUM, HIGH, VERY_HIGH
    parallelism_hint: str = "SINGLE_THREADED" # SINGLE_THREADED, MULTI_THREADED, BATCH
    risk_level: str = "LOW" # LOW, MEDIUM, HIGH

class ToolRecommendation(BaseModel):
    tool_id: str
    tool_name: str
    is_available: bool
    binary_path: Optional[str] = None
    tool_version: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    rationale: str

class AnalysisFamilyRecommendation(BaseModel):
    family_name: str
    status: str # RECOMMENDED, POSSIBLE, NOT_APPLICABLE, REQUIRES_TOOL
    rationale: str

class EvidenceTag(BaseModel):
    tag: str
    category: str # platform, format, filesystem, architecture, anomaly, characteristic
    basis: str

class PartitionInfo(BaseModel):
    partition_number: int
    partition_type: str
    filesystem: str
    start_sector: int
    size_sectors: int

class EvidenceIntelligencePayload(BaseModel):
    evidence_id: str
    evidence_name: str
    source_kind: str # FILE, DIRECTORY, DISK_IMAGE, MEMORY_DUMP, EVENT_LOG, BROWSER_DB, ARCHIVE, MALWARE_SAMPLE, GENERIC_BINARY, UNKNOWN
    evidence_type: str # DISK_IMAGE, MEMORY_DUMP, WINDOWS_EVENT_LOG, REGISTRY_HIVE, SQLITE_DATABASE, BROWSER_ARTIFACT, PE_EXECUTABLE, ELF_EXECUTABLE, ARCHIVE, DOCUMENT, IMAGE, TEXT, GENERIC_BINARY, UNKNOWN
    source_kind: str
    classification: str
    evidence_type: Optional[str] = None
    subtype: Optional[str] = None
    evidence_subtype: Optional[str] = None
    classification_status: str = "MATCH" # MATCH, MISMATCH, UNKNOWN, PARTIAL
    classification_confidence: str = "DETERMINISTIC" # DETERMINISTIC, HIGH, MEDIUM, LOW, UNKNOWN
    classification_basis: str = ""
    detected_format: str = "UNKNOWN"
    detected_mime: str = "application/octet-stream"
    confidence: float = 0.0
    platform_hint: str = "UNKNOWN"
    platform_basis: str = ""
    platform_confidence: str = "UNKNOWN"
    architecture_hint: str = "UNKNOWN"
    filesystem_type: str = "UNKNOWN"
    platform_hint: str = "UNKNOWN"
    filesystem_version: Optional[str] = None
    filesystem_basis: str = ""
    filesystem_detection_status: str = "NOT_PRESENT"
    partition_table_type: str = "NONE"
    partitions: List[PartitionInfo] = Field(default_factory=list)
    size_bytes: int = 0
    characteristics: List[str] = Field(default_factory=list)
    detection_methods: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[EvidenceTag] = Field(default_factory=list)
    recommended_analysis_families: List[AnalysisFamilyRecommendation] = Field(default_factory=list)
    recommended_tools: List[ToolRecommendation] = Field(default_factory=list)
    resource_profile: ResourceProfile
    limitations: List[str] = Field(default_factory=list)
    engine_version: str = ENGINE_VERSION
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @model_validator(mode="after")
    def sync_aliases(self):
        if not self.evidence_type and self.classification:
            self.evidence_type = self.classification
        elif not self.classification and self.evidence_type:
            self.classification = self.evidence_type
        if not self.evidence_subtype and self.subtype:
            self.evidence_subtype = self.subtype
        elif not self.subtype and self.evidence_subtype:
            self.subtype = self.evidence_subtype
        return self

class EvidenceIntelligenceEngine:
    """
    Deterministic Evidence Intelligence Subsystem.
    Given an evidence item and path, performs deterministic multi-signal header inspection,
    classifies evidence characteristics, maps available forensic tools from the registry,
    recommends analysis families, and builds resource profiles for scheduling.
    detects extension mismatches, filesystem & partition structures, maps available forensic tools,
    recommends analysis families, generates structured tags, and builds resource profiles.
    """

    @staticmethod
    def inspect_magic_header(file_path: Path) -> Tuple[str, str, Optional[str], str, float, List[Dict[str, Any]]]:
        """
        Reads initial header bytes to perform deterministic magic signature inspection.
        Returns: (source_kind, evidence_type, evidence_subtype, detected_format, confidence, detection_signals)
        Maintains backward compatibility with all existing calls.
        """
        signals = []
        if not file_path.exists() or not file_path.is_file():
            return "UNKNOWN", "UNKNOWN", None, "FILE_NOT_FOUND", 0.0, [{"method": "filesystem_check", "signal": "file_not_found", "confidence": 0.0}]

        size = file_path.stat().st_size
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        # Read first 8192 bytes for magic signature matching
        header_bytes = b""
        try:
            with open(file_path, "rb") as f:
                header_bytes = f.read(8192)
        except Exception as e:
            return "UNKNOWN", "UNKNOWN", None, f"READ_ERROR: {e}", 0.0, [{"method": "header_read", "signal": str(e), "confidence": 0.0}]

        # 1. Windows Event Log V2 (.evtx magic: ElfFile\x00)
        if header_bytes.startswith(b"ElfFile\x00"):
            signals.append({"method": "magic_bytes", "signal": "ElfFile\\x00 (EVTX Header)", "confidence": 1.0})
            return "EVENT_LOG", "WINDOWS_EVENT_LOG", "evtx", "WINDOWS_EVENT_LOG_V2", 1.0, signals

        # 2. SQLite Database (magic: SQLite format 3\x00)
        if header_bytes.startswith(b"SQLite format 3\x00"):
            is_browser = any(k in name for k in ["history", "cookies", "web data", "places.sqlite", "favicons", "top_sites", "login data"])
            ev_type = "BROWSER_ARTIFACT" if is_browser else "SQLITE_DATABASE"
            ev_subtype = "browser_db" if is_browser else "sqlite3"
            src_kind = "BROWSER_DB" if is_browser else "FILE"
            fmt = "SQLITE_V3_BROWSER_DB" if is_browser else "SQLITE_V3_DATABASE"
            signals.append({"method": "magic_bytes", "signal": "SQLite format 3\\x00", "confidence": 1.0})
            return src_kind, ev_type, ev_subtype, fmt, 1.0, signals

        # 3. PE Executable / DLL (magic: MZ)
        if header_bytes.startswith(b"MZ"):
            pe_fmt = "PE32_EXECUTABLE"
            if len(header_bytes) >= 0x40:
                pe_offset = int.from_bytes(header_bytes[0x3c:0x40], "little")
                if len(header_bytes) >= pe_offset + 24 and header_bytes[pe_offset:pe_offset+4] == b"PE\x00\x00":
                    machine = int.from_bytes(header_bytes[pe_offset+4:pe_offset+6], "little")
                    if machine in [0x8664, 0xaa64]:
                        pe_fmt = "PE32_EXECUTABLE" if machine == 0x014c else ("PE64_EXECUTABLE" if machine == 0x8664 else "PE_ARM64_EXECUTABLE")

            signals.append({"method": "magic_bytes", "signal": "MZ (DOS/PE Header)", "confidence": 0.95})
            return "MALWARE_SAMPLE", "PE_EXECUTABLE", "pe32", pe_fmt, 0.95, signals

        # 4. ELF Executable (magic: \x7fELF)
        if header_bytes.startswith(b"\x7fELF"):
            if len(header_bytes) >= 5 and header_bytes[4] == 2:
                elf_fmt = "ELF64_EXECUTABLE"
            elif len(header_bytes) >= 5 and header_bytes[4] == 1:
                elf_fmt = "ELF32_EXECUTABLE"
            else:
                elf_fmt = "ELF_EXECUTABLE"
            signals.append({"method": "magic_bytes", "signal": "\\x7fELF (ELF Binary Header)", "confidence": 0.95})
            return "MALWARE_SAMPLE", "ELF_EXECUTABLE", "elf", elf_fmt, 0.95, signals

        # 5. Zip Container / Office OpenXML / JAR (magic: PK\x03\x04)
        # 5. Mach-O Executable
        if header_bytes[:4] in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]:
            signals.append({"method": "magic_bytes", "signal": "Mach-O Binary Header", "confidence": 0.95})
            return "MALWARE_SAMPLE", "MACHO_EXECUTABLE", "macho", "MACHO_BINARY", 0.95, signals

        # 6. Zip Container (magic: PK\x03\x04)
        if header_bytes.startswith(b"PK\x03\x04"):
            signals.append({"method": "magic_bytes", "signal": "PK\\x03\\x04 (Zip Container)", "confidence": 0.9})
            return "ARCHIVE", "ARCHIVE", "zip", "ZIP_CONTAINER", 0.9, signals

        # 6. 7z Container (magic: \x37\x7a\xbc\xaf\x27\x1c)
        # 7. 7z Container
        if header_bytes.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
            signals.append({"method": "magic_bytes", "signal": "\\x37\\x7a\\xbc\\xaf (7z Container)", "confidence": 0.95})
            return "ARCHIVE", "ARCHIVE", "7z", "7Z_CONTAINER", 0.95, signals

        # 7. Gzip Container (magic: \x1f\x8b)
        # 8. Gzip Container
        if header_bytes.startswith(b"\x1f\x8b"):
            signals.append({"method": "magic_bytes", "signal": "\\x1f\\x8b (Gzip Container)", "confidence": 0.9})
            return "ARCHIVE", "ARCHIVE", "gzip", "GZIP_CONTAINER", 0.9, signals

        # 8. PDF Document (magic: %PDF)
        # 9. PDF Document
        if header_bytes.startswith(b"%PDF"):
            signals.append({"method": "magic_bytes", "signal": "%PDF (Adobe PDF Document)", "confidence": 0.95})
            return "FILE", "DOCUMENT", "pdf", "PDF_DOCUMENT", 0.95, signals

        # 9. PNG Image (magic: \x89PNG)
        # 10. PNG Image
        if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            signals.append({"method": "magic_bytes", "signal": "\\x89PNG (PNG Image)", "confidence": 0.95})
            return "FILE", "IMAGE", "png", "PNG_IMAGE", 0.95, signals

        # 10. JPEG Image (magic: \xff\xd8\xff)
        # 11. JPEG Image
        if header_bytes.startswith(b"\xff\xd8\xff"):
            signals.append({"method": "magic_bytes", "signal": "\\xff\\xd8\\xff (JPEG Image)", "confidence": 0.95})
            return "FILE", "IMAGE", "jpeg", "JPEG_IMAGE", 0.95, signals

        # 11. EnCase Expert Witness Image
        if header_bytes.startswith(b"EVF") or header_bytes.startswith(b"PAR1") or header_bytes.startswith(b"LVF"):
            signals.append({"method": "magic_bytes", "signal": "E01 Forensic Disk Image Header", "confidence": 0.95})
            return "DISK_IMAGE", "DISK_IMAGE", "e01", "E01_EXPERT_WITNESS", 0.95, signals

        # 12. Windows Minidump (magic: MDMP / \x4d\x44\x4d\x50)
        # 13. Windows Registry Hive
        if header_bytes.startswith(b"regf"):
            signals.append({"method": "magic_bytes", "signal": "regf (Windows Registry Hive)", "confidence": 1.0})
            return "FILE", "REGISTRY_HIVE", "registry", "WINDOWS_REGISTRY_HIVE", 1.0, signals

        # 14. Windows Minidump
        if header_bytes.startswith(b"MDMP"):
            signals.append({"method": "magic_bytes", "signal": "MDMP (Windows Minidump Header)", "confidence": 0.95})
            return "MEMORY_DUMP", "MEMORY_DUMP", "minidump", "WINDOWS_MINIDUMP", 0.95, signals

        # ---------------------------------------------------------------------
        # Fallback Extension & Size Heuristics when magic bytes are non-standard
        # ---------------------------------------------------------------------
        # 15. PCAP Captures
        if header_bytes[:4] in [b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"] or header_bytes.startswith(b"\x0a\x0d\x0d\x0a"):
            fmt = "PCAPNG_NETWORK_CAPTURE" if header_bytes.startswith(b"\x0a\x0d\x0d\x0a") else "PCAP_NETWORK_CAPTURE"
            signals.append({"method": "magic_bytes", "signal": "PCAP/PCAPNG Header", "confidence": 1.0})
            return "FILE", "PCAP_CAPTURE", "pcap", fmt, 1.0, signals

        # Fallback Extension & Size Heuristics
        if ext in [".e01", ".dd", ".img", ".vmdk", ".vhd", ".qcow2"]:
            signals.append({"method": "filename_extension", "signal": f"Extension {ext}", "confidence": 0.8})
            return "DISK_IMAGE", "DISK_IMAGE", ext.lstrip("."), f"{ext.lstrip('.').upper()}_DISK_IMAGE", 0.8, signals

        if ext in [".exe", ".dll", ".sys", ".elf", ".pe"]:
            signals.append({"method": "filename_extension", "signal": f"Executable extension {ext}", "confidence": 0.8})
            return "MALWARE_SAMPLE", "EXECUTABLE", ext.lstrip("."), "PE_EXECUTABLE", 0.8, signals
            return "MALWARE_SAMPLE", "PE_EXECUTABLE" if ext in [".exe", ".dll", ".sys", ".pe"] else "ELF_EXECUTABLE", ext.lstrip("."), "PE_EXECUTABLE", 0.8, signals

        if ext in [".dmp", ".vmem", ".raw"] or ("mem" in name and ext in [".raw", ".bin"]):
            signals.append({"method": "filename_heuristics", "signal": f"Name/Ext pattern '{name}'", "confidence": 0.75})
            return "MEMORY_DUMP", "MEMORY_DUMP", ext.lstrip("."), "RAW_MEMORY_DUMP", 0.75, signals

        if ext in [".log", ".evtx"] or "log" in name:
            signals.append({"method": "filename_extension", "signal": f"Log extension {ext}", "confidence": 0.7})
            return "EVENT_LOG", "LOG", "text_log", "PLAINTEXT_LOG", 0.7, signals

        # Check if printable text file
        # Printable Text Check
        sample = header_bytes[:512]
        if sample:
            non_printable = sum(1 for b in sample if b < 9 or (b > 13 and b < 32) or b == 127)
            if (non_printable / len(sample)) < 0.05:
                signals.append({"method": "text_ascii_scan", "signal": "High ASCII/UTF-8 ratio", "confidence": 0.6})
                return "FILE", "TEXT", "plaintext", "PLAINTEXT_FILE", 0.6, signals

        # Generic Binary Stream (No matching header or extension)
        signals.append({"method": "header_scan", "signal": "No recognized magic signature or extension match", "confidence": 0.2})
        return "UNKNOWN", "UNKNOWN", None, "UNKNOWN_BINARY_STREAM", 0.2, signals

    @classmethod
    def analyze_evidence(cls, evidence_id: str, evidence_name: str, file_path: str) -> EvidenceIntelligencePayload:
        p = Path(file_path).resolve()
        return cls._analyze_evidence_legacy(evidence_id, evidence_name, p)

    @classmethod
    def _analyze_evidence_legacy(cls, evidence_id: str, evidence_name: str, p: Path) -> EvidenceIntelligencePayload:
        source_kind, classification, subtype, detected_format, conf_num, detection_methods = cls.inspect_magic_header(p)
        return cls._build_evidence_payload(evidence_id, evidence_name, p, source_kind, classification, subtype, detected_format, conf_num, detection_methods)

    @classmethod
    def _build_evidence_payload(cls, evidence_id: str, evidence_name: str, p: Path, source_kind: str, classification: str, subtype: Optional[str], detected_format: str, conf_num: float, detection_methods: List[Dict[str, Any]]) -> EvidenceIntelligencePayload:
        return cls._analyze_evidence_payload(evidence_id, evidence_name, p, source_kind, classification, subtype, detected_format, conf_num, detection_methods)

    @classmethod
    def _analyze_evidence_payload(cls, evidence_id: str, evidence_name: str, p: Path, source_kind: str, classification: str, subtype: Optional[str], detected_format: str, conf_num: float, detection_methods: List[Dict[str, Any]]) -> EvidenceIntelligencePayload:
        return cls.analyze_evidence(evidence_id, evidence_name, str(p))

    @classmethod
    def inspect_full_profile(cls, file_path: Path, classification: str, subtype: Optional[str], detected_format: str, confidence_num: float) -> Tuple[
        str, # classification_status
        str, # classification_confidence
        str, # classification_basis
        str, # detected_mime
        str, # platform_hint
        str, # platform_basis
        str, # platform_confidence
        str, # architecture_hint
        str, # filesystem_type
        Optional[str], # filesystem_version
        str, # filesystem_basis
        str, # filesystem_detection_status
        str, # partition_table_type
        List[PartitionInfo], # partitions
        List[str], # characteristics
        Dict[str, Any], # metadata
        List[EvidenceTag] # tags
    ]:
        characteristics = []
        tags = []
        metadata = {}

        src_kind, ev_type, ev_subtype, fmt, conf, signals = cls.inspect_magic_header(file_path)
        ext = file_path.suffix.lower()
        name = file_path.name.lower()
        size_bytes = file_path.stat().st_size if file_path.exists() and file_path.is_file() else 0

        # Platform hint inference
        platform_hint = "UNKNOWN"
        if ev_type in ["WINDOWS_EVENT_LOG", "REGISTRY_HIVE", "WINDOWS_MINIDUMP"]:
            platform_hint = "WINDOWS"
        elif ev_type == "PE_EXECUTABLE":
            platform_hint = "WINDOWS"
        elif ev_type == "ELF_EXECUTABLE":
            platform_hint = "LINUX"
        if classification in ["PE_EXECUTABLE", "ELF_EXECUTABLE", "MACHO_EXECUTABLE"]:
            characteristics.append("EXECUTABLE_BINARY")

        # MIME type resolution
        mime_type, _ = mimetypes.guess_type(file_path.name)
        if not mime_type:
            mime_type = "application/octet-stream"

        # Characteristics extraction
        if size_bytes > 100 * 1024 * 1024:
            characteristics.append("LARGE_FILE")
        if size_bytes > 1 * 1024 * 1024 * 1024:
            characteristics.append("VERY_LARGE_FILE")
        if conf >= 0.9:
            characteristics.append("HIGH_CONFIDENCE_HEADER")
        if ev_type != "UNKNOWN":
            characteristics.append(f"TYPE_{ev_type}")

        # Resource Profile Generation
        res_profile = cls.calculate_resource_profile(size_bytes, ev_type)
        header_bytes = b""
        if file_path.exists() and file_path.is_file():
            try:
                with open(file_path, "rb") as f:
                    header_bytes = f.read(8192)
            except Exception:
                pass

        # Forensic Tool Mapping via ToolRegistry
        recommended_tools = cls.map_recommended_tools(ev_type, src_kind, str(file_path))
        # Platform & Architecture hints
        platform_hint = "UNKNOWN"
        platform_basis = ""
        platform_confidence = "UNKNOWN"
        arch_hint = "UNKNOWN"

        # Analysis Family Mapping
        analysis_families = cls.map_analysis_families(ev_type, src_kind, recommended_tools)
        if classification in ["WINDOWS_EVENT_LOG", "REGISTRY_HIVE", "MINIDUMP", "PE_EXECUTABLE"]:
            platform_hint = "WINDOWS"
            platform_basis = f"{classification} header detected"
            platform_confidence = "DETERMINISTIC" if confidence_num >= 0.9 else "HIGH"
            if classification == "PE_EXECUTABLE" and len(header_bytes) >= 0x40:
                pe_offset = int.from_bytes(header_bytes[0x3c:0x40], "little")
                if len(header_bytes) >= pe_offset + 6 and header_bytes[pe_offset:pe_offset+4] == b"PE\x00\x00":
                    machine = int.from_bytes(header_bytes[pe_offset+4:pe_offset+6], "little")
                    arch_hint = "x86_64" if machine == 0x8664 else ("ARM64" if machine == 0xaa64 else "x86")
        elif classification in ["ELF_EXECUTABLE"]:
            platform_hint = "LINUX"
            platform_basis = "ELF binary header detected"
            platform_confidence = "DETERMINISTIC"
            if len(header_bytes) >= 20:
                machine_code = int.from_bytes(header_bytes[18:20], "little")
                arch_hint = "x86_64" if machine_code == 0x3E else ("ARM64" if machine_code == 0xB7 else ("ARM" if machine_code == 0x28 else "x86"))
        elif classification in ["MACHO_EXECUTABLE"]:
            platform_hint = "MACOS"
            platform_basis = "Mach-O binary header detected"
            platform_confidence = "DETERMINISTIC"
            arch_hint = "x86_64" if header_bytes[:4] in [b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"] else "ARM64"

        # Limitations
        limitations = []
        if ev_type == "UNKNOWN" or conf < 0.5:
            limitations.append("Low confidence classification: evidence format could not be verified deterministically from headers.")
        if not any(t.is_available for t in recommended_tools):
            limitations.append("No registered forensic tools are currently available on this host system for this evidence classification.")

        # MIME resolution
        detected_mime, _ = mimetypes.guess_type(name)
        if not detected_mime:
            detected_mime = "application/octet-stream"

        # Filesystem & Partition Table Detection
        filesystem_type = "UNKNOWN"
        filesystem_version = None
        filesystem_basis = ""
        filesystem_detection_status = "NOT_PRESENT"
        partition_table_type = "NONE"
        partitions: List[PartitionInfo] = []

        if len(header_bytes) >= 11 and header_bytes[3:11] == b"NTFS    ":
            filesystem_type = "NTFS"
            filesystem_basis = "NTFS OEM ID detected at offset 0x03"
            filesystem_detection_status = "DETECTED"
            platform_hint = platform_hint if platform_hint != "UNKNOWN" else "WINDOWS"
            characteristics.append("NTFS_FILESYSTEM")

        elif len(header_bytes) >= 59 and (b"FAT12" in header_bytes[0x36:0x40] or b"FAT16" in header_bytes[0x36:0x40] or b"FAT32" in header_bytes[0x52:0x5c]):
            filesystem_type = "FAT32"
            filesystem_basis = "FAT volume boot sector signature detected"
            filesystem_detection_status = "DETECTED"
            characteristics.append("FAT_FILESYSTEM")

        elif len(header_bytes) >= 1082 and header_bytes[1080:1082] == b"\x53\xef":
            filesystem_type = "EXT4"
            filesystem_basis = "Linux ext4 superblock magic 0xEF53 detected"
            filesystem_detection_status = "DETECTED"
            platform_hint = platform_hint if platform_hint != "UNKNOWN" else "LINUX"
            characteristics.append("EXT4_FILESYSTEM")

        if len(header_bytes) >= 512 and header_bytes[510:512] == b"\x55\xaa":
            partition_table_type = "MBR"
            if len(header_bytes) >= 1024 and header_bytes[512:520] == b"EFI PART":
                partition_table_type = "GPT"
                characteristics.append("GPT_PARTITION_TABLE")
            else:
                characteristics.append("MBR_PARTITION_TABLE")

            for idx, p_offset in enumerate([446, 462, 478, 494], start=1):
                p_entry = header_bytes[p_offset:p_offset+16]
                p_type = p_entry[4]
                if p_type != 0:
                    start_sec = int.from_bytes(p_entry[8:12], "little")
                    size_sec = int.from_bytes(p_entry[12:16], "little")
                    fs_name = "NTFS/exFAT" if p_type in [0x07, 0x0E] else ("EXT4" if p_type == 0x83 else "UNKNOWN")
                    partitions.append(PartitionInfo(
                        partition_number=idx,
                        partition_type=f"0x{p_type:02X}",
                        filesystem=fs_name,
                        start_sector=start_sec,
                        size_sectors=size_sec
                    ))

        # Format Mismatch Evaluation
        classification_status = "MATCH"
        classification_confidence = "DETERMINISTIC" if confidence_num >= 0.9 else ("HIGH" if confidence_num >= 0.7 else "MEDIUM")
        classification_basis = f"Declared extension '{ext}' matches detected format '{detected_format}'."

        mismatch_rules = {
            ".evtx": ["WINDOWS_EVENT_LOG"],
            ".sqlite": ["SQLITE_DATABASE", "BROWSER_ARTIFACT"],
            ".db": ["SQLITE_DATABASE", "BROWSER_ARTIFACT"],
            ".exe": ["PE_EXECUTABLE"],
            ".dll": ["PE_EXECUTABLE"],
            ".elf": ["ELF_EXECUTABLE"],
            ".so": ["ELF_EXECUTABLE"],
            ".pdf": ["DOCUMENT"],
            ".png": ["IMAGE"],
            ".jpg": ["IMAGE"],
            ".pcap": ["PCAP_CAPTURE"],
            ".pcapng": ["PCAP_CAPTURE"],
            ".hive": ["REGISTRY_HIVE"],
            ".dmp": ["MINIDUMP", "MEMORY_DUMP"],
            ".zip": ["ARCHIVE"],
        }

        if ext in mismatch_rules:
            expected_classifications = mismatch_rules[ext]
            if classification not in expected_classifications and classification not in ["UNKNOWN", "GENERIC_BINARY"]:
                classification_status = "MISMATCH"
                classification_confidence = "HIGH"
                classification_basis = f"EXTENSION MISMATCH ALERT: File extension '{ext}' conflicts with detected magic header signature '{detected_format}' ({classification})."
                characteristics.append("EXTENSION_MISMATCH_ALERT")
                tags.append(EvidenceTag(tag="extension_mismatch", category="anomaly", basis=classification_basis))

        # Structured Tagging
        if platform_hint != "UNKNOWN":
            tags.append(EvidenceTag(tag=platform_hint.lower(), category="platform", basis=platform_basis or "Platform heuristic"))
        if arch_hint != "UNKNOWN":
            tags.append(EvidenceTag(tag=arch_hint.lower(), category="architecture", basis=f"Binary machine architecture: {arch_hint}"))
        if filesystem_type != "UNKNOWN":
            tags.append(EvidenceTag(tag=filesystem_type.lower(), category="filesystem", basis=filesystem_basis))
        if classification != "UNKNOWN":
            tags.append(EvidenceTag(tag=classification.lower(), category="format", basis=f"Format detection: {detected_format}"))
        if subtype:
            tags.append(EvidenceTag(tag=subtype.lower(), category="subtype", basis=f"Subtype: {subtype}"))

        return (
            classification_status,
            classification_confidence,
            classification_basis,
            detected_mime,
            platform_hint,
            platform_basis,
            platform_confidence,
            arch_hint,
            filesystem_type,
            filesystem_version,
            filesystem_basis,
            filesystem_detection_status,
            partition_table_type,
            partitions,
            characteristics,
            metadata,
            tags
        )

    @classmethod
    def calculate_resource_profile(cls, size_bytes: int, classification: str) -> ResourceProfile:
        size_mb = size_bytes / (1024 * 1024)

        if size_mb < 10:
            return ResourceProfile(
                estimated_input_size_bytes=size_bytes,
                expected_cpu_class="LOW",
                expected_memory_class="LOW",
                expected_storage_class="LOW",
                expected_duration_class="LOW",
                parallelism_hint="SINGLE_THREADED",
                risk_level="LOW"
            )
        elif size_mb < 500:
            return ResourceProfile(
                estimated_input_size_bytes=size_bytes,
                expected_cpu_class="MEDIUM",
                expected_memory_class="MEDIUM",
                expected_storage_class="MEDIUM",
                expected_duration_class="MEDIUM",
                parallelism_hint="MULTI_THREADED" if classification == "DISK_IMAGE" else "SINGLE_THREADED",
                risk_level="LOW"
            )
        elif size_mb < 4096:
            return ResourceProfile(
                estimated_input_size_bytes=size_bytes,
                expected_cpu_class="HIGH",
                expected_memory_class="HIGH",
                expected_storage_class="HIGH",
                expected_duration_class="HIGH",
                parallelism_hint="MULTI_THREADED",
                risk_level="MEDIUM"
            )
        else:
            return ResourceProfile(
                estimated_input_size_bytes=size_bytes,
                expected_cpu_class="VERY_HIGH",
                expected_memory_class="VERY_HIGH",
                expected_storage_class="VERY_HIGH",
                expected_duration_class="VERY_HIGH",
                parallelism_hint="MULTI_THREADED",
                risk_level="HIGH"
            )

    def map_recommended_tools(classification: str, source_kind: str, file_path: str) -> List[ToolRecommendation]:
        recommendations: List[ToolRecommendation] = []

        tool_candidates = []
        if classification == "DISK_IMAGE":
            tool_candidates.append(("sleuthkit", "SleuthKit (fls)", "File system structures and volume analysis."))
        elif classification in ["MEMORY_DUMP", "MINIDUMP"]:
            tool_candidates.append(("volatility3", "Volatility 3", "Memory forensics process enumeration and artifact extraction."))
        elif classification in ["PE_EXECUTABLE", "ELF_EXECUTABLE", "MACHO_EXECUTABLE"]:
            tool_candidates.append(("yara", "YARA Pattern Matcher", "Malware signature rules scanning."))
            tool_candidates.append(("exiftool", "ExifTool", "Binary metadata and header extraction."))
        elif classification == "WINDOWS_EVENT_LOG":
            tool_candidates.append(("python-evtx", "python-evtx Log Parser", "Windows Event Log record parsing."))
        elif classification in ["IMAGE", "DOCUMENT", "ARCHIVE", "TEXT", "GENERIC_BINARY"]:
            tool_candidates.append(("exiftool", "ExifTool", "File metadata and embedded properties extraction."))
            tool_candidates.append(("yara", "YARA Pattern Matcher", "Pattern matching and string signature scanning."))

        for tool_id, display_name, rationale in tool_candidates:
            tool_def = tool_registry.get_tool(tool_id)
            is_avail = tool_def.is_available if tool_def else False
            path_val = tool_def.path if tool_def else None
            ver_val = tool_def.version if tool_def else None
            caps = tool_def.capabilities if tool_def else []

            recommendations.append(ToolRecommendation(
                tool_id=tool_id,
                tool_name=display_name,
                is_available=is_avail,
                binary_path=path_val,
                tool_version=ver_val,
                capabilities=caps,
                rationale=rationale if is_avail else f"{rationale} (Tool not available on host system)"
            ))

        return recommendations

    def map_analysis_families(classification: str, source_kind: str, recommended_tools: List[ToolRecommendation]) -> List[AnalysisFamilyRecommendation]:
        families: List[AnalysisFamilyRecommendation] = []
        avail_tools = {t.tool_id for t in recommended_tools if t.is_available}

        if classification == "DISK_IMAGE":
            status_val = "RECOMMENDED" if "sleuthkit" in avail_tools else "REQUIRES_TOOL"
            families.append(AnalysisFamilyRecommendation(
                family_name="FILE_SYSTEM_ANALYSIS",
                status=status_val,
                rationale="Disk image contains volume structures suitable for filesystem parsing."
            ))
        elif classification in ["MEMORY_DUMP", "MINIDUMP"]:
            status_val = "RECOMMENDED" if "volatility3" in avail_tools else "REQUIRES_TOOL"
            families.append(AnalysisFamilyRecommendation(
                family_name="MEMORY_ANALYSIS",
                status=status_val,
                rationale="RAM memory dump suitable for process enumeration and kernel analysis."
            ))
        elif classification in ["PE_EXECUTABLE", "ELF_EXECUTABLE", "MACHO_EXECUTABLE"]:
            status_val = "RECOMMENDED" if "yara" in avail_tools else "POSSIBLE"
            families.append(AnalysisFamilyRecommendation(
                family_name="MALWARE_ANALYSIS",
                status=status_val,
                rationale="Executable binary file suitable for signature scanning and static disassembly."
            ))
        elif classification == "WINDOWS_EVENT_LOG":
            status_val = "RECOMMENDED" if "python-evtx" in avail_tools else "REQUIRES_TOOL"
            families.append(AnalysisFamilyRecommendation(
                family_name="EVENT_LOG_ANALYSIS",
                status=status_val,
                rationale="Windows Event Log file suitable for security event record extraction."
            ))
        elif classification in ["IMAGE", "DOCUMENT"]:
            status_val = "RECOMMENDED" if "exiftool" in avail_tools else "POSSIBLE"
            families.append(AnalysisFamilyRecommendation(
                family_name="METADATA_ANALYSIS",
                status=status_val,
                rationale="Digital media/document file suitable for EXIF and document property parsing."
            ))

        # Always include HASH_ANALYSIS and STRING_ANALYSIS as universal families
        families.append(AnalysisFamilyRecommendation(
            family_name="HASH_ANALYSIS",
            status="RECOMMENDED",
            rationale="Cryptographic hashing (SHA-256) is universally applicable to all evidence items."
        ))
        families.append(AnalysisFamilyRecommendation(
            family_name="STRING_ANALYSIS",
            status="POSSIBLE",
            rationale="Static string extraction is applicable for artifact identification."
        ))

        return families

    @classmethod
    def verify_integrity_gate(cls, db: Session, evidence: EvidenceItem, current_user: User) -> str:
        target_path = evidence.storage_path or evidence.original_path
        if not target_path or not os.path.exists(target_path):
            evidence.integrity_status = "MISSING"
            evidence.status = "INTEGRITY_WARNING"
            evidence.error_message = f"Preserved file missing at path: {target_path}"
            db.commit()

            record_custody_event(
                db=db,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                event_type="EVIDENCE_INTELLIGENCE_INTEGRITY_BLOCKED",
                actor=current_user.name or current_user.email,
                actor_id=current_user.id,
                description=f"CRITICAL: Evidence Intelligence generation BLOCKED: Vault file missing at path: {target_path}",
                sha256=evidence.sha256
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Evidence Intelligence blocked: Preserved file missing at path: {target_path}"
            )

        current_sha256, _ = calculate_sha256(target_path)
        if current_sha256.lower() != evidence.sha256.lower():
            evidence.integrity_status = "INTEGRITY_MISMATCH"
            evidence.status = "INTEGRITY_WARNING"
            evidence.error_message = f"Integrity mismatch! Baseline: {evidence.sha256}, Actual: {current_sha256}"
            db.commit()

            record_custody_event(
                db=db,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                event_type="EVIDENCE_INTELLIGENCE_INTEGRITY_BLOCKED",
                actor=current_user.name or current_user.email,
                actor_id=current_user.id,
                description=f"CRITICAL: Evidence Intelligence generation BLOCKED due to cryptographic hash mismatch! Expected: {evidence.sha256}, Actual: {current_sha256}",
                destination_path=target_path,
                sha256=current_sha256
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Evidence Intelligence blocked due to cryptographic hash mismatch! Expected: {evidence.sha256}, Actual: {current_sha256}"
            )

        return target_path

    @classmethod
    def analyze_and_store_profile(cls, db: Session, evidence: EvidenceItem, current_user: User, force_refresh: bool = False) -> EvidenceIntelligence:
        target_path = cls.verify_integrity_gate(db, evidence, current_user)
        p = Path(target_path)

        existing_profile = db.query(EvidenceIntelligence).filter(EvidenceIntelligence.evidence_id == evidence.id).first()
        if existing_profile and not force_refresh:
            return existing_profile

        source_kind, classification, subtype, detected_format, conf_num, detection_methods = cls.inspect_magic_header(p)
        (
            classification_status,
            classification_confidence,
            classification_basis,
            detected_mime,
            platform_hint,
            platform_basis,
            platform_confidence,
            architecture_hint,
            filesystem_type,
            filesystem_version,
            filesystem_basis,
            filesystem_detection_status,
            partition_table_type,
            partitions,
            characteristics,
            metadata,
            tags
        ) = cls.inspect_full_profile(p, classification, subtype, detected_format, conf_num)

        size_bytes = p.stat().st_size if p.exists() else 0

        res_profile = cls.calculate_resource_profile(size_bytes, classification)
        recommended_tools = cls.map_recommended_tools(classification, source_kind, str(p))
        analysis_families = cls.map_analysis_families(classification, source_kind, recommended_tools)

        limitations = []
        if classification == "UNKNOWN" or classification_confidence in ["LOW", "UNKNOWN"]:
            limitations.append("Low confidence classification: evidence format could not be verified deterministically from headers.")
        if classification_status == "MISMATCH":
            limitations.append(f"EXTENSION MISMATCH: File extension does not match detected magic signature '{detected_format}'.")

        partitions_dict = [pt.model_dump() for pt in partitions]
        tags_dict = [tg.model_dump() for tg in tags]
        tools_dict = [tl.model_dump() for tl in recommended_tools]
        families_dict = [fm.model_dump() for fm in analysis_families]
        res_profile_dict = res_profile.model_dump()

        payload_dict = {
            "evidence_id": evidence.id,
            "evidence_name": evidence.name,
            "source_kind": source_kind,
            "classification": classification,
            "evidence_type": classification,
            "subtype": subtype,
            "evidence_subtype": subtype,
            "classification_status": classification_status,
            "classification_confidence": classification_confidence,
            "classification_basis": classification_basis,
            "detected_format": detected_format,
            "detected_mime": detected_mime,
            "confidence": conf_num,
            "platform_hint": platform_hint,
            "platform_basis": platform_basis,
            "platform_confidence": platform_confidence,
            "architecture_hint": architecture_hint,
            "filesystem_type": filesystem_type,
            "filesystem_version": filesystem_version,
            "filesystem_basis": filesystem_basis,
            "filesystem_detection_status": filesystem_detection_status,
            "partition_table_type": partition_table_type,
            "partitions": partitions_dict,
            "size_bytes": size_bytes,
            "characteristics": characteristics,
            "detection_methods": detection_methods,
            "tags": tags_dict,
            "recommended_analysis_families": families_dict,
            "recommended_tools": tools_dict,
            "resource_profile": res_profile_dict,
            "limitations": limitations,
            "engine_version": ENGINE_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        evidence.evidence_type = classification
        evidence.evidence_subtype = subtype
        evidence.detected_format = detected_format
        evidence.platform_hint = platform_hint
        evidence.filesystem_type = filesystem_type
        evidence.mime_type = detected_mime
        evidence.intelligence_json = payload_dict

        if existing_profile:
            existing_profile.analysis_version += 1
            existing_profile.classification = classification
            existing_profile.subtype = subtype
            existing_profile.classification_status = classification_status
            existing_profile.classification_confidence = classification_confidence
            existing_profile.classification_basis = classification_basis
            existing_profile.detected_format = detected_format
            existing_profile.detected_mime = detected_mime
            existing_profile.platform_hint = platform_hint
            existing_profile.platform_basis = platform_basis
            existing_profile.platform_confidence = platform_confidence
            existing_profile.architecture_hint = architecture_hint
            existing_profile.filesystem_type = filesystem_type
            existing_profile.filesystem_version = filesystem_version
            existing_profile.filesystem_basis = filesystem_basis
            existing_profile.filesystem_detection_status = filesystem_detection_status
            existing_profile.partition_table_type = partition_table_type
            existing_profile.partitions_json = partitions_dict
            existing_profile.metadata_json = metadata
            existing_profile.characteristics_json = characteristics
            existing_profile.detection_methods = detection_methods
            existing_profile.tags_json = tags_dict
            existing_profile.resource_profile_json = res_profile_dict
            existing_profile.recommended_tools_json = tools_dict
            existing_profile.recommended_families_json = families_dict
            existing_profile.limitations_json = limitations
            existing_profile.evidence_sha256_verified = evidence.sha256
            existing_profile.updated_at = datetime.now(timezone.utc)
            profile_record = existing_profile
        else:
            profile_record = EvidenceIntelligence(
                evidence_id=evidence.id,
                case_id=evidence.case_id,
                engine_version=ENGINE_VERSION,
                analysis_version=1,
                classification=classification,
                subtype=subtype,
                classification_status=classification_status,
                classification_confidence=classification_confidence,
                classification_basis=classification_basis,
                detected_format=detected_format,
                detected_mime=detected_mime,
                platform_hint=platform_hint,
                platform_basis=platform_basis,
                platform_confidence=platform_confidence,
                architecture_hint=architecture_hint,
                filesystem_type=filesystem_type,
                filesystem_version=filesystem_version,
                filesystem_basis=filesystem_basis,
                filesystem_detection_status=filesystem_detection_status,
                partition_table_type=partition_table_type,
                partitions_json=partitions_dict,
                metadata_json=metadata,
                characteristics_json=characteristics,
                detection_methods=detection_methods,
                tags_json=tags_dict,
                resource_profile_json=res_profile_dict,
                recommended_tools_json=tools_dict,
                recommended_families_json=families_dict,
                limitations_json=limitations,
                evidence_sha256_verified=evidence.sha256,
                generated_at=datetime.now(timezone.utc)
            )
            db.add(profile_record)

        db.commit()
        db.refresh(profile_record)
        db.refresh(evidence)

        event_action = "RE_ANALYZED" if force_refresh else "GENERATED"
        record_custody_event(
            db=db,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_type="EVIDENCE_INTELLIGENCE_GENERATED",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"Evidence Intelligence profile {event_action} for '{evidence.name}' (Classification: {classification}/{detected_format}, Status: {classification_status}, SHA-256: {evidence.sha256})",
            destination_path=target_path,
            sha256=evidence.sha256,
            metadata_json={"analysis_version": profile_record.analysis_version, "classification": classification, "status": classification_status}
        )

        return profile_record

    @classmethod
    def analyze_evidence(cls, evidence_id: str, evidence_name: str, file_path: str) -> EvidenceIntelligencePayload:
        p = Path(file_path).resolve()
        source_kind, classification, subtype, detected_format, conf_num, detection_methods = cls.inspect_magic_header(p)
        (
            classification_status,
            classification_confidence,
            classification_basis,
            detected_mime,
            platform_hint,
            platform_basis,
            platform_confidence,
            architecture_hint,
            filesystem_type,
            filesystem_version,
            filesystem_basis,
            filesystem_detection_status,
            partition_table_type,
            partitions,
            characteristics,
            metadata,
            tags
        ) = cls.inspect_full_profile(p, classification, subtype, detected_format, conf_num)

        size_bytes = p.stat().st_size if p.exists() and p.is_file() else 0
        res_profile = cls.calculate_resource_profile(size_bytes, classification)
        recommended_tools = cls.map_recommended_tools(classification, source_kind, str(p))
        analysis_families = cls.map_analysis_families(classification, source_kind, recommended_tools)

        limitations = []
        if classification == "UNKNOWN" or classification_confidence in ["LOW", "UNKNOWN"]:
            limitations.append("Low confidence classification: evidence format could not be verified deterministically from headers.")
        if classification_status == "MISMATCH":
            limitations.append(f"EXTENSION MISMATCH: File extension does not match detected magic signature '{detected_format}'.")

        return EvidenceIntelligencePayload(
            evidence_id=evidence_id,
            evidence_name=evidence_name,
            source_kind=source_kind,
            classification=classification,
            evidence_type=classification,
            subtype=subtype,
            evidence_subtype=subtype,
            classification_status=classification_status,
            classification_confidence=classification_confidence,
            classification_basis=classification_basis,
            detected_format=detected_format,
            detected_mime=detected_mime,
            confidence=conf_num,
            platform_hint=platform_hint,
            platform_basis=platform_basis,
            platform_confidence=platform_confidence,
            architecture_hint=architecture_hint,
            filesystem_type=filesystem_type,
            filesystem_version=filesystem_version,
            filesystem_basis=filesystem_basis,
            filesystem_detection_status=filesystem_detection_status,
            partition_table_type=partition_table_type,
            partitions=partitions,
            size_bytes=size_bytes,
            characteristics=characteristics,
            detection_methods=detection_methods,
            tags=tags,
            recommended_analysis_families=analysis_families,
            recommended_tools=recommended_tools,
            resource_profile=res_profile,
            limitations=limitations,
            engine_version=ENGINE_VERSION
        )
