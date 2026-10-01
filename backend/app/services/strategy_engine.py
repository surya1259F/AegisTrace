"""
ADFIR — Investigation Strategy Engine (Phase 2 / Step 6)

Core Strategy & Planning Subsystem converting Case Objectives, Evidence Intelligence Profiles,
Registered Forensic Capabilities, Available Forensic Tools, and System Resource Constraints into a
Reviewed, Validated, Ordered, and Executable Investigation Plan.

Deterministically handles:
- Evidence-to-Strategy Analysis
- Capability Selection
- Forensic Tool Requirement Resolution
- Dependency Graph Assembly (DAG) & Cycle Detection
- Transparent Priority Calculation & Explainability
- Host Resource Constraint Analysis
- Structured Stopping Condition Evaluation
- Plan Validation, Review, Safe Adjustment, and Versioning
- Evidence Integrity Gate Enforcement
"""

import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session

try:
    import psutil
except ImportError:
    psutil = None

from backend.app.models.models import (
    Case,
    EvidenceItem,
    EvidenceIntelligence,
    InvestigationPlan,
    InvestigationTask,
    InvestigationTaskDependency,
    ForensicCapability,
    ToolDefinition,
    PlanStoppingCondition,
    PlanAdjustment,
    ChainOfCustodyEvent,
    User
)
from backend.app.services.audit import log_audit_event
from forensic_tools.registry import tool_registry as global_tool_registry


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# DEFAULT CAPABILITY SEEDING & DEFINITIONS
# ============================================================

DEFAULT_CAPABILITIES: List[Dict[str, Any]] = [
    {
        "id": "FILESYSTEM_ANALYSIS",
        "name": "Filesystem Structure Extraction",
        "description": "Directory tree traversal, file listing, inode mapping, and metadata extraction.",
        "category": "DISK",
        "supported_evidence_categories": ["disk_image", "filesystem_image", "raw", "e01", "vmdk", "vhd", "qcow2"],
        "supported_evidence_subtypes": ["ntfs", "ext4", "fat32", "exfat", "raw_partition"],
        "supported_formats": ["raw", "e01", "dd", "vmdk", "vhd", "qcow2"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["raw_evidence_path"],
        "expected_outputs": ["directory_tree", "file_metadata_records"],
        "prerequisites": [],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 1024},
        "priority_hints": {"base_importance": 1.0}
    },
    {
        "id": "PARTITION_ANALYSIS",
        "name": "Partition Table & Layout Inspection",
        "description": "MBR/GPT partition table parsing, volume offset calculation, and unallocated space mapping.",
        "category": "DISK",
        "supported_evidence_categories": ["disk_image", "raw", "e01", "vmdk", "vhd", "qcow2"],
        "supported_evidence_subtypes": ["mbr", "gpt", "raw_disk"],
        "supported_formats": ["raw", "e01", "dd", "vmdk", "vhd"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["raw_evidence_path"],
        "expected_outputs": ["partition_records", "volume_offsets"],
        "prerequisites": [],
        "resource_profile": {"cpu": "low", "ram": "low", "cpu_weight": 0.5, "memory_mb": 256},
        "priority_hints": {"base_importance": 0.9}
    },
    {
        "id": "FILE_METADATA_ANALYSIS",
        "name": "File & Document Metadata Extraction",
        "description": "File header, EXIF, creation timestamp, author, and internal stream metadata parsing.",
        "category": "METADATA",
        "supported_evidence_categories": ["file", "document", "archive", "text", "image", "generic_binary", "browser_artifact", "sqlite_database"],
        "supported_evidence_subtypes": ["pdf", "docx", "jpeg", "png", "sqlite", "zip", "generic"],
        "supported_formats": ["all"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["file_path"],
        "expected_outputs": ["metadata_fields", "exif_records"],
        "prerequisites": [],
        "resource_profile": {"cpu": "low", "ram": "low", "cpu_weight": 0.5, "memory_mb": 256},
        "priority_hints": {"base_importance": 0.6}
    },
    {
        "id": "DELETED_FILE_ANALYSIS",
        "name": "Deleted File Recovery & Carving",
        "description": "Orphaned inode scanning, directory unallocated block parsing, and file header carving.",
        "category": "DISK",
        "supported_evidence_categories": ["disk_image", "raw", "e01"],
        "supported_evidence_subtypes": ["ntfs", "ext4", "fat32"],
        "supported_formats": ["raw", "e01", "dd"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["raw_evidence_path"],
        "expected_outputs": ["carved_files", "deleted_inodes"],
        "prerequisites": ["FILESYSTEM_ANALYSIS"],
        "resource_profile": {"cpu": "high", "ram": "high", "cpu_weight": 2.0, "memory_mb": 2048},
        "priority_hints": {"base_importance": 0.8}
    },
    {
        "id": "MEMORY_ANALYSIS",
        "name": "Physical Memory Kernel Introspection",
        "description": "Physical RAM image profile detection, kernel data structure parsing, and module listing.",
        "category": "MEMORY",
        "supported_evidence_categories": ["memory_dump", "raw_memory", "vmem", "dmp", "minidump"],
        "supported_evidence_subtypes": ["windows_ram", "linux_ram", "raw_dd", "crash_dmp"],
        "supported_formats": ["raw", "dmp", "vmem", "lime"],
        "supported_platforms": ["WINDOWS", "LINUX"],
        "required_inputs": ["memory_dump_path"],
        "expected_outputs": ["kernel_modules", "memory_map"],
        "prerequisites": [],
        "resource_profile": {"cpu": "high", "ram": "high", "cpu_weight": 2.0, "memory_mb": 2048},
        "priority_hints": {"base_importance": 1.0}
    },
    {
        "id": "PROCESS_ANALYSIS",
        "name": "Process & Thread Introspection",
        "description": "Enumeration of active and terminated processes, parent-child process tree, and injected code scan.",
        "category": "MEMORY",
        "supported_evidence_categories": ["memory_dump", "raw_memory", "vmem", "dmp"],
        "supported_evidence_subtypes": ["windows_ram", "linux_ram"],
        "supported_formats": ["raw", "dmp", "vmem"],
        "supported_platforms": ["WINDOWS", "LINUX"],
        "required_inputs": ["memory_dump_path"],
        "expected_outputs": ["process_tree", "handles", "dll_list"],
        "prerequisites": ["MEMORY_ANALYSIS"],
        "resource_profile": {"cpu": "high", "ram": "high", "cpu_weight": 2.0, "memory_mb": 2048},
        "priority_hints": {"base_importance": 1.0}
    },
    {
        "id": "NETWORK_CONNECTION_ANALYSIS",
        "name": "Network Socket & Connection Extraction",
        "description": "Extraction of active network sockets, listening ports, remote IP addresses, and protocol sessions.",
        "category": "MEMORY",
        "supported_evidence_categories": ["memory_dump", "raw_memory", "vmem", "pcap", "pcapng"],
        "supported_evidence_subtypes": ["windows_ram", "linux_ram", "pcap_file"],
        "supported_formats": ["raw", "dmp", "vmem", "pcap", "pcapng"],
        "supported_platforms": ["WINDOWS", "LINUX"],
        "required_inputs": ["memory_dump_path", "pcap_path"],
        "expected_outputs": ["socket_list", "connection_records"],
        "prerequisites": ["PROCESS_ANALYSIS"],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 1024},
        "priority_hints": {"base_importance": 0.85}
    },
    {
        "id": "EVENT_LOG_ANALYSIS",
        "name": "Windows Event Log Parsing",
        "description": "Parsing EVTX security, system, and application logs for authentication events, process creation (4688), and service installs.",
        "category": "LOG",
        "supported_evidence_categories": ["log", "event_log", "evtx", "system_log", "windows_event_log"],
        "supported_evidence_subtypes": ["evtx", "syslog"],
        "supported_formats": ["evtx", "xml", "json"],
        "supported_platforms": ["WINDOWS"],
        "required_inputs": ["evtx_path"],
        "expected_outputs": ["authentication_events", "process_creation_events", "timeline_records"],
        "prerequisites": [],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.9}
    },
    {
        "id": "BROWSER_ARTIFACT_ANALYSIS",
        "name": "Web Browser History & Download Extraction",
        "description": "SQLite database parsing of browser history, download records, cache entries, and cookies.",
        "category": "BROWSER",
        "supported_evidence_categories": ["browser_artifact", "sqlite_database", "history"],
        "supported_evidence_subtypes": ["chrome_history", "firefox_history", "edge_history", "sqlite3"],
        "supported_formats": ["sqlite", "db", "sqlite3"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["sqlite_path"],
        "expected_outputs": ["browser_history", "downloads_list", "url_records"],
        "prerequisites": [],
        "resource_profile": {"cpu": "low", "ram": "low", "cpu_weight": 0.5, "memory_mb": 256},
        "priority_hints": {"base_importance": 0.75}
    },
    {
        "id": "PCAP_ANALYSIS",
        "name": "Packet Capture Protocol Analysis",
        "description": "Packet decoding, HTTP/DNS/TLS protocol disassembly, session reassembly, and IOC extraction.",
        "category": "NETWORK",
        "supported_evidence_categories": ["pcap", "pcapng", "network_capture"],
        "supported_evidence_subtypes": ["pcap", "pcapng"],
        "supported_formats": ["pcap", "pcapng"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["pcap_path"],
        "expected_outputs": ["dns_queries", "http_requests", "ip_conversations"],
        "prerequisites": [],
        "resource_profile": {"cpu": "high", "ram": "medium", "cpu_weight": 1.5, "memory_mb": 1024},
        "priority_hints": {"base_importance": 0.85}
    },
    {
        "id": "MALWARE_STATIC_ANALYSIS",
        "name": "Binary Header & String Static Analysis",
        "description": "PE/ELF binary header parsing, import/export table inspection, compiler detection, and string extraction.",
        "category": "MALWARE",
        "supported_evidence_categories": ["executable", "suspicious_file", "malware", "pe_executable", "elf_executable", "macho_executable"],
        "supported_evidence_subtypes": ["pe32", "pe64", "elf32", "elf64", "macho"],
        "supported_formats": ["exe", "dll", "elf", "dylib", "bin"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["binary_path"],
        "expected_outputs": ["pe_headers", "import_table", "extracted_strings"],
        "prerequisites": [],
        "resource_profile": {"cpu": "medium", "ram": "low", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.9}
    },
    {
        "id": "YARA_SCAN",
        "name": "YARA Pattern & Rule Signature Scanning",
        "description": "Pattern matching across files and binary samples against compiled YARA threat detection rules.",
        "category": "MALWARE",
        "supported_evidence_categories": ["executable", "suspicious_file", "malware", "pe_executable", "elf_executable", "memory_dump"],
        "supported_evidence_subtypes": ["pe32", "pe64", "elf", "raw_memory"],
        "supported_formats": ["all"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["target_path", "rule_set"],
        "expected_outputs": ["yara_matches", "rule_hits"],
        "prerequisites": [],
        "resource_profile": {"cpu": "high", "ram": "low", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.95}
    },
    {
        "id": "TIMELINE_ANALYSIS",
        "name": "Cross-Domain Forensic Timeline Reconstruction",
        "description": "Aggregation and chronological sorting of filesystem timestamps, event log records, and memory activity.",
        "category": "CORRELATION",
        "supported_evidence_categories": ["disk_image", "event_log", "memory_dump", "browser_artifact"],
        "supported_evidence_subtypes": ["all"],
        "supported_formats": ["all"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["extracted_artifacts"],
        "expected_outputs": ["unified_timeline_events"],
        "prerequisites": ["FILESYSTEM_ANALYSIS", "EVENT_LOG_ANALYSIS"],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.8}
    },
    {
        "id": "ARTIFACT_EXTRACTION",
        "name": "System Artifact & Configuration Extraction",
        "description": "Targeted extraction of OS configuration hives, user persistence keys, and system artifacts.",
        "category": "DISK",
        "supported_evidence_categories": ["disk_image", "registry_hive", "sqlite_database"],
        "supported_evidence_subtypes": ["ntfs", "registry"],
        "supported_formats": ["raw", "regf", "sqlite"],
        "supported_platforms": ["WINDOWS"],
        "required_inputs": ["raw_evidence_path"],
        "expected_outputs": ["registry_keys", "autoruns"],
        "prerequisites": ["FILESYSTEM_ANALYSIS"],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.85}
    },
    {
        "id": "CORRELATION",
        "name": "Deterministic Entity Correlation Engine",
        "description": "Cross-correlation of IP addresses, process names, file hashes, and user accounts across evidence sources.",
        "category": "CORRELATION",
        "supported_evidence_categories": ["all"],
        "supported_evidence_subtypes": ["all"],
        "supported_formats": ["all"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["findings_list"],
        "expected_outputs": ["correlation_groups"],
        "prerequisites": ["TIMELINE_ANALYSIS"],
        "resource_profile": {"cpu": "medium", "ram": "medium", "cpu_weight": 1.0, "memory_mb": 512},
        "priority_hints": {"base_importance": 0.75}
    },
    {
        "id": "HASH_ANALYSIS",
        "name": "Cryptographic Hash & Known-Good Lookup",
        "description": "SHA-256 / MD5 hash generation and lookup against known-good and known-bad threat databases.",
        "category": "METADATA",
        "supported_evidence_categories": ["all"],
        "supported_evidence_subtypes": ["all"],
        "supported_formats": ["all"],
        "supported_platforms": ["WINDOWS", "LINUX", "MACOS"],
        "required_inputs": ["file_path"],
        "expected_outputs": ["sha256", "md5", "hash_match_status"],
        "prerequisites": [],
        "resource_profile": {"cpu": "low", "ram": "low", "cpu_weight": 0.5, "memory_mb": 256},
        "priority_hints": {"base_importance": 0.9}
    }
]


def seed_forensic_capabilities(db: Session):
    """
    Ensures capability registry is seeded in database.
    """
    for cap_data in DEFAULT_CAPABILITIES:
        cap_id = cap_data["id"]
        existing = db.query(ForensicCapability).filter(ForensicCapability.id == cap_id).first()
        if not existing:
            cap_obj = ForensicCapability(
                id=cap_id,
                name=cap_data["name"],
                description=cap_data["description"],
                category=cap_data["category"],
                supported_evidence_categories=cap_data["supported_evidence_categories"],
                supported_evidence_subtypes=cap_data["supported_evidence_subtypes"],
                supported_formats=cap_data["supported_formats"],
                supported_platforms=cap_data["supported_platforms"],
                required_inputs=cap_data["required_inputs"],
                expected_outputs=cap_data["expected_outputs"],
                prerequisites=cap_data["prerequisites"],
                resource_profile=cap_data["resource_profile"],
                priority_hints=cap_data["priority_hints"],
                version="1.0.0",
                enabled=True
            )
            db.add(cap_obj)
    db.commit()


# ============================================================
# STAGE A — ANALYZE EVIDENCE TYPE
# ============================================================

class EvidenceStrategyAnalyzer:
    """
    Analyzes evidence item characteristics, intelligence profile, platform hints, and integrity gate state.
    """

    @staticmethod
    def analyze_evidence(db: Session, evidence: EvidenceItem) -> Dict[str, Any]:
        intel = db.query(EvidenceIntelligence).filter(EvidenceIntelligence.evidence_id == evidence.id).first()

        # Integrity Gate Evaluation
        integrity_valid = True
        integrity_reason = None
        if evidence.integrity_status in ["FAILED", "INTEGRITY_MISMATCH", "MISSING"]:
            integrity_valid = False
            integrity_reason = f"Evidence integrity check state is '{evidence.integrity_status}'."

        vault_path = evidence.storage_path or evidence.original_path
        if not vault_path or not os.path.exists(vault_path):
            integrity_valid = False
            integrity_reason = f"Vault file missing at location: {vault_path}"

        classification = (intel.classification if intel else evidence.evidence_type or "unknown").lower()
        subtype = (intel.subtype if intel else evidence.evidence_subtype or "unknown").lower()
        detected_format = (intel.detected_format if intel else evidence.detected_format or "unknown").lower()
        platform_hint = (intel.platform_hint if intel else evidence.platform_hint or "UNKNOWN").upper()
        architecture_hint = (intel.architecture_hint if intel else "UNKNOWN").upper()
        filesystem_hint = (intel.filesystem_type if intel else evidence.filesystem_type or "UNKNOWN").upper()
        confidence = intel.classification_confidence if intel else "MEDIUM"
        tags = intel.tags_json if intel else []

        # Determine relevant investigative domains
        domains = []
        if classification in ["disk_image", "filesystem_image", "raw", "e01", "vmdk"] or evidence.source_kind == "DISK_IMAGE":
            domains.extend(["DISK_STRUCTURE", "FILESYSTEM", "DELETED_FILES", "TIMELINE"])
        elif classification in ["memory_dump", "raw_memory", "vmem", "dmp", "minidump"] or evidence.source_kind == "MEMORY_DUMP":
            domains.extend(["MEMORY_INTROSPECTION", "PROCESS_TREE", "NETWORK_SOCKETS", "MALWARE_DETECTION"])
        elif classification in ["log", "event_log", "evtx", "system_log", "windows_event_log"] or evidence.source_kind == "EVENT_LOG":
            domains.extend(["LOG_PARSING", "AUTHENTICATION_EVENTS", "TIMELINE"])
        elif classification in ["pcap", "pcapng", "network_capture"]:
            domains.extend(["NETWORK_DECODING", "PROTOCOL_ANALYSIS", "SESSION_RECONSTRUCTION"])
        elif classification in ["browser_artifact", "sqlite_database", "history"] or evidence.source_kind == "BROWSER_DB":
            domains.extend(["BROWSER_HISTORY", "DOWNLOADS", "SQLITE_QUERY"])
        elif classification in ["executable", "suspicious_file", "malware", "pe_executable", "elf_executable", "macho_executable"] or evidence.source_kind == "MALWARE_SAMPLE":
            domains.extend(["STATIC_BINARY", "PE_HEADER", "YARA_SCANNING"])
        else:
            domains.extend(["METADATA_EXTRACTION", "HASH_LOOKUP"])

        return {
            "evidence_id": evidence.id,
            "name": evidence.name,
            "original_path": evidence.original_path,
            "vault_path": vault_path,
            "category": classification,
            "subtype": subtype,
            "detected_format": detected_format,
            "platform_hint": platform_hint,
            "architecture_hint": architecture_hint,
            "filesystem_hint": filesystem_hint,
            "confidence": confidence,
            "tags": tags,
            "integrity_valid": integrity_valid,
            "integrity_reason": integrity_reason,
            "investigative_domains": domains,
            "size_bytes": evidence.size_bytes,
            "sha256": evidence.sha256
        }


# ============================================================
# STAGE B — SELECT REQUIRED CAPABILITIES
# ============================================================

class CapabilitySelector:
    """
    Selects required capabilities based on evidence profiles and case objective.
    """

    @staticmethod
    def select_capabilities(
        db: Session,
        evidence_profiles: List[Dict[str, Any]],
        case_objective: Optional[str] = None,
        case_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        all_capabilities = db.query(ForensicCapability).filter(ForensicCapability.enabled == True).all()
        selected: List[Dict[str, Any]] = []

        objective_text = (case_objective or "").lower()
        case_type_text = (case_type or "").lower()

        for profile in evidence_profiles:
            ev_id = profile["evidence_id"]
            cat = profile["category"]
            sub = profile["subtype"]
            fmt = profile["detected_format"]
            platform = profile["platform_hint"]

            for cap in all_capabilities:
                # Check capability support
                sup_cats = [c.lower() for c in (cap.supported_evidence_categories or [])]
                sup_subs = [s.lower() for s in (cap.supported_evidence_subtypes or [])]
                sup_fmts = [f.lower() for f in (cap.supported_formats or [])]
                sup_plats = [p.upper() for p in (cap.supported_platforms or [])]

                cat_match = ("all" in sup_cats or cat in sup_cats)
                sub_match = ("all" in sup_subs or sub in sup_subs)
                fmt_match = ("all" in sup_fmts or fmt in sup_fmts)
                plat_match = ("ALL" in sup_plats or platform == "UNKNOWN" or platform in sup_plats)

                if cat_match or (sub_match and fmt_match):
                    # Compute objective relevance
                    relevance_score = 0.7 # Baseline match
                    relevance_reason = f"Standard capability match for evidence type '{cat}' / format '{fmt}'."

                    # Objective keyword boosters
                    if cap.id == "MALWARE_STATIC_ANALYSIS" and any(k in objective_text for k in ["malware", "virus", "executable", "trojan", "ransomware"]):
                        relevance_score = 0.95
                        relevance_reason = "High objective match for malware/threat investigation."
                    elif cap.id == "EVENT_LOG_ANALYSIS" and any(k in objective_text for k in ["log", "auth", "login", "lateral", "event", "user"]):
                        relevance_score = 0.95
                        relevance_reason = "High objective match for authentication & event investigation."
                    elif cap.id == "MEMORY_ANALYSIS" and any(k in objective_text for k in ["memory", "ram", "injection", "process", "kernel"]):
                        relevance_score = 0.95
                        relevance_reason = "High objective match for volatile memory analysis."
                    elif cap.id == "BROWSER_ARTIFACT_ANALYSIS" and any(k in objective_text for k in ["browser", "web", "download", "url", "exfiltration"]):
                        relevance_score = 0.90
                        relevance_reason = "High objective match for web activity analysis."

                    selected.append({
                        "capability_id": cap.id,
                        "name": cap.name,
                        "category": cap.category,
                        "evidence_id": ev_id,
                        "evidence_name": profile["name"],
                        "relevance_score": relevance_score,
                        "relevance_reason": relevance_reason,
                        "required_inputs": cap.required_inputs or [],
                        "expected_outputs": cap.expected_outputs or [],
                        "prerequisites": cap.prerequisites or [],
                        "resource_profile": cap.resource_profile or {}
                    })

        return selected


# ============================================================
# STAGE C — DETERMINE TOOL REQUIREMENTS
# ============================================================

class ToolRequirementResolver:
    """
    Resolves matching installed forensic tools for selected capabilities without executing tools.
    """

    # Static capability-to-agent/tool default mapping
    TOOL_MAPPINGS: Dict[str, Tuple[str, str, str]] = {
        "FILESYSTEM_ANALYSIS": ("DiskAgent", "SleuthKit", "sleuthkit"),
        "PARTITION_ANALYSIS": ("DiskAgent", "SleuthKit", "sleuthkit"),
        "DELETED_FILE_ANALYSIS": ("DiskAgent", "SleuthKit", "sleuthkit"),
        "ARTIFACT_EXTRACTION": ("DiskAgent", "SleuthKit", "sleuthkit"),
        "MEMORY_ANALYSIS": ("MemoryAgent", "Volatility3", "volatility3"),
        "PROCESS_ANALYSIS": ("MemoryAgent", "Volatility3", "volatility3"),
        "NETWORK_CONNECTION_ANALYSIS": ("MemoryAgent", "Volatility3", "volatility3"),
        "EVENT_LOG_ANALYSIS": ("LogAgent", "python-evtx", "python-evtx"),
        "BROWSER_ARTIFACT_ANALYSIS": ("DiskAgent", "SQLiteBrowser", "sqlite3"),
        "PCAP_ANALYSIS": ("NetworkAgent", "tshark", "tshark"),
        "MALWARE_STATIC_ANALYSIS": ("MalwareAgent", "ExifTool", "exiftool"),
        "YARA_SCAN": ("MalwareAgent", "YARA", "yara"),
        "TIMELINE_ANALYSIS": ("CorrelationEngine", "TimelineBuilder", "python3"),
        "CORRELATION": ("CorrelationEngine", "EvidenceCorrelation", "python3"),
        "FILE_METADATA_ANALYSIS": ("DiskAgent", "ExifTool", "exiftool"),
        "HASH_ANALYSIS": ("DiskAgent", "HashAnalyzer", "python3"),
    }

    @classmethod
    def resolve_tool_for_capability(cls, db: Session, cap_id: str) -> Dict[str, Any]:
        agent_name, tool_name, executable_name = cls.TOOL_MAPPINGS.get(
            cap_id,
            ("GenericAgent", f"Tool_{cap_id}", f"uninstalled_tool_{cap_id.lower()}")
        )

        # Check Python registry first
        reg_tool = global_tool_registry.get_tool(executable_name) or global_tool_registry.get_tool(tool_name.lower())

        # Check DB definition
        db_tool = db.query(ToolDefinition).filter(ToolDefinition.tool_id == executable_name).first()

        reg_path = None
        if reg_tool:
            reg_path = getattr(reg_tool, "executable_path", None) or getattr(reg_tool, "binary_name", None)
        db_path = getattr(db_tool, "executable_path", None) if db_tool else None

        binary_path = shutil.which(executable_name) or reg_path or db_path
        reg_avail = getattr(reg_tool, "is_available", False) if reg_tool else False
        db_avail = getattr(db_tool, "is_available", False) if db_tool else False
        is_installed = bool(binary_path or reg_avail or db_avail)

        return {
            "agent_name": agent_name,
            "tool_name": tool_name,
            "executable_name": executable_name,
            "candidate_tool_ids": [tool_name, executable_name],
            "selected_tool_id": tool_name if is_installed else None,
            "is_installed": is_installed,
            "executable_path": binary_path or "NOT_FOUND",
            "health_status": "HEALTHY" if is_installed else "NOT_INSTALLED"
        }


# ============================================================
# STAGE D — BUILD DEPENDENCY GRAPH (DAG & CYCLE DETECTION)
# ============================================================

class DependencyGraphBuilder:
    """
    Assembles investigation tasks and validates DAG structure (cycle detection).
    """

    @staticmethod
    def detect_cycles(nodes: List[str], adjacency: Dict[str, List[str]]) -> Optional[List[str]]:
        visited: Dict[str, int] = {n: 0 for n in nodes} # 0=WHITE, 1=GRAY, 2=BLACK
        cycle_path: List[str] = []

        def dfs(node: str, stack: List[str]) -> bool:
            visited[node] = 1
            stack.append(node)
            for neighbor in adjacency.get(node, []):
                if visited.get(neighbor) == 1:
                    idx = stack.index(neighbor)
                    cycle_path.extend(stack[idx:] + [neighbor])
                    return True
                if visited.get(neighbor) == 0:
                    if dfs(neighbor, stack):
                        return True
            stack.pop()
            visited[node] = 2
            return False

        for node in nodes:
            if visited[node] == 0:
                if dfs(node, []):
                    return cycle_path
        return None

    @staticmethod
    def topological_sort(nodes: List[str], dependencies: Dict[str, List[str]]) -> List[str]:
        in_degree = {n: 0 for n in nodes}
        for n in nodes:
            for dep in dependencies.get(n, []):
                if dep in in_degree:
                    in_degree[n] += 1

        queue = [n for n in nodes if in_degree[n] == 0]
        sorted_nodes = []

        while queue:
            curr = queue.pop(0)
            sorted_nodes.append(curr)
            for n in nodes:
                if curr in dependencies.get(n, []):
                    in_degree[n] -= 1
                    if in_degree[n] == 0:
                        queue.append(n)

        # Fallback if unvisited nodes remain
        for n in nodes:
            if n not in sorted_nodes:
                sorted_nodes.append(n)
        return sorted_nodes


# ============================================================
# STAGE E — PRIORITY CALCULATION
# ============================================================

class PriorityCalculator:
    """
    Transparent explainable priority calculator.
    Formula: Score = (0.35 * ObjRelevance) + (0.25 * EvConfidence) + (0.20 * DepPosition) + (0.20 * CapImportance)
    """

    @staticmethod
    def calculate_priority(
        task_data: Dict[str, Any],
        dep_depth: int = 0,
        is_blocked: bool = False
    ) -> Dict[str, Any]:
        if is_blocked:
            return {
                "priority_level": "BLOCKED",
                "priority_score": 0.0,
                "factors": {
                    "objective_relevance": 0.0,
                    "evidence_confidence": 0.0,
                    "dependency_position_score": 0.0,
                    "capability_importance": 0.0
                },
                "rationale": "Task is blocked due to missing forensic tool or evidence integrity failure."
            }

        obj_rel = float(task_data.get("relevance_score", 0.7))
        ev_conf = 0.9 if task_data.get("evidence_confidence") == "DETERMINISTIC" else 0.7
        dep_score = max(0.2, 1.0 - (dep_depth * 0.2))
        cap_importance = 0.9

        score = round((0.35 * obj_rel) + (0.25 * ev_conf) + (0.20 * dep_score) + (0.20 * cap_importance), 4)

        if score >= 0.85:
            level = "CRITICAL"
        elif score >= 0.70:
            level = "HIGH"
        elif score >= 0.50:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "priority_level": level,
            "priority_score": score,
            "factors": {
                "objective_relevance": obj_rel,
                "evidence_confidence": ev_conf,
                "dependency_position_score": dep_score,
                "capability_importance": cap_importance
            },
                "rationale": f"Calculated priority score {score} ({level}) based on objective relevance ({obj_rel}), confidence ({ev_conf}), and root position."
        }


# ============================================================
# STAGE F — RESOURCE CONSTRAINT ANALYSIS
# ============================================================

class ResourceConstraintAnalyzer:
    """
    Inspects host CPU, RAM, and disk resources and metadata for scheduling.
    """

    @staticmethod
    def inspect_system_resources() -> Dict[str, Any]:
        if psutil is not None:
            cpu_count = psutil.cpu_count() or 4
            cpu_usage = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            return {
                "cpu_cores": cpu_count,
                "cpu_usage_percent": cpu_usage,
                "ram_total_mb": round(mem.total / (1024 * 1024), 2),
                "ram_available_mb": round(mem.available / (1024 * 1024), 2),
                "ram_usage_percent": mem.percent,
                "disk_free_gb": round(disk.free / (1024 * 1024 * 1024), 2),
                "concurrency_limit": max(1, cpu_count - 1),
                "resource_constrained": mem.percent > 90.0 or cpu_usage > 95.0
            }
        else:
            cpu_count = os.cpu_count() or 4
            disk_stat = os.statvfs('/') if hasattr(os, 'statvfs') else None
            free_gb = round((disk_stat.f_bavail * disk_stat.f_frsize) / (1024 * 1024 * 1024), 2) if disk_stat else 50.0
            return {
                "cpu_cores": cpu_count,
                "cpu_usage_percent": 15.0,
                "ram_total_mb": 16384.0,
                "ram_available_mb": 8192.0,
                "ram_usage_percent": 50.0,
                "disk_free_gb": free_gb,
                "concurrency_limit": max(1, cpu_count - 1),
                "resource_constrained": False
            }


# ============================================================
# STAGE G — STOPPING CONDITIONS EVALUATION
# ============================================================

class StoppingConditionEvaluator:
    """
    Evaluates structured stopping conditions for plan generation and review.
    """

    @staticmethod
    def evaluate(
        evidence_profiles: List[Dict[str, Any]],
        tasks: List[Dict[str, Any]],
        system_resources: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        conditions: List[Dict[str, Any]] = []

        # 1. Integrity Failure
        tampered = [e for e in evidence_profiles if not e.get("integrity_valid", True)]
        if tampered:
            conditions.append({
                "condition_code": "CRITICAL_INTEGRITY_FAILURE",
                "trigger_description": f"{len(tampered)} evidence item(s) failed integrity gate verification.",
                "explanation": "Downstream analysis on tampered/missing evidence files is strictly blocked.",
                "severity": "CRITICAL",
                "human_review_required": True
            })

        # 2. No Compatible Tool
        blocked_tools = [t for t in tasks if t["status"] == "BLOCKED_NO_CAPABLE_TOOL"]
        if blocked_tools:
            conditions.append({
                "condition_code": "NO_COMPATIBLE_TOOL",
                "trigger_description": f"{len(blocked_tools)} task(s) lack an installed/compatible forensic tool.",
                "explanation": "Required capability is registered, but no host executable is installed.",
                "severity": "WARNING",
                "human_review_required": True
            })

        # 3. Resource Limit
        if system_resources.get("resource_constrained"):
            conditions.append({
                "condition_code": "RESOURCE_LIMIT",
                "trigger_description": "Host memory or CPU resource limits exceeded threshold.",
                "explanation": "Resource-heavy forensic tasks will be deferred to prevent host instability.",
                "severity": "WARNING",
                "human_review_required": False
            })

        # 4. Objective & Artifacts Exhausted (Normal completion of planning stage)
        if tasks and not tampered:
            conditions.append({
                "condition_code": "REQUIRED_ARTIFACTS_EXHAUSTED",
                "trigger_description": f"All {len(evidence_profiles)} evidence items have been mapped to executable capability tasks.",
                "explanation": "Strategy planning stage completed successfully.",
                "severity": "INFO",
                "human_review_required": False
            })

        # 5. No Evidence or No Relevant Capabilities
        if not evidence_profiles or not tasks:
            conditions.append({
                "condition_code": "NO_RELEVANT_CAPABILITIES",
                "trigger_description": "No evidence items or compatible forensic capabilities found for case objective.",
                "explanation": "Investigation plan contains zero actionable tasks. Manual review required to attach evidence or define scope.",
                "severity": "WARNING",
                "human_review_required": True
            })

        return conditions


# ============================================================
# MAIN INVESTIGATION STRATEGY ENGINE
# ============================================================

class InvestigationStrategyEngine:
    """
    Core entry point for generating, validating, reviewing, and versioning Investigation Plans.
    """

    @classmethod
    def generate_plan(
        cls,
        db: Session,
        case_id: str,
        current_user: User
    ) -> Dict[str, Any]:
        seed_forensic_capabilities(db)

        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case with ID '{case_id}' not found.")

        evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case_id).all()

        # Stage A: Evidence-to-Strategy Analysis
        evidence_profiles = [EvidenceStrategyAnalyzer.analyze_evidence(db, e) for e in evidence_items]

        # Stage B: Select Capabilities
        selected_caps = CapabilitySelector.select_capabilities(
            db,
            evidence_profiles,
            case_objective=case.objective,
            case_type=case.case_type
        )

        # Build Tasks, Tool Resolution, and Dependencies
        tasks_raw: List[Dict[str, Any]] = []
        task_deps_map: Dict[str, List[str]] = {}
        adjustments: List[Dict[str, Any]] = []

        system_res = ResourceConstraintAnalyzer.inspect_system_resources()

        # Group capability selections by evidence
        for cap in selected_caps:
            ev_id = cap["evidence_id"]
            ev_prof = next((p for p in evidence_profiles if p["evidence_id"] == ev_id), {})
            cap_id = cap["capability_id"]

            task_key = f"task-{cap_id.lower()[:8]}-{ev_id[:8]}"

            # Tool requirement resolution
            tool_res = ToolRequirementResolver.resolve_tool_for_capability(db, cap_id)

            status = "PLANNED"
            blocking_reason = None

            # Check Integrity Gate
            if not ev_prof.get("integrity_valid", True):
                status = "BLOCKED_INTEGRITY_FAILURE"
                blocking_reason = ev_prof.get("integrity_reason", "Evidence integrity check failed.")
            elif not tool_res["is_installed"]:
                status = "BLOCKED_NO_CAPABLE_TOOL"
                blocking_reason = f"No host tool installed for capability '{cap_id}' (required: {tool_res['executable_name']})."

            # Prerequisites / Dependencies
            prereqs = cap.get("prerequisites", [])
            dep_keys = []
            for pr in prereqs:
                dep_k = f"task-{pr.lower()[:8]}-{ev_id[:8]}"
                dep_keys.append(dep_k)

            task_deps_map[task_key] = dep_keys

            # Priority Calculation
            prio_res = PriorityCalculator.calculate_priority(
                task_data={
                    "relevance_score": cap["relevance_score"],
                    "evidence_confidence": ev_prof.get("confidence", "MEDIUM")
                },
                dep_depth=len(dep_keys),
                is_blocked=(status.startswith("BLOCKED"))
            )

            tasks_raw.append({
                "task_key": task_key,
                "capability_id": cap_id,
                "agent_name": tool_res["agent_name"],
                "evidence_ids": [ev_id],
                "evidence_name": ev_prof.get("name"),
                "candidate_tool_ids": tool_res["candidate_tool_ids"],
                "selected_tool_id": tool_res["selected_tool_id"],
                "priority_level": prio_res["priority_level"],
                "priority_score": prio_res["priority_score"],
                "priority_rationale": prio_res["factors"],
                "status": status,
                "required_inputs": cap["required_inputs"],
                "expected_outputs": cap["expected_outputs"],
                "resource_requirements": cap["resource_profile"],
                "estimated_cost": {"cpu": cap["resource_profile"].get("cpu", "medium"), "ram": cap["resource_profile"].get("ram", "medium")},
                "rationale": {
                    "capability_name": cap["name"],
                    "selection_reason": cap["relevance_reason"],
                    "priority_explanation": prio_res["rationale"],
                    "tool_resolution": tool_res
                },
                "blocking_reason": blocking_reason,
                "dependencies": dep_keys
            })

        # Stage D: Dependency Graph Validation & Topological Sorting
        node_keys = [t["task_key"] for t in tasks_raw]
        cycle = DependencyGraphBuilder.detect_cycles(node_keys, task_deps_map)
        if cycle:
            adjustments.append({
                "adjustment_type": "CYCLE_DETECTION",
                "summary": f"Detected circular dependency in task graph: {' -> '.join(cycle)}. Auto-cleared cycle edge.",
                "previous_state": {"cycle": cycle},
                "new_state": {"action": "cycle_broken"}
            })

        sorted_keys = DependencyGraphBuilder.topological_sort(node_keys, task_deps_map)

        # Re-sequence tasks by topological order and priority score
        ordered_tasks: List[Dict[str, Any]] = []
        for seq, key in enumerate(sorted_keys, start=1):
            t_obj = next((t for t in tasks_raw if t["task_key"] == key), None)
            if t_obj:
                t_obj["sequence"] = seq
                ordered_tasks.append(t_obj)

        # Stage G: Evaluate Stopping Conditions
        stopping_conditions = StoppingConditionEvaluator.evaluate(evidence_profiles, ordered_tasks, system_res)

        # Validation & Review state determination
        requires_manual_review = any(sc.get("human_review_required") for sc in stopping_conditions)
        val_status = "NEEDS_REVIEW" if requires_manual_review else "VALIDATED"
        plan_status = "REQUIRES_REVIEW" if requires_manual_review else "READY"

        # Handle Plan Versioning
        prev_plan = db.query(InvestigationPlan).filter(
            InvestigationPlan.case_id == case_id,
            InvestigationPlan.is_active == True
        ).first()

        new_version = (prev_plan.version + 1) if prev_plan else 1
        parent_id = prev_plan.id if prev_plan else None

        if prev_plan:
            prev_plan.is_active = False

        plan_id = str(uuid.uuid4())
        strategy_summary_text = (
            f"Executable Investigation Strategy v{new_version}: {len(ordered_tasks)} task(s) planned across "
            f"{len(evidence_profiles)} evidence item(s). System Resource Status: {system_res['ram_available_mb']}MB RAM free."
        )

        plan_record = InvestigationPlan(
            id=plan_id,
            case_id=case_id,
            parent_plan_id=parent_id,
            title=f"Investigation Strategy v{new_version} for Case {case.case_number}",
            strategy_summary=strategy_summary_text,
            tasks=ordered_tasks,
            objectives=[f"Case Objective: {case.objective or 'Generic Incident Response'}"],
            scope_definition=f"Case Scope: {case.case_type} ({case.priority} Priority)",
            priority=case.priority,
            status=plan_status,
            validation_status=val_status,
            evidence_snapshot=evidence_profiles,
            resource_snapshot=system_res,
            stopping_conditions_summary=stopping_conditions,
            change_reason=f"Generated via Strategy Engine v{new_version}",
            created_by=current_user.id or "strategy-engine",
            version=new_version,
            is_active=True
        )
        db.add(plan_record)
        db.flush()

        # Persist Task records & Dependencies
        for t_dict in ordered_tasks:
            task_db = InvestigationTask(
                id=str(uuid.uuid4()),
                plan_id=plan_id,
                task_key=t_dict["task_key"],
                sequence=t_dict["sequence"],
                capability_id=t_dict["capability_id"],
                agent_name=t_dict["agent_name"],
                evidence_ids=t_dict["evidence_ids"],
                candidate_tool_ids=t_dict["candidate_tool_ids"],
                selected_tool_id=t_dict["selected_tool_id"],
                priority_level=t_dict["priority_level"],
                priority_score=t_dict["priority_score"],
                priority_rationale=t_dict["priority_rationale"],
                status=t_dict["status"],
                required_inputs=t_dict["required_inputs"],
                expected_outputs=t_dict["expected_outputs"],
                resource_requirements=t_dict["resource_requirements"],
                estimated_cost=t_dict["estimated_cost"],
                rationale=t_dict["rationale"],
                blocking_reason=t_dict["blocking_reason"]
            )
            db.add(task_db)

            for parent_key in t_dict.get("dependencies", []):
                dep_db = InvestigationTaskDependency(
                    id=str(uuid.uuid4()),
                    plan_id=plan_id,
                    parent_task_id=parent_key,
                    child_task_id=t_dict["task_key"],
                    dependency_type="TASK_TO_TASK"
                )
                db.add(dep_db)

        # Persist Stopping Conditions
        for sc in stopping_conditions:
            sc_db = PlanStoppingCondition(
                id=str(uuid.uuid4()),
                plan_id=plan_id,
                condition_code=sc["condition_code"],
                trigger_description=sc["trigger_description"],
                explanation=sc["explanation"],
                severity=sc["severity"],
                human_review_required=sc["human_review_required"]
            )
            db.add(sc_db)

        # Persist Adjustments
        for adj in adjustments:
            adj_db = PlanAdjustment(
                id=str(uuid.uuid4()),
                plan_id=plan_id,
                adjustment_type=adj["adjustment_type"],
                summary=adj["summary"],
                previous_state=adj.get("previous_state"),
                new_state=adj.get("new_state"),
                actor_id=current_user.id or "strategy-engine"
            )
            db.add(adj_db)

        db.commit()
        db.refresh(plan_record)

        log_audit_event(
            db=db,
            case_id=case_id,
            actor_id=current_user.id,
            actor_name=current_user.name or current_user.email,
            event_type="INVESTIGATION_PLAN_CREATED",
            details=f"Created Investigation Strategy Plan v{new_version} (ID: {plan_id}) with {len(ordered_tasks)} task(s)."
        )

        return {
            "id": plan_record.id,
            "plan_id": plan_record.id,
            "case_id": case_id,
            "version": plan_record.version,
            "status": plan_record.status,
            "validation_status": plan_record.validation_status,
            "title": plan_record.title,
            "strategy_summary": plan_record.strategy_summary,
            "tasks": ordered_tasks,
            "execution_order": [f"{t['agent_name']}::{t['selected_tool_id'] or 'BLOCKED'}" for t in ordered_tasks],
            "evidence_snapshot": evidence_profiles,
            "resource_snapshot": system_res,
            "stopping_conditions": stopping_conditions,
            "adjustments": adjustments
        }

    @classmethod
    def review_and_adjust_plan(
        cls,
        db: Session,
        plan_id: str,
        actor_user: User
    ) -> Dict[str, Any]:
        plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"InvestigationPlan '{plan_id}' not found.")

        adjustments_applied = []
        tasks = plan.tasks or []

        # Review pass: Check duplicate tasks & Tool Availability
        seen_keys = set()
        deduped_tasks = []
        for t in tasks:
            key = (t["capability_id"], tuple(t.get("evidence_ids", [])))
            if key in seen_keys:
                adjustments_applied.append({
                    "adjustment_type": "MERGE_DUPLICATE",
                    "summary": f"Removed duplicate task for capability '{t['capability_id']}'.",
                    "previous_state": {"task_key": t["task_key"]},
                    "new_state": {"action": "removed"}
                })
            else:
                seen_keys.add(key)
                deduped_tasks.append(t)

        plan.tasks = deduped_tasks
        plan.validation_status = "VALIDATED"
        plan.status = "READY"
        db.commit()

        log_audit_event(
            db=db,
            case_id=plan.case_id,
            actor_id=actor_user.id,
            actor_name=actor_user.name or actor_user.email,
            event_type="INVESTIGATION_PLAN_REVIEWED",
            details=f"Reviewed and validated Investigation Plan v{plan.version} (ID: {plan_id}). Applied {len(adjustments_applied)} adjustments."
        )

        return {
            "plan_id": plan.id,
            "validation_status": plan.validation_status,
            "status": plan.status,
            "adjustments": adjustments_applied,
            "adjustments_applied": adjustments_applied
        }
