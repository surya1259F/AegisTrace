"""
ADFIR — Capability / Tool Selection Subsystem (Phase 2 / Step 7)

Deterministically selects and validates forensic tools for tasks requested by the
Investigation Strategy Engine based on Evidence Intelligence, tool registries, host
availability, platform support, system resources, version constraints, and safety profiles.

NO forensic tools are executed by this subsystem.
NO LLM or autonomous reasoning is used.
"""

import sys
import os
import shutil
import platform
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from backend.app.models.models import (
    ToolDefinition as DBToolDefinition,
    ToolSelectionRecord,
    ForensicCapability,
    InvestigationPlan,
    InvestigationTask,
    EvidenceItem,
    EvidenceIntelligence,
    User
)
from backend.app.services.audit import log_audit_event
from forensic_tools.registry import (
    tool_registry as global_tool_registry,
    DISALLOWED_BINARIES
)

logger = logging.getLogger("ADFIR_TOOL_SELECTOR")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_host_platform() -> str:
    """Returns normalized host OS: 'linux', 'windows', or 'darwin'."""
    plat = sys.platform.lower()
    if plat.startswith("win"):
        return "windows"
    if plat.startswith("linux"):
        return "linux"
    if plat.startswith("darwin"):
        return "darwin"
    return plat


def get_host_architecture() -> str:
    """Returns normalized host architecture, e.g. 'x86_64', 'arm64'."""
    return platform.machine().lower()


def get_system_resources() -> Dict[str, Any]:
    """
    Samples current host resources (CPU cores, available RAM, available disk space)
    without running any external forensic binaries.
    """
    cpu_cores = os.cpu_count() or 1
    ram_mb = 4096.0
    disk_mb = 10240.0

    try:
        import psutil
        vm = psutil.virtual_memory()
        ram_mb = round(vm.available / (1024 * 1024), 2)
    except Exception:
        # Fallback reading /proc/meminfo on Linux if available
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            parts = line.split()
                            ram_mb = round(float(parts[1]) / 1024, 2)
                            break
            except Exception:
                pass

    try:
        # Check disk space in current working dir or temp
        target_dir = os.getcwd()
        du = shutil.disk_usage(target_dir)
        disk_mb = round(du.free / (1024 * 1024), 2)
    except Exception:
        pass

    return {
        "platform": get_host_platform(),
        "architecture": get_host_architecture(),
        "cpu_cores": cpu_cores,
        "available_ram_mb": ram_mb,
        "available_disk_mb": disk_mb
    }


# =============================================================================
# DEFAULT SEEDED TOOL DEFINITIONS
# =============================================================================

DEFAULT_TOOLS: List[Dict[str, Any]] = [
    {
        "tool_id": "sleuthkit_fls",
        "name": "sleuthkit",
        "display_name": "The Sleuth Kit (fls)",
        "binary_name": "fls",
        "version": "4.12.0",
        "executable_path": "fls",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["disk_image", "raw", "e01", "filesystem_image", "vmdk", "vhd"],
        "supported_formats": ["raw", "e01", "dd", "img", "vmdk", "vhd", "qcow2"],
        "capabilities_json": ["FILESYSTEM_ANALYSIS", "PARTITION_ANALYSIS", "DELETED_FILE_ANALYSIS", "ARTIFACT_EXTRACTION"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100},
        "min_version": "4.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&", "`", "$"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "volatility3",
        "name": "volatility3",
        "display_name": "Volatility 3 Memory Forensics",
        "binary_name": "vol",
        "version": "2.28.0",
        "executable_path": "vol",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["memory_dump", "raw_memory", "vmem", "dmp", "minidump"],
        "supported_formats": ["raw", "dmp", "vmem", "lime", "bin"],
        "capabilities_json": ["MEMORY_ANALYSIS", "PROCESS_ANALYSIS", "NETWORK_CONNECTION_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 2, "ram_mb": 2048, "disk_mb": 500},
        "min_version": "2.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "yara",
        "name": "yara",
        "display_name": "YARA Pattern Matcher",
        "binary_name": "yara",
        "version": "4.3.2",
        "executable_path": "yara",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["executable", "suspicious_file", "malware", "file", "document", "generic_binary", "text"],
        "supported_formats": ["exe", "dll", "elf", "bin", "raw", "all", "*"],
        "capabilities_json": ["YARA_SCAN"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 50},
        "min_version": "3.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "exiftool",
        "name": "exiftool",
        "display_name": "ExifTool Metadata Extractor",
        "binary_name": "exiftool",
        "version": "12.76",
        "executable_path": "exiftool",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["file", "document", "archive", "text", "image", "generic_binary", "browser_artifact", "sqlite_database", "executable", "suspicious_file", "malware"],
        "supported_formats": ["all", "*", "pdf", "docx", "jpeg", "png", "exe", "dll", "elf"],
        "capabilities_json": ["FILE_METADATA_ANALYSIS", "MALWARE_STATIC_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 256, "disk_mb": 50},
        "min_version": "10.00",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "python-evtx",
        "name": "python-evtx",
        "display_name": "python-evtx Log Parser",
        "binary_name": "python-evtx",
        "version": "0.7.4",
        "executable_path": sys.executable,
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["log", "event_log", "evtx", "system_log", "windows_event_log"],
        "supported_formats": ["evtx", "xml", "json"],
        "capabilities_json": ["EVENT_LOG_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 50},
        "min_version": "0.6.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "sqlite3",
        "name": "sqlite3",
        "display_name": "SQLite Browser & Parser",
        "binary_name": "sqlite3",
        "version": "3.40.0",
        "executable_path": "sqlite3",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["browser_artifact", "sqlite_database", "history"],
        "supported_formats": ["sqlite", "db", "sqlite3"],
        "capabilities_json": ["BROWSER_ARTIFACT_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 256, "disk_mb": 50},
        "min_version": "3.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "tshark",
        "name": "tshark",
        "display_name": "Wireshark TShark Packet Analyzer",
        "binary_name": "tshark",
        "version": "4.2.0",
        "executable_path": "tshark",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["pcap", "pcapng", "network_capture"],
        "supported_formats": ["pcap", "pcapng"],
        "capabilities_json": ["PCAP_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 2, "ram_mb": 1024, "disk_mb": 200},
        "min_version": "3.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [">", "|", ";", "&"], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "hash_analyzer",
        "name": "hash_analyzer",
        "display_name": "Deterministic Hash Analyzer",
        "binary_name": "sha256sum",
        "version": "1.0.0",
        "executable_path": "sha256sum",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["*"],
        "supported_formats": ["all", "*"],
        "capabilities_json": ["HASH_ANALYSIS"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 256, "disk_mb": 10},
        "min_version": "1.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [], "shell": False, "sandbox_compatible": True},
        "enabled": True
    },
    {
        "tool_id": "timeline_correlator",
        "name": "timeline_correlator",
        "display_name": "Deterministic Timeline Correlator",
        "binary_name": "internal_correlator",
        "version": "1.0.0",
        "executable_path": "internal_correlator",
        "platforms": ["linux", "windows", "darwin"],
        "supported_evidence": ["*"],
        "supported_formats": ["all", "*"],
        "capabilities_json": ["TIMELINE_ANALYSIS", "CORRELATION"],
        "resource_requirements": {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 50},
        "min_version": "1.0.0",
        "max_version": None,
        "dependencies": [],
        "safety_profile": {"read_only": True, "disallowed_args": [], "shell": False, "sandbox_compatible": True},
        "enabled": True
    }
]


def seed_default_tools(db: Session):
    """
    Seeds default ToolDefinition records into the database if not present,
    and updates existing definitions with missing metadata.
    """
    for t_data in DEFAULT_TOOLS:
        existing = db.query(DBToolDefinition).filter(DBToolDefinition.tool_id == t_data["tool_id"]).first()
        if not existing:
            # Check availability at seed time
            bin_name = t_data["binary_name"]
            is_avail = bool(shutil.which(bin_name) or t_data["executable_path"] == sys.executable)
            tool = DBToolDefinition(
                tool_id=t_data["tool_id"],
                name=t_data["name"],
                display_name=t_data["display_name"],
                binary_name=t_data["binary_name"],
                version=t_data["version"],
                executable_path=t_data["executable_path"],
                platforms=t_data["platforms"],
                supported_evidence=t_data["supported_evidence"],
                supported_formats=t_data["supported_formats"],
                capabilities_json=t_data["capabilities_json"],
                resource_requirements=t_data["resource_requirements"],
                min_version=t_data["min_version"],
                max_version=t_data["max_version"],
                dependencies=t_data["dependencies"],
                safety_profile=t_data["safety_profile"],
                enabled=t_data["enabled"],
                is_available=is_avail
            )
            db.add(tool)
        else:
            # Ensure new columns are populated
            if not existing.display_name:
                existing.display_name = t_data["display_name"]
            if not existing.binary_name:
                existing.binary_name = t_data["binary_name"]
            if not existing.platforms:
                existing.platforms = t_data["platforms"]
            if not existing.supported_formats:
                existing.supported_formats = t_data["supported_formats"]
            if not existing.resource_requirements:
                existing.resource_requirements = t_data["resource_requirements"]
            if not existing.safety_profile:
                existing.safety_profile = t_data["safety_profile"]
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Error seeding default tools: {e}")


# =============================================================================
# STAGE 1 — CAPABILITY REGISTRY MATCHER
# =============================================================================

class CapabilityMatcher:
    """
    Matches a requested capability against Evidence Intelligence data.
    Validates evidence category, subtype, format, and platform.
    Returns CAPABILITY_UNSUPPORTED with clear rationale if incompatible.
    """

    @classmethod
    def match(
        cls,
        capability: ForensicCapability,
        evidence: Optional[EvidenceItem] = None,
        intel: Optional[EvidenceIntelligence] = None,
        category: Optional[str] = None,
        subtype: Optional[str] = None,
        fmt: Optional[str] = None,
        platform_name: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Returns (is_supported: bool, reason: str, status: str).
        Status is either CAPABILITY_SUPPORTED or CAPABILITY_UNSUPPORTED.
        """
        if not capability or not capability.enabled:
            return False, "Capability is missing or disabled in registry", "CAPABILITY_UNSUPPORTED"

        # Resolve evidence properties from objects or overrides
        ev_cat = (category or "").lower().strip()
        ev_sub = (subtype or "").lower().strip()
        ev_fmt = (fmt or "").lower().strip()
        ev_plat = (platform_name or "").lower().strip()

        if evidence:
            ev_type = getattr(evidence, "evidence_type", None) or getattr(evidence, "category", "") or ""
            ev_sub = ev_sub or (getattr(evidence, "evidence_subtype", None) or getattr(evidence, "subtype", "") or "").lower().strip()
            ev_fmt = ev_fmt or (getattr(evidence, "detected_format", None) or "").lower().strip()
            ev_plat = ev_plat or (getattr(evidence, "platform_hint", None) or "").lower().strip()
            if not ev_cat:
                ev_cat = str(ev_type).lower().strip()

        if intel:
            in_cat = getattr(intel, "category", None) or getattr(intel, "evidence_type", "") or ""
            ev_sub = ev_sub or (getattr(intel, "subtype", None) or "").lower().strip()
            ev_fmt = ev_fmt or (getattr(intel, "detected_format", None) or "").lower().strip()
            ev_plat = ev_plat or (getattr(intel, "platform", None) or "").lower().strip()
            if not ev_cat:
                ev_cat = str(in_cat).lower().strip()

        # If no evidence properties specified, capability is supported in the abstract
        if not ev_cat and not ev_fmt and not ev_sub:
            return True, "No specific evidence constraints supplied; capability is valid in registry", "CAPABILITY_SUPPORTED"

        # 1. Match Evidence Category
        sup_cats = [c.lower().strip() for c in (capability.supported_evidence_categories or [])]
        if sup_cats and "*" not in sup_cats and "all" not in sup_cats:
            if ev_cat and ev_cat not in sup_cats:
                return (
                    False,
                    f"Evidence category '{ev_cat}' is not supported by capability '{capability.id}' (expected: {sup_cats})",
                    "CAPABILITY_UNSUPPORTED"
                )

        # 2. Match Evidence Format
        sup_fmts = [f.lower().strip() for f in (capability.supported_formats or [])]
        if sup_fmts and "*" not in sup_fmts and "all" not in sup_fmts:
            if ev_fmt and ev_fmt not in sup_fmts:
                return (
                    False,
                    f"Evidence format '{ev_fmt}' is not supported by capability '{capability.id}' (expected: {sup_fmts})",
                    "CAPABILITY_UNSUPPORTED"
                )

        # 3. Match Platform
        sup_plats = [p.lower().strip() for p in (capability.supported_platforms or [])]
        if sup_plats and "*" not in sup_plats and "all" not in sup_plats:
            if ev_plat and ev_plat != "unknown" and ev_plat not in sup_plats:
                return (
                    False,
                    f"Evidence platform '{ev_plat}' is not supported by capability '{capability.id}' (expected: {sup_plats})",
                    "CAPABILITY_UNSUPPORTED"
                )

        return True, "Evidence properties match capability registry requirements", "CAPABILITY_SUPPORTED"


# =============================================================================
# STAGE 2 — TOOL EVALUATOR
# =============================================================================

class ToolEvaluator:
    """
    Evaluates a candidate tool against 6 strict verification dimensions:
    1. Availability (binary installed, executable permissions, enabled flag)
    2. Platform compatibility (host OS & architecture)
    3. Evidence compatibility (evidence type & format)
    4. Resource suitability (RAM, CPU cores, scratch disk)
    5. Version constraints (semver checking)
    6. Safety profile (read-only, no shells, safe args)
    """

    @classmethod
    def evaluate_availability(
        cls,
        tool: DBToolDefinition,
        custom_binary_path: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: AVAILABLE, UNAVAILABLE, DISABLED, MISSING, INCOMPATIBLE, REQUIRES_REVIEW.
        """
        if not tool.enabled:
            return "DISABLED", f"Tool '{tool.tool_id}' is explicitly disabled in registry"

        bin_name = tool.binary_name or tool.name
        if not bin_name:
            return "MISSING", f"Tool '{tool.tool_id}' does not define a binary name"

        # Check safety disallowed binaries
        clean_bin = bin_name.lower().strip()
        if clean_bin in DISALLOWED_BINARIES or os.path.basename(clean_bin) in DISALLOWED_BINARIES:
            return "INCOMPATIBLE", f"Tool binary '{clean_bin}' is in disallowed execution list (system shells/interpreters)"

        # Special internal tools
        if bin_name in ["internal_correlator", "python-evtx", "sha256sum"]:
            if bin_name == "python-evtx":
                # Check python evtx package or python binary
                return "AVAILABLE", None
            if bin_name == "internal_correlator":
                return "AVAILABLE", None
            if shutil.which("sha256sum") or shutil.which("shasum"):
                return "AVAILABLE", None

        # Check path
        resolved_path = custom_binary_path or shutil.which(bin_name)
        if not resolved_path and tool.executable_path:
            if os.path.exists(tool.executable_path):
                resolved_path = tool.executable_path
            else:
                resolved_path = shutil.which(tool.executable_path)

        # Check global registry
        if not resolved_path:
            reg_tool = global_tool_registry.get_tool(tool.name) or global_tool_registry.get_tool(tool.tool_id)
            if reg_tool and getattr(reg_tool, "path", None):
                resolved_path = reg_tool.path

        if not resolved_path:
            return "MISSING", f"Binary '{bin_name}' was not found in system PATH or configured directories"

        # Check file permissions on non-windows
        if not sys.platform.startswith("win"):
            if os.path.isabs(resolved_path) and os.path.exists(resolved_path):
                if not os.access(resolved_path, os.X_OK):
                    return "UNAVAILABLE", f"Binary at '{resolved_path}' exists but lacks executable permissions (os.X_OK)"

        return "AVAILABLE", None

    @classmethod
    def evaluate_platform(
        cls,
        tool: DBToolDefinition,
        host_platform: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: COMPATIBLE, INCOMPATIBLE, REQUIRES_REVIEW.
        """
        current_os = (host_platform or get_host_platform()).lower()
        supported = [p.lower().strip() for p in (tool.platforms or [])]

        if not supported or "*" in supported or "all" in supported:
            return "COMPATIBLE", None

        if current_os in supported:
            return "COMPATIBLE", None

        return (
            "INCOMPATIBLE",
            f"Host platform '{current_os}' is not supported by tool '{tool.tool_id}' (supported: {supported})"
        )

    @classmethod
    def evaluate_evidence_compatibility(
        cls,
        tool: DBToolDefinition,
        evidence: Optional[EvidenceItem] = None,
        category: Optional[str] = None,
        fmt: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: COMPATIBLE, INCOMPATIBLE, REQUIRES_REVIEW.
        """
        ev_cat = (category or "").lower().strip()
        ev_fmt = (fmt or "").lower().strip()

        if evidence:
            ev_type = getattr(evidence, "evidence_type", None) or getattr(evidence, "category", "") or ""
            if not ev_cat:
                ev_cat = str(ev_type).lower().strip()
            ev_fmt = ev_fmt or (getattr(evidence, "detected_format", None) or "").lower().strip()

        if not ev_cat and not ev_fmt:
            return "COMPATIBLE", None

        sup_ev = [e.lower().strip() for e in (tool.supported_evidence or [])]
        sup_fmts = [f.lower().strip() for f in (tool.supported_formats or [])]

        # Check evidence category
        if sup_ev and "*" not in sup_ev and "all" not in sup_ev:
            if ev_cat and ev_cat not in sup_ev:
                return (
                    "INCOMPATIBLE",
                    f"Evidence category '{ev_cat}' is not in tool supported types: {sup_ev}"
                )

        # Check evidence format
        if sup_fmts and "*" not in sup_fmts and "all" not in sup_fmts:
            if ev_fmt and ev_fmt not in sup_fmts:
                return (
                    "INCOMPATIBLE",
                    f"Evidence format '{ev_fmt}' is not in tool supported formats: {sup_fmts}"
                )

        return "COMPATIBLE", None

    @classmethod
    def evaluate_resources(
        cls,
        tool: DBToolDefinition,
        sys_res: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: RESOURCE_OK, RESOURCE_CONSTRAINED, RESOURCE_INSUFFICIENT.
        """
        res = sys_res or get_system_resources()
        reqs = tool.resource_requirements or {}

        req_ram = float(reqs.get("ram_mb", 256))
        req_cpu = int(reqs.get("cpu_cores", 1))
        req_disk = float(reqs.get("disk_mb", 50))

        avail_ram = float(res.get("available_ram_mb", 4096))
        avail_cpu = int(res.get("cpu_cores", 1))
        avail_disk = float(res.get("available_disk_mb", 10240))

        # Hard failure: available RAM or disk < 50% of required
        if avail_ram < (req_ram * 0.5):
            return (
                "RESOURCE_INSUFFICIENT",
                f"Available system RAM ({avail_ram:.1f} MB) is critically insufficient for tool requirement ({req_ram:.1f} MB)"
            )
        if avail_disk < (req_disk * 0.5):
            return (
                "RESOURCE_INSUFFICIENT",
                f"Available scratch disk ({avail_disk:.1f} MB) is critically insufficient for tool requirement ({req_disk:.1f} MB)"
            )

        # Warning/constrained: available is less than required, but >= 50%
        if avail_ram < req_ram:
            return (
                "RESOURCE_CONSTRAINED",
                f"Available system RAM ({avail_ram:.1f} MB) is below recommended ({req_ram:.1f} MB)"
            )
        if avail_cpu < req_cpu:
            return (
                "RESOURCE_CONSTRAINED",
                f"Available CPU cores ({avail_cpu}) below recommended ({req_cpu})"
            )
        if avail_disk < req_disk:
            return (
                "RESOURCE_CONSTRAINED",
                f"Available scratch disk ({avail_disk:.1f} MB) below recommended ({req_disk:.1f} MB)"
            )

        return "RESOURCE_OK", None

    @classmethod
    def _parse_semver(cls, v_str: Optional[str]) -> Tuple[int, ...]:
        if not v_str:
            return (0, 0, 0)
        # Strip prefixes like 'v' or 'fls-'
        cleaned = ""
        for part in v_str.replace("v", "").replace("-", " ").split():
            # Find first dot-separated digit group
            candidate = "".join([c for c in part if c.isdigit() or c == "."])
            if candidate and "." in candidate:
                cleaned = candidate
                break
        if not cleaned:
            cleaned = "".join([c for c in v_str if c.isdigit() or c == "."])

        nums = []
        for x in cleaned.split("."):
            try:
                nums.append(int(x))
            except ValueError:
                break
        return tuple(nums) or (0, 0, 0)

    @classmethod
    def evaluate_version(
        cls,
        tool: DBToolDefinition
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: VERSION_OK, VERSION_UNKNOWN, VERSION_INCOMPATIBLE.
        """
        if not tool.min_version and not tool.max_version:
            return "VERSION_OK", None

        if not tool.version:
            if tool.min_version:
                return "VERSION_UNKNOWN", f"Tool has min_version requirement '{tool.min_version}' but installed version is unknown"
            return "VERSION_OK", None

        tool_v = cls._parse_semver(tool.version)

        if tool.min_version:
            min_v = cls._parse_semver(tool.min_version)
            if tool_v < min_v:
                return (
                    "VERSION_INCOMPATIBLE",
                    f"Installed tool version '{tool.version}' is lower than required minimum '{tool.min_version}'"
                )

        if tool.max_version:
            max_v = cls._parse_semver(tool.max_version)
            if tool_v > max_v:
                return (
                    "VERSION_INCOMPATIBLE",
                    f"Installed tool version '{tool.version}' exceeds maximum allowed '{tool.max_version}'"
                )

        return "VERSION_OK", None

    @classmethod
    def evaluate_safety(
        cls,
        tool: DBToolDefinition
    ) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        Status values: SAFE, UNSAFE, SAFETY_UNKNOWN, REQUIRES_REVIEW.
        """
        profile = tool.safety_profile or {}

        # 1. Check read_only enforcement
        if not profile.get("read_only", True):
            return "UNSAFE", f"Tool '{tool.tool_id}' safety profile permits write operations (not strictly read-only)"

        # 2. Check shell execution prohibition
        if profile.get("shell", False) is True:
            return "UNSAFE", f"Tool '{tool.tool_id}' safety profile configures shell=True (prohibited)"

        # 3. Disallowed binary check
        bin_name = (tool.binary_name or tool.name or "").lower().strip()
        if bin_name in DISALLOWED_BINARIES or os.path.basename(bin_name) in DISALLOWED_BINARIES:
            return "UNSAFE", f"Binary '{bin_name}' is in disallowed execution list"

        # 4. Custom/untrusted executable path
        if tool.executable_path and ("tmp" in tool.executable_path.lower() or "temp" in tool.executable_path.lower()):
            return "REQUIRES_REVIEW", f"Tool executable path '{tool.executable_path}' points to temporary directory"

        return "SAFE", None


# =============================================================================
# STAGE 3 — TOOL SELECTOR ENGINE
# =============================================================================

class ToolSelectorEngine:
    """
    Core engine for Phase 2 / Step 7: Capability / Tool Selection.
    Evaluates candidate tools for tasks, resolves multi-candidate priorities,
    records selection outcomes, and updates InvestigationTask states.
    """

    @classmethod
    def select_tool_for_task(
        cls,
        db: Session,
        task: InvestigationTask,
        evidence: Optional[EvidenceItem] = None,
        intel: Optional[EvidenceIntelligence] = None,
        sys_res: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates and selects an appropriate tool for a single InvestigationTask.
        Does NOT commit changes directly; returns comprehensive structured evaluation.
        """
        system_resources = sys_res or get_system_resources()

        # Step 1: Query capability
        cap = db.query(ForensicCapability).filter(ForensicCapability.id == task.capability_id).first()
        if not cap:
            return {
                "selected_tool_id": None,
                "selection_status": "NO_COMPATIBLE_TOOL",
                "availability_status": "MISSING",
                "evidence_compatibility": "INCOMPATIBLE",
                "platform_compatibility": "COMPATIBLE",
                "resource_status": "RESOURCE_OK",
                "version_status": "VERSION_OK",
                "safety_status": "SAFE",
                "candidate_tools": [],
                "rejection_reasons": {"capability": f"Forensic capability '{task.capability_id}' is not registered in the system"},
                "rationale": f"Capability '{task.capability_id}' not found in registry"
            }

        # Step 2: Match capability against evidence intelligence
        cap_ok, cap_reason, cap_status = CapabilityMatcher.match(cap, evidence=evidence, intel=intel)
        if not cap_ok:
            return {
                "selected_tool_id": None,
                "selection_status": "NO_COMPATIBLE_TOOL",
                "availability_status": "INCOMPATIBLE",
                "evidence_compatibility": "INCOMPATIBLE",
                "platform_compatibility": "COMPATIBLE",
                "resource_status": "RESOURCE_OK",
                "version_status": "VERSION_OK",
                "safety_status": "SAFE",
                "candidate_tools": [],
                "rejection_reasons": {"capability_match": cap_reason},
                "rationale": f"Evidence attributes do not satisfy capability requirements: {cap_reason}"
            }

        # Step 3: Find candidate tools that declare this capability
        all_tools = db.query(DBToolDefinition).all()
        candidate_tools: List[DBToolDefinition] = []
        for t in all_tools:
            caps = t.capabilities_json or []
            if task.capability_id in caps or task.capability_id.lower() in [c.lower() for c in caps]:
                candidate_tools.append(t)

        candidate_ids = [t.tool_id for t in candidate_tools]
        if not candidate_tools:
            return {
                "selected_tool_id": None,
                "selection_status": "NO_COMPATIBLE_TOOL",
                "availability_status": "MISSING",
                "evidence_compatibility": "COMPATIBLE",
                "platform_compatibility": "COMPATIBLE",
                "resource_status": "RESOURCE_OK",
                "version_status": "VERSION_OK",
                "safety_status": "SAFE",
                "candidate_tools": [],
                "rejection_reasons": {"registry": f"No tools in registry advertise capability '{task.capability_id}'"},
                "rationale": f"No registered tools support capability '{task.capability_id}'"
            }

        # Step 4: Evaluate each candidate tool
        evaluations: List[Dict[str, Any]] = []
        rejections: Dict[str, List[str]] = {}

        for tool in candidate_tools:
            tool_rejections = []

            avail_st, avail_re = ToolEvaluator.evaluate_availability(tool)
            if avail_st not in ["AVAILABLE", "REQUIRES_REVIEW"]:
                tool_rejections.append(f"AVAILABILITY ({avail_st}): {avail_re}")

            plat_st, plat_re = ToolEvaluator.evaluate_platform(tool, host_platform=system_resources["platform"])
            if plat_st == "INCOMPATIBLE":
                tool_rejections.append(f"PLATFORM: {plat_re}")

            ev_st, ev_re = ToolEvaluator.evaluate_evidence_compatibility(tool, evidence=evidence)
            if ev_st == "INCOMPATIBLE":
                tool_rejections.append(f"EVIDENCE: {ev_re}")

            res_st, res_re = ToolEvaluator.evaluate_resources(tool, sys_res=system_resources)
            if res_st == "RESOURCE_INSUFFICIENT":
                tool_rejections.append(f"RESOURCE: {res_re}")

            ver_st, ver_re = ToolEvaluator.evaluate_version(tool)
            if ver_st == "VERSION_INCOMPATIBLE":
                tool_rejections.append(f"VERSION: {ver_re}")

            safe_st, safe_re = ToolEvaluator.evaluate_safety(tool)
            if safe_st == "UNSAFE":
                tool_rejections.append(f"SAFETY: {safe_re}")

            evaluations.append({
                "tool": tool,
                "tool_id": tool.tool_id,
                "availability": avail_st,
                "platform": plat_st,
                "evidence": ev_st,
                "resources": res_st,
                "version": ver_st,
                "safety": safe_st,
                "rejections": tool_rejections,
                "is_eligible": len(tool_rejections) == 0
            })

            if tool_rejections:
                rejections[tool.tool_id] = tool_rejections

        # Step 5: Select best eligible candidate
        eligible = [e for e in evaluations if e["is_eligible"]]

        if eligible:
            # Multi-candidate selection ranking:
            # 1. Prefer RESOURCE_OK over RESOURCE_CONSTRAINED
            # 2. Prefer specific format matches over wildcards
            # 3. Prefer highest min_version or declared priority
            def score_candidate(cand: Dict[str, Any]) -> float:
                score = 10.0
                if cand["resources"] == "RESOURCE_OK":
                    score += 5.0
                if cand["safety"] == "SAFE":
                    score += 5.0
                if cand["availability"] == "AVAILABLE":
                    score += 5.0
                # Prefer tools with explicit format match
                ev_fmt = (evidence.detected_format if evidence else "") or ""
                sup_fmts = cand["tool"].supported_formats or []
                if ev_fmt and ev_fmt.lower() in [f.lower() for f in sup_fmts]:
                    score += 3.0
                return score

            best = max(eligible, key=score_candidate)
            sel_tool = best["tool"]

            # Determine final status
            final_status = "SELECTED"
            if best["safety"] == "REQUIRES_REVIEW" or best["availability"] == "REQUIRES_REVIEW":
                final_status = "REQUIRES_REVIEW"

            return {
                "selected_tool_id": sel_tool.tool_id,
                "selection_status": final_status,
                "availability_status": best["availability"],
                "evidence_compatibility": best["evidence"],
                "platform_compatibility": best["platform"],
                "resource_status": best["resources"],
                "version_status": best["version"],
                "safety_status": best["safety"],
                "candidate_tools": candidate_ids,
                "rejection_reasons": rejections,
                "rationale": f"Selected tool '{sel_tool.tool_id}' ({sel_tool.display_name}) satisfying capability '{task.capability_id}' with all compatibility checks passed."
            }

        # Step 6: No eligible candidate found — categorize failure reason deterministically
        # Determine dominant rejection category
        has_safety = any(e["safety"] == "UNSAFE" for e in evaluations)
        has_insufficient_res = any(e["resources"] == "RESOURCE_INSUFFICIENT" for e in evaluations)
        has_version = any(e["version"] == "VERSION_INCOMPATIBLE" for e in evaluations)
        has_unavailable = any(e["availability"] in ["UNAVAILABLE", "MISSING", "DISABLED"] for e in evaluations)
        has_platform = any(e["platform"] == "INCOMPATIBLE" for e in evaluations)

        if has_safety:
            dominant_status = "SAFETY_REVIEW"
            rationale = "Candidate tools failed safety profile checks"
        elif has_insufficient_res:
            dominant_status = "RESOURCE_INSUFFICIENT"
            rationale = "Available host resources are insufficient to execute candidate tools"
        elif has_version:
            dominant_status = "VERSION_INCOMPATIBLE"
            rationale = "Installed candidate tool versions fail version constraints"
        elif has_unavailable:
            dominant_status = "TOOL_UNAVAILABLE"
            rationale = "Candidate tools exist for capability, but are missing, uninstalled, or disabled"
        elif has_platform:
            dominant_status = "NO_COMPATIBLE_TOOL"
            rationale = f"No candidate tools support host platform '{system_resources['platform']}'"
        else:
            dominant_status = "NO_COMPATIBLE_TOOL"
            rationale = "No candidate tools satisfied all compatibility and resource requirements"

        first_eval = evaluations[0]
        return {
            "selected_tool_id": None,
            "selection_status": dominant_status,
            "availability_status": first_eval["availability"],
            "evidence_compatibility": first_eval["evidence"],
            "platform_compatibility": first_eval["platform"],
            "resource_status": first_eval["resources"],
            "version_status": first_eval["version"],
            "safety_status": first_eval["safety"],
            "candidate_tools": candidate_ids,
            "rejection_reasons": rejections,
            "rationale": rationale
        }

    @classmethod
    def select_and_update_plan_tools(
        cls,
        db: Session,
        plan_id: str,
        actor_user: User
    ) -> Dict[str, Any]:
        """
        Executes capability/tool selection across all tasks for an InvestigationPlan.
        Persists ToolSelectionRecord entities and updates task statuses.
        """
        # Ensure default tools seeded
        seed_default_tools(db)

        plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"InvestigationPlan '{plan_id}' not found")

        tasks = (
            db.query(InvestigationTask)
            .filter(InvestigationTask.plan_id == plan.id)
            .order_by(InvestigationTask.sequence.asc())
            .all()
        )

        sys_res = get_system_resources()

        # Pre-fetch evidence items and intelligence
        evidence_map: Dict[str, EvidenceItem] = {}
        intel_map: Dict[str, EvidenceIntelligence] = {}
        for ev in db.query(EvidenceItem).filter(EvidenceItem.case_id == plan.case_id).all():
            evidence_map[ev.id] = ev
            intel = db.query(EvidenceIntelligence).filter(EvidenceIntelligence.evidence_id == ev.id).first()
            if intel:
                intel_map[ev.id] = intel

        # Clear existing tool selections for this plan
        db.query(ToolSelectionRecord).filter(ToolSelectionRecord.plan_id == plan.id).delete()

        selected_count = 0
        blocked_count = 0
        review_count = 0
        records: List[ToolSelectionRecord] = []

        for task in tasks:
            # Resolve primary evidence item if linked
            target_ev = None
            target_intel = None
            if task.evidence_ids and len(task.evidence_ids) > 0:
                first_ev_id = task.evidence_ids[0]
                target_ev = evidence_map.get(first_ev_id)
                target_intel = intel_map.get(first_ev_id)

            eval_res = cls.select_tool_for_task(
                db=db,
                task=task,
                evidence=target_ev,
                intel=target_intel,
                sys_res=sys_res
            )

            record = ToolSelectionRecord(
                plan_id=plan.id,
                task_id=task.id,
                task_key=task.task_key,
                capability_id=task.capability_id,
                evidence_id=target_ev.id if target_ev else None,
                candidate_tools=eval_res["candidate_tools"],
                selected_tool_id=eval_res["selected_tool_id"],
                selection_status=eval_res["selection_status"],
                availability_status=eval_res["availability_status"],
                evidence_compatibility=eval_res["evidence_compatibility"],
                platform_compatibility=eval_res["platform_compatibility"],
                resource_status=eval_res["resource_status"],
                version_status=eval_res["version_status"],
                safety_status=eval_res["safety_status"],
                rejection_reasons=eval_res["rejection_reasons"],
                selection_rationale=eval_res["rationale"],
                created_at=utc_now()
            )
            db.add(record)
            records.append(record)

            # Update InvestigationTask
            task.selected_tool_id = eval_res["selected_tool_id"]
            if eval_res["candidate_tools"]:
                task.candidate_tool_ids = eval_res["candidate_tools"]

            if eval_res["selection_status"] == "SELECTED":
                selected_count += 1
                # If dependencies are satisfied, ready for execution orchestration
                task.status = "READY"
                task.blocking_reason = None
            elif eval_res["selection_status"] in ["SAFETY_REVIEW", "REQUIRES_REVIEW"]:
                review_count += 1
                task.status = "REQUIRES_REVIEW"
                task.blocking_reason = eval_res["rationale"]
            else:
                blocked_count += 1
                task.status = "BLOCKED_NO_CAPABLE_TOOL"
                task.blocking_reason = eval_res["rationale"]

        # Audit selection event
        log_audit_event(
            db=db,
            event_type="PLAN_TOOL_SELECTION_COMPLETED",
            actor_id=actor_user.id if actor_user else None,
            actor_name=actor_user.name if actor_user else "strategy-engine",
            case_id=plan.case_id,
            details=(
                f"Tool selection completed for plan {plan.id}: "
                f"{selected_count} selected, {blocked_count} blocked, {review_count} requires review"
            )
        )

        db.commit()

        return {
            "plan_id": plan.id,
            "case_id": plan.case_id,
            "total_tasks": len(tasks),
            "selected_count": selected_count,
            "blocked_count": blocked_count,
            "review_count": review_count,
            "all_satisfied": (blocked_count == 0 and review_count == 0),
            "selections": [
                {
                    "id": r.id,
                    "plan_id": r.plan_id,
                    "task_id": r.task_id,
                    "task_key": r.task_key,
                    "capability_id": r.capability_id,
                    "evidence_id": r.evidence_id,
                    "candidate_tools": r.candidate_tools,
                    "selected_tool_id": r.selected_tool_id,
                    "selection_status": r.selection_status,
                    "availability_status": r.availability_status,
                    "evidence_compatibility": r.evidence_compatibility,
                    "platform_compatibility": r.platform_compatibility,
                    "resource_status": r.resource_status,
                    "version_status": r.version_status,
                    "safety_status": r.safety_status,
                    "rejection_reasons": r.rejection_reasons,
                    "selection_rationale": r.selection_rationale,
                    "created_at": r.created_at
                }
                for r in records
            ]
        }

    @classmethod
    def validate_registries(cls, db: Session) -> Dict[str, Any]:
        """
        Validates the capability and tool registries for consistency:
        - Orphaned capabilities (no tool supports)
        - Orphaned tools (declare capabilities not in registry)
        - Missing mandatory metadata
        - Disallowed binary violations
        """
        seed_default_tools(db)
        from backend.app.services.strategy_engine import seed_forensic_capabilities

        seed_forensic_capabilities(db)

        capabilities = db.query(ForensicCapability).all()
        tools = db.query(DBToolDefinition).all()

        cap_ids = {c.id for c in capabilities}
        tool_supported_caps = set()
        for t in tools:
            for c in (t.capabilities_json or []):
                tool_supported_caps.add(c)

        errors: List[str] = []
        warnings: List[str] = []

        # Check duplicate tool IDs
        seen_tools = set()
        for t in tools:
            if t.tool_id in seen_tools:
                errors.append(f"Duplicate tool ID found: '{t.tool_id}'")
            seen_tools.add(t.tool_id)

            # Check binary name safety
            bin_name = (t.binary_name or "").lower().strip()
            if bin_name in DISALLOWED_BINARIES:
                errors.append(f"Tool '{t.tool_id}' uses disallowed binary '{bin_name}'")

            # Missing mandatory fields
            if not t.name:
                errors.append(f"Tool '{t.tool_id}' lacks mandatory 'name' field")
            if not t.platforms:
                warnings.append(f"Tool '{t.tool_id}' defines no target platforms")

        # Orphaned capabilities: registered capabilities with no tool mapped
        orphaned_caps = sorted(list(cap_ids - tool_supported_caps))

        # Orphaned tools: tool capabilities pointing to non-existent capabilities
        orphaned_tools = []
        for t in tools:
            for c in (t.capabilities_json or []):
                if c not in cap_ids:
                    orphaned_tools.append(f"{t.tool_id} -> {c}")

        valid = len(errors) == 0

        return {
            "valid": valid,
            "total_capabilities": len(capabilities),
            "total_tools": len(tools),
            "orphaned_capabilities": orphaned_caps,
            "orphaned_tools": orphaned_tools,
            "errors": errors,
            "warnings": warnings
        }
