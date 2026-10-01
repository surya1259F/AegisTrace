"""
ADFIR — Specialist Agent Layer Subsystem (Phase 2 / Step 16)

Implements the controlled Specialist Agent framework. Specialist agents analyze approved
structured forensic data (from Steps 10-15) and request registered capabilities (through Step 7/8/9).
Agents NEVER execute arbitrary shell commands, invoke subprocesses directly, or invent unobserved facts.

Enforces:
- 11 Registered Specialist Agents
- Strict Agent Contract (Inputs, Capabilities, Observations, Confidence, Provenance)
- Capability Request Gate (Validates against Step 7 Registry; rejects unauthorized/direct execution)
- Deterministic Lifecycle Management (REGISTERED -> READY -> RUNNING -> COMPLETED/WAITING_CAPABILITY/FAILED/BLOCKED)
- Full Provenance & Traceability (7-tier linkage)
- Cryptographic SHA-256 Integrity Verification & Tamper Detection
- Isolated Case-Scoped Storage & Vault Write-Protection
- RBAC, Case Isolation, and IDOR Defense
"""

import os
import sys
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.models import (
    Case,
    EvidenceItem,
    ForensicCapability,
    NormalizedArtifact,
    TimelineEvent,
    ArtifactRelationship,
    DeterministicFinding,
    SpecialistAgentRecord,
    AgentAnalysisRequestRecord,
    AgentAnalysisResultRecord,
    AgentCapabilityRequestRecord,
    AgentLifecycleEvent,
    User
)
from backend.app.services.audit import log_audit_event
from backend.app.core.config import settings

# Import specialist agent classes
from agents.planner.planner_agent import InvestigationStrategyAgent
from agents.disk.disk_agent import DiskForensicsAgent
from agents.memory.memory_agent import MemoryForensicsAgent
from agents.malware.malware_agent import MalwareAnalysisAgent
from agents.windows.windows_agent import WindowsForensicsAgent
from agents.browser.browser_agent import BrowserForensicsAgent
from agents.linux.linux_agent import LinuxForensicsAgent
from agents.network.network_agent import NetworkForensicsAgent
from agents.correlation.correlation_agent import TimelineCorrelationAgent
from agents.verification.verification_agent import EvidenceVerificationAgent
from agents.report.report_agent import ReportSummaryAgent
from agents.base.agent import AgentSafetyProfile


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# 1. SPECIALIST AGENT SPECIFICATIONS (11 Specialist Agents)
# ============================================================

SPECIALIST_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "id": "agent-investigation-strategy",
        "name": "Investigation Strategy Agent",
        "version": "1.0.0",
        "agent_type": "STRATEGY",
        "description": "Plans evidence-driven forensic analysis, establishes hypotheses, and sequences investigative capabilities.",
        "supported_evidence_domains": ["STRATEGY", "PLANNING", "MULTI_DOMAIN", "CASE"],
        "supported_artifact_types": ["EVIDENCE", "FINDING", "ARTIFACT", "CORRELATION", "TIMELINE_EVENT"],
        "supported_analysis_capabilities": [
            "investigation_planning", "evidence_triage", "capability_sequencing", "case_assessment"
        ],
        "agent_class": InvestigationStrategyAgent
    },
    {
        "id": "agent-disk-forensics",
        "name": "Disk Forensics Agent",
        "version": "1.0.0",
        "agent_type": "DISK",
        "description": "Analyzes filesystem structures, directory trees, deleted files, and file metadata.",
        "supported_evidence_domains": ["DISK", "FILESYSTEM", "METADATA"],
        "supported_artifact_types": ["FILE", "DIRECTORY", "PARTITION", "METADATA", "FILESYSTEM"],
        "supported_analysis_capabilities": [
            "filesystem_analysis", "deleted_file_carving", "inode_lookup", "metadata_extraction",
            "FILESYSTEM_ANALYSIS", "DELETED_FILE_ANALYSIS", "FILE_METADATA_ANALYSIS", "PARTITION_ANALYSIS"
        ],
        "agent_class": DiskForensicsAgent
    },
    {
        "id": "agent-memory-forensics",
        "name": "Memory Forensics Agent",
        "version": "1.0.0",
        "agent_type": "MEMORY",
        "description": "Introspects kernel memory dumps, processes, network sockets, handles, and injected code.",
        "supported_evidence_domains": ["MEMORY", "VOLATILITY", "PROCESS", "NETWORK"],
        "supported_artifact_types": ["PROCESS", "THREAD", "HANDLE", "NETWORK_CONNECTION", "INJECTION", "DLL", "KERNEL_MODULE"],
        "supported_analysis_capabilities": [
            "process_listing", "network_scan", "dll_list", "malfind_injection", "memory_analysis",
            "MEMORY_ANALYSIS", "PROCESS_ANALYSIS", "MEMORY_PROCESS_ANALYSIS", "MEMORY_NETWORK_ANALYSIS"
        ],
        "agent_class": MemoryForensicsAgent
    },
    {
        "id": "agent-malware-analysis",
        "name": "Malware Analysis Agent",
        "version": "1.0.0",
        "agent_type": "MALWARE",
        "description": "Performs static binary analysis, YARA signature scanning, hash lookup, and string extraction.",
        "supported_evidence_domains": ["MALWARE", "SIGNATURE", "STATIC_ANALYSIS", "BINARY"],
        "supported_artifact_types": ["MALWARE_HIT", "YARA_HIT", "HASH", "STRING_EXTRACT", "SIGNATURE_MATCH", "PE_METADATA"],
        "supported_analysis_capabilities": [
            "yara_scanning", "file_hashing", "string_extraction", "malware_signature_verification",
            "STATIC_MALWARE_ANALYSIS", "YARA_RULE_SCAN"
        ],
        "agent_class": MalwareAnalysisAgent
    },
    {
        "id": "agent-windows-forensics",
        "name": "Windows Forensics Agent",
        "version": "1.0.0",
        "agent_type": "WINDOWS",
        "description": "Analyzes Windows artifacts including EVTX event logs, Registry, Prefetch, Amcache, Shimcache, SRUM, LNK, Jump Lists, and Defender.",
        "supported_evidence_domains": ["WINDOWS", "LOGS", "REGISTRY", "SYSTEM"],
        "supported_artifact_types": [
            "EVENT_LOG", "EVTX", "REGISTRY", "PREFETCH", "AMCACHE",
            "SHIMCACHE", "SRUM", "LNK", "JUMPLIST", "DEFENDER_ALERT"
        ],
        "supported_analysis_capabilities": [
            "evtx_analysis", "registry_analysis", "prefetch_analysis", "amcache_analysis",
            "shimcache_analysis", "srum_analysis", "lnk_analysis", "jumplist_analysis",
            "defender_alert_analysis", "security_event_audit",
            "WINDOWS_EVTX_ANALYSIS", "REGISTRY_ANALYSIS", "PREFETCH_EXECUTION_ANALYSIS"
        ],
        "agent_class": WindowsForensicsAgent
    },
    {
        "id": "agent-browser-forensics",
        "name": "Browser Forensics Agent",
        "version": "1.0.0",
        "agent_type": "BROWSER",
        "description": "Extracts web navigation history, downloads, cookies, cache, and session data across Chrome, Edge, and Firefox.",
        "supported_evidence_domains": ["BROWSER", "HISTORY", "DOWNLOADS", "WEB", "NETWORK"],
        "supported_artifact_types": [
            "BROWSER_HISTORY", "BROWSER_DOWNLOAD", "BROWSER_COOKIE",
            "BROWSER_CACHE", "BROWSER_SESSION", "URL", "WEB_VISIT"
        ],
        "supported_analysis_capabilities": [
            "history_extraction", "download_history", "cookie_analysis", "cache_analysis",
            "session_analysis", "browser_url_audit", "BROWSER_HISTORY_ANALYSIS"
        ],
        "agent_class": BrowserForensicsAgent
    },
    {
        "id": "agent-linux-forensics",
        "name": "Linux Forensics Agent",
        "version": "1.0.0",
        "agent_type": "LINUX",
        "description": "Analyzes Linux auth logs, journal/systemd, shell history, cron schedules, and persistence.",
        "supported_evidence_domains": ["LINUX", "LOGS", "AUTH", "SYSTEMD", "SHELL", "CRON"],
        "supported_artifact_types": [
            "AUTH_LOG", "SYSLOG", "JOURNALD", "BASH_HISTORY",
            "SHELL_HISTORY", "CRON_JOB", "SYSTEMD_SERVICE", "LINUX_PERSISTENCE"
        ],
        "supported_analysis_capabilities": [
            "auth_log_analysis", "journal_analysis", "shell_history_audit", "cron_audit",
            "linux_persistence_check", "LINUX_LOG_ANALYSIS", "SHELL_HISTORY_AUDIT", "CRON_AUDIT"
        ],
        "agent_class": LinuxForensicsAgent
    },
    {
        "id": "agent-network-forensics",
        "name": "Network Forensics Agent",
        "version": "1.0.0",
        "agent_type": "NETWORK",
        "description": "Analyzes PCAP network captures, flow records, DNS requests, HTTP transactions, and TLS sessions.",
        "supported_evidence_domains": ["NETWORK", "PCAP", "FLOW", "DNS", "HTTP", "TLS"],
        "supported_artifact_types": [
            "PACKET", "NETWORK_FLOW", "DNS_QUERY", "HTTP_REQUEST",
            "TLS_HANDSHAKE", "NETWORK_CONNECTION", "IP_ENDPOINT"
        ],
        "supported_analysis_capabilities": [
            "packet_dissection", "dns_lookup_analysis", "flow_reconstruction",
            "tls_metadata_extraction", "http_request_analysis",
            "PCAP_PACKET_DISSECTION", "NETWORK_FLOW_ANALYSIS"
        ],
        "agent_class": NetworkForensicsAgent
    },
    {
        "id": "agent-timeline-correlation",
        "name": "Timeline / Correlation Agent",
        "version": "1.0.0",
        "agent_type": "CORRELATION",
        "description": "Groups and links multi-domain events and artifacts into causal timeline sequences.",
        "supported_evidence_domains": ["TIMELINE", "CORRELATION", "CROSS_DOMAIN", "TEMPORAL"],
        "supported_artifact_types": [
            "TIMELINE_EVENT", "ARTIFACT_RELATIONSHIP", "CORRELATION_GROUP", "TEMPORAL_WINDOW"
        ],
        "supported_analysis_capabilities": [
            "entity_correlation", "temporal_alignment", "provenance_graph",
            "cross_domain_linking", "cluster_analysis", "TIMELINE_CORRELATION"
        ],
        "agent_class": TimelineCorrelationAgent
    },
    {
        "id": "agent-evidence-verification",
        "name": "Evidence Verification Agent",
        "version": "1.0.0",
        "agent_type": "VERIFICATION",
        "description": "Validates findings against evidence references, verifies cryptographic integrity, and checks for contradictions.",
        "supported_evidence_domains": ["VERIFICATION", "INTEGRITY", "PROVENANCE", "GROUND_TRUTH"],
        "supported_artifact_types": [
            "EVIDENCE_ITEM", "STRUCTURED_ARTIFACT", "NORMALIZED_ARTIFACT", "FINDING", "HASH_INTEGRITY"
        ],
        "supported_analysis_capabilities": [
            "ground_truth_validation", "conflict_detection", "confidence_scoring",
            "provenance_audit", "cryptographic_integrity_check", "PROVENANCE_AUDIT"
        ],
        "agent_class": EvidenceVerificationAgent
    },
    {
        "id": "agent-report-summary",
        "name": "Report / Summary Agent",
        "version": "1.0.0",
        "agent_type": "REPORT",
        "description": "Converts verified investigation state, findings, and timeline events into court-ready report content.",
        "supported_evidence_domains": ["REPORT", "SUMMARY", "EXECUTIVE", "COURT_READY"],
        "supported_artifact_types": [
            "FINDING", "EVIDENCE_ITEM", "TIMELINE_EVENT", "CORRELATION_GROUP", "REPORT_SECTION"
        ],
        "supported_analysis_capabilities": [
            "report_synthesis", "mitre_mapping", "remediation_planning",
            "executive_summary", "chain_of_custody_report", "REPORT_SYNTHESIS"
        ],
        "agent_class": ReportSummaryAgent
    }
]


# ============================================================
# 2. ISOLATED STORAGE & INTEGRITY MANAGER
# ============================================================

class AgentStorageManager:
    """
    Manages isolated, tamper-evident file-backed storage for agent requests and results.
    Strictly forbids writing into evidence vaults or executing path traversal.
    """

    @staticmethod
    def get_base_dir() -> Path:
        base = getattr(settings, "DATA_DIR", Path("/home/nandireddy/ADFIR/data"))
        return Path(base).resolve() / "storage" / "agents"

    @classmethod
    def get_case_dir(cls, case_id: str) -> Path:
        clean_case_id = str(case_id).strip().replace("/", "_").replace("\\", "_").replace("..", "")
        case_dir = cls.get_base_dir() / "cases" / clean_case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        # Ensure 0o700 permission
        try:
            os.chmod(case_dir, 0o700)
        except OSError:
            pass
        return case_dir

    @classmethod
    def save_json(cls, case_id: str, file_id: str, data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Saves data as canonical JSON with SHA-256 hash.
        Returns: (file_path_str, sha256_hash)
        """
        if ".." in str(file_id) or "/" in str(file_id) or "\\" in str(file_id):
            raise ValueError(f"Security Violation: Path traversal detected for file_id '{file_id}'.")

        clean_file_id = str(file_id).strip()
        case_dir = cls.get_case_dir(case_id)
        target_path = case_dir / f"{clean_file_id}.json"

        # Validate path stays within case_dir (Path Traversal defense)
        if not str(target_path.resolve()).startswith(str(case_dir.resolve())):
            raise ValueError(f"Security Violation: Path traversal detected for file_id '{file_id}'.")

        # Reject writing into vault directory
        resolved_str = str(target_path.resolve())
        if "/vault/" in resolved_str or resolved_str.endswith("/vault"):
            raise ValueError("Security Violation: Direct modification of evidence vault is prohibited.")

        canonical_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        with open(target_path, "wb") as f:
            f.write(canonical_bytes)

        try:
            os.chmod(target_path, 0o600)
        except OSError:
            pass

        return str(target_path), sha256

    @classmethod
    def load_json(cls, file_path: str) -> Tuple[Dict[str, Any], str]:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Agent storage file does not exist: {file_path}")

        with open(path, "rb") as f:
            raw_bytes = f.read()

        current_hash = hashlib.sha256(raw_bytes).hexdigest()
        data = json.loads(raw_bytes.decode("utf-8"))
        return data, current_hash


# ============================================================
# 3. CAPABILITY REQUEST GATE
# ============================================================

class CapabilityRequestGate:
    """
    Enforces the controlled flow:
    Agent -> Capability Request -> Step 7 Validation -> Step 8 Scheduler -> Step 9 Execution.
    Strictly forbids direct subprocess execution and arbitrary shell commands.
    """

    DANGEROUS_PARAM_KEYS = {
        "shell", "command", "cmd", "exec", "subprocess", "popen",
        "eval", "bash", "sh", "system", "script"
    }

    @classmethod
    def validate_capability_request(
        cls,
        db: Session,
        case_id: str,
        agent_record: SpecialistAgentRecord,
        capability_id: str,
        evidence_id: str,
        parameters: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates the capability request against Step 7 registered capabilities,
        agent authorization, case scoping, and command safety.
        Returns: (is_valid, error_message)
        """
        # 1. Evidence Verification & Case Scoping (IDOR Protection)
        evidence = db.query(EvidenceItem).filter(
            EvidenceItem.id == evidence_id,
            EvidenceItem.case_id == case_id
        ).first()

        if not evidence:
            return False, f"IDOR / Scoping Error: Evidence item '{evidence_id}' does not exist or does not belong to case '{case_id}'."

        # 2. Check for dangerous command execution parameters
        param_keys_lower = [str(k).lower() for k in parameters.keys()]
        for dk in cls.DANGEROUS_PARAM_KEYS:
            if dk in param_keys_lower:
                return False, f"Security Violation: Parameter '{dk}' is strictly prohibited. Direct shell execution is forbidden."

        # Check for shell metacharacters in parameter values
        for k, v in parameters.items():
            if isinstance(v, str):
                for ch in [";", "|", "&", "`", "$(", "${"]:
                    if ch in v:
                        return False, f"Security Violation: Shell metacharacter '{ch}' detected in parameter '{k}'. Direct commands forbidden."

        # 3. Agent Capability Authorization
        supported_caps = [c.upper() for c in (agent_record.supported_analysis_capabilities or [])]
        req_cap_upper = capability_id.upper()
        if req_cap_upper not in supported_caps and capability_id not in supported_caps:
            return False, f"Permission Error: Agent '{agent_record.name}' is not authorized to request capability '{capability_id}'."

        # 4. Step 7 Registered Forensic Capability Validation
        db_cap = db.query(ForensicCapability).filter(ForensicCapability.id == capability_id).first()
        if not db_cap:
            # Check upper case
            db_cap = db.query(ForensicCapability).filter(ForensicCapability.id == req_cap_upper).first()

        # If not in DB table, verify it is in known allowed forensic capabilities
        from backend.app.services.strategy_engine import DEFAULT_CAPABILITIES
        known_cap_ids = {c["id"].upper() for c in DEFAULT_CAPABILITIES}
        # Additional specialist capabilities
        known_specialist_caps = {
            "WINDOWS_EVTX_ANALYSIS", "REGISTRY_ANALYSIS", "PREFETCH_EXECUTION_ANALYSIS",
            "BROWSER_HISTORY_ANALYSIS", "LINUX_LOG_ANALYSIS", "SHELL_HISTORY_AUDIT",
            "CRON_AUDIT", "PCAP_PACKET_DISSECTION", "NETWORK_FLOW_ANALYSIS",
            "TIMELINE_CORRELATION", "PROVENANCE_AUDIT", "REPORT_SYNTHESIS",
            "STATIC_MALWARE_ANALYSIS", "YARA_RULE_SCAN", "FILESYSTEM_ANALYSIS",
            "MEMORY_ANALYSIS", "MEMORY_PROCESS_ANALYSIS", "MEMORY_NETWORK_ANALYSIS"
        }
        all_allowed_caps = known_cap_ids.union(known_specialist_caps)

        if not db_cap and (req_cap_upper not in all_allowed_caps and capability_id not in all_allowed_caps):
            return False, f"Registry Error: Capability '{capability_id}' is not registered in the Step 7 capability registry."

        if db_cap and not db_cap.enabled:
            return False, f"Capability Error: Capability '{capability_id}' is currently disabled in the registry."

        return True, None


# ============================================================
# 4. SPECIALIST AGENT SERVICE
# ============================================================

class SpecialistAgentService:
    """
    Central orchestration service for the Specialist Agent Layer (Phase 2 / Step 16).
    """

    @classmethod
    def ensure_seeded(cls, db: Session) -> int:
        """
        Seeds all 11 specialist agents into the database if not already present.
        Returns count of seeded agents.
        """
        seeded_count = 0
        for spec in SPECIALIST_AGENT_SPECS:
            existing = db.query(SpecialistAgentRecord).filter(
                SpecialistAgentRecord.id == spec["id"]
            ).first()

            if not existing:
                agent_inst = spec["agent_class"]()
                safety_dict = agent_inst.safety_profile.to_dict()

                agent_record = SpecialistAgentRecord(
                    id=spec["id"],
                    name=spec["name"],
                    version=spec["version"],
                    agent_type=spec["agent_type"],
                    description=spec["description"],
                    supported_evidence_domains=spec["supported_evidence_domains"],
                    supported_artifact_types=spec["supported_artifact_types"],
                    supported_analysis_capabilities=spec["supported_analysis_capabilities"],
                    is_enabled=True,
                    status="REGISTERED",
                    safety_permission_profile=safety_dict,
                    provenance={
                        "registered_by": "system",
                        "registered_at": utc_now().isoformat(),
                        "agent_class": spec["agent_class"].__name__,
                        "safety_enforced": True
                    }
                )
                db.add(agent_record)
                seeded_count += 1

        if seeded_count > 0:
            db.commit()

        return seeded_count

    @classmethod
    def list_agents(
        cls,
        db: Session,
        enabled_only: bool = False
    ) -> List[SpecialistAgentRecord]:
        cls.ensure_seeded(db)
        query = db.query(SpecialistAgentRecord)
        if enabled_only:
            query = query.filter(SpecialistAgentRecord.is_enabled == True)
        return query.order_by(SpecialistAgentRecord.id).all()

    @classmethod
    def get_agent(
        cls,
        db: Session,
        agent_id: str
    ) -> Optional[SpecialistAgentRecord]:
        cls.ensure_seeded(db)
        return db.query(SpecialistAgentRecord).filter(
            (SpecialistAgentRecord.id == agent_id) | (SpecialistAgentRecord.name == agent_id)
        ).first()

    @classmethod
    def toggle_agent(
        cls,
        db: Session,
        agent_id: str,
        is_enabled: bool,
        user: Optional[User] = None
    ) -> SpecialistAgentRecord:
        agent = cls.get_agent(db, agent_id)
        if not agent:
            raise ValueError(f"Agent with ID '{agent_id}' does not exist.")

        prev_status = agent.status
        agent.is_enabled = is_enabled
        agent.status = "ENABLED" if is_enabled else "DISABLED"
        agent.updated_at = utc_now()
        db.commit()
        db.refresh(agent)

        log_audit_event(
            db=db,
            event_type="TOGGLE_AGENT",
            details=f"Agent '{agent.id}' status changed from '{prev_status}' to '{agent.status}' (enabled={agent.is_enabled})",
            actor_id=str(user.id) if user and hasattr(user, "id") else None,
            actor_name=getattr(user, "email", "system") if user else "system",
            metadata_json={
                "target_type": "specialist_agent",
                "target_id": agent.id,
                "previous_status": prev_status,
                "new_status": agent.status,
                "is_enabled": agent.is_enabled
            }
        )
        return agent

    @classmethod
    def _record_lifecycle_event(
        cls,
        db: Session,
        case_id: str,
        agent_id: str,
        request_id: str,
        from_state: str,
        to_state: str,
        reason: str,
        details: Dict[str, Any]
    ) -> AgentLifecycleEvent:
        """
        Records a deterministic lifecycle event with cryptographic hash chaining.
        """
        now = utc_now()
        # Find previous event hash for this request
        last_event = db.query(AgentLifecycleEvent).filter(
            AgentLifecycleEvent.request_id == request_id
        ).order_by(desc(AgentLifecycleEvent.timestamp)).first()

        prev_hash = last_event.event_hash if last_event else "GENESIS"
        raw_to_hash = f"{prev_hash}:{case_id}:{agent_id}:{request_id}:{from_state}:{to_state}:{now.isoformat()}"
        event_hash = hashlib.sha256(raw_to_hash.encode("utf-8")).hexdigest()

        event = AgentLifecycleEvent(
            case_id=case_id,
            agent_id=agent_id,
            request_id=request_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            details=details,
            timestamp=now,
            event_hash=event_hash
        )
        db.add(event)
        return event

    @classmethod
    def create_analysis_request(
        cls,
        db: Session,
        case_id: str,
        agent_id: str,
        analysis_objective: str,
        evidence_id: Optional[str] = None,
        input_references: Optional[Dict[str, Any]] = None,
        user: Optional[User] = None
    ) -> AgentAnalysisRequestRecord:
        """
        Creates and persists a new analysis request for an agent within a case.
        """
        cls.ensure_seeded(db)

        # 1. Validate Case
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case with ID '{case_id}' does not exist.")

        # 2. Validate Agent
        agent = cls.get_agent(db, agent_id)
        if not agent:
            raise ValueError(f"Specialist agent '{agent_id}' does not exist.")

        if not agent.is_enabled:
            raise ValueError(f"Specialist agent '{agent.name}' is currently disabled.")

        # 3. Validate Evidence if specified
        if evidence_id:
            ev = db.query(EvidenceItem).filter(
                EvidenceItem.id == evidence_id,
                EvidenceItem.case_id == case_id
            ).first()
            if not ev:
                raise ValueError(f"Evidence item '{evidence_id}' does not exist or does not belong to case '{case_id}'.")

        request_id = str(uuid.uuid4())
        initial_provenance = {
            "requested_by": getattr(user, "email", "system") if user else "system",
            "case_id": case_id,
            "agent_id": agent.id,
            "agent_name": agent.name,
            "agent_version": agent.version,
            "created_at": utc_now().isoformat()
        }

        # Canonical initial hash
        req_repr = {
            "request_id": request_id,
            "case_id": case_id,
            "agent_id": agent.id,
            "evidence_id": evidence_id,
            "objective": analysis_objective
        }
        sha256 = hashlib.sha256(json.dumps(req_repr, sort_keys=True).encode("utf-8")).hexdigest()

        req_record = AgentAnalysisRequestRecord(
            id=request_id,
            case_id=case_id,
            agent_id=agent.id,
            agent_version=agent.version,
            evidence_id=evidence_id,
            analysis_objective=analysis_objective,
            lifecycle_state="READY",
            input_references=input_references or {},
            requested_capabilities=[],
            results_summary={},
            provenance=initial_provenance,
            sha256_hash=sha256
        )
        db.add(req_record)

        # Record Lifecycle transition: REGISTERED -> READY
        cls._record_lifecycle_event(
            db=db,
            case_id=case_id,
            agent_id=agent.id,
            request_id=request_id,
            from_state="REGISTERED",
            to_state="READY",
            reason="Analysis request created and initialized.",
            details={"objective": analysis_objective, "evidence_id": evidence_id}
        )

        db.commit()
        db.refresh(req_record)
        return req_record

    @classmethod
    def _gather_evidence_context(
        cls,
        db: Session,
        case_id: str,
        evidence_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Pulls approved case-scoped forensic data for the agent to analyze.
        Strictly scopes to the target case (cross-case isolation).
        """
        # 1. Evidence items
        ev_query = db.query(EvidenceItem).filter(EvidenceItem.case_id == case_id)
        if evidence_id:
            ev_query = ev_query.filter(EvidenceItem.id == evidence_id)
        evidence_items = [
            {
                "id": e.id,
                "name": e.name,
                "evidence_type": e.evidence_type,
                "storage_path": e.storage_path,
                "sha256_hash": e.sha256_hash,
                "status": e.status
            }
            for e in ev_query.all()
        ]

        # 2. Normalized Artifacts (Step 12)
        art_query = db.query(NormalizedArtifact).filter(NormalizedArtifact.case_id == case_id)
        if evidence_id:
            art_query = art_query.filter(NormalizedArtifact.evidence_id == evidence_id)
        normalized_artifacts = [
            {
                "id": a.id,
                "entity_type": a.entity_type,
                "normalized_fields": a.normalized_fields,
                "source_artifact_id": a.source_artifact_id,
                "evidence_id": a.evidence_id,
                "execution_id": a.execution_id,
                "provenance": a.provenance,
                "sha256_hash": a.sha256_hash
            }
            for a in art_query.all()
        ]

        # 3. Timeline Events (Step 13)
        timeline_events = [
            {
                "id": t.id,
                "utc_timestamp": t.timestamp_utc.isoformat() if t.timestamp_utc else None,
                "event_type": t.event_type,
                "event_source": t.event_source,
                "source_artifact_id": t.normalized_artifact_id,
                "evidence_id": t.evidence_id,
                "event_data": t.event_data,
                "confidence_score": t.confidence_score
            }
            for t in db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).order_by(TimelineEvent.timestamp_utc).all()
        ]

        # 4. Artifact Relationships (Step 14)
        relationships = [
            {
                "id": r.id,
                "relationship_type": r.relationship_type,
                "matching_identifier": r.matching_identifier,
                "source_artifact_id": r.source_artifact_id,
                "target_artifact_id": r.target_artifact_id,
                "evidence_references": r.evidence_references,
                "confidence_score": r.confidence_score
            }
            for r in db.query(ArtifactRelationship).filter(ArtifactRelationship.case_id == case_id).all()
        ]

        # 5. Deterministic Findings (Step 15)
        findings = [
            {
                "id": f.id,
                "finding_id": f.finding_id,
                "title": f.title,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "confidence_score": f.confidence_score,
                "supporting_artifact_ids": f.supporting_artifact_ids,
                "supporting_correlation_ids": f.supporting_correlation_ids,
                "provenance": f.provenance
            }
            for f in db.query(DeterministicFinding).filter(DeterministicFinding.case_id == case_id).all()
        ]

        return {
            "case_id": case_id,
            "evidence_items": evidence_items,
            "normalized_artifacts": normalized_artifacts,
            "timeline_events": timeline_events,
            "artifact_relationships": relationships,
            "deterministic_findings": findings
        }

    @classmethod
    def execute_analysis(
        cls,
        db: Session,
        request_id: str,
        user: Optional[User] = None
    ) -> AgentAnalysisResultRecord:
        """
        Executes an agent analysis request deterministically:
        1. Transition to RUNNING
        2. Gather approved case evidence context
        3. Instantiate agent and run `analyze_structured_data(context)`
        4. Validate capability requests through CapabilityRequestGate
        5. Persist result and state transitions
        6. Compute and store canonical SHA-256 hash
        """
        req = db.query(AgentAnalysisRequestRecord).filter(
            AgentAnalysisRequestRecord.id == request_id
        ).first()

        if not req:
            raise ValueError(f"Analysis request with ID '{request_id}' does not exist.")

        agent_record = db.query(SpecialistAgentRecord).filter(
            SpecialistAgentRecord.id == req.agent_id
        ).first()

        if not agent_record:
            raise ValueError(f"Specialist agent '{req.agent_id}' does not exist.")

        # Transition: READY -> RUNNING
        prev_state = req.lifecycle_state
        req.lifecycle_state = "RUNNING"
        req.updated_at = utc_now()
        cls._record_lifecycle_event(
            db=db,
            case_id=req.case_id,
            agent_id=req.agent_id,
            request_id=req.id,
            from_state=prev_state,
            to_state="RUNNING",
            reason="Execution started by execution engine.",
            details={"agent": agent_record.name}
        )
        db.commit()

        try:
            # Find agent class
            spec = next((s for s in SPECIALIST_AGENT_SPECS if s["id"] == agent_record.id), None)
            if not spec:
                raise ValueError(f"Specialist agent class for '{agent_record.id}' is not registered in system.")

            agent_instance = spec["agent_class"]()

            # Gather approved case-scoped evidence context
            context_data = cls._gather_evidence_context(db, req.case_id, req.evidence_id)

            # Execute agent analysis
            analysis_output = agent_instance.analyze_structured_data(context_data, context={"request_id": req.id})

            # Process capability requests through the CapabilityRequestGate
            cap_requests_records = []
            validated_caps = []
            for cap_req in analysis_output.capability_requests:
                cap_id = cap_req.get("capability_id")
                ev_id = cap_req.get("evidence_id") or req.evidence_id
                params = cap_req.get("parameters") or {}
                rationale = cap_req.get("rationale") or f"Requested by {agent_record.name}"
                priority = cap_req.get("priority", 1)

                if ev_id:
                    is_valid, err_msg = CapabilityRequestGate.validate_capability_request(
                        db=db,
                        case_id=req.case_id,
                        agent_record=agent_record,
                        capability_id=cap_id,
                        evidence_id=ev_id,
                        parameters=params
                    )

                    cap_record_id = str(uuid.uuid4())
                    raw_cap_repr = {
                        "id": cap_record_id,
                        "case_id": req.case_id,
                        "agent_id": agent_record.id,
                        "capability_id": cap_id,
                        "evidence_id": ev_id,
                        "parameters": params
                    }
                    cap_hash = hashlib.sha256(json.dumps(raw_cap_repr, sort_keys=True).encode("utf-8")).hexdigest()

                    cap_record = AgentCapabilityRequestRecord(
                        id=cap_record_id,
                        case_id=req.case_id,
                        agent_id=agent_record.id,
                        request_id=req.id,
                        capability_id=cap_id,
                        evidence_id=ev_id,
                        parameters=params,
                        rationale=rationale,
                        priority=priority,
                        validation_status="VALIDATED" if is_valid else "REJECTED",
                        validation_error=err_msg,
                        provenance={
                            "requested_by_agent": agent_record.name,
                            "agent_version": agent_record.version,
                            "validated_at": utc_now().isoformat(),
                            "validation_status": "VALIDATED" if is_valid else "REJECTED"
                        },
                        sha256_hash=cap_hash
                    )
                    db.add(cap_record)
                    cap_requests_records.append(cap_record)
                    if is_valid:
                        validated_caps.append(cap_id)

            # Persist Result Record
            result_id = str(uuid.uuid4())
            result_dict = {
                "id": result_id,
                "request_id": req.id,
                "case_id": req.case_id,
                "agent_id": agent_record.id,
                "agent_version": agent_record.version,
                "analysis_type": analysis_output.analysis_type,
                "observations": analysis_output.observations,
                "capability_requests": [
                    {
                        "capability_id": c.capability_id,
                        "evidence_id": c.evidence_id,
                        "status": c.validation_status,
                        "error": c.validation_error
                    }
                    for c in cap_requests_records
                ],
                "supporting_evidence_ids": analysis_output.supporting_evidence_ids,
                "supporting_artifact_ids": analysis_output.supporting_artifact_ids,
                "supporting_correlation_ids": analysis_output.supporting_correlation_ids,
                "supporting_finding_ids": analysis_output.supporting_finding_ids,
                "confidence_inputs": analysis_output.confidence_inputs,
                "confidence_score": analysis_output.confidence_score,
                "summary": analysis_output.summary,
                "provenance": analysis_output.provenance
            }

            # Save to isolated storage
            storage_path, result_hash = AgentStorageManager.save_json(
                case_id=req.case_id,
                file_id=result_id,
                data=result_dict
            )

            result_record = AgentAnalysisResultRecord(
                id=result_id,
                request_id=req.id,
                case_id=req.case_id,
                agent_id=agent_record.id,
                agent_version=agent_record.version,
                analysis_type=analysis_output.analysis_type,
                observations=analysis_output.observations,
                capability_requests=[
                    {
                        "capability_id": c.capability_id,
                        "evidence_id": c.evidence_id,
                        "status": c.validation_status,
                        "error": c.validation_error
                    }
                    for c in cap_requests_records
                ],
                supporting_evidence_ids=analysis_output.supporting_evidence_ids,
                supporting_artifact_ids=analysis_output.supporting_artifact_ids,
                supporting_correlation_ids=analysis_output.supporting_correlation_ids,
                supporting_finding_ids=analysis_output.supporting_finding_ids,
                confidence_inputs=analysis_output.confidence_inputs,
                confidence_score=analysis_output.confidence_score,
                provenance=analysis_output.provenance,
                sha256_hash=result_hash,
                storage_path=storage_path
            )
            db.add(result_record)

            # Update Request lifecycle state
            # If valid capability requests are pending execution -> WAITING_CAPABILITY, else COMPLETED
            next_state = "WAITING_CAPABILITY" if validated_caps else "COMPLETED"
            req.lifecycle_state = next_state
            req.requested_capabilities = [c.capability_id for c in cap_requests_records]
            req.results_summary = {
                "result_id": result_id,
                "observations_count": len(analysis_output.observations),
                "summary": analysis_output.summary,
                "confidence_score": analysis_output.confidence_score,
                "validated_capabilities": validated_caps
            }
            req.completed_at = utc_now() if next_state == "COMPLETED" else None
            req.updated_at = utc_now()

            cls._record_lifecycle_event(
                db=db,
                case_id=req.case_id,
                agent_id=req.agent_id,
                request_id=req.id,
                from_state="RUNNING",
                to_state=next_state,
                reason=f"Analysis completed. Generated {len(analysis_output.observations)} observations and {len(cap_requests_records)} capability requests.",
                details={"result_id": result_id, "validated_capabilities": validated_caps}
            )

            db.commit()
            db.refresh(result_record)
            return result_record

        except Exception as e:
            req.lifecycle_state = "FAILED"
            req.error_message = str(e)
            req.updated_at = utc_now()
            cls._record_lifecycle_event(
                db=db,
                case_id=req.case_id,
                agent_id=req.agent_id,
                request_id=req.id,
                from_state="RUNNING",
                to_state="FAILED",
                reason=f"Execution failed with error: {str(e)}",
                details={"error": str(e)}
            )
            db.commit()
            raise

    @classmethod
    def submit_capability_request(
        cls,
        db: Session,
        case_id: str,
        agent_id: str,
        request_id: str,
        capability_id: str,
        evidence_id: str,
        parameters: Dict[str, Any],
        rationale: str,
        priority: int = 1,
        user: Optional[User] = None
    ) -> AgentCapabilityRequestRecord:
        """
        Explicit capability submission gate. Validates request and persists gate record.
        """
        # Validate agent
        agent = cls.get_agent(db, agent_id)
        if not agent:
            raise ValueError(f"Specialist agent '{agent_id}' does not exist.")

        # Validate request
        analysis_req = db.query(AgentAnalysisRequestRecord).filter(
            AgentAnalysisRequestRecord.id == request_id,
            AgentAnalysisRequestRecord.case_id == case_id
        ).first()
        if not analysis_req:
            raise ValueError(f"Analysis request '{request_id}' not found for case '{case_id}'.")

        # Validate capability
        is_valid, err_msg = CapabilityRequestGate.validate_capability_request(
            db=db,
            case_id=case_id,
            agent_record=agent,
            capability_id=capability_id,
            evidence_id=evidence_id,
            parameters=parameters
        )

        cap_id = str(uuid.uuid4())
        raw_cap_repr = {
            "id": cap_id,
            "case_id": case_id,
            "agent_id": agent.id,
            "capability_id": capability_id,
            "evidence_id": evidence_id,
            "parameters": parameters
        }
        cap_hash = hashlib.sha256(json.dumps(raw_cap_repr, sort_keys=True).encode("utf-8")).hexdigest()

        cap_record = AgentCapabilityRequestRecord(
            id=cap_id,
            case_id=case_id,
            agent_id=agent.id,
            request_id=request_id,
            capability_id=capability_id,
            evidence_id=evidence_id,
            parameters=parameters,
            rationale=rationale,
            priority=priority,
            validation_status="VALIDATED" if is_valid else "REJECTED",
            validation_error=err_msg,
            provenance={
                "submitted_by": getattr(user, "email", "system") if user else "system",
                "agent_name": agent.name,
                "agent_version": agent.version,
                "submitted_at": utc_now().isoformat()
            },
            sha256_hash=cap_hash
        )
        db.add(cap_record)

        if not is_valid:
            # Record BLOCKED or rejected lifecycle event
            cls._record_lifecycle_event(
                db=db,
                case_id=case_id,
                agent_id=agent.id,
                request_id=request_id,
                from_state=analysis_req.lifecycle_state,
                to_state="BLOCKED",
                reason=f"Capability request '{capability_id}' rejected by Gate: {err_msg}",
                details={"error": err_msg, "capability_id": capability_id}
            )
            analysis_req.lifecycle_state = "BLOCKED"

        db.commit()
        db.refresh(cap_record)
        return cap_record

    @classmethod
    def verify_result_integrity(
        cls,
        db: Session,
        result_id: str
    ) -> Dict[str, Any]:
        """
        Cryptographic integrity check for an agent analysis result.
        Validates database hash against disk storage hash.
        """
        result = db.query(AgentAnalysisResultRecord).filter(
            AgentAnalysisResultRecord.id == result_id
        ).first()

        if not result:
            raise ValueError(f"Agent analysis result '{result_id}' does not exist.")

        if not result.storage_path or not os.path.exists(result.storage_path):
            return {
                "result_id": result_id,
                "status": "MISSING_STORAGE_FILE",
                "is_intact": False,
                "db_hash": result.sha256_hash,
                "current_hash": None,
                "error": f"Storage file '{result.storage_path}' is missing."
            }

        with open(result.storage_path, "rb") as f:
            current_bytes = f.read()

        current_hash = hashlib.sha256(current_bytes).hexdigest()
        is_intact = (current_hash == result.sha256_hash)

        return {
            "result_id": result_id,
            "status": "VERIFIED" if is_intact else "TAMPER_DETECTED",
            "is_intact": is_intact,
            "db_hash": result.sha256_hash,
            "current_hash": current_hash,
            "verified_at": utc_now().isoformat()
        }

    @classmethod
    def get_provenance_trace(
        cls,
        db: Session,
        request_id: str
    ) -> Dict[str, Any]:
        """
        Full 7-tier provenance trace for an agent analysis request:
        Evidence -> Execution -> Raw Output -> Structured Artifact -> Normalized Artifact -> Timeline / Finding -> Agent Analysis -> Capability Request
        """
        req = db.query(AgentAnalysisRequestRecord).filter(
            AgentAnalysisRequestRecord.id == request_id
        ).first()

        if not req:
            raise ValueError(f"Analysis request '{request_id}' not found.")

        results = db.query(AgentAnalysisResultRecord).filter(
            AgentAnalysisResultRecord.request_id == request_id
        ).all()

        cap_requests = db.query(AgentCapabilityRequestRecord).filter(
            AgentCapabilityRequestRecord.request_id == request_id
        ).all()

        events = db.query(AgentLifecycleEvent).filter(
            AgentLifecycleEvent.request_id == request_id
        ).order_by(AgentLifecycleEvent.timestamp).all()

        return {
            "request_id": req.id,
            "case_id": req.case_id,
            "agent_id": req.agent_id,
            "agent_version": req.agent_version,
            "lifecycle_state": req.lifecycle_state,
            "sha256_hash": req.sha256_hash,
            "provenance": req.provenance,
            "lifecycle_history": [
                {
                    "from_state": e.from_state,
                    "to_state": e.to_state,
                    "reason": e.reason,
                    "timestamp": e.timestamp.isoformat(),
                    "event_hash": e.event_hash
                }
                for e in events
            ],
            "results": [
                {
                    "result_id": r.id,
                    "analysis_type": r.analysis_type,
                    "sha256_hash": r.sha256_hash,
                    "confidence_score": r.confidence_score,
                    "supporting_evidence_ids": r.supporting_evidence_ids,
                    "supporting_artifact_ids": r.supporting_artifact_ids,
                    "supporting_correlation_ids": r.supporting_correlation_ids,
                    "supporting_finding_ids": r.supporting_finding_ids,
                    "storage_path": r.storage_path
                }
                for r in results
            ],
            "capability_requests": [
                {
                    "capability_id": c.capability_id,
                    "evidence_id": c.evidence_id,
                    "validation_status": c.validation_status,
                    "validation_error": c.validation_error,
                    "sha256_hash": c.sha256_hash
                }
                for c in cap_requests
            ]
        }
