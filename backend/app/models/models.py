import uuid
import json
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Float,
    Integer,
    ForeignKey,
    JSON,
    Boolean,
    BigInteger
)
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    """
    Authenticated investigator or analyst in the forensic workstation.
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    organization = Column(String, default="Digital Forensics Unit", nullable=False)
    badge_id = Column(String, nullable=True)
    role = Column(String, default="INVESTIGATOR", nullable=False) # ADMIN, INVESTIGATOR, ANALYST, VIEWER
    is_active = Column(Boolean, default=True, nullable=False)
    password_hash = Column(String, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case_memberships = relationship("CaseMember", back_populates="user", cascade="all, delete-orphan")
    decisions = relationship("InvestigatorDecision", back_populates="investigator")
    audit_events = relationship("AuditEvent", back_populates="actor")
    ai_provider_configs = relationship("AIProviderConfigRecord", back_populates="user", cascade="all, delete-orphan")
    investigator_reviews = relationship("InvestigatorReviewRecord", back_populates="investigator")

    @property
    def roles(self):
        return [self.role] if self.role else ["INVESTIGATOR"]

    @property
    def permissions(self):
        from backend.app.services.authorization import get_role_permissions
        return get_role_permissions(self.role)

class Case(Base):
    """
    Core Case / Investigation container.
    """
    __tablename__ = "cases"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    objective = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    case_type = Column(String, default="GENERIC_INCIDENT", nullable=False)
    priority = Column(String, default="MEDIUM", nullable=False)
    status = Column(String, default="OPEN", nullable=False, index=True) # DRAFT, OPEN, CLOSED, ARCHIVED
    owner_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    created_by = Column(String, default="local-investigator", nullable=False)
    workspace_state = Column(String, default="NOT_INITIALIZED", nullable=False) # NOT_INITIALIZED, INITIALIZING, READY, FAILED
    workspace_path = Column(String, nullable=True)
    case_permissions = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    closed_at = Column(DateTime, nullable=True)
    closed_by = Column(String, nullable=True)
    closure_rationale = Column(Text, nullable=True)
    closure_metadata = Column(JSON, default=dict)
    closure_hash = Column(String(64), nullable=True)

    members = relationship("CaseMember", back_populates="case", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceItem", back_populates="case", cascade="all, delete-orphan")
    acquisitions = relationship("EvidenceAcquisition", back_populates="case", cascade="all, delete-orphan")
    custody_events = relationship("ChainOfCustodyEvent", back_populates="case", cascade="all, delete-orphan")
    executions = relationship("ToolExecution", back_populates="case", cascade="all, delete-orphan")
    artifacts = relationship("ExecutionArtifact", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    correlation_groups = relationship("CorrelationGroup", back_populates="case", cascade="all, delete-orphan")
    decisions = relationship("InvestigatorDecision", back_populates="case", cascade="all, delete-orphan")
    plans = relationship("InvestigationPlan", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="case", cascade="all, delete-orphan")
    analysis_requests = relationship("AnalysisRequest", back_populates="case", cascade="all, delete-orphan")
    forensic_executions = relationship("ForensicExecution", back_populates="case", cascade="all, delete-orphan")
    execution_outputs = relationship("ExecutionOutput", back_populates="case", cascade="all, delete-orphan")
    structured_artifacts = relationship("StructuredArtifact", back_populates="case", cascade="all, delete-orphan")
    normalized_artifacts = relationship("NormalizedArtifact", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    artifact_relationships = relationship("ArtifactRelationship", back_populates="case", cascade="all, delete-orphan")
    forensic_correlation_groups = relationship("ForensicCorrelationGroup", back_populates="case", cascade="all, delete-orphan")
    deterministic_findings = relationship("DeterministicFinding", back_populates="case", cascade="all, delete-orphan")
    agent_analysis_requests = relationship("AgentAnalysisRequestRecord", back_populates="case", cascade="all, delete-orphan")
    agent_analysis_results = relationship("AgentAnalysisResultRecord", back_populates="case", cascade="all, delete-orphan")
    agent_capability_requests = relationship("AgentCapabilityRequestRecord", back_populates="case", cascade="all, delete-orphan")
    agent_lifecycle_events = relationship("AgentLifecycleEvent", back_populates="case", cascade="all, delete-orphan")
    governance_decisions = relationship("GovernanceDecisionRecord", back_populates="case", cascade="all, delete-orphan")
    evidence_verifications = relationship("EvidenceVerificationRecord", back_populates="case", cascade="all, delete-orphan")
    governance_audit_events = relationship("GovernanceAuditEvent", back_populates="case", cascade="all, delete-orphan")
    ai_provider_configs = relationship("AIProviderConfigRecord", back_populates="case", cascade="all, delete-orphan")
    ai_reasoning_records = relationship("AIReasoningRecord", back_populates="case", cascade="all, delete-orphan")
    investigator_reviews = relationship("InvestigatorReviewRecord", back_populates="case", cascade="all, delete-orphan")
    investigation_runs = relationship("InvestigationRun", back_populates="case", cascade="all, delete-orphan")

    @property
    def title(self):
        return self.name

    @title.setter
    def title(self, value):
        self.name = value

    @property
    def investigator(self):
        return self.created_by

    @investigator.setter
    def investigator(self, value):
        self.created_by = value

# Investigation is aliased to Case for full architectural compatibility
Investigation = Case

class CaseMember(Base):
    """
    Associates an investigator/user with a specific Case.
    """
    __tablename__ = "case_members"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String, default="PRIMARY_INVESTIGATOR", nullable=False)
    added_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="members")
    user = relationship("User", back_populates="case_memberships")

class EvidenceAcquisition(Base):
    """
    Tracks an evidence acquisition session (single file, directory recursive, disk image, memory dump, EVTX, PCAP, Browser DB).
    """
    __tablename__ = "evidence_acquisitions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    acquisition_type = Column(String, nullable=False) # SINGLE_FILE, DIRECTORY, DISK_IMAGE, MEMORY_DUMP, EVTX, BROWSER, PCAP
    source_path = Column(String, nullable=False)
    total_files = Column(Integer, default=1, nullable=False)
    total_bytes = Column(BigInteger, default=0, nullable=False)
    successful_files = Column(Integer, default=0, nullable=False)
    failed_files = Column(Integer, default=0, nullable=False)
    manifest_hash = Column(String, nullable=True) # SHA256 of the manifest JSON
    status = Column(String, default="IN_PROGRESS", nullable=False, index=True) # IN_PROGRESS, COMPLETED, FAILED, PARTIAL
    error_message = Column(Text, nullable=True)
    created_by_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="acquisitions")
    created_by_user = relationship("User")
    evidence_items = relationship("EvidenceItem", back_populates="acquisition")

class EvidenceItem(Base):
    """
    Immutable forensic evidence container.
    """
    __tablename__ = "evidence_items"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    parent_acquisition_id = Column(String, ForeignKey("evidence_acquisitions.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    original_path = Column(String, nullable=False)
    storage_path = Column(String, nullable=True)
    evidence_type = Column(String, nullable=False) # DISK_IMAGE, MEMORY_DUMP, WINDOWS_EVENT_LOG, REGISTRY_HIVE, SQLITE_DATABASE, BROWSER_ARTIFACT, PE_EXECUTABLE, ELF_EXECUTABLE, ARCHIVE, DOCUMENT, IMAGE, TEXT, GENERIC_BINARY, UNKNOWN
    evidence_subtype = Column(String, nullable=True)
    source_kind = Column(String, default="FILE", nullable=False) # FILE, DIRECTORY, DISK_IMAGE, MEMORY_DUMP, EVENT_LOG, BROWSER_DB, ARCHIVE, MALWARE_SAMPLE, GENERIC_BINARY, UNKNOWN
    acquisition_method = Column(String, default="INVESTIGATOR_IMPORT", nullable=False) # INVESTIGATOR_IMPORT, FORENSIC_ACQUISITION, TOOL_EXTRACT
    detected_format = Column(String, nullable=True)
    filesystem_type = Column(String, nullable=True)
    platform_hint = Column(String, nullable=True)
    size_bytes = Column(Float, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    md5 = Column(String, nullable=True)
    mime_type = Column(String, default="application/octet-stream")
    status = Column(String, default="REGISTERED", nullable=False, index=True) # REGISTERED, PRESERVING, PRESERVED, VERIFYING, VERIFIED, INTEGRITY_WARNING, INVALID, ANALYSIS_READY, ARCHIVED
    intake_status = Column(String, default="INTAKE_COMPLETE", nullable=False) # INTAKE_COMPLETE, QUARANTINED, ARCHIVED
    integrity_status = Column(String, default="VERIFIED", nullable=False) # VERIFIED, FAILED, UNCHECKED, MISSING, INTEGRITY_MISMATCH
    read_only_verified = Column(Boolean, default=True, nullable=False)
    notes = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict)
    intelligence_json = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    created_by = Column(String, default="local-investigator", nullable=False)
    acquired_at = Column(DateTime, default=utc_now, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    modified_at = Column(DateTime, default=utc_now, nullable=False)

    # Property wrappers for backward compatibility and domain alias access
    # investigation_id property for backward compatibility
    @property
    def original_name(self):
        return self.name

    @original_name.setter
    def original_name(self, value):
        self.name = value

    @property
    def preserved_path(self):
        return self.storage_path

    @preserved_path.setter
    def preserved_path(self, value):
        self.storage_path = value

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    @property
    def file_name(self):
        return self.name

    @file_name.setter
    def file_name(self, value):
        self.name = value

    @property
    def file_path(self):
        return self.original_path

    @file_path.setter
    def file_path(self, value):
        self.original_path = value

    @property
    def sha256_hash(self):
        return self.sha256

    @sha256_hash.setter
    def sha256_hash(self, value):
        self.sha256 = value

    @property
    def md5_hash(self):
        return self.md5

    @md5_hash.setter
    def md5_hash(self, value):
        self.md5 = value

    @property
    def chain_of_custody_log(self):
        return getattr(self, "_chain_of_custody_log", [])

    @chain_of_custody_log.setter
    def chain_of_custody_log(self, value):
        self._chain_of_custody_log = value

    @property
    def metadata_info(self):
        if self.metadata_json is not None and isinstance(self.metadata_json, dict):
            return self.metadata_json
        return getattr(self, "_metadata_info", {})

    @metadata_info.setter
    def metadata_info(self, value):
        self._metadata_info = value
        if isinstance(value, dict):
            self.metadata_json = value

    case = relationship("Case", back_populates="evidence_items", overlaps="case,evidence_items")
    investigation = relationship("Case", overlaps="case,evidence_items")
    acquisition = relationship("EvidenceAcquisition", back_populates="evidence_items")
    intelligence_profile = relationship("EvidenceIntelligence", uselist=False, back_populates="evidence_item", cascade="all, delete-orphan")
    custody_events = relationship("ChainOfCustodyEvent", back_populates="evidence", cascade="all, delete-orphan")
    executions = relationship("ToolExecution", back_populates="evidence", cascade="all, delete-orphan")
    artifacts = relationship("ExecutionArtifact", back_populates="evidence", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="evidence", cascade="all, delete-orphan")
    forensic_executions = relationship("ForensicExecution", back_populates="evidence")
    execution_outputs = relationship("ExecutionOutput", back_populates="evidence")
    structured_artifacts = relationship("StructuredArtifact", back_populates="evidence")
    normalized_artifacts = relationship("NormalizedArtifact", back_populates="evidence")
    timeline_events = relationship("TimelineEvent", back_populates="evidence")

# Evidence is aliased to EvidenceItem for full backward compatibility
Evidence = EvidenceItem

class EvidenceIntelligence(Base):
    """
    Deterministic Evidence Intelligence Profile.
    Persists evidence classification, subtype, header signatures, platform/architecture hints,
    filesystem detection, characteristics, structured tags, tool mapping, and resource profiles.
    """
    __tablename__ = "evidence_intelligence"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = Column(String, ForeignKey("evidence_items.id"), unique=True, nullable=False, index=True)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    engine_version = Column(String, default="1.0.0", nullable=False)
    analysis_version = Column(Integer, default=1, nullable=False)

    classification = Column(String, nullable=False, index=True)
    subtype = Column(String, nullable=True, index=True)
    classification_status = Column(String, default="MATCH", nullable=False) # MATCH, MISMATCH, UNKNOWN, PARTIAL
    classification_confidence = Column(String, default="DETERMINISTIC", nullable=False) # DETERMINISTIC, HIGH, MEDIUM, LOW, UNKNOWN
    classification_basis = Column(Text, nullable=True)

    detected_format = Column(String, nullable=False, index=True)
    detected_mime = Column(String, default="application/octet-stream", nullable=False)

    platform_hint = Column(String, default="UNKNOWN", nullable=False) # WINDOWS, LINUX, MACOS, ANDROID, IOS, UNKNOWN
    platform_basis = Column(Text, nullable=True)
    platform_confidence = Column(String, default="UNKNOWN", nullable=False) # DETERMINISTIC, HIGH, MEDIUM, LOW, UNKNOWN
    architecture_hint = Column(String, default="UNKNOWN", nullable=False) # x86, x86_64, ARM, ARM64, MIPS, UNKNOWN

    filesystem_type = Column(String, default="UNKNOWN", nullable=False) # NTFS, FAT12, FAT16, FAT32, EXFAT, EXT2, EXT3, EXT4, HFS_PLUS, APFS, UNKNOWN
    filesystem_version = Column(String, nullable=True)
    filesystem_basis = Column(Text, nullable=True)
    filesystem_detection_status = Column(String, default="NOT_PRESENT", nullable=False) # DETECTED, NOT_PRESENT, UNSUPPORTED, CORRUPTED, UNKNOWN
    partition_table_type = Column(String, default="NONE", nullable=False) # MBR, GPT, RAW, UNKNOWN, NONE
    partitions_json = Column(JSON, default=list)

    metadata_json = Column(JSON, default=dict)
    characteristics_json = Column(JSON, default=dict)
    detection_methods = Column(JSON, default=list)
    tags_json = Column(JSON, default=list)
    resource_profile_json = Column(JSON, default=dict)
    recommended_tools_json = Column(JSON, default=list)
    recommended_families_json = Column(JSON, default=list)
    limitations_json = Column(JSON, default=list)

    evidence_sha256_verified = Column(String, nullable=False)
    generated_at = Column(DateTime, default=utc_now, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    evidence_item = relationship("EvidenceItem", back_populates="intelligence_profile")
    case = relationship("Case")

class ChainOfCustodyEvent(Base):
    """
    Append-only immutable chain of custody record with cryptographic chaining.
    """
    __tablename__ = "chain_of_custody_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id"), nullable=False, index=True)
    actor_id = Column(String, nullable=False, default="local-investigator")
    actor = Column(String, default="local-investigator", nullable=False)
    event_type = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    description = Column(Text, nullable=False)
    source_path = Column(String, nullable=True)
    destination_path = Column(String, nullable=True)
    sha256 = Column(String, nullable=True)
    metadata_json = Column(JSON, default=dict)
    previous_event_hash = Column(String, nullable=True)
    event_hash = Column(String, nullable=True)

    case = relationship("Case", back_populates="custody_events")
    evidence = relationship("EvidenceItem", back_populates="custody_events")

    @property
    def action(self):
        return self.event_type

    @action.setter
    def action(self, value):
        self.event_type = value

    @property
    def notes(self):
        return self.description

    @notes.setter
    def notes(self, value):
        self.description = value

class ToolDefinition(Base):
    """
    Registered local forensic executable definitions.
    """
    __tablename__ = "tool_definitions"

    tool_id = Column(String, primary_key=True) # sleuthkit_fls, volatility3, yara, python_evtx, exiftool
    name = Column(String, nullable=False)
    display_name = Column(String, nullable=True)
    binary_name = Column(String, nullable=True)
    version = Column(String, nullable=True)
    executable_path = Column(String, nullable=False)
    platforms = Column(JSON, default=list) # ["linux", "windows", "darwin"]
    supported_evidence = Column(JSON, default=list) # ["disk_image", "memory_dump", "log", etc.]
    supported_formats = Column(JSON, default=list) # ["raw", "e01", "pcap", "evtx", etc.]
    capabilities_json = Column(JSON, default=list) # List of supported capability IDs
    resource_requirements = Column(JSON, default=dict) # {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100}
    min_version = Column(String, nullable=True)
    max_version = Column(String, nullable=True)
    dependencies = Column(JSON, default=list)
    safety_profile = Column(JSON, default=dict)
    enabled = Column(Boolean, default=True, nullable=False)
    is_available = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    @property
    def id(self):
        return self.tool_id

    @id.setter
    def id(self, value):
        self.tool_id = value

class ToolExecution(Base):
    """
    Real-time process execution record for a forensic tool invocation.
    """
    __tablename__ = "tool_executions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id"), nullable=False, index=True)
    tool_id = Column(String, nullable=False, index=True)
    command_args = Column(JSON, default=list)
    status = Column(String, default="QUEUED", nullable=False, index=True) # QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, TIMED_OUT
    exit_code = Column(Integer, nullable=True)
    stdout_path = Column(String, nullable=True)
    stderr_path = Column(String, nullable=True)
    execution_time_ms = Column(Float, nullable=True)
    operator_id = Column(String, default="local-investigator", nullable=False)
    error_message = Column(Text, nullable=True)
    pid = Column(Integer, nullable=True)
    process_start_time = Column(Float, nullable=True)
    timeout_seconds = Column(Integer, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    cancelled_by = Column(String, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="executions")
    evidence = relationship("EvidenceItem", back_populates="executions")
    artifacts = relationship("ExecutionArtifact", back_populates="execution", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="execution")

class ExecutionArtifact(Base):
    """
    Every raw discovered object/entry extracted from evidence.
    Separated strictly from 'Finding' (which represents anomalous/candidate findings).
    """
    __tablename__ = "execution_artifacts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id"), nullable=False, index=True)
    execution_id = Column(String, ForeignKey("tool_executions.id"), nullable=True, index=True)
    agent = Column(String, nullable=False) # DiskAgent, MemoryAgent, MalwareAgent, LogAgent
    tool = Column(String, nullable=False) # SleuthKit, Volatility3, YARA, python-evtx, ExifTool
    artifact_type = Column(String, nullable=False, index=True) # filesystem_entry, process_entry, network_connection, signature_match, event_log
    source_reference = Column(String, nullable=False) # inode:4, pid:1044, rule:rule_name, record:1002
    path = Column(String, nullable=True)
    inode = Column(String, nullable=True)
    size_bytes = Column(Float, nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)
    metadata_json = Column(JSON, default=dict)
    raw_output_reference = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    case = relationship("Case", back_populates="artifacts", overlaps="artifacts,case")
    investigation = relationship("Case", overlaps="artifacts,case")
    evidence = relationship("EvidenceItem", back_populates="artifacts")
    execution = relationship("ToolExecution", back_populates="artifacts")

# Artifact is aliased to ExecutionArtifact for backward compatibility
Artifact = ExecutionArtifact

class Finding(Base):
    """
    Represents an evidence-backed candidate finding or security-relevant artifact.
    Must have concrete provenance linking it to evidence and execution.
    """
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id"), nullable=True, index=True)
    execution_id = Column(String, ForeignKey("tool_executions.id"), nullable=True, index=True)
    artifact_id = Column(String, ForeignKey("execution_artifacts.id"), nullable=True, index=True)
    agent = Column(String, nullable=False, default="GenericAgent") # DiskAgent, MemoryAgent, MalwareAgent, LogAgent, CorrelationEngine
    tool = Column(String, nullable=False, default="GenericTool") # SleuthKit, Volatility3, YARA, python-evtx, DeterministicCorrelation
    finding_type = Column(String, nullable=False, default="generic_finding", index=True) # filesystem_artifact, process_artifact, network_artifact, malware_signature, log_event
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, default="MEDIUM", nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    classification = Column(String, default="FACT", nullable=False) # FACT, INFERENCE, UNVERIFIED
    confidence = Column(Float, nullable=True) # null if unscored
    timestamp = Column(DateTime, nullable=True)
    evidence_reference = Column(String, nullable=True) # inode, memory offset, record ID, file path
    verification_status = Column(String, default="UNVERIFIED", nullable=False, index=True) # SUPPORTED, UNSUPPORTED, CONFLICTING, UNVERIFIED
    raw_output_reference = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    @property
    def details(self):
        if hasattr(self, "_details") and self._details is not None:
            return self._details
        if self.raw_output_reference:
            try:
                parsed = json.loads(self.raw_output_reference)
                if isinstance(parsed, dict):
                    if "details" in parsed and isinstance(parsed["details"], dict):
                        return parsed["details"]
                    return parsed
            except Exception:
                pass
        if self.description:
            try:
                import ast
                parsed = ast.literal_eval(self.description)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {}

    @details.setter
    def details(self, value):
        self._details = value
        if isinstance(value, dict) and not self.raw_output_reference:
            try:
                self.raw_output_reference = json.dumps(value)
            except Exception:
                pass

    @property
    def mitre_techniques(self):
        if hasattr(self, "_mitre_techniques") and self._mitre_techniques is not None:
            return self._mitre_techniques
        if self.raw_output_reference:
            try:
                parsed = json.loads(self.raw_output_reference)
                if isinstance(parsed, dict) and "mitre_techniques" in parsed and isinstance(parsed["mitre_techniques"], list):
                    return parsed["mitre_techniques"]
            except Exception:
                pass
        return []

    @mitre_techniques.setter
    def mitre_techniques(self, value):
        self._mitre_techniques = value

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    @property
    def source_tool(self):
        return self.tool

    @source_tool.setter
    def source_tool(self, value):
        self.tool = value

    @property
    def category(self):
        return self.finding_type

    @category.setter
    def category(self, value):
        self.finding_type = value

    @property
    def confidence_score(self):
        return self.confidence

    @confidence_score.setter
    def confidence_score(self, value):
        self.confidence = value

    @property
    def agent_type(self):
        return self.agent

    @agent_type.setter
    def agent_type(self, value):
        self.agent = value

    case = relationship("Case", back_populates="findings", overlaps="case,findings")
    investigation = relationship("Case", overlaps="case,findings")
    evidence = relationship("EvidenceItem", back_populates="findings")
    execution = relationship("ToolExecution", back_populates="findings")

class CorrelationGroup(Base):
    """
    Correlated cluster of cross-domain entities across disk, memory, malware, and logs.
    """
    __tablename__ = "correlation_groups"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    dimension = Column(String, nullable=False) # process_name, ip_address, file_hash, user_account, threat_indicator, forensic_reference
    rule = Column(String, nullable=True) # SHARED_IP, SHARED_PROCESS, SHARED_ACCOUNT, SHARED_HASH, SHARED_INDICATOR, SHARED_FORENSIC_OBJECT
    correlated_entity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    tools_involved = Column(JSON, default=list)
    supporting_finding_ids = Column(JSON, default=list)
    supporting_artifact_ids = Column(JSON, default=list)
    supporting_evidence_ids = Column(JSON, default=list)
    correlation_confidence = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    case = relationship("Case", back_populates="correlation_groups")

class InvestigatorDecision(Base):
    """
    Mandatory Human Decision Gate record.
    Authorizes official report generation.
    """
    __tablename__ = "investigator_decisions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    investigator_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    investigator_name = Column(String, nullable=False)
    decision = Column(String, nullable=False, index=True) # CONFIRM, REJECT, INCONCLUSIVE, REQUEST_MORE_EVIDENCE
    rationale = Column(Text, nullable=False)
    finding_ids = Column(JSON, default=list)
    evidence_ids = Column(JSON, default=list)
    timestamp = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="decisions")
    investigator = relationship("User", back_populates="decisions")
    reports = relationship("Report", back_populates="decision")

class InvestigationPlan(Base):
    """
    Defines investigative objectives, strategy, and ordered forensic execution tasks.
    Persisted state tracks task lifecycles (PLANNED, READY, RUNNING, COMPLETED, FAILED, CANCELLED).
    """
    __tablename__ = "investigation_plans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    parent_plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=True, index=True)
    title = Column(String, nullable=True)
    strategy_summary = Column(Text, nullable=True)
    tasks = Column(JSON, default=list) # Ordered list of planned task dicts
    objectives = Column(JSON, default=list) # List of strategy bullets
    scope_definition = Column(Text, nullable=True)
    priority = Column(String, default="MEDIUM") # LOW, MEDIUM, HIGH, URGENT
    status = Column(String, default="PLANNED", nullable=False) # PLANNED, READY, RUNNING, COMPLETED, FAILED, PARTIALLY_COMPLETED, REQUIRES_REVIEW
    validation_status = Column(String, default="VALIDATED", nullable=False) # VALIDATED, NEEDS_REVIEW, INVALID, ADJUSTED
    evidence_snapshot = Column(JSON, default=list)
    resource_snapshot = Column(JSON, default=dict)
    stopping_conditions_summary = Column(JSON, default=list)
    change_reason = Column(Text, nullable=True)
    created_by = Column(String, default="strategy-engine", nullable=False)
    version = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    completed_at = Column(DateTime, nullable=True)

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    @property
    def strategy(self):
        return getattr(self, "_strategy", {
            "strategy_summary": self.strategy_summary,
            "tasks": self.tasks,
            "objectives": self.objectives
        })

    @strategy.setter
    def strategy(self, value):
        self._strategy = value
        if isinstance(value, dict):
            if "strategy_summary" in value:
                self.strategy_summary = value["strategy_summary"]
            if "tasks" in value:
                self.tasks = value["tasks"]
            elif "planned_tasks" in value:
                self.tasks = value["planned_tasks"]
            elif "steps" in value:
                self.tasks = value["steps"]

    @property
    def objective(self):
        return self.objectives[0] if self.objectives else self.strategy_summary

    @objective.setter
    def objective(self, value):
        self.strategy_summary = str(value)
        self.objectives = [str(value)]

    case = relationship("Case", back_populates="plans")
    plan_tasks = relationship("InvestigationTask", back_populates="plan", cascade="all, delete-orphan")
    plan_dependencies = relationship("InvestigationTaskDependency", back_populates="plan", cascade="all, delete-orphan")
    stopping_conditions = relationship("PlanStoppingCondition", back_populates="plan", cascade="all, delete-orphan")
    adjustments = relationship("PlanAdjustment", back_populates="plan", cascade="all, delete-orphan")
    tool_selections = relationship("ToolSelectionRecord", back_populates="plan", cascade="all, delete-orphan")
    analysis_requests = relationship("AnalysisRequest", back_populates="plan", cascade="all, delete-orphan")
    investigation_runs = relationship("InvestigationRun", back_populates="plan")


class InvestigationRun(Base):
    """
    Step 21 Persistent Investigation Runtime & Execution Coordinator.
    Coordinates the full forensic pipeline from Evidence/Strategy down to Final Report.
    Tracks cycle numbers, stages, stage progression, timestamps, errors, and cancellation/pause states.
    Supports deterministic restart/recovery and tamper detection.
    """
    __tablename__ = "investigation_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(String, ForeignKey("investigation_plans.id", ondelete="SET NULL"), nullable=True, index=True)
    cycle_number = Column(Integer, default=1, nullable=False)
    current_stage = Column(String, default="STRATEGY", nullable=False, index=True)
    status = Column(String, default="PENDING", nullable=False, index=True) # PENDING, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED, INTERRUPTED, RECOVERED
    stage_progress = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    failure_count = Column(Integer, default=0, nullable=False)
    run_metadata = Column(JSON, default=dict)
    sha256_hash = Column(String(64), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String, default="system", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="investigation_runs")
    plan = relationship("InvestigationPlan", back_populates="investigation_runs")
    tasks = relationship("InvestigationTask", back_populates="run", cascade="all, delete-orphan")


class ForensicCapability(Base):
    """
    Registered Forensic Capability Definition.
    """
    __tablename__ = "forensic_capabilities"

    id = Column(String, primary_key=True) # e.g. FILESYSTEM_ANALYSIS
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String, nullable=False) # DISK, MEMORY, LOG, NETWORK, MALWARE, BROWSER, METADATA, CORRELATION
    supported_evidence_categories = Column(JSON, default=list)
    supported_evidence_subtypes = Column(JSON, default=list)
    supported_formats = Column(JSON, default=list)
    supported_platforms = Column(JSON, default=list)
    required_inputs = Column(JSON, default=list)
    expected_outputs = Column(JSON, default=list)
    prerequisites = Column(JSON, default=list)
    resource_profile = Column(JSON, default=dict)
    priority_hints = Column(JSON, default=dict)
    version = Column(String, default="1.0.0", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

class InvestigationTask(Base):
    """
    Normalized persisted task within an InvestigationPlan.
    """
    __tablename__ = "investigation_tasks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=True, index=True)
    task_key = Column(String, default=lambda: f"task-{uuid.uuid4().hex[:8]}", nullable=False, index=True) # e.g. task-disk-a1b2c3d4
    sequence = Column(Integer, default=1, nullable=False)
    capability_id = Column(String, default="FORENSIC_ANALYSIS", nullable=False, index=True)
    agent_name = Column(String, default="ForensicAgent", nullable=False)
    evidence_ids = Column(JSON, default=list)
    candidate_tool_ids = Column(JSON, default=list)
    selected_tool_id = Column(String, nullable=True)
    priority_level = Column(String, default="MEDIUM", nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, BLOCKED
    priority_score = Column(Float, default=0.5, nullable=False)
    priority_rationale = Column(JSON, default=dict)
    status = Column(String, default="PLANNED", nullable=False, index=True) # PLANNED, READY, RUNNING, COMPLETED, FAILED, BLOCKED_NO_CAPABLE_TOOL, BLOCKED_INTEGRITY_FAILURE, DEFERRED, REQUIRES_REVIEW
    required_inputs = Column(JSON, default=list)
    expected_outputs = Column(JSON, default=list)
    resource_requirements = Column(JSON, default=dict)
    estimated_cost = Column(JSON, default=dict)
    rationale = Column(JSON, default=dict)
    blocking_reason = Column(Text, nullable=True)
    stopping_conditions_json = Column(JSON, default=list)
    run_id = Column(String, ForeignKey("investigation_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    plan = relationship("InvestigationPlan", back_populates="plan_tasks")
    run = relationship("InvestigationRun", back_populates="tasks")
    tool_selections = relationship("ToolSelectionRecord", back_populates="task", cascade="all, delete-orphan")
    analysis_requests = relationship("AnalysisRequest", back_populates="task", cascade="all, delete-orphan")

    @property
    def task_type(self):
        return self.capability_id

    @task_type.setter
    def task_type(self, value):
        self.capability_id = value

    @property
    def tool_id(self):
        return self.selected_tool_id

    @tool_id.setter
    def tool_id(self, value):
        self.selected_tool_id = value

    @property
    def priority(self):
        return self.priority_score

    @priority.setter
    def priority(self, value):
        self.priority_score = float(value)

class InvestigationTaskDependency(Base):
    """
    Explicit dependency relationship between tasks in an InvestigationPlan.
    """
    __tablename__ = "investigation_task_dependencies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=False, index=True)
    parent_task_id = Column(String, nullable=False, index=True)
    child_task_id = Column(String, nullable=False, index=True)
    dependency_type = Column(String, default="TASK_TO_TASK", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    plan = relationship("InvestigationPlan", back_populates="plan_dependencies")

class PlanStoppingCondition(Base):
    """
    Structured stopping condition records for an InvestigationPlan.
    """
    __tablename__ = "plan_stopping_conditions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=False, index=True)
    condition_code = Column(String, nullable=False, index=True)
    trigger_description = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    severity = Column(String, default="INFO", nullable=False)
    human_review_required = Column(Boolean, default=False, nullable=False)
    triggered_at = Column(DateTime, default=utc_now, nullable=False)

    plan = relationship("InvestigationPlan", back_populates="stopping_conditions")

class PlanAdjustment(Base):
    """
    Audit log of automatic or manual plan adjustments during review.
    """
    __tablename__ = "plan_adjustments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=False, index=True)
    adjustment_type = Column(String, nullable=False)
    summary = Column(Text, nullable=False)
    previous_state = Column(JSON, default=dict)
    new_state = Column(JSON, default=dict)
    actor_id = Column(String, default="strategy-engine", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    plan = relationship("InvestigationPlan", back_populates="adjustments")

class ToolSelectionRecord(Base):
    """
    Persisted evaluation and selection result of a forensic tool for an investigation task.
    """
    __tablename__ = "tool_selections"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=False, index=True)
    task_id = Column(String, ForeignKey("investigation_tasks.id"), nullable=True, index=True)
    task_key = Column(String, nullable=False, index=True)
    capability_id = Column(String, nullable=False, index=True)
    evidence_id = Column(String, nullable=True, index=True)
    candidate_tools = Column(JSON, default=list)
    selected_tool_id = Column(String, nullable=True)
    selection_status = Column(String, nullable=False, index=True) # SELECTED, NO_COMPATIBLE_TOOL, TOOL_UNAVAILABLE, RESOURCE_INSUFFICIENT, VERSION_INCOMPATIBLE, SAFETY_REVIEW, REQUIRES_REVIEW
    availability_status = Column(String, nullable=False) # AVAILABLE, UNAVAILABLE, DISABLED, MISSING, INCOMPATIBLE, REQUIRES_REVIEW
    evidence_compatibility = Column(String, nullable=False) # COMPATIBLE, INCOMPATIBLE, REQUIRES_REVIEW
    platform_compatibility = Column(String, nullable=False) # COMPATIBLE, INCOMPATIBLE, REQUIRES_REVIEW
    resource_status = Column(String, nullable=False) # RESOURCE_OK, RESOURCE_CONSTRAINED, RESOURCE_INSUFFICIENT
    version_status = Column(String, nullable=False) # VERSION_OK, VERSION_UNKNOWN, VERSION_INCOMPATIBLE
    safety_status = Column(String, nullable=False) # SAFE, UNSAFE, SAFETY_UNKNOWN, REQUIRES_REVIEW
    rejection_reasons = Column(JSON, default=dict)
    selection_rationale = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    plan = relationship("InvestigationPlan", back_populates="tool_selections")
    task = relationship("InvestigationTask", back_populates="tool_selections")


class AnalysisRequest(Base):
    """
    Persistent analysis job request managed by the Resource-Aware Scheduler (Phase 2 / Step 8).
    Bridges validated Step 7 Tool Selection with future Step 9 Execution.
    Tracks state, dependencies, system resource allocations, timeout, and retry policies.
    """
    __tablename__ = "analysis_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    plan_id = Column(String, ForeignKey("investigation_plans.id"), nullable=True, index=True)
    task_id = Column(String, ForeignKey("investigation_tasks.id"), nullable=True, index=True)
    task_key = Column(String, default=lambda: f"task-{uuid.uuid4().hex[:8]}", nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id"), nullable=True, index=True)
    capability_id = Column(String, default="FORENSIC_ANALYSIS", nullable=False, index=True)
    selected_tool_id = Column(String, default="volatility3", nullable=False, index=True)
    resource_requirements = Column(JSON, default=dict) # {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100}
    priority_level = Column(String, default="MEDIUM", nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    priority_score = Column(Float, default=0.5, nullable=False)
    timeout_seconds = Column(Integer, default=300, nullable=False)
    retry_policy = Column(JSON, default=lambda: {"max_retries": 3, "retry_count": 0, "retry_delay_seconds": 60, "backoff_factor": 2.0, "is_retryable": True})
    dependencies = Column(JSON, default=list) # List of required parent task_key / task_id
    scheduler_status = Column(String, default="QUEUED", nullable=False, index=True) # QUEUED, WAITING_DEPENDENCY, WAITING_RESOURCE, READY, RUNNING, CANCELLED, TIMEOUT, FAILED, COMPLETED, RETRY_PENDING, BLOCKED
    allocated_resources = Column(JSON, default=dict) # {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100}
    blocking_reason = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
    queued_at = Column(DateTime, default=utc_now, nullable=False)
    ready_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="analysis_requests")
    plan = relationship("InvestigationPlan", back_populates="analysis_requests")
    task = relationship("InvestigationTask", back_populates="analysis_requests")
    evidence = relationship("EvidenceItem")

    @property
    def tool_id(self):
        return self.selected_tool_id

    @tool_id.setter
    def tool_id(self, value):
        self.selected_tool_id = value
    executions = relationship("ForensicExecution", back_populates="request", cascade="all, delete-orphan")
    outputs = relationship("ExecutionOutput", back_populates="request", cascade="all, delete-orphan")


class ForensicExecution(Base):
    """
    Real-time process execution record and provenance for a forensic tool invocation (Phase 2 / Step 9).
    Bridges READY analysis requests from Step 8 to verified output artifacts.
    Enforces argv-only list execution, shell=False, strict workspace isolation, bounded stdout/stderr capture,
    authoritative process identity monitoring, and immutable provenance.
    """
    __tablename__ = "forensic_executions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String, ForeignKey("analysis_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(String, ForeignKey("investigation_plans.id", ondelete="CASCADE"), nullable=True, index=True)
    task_id = Column(String, ForeignKey("investigation_tasks.id", ondelete="CASCADE"), nullable=True, index=True)
    task_key = Column(String, default=lambda: f"task-{uuid.uuid4().hex[:8]}", nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    tool_id = Column(String, nullable=False, index=True)
    tool_version = Column(String, nullable=True)
    executable_path = Column(String, default="/usr/bin/tool", nullable=False)
    validated_argv = Column(JSON, default=list, nullable=False)
    host_platform = Column(String, default="linux", nullable=False)
    host_architecture = Column(String, default="x86_64", nullable=False)
    workspace_path = Column(String, default="/tmp/adfir-workspace", nullable=False)
    resource_allocation = Column(JSON, default=dict)
    timeout_seconds = Column(Integer, default=300, nullable=False)
    execution_status = Column(String, default="STARTING", nullable=False, index=True) # STARTING, RUNNING, COMPLETED, FAILED, TIMEOUT, CANCELLED, RESOURCE_LIMIT, BLOCKED
    exit_code = Column(Integer, nullable=True)
    pid = Column(Integer, nullable=True)
    process_start_time = Column(Float, nullable=True)
    stdout_path = Column(String, nullable=True)
    stderr_path = Column(String, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    cancellation_reason = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
    output_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="forensic_executions")
    request = relationship("AnalysisRequest", back_populates="executions")
    evidence = relationship("EvidenceItem", back_populates="forensic_executions")
    outputs = relationship("ExecutionOutput", back_populates="execution", cascade="all, delete-orphan")
    structured_artifacts = relationship("StructuredArtifact", back_populates="execution", cascade="all, delete-orphan")
    normalized_artifacts = relationship("NormalizedArtifact", back_populates="execution", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="execution", cascade="all, delete-orphan")

    @property
    def tool_name(self):
        return self.tool_id

    @tool_name.setter
    def tool_name(self, value):
        self.tool_id = value

    @property
    def status(self):
        return self.execution_status

    @status.setter
    def status(self, value):
        self.execution_status = value

    @property
    def capability_requested(self):
        return self.task_key

    @capability_requested.setter
    def capability_requested(self, value):
        self.task_key = value

    @property
    def parameters(self):
        return {"validated_argv": self.validated_argv}


class ExecutionOutput(Base):
    """
    Verified raw forensic output artifact produced in the isolated workspace by ForensicExecution (Phase 2 / Step 10).
    Represents raw evidence-derived data (NOT a conclusion).
    Strictly isolated outside the evidence vault; SHA-256 hashed and registered with execution provenance.
    """
    __tablename__ = "execution_outputs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String, ForeignKey("forensic_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    request_id = Column(String, ForeignKey("analysis_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    task_id = Column(String, nullable=True, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    tool_id = Column(String, nullable=True, index=True)
    tool_version = Column(String, nullable=True)
    output_type = Column(String, default="TOOL_OUTPUT", nullable=False, index=True) # TOOL_OUTPUT, STDOUT, STDERR, LOG
    filename = Column(String, nullable=False)
    relative_path = Column(String, nullable=False)
    storage_path = Column(String, nullable=False)
    size_bytes = Column(BigInteger, default=0, nullable=False)
    sha256_hash = Column(String, nullable=False, index=True)
    mime_type = Column(String, nullable=True)
    exit_code = Column(Integer, nullable=True)
    execution_status = Column(String, nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    execution = relationship("ForensicExecution", back_populates="outputs")
    request = relationship("AnalysisRequest", back_populates="outputs")
    case = relationship("Case", back_populates="execution_outputs")
    evidence = relationship("EvidenceItem", back_populates="execution_outputs")


class StructuredArtifact(Base):
    """
    Structured forensic artifact extracted from raw forensic outputs (Phase 2 / Step 11).
    Evidence-derived data without subjective interpretations or conclusions.
    """
    __tablename__ = "structured_artifacts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    execution_id = Column(String, ForeignKey("forensic_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    raw_output_id = Column(String, ForeignKey("execution_outputs.id", ondelete="CASCADE"), nullable=False, index=True)
    request_id = Column(String, ForeignKey("analysis_requests.id", ondelete="SET NULL"), nullable=True, index=True)
    task_id = Column(String, nullable=True, index=True)
    tool_id = Column(String, nullable=True, index=True)
    tool_version = Column(String, nullable=True)

    parser_name = Column(String, nullable=False, index=True)
    parser_version = Column(String, default="1.0.0", nullable=False)
    artifact_type = Column(String, nullable=False, index=True)
    source_reference = Column(String, nullable=True)
    normalized_data = Column(JSON, default=dict, nullable=False)
    raw_record = Column(Text, nullable=True)

    sha256_hash = Column(String(64), nullable=False, index=True)
    source_raw_output_hash = Column(String(64), nullable=False)

    storage_path = Column(String, nullable=True)
    extraction_status = Column(String, default="EXTRACTED", nullable=False, index=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="structured_artifacts")
    evidence = relationship("EvidenceItem", back_populates="structured_artifacts")
    execution = relationship("ForensicExecution", back_populates="structured_artifacts")
    raw_output = relationship("ExecutionOutput")
    request = relationship("AnalysisRequest")
    normalized_artifacts = relationship("NormalizedArtifact", back_populates="source_artifact", cascade="all, delete-orphan")


class NormalizedArtifact(Base):
    """
    Standardized, comparable forensic artifact entity produced by Phase 2 / Step 12 Artifact Normalization.
    Common schema for cross-tool, cross-domain forensic analysis without interpretation or conclusions.
    Maintains deterministic entity identity, multi-source provenance, and cryptographic integrity.
    """
    __tablename__ = "normalized_artifacts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    execution_id = Column(String, ForeignKey("forensic_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    source_artifact_id = Column(String, ForeignKey("structured_artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    raw_output_id = Column(String, ForeignKey("execution_outputs.id", ondelete="SET NULL"), nullable=True, index=True)
    request_id = Column(String, ForeignKey("analysis_requests.id", ondelete="SET NULL"), nullable=True, index=True)
    task_id = Column(String, nullable=True, index=True)

    entity_type = Column(String, nullable=False, index=True) # FILE, PROCESS, NETWORK_CONNECTION, EVENT, MALWARE_MATCH, METADATA, GENERIC, UNSUPPORTED
    entity_identity = Column(String(128), nullable=False, index=True) # Deterministic fingerprint from key fields
    source_specific_identity = Column(String, nullable=True) # e.g. inode:1234, pid:4, rule:mimikatz

    normalized_fields = Column(JSON, default=dict, nullable=False)
    evidence_reference = Column(JSON, default=dict, nullable=False) # {id, name, type, sha256}
    provenance_summary = Column(JSON, default=dict, nullable=False) # {tool_id, tool_version, parser_name, parser_version}

    contributing_source_artifact_ids = Column(JSON, default=list, nullable=False) # list of StructuredArtifact IDs
    occurrence_count = Column(Integer, default=1, nullable=False)

    entity_timestamp = Column(DateTime, nullable=True, index=True)
    sha256_hash = Column(String(64), nullable=False, index=True)
    source_artifact_hash = Column(String(64), nullable=False)

    storage_path = Column(String, nullable=True)
    normalization_status = Column(String, default="NORMALIZED", nullable=False, index=True) # NORMALIZED, PARTIAL_IDENTITY, UNSUPPORTED
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="normalized_artifacts")
    evidence = relationship("EvidenceItem", back_populates="normalized_artifacts")
    execution = relationship("ForensicExecution", back_populates="normalized_artifacts")
    source_artifact = relationship("StructuredArtifact", back_populates="normalized_artifacts")
    raw_output = relationship("ExecutionOutput")
    request = relationship("AnalysisRequest")
    timeline_events = relationship("TimelineEvent", back_populates="normalized_artifact", cascade="all, delete-orphan")

    @property
    def canonical_identifier(self):
        return self.entity_identity

    @canonical_identifier.setter
    def canonical_identifier(self, value):
        self.entity_identity = value

    @property
    def is_deduplicated(self):
        return self.occurrence_count > 1


class TimelineEvent(Base):
    """
    Unified UTC investigation timeline event (Phase 2 / Step 13).
    Converts timestamped normalized artifacts into an ordered, trustworthy temporal representation.
    Preserves exact original timestamp and timezone metadata without inventing missing timestamps.
    Maintains end-to-end cryptographic lineage back to evidence and execution.
    """
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    execution_id = Column(String, ForeignKey("forensic_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    normalized_artifact_id = Column(String, ForeignKey("normalized_artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    structured_artifact_id = Column(String, ForeignKey("structured_artifacts.id", ondelete="SET NULL"), nullable=True, index=True)

    timestamp_utc = Column(DateTime, nullable=False, index=True)
    original_timestamp = Column(String, nullable=False)
    original_timezone = Column(String, nullable=True)
    timezone_offset = Column(String, nullable=True)
    timezone_source = Column(String, nullable=True)
    timezone_status = Column(String, default="EXPLICIT", nullable=False) # EXPLICIT, AMBIGUOUS, UNKNOWN

    event_type = Column(String, nullable=False, index=True) # FILE_MODIFIED, FILE_CREATED, FILE_ACCESSED, PROCESS_LAUNCH, NETWORK_CONNECTION, EVENT_LOG, MALWARE_DISCOVERY, METADATA_TIMESTAMP, GENERIC_EVENT
    event_source = Column(String, nullable=False, index=True) # FLS, EVTX, PSLIST, NETSCAN, YARA, EXIFTOOL, GENERIC
    event_data = Column(JSON, default=dict, nullable=False)

    confidence_score = Column(Float, default=1.0, nullable=False, index=True) # 0.0 - 1.0 (temporal quality/provenance only)
    temporal_precision = Column(String, default="SECOND", nullable=False, index=True) # EXACT, SECOND, MINUTE, HOUR, DAY, UNKNOWN
    window_start_utc = Column(DateTime, nullable=True)
    window_end_utc = Column(DateTime, nullable=True)

    sha256_hash = Column(String(64), nullable=False, index=True)
    source_artifact_hash = Column(String(64), nullable=False)
    storage_path = Column(String, nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="timeline_events")
    evidence = relationship("EvidenceItem", back_populates="timeline_events")
    execution = relationship("ForensicExecution", back_populates="timeline_events")
    normalized_artifact = relationship("NormalizedArtifact", back_populates="timeline_events")
    structured_artifact = relationship("StructuredArtifact")

    @property
    def confidence(self):
        return self.confidence_score

    @confidence.setter
    def confidence(self, value):
        self.confidence_score = value

    @property
    def description(self):
        if hasattr(self, "_description") and self._description:
            return self._description
        if self.event_data and "description" in self.event_data:
            return self.event_data["description"]
        return f"{self.event_type} observed via {self.event_source}"

    @description.setter
    def description(self, value):
        self._description = value
        if not self.event_data:
            self.event_data = {}
        self.event_data["description"] = value

    @property
    def certainty(self):
        return "CONFIRMED" if self.confidence_score >= 0.9 else "OBSERVED"

    @property
    def temporal_window_start(self):
        return self.window_start_utc

    @property
    def temporal_window_end(self):
        return self.window_end_utc

    @property
    def timestamp_source(self):
        return self.event_source

    @property
    def source_artifact_id(self):
        return self.structured_artifact_id or self.normalized_artifact_id

    @source_artifact_id.setter
    def source_artifact_id(self, value):
        self.structured_artifact_id = value


class ForensicCorrelationGroup(Base):
    """
    Step 14 Cross-Domain Correlation Group (Cluster).
    Groups related normalized artifacts and timeline events using deterministic relationship rules.
    Does NOT declare attacks, threats, findings, or conclusions.
    Maintains complete provenance and cryptographic integrity.
    """
    __tablename__ = "forensic_correlation_groups"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    member_artifact_ids = Column(JSON, default=list, nullable=False)
    member_event_ids = Column(JSON, default=list, nullable=False)
    relationship_ids = Column(JSON, default=list, nullable=False)
    contributing_domains = Column(JSON, default=list, nullable=False)
    source_evidence_ids = Column(JSON, default=list, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False, index=True)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="forensic_correlation_groups")
    relationships = relationship("ArtifactRelationship", back_populates="group")

    @property
    def group_name(self):
        return self.title

    @group_name.setter
    def group_name(self, value):
        self.title = value

    @property
    def correlation_type(self):
        return self.contributing_domains[0] if self.contributing_domains else "CROSS_DOMAIN"

    @property
    def dimension(self):
        return "TEMPORAL_AND_IDENTITY"

    @property
    def rule(self):
        return self.provenance.get("rule", "R-GENERIC-CORRELATION") if self.provenance else "R-GENERIC-CORRELATION"

    @property
    def correlated_entity(self):
        return self.description

    @property
    def participating_artifact_ids(self):
        return self.member_artifact_ids


class ArtifactRelationship(Base):
    """
    Step 14 Cross-Domain Forensic Relationship (Edge).
    Represents an evidence-derived relationship connecting two normalized artifacts or timeline events.
    Does NOT infer attacker intent or declare attacks.
    """
    __tablename__ = "artifact_relationships"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id = Column(String, ForeignKey("forensic_correlation_groups.id", ondelete="SET NULL"), nullable=True, index=True)
    source_id = Column(String, nullable=False, index=True)
    source_type = Column(String, nullable=False, index=True) # NORMALIZED_ARTIFACT, TIMELINE_EVENT
    source_domain = Column(String, nullable=False) # FILESYSTEM, MEMORY, NETWORK, MALWARE, LOGS, METADATA, GENERIC
    target_id = Column(String, nullable=False, index=True)
    target_type = Column(String, nullable=False, index=True) # NORMALIZED_ARTIFACT, TIMELINE_EVENT
    target_domain = Column(String, nullable=False) # FILESYSTEM, MEMORY, NETWORK, MALWARE, LOGS, METADATA, GENERIC
    relationship_type = Column(String, nullable=False, index=True) # FILE_HASH_MATCH, MALWARE_TARGET_MATCH, PROCESS_MEMORY_MATCH, USER_LOGON_MATCH, BROWSER_NETWORK_MATCH, SHARED_IDENTIFIER, TEMPORAL_COINCIDENCE, TEMPORAL_SEQUENCE, OVERLAPPING_WINDOW
    matching_identifier = Column(String, nullable=True, index=True)
    matching_field = Column(String, nullable=True)
    temporal_relationship = Column(JSON, nullable=True)
    confidence_score = Column(Float, default=1.0, nullable=False, index=True)
    evidence_ids = Column(JSON, default=list, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="artifact_relationships")
    group = relationship("ForensicCorrelationGroup", back_populates="relationships")

    @property
    def source_entity(self):
        return f"{self.source_type}:{self.source_id}"

    @property
    def target_entity(self):
        return f"{self.target_type}:{self.target_id}"

    @property
    def confidence(self):
        return self.confidence_score


class DeterministicFinding(Base):
    """
    Step 15 Deterministic Finding Model.
    Evidence-grounded finding generated deterministically from Steps 12-14 before any AI reasoning.
    Does NOT infer attacker intent, declare unsupported attacks, or use LLMs.
    """
    __tablename__ = "deterministic_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    observed_facts = Column(JSON, default=list, nullable=False)
    finding_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True) # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    severity_rule = Column(String, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False, index=True)
    confidence_inputs = Column(JSON, default=dict, nullable=False)
    supporting_artifact_ids = Column(JSON, default=list, nullable=False)
    supporting_event_ids = Column(JSON, default=list, nullable=False)
    supporting_relationship_ids = Column(JSON, default=list, nullable=False)
    supporting_group_ids = Column(JSON, default=list, nullable=False)
    supporting_evidence_ids = Column(JSON, default=list, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="deterministic_findings")

    @property
    def verification_status(self):
        if hasattr(self, "_verification_status") and self._verification_status is not None:
            return self._verification_status
        if self.supporting_evidence_ids or self.supporting_artifact_ids:
            return "SUPPORTED"
        return "UNVERIFIED"

    @verification_status.setter
    def verification_status(self, value):
        self._verification_status = value

    @property
    def mitre_techniques(self):
        return getattr(self, "_mitre_techniques", ["T1053.003"])

    @mitre_techniques.setter
    def mitre_techniques(self, value):
        self._mitre_techniques = value


class Report(Base):
    """
    Court-oriented synthesized forensic report.
    """
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    decision_id = Column(String, ForeignKey("investigator_decisions.id"), nullable=True, index=True)
    version = Column(Integer, default=1, nullable=False, index=True)
    title = Column(String, nullable=False)
    executive_summary = Column(Text, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    evidence_count = Column(Integer, default=0, nullable=False)
    full_report_markdown = Column(Text, nullable=False)
    report_hash = Column(String(64), nullable=True, index=True) # SHA-256 of canonical report JSON
    status = Column(String, default="OFFICIAL_FINAL", nullable=False, index=True) # DRAFT, OFFICIAL_FINAL, ARCHIVED
    generated_by = Column(String, default="lead-investigator", nullable=False)
    generated_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    # Step 20 Final Forensic Report Structured Sections & Provenance
    sections = Column(JSON, default=dict, nullable=True) # 12 structured sections
    provenance = Column(JSON, default=dict, nullable=True) # Full multi-tier lineage trace
    report_metadata = Column(JSON, default=dict, nullable=True) # Generation config, tool versions, methodology
    integrity_status = Column(String, default="VERIFIED", nullable=True, index=True) # VERIFIED, INTEGRITY_WARNING, TAMPERED
    evidence_integrity_summary = Column(JSON, default=dict, nullable=True) # Summary of evidence hash verifications
    storage_path = Column(String, nullable=True) # File path of report archive
    created_at = Column(DateTime, default=utc_now, nullable=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=True)

    @property
    def sha256_hash(self):
        return self.report_hash

    @sha256_hash.setter
    def sha256_hash(self, value):
        self.report_hash = value

    @property
    def summary(self):
        return self.executive_summary

    @summary.setter
    def summary(self, value):
        self.executive_summary = str(value) if not isinstance(value, str) else value

    @property
    def attack_summary(self):
        return getattr(self, "_attack_summary", None)

    @attack_summary.setter
    def attack_summary(self, value):
        self._attack_summary = value

    @property
    def timeline_events(self):
        return getattr(self, "_timeline_events", [])

    @timeline_events.setter
    def timeline_events(self, value):
        self._timeline_events = value

    @property
    def indicators_of_compromise(self):
        return getattr(self, "_indicators_of_compromise", [])

    @indicators_of_compromise.setter
    def indicators_of_compromise(self, value):
        self._indicators_of_compromise = value

    @property
    def remediation_recommendations(self):
        return getattr(self, "_remediation_recommendations", [])

    @remediation_recommendations.setter
    def remediation_recommendations(self, value):
        self._remediation_recommendations = value

    @property
    def plan_id(self):
        return getattr(self, "_plan_id", None)

    @plan_id.setter
    def plan_id(self, value):
        self._plan_id = value

    @property
    def investigation_id(self):
        return self.case_id

    @investigation_id.setter
    def investigation_id(self, value):
        self.case_id = value

    case = relationship("Case", back_populates="reports")
    decision = relationship("InvestigatorDecision", back_populates="reports")

class AuditEvent(Base):
    """
    Immutable system-wide and case-specific security audit trail.
    """
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id"), nullable=True, index=True)
    actor_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    actor_name = Column(String, default="system", nullable=False)
    event_type = Column(String, nullable=False, index=True)
    details = Column(Text, nullable=False)
    metadata_json = Column(JSON, default=dict)
    ip_address = Column(String, default="127.0.0.1", nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    event_hash = Column(String, nullable=True)
    previous_hash = Column(String(64), nullable=True)
    chain_index = Column(Integer, nullable=True, index=True)
    provenance_context = Column(JSON, default=dict)

    case = relationship("Case", back_populates="audit_events")
    actor = relationship("User", back_populates="audit_events")


# =============================================================================
# STEP 16: SPECIALIST AGENT LAYER MODELS
# =============================================================================

class SpecialistAgentRecord(Base):
    """
    Step 16 Persistent/Versioned Specialist Agent Definition.
    Enforces registered domains, capabilities, and strict safety/permission profiles.
    """
    __tablename__ = "specialist_agents"

    id = Column(String, primary_key=True) # e.g. "agent-investigation-strategy"
    name = Column(String, nullable=False, unique=True, index=True)
    version = Column(String, default="1.0.0", nullable=False)
    agent_type = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=False)
    supported_evidence_domains = Column(JSON, default=list, nullable=False)
    supported_artifact_types = Column(JSON, default=list, nullable=False)
    supported_analysis_capabilities = Column(JSON, default=list, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    status = Column(String, default="REGISTERED", nullable=False) # REGISTERED, ENABLED, DISABLED
    safety_permission_profile = Column(JSON, default=dict, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    analysis_requests = relationship("AgentAnalysisRequestRecord", back_populates="agent", cascade="all, delete-orphan")


class AgentAnalysisRequestRecord(Base):
    """
    Step 16 Agent Analysis Request.
    Scoped to a specific Case, tracking evidence context, analysis objective,
    deterministic lifecycle state, and complete provenance.
    """
    __tablename__ = "agent_analysis_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(String, ForeignKey("specialist_agents.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_version = Column(String, nullable=False)
    evidence_id = Column(String, ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_objective = Column(Text, nullable=False)
    lifecycle_state = Column(String, default="REGISTERED", nullable=False, index=True)
    # REGISTERED, ENABLED, DISABLED, READY, RUNNING, WAITING_CAPABILITY, COMPLETED, FAILED, BLOCKED
    input_references = Column(JSON, default=dict, nullable=False)
    requested_capabilities = Column(JSON, default=list, nullable=False)
    results_summary = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text, nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="agent_analysis_requests")
    agent = relationship("SpecialistAgentRecord", back_populates="analysis_requests")
    results = relationship("AgentAnalysisResultRecord", back_populates="request", cascade="all, delete-orphan")
    capability_requests = relationship("AgentCapabilityRequestRecord", back_populates="request", cascade="all, delete-orphan")
    lifecycle_events = relationship("AgentLifecycleEvent", back_populates="request", cascade="all, delete-orphan")


class AgentAnalysisResultRecord(Base):
    """
    Step 16 Auditable Agent Analysis Result.
    Contains grounded observations, capability requests, confidence inputs,
    and complete provenance references. Does NOT allow unsupported claims.
    """
    __tablename__ = "agent_analysis_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String, ForeignKey("agent_analysis_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    agent_version = Column(String, nullable=False)
    analysis_type = Column(String, nullable=False, index=True)
    observations = Column(JSON, default=list, nullable=False)
    capability_requests = Column(JSON, default=list, nullable=False)
    supporting_evidence_ids = Column(JSON, default=list, nullable=False)
    supporting_artifact_ids = Column(JSON, default=list, nullable=False)
    supporting_correlation_ids = Column(JSON, default=list, nullable=False)
    supporting_finding_ids = Column(JSON, default=list, nullable=False)
    confidence_inputs = Column(JSON, default=dict, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="agent_analysis_results")
    request = relationship("AgentAnalysisRequestRecord", back_populates="results")


class AgentCapabilityRequestRecord(Base):
    """
    Step 16 Capability Request Gate Record.
    Enforces the flow: Agent -> Capability Request -> Step 7 validation -> Step 8 Scheduler -> Step 9 Execution.
    Rejects direct subprocess execution and arbitrary commands.
    """
    __tablename__ = "agent_capability_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    request_id = Column(String, ForeignKey("agent_analysis_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    capability_id = Column(String, nullable=False, index=True) # Validated against Step 7 registry
    evidence_id = Column(String, nullable=False, index=True)
    parameters = Column(JSON, default=dict, nullable=False)
    rationale = Column(Text, nullable=False)
    priority = Column(Integer, default=1, nullable=False)
    validation_status = Column(String, default="PENDING", nullable=False, index=True)
    # PENDING, VALIDATED, REJECTED, SCHEDULED, EXECUTING, COMPLETED, FAILED
    validation_error = Column(Text, nullable=True)
    execution_id = Column(String, nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="agent_capability_requests")
    request = relationship("AgentAnalysisRequestRecord", back_populates="capability_requests")


class AgentLifecycleEvent(Base):
    """
    Step 16 Agent Deterministic Lifecycle and Audit Event.
    Records every lifecycle state transition with timestamp and hash.
    """
    __tablename__ = "agent_lifecycle_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    agent_id = Column(String, nullable=False, index=True)
    request_id = Column(String, ForeignKey("agent_analysis_requests.id", ondelete="CASCADE"), nullable=True, index=True)
    from_state = Column(String, nullable=False)
    to_state = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    event_hash = Column(String(64), nullable=False)

    case = relationship("Case", back_populates="agent_lifecycle_events")
    request = relationship("AgentAnalysisRequestRecord", back_populates="lifecycle_events")


# =============================================================================
# STEP 17: GOVERNANCE GATE MODELS
# =============================================================================

class GovernanceDecisionRecord(Base):
    """
    Step 17 Persistent Governance Decision Record.
    Enforces deterministic policy controls, approval workflows for high-risk actions,
    PII/sensitive data handling, prompt-injection defense, and SHA-256 integrity.
    """
    __tablename__ = "governance_decisions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    requesting_agent = Column(String, nullable=True, index=True) # Agent ID or user identity
    action_type = Column(String, nullable=False, index=True) # CAPABILITY_REQUEST, EXECUTION, REPORT_GENERATION, etc.
    target_resource_type = Column(String, nullable=True, index=True) # EVIDENCE, ARTIFACT, TOOL_OUTPUT, CAPABILITY
    target_resource_id = Column(String, nullable=True, index=True)
    policy_checks = Column(JSON, default=dict, nullable=False) # Detailed check results
    risk_level = Column(String, default="LOW", nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    approval_status = Column(String, default="NOT_REQUIRED", nullable=False, index=True) # NOT_REQUIRED, REQUIRED, PENDING, APPROVED, REJECTED
    decision = Column(String, nullable=False, index=True) # APPROVED, BLOCKED, REVIEW_REQUIRED
    reason = Column(Text, nullable=False)
    approved_by = Column(String, nullable=True) # User ID who approved
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    input_references = Column(JSON, default=dict, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)

    case = relationship("Case", back_populates="governance_decisions")
    audit_events = relationship("GovernanceAuditEvent", back_populates="governance_decision", cascade="all, delete-orphan")


class EvidenceVerificationRecord(Base):
    """
    Step 17 Evidence / Artifact / Tool Output Verification Record.
    Validates integrity, verifies artifact lineage, checks provenance,
    verifies tool output metadata/hash, and detects cross-domain contradictions.
    """
    __tablename__ = "evidence_verifications"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    target_type = Column(String, nullable=False, index=True) # EVIDENCE, RAW_OUTPUT, STRUCTURED_ARTIFACT, NORMALIZED_ARTIFACT, TOOL_OUTPUT
    target_id = Column(String, nullable=False, index=True)
    verification_status = Column(String, nullable=False, index=True) # VERIFIED, FAILED, REVIEW_REQUIRED
    integrity_check = Column(JSON, default=dict, nullable=False)
    lineage_check = Column(JSON, default=dict, nullable=False)
    provenance_check = Column(JSON, default=dict, nullable=False)
    metadata_check = Column(JSON, default=dict, nullable=False)
    contradiction_check = Column(JSON, default=dict, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    notes = Column(Text, nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)

    case = relationship("Case", back_populates="evidence_verifications")


class GovernanceAuditEvent(Base):
    """
    Step 17 Governance Audit Event.
    Immutable, hash-chained audit record of every governance evaluation,
    approval, rejection, or verification action.
    """
    __tablename__ = "governance_audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    decision_id = Column(String, ForeignKey("governance_decisions.id", ondelete="CASCADE"), nullable=True, index=True)
    verification_id = Column(String, ForeignKey("evidence_verifications.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String, nullable=False, index=True) # EVALUATION, APPROVAL, REJECTION, VERIFICATION, BLOCK
    actor = Column(String, nullable=False)
    input_references = Column(JSON, default=dict, nullable=False)
    checks_performed = Column(JSON, default=list, nullable=False)
    decision = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    approval_identity = Column(String, nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    event_hash = Column(String(64), nullable=False)
    prev_event_hash = Column(String(64), nullable=True)

    case = relationship("Case", back_populates="governance_audit_events")
    governance_decision = relationship("GovernanceDecisionRecord", back_populates="audit_events")


# =============================================================================
# STEP 18: AI REASONING LAYER MODELS
# =============================================================================

class AIProviderConfigRecord(Base):
    """
    Step 18 Configurable External / Local LLM Provider Configuration.
    Stores provider endpoint, model, encrypted credentials, enabled state, and health status.
    API keys are strictly encrypted at rest and never exposed in API responses or logs.
    """
    __tablename__ = "ai_provider_configs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    provider = Column(String, nullable=False, index=True) # openai, anthropic, gemini, local_openai, local_stub
    model = Column(String, nullable=False)
    endpoint = Column(String, nullable=True)
    api_key_encrypted = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    status = Column(String, default="CONFIGURED", nullable=False) # CONFIGURED, ACTIVE, DISABLED, ERROR, UNCONFIGURED
    last_tested_at = Column(DateTime, nullable=True)
    last_test_status = Column(String, nullable=True) # SUCCESS, FAILED
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    user = relationship("User", back_populates="ai_provider_configs")
    case = relationship("Case", back_populates="ai_provider_configs")


class AIReasoningRecord(Base):
    """
    Step 18 Governed AI Reasoning Request and Result Record.
    Accepts verified structured data downstream of forensic structures.
    Every statement is classified as FACT, INFERENCE, or UNVERIFIED with verifiable evidence citations.
    Enforces no raw evidence external egress and strict SHA-256 integrity hashing.
    """
    __tablename__ = "ai_reasoning_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    request_user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    governance_decision_id = Column(String, ForeignKey("governance_decisions.id", ondelete="SET NULL"), nullable=True, index=True)
    objective = Column(Text, nullable=False)
    status = Column(String, default="COMPLETED", nullable=False, index=True) # COMPLETED, BLOCKED, FAILED, REVIEW_REQUIRED
    execution_mode = Column(String, nullable=False) # EXTERNAL_LLM, LOCAL_LLM, DETERMINISTIC_FALLBACK
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    input_references = Column(JSON, default=dict, nullable=False) # finding_ids, artifact_ids, timeline_event_ids, correlation_ids, evidence_ids
    raw_evidence_egress_blocked = Column(Boolean, default=True, nullable=False)
    egress_approved = Column(Boolean, default=False, nullable=False)
    statements = Column(JSON, default=list, nullable=False)
    citations_verified = Column(Boolean, default=True, nullable=False)
    summary = Column(Text, nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    reasoning_metadata = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="ai_reasoning_records")
    request_user = relationship("User")
    governance_decision = relationship("GovernanceDecisionRecord")


class InvestigatorReviewRecord(Base):
    """
    Step 19 Human-in-the-Loop Investigator Review Record.
    Empowers an authorized investigator to review evidence integrity, deterministic findings,
    provenance lineage, and AI reasoning with FACT / INFERENCE / UNVERIFIED classifications.
    The investigator can ACCEPT, CHALLENGE, REJECT, or REQUEST_MORE_EVIDENCE.
    Original findings, evidence, and AI reasoning remain strictly immutable.
    Maintains cryptographic SHA-256 integrity and audit chaining.
    """
    __tablename__ = "investigator_reviews"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    investigator_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    investigator_name = Column(String, nullable=False)

    # Target claim / item
    target_type = Column(String, nullable=False, index=True) # FINDING, AI_REASONING, EVIDENCE, CLAIM
    target_id = Column(String, nullable=False, index=True) # finding_id or reasoning_id
    statement_id = Column(String, nullable=True, index=True) # specific statement within AI reasoning if applicable

    # Decision
    decision = Column(String, nullable=False, index=True) # ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE
    comment = Column(Text, nullable=False) # Investigator explanation / rationale

    # Context & supporting links
    supporting_references = Column(JSON, default=list, nullable=False) # referenced artifact_ids, evidence_ids, etc.
    resulting_workflow_action = Column(String, nullable=False, index=True) # ACCEPTED_CLAIM, CHALLENGED_CLAIM, REJECTED_CLAIM, EVIDENCE_REQUESTED
    action_reference_id = Column(String, nullable=True, index=True) # linked request/task/plan ID if REQUEST_MORE_EVIDENCE

    # Verification & Security
    provenance = Column(JSON, default=dict, nullable=False)
    review_metadata = Column(JSON, default=dict, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_path = Column(String, nullable=True)

    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("Case", back_populates="investigator_reviews")
    investigator = relationship("User", back_populates="investigator_reviews")

    @property
    def integrity_hash(self):
        return self.sha256_hash



    @integrity_hash.setter
    def integrity_hash(self, value):
        self.sha256_hash = value


class RevokedToken(Base):
    """
    Persists revoked JWT JTIs so that token revocation survives server restarts.
    The in-memory REVOKED_TOKENS set in security.py is the fast path; this table
    is the authoritative source consulted on cache miss (e.g., after a restart).
    """
    __tablename__ = "revoked_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    jti = Column(String, unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=utc_now, nullable=False)
