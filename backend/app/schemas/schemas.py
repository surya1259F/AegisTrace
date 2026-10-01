from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator, computed_field

# Health & System Status
class HealthResponse(BaseModel):
    status: str = "ok"
    application: str = "ADFIR"
    version: str = "0.1.0"

class SystemStatusResponse(BaseModel):
    application: str
    version: str
    status: str
    platform: str
    logical_cpus: int
    max_concurrent_tasks: int
    active_tasks: int
    forensic_tools: Dict[str, Dict[str, Any]]

# User Schemas
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    name: str
    organization: str
    badge_id: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    @computed_field
    @property
    def roles(self) -> List[str]:
        return [self.role] if self.role else ["INVESTIGATOR"]

    @computed_field
    @property
    def permissions(self) -> List[str]:
        from backend.app.services.authorization import get_role_permissions
        return get_role_permissions(self.role)

# Case Member & Workspace Schemas
class CaseMemberCreateRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    role: str = "COLLABORATOR"

class CaseMemberUpdateRequest(BaseModel):
    role: str

class CaseMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    user_id: str
    role: str
    added_at: datetime
    email: Optional[str] = None
    name: Optional[str] = None

class CasePermissionUpdateRequest(BaseModel):
    permissions: Dict[str, bool]

class WorkspaceInitResponse(BaseModel):
    case_id: str
    workspace_state: str
    workspace_path: Optional[str] = None
    subdirectories: List[str] = Field(default_factory=list)
    initialized_at: Optional[str] = None

# Case / Investigation Schemas
class CaseCreate(BaseModel):
    name: Optional[str] = None
    title: Optional[str] = None
    case_number: Optional[str] = None
    description: Optional[str] = None
    objective: Optional[str] = None
    case_type: Optional[str] = "GENERAL_INVESTIGATION"
    priority: Optional[str] = "MEDIUM"
    investigator: Optional[str] = None
    created_by: Optional[str] = None
    case_permissions: Optional[Dict[str, Any]] = None
    members: Optional[List[CaseMemberCreateRequest]] = None

    @model_validator(mode="after")
    def sync_case_create_aliases(self):
        if not self.name and self.title:
            self.name = self.title
        elif not self.title and self.name:
            self.title = self.name
        if not self.created_by and self.investigator:
            self.created_by = self.investigator
        elif not self.investigator and self.created_by:
            self.investigator = self.created_by
        return self

class CaseUpdate(BaseModel):
    name: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    objective: Optional[str] = None
    case_type: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    case_permissions: Optional[Dict[str, Any]] = None

class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_number: str
    name: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    objective: Optional[str] = None
    case_type: Optional[str] = "GENERAL_INVESTIGATION"
    priority: Optional[str] = "MEDIUM"
    status: str = "OPEN"
    workspace_state: str = "NOT_INITIALIZED"
    workspace_path: Optional[str] = None
    case_permissions: Optional[Dict[str, Any]] = None
    owner_id: Optional[str] = None
    created_by: Optional[str] = None
    investigator: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    evidence_count: Optional[int] = 0
    findings_count: Optional[int] = 0
    artifacts_count: Optional[int] = 0
    members_count: Optional[int] = 1

    @model_validator(mode="after")
    def sync_case_response_aliases(self):
        if not self.title and self.name:
            self.title = self.name
        elif not self.name and self.title:
            self.name = self.title
        if not self.investigator and self.created_by:
            self.investigator = self.created_by
        elif not self.created_by and self.investigator:
            self.created_by = self.investigator
        return self

# Aliases for backward compatibility
InvestigationCreate = CaseCreate
InvestigationResponse = CaseResponse

# Evidence Schemas
class EvidenceIntakeRequest(BaseModel):
    path: Optional[str] = None
    file_path: Optional[str] = None
    case_id: Optional[str] = None
    evidence_type: Optional[str] = None
    notes: Optional[str] = None
    acquisition_notes: Optional[str] = None

    @model_validator(mode="after")
    def sync_evidence_intake_aliases(self):
        if not self.path and self.file_path:
            self.path = self.file_path
        elif not self.file_path and self.path:
            self.file_path = self.path
        if not self.notes and self.acquisition_notes:
            self.notes = self.acquisition_notes
        elif not self.acquisition_notes and self.notes:
            self.acquisition_notes = self.notes
        return self

class CustodyRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: str
    actor_id: str
    actor: str
    event_type: str
    timestamp: datetime
    description: str
    source_path: Optional[str] = None
    destination_path: Optional[str] = None
    sha256: Optional[str] = None
    metadata_json: Dict[str, Any] = {}
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    name: Optional[str] = None
    file_name: Optional[str] = None
    original_path: Optional[str] = None
    file_path: Optional[str] = None
    storage_path: Optional[str] = None
    evidence_type: str
    evidence_subtype: Optional[str] = None
    source_kind: Optional[str] = "FILE"
    acquisition_method: Optional[str] = "INVESTIGATOR_IMPORT"
    detected_format: Optional[str] = None
    filesystem_type: Optional[str] = None
    platform_hint: Optional[str] = None
    size_bytes: float
    sha256: Optional[str] = None
    sha256_hash: Optional[str] = None
    md5: Optional[str] = None
    md5_hash: Optional[str] = None
    mime_type: Optional[str] = "application/octet-stream"
    status: Optional[str] = "REGISTERED"
    intake_status: Optional[str] = "INTAKE_COMPLETE"
    integrity_status: Optional[str] = "VERIFIED"
    read_only_verified: Optional[bool] = True
    notes: Optional[str] = None
    acquisition_notes: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None
    intelligence_json: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_by: Optional[str] = "NOT_RECORDED"
    acquired_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    chain_of_custody_log: Optional[List[Any]] = None
    metadata_info: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def sync_evidence_response_aliases(self):
        if not self.name and self.file_name:
            self.name = self.file_name
        elif not self.file_name and self.name:
            self.file_name = self.name
        if not self.original_path and self.file_path:
            self.original_path = self.file_path
        elif not self.file_path and self.original_path:
            self.file_path = self.original_path
        if not self.sha256 and self.sha256_hash:
            self.sha256 = self.sha256_hash
        elif not self.sha256_hash and self.sha256:
            self.sha256_hash = self.sha256
        if not self.md5 and self.md5_hash:
            self.md5 = self.md5_hash
        elif not self.md5_hash and self.md5:
            self.md5_hash = self.md5
        if not self.notes and self.acquisition_notes:
            self.notes = self.acquisition_notes
        elif not self.acquisition_notes and self.notes:
            self.acquisition_notes = self.notes
        if not self.metadata_json and self.metadata_info:
            self.metadata_json = self.metadata_info
        elif not self.metadata_info and self.metadata_json:
            self.metadata_info = self.metadata_json
        return self

class EvidenceVerificationResponse(BaseModel):
    evidence_id: str
    integrity_status: str
    expected_sha256: str
    current_sha256: str
    read_only_verified: bool
    verified_at: datetime
    message: str

class EvidenceAcquisitionCreateRequest(BaseModel):
    source_path: str
    acquisition_type: str = "SINGLE_FILE" # SINGLE_FILE, DIRECTORY, DISK_IMAGE, MEMORY_DUMP, EVTX, BROWSER, PCAP
    evidence_type: Optional[str] = None
    notes: Optional[str] = None

class EvidenceAcquisitionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    acquisition_type: str
    source_path: str
    total_files: int
    total_bytes: int
    successful_files: int
    failed_files: int
    manifest_hash: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    created_by_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class EvidenceManifestItem(BaseModel):
    evidence_id: Optional[str] = None
    relative_path: str
    original_path: str
    storage_path: Optional[str] = None
    size_bytes: Optional[int] = 0
    sha256: Optional[str] = None
    source_kind: Optional[str] = "FILE"
    evidence_type: Optional[str] = "GENERIC_BINARY"
    detected_format: Optional[str] = None
    status: str

class EvidenceManifestResponse(BaseModel):
    acquisition_id: str
    case_id: str
    source_path: str
    total_files: int
    successful_files: int
    failed_files: int
    total_bytes: int
    generated_at: str
    files: List[EvidenceManifestItem]

class CustodyChainVerificationResponse(BaseModel):
    case_id: str
    evidence_id: str
    total_events: int
    chain_valid: bool
    tampered_event_id: Optional[str] = None
    message: str

class EvidenceIntelligenceResponse(BaseModel):
    evidence_id: str
    intelligence: Dict[str, Any]

class EvidenceIntelligenceProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    case_id: str
    engine_version: str = "1.0.0"
    analysis_version: int = 1
    classification: str
    subtype: Optional[str] = None
    classification_status: str = "MATCH"
    classification_confidence: str = "DETERMINISTIC"
    classification_basis: Optional[str] = None
    detected_format: str
    detected_mime: str = "application/octet-stream"
    platform_hint: str = "UNKNOWN"
    platform_basis: Optional[str] = None
    platform_confidence: str = "UNKNOWN"
    architecture_hint: str = "UNKNOWN"
    filesystem_type: str = "UNKNOWN"
    filesystem_version: Optional[str] = None
    filesystem_basis: Optional[str] = None
    filesystem_detection_status: str = "NOT_PRESENT"
    partition_table_type: str = "NONE"
    partitions_json: Optional[List[Any]] = Field(default_factory=list)
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)
    characteristics_json: Optional[List[Any]] = Field(default_factory=list)
    detection_methods: Optional[List[Any]] = Field(default_factory=list)
    tags_json: Optional[List[Any]] = Field(default_factory=list)
    resource_profile_json: Optional[Dict[str, Any]] = Field(default_factory=dict)
    recommended_tools_json: Optional[List[Any]] = Field(default_factory=list)
    recommended_families_json: Optional[List[Any]] = Field(default_factory=list)
    limitations_json: Optional[List[Any]] = Field(default_factory=list)
    evidence_sha256_verified: str
    generated_at: datetime
    created_at: datetime
    updated_at: datetime

    @property
    def investigation_id(self) -> str:
        return self.case_id

# Artifact Schemas
class ArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: str
    execution_id: Optional[str] = None
    agent: str
    tool: str
    artifact_type: str
    source_reference: str
    path: Optional[str] = None
    inode: Optional[str] = None
    size_bytes: Optional[float] = None
    is_deleted: bool = False
    metadata_json: Dict[str, Any] = {}
    raw_output_reference: Optional[str] = None
    created_at: datetime

    @property
    def investigation_id(self) -> str:
        return self.case_id

# Finding Schemas
class FindingCreate(BaseModel):
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    execution_id: Optional[str] = None
    artifact_id: Optional[str] = None
    agent: Optional[str] = None
    agent_type: Optional[str] = None
    tool: Optional[str] = None
    source_tool: Optional[str] = None
    finding_type: Optional[str] = None
    category: Optional[str] = None
    title: str
    description: Optional[str] = None
    details: Optional[Any] = None
    severity: Optional[str] = "MEDIUM"
    classification: Optional[str] = "FACT"
    confidence: Optional[float] = None
    confidence_score: Optional[float] = None
    timestamp: Optional[datetime] = None
    evidence_reference: Optional[str] = None
    raw_output_reference: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None

    @model_validator(mode="after")
    def sync_finding_aliases(self):
        if not self.agent and self.agent_type:
            self.agent = self.agent_type
        elif not self.agent_type and self.agent:
            self.agent_type = self.agent

        if not self.tool and self.source_tool:
            self.tool = self.source_tool
        elif not self.source_tool and self.tool:
            self.source_tool = self.tool

        if not self.finding_type and self.category:
            self.finding_type = self.category
        elif not self.category and self.finding_type:
            self.category = self.finding_type

        if not self.description and self.details:
            self.description = str(self.details)
        elif not self.details and self.description:
            self.details = {"description": self.description}

        if self.confidence is None and self.confidence_score is not None:
            self.confidence = self.confidence_score
        elif self.confidence_score is None and self.confidence is not None:
            self.confidence_score = self.confidence

        if not self.agent:
            self.agent = "GenericAgent"
        if not self.tool:
            self.tool = "GenericTool"
        if not self.finding_type:
            self.finding_type = "generic_finding"
        if not self.description:
            self.description = self.title

        return self

class FindingResponse(FindingCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    verification_status: Optional[str] = "UNVERIFIED"
    created_at: Optional[datetime] = None

    @property
    def investigation_id(self) -> str:
        return self.case_id

# Tool & Execution Schemas
class ToolDefinitionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tool_id: str
    name: str
    version: Optional[str] = None
    executable_path: str
    supported_evidence: List[str] = Field(default_factory=list)
    capabilities_json: Dict[str, Any] = Field(default_factory=dict)
    is_available: bool

class ToolExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: str
    tool_id: str
    status: str
    exit_code: Optional[int] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    execution_time_ms: Optional[float] = None
    operator_id: str
    error_message: Optional[str] = None
    pid: Optional[int] = None
    process_start_time: Optional[float] = None
    timeout_seconds: Optional[int] = None
    cancelled_at: Optional[datetime] = None
    cancelled_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

class TaskCancelResponse(BaseModel):
    case_id: str
    task_id: str
    status: str
    message: str
    execution_id: Optional[str] = None
    cancelled_at: Optional[datetime] = None


# Analysis Request / Response Schemas
class DiskAnalysisRequest(BaseModel):
    evidence_id: str
    recursive: bool = True
    include_deleted: bool = True
    offset_sectors: int = 0
    timeout_seconds: int = Field(default=60, ge=1, le=600)

class DiskAnalysisResponse(BaseModel):
    investigation_id: str
    evidence_id: str
    status: str
    execution_id: str
    artifacts_count: int
    findings_count: int
    execution_time_ms: float
    tool_version: Optional[str] = None
    raw_output_reference: Optional[str] = None
    error: Optional[str] = None
    artifacts: List[ArtifactResponse] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)

class MemoryAnalysisRequest(BaseModel):
    evidence_id: str
    plugin: str = Field(default="windows.pslist", pattern=r"^[a-zA-Z0-9_\.]+$")
    timeout_seconds: int = Field(default=120, ge=1, le=600)

class MemoryAnalysisResponse(BaseModel):
    investigation_id: str
    evidence_id: str
    status: str
    plugin: str
    execution_id: str
    artifacts_count: int
    findings_count: int
    execution_time_ms: float
    tool_version: Optional[str] = None
    raw_output_reference: Optional[str] = None
    error: Optional[str] = None
    artifacts: List[ArtifactResponse] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)

class MalwareAnalysisRequest(BaseModel):
    evidence_id: str
    rule_id: str = Field(default="adfir_webshell_indicators", pattern=r"^[a-zA-Z0-9_\-]+$")
    timeout_seconds: int = Field(default=60, ge=1, le=600)

class MalwareAnalysisResponse(BaseModel):
    investigation_id: str
    evidence_id: str
    status: str
    rule_id: str
    rule_sha256: Optional[str] = None
    execution_id: str
    artifacts_count: int
    findings_count: int
    execution_time_ms: float
    tool_version: Optional[str] = None
    raw_output_reference: Optional[str] = None
    error: Optional[str] = None
    artifacts: List[ArtifactResponse] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)

class LogAnalysisRequest(BaseModel):
    evidence_id: str
    max_records: int = Field(default=5000, ge=1, le=100000)
    timeout_seconds: int = Field(default=120, ge=1, le=600)

class LogAnalysisResponse(BaseModel):
    investigation_id: str
    evidence_id: str
    status: str
    execution_id: str
    artifacts_count: int
    findings_count: int
    execution_time_ms: float
    tool_version: Optional[str] = None
    raw_output_reference: Optional[str] = None
    error: Optional[str] = None
    artifacts: List[ArtifactResponse] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)

class YaraRuleResponse(BaseModel):
    rule_id: str
    filename: str
    sha256: str
    is_valid: bool
    description: Optional[str] = None
    category: Optional[str] = None

# Planner, Correlation, Verification Schemas
class PlanTaskStep(BaseModel):
    step_id: str
    task_id: Optional[str] = None
    agent: str
    agent_name: Optional[str] = None
    tool: str
    tool_name: Optional[str] = None
    tool_available: bool = True
    evidence_id: Optional[str] = None
    evidence_name: Optional[str] = None
    action: str
    reason: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    priority: int = 1
    status: str = "PLANNED"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    estimated_resource_cost: Dict[str, str] = Field(default_factory=dict)
    execution_id: Optional[str] = None
    artifacts_count: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @model_validator(mode="after")
    def sync_task_step_aliases(self):
        if not self.task_id and self.step_id:
            self.task_id = self.step_id
        elif not self.step_id and self.task_id:
            self.step_id = self.task_id

        if not self.agent_name and self.agent:
            self.agent_name = self.agent
        elif not self.agent and self.agent_name:
            self.agent = self.agent_name

        if not self.tool_name and self.tool:
            self.tool_name = self.tool
        elif not self.tool and self.tool_name:
            self.tool = self.tool_name
        return self

class StoppingConditionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    plan_id: Optional[str] = None
    condition_code: Optional[str] = None
    trigger_description: Optional[str] = None
    explanation: Optional[str] = None
    severity: Optional[str] = "INFO"
    human_review_required: Optional[bool] = False
    triggered_at: Optional[datetime] = None


class InvestigationPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    plan_id: Optional[str] = None
    investigation_id: Optional[str] = None
    case_id: Optional[str] = None
    parent_plan_id: Optional[str] = None
    title: Optional[str] = None
    strategy_summary: Optional[str] = None
    validation_status: Optional[str] = "VALIDATED"
    identified_evidence: Optional[List[Any]] = None
    planned_tasks: Optional[List[Any]] = None
    execution_order: Optional[List[str]] = None
    steps: Optional[List[PlanTaskStep]] = None
    tasks: Optional[List[Any]] = None
    total_tasks: Optional[int] = None
    evidence_snapshot: Optional[List[Any]] = None
    resource_snapshot: Optional[Dict[str, Any]] = None
    stopping_conditions: Optional[List[Any]] = None
    stopping_conditions_summary: Optional[List[Any]] = None
    adjustments: Optional[List[Any]] = None
    status: str = "PLANNED"
    version: int = 1
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @model_validator(mode="after")
    def sync_plan_aliases(self):
        if not self.id and self.plan_id:
            self.id = self.plan_id
        elif not self.plan_id and self.id:
            self.plan_id = self.id

        if not self.investigation_id and self.case_id:
            self.investigation_id = self.case_id
        elif not self.case_id and self.investigation_id:
            self.case_id = self.investigation_id

        # Sync stopping conditions from ORM if needed
        if self.stopping_conditions:
            serialized_sc = []
            for sc in self.stopping_conditions:
                if isinstance(sc, dict):
                    serialized_sc.append(sc)
                elif hasattr(sc, "condition_code"):
                    serialized_sc.append({
                        "id": getattr(sc, "id", None),
                        "plan_id": getattr(sc, "plan_id", None),
                        "condition_code": getattr(sc, "condition_code", None),
                        "trigger_description": getattr(sc, "trigger_description", None),
                        "explanation": getattr(sc, "explanation", None),
                        "severity": getattr(sc, "severity", "INFO"),
                        "human_review_required": getattr(sc, "human_review_required", False),
                    })
                else:
                    serialized_sc.append(sc)
            self.stopping_conditions = serialized_sc

        # Sync adjustments from ORM if needed
        if self.adjustments:
            serialized_adj = []
            for adj in self.adjustments:
                if isinstance(adj, dict):
                    serialized_adj.append(adj)
                elif hasattr(adj, "adjustment_type"):
                    serialized_adj.append({
                        "id": getattr(adj, "id", None),
                        "plan_id": getattr(adj, "plan_id", None),
                        "adjustment_type": getattr(adj, "adjustment_type", None),
                        "summary": getattr(adj, "summary", None),
                        "previous_state": getattr(adj, "previous_state", None),
                        "new_state": getattr(adj, "new_state", None),
                        "actor_id": getattr(adj, "actor_id", None),
                    })
                else:
                    serialized_adj.append(adj)
            self.adjustments = serialized_adj

        # Sync planned_tasks, tasks, and steps
        if not self.planned_tasks and self.tasks:
            self.planned_tasks = self.tasks
        elif not self.tasks and self.planned_tasks:
            self.tasks = self.planned_tasks

        if self.tasks and not self.steps:
            try:
                self.steps = [PlanTaskStep(**t) if isinstance(t, dict) else t for t in self.tasks]
            except Exception:
                pass
        elif self.steps and not self.tasks:
            self.tasks = self.steps
            if not self.planned_tasks:
                self.planned_tasks = self.steps

        if self.tasks:
            self.total_tasks = len(self.tasks)
            if not self.execution_order:
                self.execution_order = [
                    f"{t.get('agent_name', 'Agent')}::{t.get('selected_tool_id') or t.get('tool_name', 'Tool')}"
                    if isinstance(t, dict) else "Agent::Tool"
                    for t in self.tasks
                ]
        return self

class DependencyGraphResponse(BaseModel):
    plan_id: str
    case_id: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    is_valid_dag: bool = True

class PlanReviewResponse(BaseModel):
    plan_id: str
    validation_status: str
    status: str
    adjustments_applied: List[Dict[str, Any]]

class PlanExecutionResponse(BaseModel):
    investigation_id: str
    plan_id: str
    status: str
    tasks_executed: int
    tasks_succeeded: int
    tasks_failed: int
    total_artifacts: int
    total_findings: int
    tasks: List[PlanTaskStep]
    completed_at: Optional[datetime] = None

class CorrelatedGroupResponse(BaseModel):
    id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    dimension: str
    rule: Optional[str] = None
    correlated_entity: str
    title: str
    description: str
    tools_involved: List[str] = Field(default_factory=list)
    supporting_finding_ids: List[str] = Field(default_factory=list)
    supporting_artifact_ids: Optional[List[str]] = Field(default_factory=list)
    supporting_evidence_ids: Optional[List[str]] = Field(default_factory=list)
    correlation_confidence: float
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def sync_id_aliases(self):
        if not self.investigation_id and self.case_id:
            self.investigation_id = self.case_id
        elif not self.case_id and self.investigation_id:
            self.case_id = self.investigation_id
        return self

class VerificationResultResponse(BaseModel):
    finding_id: Optional[str] = None
    verification_status: str
    confidence_score: Optional[float] = None
    reason: str

# Investigator Decision Schemas (Mandatory Gate)
class InvestigatorDecisionCreate(BaseModel):
    decision: str = Field(..., pattern=r"^(CONFIRM|REJECT|INCONCLUSIVE|REQUEST_MORE_EVIDENCE)$")
    rationale: str = Field(..., min_length=3)
    finding_ids: List[str] = []
    evidence_ids: List[str] = []
    investigator_name: Optional[str] = None

class InvestigatorDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    investigator_id: Optional[str] = None
    investigator_name: str
    decision: str
    rationale: str
    finding_ids: List[str] = []
    evidence_ids: List[str] = []
    timestamp: datetime

# Report Schemas
class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    version: Optional[int] = 1
    title: str
    executive_summary: str
    attack_summary: Optional[Union[Dict[str, Any], str]] = None
    timeline_events: Optional[List[Any]] = None
    indicators_of_compromise: Optional[List[Any]] = None
    remediation_recommendations: Optional[List[Any]] = None
    findings_count: Optional[int] = 0
    evidence_count: Optional[int] = 0
    full_report_markdown: str
    report_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    status: Optional[str] = "OFFICIAL_FINAL"
    integrity_status: Optional[str] = "VERIFIED"
    sections: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None
    report_metadata: Optional[Dict[str, Any]] = None
    evidence_integrity_summary: Optional[Dict[str, Any]] = None
    storage_path: Optional[str] = None
    generated_by: Optional[str] = "lead-investigator"
    generated_at: Optional[Any] = None

    @model_validator(mode="after")
    def sync_report_aliases(self):
        if not self.investigation_id and self.case_id:
            self.investigation_id = self.case_id
        elif not self.case_id and self.investigation_id:
            self.case_id = self.investigation_id
        if not self.sha256_hash and self.report_hash:
            self.sha256_hash = self.report_hash
        elif not self.report_hash and self.sha256_hash:
            self.report_hash = self.sha256_hash
        return self

# Audit Event Schemas
class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_name: str
    event_type: str
    details: str
    event_hash: Optional[str] = None


# =============================================================================
# Authentication & User Schemas
# =============================================================================

class UserRegisterRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8)
    name: str
    organization: Optional[str] = "Digital Forensics Unit"
    badge_id: Optional[str] = None


class UserLoginRequest(BaseModel):
    email: str
    password: str


class UserAdminCreateRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8)
    name: str
    organization: Optional[str] = "Digital Forensics Unit"
    role: Optional[str] = "INVESTIGATOR"
    badge_id: Optional[str] = None


class UserAdminUpdateRequest(BaseModel):
    name: Optional[str] = None
    organization: Optional[str] = None
    role: Optional[str] = None
    badge_id: Optional[str] = None
    is_active: Optional[bool] = None


class UserProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    badge_id: Optional[str] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    name: str
    organization: str
    badge_id: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    @computed_field
    @property
    def roles(self) -> List[str]:
        return [self.role] if self.role else ["INVESTIGATOR"]

    @computed_field
    @property
    def permissions(self) -> List[str]:
        from backend.app.services.authorization import get_role_permissions
        return get_role_permissions(self.role)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user: UserResponse


class CaseMemberAddRequest(BaseModel):
    user_id: str
    role: Optional[str] = "COLLABORATOR"


class CaseMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    user_id: str
    role: str
    added_at: datetime
    email: Optional[str] = None
    name: Optional[str] = None


# =============================================================================
# AI Copilot & Provider Schemas
# =============================================================================

from enum import Enum

class EgressPolicy(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    EXTERNAL_PROVIDER_ALLOWED = "EXTERNAL_PROVIDER_ALLOWED"
    EXTERNAL_PROVIDER_BLOCKED = "EXTERNAL_PROVIDER_BLOCKED"


class CopilotQueryRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    query: str = Field(..., min_length=1, max_length=4000)
    provider: Optional[str] = "local_stub"
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    egress_policy: EgressPolicy = EgressPolicy.LOCAL_ONLY


class ExplainFindingRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    finding_id: str = Field(..., min_length=1)
    provider: Optional[str] = "local_stub"
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    egress_policy: EgressPolicy = EgressPolicy.LOCAL_ONLY


class ProviderTestRequest(BaseModel):
    provider: str = Field(..., min_length=1)
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class ProviderTestResponse(BaseModel):
    provider: str
    model: str
    status: str  # "SUCCESS" or "FAILED"
    details: str


# =============================================================================
# Tool Selection & Registry Validation Schemas (Phase 2 / Step 7)
# =============================================================================

class ToolSelectionItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_id: str
    task_id: Optional[str] = None
    task_key: str
    capability_id: str
    evidence_id: Optional[str] = None
    candidate_tools: List[str] = []
    selected_tool_id: Optional[str] = None
    selection_status: str
    availability_status: str
    evidence_compatibility: str
    platform_compatibility: str
    resource_status: str
    version_status: str
    safety_status: str
    rejection_reasons: Dict[str, Any] = {}
    selection_rationale: Optional[str] = None
    created_at: Optional[datetime] = None


class PlanToolSelectionSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    plan_id: str
    case_id: str
    total_tasks: int
    selected_count: int
    blocked_count: int
    review_count: int
    all_satisfied: bool
    selections: List[ToolSelectionItemResponse] = []


class ToolValidationRequest(BaseModel):
    capability_id: str = Field(..., min_length=1)
    evidence_id: Optional[str] = None
    evidence_category: Optional[str] = None
    evidence_subtype: Optional[str] = None
    evidence_format: Optional[str] = None
    tool_id: Optional[str] = None


class ToolValidationResponse(BaseModel):
    capability_id: str
    capability_supported: bool
    capability_reason: str
    candidate_tools: List[Dict[str, Any]] = []
    selected_tool_id: Optional[str] = None
    selection_status: str
    system_resources: Dict[str, Any] = {}


class RegistryValidationResponse(BaseModel):
    valid: bool
    total_capabilities: int
    total_tools: int
    orphaned_capabilities: List[str] = []
    orphaned_tools: List[str] = []
    errors: List[str] = []
    warnings: List[str] = []


# =============================================================================
# Resource-Aware Scheduler Schemas (Phase 2 / Step 8)
# =============================================================================

class AnalysisRequestCreate(BaseModel):
    case_id: Optional[str] = None
    plan_id: str = Field(..., min_length=1)
    task_id: Optional[str] = None
    task_key: str = Field(..., min_length=1)
    evidence_id: Optional[str] = None
    capability_id: str = Field(..., min_length=1)
    selected_tool_id: str = Field(..., min_length=1)
    resource_requirements: Optional[Dict[str, Any]] = None
    priority_level: Optional[str] = "MEDIUM"
    priority_score: Optional[float] = 0.5
    timeout_seconds: Optional[int] = Field(default=300, ge=10, le=86400)
    retry_policy: Optional[Dict[str, Any]] = None
    dependencies: Optional[List[str]] = None


class AnalysisRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    plan_id: str
    task_id: Optional[str] = None
    task_key: str
    evidence_id: Optional[str] = None
    capability_id: str
    selected_tool_id: str
    resource_requirements: Dict[str, Any] = {}
    priority_level: str
    priority_score: float
    timeout_seconds: int
    retry_policy: Dict[str, Any] = {}
    dependencies: List[str] = []
    scheduler_status: str
    allocated_resources: Dict[str, Any] = {}
    blocking_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    queued_at: datetime
    ready_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class SchedulerPlanBatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    plan_id: str
    case_id: str
    total_tasks: int
    scheduled_jobs: int
    blocked_jobs: int
    requests: List[AnalysisRequestResponse] = []


class SchedulerStatusResponse(BaseModel):
    total_jobs: int
    status_counts: Dict[str, int]
    max_concurrent_jobs: int
    active_jobs_count: int
    host_capacity: Dict[str, Any]
    allocated_resources: Dict[str, Any]
    available_capacity: Dict[str, Any]


class SchedulerEvaluationResponse(BaseModel):
    evaluated_jobs: int
    promoted_to_ready: int
    waiting_resource: int
    waiting_dependency: int
    blocked: int
    timed_out: int
    scheduler_status: SchedulerStatusResponse


# =============================================================================
# PHASE 2 / STEP 9: SECURE FORENSIC EXECUTION SCHEMAS
# =============================================================================

class ExecutionOutputResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    execution_id: str
    request_id: str
    case_id: str
    task_id: Optional[str] = None
    evidence_id: Optional[str] = None
    tool_id: Optional[str] = None
    tool_version: Optional[str] = None
    output_type: str = "TOOL_OUTPUT" # TOOL_OUTPUT, STDOUT, STDERR, LOG
    filename: str
    relative_path: str
    storage_path: str
    size_bytes: int
    sha256_hash: str
    mime_type: Optional[str] = None
    exit_code: Optional[int] = None
    execution_status: Optional[str] = None
    metadata_json: Dict[str, Any] = {}
    created_at: datetime


class OutputIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    output_id: str
    filename: str
    output_type: str
    expected_sha256: str
    calculated_sha256: str
    integrity_verified: bool
    size_bytes: int
    checked_at: datetime



class ForensicExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    request_id: str
    case_id: str
    plan_id: Optional[str] = None
    task_id: Optional[str] = None
    task_key: str
    evidence_id: Optional[str] = None
    tool_id: str
    tool_version: Optional[str] = None
    executable_path: str
    validated_argv: List[str] = []
    host_platform: str
    host_architecture: str
    workspace_path: str
    resource_allocation: Dict[str, Any] = {}
    timeout_seconds: int
    execution_status: str
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    process_start_time: Optional[float] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    cancellation_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    output_count: int = 0
    created_at: datetime
    updated_at: datetime
    outputs: List[ExecutionOutputResponse] = []


class ExecutionStartRequest(BaseModel):
    custom_parameters: Dict[str, Any] = {}


class ExecutionStatusResponse(BaseModel):
    execution_id: str
    request_id: str
    execution_status: str
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    duration_seconds: Optional[float] = None
    output_count: int = 0


class ExecutionCancelRequest(BaseModel):
    reason: Optional[str] = "Cancelled by investigator"


class ExecutionArtifactContentResponse(BaseModel):
    execution_id: str
    stream_type: str
    content: str
    is_truncated: bool
    total_bytes: int


# =============================================================================
# PHASE 2 / STEP 11: STRUCTURED ARTIFACT EXTRACTION SCHEMAS
# =============================================================================

class StructuredArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: Optional[str] = None
    execution_id: str
    raw_output_id: str
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    tool_id: Optional[str] = None
    tool_version: Optional[str] = None
    parser_name: str
    parser_version: str
    artifact_type: str
    source_reference: Optional[str] = None
    normalized_data: Dict[str, Any] = {}
    raw_record: Optional[str] = None
    sha256_hash: str
    source_raw_output_hash: str
    storage_path: Optional[str] = None
    extraction_status: str
    error_message: Optional[str] = None
    created_at: datetime


class ArtifactIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    artifact_type: str
    expected_sha256: str
    calculated_sha256: str
    source_raw_output_hash: str
    raw_output_current_hash: Optional[str] = None
    integrity_status: str # VALID, TAMPERED, FILE_MISSING, RAW_OUTPUT_MISMATCH
    provenance_chain: Dict[str, Any]
    checked_at: datetime


class ArtifactExtractionBatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    execution_id: str
    total_raw_outputs: int
    processed_outputs: int
    extracted_artifacts_count: int
    unsupported_outputs_count: int
    artifacts: List[StructuredArtifactResponse]


# =============================================================================
# PHASE 2 / STEP 12: ARTIFACT NORMALIZATION SCHEMAS
# =============================================================================

class NormalizedArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: Optional[str] = None
    execution_id: str
    source_artifact_id: str
    raw_output_id: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    entity_type: str
    entity_identity: str
    source_specific_identity: Optional[str] = None
    normalized_fields: Dict[str, Any] = {}
    evidence_reference: Dict[str, Any] = {}
    provenance_summary: Dict[str, Any] = {}
    contributing_source_artifact_ids: List[str] = []
    occurrence_count: int = 1
    entity_timestamp: Optional[datetime] = None
    sha256_hash: str
    source_artifact_hash: str
    storage_path: Optional[str] = None
    normalization_status: str
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class NormalizedIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    normalized_id: str
    entity_type: str
    entity_identity: str
    expected_sha256: str
    calculated_sha256: str
    source_artifact_hash: str
    source_artifact_current_hash: Optional[str] = None
    integrity_status: str  # VALID, TAMPERED, FILE_MISSING, SOURCE_ARTIFACT_MISMATCH
    provenance_chain: Dict[str, Any]
    checked_at: datetime


class NormalizedProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    normalized_id: str
    case_id: str
    entity_type: str
    entity_identity: str
    occurrence_count: int
    contributing_source_artifact_ids: List[str]
    evidence: Dict[str, Any]
    execution: Dict[str, Any]
    raw_output: Optional[Dict[str, Any]] = None
    source_artifact: Dict[str, Any]
    parser_info: Dict[str, Any]
    traceability_chain: List[str]
    created_at: datetime
    updated_at: datetime


class NormalizationBatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    execution_id: str
    case_id: str
    total_structured_artifacts: int
    processed_count: int
    normalized_created_count: int
    deduplicated_count: int
    unsupported_count: int
    normalized_artifacts: List[NormalizedArtifactResponse]


# =============================================================================
# PHASE 2 / STEP 13: UNIFIED TIMELINE SCHEMAS
# =============================================================================

class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    evidence_id: Optional[str] = None
    execution_id: str
    normalized_artifact_id: str
    structured_artifact_id: Optional[str] = None
    timestamp_utc: datetime
    original_timestamp: str
    original_timezone: Optional[str] = None
    timezone_offset: Optional[str] = None
    timezone_source: Optional[str] = None
    timezone_status: str
    event_type: str
    event_source: str
    event_data: Dict[str, Any] = {}
    confidence_score: float
    temporal_precision: str
    window_start_utc: Optional[datetime] = None
    window_end_utc: Optional[datetime] = None
    sha256_hash: str
    source_artifact_hash: str
    storage_path: Optional[str] = None
    created_at: datetime


class TimelineIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    event_type: str
    timestamp_utc: datetime
    expected_sha256: str
    calculated_sha256: str
    source_artifact_hash: str
    source_artifact_current_hash: Optional[str] = None
    integrity_status: str  # VALID, TAMPERED, FILE_MISSING, SOURCE_ARTIFACT_MISMATCH
    provenance_chain: Dict[str, Any]
    checked_at: datetime


class TimelineProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    case_id: str
    event_type: str
    event_source: str
    timestamp_utc: datetime
    original_timestamp: str
    timezone_metadata: Dict[str, Any]
    confidence_score: float
    temporal_precision: str
    evidence: Dict[str, Any]
    execution: Dict[str, Any]
    raw_output: Optional[Dict[str, Any]] = None
    structured_artifact: Optional[Dict[str, Any]] = None
    normalized_artifact: Dict[str, Any]
    traceability_chain: List[str]
    created_at: datetime


class TimelineBatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    execution_id: Optional[str] = None
    total_normalized_artifacts: int
    processed_count: int
    events_generated_count: int
    skipped_count: int
    events: List[TimelineEventResponse]


# =============================================================================
# STEP 14: CROSS-DOMAIN CORRELATION SCHEMAS
# =============================================================================

class CorrelationGenerateRequest(BaseModel):
    time_window_seconds: float = Field(default=60.0, ge=1.0, le=86400.0)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    include_temporal: bool = True
    include_cross_domain: bool = True


class RelationshipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    group_id: Optional[str] = None
    source_id: str
    source_type: str
    source_domain: str
    target_id: str
    target_type: str
    target_domain: str
    relationship_type: str
    matching_identifier: Optional[str] = None
    matching_field: Optional[str] = None
    temporal_relationship: Optional[Dict[str, Any]] = None
    confidence_score: float
    evidence_ids: List[str] = []
    provenance: Dict[str, Any] = {}
    sha256_hash: str
    storage_path: Optional[str] = None
    created_at: datetime


class RelationshipIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    relationship_id: str
    relationship_type: str
    stored_sha256: str
    computed_sha256: str
    integrity_passed: bool
    file_exists: bool
    tamper_detected: bool
    storage_path: Optional[str] = None
    checked_at: datetime


class RelationshipProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    relationship_id: str
    case_id: str
    relationship_type: str
    matching_identifier: Optional[str] = None
    matching_field: Optional[str] = None
    confidence_score: float
    evidence_ids: List[str] = []
    source_id: str
    source_type: str
    source_domain: str
    source_provenance: Dict[str, Any] = {}
    target_id: str
    target_type: str
    target_domain: str
    target_provenance: Dict[str, Any] = {}
    temporal_relationship: Optional[Dict[str, Any]] = None
    created_at: datetime


class CorrelationGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    title: str
    description: str
    member_artifact_ids: List[str] = []
    member_event_ids: List[str] = []
    relationship_ids: List[str] = []
    contributing_domains: List[str] = []
    source_evidence_ids: List[str] = []
    confidence_score: float
    sha256_hash: str
    storage_path: Optional[str] = None
    created_at: datetime


class CorrelationGroupDetailResponse(CorrelationGroupResponse):
    member_artifacts: List[Dict[str, Any]] = []
    member_events: List[Dict[str, Any]] = []
    relationships: List[RelationshipResponse] = []


class GroupIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    group_id: str
    title: str
    stored_sha256: str
    computed_sha256: str
    integrity_passed: bool
    file_exists: bool
    tamper_detected: bool
    storage_path: Optional[str] = None
    checked_at: datetime


class CorrelationGraphNode(BaseModel):
    id: str
    node_type: str  # NORMALIZED_ARTIFACT, TIMELINE_EVENT
    domain: str  # FILESYSTEM, MEMORY, NETWORK, MALWARE, LOGS, METADATA, GENERIC
    entity_type: str
    label: str
    confidence: float
    evidence_id: Optional[str] = None
    group_ids: List[str] = []
    provenance: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}


class CorrelationGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    matching_identifier: Optional[str] = None
    matching_field: Optional[str] = None
    temporal_relationship: Optional[Dict[str, Any]] = None
    confidence: float
    group_id: Optional[str] = None


class CorrelationGraphResponse(BaseModel):
    case_id: str
    nodes: List[CorrelationGraphNode]
    edges: List[CorrelationGraphEdge]
    groups: List[CorrelationGroupResponse]
    total_nodes: int
    total_edges: int
    total_groups: int


class CorrelationSummaryResponse(BaseModel):
    case_id: str
    relationships_generated: int
    groups_created: int
    total_nodes_correlated: int
    relationships: List[RelationshipResponse] = []
    groups: List[CorrelationGroupResponse] = []
    execution_timestamp: datetime


# =============================================================================
# STEP 15: DETERMINISTIC FINDINGS SCHEMAS
# =============================================================================

class FindingGenerateRequest(BaseModel):
    time_window_seconds: Optional[float] = Field(default=None, ge=1.0, le=86400.0)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    include_rules: Optional[List[str]] = None
    evidence_id: Optional[str] = None


class DeterministicFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    title: str
    description: str
    observed_facts: List[Dict[str, Any]] = []
    finding_type: str
    severity: str # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    severity_rule: str
    confidence: float
    confidence_inputs: Dict[str, Any] = {}
    supporting_artifact_ids: List[str] = []
    supporting_event_ids: List[str] = []
    supporting_relationship_ids: List[str] = []
    supporting_group_ids: List[str] = []
    supporting_evidence_ids: List[str] = []
    provenance: Dict[str, Any] = {}
    sha256_hash: str
    storage_path: Optional[str] = None
    created_at: datetime


class FindingIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    title: str
    stored_sha256: str
    computed_sha256: str
    integrity_passed: bool
    file_exists: bool
    tamper_detected: bool
    storage_path: Optional[str] = None
    checked_at: datetime


class FindingProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    case_id: str
    title: str
    finding_type: str
    severity: str
    severity_rule: str
    confidence: float
    confidence_inputs: Dict[str, Any] = {}
    provenance_chain: Dict[str, Any] = {}
    supporting_evidence_ids: List[str] = []
    lineage_summary: List[Dict[str, Any]] = []
    created_at: datetime


class FindingSupportingEvidenceResponse(BaseModel):
    finding_id: str
    case_id: str
    observed_facts: List[Dict[str, Any]] = []
    supporting_artifacts: List[Dict[str, Any]] = []
    supporting_events: List[Dict[str, Any]] = []
    supporting_relationships: List[Dict[str, Any]] = []
    supporting_groups: List[Dict[str, Any]] = []
    supporting_evidence_items: List[Dict[str, Any]] = []


class FindingSummaryResponse(BaseModel):
    case_id: str
    total_findings_generated: int
    severity_breakdown: Dict[str, int] = {}
    type_breakdown: Dict[str, int] = {}
    findings: List[DeterministicFindingResponse] = []
    generated_at: datetime




# ============================================================
# Step 16 Specialist Agent Schemas
# ============================================================

class SpecialistAgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    version: str
    agent_type: str
    description: str
    supported_evidence_domains: List[str] = []
    supported_artifact_types: List[str] = []
    supported_analysis_capabilities: List[str] = []
    is_enabled: bool
    status: str
    safety_permission_profile: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class AgentToggleRequest(BaseModel):
    is_enabled: bool


class AgentAnalysisRequestCreate(BaseModel):
    agent_id: str
    analysis_objective: str
    evidence_id: Optional[str] = None
    input_references: Dict[str, Any] = Field(default_factory=dict)


class AgentAnalysisRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    agent_id: str
    agent_version: str
    evidence_id: Optional[str] = None
    analysis_objective: str
    lifecycle_state: str
    input_references: Dict[str, Any] = {}
    requested_capabilities: List[str] = []
    results_summary: Dict[str, Any] = {}
    error_message: Optional[str] = None
    sha256_hash: str
    storage_path: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class AgentAnalysisResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    request_id: str
    case_id: str
    agent_id: str
    agent_version: str
    analysis_type: str
    observations: List[Dict[str, Any]] = []
    capability_requests: List[Dict[str, Any]] = []
    supporting_evidence_ids: List[str] = []
    supporting_artifact_ids: List[str] = []
    supporting_correlation_ids: List[str] = []
    supporting_finding_ids: List[str] = []
    confidence_inputs: Dict[str, Any] = {}
    confidence_score: float
    provenance: Dict[str, Any] = {}
    sha256_hash: str
    storage_path: Optional[str] = None
    created_at: datetime


class AgentCapabilityRequestCreate(BaseModel):
    capability_id: str
    evidence_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    priority: int = 1


class AgentCapabilityRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    agent_id: str
    request_id: str
    capability_id: str
    evidence_id: str
    parameters: Dict[str, Any] = {}
    rationale: str
    priority: int
    validation_status: str
    validation_error: Optional[str] = None
    sha256_hash: str
    created_at: datetime
    updated_at: datetime


class AgentIntegrityCheckResponse(BaseModel):
    result_id: str
    status: str
    is_intact: bool
    db_hash: str
    current_hash: Optional[str] = None
    verified_at: Optional[str] = None
    error: Optional[str] = None


class AgentProvenanceTraceResponse(BaseModel):
    request_id: str
    case_id: str
    agent_id: str
    agent_version: str
    lifecycle_state: str
    sha256_hash: str
    provenance: Dict[str, Any] = {}
    lifecycle_history: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    capability_requests: List[Dict[str, Any]] = []


# =============================================================================
# STEP 17: GOVERNANCE GATE SCHEMAS
# =============================================================================

class GovernanceEvaluateRequest(BaseModel):
    requesting_agent: Optional[str] = None
    action_type: str  # e.g. CAPABILITY_REQUEST, EXECUTION, REPORT_GENERATION, DESTRUCTIVE_TOOL, etc.
    target_resource_type: Optional[str] = None  # EVIDENCE, ARTIFACT, TOOL_OUTPUT, CAPABILITY
    target_resource_id: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    input_references: Dict[str, Any] = Field(default_factory=dict)
    content_payload: Optional[str] = None  # Text payload to scan for PII or prompt injection


class GovernanceDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    requesting_agent: Optional[str] = None
    action_type: str
    target_resource_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    policy_checks: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    approval_status: str  # NOT_REQUIRED, REQUIRED, PENDING, APPROVED, REJECTED
    decision: str  # APPROVED, BLOCKED, REVIEW_REQUIRED
    reason: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    input_references: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    sha256_hash: str


class GovernanceApprovalRequest(BaseModel):
    notes: Optional[str] = None


class GovernanceRejectionRequest(BaseModel):
    reason: str


class EvidenceVerifyRequest(BaseModel):
    target_type: str  # EVIDENCE, RAW_OUTPUT, STRUCTURED_ARTIFACT, NORMALIZED_ARTIFACT, TOOL_OUTPUT
    target_id: str
    notes: Optional[str] = None


class EvidenceVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    target_type: str
    target_id: str
    verification_status: str  # VERIFIED, FAILED, REVIEW_REQUIRED
    integrity_check: Dict[str, Any] = Field(default_factory=dict)
    lineage_check: Dict[str, Any] = Field(default_factory=dict)
    provenance_check: Dict[str, Any] = Field(default_factory=dict)
    metadata_check: Dict[str, Any] = Field(default_factory=dict)
    contradiction_check: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    sha256_hash: str


class GovernanceAuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: Optional[str] = None
    decision_id: Optional[str] = None
    verification_id: Optional[str] = None
    event_type: str
    actor: str
    input_references: Dict[str, Any] = Field(default_factory=dict)
    checks_performed: List[str] = Field(default_factory=list)
    decision: str
    reason: str
    approval_identity: Optional[str] = None
    timestamp: datetime
    event_hash: str
    prev_event_hash: Optional[str] = None


# =============================================================================
# STEP 18: AI REASONING LAYER SCHEMAS
# =============================================================================

class AIStatementItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    statement_id: str
    insight: str
    classification: str  # FACT, INFERENCE, UNVERIFIED
    confidence: Optional[float] = None
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    supporting_artifact_ids: List[str] = Field(default_factory=list)
    supporting_finding_ids: List[str] = Field(default_factory=list)
    supporting_correlation_ids: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    reasoning_metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    version: str = "1.0.0"


class AIProviderConfigRequest(BaseModel):
    provider: str
    model: str
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    is_enabled: bool = True


class AIProviderConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    provider: str
    model: str
    endpoint: Optional[str] = None
    has_api_key: bool = False
    masked_api_key: Optional[str] = None
    is_enabled: bool = True
    status: str = "CONFIGURED"
    last_tested_at: Optional[datetime] = None
    last_test_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AIProviderConnectionTestRequest(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    endpoint: Optional[str] = None
    api_key: Optional[str] = None


class AIProviderConnectionTestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    model: str
    success: bool
    status_message: str
    latency_ms: Optional[float] = None
    has_key: bool = False


class AIReasoningRequest(BaseModel):
    objective: str
    finding_ids: Optional[List[str]] = None
    artifact_ids: Optional[List[str]] = None
    timeline_event_ids: Optional[List[str]] = None
    correlation_ids: Optional[List[str]] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    allow_external_egress: bool = False


class AIReasoningResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    objective: str
    status: str  # COMPLETED, BLOCKED, FAILED, REVIEW_REQUIRED
    execution_mode: str  # EXTERNAL_LLM, LOCAL_LLM, DETERMINISTIC_FALLBACK
    provider: str
    model: str
    governance_decision_id: Optional[str] = None
    input_references: Dict[str, List[str]] = Field(default_factory=dict)
    raw_evidence_egress_blocked: bool = True
    egress_approved: bool = False
    statements: List[AIStatementItem] = Field(default_factory=list)
    citations_verified: bool = True
    summary: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    reasoning_metadata: Dict[str, Any] = Field(default_factory=dict)
    sha256_hash: str
    created_at: datetime
    completed_at: Optional[datetime] = None


class AIReasoningIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reasoning_id: str
    expected_hash: str
    computed_hash: str
    integrity_status: str  # VERIFIED, FAILED
    tamper_detected: bool
    checked_at: datetime


class AIReasoningProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reasoning_id: str
    case_id: str
    governance_decision_id: Optional[str] = None
    provider: str
    model: str
    execution_mode: str
    input_references: Dict[str, List[str]] = Field(default_factory=dict)
    statements_count: int
    raw_evidence_egress_blocked: bool
    sha256_hash: str
    created_at: datetime


# =============================================================================
# STEP 19: INVESTIGATOR REVIEW SCHEMAS
# =============================================================================

class InvestigatorDecisionType(str, Enum):
    ACCEPT = "ACCEPT"
    CHALLENGE = "CHALLENGE"
    REJECT = "REJECT"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"


class InvestigatorReviewCreateRequest(BaseModel):
    target_type: str = Field(..., description="Target type: FINDING, AI_REASONING, CLAIM")
    target_id: str = Field(..., min_length=1, description="Target finding or reasoning record ID")
    statement_id: Optional[str] = Field(None, description="Optional specific AI statement ID")
    decision: str = Field(..., description="ACCEPT, CHALLENGE, REJECT, or REQUEST_MORE_EVIDENCE")
    comment: Optional[str] = Field(None, description="Investigator rationale and notes")
    supporting_references: List[str] = Field(default_factory=list, description="Referenced evidence/artifact/finding IDs")


class InvestigatorReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    investigator_id: str
    investigator_name: Optional[str] = None
    target_type: str
    target_id: str
    statement_id: Optional[str] = None
    decision: str
    comment: Optional[str] = None
    supporting_references: List[str] = Field(default_factory=list)
    resulting_workflow_action: Optional[str] = None
    action_reference_id: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    review_metadata: Dict[str, Any] = Field(default_factory=dict)
    sha256_hash: str
    storage_path: Optional[str] = None
    timestamp: datetime
    created_at: datetime
    updated_at: datetime


class InvestigatorReviewIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    review_id: str
    expected_hash: str
    computed_hash: str
    integrity_status: str  # VERIFIED, FAILED
    tamper_detected: bool
    checked_at: datetime


class RequestMoreEvidenceRequest(BaseModel):
    target_type: str = "CLAIM"
    target_id: str = Field(..., min_length=1)
    statement_id: Optional[str] = None
    evidence_id: Optional[str] = None
    analysis_objective: str = Field(..., min_length=1)
    requested_capability: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    comment: str = Field(..., min_length=1)
    supporting_references: List[str] = Field(default_factory=list)


class RequestMoreEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    review: InvestigatorReviewResponse
    governance_decision_id: Optional[str] = None
    analysis_request_id: Optional[str] = None
    execution_id: Optional[str] = None
    workflow_status: str
    message: str


class ReviewItemsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    deterministic_findings: List[Dict[str, Any]] = Field(default_factory=list)
    ai_reasoning_records: List[Dict[str, Any]] = Field(default_factory=list)
    existing_reviews: List[InvestigatorReviewResponse] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class ClaimProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    target_type: str
    target_id: str
    statement_id: Optional[str] = None
    claim_summary: Dict[str, Any] = Field(default_factory=dict)
    lineage: List[Dict[str, Any]] = Field(default_factory=list)
    supporting_artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    verified_integrity: bool


# =============================================================================
# STEP 20: FINAL FORENSIC REPORT SCHEMAS
# =============================================================================

class ForensicReportGenerateRequest(BaseModel):
    title: Optional[str] = None
    executive_summary_override: Optional[str] = None
    methodology_notes: Optional[str] = None
    include_ai_reasoning: bool = True
    include_investigator_reviews: bool = True
    options: Dict[str, Any] = Field(default_factory=dict)


class ForensicReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    version: int
    title: str
    executive_summary: str
    findings_count: int
    evidence_count: int
    full_report_markdown: str
    report_hash: str
    sha256_hash: Optional[str] = None
    status: str
    sections: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    report_metadata: Dict[str, Any] = Field(default_factory=dict)
    integrity_status: str
    evidence_integrity_summary: Dict[str, Any] = Field(default_factory=dict)
    storage_path: Optional[str] = None
    generated_by: str
    generated_at: datetime

    @model_validator(mode="after")
    def sync_hashes(self):
        if not self.sha256_hash and self.report_hash:
            self.sha256_hash = self.report_hash
        elif not self.report_hash and self.sha256_hash:
            self.report_hash = self.sha256_hash
        return self


class ForensicReportVersionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    version: int
    title: str
    findings_count: int
    evidence_count: int
    report_hash: str
    sha256_hash: Optional[str] = None
    status: str
    integrity_status: str
    generated_by: str
    generated_at: datetime

    @model_validator(mode="after")
    def sync_hashes(self):
        if not self.sha256_hash and self.report_hash:
            self.sha256_hash = self.report_hash
        elif not self.report_hash and self.sha256_hash:
            self.report_hash = self.sha256_hash
        return self


class ForensicReportIntegrityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    case_id: str
    version: int
    expected_hash: str
    computed_hash: str
    integrity_status: str  # VERIFIED, TAMPERED, FAILED
    tamper_detected: bool
    evidence_integrity: Dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime


class ForensicReportProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    case_id: str
    version: int
    lineage: List[Dict[str, Any]] = Field(default_factory=list)
    graph: Dict[str, Any] = Field(default_factory=dict)
    node_counts: Dict[str, int] = Field(default_factory=dict)
    report_hash: str


# =============================================================================
# STEP 21: INVESTIGATION ORCHESTRATION, AUDIT CHAIN, RECOVERY & CASE CLOSURE
# =============================================================================

class InvestigationRunCreateRequest(BaseModel):
    plan_id: Optional[str] = None
    stopping_conditions: Optional[Dict[str, Any]] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class InvestigationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    plan_id: Optional[str] = None
    cycle_number: int
    current_stage: str
    status: str
    stage_progress: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    failure_count: int
    run_metadata: Dict[str, Any] = Field(default_factory=dict)
    sha256_hash: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class InvestigationRunActionRequest(BaseModel):
    action: Optional[str] = Field(default=None, description="PAUSE, RESUME, CANCEL, or STEP")
    reason: Optional[str] = None


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_name: str
    event_type: str
    details: str
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    ip_address: str
    timestamp: datetime
    event_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    chain_index: Optional[int] = None
    provenance_context: Dict[str, Any] = Field(default_factory=dict)


class AuditChainVerificationResponse(BaseModel):
    case_id: Optional[str] = None
    total_events: int
    is_valid: bool
    tamper_detected: bool
    broken_link_index: Optional[int] = None
    broken_event_id: Optional[str] = None
    verification_message: str
    genesis_hash: Optional[str] = None
    latest_hash: Optional[str] = None
    verified_at: datetime


class RecoveryRequest(BaseModel):
    force: bool = False
    safe_reset_stale_tasks: bool = True


class RecoveryResponse(BaseModel):
    case_id: str
    status: str
    recovered_runs_count: int
    recovered_tasks_count: int
    interrupted_tasks_resumed: int
    valid_outputs_preserved: int
    audit_chain_verified: bool
    message: str
    recovery_details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime


class CaseClosureRequest(BaseModel):
    rationale: str
    investigator_notes: Optional[str] = None
    confirm_audit_verification: bool = True


class CaseClosureResponse(BaseModel):
    case_id: str
    status: str
    closed_at: datetime
    closed_by: str
    closure_rationale: str
    closure_hash: str
    evidence_verified_count: int
    audit_chain_verified: bool
    final_report_verified: bool
    closure_metadata: Dict[str, Any] = Field(default_factory=dict)


