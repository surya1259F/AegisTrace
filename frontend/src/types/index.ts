export interface CasePermissions {
  view_case: boolean;
  edit_case_details: boolean;
  manage_members: boolean;
  manage_case_settings: boolean;
  add_evidence: boolean;
  run_investigation: boolean;
  view_findings: boolean;
  export_report: boolean;
}

export interface CaseMember {
  id: string;
  case_id: string;
  user_id: string;
  role: string;
  added_at: string;
  email?: string;
  name?: string;
}

export interface CaseMemberCreateRequest {
  user_id?: string;
  email?: string;
  role: string;
}

export interface Case {
  id: string;
  case_number?: string;
  name: string;
  title?: string;
  description?: string;
  objective?: string;
  case_type?: string;
  priority?: string;
  status: string;
  workspace_state?: string;
  workspace_path?: string;
  case_permissions?: CasePermissions;
  owner_id?: string;
  created_by?: string;
  investigator?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  evidence_count?: number;
  findings_count?: number;
  artifacts_count?: number;
  members_count?: number;
}

export interface CaseCreateRequest {
  title: string;
  name?: string;
  case_number?: string;
  description?: string;
  objective?: string;
  case_type?: string;
  priority?: string;
  case_permissions?: Record<string, boolean>;
  members?: CaseMemberCreateRequest[];
}

export interface CaseUpdateRequest {
  name?: string;
  title?: string;
  description?: string;
  objective?: string;
  case_type?: string;
  priority?: string;
  status?: string;
  case_permissions?: Record<string, boolean>;
}

export interface WorkspaceStatusResponse {
  case_id: string;
  workspace_state: string;
  workspace_path?: string;
  exists: boolean;
  subdirectories_present: string[];
  metadata_present: boolean;
  is_ready: boolean;
}

export type Investigation = Case;

export interface CustodyRecord {
  id: string;
  evidence_id: string;
  event_type: string;
  timestamp: string;
  actor: string;
  description: string;
  source_path?: string;
  destination_path?: string;
  sha256?: string;
  metadata_json: Record<string, any>;
}

export interface Evidence {
  id: string;
  investigation_id: string;
  name: string;
  original_path: string;
  storage_path?: string;
  evidence_type: string;
  evidence_subtype?: string;
  source_kind?: string;
  acquisition_method?: string;
  detected_format?: string;
  filesystem_type?: string;
  platform_hint?: string;
  size_bytes: number;
  sha256: string;
  md5?: string;
  mime_type?: string;
  status?: string;
  created_at: string;
  modified_at: string;
  intake_status: string;
  integrity_status: string;
  read_only_verified: boolean;
  notes?: string;
  created_by: string;
  metadata_json?: Record<string, any>;
  intelligence_json?: Record<string, any>;
  error_message?: string;
}

export interface EvidenceVerificationResult {
  evidence_id: string;
  integrity_status: string;
  expected_sha256: string;
  current_sha256: string;
  read_only_verified: boolean;
  verified_at: string;
  message: string;
}

export interface ToolRecommendation {
  tool_id: string;
  tool_name: string;
  is_available: boolean;
  binary_path?: string;
  tool_version?: string;
  capabilities: string[];
  rationale: string;
}

export interface AnalysisFamilyRecommendation {
  family_name: string;
  status: 'RECOMMENDED' | 'POSSIBLE' | 'NOT_APPLICABLE' | 'REQUIRES_TOOL';
  rationale: string;
}

export interface ResourceProfile {
  estimated_input_size_bytes: number;
  expected_cpu_class: string;
  expected_memory_class: string;
  expected_storage_class: string;
  expected_duration_class: string;
  parallelism_hint: string;
  risk_level: string;
}

export interface EvidenceIntelligence {
  evidence_id: string;
  evidence_name: string;
  source_kind: string;
  evidence_type: string;
  evidence_subtype?: string;
  detected_format: string;
  detected_mime: string;
  confidence: number;
  filesystem_type: string;
  platform_hint: string;
  size_bytes: number;
  characteristics: string[];
  detection_methods: Record<string, any>[];
  recommended_analysis_families: AnalysisFamilyRecommendation[];
  recommended_tools: ToolRecommendation[];
  resource_profile: ResourceProfile;
  limitations: string[];
  engine_version: string;
  generated_at: string;
}

export interface EvidenceTag {
  tag: string;
  category: string;
  basis: string;
}

export interface PartitionInfo {
  partition_number: number;
  partition_type: string;
  filesystem: string;
  start_sector: number;
  size_sectors: number;
}

export interface EvidenceIntelligenceProfile {
  id: string;
  evidence_id: string;
  case_id: string;
  engine_version: string;
  analysis_version: number;
  classification: string;
  subtype?: string;
  classification_status: 'MATCH' | 'MISMATCH' | 'UNKNOWN' | 'PARTIAL';
  classification_confidence: string;
  classification_basis?: string;
  detected_format: string;
  detected_mime: string;
  platform_hint: string;
  platform_basis?: string;
  platform_confidence: string;
  architecture_hint: string;
  filesystem_type: string;
  filesystem_version?: string;
  filesystem_basis?: string;
  filesystem_detection_status: string;
  partition_table_type: string;
  partitions_json?: PartitionInfo[];
  metadata_json?: Record<string, any>;
  characteristics_json?: string[];
  detection_methods?: Record<string, any>[];
  tags_json?: EvidenceTag[];
  resource_profile_json?: ResourceProfile;
  recommended_tools_json?: ToolRecommendation[];
  recommended_families_json?: AnalysisFamilyRecommendation[];
  limitations_json?: string[];
  evidence_sha256_verified: string;
  generated_at: string;
  created_at: string;
  updated_at: string;
}

export interface Artifact {
  id: string;
  investigation_id: string;
  evidence_id: string;
  agent: string;
  tool: string;
  artifact_type: string;
  source_reference: string;
  path?: string;
  inode?: string;
  size_bytes?: number;
  is_deleted: boolean;
  metadata_json: Record<string, any>;
  raw_output_reference?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  investigation_id: string;
  evidence_id?: string;
  agent: string;
  tool: string;
  finding_type: string;
  title: string;
  description: string;
  confidence?: number;
  timestamp?: string;
  evidence_reference?: string;
  verification_status: 'SUPPORTED' | 'UNSUPPORTED' | 'CONFLICTING' | 'UNVERIFIED';
  raw_output_reference?: string;
  created_at: string;
}

export interface DiskAnalysisResult {
  investigation_id: string;
  evidence_id: string;
  status: string;
  execution_id: string;
  artifacts_count: number;
  findings_count: number;
  execution_time_ms: number;
  tool_version?: string;
  raw_output_reference?: string;
  error?: string;
  artifacts: Artifact[];
  findings: Finding[];
}

export interface MemoryAnalysisResult {
  investigation_id: string;
  evidence_id: string;
  status: string;
  plugin: string;
  execution_id: string;
  artifacts_count: number;
  findings_count: number;
  execution_time_ms: number;
  tool_version?: string;
  raw_output_reference?: string;
  error?: string;
  artifacts: Artifact[];
  findings: Finding[];
}

export interface MalwareAnalysisResult {
  investigation_id: string;
  evidence_id: string;
  status: string;
  rule_id: string;
  rule_sha256?: string;
  execution_id: string;
  artifacts_count: number;
  findings_count: number;
  execution_time_ms: number;
  tool_version?: string;
  raw_output_reference?: string;
  error?: string;
  artifacts: Artifact[];
  findings: Finding[];
}

export interface LogAnalysisResult {
  investigation_id: string;
  evidence_id: string;
  status: string;
  execution_id: string;
  artifacts_count: number;
  findings_count: number;
  execution_time_ms: number;
  tool_version?: string;
  raw_output_reference?: string;
  error?: string;
  artifacts: Artifact[];
  findings: Finding[];
}

export interface PlanStep {
  step_id: string;
  task_id?: string;
  agent: string;
  agent_name?: string;
  tool: string;
  tool_name?: string;
  tool_available: boolean;
  evidence_id?: string;
  evidence_name?: string;
  action: string;
  reason?: string;
  dependencies?: string[];
  priority: number;
  status?: string;
  parameters?: Record<string, any>;
  estimated_resource_cost?: Record<string, string>;
  execution_id?: string;
  artifacts_count?: number;
  findings_count?: number;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
}

export interface StrategyTask {
  task_key: string;
  capability_id: string;
  agent_name: string;
  evidence_ids: string[];
  evidence_name?: string;
  candidate_tool_ids: string[];
  selected_tool_id?: string;
  priority_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BLOCKED';
  priority_score: number;
  priority_rationale?: Record<string, any>;
  status: string;
  required_inputs: string[];
  expected_outputs: string[];
  resource_requirements: Record<string, any>;
  estimated_cost?: Record<string, any>;
  rationale?: Record<string, any>;
  blocking_reason?: string;
  dependencies: string[];
  sequence?: number;
}

export interface DependencyGraphNode {
  id: string;
  label: string;
  agent: string;
  tool: string;
  priority: string;
  status: string;
  evidence_id?: string;
}

export interface DependencyGraphEdge {
  source: string;
  target: string;
  type: string;
}

export interface DependencyGraph {
  plan_id: string;
  case_id: string;
  nodes: DependencyGraphNode[];
  edges: DependencyGraphEdge[];
  is_valid_dag: boolean;
}

export interface StoppingCondition {
  condition_code: string;
  trigger_description: string;
  explanation: string;
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  human_review_required: boolean;
}

export interface PlanAdjustment {
  adjustment_type: string;
  summary: string;
  previous_state?: Record<string, any>;
  new_state?: Record<string, any>;
  actor_id?: string;
}

export interface ForensicCapability {
  id: string;
  name: string;
  description: string;
  category: string;
  supported_evidence_categories: string[];
  supported_evidence_subtypes: string[];
  supported_formats: string[];
  supported_platforms: string[];
  required_inputs: string[];
  expected_outputs: string[];
  prerequisites: string[];
  resource_profile: Record<string, any>;
  priority_hints: Record<string, any>;
  version: string;
  enabled: boolean;
}

export interface ForensicTool {
  capability_id: string;
  tool_name: string;
  executable_name: string;
  is_installed: boolean;
  executable_path: string;
  health_status: string;
}

export interface InvestigationPlan {
  id?: string;
  investigation_id: string;
  case_id?: string;
  parent_plan_id?: string;
  title?: string;
  steps: PlanStep[];
  tasks?: (PlanStep | StrategyTask)[];
  strategy_summary: string;
  validation_status?: string;
  total_tasks: number;
  status: string;
  version?: number;
  evidence_snapshot?: any[];
  resource_snapshot?: Record<string, any>;
  stopping_conditions?: StoppingCondition[];
  adjustments?: PlanAdjustment[];
  created_at?: string;
  completed_at?: string;
}

export interface PlanExecutionSummary {
  investigation_id: string;
  plan_id: string;
  status: string;
  tasks_executed: number;
  tasks_succeeded: number;
  tasks_failed: number;
  total_artifacts: number;
  total_findings: number;
  tasks: PlanStep[];
}

export interface CorrelatedGroup {
  id?: string;
  case_id?: string;
  investigation_id?: string;
  dimension: string;
  rule?: string;
  correlated_entity: string;
  title: string;
  description: string;
  tools_involved: string[];
  supporting_finding_ids: string[];
  supporting_artifact_ids?: string[];
  supporting_evidence_ids?: string[];
  correlation_confidence: number;
  created_at?: string;
}

export interface VerificationResult {
  finding_id?: string;
  verification_status: string;
  confidence_score: number;
  reason: string;
}

export interface Report {
  title: string;
  investigation_id: string;
  executive_summary: string;
  findings_count: number;
  evidence_count: number;
  full_report_markdown: string;
  generated_at: string;
}

export interface SystemStatus {
  application: string;
  version: string;
  status: string;
  platform: string;
  logical_cpus: number;
  max_concurrent_tasks: number;
  active_tasks: number;
  forensic_tools: Record<string, {
    name: string;
    available: boolean;
    version?: string;
    supported_evidence: string[];
  }>;
}

export type AuthStatus = 'RESTORING' | 'AUTHENTICATED' | 'UNAUTHENTICATED';

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  organization: string;
  badge_id?: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  roles?: string[];
  permissions?: string[];
}

export interface UserLoginRequest {
  email: string;
  password: string;
}

export interface UserRegisterRequest {
  email: string;
  name: string;
  password: string;
  organization?: string;
  badge_id?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_seconds: number;
  user: UserProfile;
}

export interface AIProviderConfig {
  provider: 'openai' | 'anthropic' | 'google' | 'local_stub';
  model: string;
  has_key: boolean;
  is_tested: boolean;
  status: 'AVAILABLE' | 'CONFIGURED' | 'NOT_CONFIGURED';
  last_tested?: string;
}

export interface AppSettings {
  theme: 'dark' | 'system';
  data_directory: string;
  stream_chunk_size_mb: number;
  session_timeout_minutes: number;
  audit_logging_enabled: boolean;
  read_only_mode: boolean;
}

export interface InvestigatorDecision {
  decision: 'CONFIRM' | 'REJECT' | 'INCONCLUSIVE' | 'REQUEST_MORE_EVIDENCE';
  investigator_notes: string;
  timestamp: string;
  investigator_id: string;
  investigator_name: string;
}

export interface CaseConfidenceBreakdown {
  overall_score: number;
  evidence_strength_weight: number;
  corroboration_score: number;
  verification_pass_rate: number;
  source_reliability_index: number;
  contradiction_penalties: number;
  completeness_pct: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  source_agent: string;
  source_tool: string;
  evidence_id: string;
  classification: 'FACT' | 'INFERENCE' | 'UNVERIFIED';
}

export interface MitreTacticMapping {
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  evidence_references: string[];
}

export interface ExtractedIOC {
  type: 'IP' | 'HASH' | 'FILENAME' | 'REGISTRY' | 'MUTEX';
  value: string;
  source_tool: string;
  finding_id: string;
}

export interface AuditEvent {
  id: string;
  case_id?: string;
  actor_id?: string;
  actor_name: string;
  event_type: string;
  details: string;
  metadata_json: Record<string, any>;
  ip_address: string;
  timestamp: string;
  event_hash?: string;
}

export interface ToolDefinition {
  tool_id: string;
  name: string;
  version?: string;
  executable_path: string;
  supported_evidence: string[];
  capabilities_json: Record<string, any>;
  is_available: boolean;
}

export type EgressPolicy = 'LOCAL_ONLY' | 'EXTERNAL_PROVIDER_ALLOWED' | 'EXTERNAL_PROVIDER_BLOCKED';

export type AIClaimType = 'FACT' | 'INFERENCE' | 'UNVERIFIED';

export interface AIClaimItem {
  claim_type: AIClaimType;
  statement: string;
  source_finding_id?: string | null;
  source_artifact_id?: string | null;
}

export interface AICopilotRequest {
  case_id: string;
  query: string;
  provider?: string;
  model?: string | null;
  api_key?: string | null;
  base_url?: string | null;
  egress_policy?: EgressPolicy;
}

export type CopilotQueryRequest = AICopilotRequest;

export interface AICopilotResponse {
  answer: string;
  claims: AIClaimItem[];
  provider: string;
  model: string;
  execution_mode: string;
  fallback_used: boolean;
  provider_status: string;
  context_truncated: boolean;
}

export interface AIExplainFindingRequest {
  case_id: string;
  finding_id: string;
  provider?: string;
  model?: string | null;
  api_key?: string | null;
  base_url?: string | null;
  egress_policy?: EgressPolicy;
}

export type ExplainFindingRequest = AIExplainFindingRequest;

export interface AIExplanationResponse {
  finding_id: string;
  title: string;
  explanation: string;
  mitre_techniques: string[];
  provider: string;
  model: string;
  execution_mode: string;
  fallback_used: boolean;
  provider_status: string;
}

export interface AIProviderTestRequest {
  provider: string;
  model?: string | null;
  api_key?: string | null;
  base_url?: string | null;
}

export type ProviderTestRequest = AIProviderTestRequest;

export interface AIProviderTestResponse {
  provider: string;
  model: string;
  status: string;
  details: string;
}

export type ProviderTestResponse = AIProviderTestResponse;

// ============================================================================
// Step 19 Investigator Review Types
// ============================================================================

export type InvestigatorDecisionType = 'ACCEPT' | 'CHALLENGE' | 'REJECT' | 'REQUEST_MORE_EVIDENCE';

export interface InvestigatorReviewCreateRequest {
  target_type: 'FINDING' | 'AI_REASONING' | 'CLAIM';
  target_id: string;
  statement_id?: string | null;
  decision: InvestigatorDecisionType;
  comment?: string;
  supporting_references?: string[];
}

export interface InvestigatorReviewResponse {
  id: string;
  case_id: string;
  investigator_id: string;
  investigator_name: string;
  target_type: string;
  target_id: string;
  statement_id?: string | null;
  decision: InvestigatorDecisionType;
  comment?: string;
  supporting_references: string[];
  resulting_workflow_action: string;
  action_reference_id?: string | null;
  provenance: Record<string, any>;
  review_metadata: Record<string, any>;
  sha256_hash: string;
  storage_path?: string | null;
  timestamp: string;
  created_at: string;
  updated_at: string;
}

export interface InvestigatorReviewIntegrityResponse {
  review_id: string;
  expected_hash: string;
  computed_hash: string;
  integrity_status: 'VERIFIED' | 'FAILED';
  tamper_detected: boolean;
  verified_at: string;
  storage_path?: string | null;
}

export interface RequestMoreEvidenceRequest {
  target_type: string;
  target_id: string;
  statement_id?: string | null;
  evidence_id?: string | null;
  analysis_objective: string;
  requested_capability: string;
  parameters?: Record<string, any>;
  comment?: string;
  supporting_references?: string[];
}

export interface RequestMoreEvidenceResponse {
  review_record: InvestigatorReviewResponse;
  analysis_request_id: string;
  task_key: string;
  pipeline_stage: string;
  governance_decision_id: string;
  governance_decision: string;
  status: string;
  reentry_objective: string;
}

export interface ReviewEvidenceItem {
  id: string;
  name: string;
  evidence_type: string;
  sha256_hash: string;
  size_bytes?: number;
  status: string;
  verification_status: string;
  chain_of_custody_events_count: number;
}

export interface ReviewFindingItem {
  id: string;
  title: string;
  description: string;
  severity: string;
  finding_type: string;
  rule_name?: string | null;
  confidence: number;
  supporting_artifact_ids: string[];
  supporting_evidence_ids: string[];
  sha256_hash: string;
  created_at?: string;
  existing_reviews: InvestigatorReviewResponse[];
  latest_decision?: InvestigatorDecisionType | null;
}

export interface ReviewAIClaimStatement {
  statement_id: string;
  classification: 'FACT' | 'INFERENCE' | 'UNVERIFIED';
  insight: string;
  confidence: number;
  supporting_evidence_ids: string[];
  supporting_artifact_ids: string[];
  supporting_finding_ids: string[];
  supporting_correlation_ids: string[];
  provenance_summary: string;
  reasoning_metadata: Record<string, any>;
  citations_verified: boolean;
  existing_reviews: InvestigatorReviewResponse[];
  latest_decision?: InvestigatorDecisionType | null;
}

export interface ReviewAIReasoningItem {
  id: string;
  objective: string;
  provider: string;
  model: string;
  execution_mode: string;
  statements_count: number;
  statements: ReviewAIClaimStatement[];
  sha256_hash: string;
  created_at?: string;
}

export interface ReviewItemsResponse {
  case_id: string;
  evidence_items: ReviewEvidenceItem[];
  deterministic_findings: ReviewFindingItem[];
  ai_reasoning_records: ReviewAIReasoningItem[];
  total_reviewable_claims: number;
  reviewed_claims_count: number;
  pending_claims_count: number;
}

export interface ClaimProvenanceResponse {
  case_id: string;
  target_type: string;
  target_id: string;
  statement_id?: string | null;
  claim_summary: Record<string, any>;
  lineage: Array<Record<string, any>>;
  supporting_artifacts: Array<Record<string, any>>;
  supporting_evidence: Array<Record<string, any>>;
  verified_integrity: boolean;
}

// Step 20 Final Forensic Report Interfaces
export interface ForensicReportGenerateRequest {
  title?: string;
  executive_summary_override?: string;
  methodology_notes?: string;
  include_ai_reasoning?: boolean;
  include_investigator_reviews?: boolean;
  options?: Record<string, any>;
}

export interface ForensicReportVersionItem {
  id: string;
  case_id: string;
  version: number;
  title: string;
  findings_count: number;
  evidence_count: number;
  report_hash: string;
  sha256_hash?: string;
  status: string;
  integrity_status: string;
  generated_by: string;
  generated_at: string;
}

export interface ForensicReportResponse {
  id: string;
  case_id: string;
  version: number;
  title: string;
  executive_summary: string;
  findings_count: number;
  evidence_count: number;
  full_report_markdown: string;
  report_hash: string;
  sha256_hash?: string;
  status: string;
  sections: {
    case_information: Record<string, any>;
    evidence_inventory: Array<Record<string, any>>;
    hashes_preservation: Array<Record<string, any>>;
    chain_of_custody: Array<Record<string, any>>;
    tool_executions: Array<Record<string, any>>;
    artifacts: Record<string, any>;
    timeline: Array<Record<string, any>>;
    correlations: Record<string, any>;
    findings: {
      total_findings: number;
      deterministic_count: number;
      ai_reasoning_claims_count: number;
      items: Array<{
        id: string;
        type: string;
        title: string;
        finding_type: string;
        severity: string;
        confidence: number;
        classification: 'FACT' | 'INFERENCE' | 'UNVERIFIED';
        supporting_evidence_ids: string[];
        supporting_artifact_ids: string[];
        verification_status: string;
        is_grounded: boolean;
        investigator_decision?: string;
        investigator_rationale?: string;
        sha256_hash?: string;
      }>;
    };
    confidence_verification: Record<string, any>;
    investigator_decisions: {
      total_reviews: number;
      accepted_count: number;
      challenged_count: number;
      rejected_count: number;
      requested_more_evidence_count: number;
      reviews: Array<Record<string, any>>;
    };
    explainability_provenance: {
      case_id: string;
      lineage_depth: number;
      pipeline_trace: string[];
      nodes_count: number;
      sample_nodes: Array<Record<string, any>>;
    };
  };
  provenance: Record<string, any>;
  report_metadata: Record<string, any>;
  integrity_status: string;
  evidence_integrity_summary: Record<string, any>;
  storage_path?: string | null;
  generated_by: string;
  generated_at: string;
}

export interface ForensicReportIntegrityResponse {
  report_id: string;
  case_id: string;
  version: number;
  expected_hash: string;
  computed_hash: string;
  integrity_status: string;
  tamper_detected: boolean;
  evidence_integrity: Record<string, any>;
  checked_at: string;
}

export interface ForensicReportProvenanceResponse {
  report_id: string;
  case_id: string;
  version: number;
  lineage: Array<Record<string, any>>;
  graph: Record<string, any>;
  node_counts: Record<string, number>;
  report_hash: string;
}

