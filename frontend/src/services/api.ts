import axios from 'axios';
import type {
  Investigation,
  Case,
  Evidence,
  EvidenceVerificationResult,
  EvidenceIntelligence,
  EvidenceIntelligenceProfile,
  Artifact,
  CustodyRecord,
  Finding,
  DiskAnalysisResult,
  MemoryAnalysisResult,
  MalwareAnalysisResult,
  LogAnalysisResult,
  InvestigationPlan,
  PlanStep,
  PlanExecutionSummary,
  DependencyGraph,
  ForensicCapability,
  ForensicTool,
  CorrelatedGroup,
  VerificationResult,
  InvestigatorDecision,
  Report,
  SystemStatus,
  AuditEvent,
  ToolDefinition,
  UserProfile,
  UserLoginRequest,
  UserRegisterRequest,
  TokenResponse,
  AICopilotRequest,
  AICopilotResponse,
  AIExplainFindingRequest,
  AIExplanationResponse,
  AIProviderTestRequest,
  AIProviderTestResponse,
  InvestigatorReviewCreateRequest,
  InvestigatorReviewResponse,
  InvestigatorReviewIntegrityResponse,
  RequestMoreEvidenceRequest,
  RequestMoreEvidenceResponse,
  ReviewItemsResponse,
  ClaimProvenanceResponse,
  ForensicReportGenerateRequest,
  ForensicReportResponse,
  ForensicReportVersionItem,
  ForensicReportIntegrityResponse,
  ForensicReportProvenanceResponse
} from '../types';

let currentApiBase = 'http://localhost:8000/api';

export const validateDiscoveredBackendUrl = (urlStr: string, expectedPort?: number): boolean => {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'http:') return false;
    if (parsed.hostname !== '127.0.0.1') return false;
    if (parsed.username !== '' || parsed.password !== '') return false;
    if (parsed.search !== '' || parsed.hash !== '') return false;
    if (parsed.pathname !== '/api') return false;

    if (!parsed.port) return false;
    const portNum = parseInt(parsed.port, 10);
    if (isNaN(portNum) || portNum < 1024 || portNum > 65535) return false;
    if (expectedPort !== undefined && portNum !== expectedPort) return false;

    return true;
  } catch {
    return false;
  }
};

let currentToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;
let backendNetworkErrorHandler: ((error: any) => void) | null = null;

export const setAccessToken = (token: string | null) => {
  currentToken = token;
};

export const getAccessToken = (): string | null => {
  return currentToken;
};

export const setUnauthorizedHandler = (handler: (() => void) | null) => {
  unauthorizedHandler = handler;
};

export const setBackendNetworkErrorHandler = (handler: ((error: any) => void) | null) => {
  backendNetworkErrorHandler = handler;
};

const client = axios.create({
  baseURL: currentApiBase,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const setApiBaseUrl = (url: string) => {
  currentApiBase = url;
  client.defaults.baseURL = url;
};

export const getApiBaseUrl = (): string => {
  return currentApiBase;
};

// Request Interceptor: Attach Authorization Bearer header if token exists
client.interceptors.request.use((config) => {
  if (currentToken && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${currentToken}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Response Interceptor: Handle 401 Unauthorized globally & Network Failures
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Do not trigger unauthorized handler on initial login attempt failure
      const isLoginRequest = error.config && error.config.url && error.config.url.endsWith('/v1/auth/login');
      if (!isLoginRequest && unauthorizedHandler) {
        unauthorizedHandler();
      }
    } else if (!error.response || error.code === 'ERR_NETWORK' || error.code === 'ECONNREFUSED') {
      // Backend Network / Unavailability Error: notify store without clearing user JWT
      if (backendNetworkErrorHandler) {
        backendNetworkErrorHandler(error);
      }
    }
    return Promise.reject(error);
  }
);

export const api = {
  // Auth API Methods
  login: async (credentials: UserLoginRequest): Promise<TokenResponse> => {
    const res = await client.post<TokenResponse>('/v1/auth/login', credentials);
    setAccessToken(res.data.access_token);
    return res.data;
  },

  signup: async (data: UserRegisterRequest): Promise<UserProfile> => {
    const res = await client.post<UserProfile>('/v1/auth/signup', data);
    return res.data;
  },

  logout: async (): Promise<void> => {
    try {
      await client.post('/v1/auth/logout');
    } catch {
      // Ignore logout request errors (token may already be expired/revoked)
    } finally {
      setAccessToken(null);
    }
  },

  getMe: async (): Promise<UserProfile> => {
    const res = await client.get<UserProfile>('/v1/auth/me');
    return res.data;
  },
  getHealth: async (): Promise<{ status: string; application: string; version: string }> => {
    const res = await client.get('/health');
    return res.data;
  },

  getSystemStatus: async (): Promise<SystemStatus> => {
    const res = await client.get<SystemStatus>('/system/status');
    return res.data;
  },

  getTools: async (): Promise<ToolDefinition[]> => {
    const res = await client.get<ToolDefinition[]>('/tools');
    return res.data;
  },

  getAuditTrail: async (caseId?: string, eventType?: string): Promise<AuditEvent[]> => {
    const params: Record<string, string> = {};
    if (caseId) params.case_id = caseId;
    if (eventType) params.event_type = eventType;
    const res = await client.get<AuditEvent[]>('/audit', { params });
    return res.data;
  },

  getInvestigations: async (): Promise<Investigation[]> => {
    const res = await client.get<Investigation[]>('/v1/cases/');
    return res.data;
  },

  getInvestigation: async (id: string): Promise<Investigation> => {
    const res = await client.get<Investigation>(`/v1/cases/${id}`);
    return res.data;
  },

  createInvestigation: async (data: { name: string; description?: string }): Promise<Investigation> => {
    const res = await client.post<Investigation>('/v1/cases/', data);
    return res.data;
  },

  getCases: async (): Promise<Case[]> => {
    const res = await client.get<Case[]>('/v1/cases/');
    return res.data;
  },

  getCase: async (id: string): Promise<Case> => {
    const res = await client.get<Case>(`/v1/cases/${id}`);
    return res.data;
  },

  createCase: async (data: any): Promise<Case> => {
    const res = await client.post<Case>('/v1/cases/', data);
    return res.data;
  },

  updateCase: async (id: string, data: any): Promise<Case> => {
    const res = await client.patch<Case>(`/v1/cases/${id}`, data);
    return res.data;
  },

  initializeWorkspace: async (id: string): Promise<any> => {
    const res = await client.post(`/v1/cases/${id}/workspace/initialize`);
    return res.data;
  },

  getWorkspaceStatus: async (id: string): Promise<any> => {
    const res = await client.get(`/v1/cases/${id}/workspace/status`);
    return res.data;
  },

  getCaseMembers: async (id: string): Promise<any[]> => {
    const res = await client.get(`/v1/cases/${id}/members`);
    return res.data;
  },

  addCaseMember: async (id: string, member: any): Promise<any> => {
    const res = await client.post(`/v1/cases/${id}/members`, member);
    return res.data;
  },

  updateCaseMemberRole: async (id: string, userId: string, role: string): Promise<any> => {
    const res = await client.patch(`/v1/cases/${id}/members/${userId}`, { role });
    return res.data;
  },

  removeCaseMember: async (id: string, userId: string): Promise<{ detail: string }> => {
    const res = await client.delete<{ detail: string }>(`/v1/cases/${id}/members/${userId}`);
    return res.data;
  },

  getCasePermissions: async (id: string): Promise<Record<string, boolean>> => {
    const res = await client.get<Record<string, boolean>>(`/v1/cases/${id}/permissions`);
    return res.data;
  },

  updateCasePermissions: async (id: string, permissions: Record<string, boolean>): Promise<Record<string, boolean>> => {
    const res = await client.patch<Record<string, boolean>>(`/v1/cases/${id}/permissions`, { permissions });
    return res.data;
  },

  closeCase: async (id: string): Promise<Investigation> => {
    const res = await client.patch<Investigation>(`/v1/cases/${id}`, { status: 'CLOSED' });
    return res.data;
  },

  archiveCase: async (id: string): Promise<Investigation> => {
    const res = await client.patch<Investigation>(`/v1/cases/${id}`, { status: 'ARCHIVED' });
    return res.data;
  },

  intakeEvidence: async (investigationId: string, path: string, notes?: string): Promise<Evidence> => {
    const res = await client.post<Evidence>(`/cases/${investigationId}/evidence/intake`, { path, notes });
    return res.data;
  },

  getEvidence: async (investigationId: string): Promise<Evidence[]> => {
    const res = await client.get<Evidence[]>(`/cases/${investigationId}/evidence`);
    return res.data;
  },

  getEvidenceItem: async (investigationId: string, evidenceId: string): Promise<Evidence> => {
    const res = await client.get<Evidence>(`/cases/${investigationId}/evidence/${evidenceId}`);
    return res.data;
  },

  verifyEvidence: async (investigationId: string, evidenceId: string): Promise<EvidenceVerificationResult> => {
    const res = await client.post<EvidenceVerificationResult>(`/cases/${investigationId}/evidence/${evidenceId}/verify`);
    return res.data;
  },

  getCustodyEvents: async (investigationId: string): Promise<CustodyRecord[]> => {
    const res = await client.get<CustodyRecord[]>(`/cases/${investigationId}/custody`);
    return res.data;
  },

  getEvidenceCustodyEvents: async (investigationId: string, evidenceId: string): Promise<CustodyRecord[]> => {
    const res = await client.get<CustodyRecord[]>(`/cases/${investigationId}/evidence/${evidenceId}/custody`);
    return res.data;
  },

  getEvidenceIntelligence: async (investigationId: string, evidenceId: string): Promise<{ evidence_id: string; intelligence: EvidenceIntelligence }> => {
    const res = await client.get<{ evidence_id: string; intelligence: EvidenceIntelligence }>(`/cases/${investigationId}/evidence/${evidenceId}/intelligence`);
    return res.data;
  },

  getEvidenceIntelligenceProfile: async (_investigationId: string, evidenceId: string): Promise<EvidenceIntelligenceProfile> => {
    const res = await client.get<EvidenceIntelligenceProfile>(`/v1/evidence/${evidenceId}/intelligence/profile`);
    return res.data;
  },

  refreshEvidenceIntelligence: async (investigationId: string, evidenceId: string): Promise<{ evidence_id: string; intelligence: EvidenceIntelligence }> => {
    const res = await client.post<{ evidence_id: string; intelligence: EvidenceIntelligence }>(`/cases/${investigationId}/evidence/${evidenceId}/intelligence/refresh`);
    return res.data;
  },

  executeDiskAnalysis: async (
    investigationId: string,
    evidenceId: string,
    options?: { recursive?: boolean; include_deleted?: boolean; offset_sectors?: number }
  ): Promise<DiskAnalysisResult> => {
    const res = await client.post<DiskAnalysisResult>(`/cases/${investigationId}/analysis/disk`, {
      evidence_id: evidenceId,
      recursive: options?.recursive ?? true,
      include_deleted: options?.include_deleted ?? true,
      offset_sectors: options?.offset_sectors ?? 0
    });
    return res.data;
  },

  executeMemoryAnalysis: async (
    investigationId: string,
    evidenceId: string,
    plugin: string = 'windows.pslist'
  ): Promise<MemoryAnalysisResult> => {
    const res = await client.post<MemoryAnalysisResult>(`/cases/${investigationId}/analysis/memory`, {
      evidence_id: evidenceId,
      plugin
    });
    return res.data;
  },

  executeMalwareAnalysis: async (
    investigationId: string,
    evidenceId: string,
    ruleId: string = 'adfir_test_rules'
  ): Promise<MalwareAnalysisResult> => {
    const res = await client.post<MalwareAnalysisResult>(`/cases/${investigationId}/analysis/malware`, {
      evidence_id: evidenceId,
      rule_id: ruleId
    });
    return res.data;
  },

  executeLogAnalysis: async (
    investigationId: string,
    evidenceId: string,
    maxRecords: number = 5000
  ): Promise<LogAnalysisResult> => {
    const res = await client.post<LogAnalysisResult>(`/cases/${investigationId}/analysis/log`, {
      evidence_id: evidenceId,
      max_records: maxRecords
    });
    return res.data;
  },

  getArtifacts: async (investigationId: string): Promise<Artifact[]> => {
    const res = await client.get<Artifact[]>(`/cases/${investigationId}/artifacts`);
    return res.data;
  },

  planInvestigation: async (investigationId: string): Promise<InvestigationPlan> => {
    const res = await client.post<InvestigationPlan>(`/v1/cases/${investigationId}/investigation-plans`);
    return res.data;
  },

  createStrategyPlan: async (caseId: string): Promise<InvestigationPlan> => {
    const res = await client.post<InvestigationPlan>(`/v1/cases/${caseId}/investigation-plans`);
    return res.data;
  },

  getStrategyPlan: async (planId: string): Promise<InvestigationPlan> => {
    const res = await client.get<InvestigationPlan>(`/v1/investigation-plans/${planId}`);
    return res.data;
  },

  getStrategyPlanTasks: async (planId: string): Promise<any[]> => {
    const res = await client.get<any[]>(`/v1/investigation-plans/${planId}/tasks`);
    return res.data;
  },

  getStrategyPlanGraph: async (planId: string): Promise<DependencyGraph> => {
    const res = await client.get<DependencyGraph>(`/v1/investigation-plans/${planId}/graph`);
    return res.data;
  },

  reviewStrategyPlan: async (planId: string): Promise<{ plan_id: string; validation_status: string; status: string; adjustments_applied: any[] }> => {
    const res = await client.post<{ plan_id: string; validation_status: string; status: string; adjustments_applied: any[] }>(`/v1/investigation-plans/${planId}/review`);
    return res.data;
  },

  recalculateStrategyPlan: async (planId: string): Promise<InvestigationPlan> => {
    const res = await client.post<InvestigationPlan>(`/v1/investigation-plans/${planId}/recalculate`);
    return res.data;
  },

  getCaseStrategyPlans: async (caseId: string): Promise<InvestigationPlan[]> => {
    const res = await client.get<InvestigationPlan[]>(`/v1/cases/${caseId}/investigation-plans`);
    return res.data;
  },

  getStrategyCapabilities: async (): Promise<ForensicCapability[]> => {
    const res = await client.get<ForensicCapability[]>(`/v1/strategy/capabilities`);
    return res.data;
  },

  getStrategyTools: async (): Promise<ForensicTool[]> => {
    const res = await client.get<ForensicTool[]>(`/v1/strategy/tools`);
    return res.data;
  },

  getPlan: async (investigationId: string): Promise<InvestigationPlan> => {
    const res = await client.get<InvestigationPlan>(`/cases/${investigationId}/plan`);
    return res.data;
  },

  executePlan: async (investigationId: string): Promise<PlanExecutionSummary> => {
    const res = await client.post<PlanExecutionSummary>(`/cases/${investigationId}/plan/execute`);
    return res.data;
  },

  getPlanTasks: async (investigationId: string): Promise<PlanStep[]> => {
    const res = await client.get<PlanStep[]>(`/cases/${investigationId}/tasks`);
    return res.data;
  },

  getFindings: async (investigationId: string): Promise<Finding[]> => {
    const res = await client.get<Finding[]>(`/cases/${investigationId}/findings`);
    return res.data;
  },

  addFinding: async (investigationId: string, data: Partial<Finding>): Promise<Finding> => {
    const res = await client.post<Finding>(`/cases/${investigationId}/findings`, data);
    return res.data;
  },

  correlateFindings: async (investigationId: string): Promise<CorrelatedGroup[]> => {
    const res = await client.post<CorrelatedGroup[]>(`/cases/${investigationId}/correlate`);
    return res.data;
  },

  getCorrelations: async (investigationId: string): Promise<CorrelatedGroup[]> => {
    const res = await client.get<CorrelatedGroup[]>(`/cases/${investigationId}/correlations`);
    return res.data;
  },

  verifyFindings: async (investigationId: string): Promise<VerificationResult[]> => {
    const res = await client.post<VerificationResult[]>(`/cases/${investigationId}/verify`);
    return res.data;
  },

  recordDecision: async (investigationId: string, data: { decision: string; rationale: string; finding_ids?: string[]; evidence_ids?: string[]; investigator_name?: string }): Promise<InvestigatorDecision> => {
    const res = await client.post<InvestigatorDecision>(`/cases/${investigationId}/decisions`, data);
    return res.data;
  },

  getDecisions: async (investigationId: string): Promise<InvestigatorDecision[]> => {
    const res = await client.get<InvestigatorDecision[]>(`/cases/${investigationId}/decisions`);
    return res.data;
  },

  generateReport: async (investigationId: string): Promise<Report> => {
    const res = await client.post<Report>(`/cases/${investigationId}/report`);
    return res.data;
  },

  getReports: async (investigationId: string): Promise<Report[]> => {
    const res = await client.get<Report[]>(`/cases/${investigationId}/reports`);
    return res.data;
  },

  // User Administration API Methods
  getUsers: async (): Promise<UserProfile[]> => {
    const res = await client.get<UserProfile[]>('/v1/users/');
    return res.data;
  },

  getUser: async (id: string): Promise<UserProfile> => {
    const res = await client.get<UserProfile>(`/v1/users/${id}`);
    return res.data;
  },

  createUser: async (data: UserRegisterRequest & { role?: string }): Promise<UserProfile> => {
    const res = await client.post<UserProfile>('/v1/users/', data);
    return res.data;
  },

  updateUser: async (id: string, data: Partial<UserProfile>): Promise<UserProfile> => {
    const res = await client.patch<UserProfile>(`/v1/users/${id}`, data);
    return res.data;
  },

  updateSelfProfile: async (data: { name?: string; badge_id?: string }): Promise<UserProfile> => {
    const res = await client.patch<UserProfile>('/v1/auth/me', data);
    return res.data;
  },

  enableUser: async (id: string): Promise<UserProfile> => {
    const res = await client.post<UserProfile>(`/v1/users/${id}/enable`);
    return res.data;
  },

  disableUser: async (id: string): Promise<UserProfile> => {
    const res = await client.post<UserProfile>(`/v1/users/${id}/disable`);
    return res.data;
  },

  deactivateUser: async (id: string): Promise<UserProfile> => {
    const res = await client.delete<UserProfile>(`/v1/users/${id}`);
    return res.data;
  },

  // Task 9 AI Copilot API Methods
  copilotQuery: async (data: AICopilotRequest): Promise<AICopilotResponse> => {
    const res = await client.post<AICopilotResponse>('/v1/ai/copilot', data);
    return res.data;
  },

  explainFinding: async (data: AIExplainFindingRequest): Promise<AIExplanationResponse> => {
    const res = await client.post<AIExplanationResponse>('/v1/ai/explain-finding', data);
    return res.data;
  },

  testAIProvider: async (data: AIProviderTestRequest): Promise<AIProviderTestResponse> => {
    const res = await client.post<AIProviderTestResponse>('/v1/ai/provider/test', data);
    return res.data;
  },

  // Step 19 Investigator Review API Methods
  getReviewItems: async (caseId: string): Promise<ReviewItemsResponse> => {
    const res = await client.get<ReviewItemsResponse>(`/v1/cases/${caseId}/review/items`);
    return res.data;
  },

  submitReviewDecision: async (caseId: string, data: InvestigatorReviewCreateRequest): Promise<InvestigatorReviewResponse> => {
    const res = await client.post<InvestigatorReviewResponse>(`/v1/cases/${caseId}/review/decisions`, data);
    return res.data;
  },

  listReviewDecisions: async (caseId: string, params?: { target_id?: string; decision?: string }): Promise<InvestigatorReviewResponse[]> => {
    const res = await client.get<InvestigatorReviewResponse[]>(`/v1/cases/${caseId}/review/decisions`, { params });
    return res.data;
  },

  verifyReviewIntegrity: async (caseId: string, reviewId: string): Promise<InvestigatorReviewIntegrityResponse> => {
    const res = await client.get<InvestigatorReviewIntegrityResponse>(`/v1/cases/${caseId}/review/decisions/${reviewId}/integrity`);
    return res.data;
  },

  getClaimProvenance: async (caseId: string, targetId: string, targetType?: string): Promise<ClaimProvenanceResponse> => {
    const res = await client.get<ClaimProvenanceResponse>(`/v1/cases/${caseId}/review/provenance/${targetId}`, {
      params: targetType ? { target_type: targetType } : undefined
    });
    return res.data;
  },

  requestMoreEvidence: async (caseId: string, data: RequestMoreEvidenceRequest): Promise<RequestMoreEvidenceResponse> => {
    const res = await client.post<RequestMoreEvidenceResponse>(`/v1/cases/${caseId}/review/request-more-evidence`, data);
    return res.data;
  },

  // Step 20 Final Forensic Report API Methods
  generateForensicReport: async (caseId: string, data?: ForensicReportGenerateRequest): Promise<ForensicReportResponse> => {
    const res = await client.post<ForensicReportResponse>(`/v1/cases/${caseId}/reports/generate`, data || {});
    return res.data;
  },

  listForensicReports: async (caseId: string): Promise<ForensicReportVersionItem[]> => {
    const res = await client.get<ForensicReportVersionItem[]>(`/v1/cases/${caseId}/reports`);
    return res.data;
  },

  getForensicReport: async (caseId: string, reportId: string): Promise<ForensicReportResponse> => {
    const res = await client.get<ForensicReportResponse>(`/v1/cases/${caseId}/reports/${reportId}`);
    return res.data;
  },

  getLatestForensicReport: async (caseId: string): Promise<ForensicReportResponse> => {
    const res = await client.get<ForensicReportResponse>(`/v1/cases/${caseId}/reports/latest`);
    return res.data;
  },

  verifyForensicReportIntegrity: async (caseId: string, reportId: string): Promise<ForensicReportIntegrityResponse> => {
    const res = await client.get<ForensicReportIntegrityResponse>(`/v1/cases/${caseId}/reports/${reportId}/integrity`);
    return res.data;
  },

  getForensicReportProvenance: async (caseId: string, reportId: string): Promise<ForensicReportProvenanceResponse> => {
    const res = await client.get<ForensicReportProvenanceResponse>(`/v1/cases/${caseId}/reports/${reportId}/provenance`);
    return res.data;
  },

  exportForensicReport: async (
    caseId: string,
    reportId: string,
    format: 'markdown' | 'json' = 'markdown'
  ): Promise<{ data: any; filename: string; contentType: string }> => {
    const res = await client.get(`/v1/cases/${caseId}/reports/${reportId}/export`, {
      params: { format },
      responseType: format === 'json' ? 'json' : 'text'
    });
    const disposition = res.headers['content-disposition'] || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : `forensic_report_${reportId}.${format === 'json' ? 'json' : 'md'}`;
    const contentType = String(res.headers['content-type'] || (format === 'json' ? 'application/json' : 'text/markdown'));
    return {
      data: typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2),
      filename,
      contentType
    };
  }
};
