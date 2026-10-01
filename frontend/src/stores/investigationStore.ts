import { create } from 'zustand';
import type {
  Investigation,
  Evidence,
  Artifact,
  CustodyRecord,
  Finding,
  InvestigationPlan,
  CorrelatedGroup,
  VerificationResult,
  Report,
  SystemStatus,
  UserProfile,
  AuthStatus,
  UserLoginRequest,
  UserRegisterRequest,
  AIProviderConfig,
  AppSettings,
  InvestigatorDecision,
  AuditEvent,
  ToolDefinition,
  AICopilotRequest,
  AICopilotResponse,
  AIExplainFindingRequest,
  AIExplanationResponse,
  EvidenceVerificationResult,
  EvidenceIntelligence,
  AIProviderTestRequest,
  AIProviderTestResponse
} from '../types';
import { api, setAccessToken, getAccessToken, setUnauthorizedHandler, setApiBaseUrl, validateDiscoveredBackendUrl, setBackendNetworkErrorHandler } from '../services/api';

let pollIntervalId: any = null;

export interface ToolExecutionTracker {
  status: 'NOT_STARTED' | 'QUEUED' | 'PLANNING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  activeTool?: string;
  toolOutputLog: string[];
  lastError?: string;
  executionStartTime?: string;
}

interface InvestigationState {
  currentTab: string;
  investigations: Investigation[];
  activeInvestigation: Investigation | null;
  evidenceList: Evidence[];
  artifacts: Artifact[];
  selectedEvidence: Evidence | null;
  custodyEvents: CustodyRecord[];
  findings: Finding[];
  currentPlan: InvestigationPlan | null;
  correlatedGroups: CorrelatedGroup[];
  verificationResults: VerificationResult[];
  activeReport: Report | null;
  systemStatus: SystemStatus | null;
  currentDecision: InvestigatorDecision | null;
  auditEvents: AuditEvent[];
  registeredTools: ToolDefinition[];
  toolExecutionTracker: ToolExecutionTracker;
  loading: boolean;
  error: string | null;

  // Memory-only Backend Discovery Runtime State
  backendState: 'DISCOVERING' | 'READY' | 'UNAVAILABLE' | 'CRASHED' | 'STOPPING';
  backendUrl: string | null;
  backendError: string | null;
  initializeBackend: () => Promise<void>;
  checkBackendStatus: () => Promise<void>;
  startStatusPolling: () => void;
  stopStatusPolling: () => void;
  setBackendStopping: () => void;
  handleBackendNetworkFailure: () => void;

  // Auth, Profile & Provider Configuration
  authStatus: AuthStatus;
  currentUser: UserProfile | null;
  aiConfig: AIProviderConfig;
  settings: AppSettings;
  isAuthModalOpen: boolean;

  // Task 9 AI Copilot State
  copilotResponse: AICopilotResponse | null;
  copilotLoading: boolean;
  copilotError: string | null;
  findingExplanation: AIExplanationResponse | null;
  findingExplanationLoading: boolean;
  findingExplanationError: string | null;
  aiProviderTest: AIProviderTestResponse | null;
  aiProviderTestLoading: boolean;
  aiProviderTestError: string | null;

  setCurrentTab: (tab: string) => void;
  setAuthModalOpen: (open: boolean) => void;
  restoreSession: () => Promise<void>;
  login: (credentials: UserLoginRequest) => Promise<void>;
  signup: (data: UserRegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  handleUnauthorized: () => void;
  logoutUser: () => void;
  updateProfile: (profile: Partial<UserProfile>) => void;
  updateAIConfig: (config: Partial<AIProviderConfig>) => void;
  updateSettings: (settings: Partial<AppSettings>) => void;
  submitInvestigatorDecision: (decision: 'CONFIRM' | 'REJECT' | 'INCONCLUSIVE' | 'REQUEST_MORE_EVIDENCE', notes: string) => Promise<void>;
  cancelActiveExecution: () => void;

  fetchSystemStatus: () => Promise<void>;
  fetchTools: () => Promise<void>;
  fetchAuditTrail: (caseId?: string) => Promise<void>;
  fetchInvestigations: () => Promise<void>;
  setActiveInvestigation: (inv: Investigation) => Promise<void>;
  createInvestigation: (name: string, description?: string) => Promise<Investigation>;
  closeActiveCase: () => Promise<void>;
  archiveActiveCase: () => Promise<void>;
  intakeEvidence: (path: string, notes?: string) => Promise<Evidence>;
  fetchEvidence: (invId: string) => Promise<void>;
  verifyEvidenceItem: (evidenceId: string) => Promise<EvidenceVerificationResult>;
  fetchEvidenceIntelligence: (evidenceId: string) => Promise<EvidenceIntelligence>;
  refreshEvidenceIntelligence: (evidenceId: string) => Promise<EvidenceIntelligence>;
  fetchArtifacts: (invId: string) => Promise<void>;
  executeDiskAnalysis: (evidenceId: string) => Promise<void>;
  executeMemoryAnalysis: (evidenceId: string, plugin?: string) => Promise<void>;
  executeMalwareAnalysis: (evidenceId: string, ruleId?: string) => Promise<void>;
  executeLogAnalysis: (evidenceId: string, maxRecords?: number) => Promise<void>;
  fetchCustody: (invId: string) => Promise<void>;
  setSelectedEvidence: (ev: Evidence | null) => void;
  generatePlan: (invId: string) => Promise<void>;
  executePlanAction: (invId: string) => Promise<void>;
  fetchFindings: (invId: string) => Promise<void>;
  correlateAndVerify: (invId: string) => Promise<void>;
  generateReport: (invId: string) => Promise<void>;
  copilotQuery: (request: AICopilotRequest) => Promise<AICopilotResponse>;
  explainFinding: (request: AIExplainFindingRequest) => Promise<AIExplanationResponse>;
  testAIProvider: (request: AIProviderTestRequest) => Promise<AIProviderTestResponse>;
}

export const useInvestigationStore = create<InvestigationState>((set, get) => ({
  currentTab: 'home',
  investigations: [],
  activeInvestigation: null,
  evidenceList: [],
  artifacts: [],
  selectedEvidence: null,
  custodyEvents: [],
  findings: [],
  currentPlan: null,
  correlatedGroups: [],
  verificationResults: [],
  activeReport: null,
  systemStatus: null,
  currentDecision: null,
  auditEvents: [],
  registeredTools: [],
  toolExecutionTracker: {
    status: 'NOT_STARTED',
    toolOutputLog: []
  },
  loading: false,
  error: null,

  backendState: 'DISCOVERING',
  backendUrl: null,
  backendError: null,

  initializeBackend: async () => {
    set({ backendState: 'DISCOVERING', backendError: null });

    setBackendNetworkErrorHandler(() => {
      get().handleBackendNetworkFailure();
    });

    const isTauriEnv = typeof window !== 'undefined' &&
      (('__TAURI__' in window) || ('__TAURI_INTERNALS__' in window));

    if (isTauriEnv) {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const config = await invoke<{ port: number; url: string }>('get_backend_config');

        if (!config || typeof config.url !== 'string') {
          set({
            backendState: 'UNAVAILABLE',
            backendError: 'Invalid backend configuration payload received from Tauri IPC.',
            backendUrl: null
          });
          return;
        }

        const isValid = validateDiscoveredBackendUrl(config.url, config.port);
        if (!isValid) {
          set({
            backendState: 'UNAVAILABLE',
            backendError: `Discovered backend URL '${config.url}' failed strict loopback security validation.`,
            backendUrl: null
          });
          return;
        }

        setApiBaseUrl(config.url);
        set({
          backendState: 'READY',
          backendUrl: config.url,
          backendError: null
        });
        get().startStatusPolling();
      } catch (err: any) {
        const errorMsg = err?.message || String(err) || 'Failed to communicate with Tauri backend manager.';
        set({
          backendState: 'UNAVAILABLE',
          backendError: errorMsg,
          backendUrl: null
        });
      }
    } else {
      // Standalone browser / Vite development fallback ONLY
      const devUrl = 'http://localhost:8000/api';
      setApiBaseUrl(devUrl);
      set({
        backendState: 'READY',
        backendUrl: devUrl,
        backendError: null
      });
    }
  },

  checkBackendStatus: async () => {
    const currentState = get().backendState;
    if (currentState === 'STOPPING' || currentState === 'DISCOVERING') return;

    const isTauriEnv = typeof window !== 'undefined' &&
      (('__TAURI__' in window) || ('__TAURI_INTERNALS__' in window));

    if (isTauriEnv) {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const status = await invoke<{ is_running: boolean; is_packaged: boolean; port: number; has_crashed: boolean }>('get_backend_status');

        if (status.is_running && status.port) {
          const currentUrl = get().backendUrl;
          const expectedUrl = `http://127.0.0.1:${status.port}/api`;
          if (currentUrl && currentUrl !== expectedUrl) {
            if (validateDiscoveredBackendUrl(expectedUrl, status.port)) {
              setApiBaseUrl(expectedUrl);
              set({ backendUrl: expectedUrl });
            }
          }
        }

        if (status.has_crashed) {
          set({
            backendState: 'CRASHED',
            backendError: 'Backend process crashed unexpectedly.'
          });
        } else if (status.is_packaged && !status.is_running) {
          set({
            backendState: 'UNAVAILABLE',
            backendError: 'Backend process is no longer running.'
          });
        } else if (status.is_running && get().backendState !== 'READY' && get().backendState !== 'STOPPING') {
          set({
            backendState: 'READY',
            backendError: null
          });
        }
      } catch (err: any) {
        if (get().backendState === 'STOPPING') return;
        set({
          backendState: 'UNAVAILABLE',
          backendError: 'Failed to poll backend status from Tauri shell.'
        });
      }
    }
  },

  startStatusPolling: () => {
    get().stopStatusPolling();
    pollIntervalId = setInterval(() => {
      get().checkBackendStatus();
    }, 4000);
  },

  stopStatusPolling: () => {
    if (pollIntervalId) {
      clearInterval(pollIntervalId);
      pollIntervalId = null;
    }
  },

  setBackendStopping: () => {
    get().stopStatusPolling();
    set({
      backendState: 'STOPPING',
      backendError: null
    });
  },

  handleBackendNetworkFailure: () => {
    if (get().backendState === 'STOPPING') return;
    set({
      backendState: 'UNAVAILABLE',
      backendError: 'Backend network connection lost. Local desktop service is unreachable.'
    });
  },

  authStatus: 'RESTORING',
  currentUser: null,

  aiConfig: {
    provider: 'local_stub',
    model: 'adfir-deterministic-engine',
    has_key: true,
    is_tested: true,
    status: 'CONFIGURED'
  },

  settings: {
    theme: 'dark',
    data_directory: '/home/nandireddy/ADFIR/data',
    stream_chunk_size_mb: 8,
    session_timeout_minutes: 60,
    audit_logging_enabled: true,
    read_only_mode: true
  },

  copilotResponse: null,
  copilotLoading: false,
  copilotError: null,
  findingExplanation: null,
  findingExplanationLoading: false,
  findingExplanationError: null,
  aiProviderTest: null,
  aiProviderTestLoading: false,
  aiProviderTestError: null,

  isAuthModalOpen: false,

  setCurrentTab: (tab: string) => set({ currentTab: tab }),
  setAuthModalOpen: (open: boolean) => set({ isAuthModalOpen: open }),

  restoreSession: async () => {
    const token = getAccessToken();
    if (!token) {
      set({ authStatus: 'UNAUTHENTICATED', currentUser: null });
      return;
    }
    set({ authStatus: 'RESTORING', loading: true, error: null });
    try {
      const userProfile = await api.getMe();
      set({
        currentUser: userProfile,
        authStatus: 'AUTHENTICATED',
        loading: false
      });
    } catch {
      get().handleUnauthorized();
    }
  },

  login: async (credentials: UserLoginRequest) => {
    set({ loading: true, error: null });
    try {
      const res = await api.login(credentials);
      set({
        currentUser: res.user,
        authStatus: 'AUTHENTICATED',
        isAuthModalOpen: false,
        loading: false
      });
      await get().fetchInvestigations();
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || 'Invalid email or password.';
      set({ error: errorMsg, loading: false });
      throw new Error(errorMsg);
    }
  },

  signup: async (data: UserRegisterRequest) => {
    set({ loading: true, error: null });
    try {
      await api.signup(data);
      // Auto-login after successful registration
      await get().login({ email: data.email, password: data.password });
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || 'Failed to create investigator account.';
      set({ error: errorMsg, loading: false });
      throw new Error(errorMsg);
    }
  },

  logout: async () => {
    set({ loading: true });
    try {
      await api.logout();
    } finally {
      get().handleUnauthorized();
    }
  },

  handleUnauthorized: () => {
    setAccessToken(null);
    set({
      authStatus: 'UNAUTHENTICATED',
      currentUser: null,
      investigations: [],
      activeInvestigation: null,
      evidenceList: [],
      artifacts: [],
      selectedEvidence: null,
      custodyEvents: [],
      findings: [],
      currentPlan: null,
      correlatedGroups: [],
      verificationResults: [],
      activeReport: null,
      currentDecision: null,
      auditEvents: [],
      copilotResponse: null,
      copilotLoading: false,
      copilotError: null,
      findingExplanation: null,
      findingExplanationLoading: false,
      findingExplanationError: null,
      aiProviderTest: null,
      aiProviderTestLoading: false,
      aiProviderTestError: null,
      loading: false,
      error: null
    });
  },

  logoutUser: () => {
    get().handleUnauthorized();
  },

  updateProfile: (profile: Partial<UserProfile>) => {
    set((state) => ({
      currentUser: state.currentUser ? { ...state.currentUser, ...profile } : null
    }));
  },

  updateAIConfig: (config: Partial<AIProviderConfig>) => {
    set((state) => ({
      aiConfig: { ...state.aiConfig, ...config }
    }));
  },

  updateSettings: (newSettings: Partial<AppSettings>) => {
    set((state) => ({
      settings: { ...state.settings, ...newSettings }
    }));
  },

  submitInvestigatorDecision: async (decision, notes) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    const user = get().currentUser;
    set({ loading: true, error: null });
    try {
      const dec = await api.recordDecision(active.id, {
        decision,
        rationale: notes,
        finding_ids: get().findings.map((f) => f.id),
        evidence_ids: get().evidenceList.map((e) => e.id),
        investigator_name: user?.name || 'Investigator'
      });
      set({ currentDecision: dec, loading: false });
      await get().fetchAuditTrail(active.id);
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Failed to record decision';
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  cancelActiveExecution: () => {
    set((state) => ({
      toolExecutionTracker: {
        ...state.toolExecutionTracker,
        status: 'CANCELLED',
        toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, '[PROCESS CANCELLED]: Operation halted by investigator request.']
      },
      loading: false
    }));
  },

  fetchSystemStatus: async () => {
    try {
      const status = await api.getSystemStatus();
      set({ systemStatus: status });
    } catch (e: any) {
      console.warn('Backend offline or initializing:', e.message);
    }
  },

  fetchTools: async () => {
    try {
      const tools = await api.getTools();
      set({ registeredTools: tools });
    } catch (e: any) {
      console.error('Error fetching tools:', e);
    }
  },

  fetchAuditTrail: async (caseId?: string) => {
    try {
      const events = await api.getAuditTrail(caseId);
      set({ auditEvents: events });
    } catch (e: any) {
      console.error('Error fetching audit trail:', e);
    }
  },

  fetchInvestigations: async () => {
    set({ loading: true, error: null });
    try {
      const list = await api.getInvestigations();
      set({ investigations: list, loading: false });
      if (list.length > 0 && !get().activeInvestigation) {
        await get().setActiveInvestigation(list[0]);
      } else if (list.length === 0) {
        set({ activeInvestigation: null, evidenceList: [], artifacts: [], findings: [], currentPlan: null, custodyEvents: [], verificationResults: [], correlatedGroups: [], activeReport: null, copilotResponse: null, copilotError: null, findingExplanation: null, findingExplanationError: null });
      }
    } catch (e: any) {
      set({ error: e.message || 'Failed to fetch cases', loading: false });
    }
  },

  setActiveInvestigation: async (inv: Investigation) => {
    set({
      activeInvestigation: inv,
      loading: true,
      selectedEvidence: null,
      currentDecision: null,
      copilotResponse: null,
      copilotError: null,
      findingExplanation: null,
      findingExplanationError: null,
      toolExecutionTracker: {
        status: inv.artifacts_count && inv.artifacts_count > 0 ? 'COMPLETED' : 'NOT_STARTED',
        toolOutputLog: []
      }
    });
    try {
      const [evList, artList, custEvents, findList, decList, repList, corrList, planRes] = await Promise.all([
        api.getEvidence(inv.id).catch(() => []),
        api.getArtifacts(inv.id).catch(() => []),
        api.getCustodyEvents(inv.id).catch(() => []),
        api.getFindings(inv.id).catch(() => []),
        api.getDecisions(inv.id).catch(() => []),
        api.getReports(inv.id).catch(() => []),
        api.getCorrelations(inv.id).catch(() => []),
        api.getPlan(inv.id).catch(() => null)
      ]);
      set({
        evidenceList: evList,
        artifacts: artList,
        custodyEvents: custEvents,
        findings: findList,
        currentDecision: decList.length > 0 ? decList[0] : null,
        activeReport: repList.length > 0 ? repList[0] : null,
        correlatedGroups: corrList,
        currentPlan: planRes
      });
      await get().fetchAuditTrail(inv.id);
    } finally {
      set({ loading: false });
    }
  },

  createInvestigation: async (name: string, description?: string) => {
    set({ loading: true, error: null });
    try {
      const newInv = await api.createInvestigation({ name, description });
      set((state) => ({
        investigations: [newInv, ...state.investigations],
        activeInvestigation: newInv,
        currentDecision: null,
        evidenceList: [],
        artifacts: [],
        findings: [],
        activeReport: null,
        custodyEvents: [],
        loading: false
      }));
      await get().fetchAuditTrail(newInv.id);
      return newInv;
    } catch (e: any) {
      set({ error: e.message || 'Failed to create case', loading: false });
      throw e;
    }
  },

  closeActiveCase: async () => {
    const active = get().activeInvestigation;
    if (!active) return;
    set({ loading: true, error: null });
    try {
      const updated = await api.closeCase(active.id);
      set((state) => ({
        activeInvestigation: updated,
        investigations: state.investigations.map((i) => i.id === updated.id ? updated : i),
        loading: false
      }));
      await get().fetchAuditTrail(active.id);
    } catch (e: any) {
      set({ error: e.message || 'Failed to close case', loading: false });
    }
  },

  archiveActiveCase: async () => {
    const active = get().activeInvestigation;
    if (!active) return;
    set({ loading: true, error: null });
    try {
      const updated = await api.archiveCase(active.id);
      set((state) => ({
        activeInvestigation: updated,
        investigations: state.investigations.map((i) => i.id === updated.id ? updated : i),
        loading: false
      }));
      await get().fetchAuditTrail(active.id);
    } catch (e: any) {
      set({ error: e.message || 'Failed to archive case', loading: false });
    }
  },

  intakeEvidence: async (path: string, notes?: string) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({ loading: true, error: null });
    try {
      const ev = await api.intakeEvidence(active.id, path, notes);
      set((state) => ({ evidenceList: [ev, ...state.evidenceList], loading: false }));
      await Promise.all([
        get().fetchCustody(active.id),
        get().fetchAuditTrail(active.id)
      ]);
      return ev;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Evidence intake failed';
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  fetchEvidence: async (invId: string) => {
    try {
      const list = await api.getEvidence(invId);
      set({ evidenceList: list });
    } catch (e: any) {
      console.error('Error fetching evidence:', e);
    }
  },

  verifyEvidenceItem: async (evidenceId: string) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({ loading: true, error: null });
    try {
      const res = await api.verifyEvidence(active.id, evidenceId);
      await Promise.all([
        get().fetchEvidence(active.id),
        get().fetchCustody(active.id)
      ]);
      set({ loading: false });
      return res;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Evidence verification failed';
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  fetchEvidenceIntelligence: async (evidenceId: string) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    try {
      const res = await api.getEvidenceIntelligence(active.id, evidenceId);
      return res.intelligence;
    } catch (e: any) {
      console.error('Error fetching evidence intelligence:', e);
      throw e;
    }
  },

  refreshEvidenceIntelligence: async (evidenceId: string) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({ loading: true, error: null });
    try {
      const res = await api.refreshEvidenceIntelligence(active.id, evidenceId);
      await get().fetchEvidence(active.id);
      set({ loading: false });
      return res.intelligence;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Refreshing evidence intelligence failed';
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  fetchArtifacts: async (invId: string) => {
    try {
      const list = await api.getArtifacts(invId);
      set({ artifacts: list });
    } catch (e: any) {
      console.error('Error fetching artifacts:', e);
    }
  },

  executeDiskAnalysis: async (evidenceId: string) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'RUNNING',
        activeTool: 'The Sleuth Kit (fls)',
        executionStartTime: new Date().toISOString(),
        toolOutputLog: ['[START]: Spawning SleuthKit fls binary subprocess...', '[EXEC]: Reading filesystem metadata and inode tables...']
      }
    });
    try {
      const res = await api.executeDiskAnalysis(active.id, evidenceId);
      await Promise.all([
        get().fetchArtifacts(active.id),
        get().fetchFindings(active.id),
        get().fetchCustody(active.id),
        get().fetchAuditTrail(active.id)
      ]);
      set((state) => ({
        loading: false,
        toolExecutionTracker: {
          status: 'COMPLETED',
          activeTool: 'The Sleuth Kit (fls)',
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[SUCCESS]: Extracted ${res.artifacts_count} disk artifacts and ${res.findings_count} findings in ${res.execution_time_ms}ms.`,
            `[REF]: Output written to ${res.raw_output_reference || 'data/investigation_outputs/'}`
          ]
        }
      }));
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Disk analysis execution failed';
      set((state) => ({
        error: msg,
        loading: false,
        toolExecutionTracker: {
          status: 'FAILED',
          activeTool: 'The Sleuth Kit (fls)',
          lastError: msg,
          toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, `[ERROR]: ${msg}`]
        }
      }));
      throw new Error(msg);
    }
  },

  executeMemoryAnalysis: async (evidenceId: string, plugin: string = 'windows.pslist') => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'RUNNING',
        activeTool: `Volatility 3 (${plugin})`,
        executionStartTime: new Date().toISOString(),
        toolOutputLog: [`[START]: Invoking Volatility 3 framework with plugin: ${plugin}...`, '[EXEC]: Scanning virtual memory space and process structures...']
      }
    });
    try {
      const res = await api.executeMemoryAnalysis(active.id, evidenceId, plugin);
      await Promise.all([
        get().fetchArtifacts(active.id),
        get().fetchFindings(active.id),
        get().fetchCustody(active.id),
        get().fetchAuditTrail(active.id)
      ]);
      set((state) => ({
        loading: false,
        toolExecutionTracker: {
          status: 'COMPLETED',
          activeTool: `Volatility 3 (${plugin})`,
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[SUCCESS]: Extracted ${res.artifacts_count} memory artifacts and ${res.findings_count} findings in ${res.execution_time_ms}ms.`,
            `[REF]: Output reference: ${res.raw_output_reference || 'data/investigation_outputs/'}`
          ]
        }
      }));
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Memory analysis execution failed';
      set((state) => ({
        error: msg,
        loading: false,
        toolExecutionTracker: {
          status: 'FAILED',
          activeTool: `Volatility 3 (${plugin})`,
          lastError: msg,
          toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, `[ERROR]: ${msg}`]
        }
      }));
      throw new Error(msg);
    }
  },

  executeMalwareAnalysis: async (evidenceId: string, ruleId: string = 'adfir_test_rules') => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'RUNNING',
        activeTool: `YARA (${ruleId})`,
        executionStartTime: new Date().toISOString(),
        toolOutputLog: [`[START]: Compiling approved YARA ruleset: ${ruleId}...`, '[EXEC]: Scanning target evidence bytes against compiled signatures...']
      }
    });
    try {
      const res = await api.executeMalwareAnalysis(active.id, evidenceId, ruleId);
      await Promise.all([
        get().fetchArtifacts(active.id),
        get().fetchFindings(active.id),
        get().fetchCustody(active.id),
        get().fetchAuditTrail(active.id)
      ]);
      set((state) => ({
        loading: false,
        toolExecutionTracker: {
          status: 'COMPLETED',
          activeTool: `YARA (${ruleId})`,
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[SUCCESS]: Pattern scan completed. Extracted ${res.artifacts_count} artifacts and ${res.findings_count} findings in ${res.execution_time_ms}ms.`,
            `[REF]: Output reference: ${res.raw_output_reference || 'data/investigation_outputs/'}`
          ]
        }
      }));
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Malware analysis execution failed';
      set((state) => ({
        error: msg,
        loading: false,
        toolExecutionTracker: {
          status: 'FAILED',
          activeTool: `YARA (${ruleId})`,
          lastError: msg,
          toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, `[ERROR]: ${msg}`]
        }
      }));
      throw new Error(msg);
    }
  },

  executeLogAnalysis: async (evidenceId: string, maxRecords: number = 5000) => {
    const active = get().activeInvestigation;
    if (!active) throw new Error("No active case");
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'RUNNING',
        activeTool: 'python-evtx',
        executionStartTime: new Date().toISOString(),
        toolOutputLog: [`[START]: Ingesting EVTX binary stream (max: ${maxRecords} records)...`, '[EXEC]: Decoding XML chunk trees and filtering high-signal Event IDs...']
      }
    });
    try {
      const res = await api.executeLogAnalysis(active.id, evidenceId, maxRecords);
      await Promise.all([
        get().fetchArtifacts(active.id),
        get().fetchFindings(active.id),
        get().fetchCustody(active.id),
        get().fetchAuditTrail(active.id)
      ]);
      set((state) => ({
        loading: false,
        toolExecutionTracker: {
          status: 'COMPLETED',
          activeTool: 'python-evtx',
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[SUCCESS]: Event log parsing completed. Extracted ${res.artifacts_count} log artifacts and ${res.findings_count} findings in ${res.execution_time_ms}ms.`,
            `[REF]: Output reference: ${res.raw_output_reference || 'data/investigation_outputs/'}`
          ]
        }
      }));
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Log analysis execution failed';
      set((state) => ({
        error: msg,
        loading: false,
        toolExecutionTracker: {
          status: 'FAILED',
          activeTool: 'python-evtx',
          lastError: msg,
          toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, `[ERROR]: ${msg}`]
        }
      }));
      throw new Error(msg);
    }
  },

  fetchCustody: async (invId: string) => {
    try {
      const list = await api.getCustodyEvents(invId);
      set({ custodyEvents: list });
    } catch (e: any) {
      console.error('Error fetching custody events:', e);
    }
  },

  setSelectedEvidence: (ev: Evidence | null) => {
    set({ selectedEvidence: ev });
  },

  generatePlan: async (invId: string) => {
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'PLANNING',
        toolOutputLog: ['[PLANNER]: Analyzing ingested evidence MIME types and headers...', '[PLANNER]: Constructing directed acyclic task execution graph (DAG)...']
      }
    });
    try {
      const plan = await api.planInvestigation(invId);
      set((state) => ({
        currentPlan: plan,
        loading: false,
        toolExecutionTracker: {
          status: 'QUEUED',
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[PLANNER]: Generated execution graph with ${plan.steps.length} tasks. Strategy: ${plan.strategy_summary}`
          ]
        }
      }));
    } catch (e: any) {
      set({ error: e.message || 'Failed to plan investigation', loading: false });
    }
  },

  executePlanAction: async (invId: string) => {
    set({
      loading: true,
      error: null,
      toolExecutionTracker: {
        status: 'RUNNING',
        activeTool: 'InvestigationOrchestrator',
        executionStartTime: new Date().toISOString(),
        toolOutputLog: [
          '[ORCHESTRATOR]: Initializing deterministic forensic execution pipeline...',
          '[ORCHESTRATOR]: Verifying evidence vault path isolation and pre-analysis SHA-256 integrity...'
        ]
      }
    });
    try {
      const summary = await api.executePlan(invId);
      const [artList, findList, custEvents, planRes] = await Promise.all([
        api.getArtifacts(invId).catch(() => []),
        api.getFindings(invId).catch(() => []),
        api.getCustodyEvents(invId).catch(() => []),
        api.getPlan(invId).catch(() => null)
      ]);
      await get().fetchAuditTrail(invId);
      set((state) => ({
        artifacts: artList,
        findings: findList,
        custodyEvents: custEvents,
        currentPlan: planRes || state.currentPlan,
        loading: false,
        toolExecutionTracker: {
          status: summary.status === 'COMPLETED' ? 'COMPLETED' : 'FAILED',
          activeTool: 'InvestigationOrchestrator',
          toolOutputLog: [
            ...state.toolExecutionTracker.toolOutputLog,
            `[EXECUTION]: Pipeline finished with status ${summary.status}.`,
            `[METRICS]: Tasks executed: ${summary.tasks_executed} (Succeeded: ${summary.tasks_succeeded}, Failed: ${summary.tasks_failed}).`,
            `[PERSISTENCE]: Persisted ${summary.total_artifacts} artifacts and ${summary.total_findings} normalized findings.`
          ]
        }
      }));
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Plan execution failed';
      set((state) => ({
        error: msg,
        loading: false,
        toolExecutionTracker: {
          status: 'FAILED',
          activeTool: 'InvestigationOrchestrator',
          lastError: msg,
          toolOutputLog: [...state.toolExecutionTracker.toolOutputLog, `[ERROR]: ${msg}`]
        }
      }));
      throw new Error(msg);
    }
  },

  fetchFindings: async (invId: string) => {
    try {
      const list = await api.getFindings(invId);
      set({ findings: list });
    } catch (e: any) {
      console.error('Error fetching findings:', e);
    }
  },

  correlateAndVerify: async (invId: string) => {
    set({ loading: true, error: null });
    try {
      const [corr, ver] = await Promise.all([
        api.correlateFindings(invId),
        api.verifyFindings(invId),
      ]);
      set({ correlatedGroups: corr, verificationResults: ver, loading: false });
      await Promise.all([
        get().fetchFindings(invId),
        get().fetchAuditTrail(invId)
      ]);
    } catch (e: any) {
      set({ error: e.message || 'Correlation and verification failed', loading: false });
    }
  },

  generateReport: async (invId: string) => {
    set({ loading: true, error: null });
    try {
      const rep = await api.generateReport(invId);
      set({ activeReport: rep, loading: false });
      await get().fetchAuditTrail(invId);
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'Report generation failed';
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  copilotQuery: async (request: AICopilotRequest): Promise<AICopilotResponse> => {
    set({ copilotLoading: true, copilotError: null });
    try {
      const res = await api.copilotQuery(request);
      set({ copilotResponse: res, copilotLoading: false });
      return res;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'AI Copilot query failed';
      set({ copilotError: msg, copilotLoading: false });
      throw new Error(msg);
    }
  },

  explainFinding: async (request: AIExplainFindingRequest): Promise<AIExplanationResponse> => {
    set({ findingExplanationLoading: true, findingExplanationError: null });
    try {
      const res = await api.explainFinding(request);
      set({ findingExplanation: res, findingExplanationLoading: false });
      return res;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'AI finding explanation failed';
      set({ findingExplanationError: msg, findingExplanationLoading: false });
      throw new Error(msg);
    }
  },

  testAIProvider: async (request: AIProviderTestRequest): Promise<AIProviderTestResponse> => {
    set({ aiProviderTestLoading: true, aiProviderTestError: null });
    try {
      const res = await api.testAIProvider(request);
      set({ aiProviderTest: res, aiProviderTestLoading: false });
      return res;
    } catch (e: any) {
      const msg = e.response?.data?.detail || e.message || 'AI provider test failed';
      set({ aiProviderTestError: msg, aiProviderTestLoading: false });
      throw new Error(msg);
    }
  },
}));

setUnauthorizedHandler(() => {
  useInvestigationStore.getState().handleUnauthorized();
});
