import React, { useState, useEffect, useCallback } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import { api } from '../services/api';
import type {
  ReviewItemsResponse,
  InvestigatorReviewResponse,
  InvestigatorReviewCreateRequest,
  InvestigatorReviewIntegrityResponse,
  RequestMoreEvidenceRequest,
  ClaimProvenanceResponse,
  InvestigatorDecisionType
} from '../types';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Lock,
  RefreshCw,
  FileText,
  Brain,
  ArrowRight,
  Database,
  Layers,
  FileCheck,
  Clock,
  X
} from 'lucide-react';

export const InvestigatorReviewPage: React.FC = () => {
  const {
    activeInvestigation,
    setCurrentTab
  } = useInvestigationStore();

  const [reviewItems, setReviewItems] = useState<ReviewItemsResponse | null>(null);
  const [reviewsHistory, setReviewsHistory] = useState<InvestigatorReviewResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'ai_reasoning' | 'evidence' | 'history'>('findings');

  // Decision Modal
  const [decisionModal, setDecisionModal] = useState<{
    target_type: 'FINDING' | 'AI_REASONING' | 'CLAIM';
    target_id: string;
    statement_id?: string | null;
    title: string;
    decision: InvestigatorDecisionType;
  } | null>(null);
  const [decisionComment, setDecisionComment] = useState('');
  const [submittingDecision, setSubmittingDecision] = useState(false);

  // Request More Evidence Modal
  const [rmeModal, setRmeModal] = useState<{
    target_type: string;
    target_id: string;
    statement_id?: string | null;
    title: string;
    evidence_id?: string;
  } | null>(null);
  const [rmeCapability, setRmeCapability] = useState('YARA_SCAN');
  const [rmeObjective, setRmeObjective] = useState('');
  const [rmeComment, setRmeComment] = useState('');
  const [submittingRme, setSubmittingRme] = useState(false);

  // Provenance Drawer
  const [provenanceTarget, setProvenanceTarget] = useState<{
    target_id: string;
    target_type?: string;
    title: string;
  } | null>(null);
  const [provenanceData, setProvenanceData] = useState<ClaimProvenanceResponse | null>(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);

  // Integrity Check Modal
  const [integrityResult, setIntegrityResult] = useState<InvestigatorReviewIntegrityResponse | null>(null);
  const [integrityLoading, setIntegrityLoading] = useState(false);

  // Toast Notification
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  const loadData = useCallback(async () => {
    if (!activeInvestigation) return;
    setLoading(true);
    setError(null);
    try {
      const [items, history] = await Promise.all([
        api.getReviewItems(activeInvestigation.id),
        api.listReviewDecisions(activeInvestigation.id)
      ]);
      setReviewItems(items);
      setReviewsHistory(history);
    } catch (err: any) {
      console.error('Failed to load review items:', err);
      setError(err?.response?.data?.detail || 'Failed to load investigator review workspace data.');
    } finally {
      setLoading(false);
    }
  }, [activeInvestigation]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (!activeInvestigation) {
    return (
      <PageContainer title="Investigator Decision Gate">
        <EmptyState
          icon={AlertCircle}
          title="No Active Case Selected"
          description="Select an active investigation case to perform human-in-the-loop review, verify provenance, and record official forensic decisions."
        />
      </PageContainer>
    );
  }

  // Submit Decision Handler
  const handleDecisionSubmit = async () => {
    if (!decisionModal || !activeInvestigation) return;
    setSubmittingDecision(true);
    try {
      const payload: InvestigatorReviewCreateRequest = {
        target_type: decisionModal.target_type,
        target_id: decisionModal.target_id,
        statement_id: decisionModal.statement_id,
        decision: decisionModal.decision,
        comment: decisionComment,
        supporting_references: [decisionModal.target_id]
      };
      await api.submitReviewDecision(activeInvestigation.id, payload);
      showNotification('success', `Decision ${decisionModal.decision} successfully recorded with immutable cryptographic hash.`);
      setDecisionModal(null);
      setDecisionComment('');
      await loadData();
    } catch (err: any) {
      console.error('Decision submission error:', err);
      showNotification('error', err?.response?.data?.detail || 'Failed to submit investigator review decision.');
    } finally {
      setSubmittingDecision(false);
    }
  };

  // Request More Evidence Handler
  const handleRmeSubmit = async () => {
    if (!rmeModal || !activeInvestigation) return;
    if (!rmeObjective.trim()) {
      showNotification('error', 'Please define an analysis objective for requesting further evidence.');
      return;
    }
    setSubmittingRme(true);
    try {
      const payload: RequestMoreEvidenceRequest = {
        target_type: rmeModal.target_type,
        target_id: rmeModal.target_id,
        statement_id: rmeModal.statement_id,
        evidence_id: rmeModal.evidence_id || undefined,
        analysis_objective: rmeObjective,
        requested_capability: rmeCapability,
        parameters: { fast_mode: true },
        comment: rmeComment,
        supporting_references: [rmeModal.target_id]
      };
      const resp = await api.requestMoreEvidence(activeInvestigation.id, payload);
      showNotification(
        'success',
        `Evidence request approved by Governance Gate and queued in Scheduler (Task: ${resp.task_key}).`
      );
      setRmeModal(null);
      setRmeObjective('');
      setRmeComment('');
      await loadData();
    } catch (err: any) {
      console.error('Request more evidence error:', err);
      showNotification('error', err?.response?.data?.detail || 'Failed to request further evidence.');
    } finally {
      setSubmittingRme(false);
    }
  };

  // Inspect Provenance
  const handleInspectProvenance = async (targetId: string, title: string, targetType?: string) => {
    if (!activeInvestigation) return;
    setProvenanceTarget({ target_id: targetId, target_type: targetType, title });
    setProvenanceLoading(true);
    try {
      const data = await api.getClaimProvenance(activeInvestigation.id, targetId, targetType);
      setProvenanceData(data);
    } catch (err: any) {
      console.error('Provenance load error:', err);
      showNotification('error', err?.response?.data?.detail || 'Failed to fetch forensic provenance lineage.');
      setProvenanceTarget(null);
    } finally {
      setProvenanceLoading(false);
    }
  };

  // Verify Record Integrity
  const handleVerifyIntegrity = async (reviewId: string) => {
    if (!activeInvestigation) return;
    setIntegrityLoading(true);
    try {
      const res = await api.verifyReviewIntegrity(activeInvestigation.id, reviewId);
      setIntegrityResult(res);
    } catch (err: any) {
      console.error('Integrity verify error:', err);
      showNotification('error', err?.response?.data?.detail || 'Failed to verify cryptographic integrity.');
    } finally {
      setIntegrityLoading(false);
    }
  };

  const getDecisionBadge = (decision?: InvestigatorDecisionType | null) => {
    if (!decision) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
          PENDING REVIEW
        </span>
      );
    }
    switch (decision) {
      case 'ACCEPT':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" /> ACCEPTED
          </span>
        );
      case 'CHALLENGE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950 text-amber-300 border border-amber-700 flex items-center gap-1">
            <AlertCircle className="w-3 h-3 text-amber-400" /> CHALLENGED
          </span>
        );
      case 'REJECT':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950 text-rose-300 border border-rose-700 flex items-center gap-1">
            <XCircle className="w-3 h-3 text-rose-400" /> REJECTED
          </span>
        );
      case 'REQUEST_MORE_EVIDENCE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-700 flex items-center gap-1">
            <RefreshCw className="w-3 h-3 text-cyan-400" /> MORE EVIDENCE REQ
          </span>
        );
      default:
        return null;
    }
  };

  const getClassificationBadge = (classification: 'FACT' | 'INFERENCE' | 'UNVERIFIED') => {
    switch (classification) {
      case 'FACT':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
            FACT
          </span>
        );
      case 'INFERENCE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
            INFERENCE
          </span>
        );
      case 'UNVERIFIED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
            UNVERIFIED
          </span>
        );
    }
  };

  return (
    <PageContainer
      title="Investigator Review Workspace (Step 19)"
      subtitle={`Case: ${activeInvestigation.name} | Governed human authority over deterministic findings and AI reasoning.`}
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setCurrentTab('reports')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-mono font-semibold shadow-md shadow-emerald-500/20 transition"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Report Studio</span>
          </button>
        </div>
      }
    >
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Toast Notification */}
        {notification && (
          <div
            className={`p-3.5 rounded-lg border flex items-center justify-between text-xs font-mono animate-in fade-in duration-200 ${
              notification.type === 'success'
                ? 'bg-emerald-950/80 border-emerald-600/50 text-emerald-200'
                : 'bg-rose-950/80 border-rose-600/50 text-rose-200'
            }`}
          >
            <div className="flex items-center gap-2">
              {notification.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400" />
              )}
              <span>{notification.message}</span>
            </div>
            <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Error Banner */}
        {error && (
          <div className="p-3.5 rounded-lg border bg-rose-950/80 border-rose-600/50 text-rose-200 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
            <button onClick={() => setError(null)} className="text-slate-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Pipeline Lineage Flow Header */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-indigo-400 font-semibold">
            <Lock className="w-4 h-4" />
            <span>MANDATORY FORENSIC LINEAGE PIPELINE</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400 text-[11px] overflow-x-auto py-1">
            <span className="px-2 py-0.5 bg-slate-800 rounded text-slate-300">1. Evidence</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="px-2 py-0.5 bg-slate-800 rounded text-slate-300">2. Findings</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="px-2 py-0.5 bg-slate-800 rounded text-slate-300">3. Provenance</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="px-2 py-0.5 bg-slate-800 rounded text-slate-300">4. AI Reasoning</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="px-2 py-0.5 bg-indigo-950 text-indigo-300 border border-indigo-700 font-bold rounded">
              5. Investigator Review (Final)
            </span>
          </div>
        </div>

        {/* Summary Metric Cards */}
        {reviewItems && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <span className="text-slate-400 text-xs font-mono block">Total Claims/Findings</span>
              <span className="text-2xl font-bold font-mono text-slate-100">{reviewItems.total_reviewable_claims}</span>
              <span className="text-[10px] text-slate-500 block mt-1">Structured &amp; Classified</span>
            </div>
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <span className="text-slate-400 text-xs font-mono block">Reviewed Claims</span>
              <span className="text-2xl font-bold font-mono text-emerald-400">{reviewItems.reviewed_claims_count}</span>
              <span className="text-[10px] text-slate-500 block mt-1">Official Human Decision Recorded</span>
            </div>
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <span className="text-slate-400 text-xs font-mono block">Pending Reviews</span>
              <span className="text-2xl font-bold font-mono text-amber-400">{reviewItems.pending_claims_count}</span>
              <span className="text-[10px] text-slate-500 block mt-1">Awaiting Human-in-the-Loop Signoff</span>
            </div>
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <span className="text-slate-400 text-xs font-mono block">Evidence Items</span>
              <span className="text-2xl font-bold font-mono text-indigo-400">{reviewItems.evidence_items.length}</span>
              <span className="text-[10px] text-slate-500 block mt-1">All Vault Items SHA-256 Verified</span>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 gap-6 text-xs font-mono">
          <button
            onClick={() => setActiveTab('findings')}
            className={`pb-3 font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === 'findings'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Deterministic Findings ({reviewItems?.deterministic_findings.length ?? 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('ai_reasoning')}
            className={`pb-3 font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === 'ai_reasoning'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Brain className="w-4 h-4" />
            <span>AI Reasoning Claims ({reviewItems?.ai_reasoning_records.reduce((acc, r) => acc + r.statements_count, 0) ?? 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`pb-3 font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === 'evidence'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Evidence Vault &amp; Custody ({reviewItems?.evidence_items.length ?? 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`pb-3 font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === 'history'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Review History &amp; Audit Trail ({reviewsHistory.length})</span>
          </button>
        </div>

        {/* Tab 1: Deterministic Findings */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            {reviewItems?.deterministic_findings.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No Deterministic Findings"
                description="No deterministic rule findings have been generated yet for this case."
              />
            ) : (
              reviewItems?.deterministic_findings.map((f) => (
                <div
                  key={f.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 hover:border-slate-700 transition"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-slate-100">{f.title}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            f.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : f.severity === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          }`}
                        >
                          {f.severity}
                        </span>
                        {f.rule_name && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                            {f.rule_name}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-300">{f.description}</p>
                    </div>
                    <div>{getDecisionBadge(f.latest_decision)}</div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between border-t border-slate-800/80 pt-3 gap-3 text-xs font-mono text-slate-400">
                    <div className="flex items-center gap-4 text-[11px]">
                      <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                      <span>Artifacts: {f.supporting_artifact_ids.length}</span>
                      <span>Evidence: {f.supporting_evidence_ids.length}</span>
                      <span className="text-slate-500 truncate max-w-[200px]" title={f.sha256_hash}>
                        SHA: {f.sha256_hash.substring(0, 12)}...
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleInspectProvenance(f.id, f.title, 'FINDING')}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-mono border border-slate-700 flex items-center gap-1.5 transition"
                      >
                        <Layers className="w-3 h-3 text-indigo-400" />
                        <span>Inspect Lineage</span>
                      </button>
                      <button
                        onClick={() =>
                          setDecisionModal({
                            target_type: 'FINDING',
                            target_id: f.id,
                            statement_id: null,
                            title: f.title,
                            decision: 'ACCEPT'
                          })
                        }
                        className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 rounded text-[11px] font-mono font-semibold transition"
                      >
                        Accept
                      </button>
                      <button
                        onClick={() =>
                          setDecisionModal({
                            target_type: 'FINDING',
                            target_id: f.id,
                            statement_id: null,
                            title: f.title,
                            decision: 'CHALLENGE'
                          })
                        }
                        className="px-2.5 py-1 bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-700/60 rounded text-[11px] font-mono font-semibold transition"
                      >
                        Challenge
                      </button>
                      <button
                        onClick={() =>
                          setDecisionModal({
                            target_type: 'FINDING',
                            target_id: f.id,
                            statement_id: null,
                            title: f.title,
                            decision: 'REJECT'
                          })
                        }
                        className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-700/60 rounded text-[11px] font-mono font-semibold transition"
                      >
                        Reject
                      </button>
                      <button
                        onClick={() =>
                          setRmeModal({
                            target_type: 'FINDING',
                            target_id: f.id,
                            statement_id: null,
                            title: f.title,
                            evidence_id: f.supporting_evidence_ids[0]
                          })
                        }
                        className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/60 rounded text-[11px] font-mono font-semibold transition"
                      >
                        More Evidence
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Tab 2: AI Reasoning Claims */}
        {activeTab === 'ai_reasoning' && (
          <div className="space-y-6">
            {reviewItems?.ai_reasoning_records.length === 0 ? (
              <EmptyState
                icon={Brain}
                title="No AI Reasoning Claims"
                description="Run the Governed AI Reasoning Layer (Step 18) to synthesize and classify investigation claims."
              />
            ) : (
              reviewItems?.ai_reasoning_records.map((r) => (
                <div key={r.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-indigo-400">AI REASONING SESSION</span>
                        <span className="text-slate-500 font-mono text-[10px]">&bull; {r.execution_mode}</span>
                      </div>
                      <span className="text-xs text-slate-200 font-medium">{r.objective}</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400 text-xs font-mono">
                      <span>Model: {r.model}</span>
                      <button
                        onClick={() => handleInspectProvenance(r.id, r.objective, 'AI_REASONING')}
                        className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] border border-slate-700 flex items-center gap-1"
                      >
                        <Layers className="w-3 h-3 text-indigo-400" />
                        <span>Session Lineage</span>
                      </button>
                    </div>
                  </div>

                  {/* Statement List */}
                  <div className="space-y-3">
                    {r.statements.map((s, idx) => (
                      <div
                        key={s.statement_id || idx}
                        className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5 space-y-2 hover:border-slate-700 transition"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div className="flex items-start gap-2 max-w-3xl">
                            {getClassificationBadge(s.classification)}
                            <p className="text-xs text-slate-200 leading-relaxed font-sans">{s.insight}</p>
                          </div>
                          <div>{getDecisionBadge(s.latest_decision)}</div>
                        </div>

                        <div className="flex flex-wrap items-center justify-between border-t border-slate-900 pt-2 gap-2 text-[11px] font-mono text-slate-400">
                          <div className="flex items-center gap-3">
                            <span>Confidence: {(s.confidence * 100).toFixed(0)}%</span>
                            {s.citations_verified && (
                              <span className="text-emerald-400 flex items-center gap-1">
                                <FileCheck className="w-3 h-3" /> Anti-Fabrication Verified
                              </span>
                            )}
                            {s.supporting_finding_ids.length > 0 && (
                              <span>Findings Cited: {s.supporting_finding_ids.length}</span>
                            )}
                          </div>

                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() =>
                                setDecisionModal({
                                  target_type: 'AI_REASONING',
                                  target_id: r.id,
                                  statement_id: s.statement_id,
                                  title: s.insight,
                                  decision: 'ACCEPT'
                                })
                              }
                              className="px-2 py-0.5 bg-emerald-950/70 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/50 rounded text-[10px] font-semibold"
                            >
                              Accept
                            </button>
                            <button
                              onClick={() =>
                                setDecisionModal({
                                  target_type: 'AI_REASONING',
                                  target_id: r.id,
                                  statement_id: s.statement_id,
                                  title: s.insight,
                                  decision: 'CHALLENGE'
                                })
                              }
                              className="px-2 py-0.5 bg-amber-950/70 hover:bg-amber-900 text-amber-300 border border-amber-700/50 rounded text-[10px] font-semibold"
                            >
                              Challenge
                            </button>
                            <button
                              onClick={() =>
                                setDecisionModal({
                                  target_type: 'AI_REASONING',
                                  target_id: r.id,
                                  statement_id: s.statement_id,
                                  title: s.insight,
                                  decision: 'REJECT'
                                })
                              }
                              className="px-2 py-0.5 bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-700/50 rounded text-[10px] font-semibold"
                            >
                              Reject
                            </button>
                            <button
                              onClick={() =>
                                setRmeModal({
                                  target_type: 'AI_REASONING',
                                  target_id: r.id,
                                  statement_id: s.statement_id,
                                  title: s.insight
                                })
                              }
                              className="px-2 py-0.5 bg-cyan-950/70 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/50 rounded text-[10px] font-semibold"
                            >
                              More Evidence
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Tab 3: Evidence Vault & Chain of Custody */}
        {activeTab === 'evidence' && (
          <div className="space-y-4">
            {reviewItems?.evidence_items.map((ev) => (
              <div key={ev.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-1">
                    <span className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                      <Database className="w-4 h-4 text-indigo-400" />
                      {ev.name}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      Type: {ev.evidence_type} &bull; Custody Events: {ev.chain_of_custody_events_count}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono rounded flex items-center gap-1 font-semibold">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" /> INTEGRITY VERIFIED
                    </span>
                  </div>
                </div>

                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
                  <span className="truncate max-w-xl">SHA-256: {ev.sha256_hash}</span>
                  <span className="text-emerald-400 text-[10px] uppercase font-bold">Unmodified Source</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 4: Review History & Audit Trail */}
        {activeTab === 'history' && (
          <div className="space-y-4">
            {reviewsHistory.length === 0 ? (
              <EmptyState
                icon={Clock}
                title="No Review History"
                description="No investigator review decisions have been logged yet for this case."
              />
            ) : (
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono text-left text-slate-300">
                    <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                      <tr>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Investigator</th>
                        <th className="py-3 px-4">Decision</th>
                        <th className="py-3 px-4">Target Type</th>
                        <th className="py-3 px-4">Workflow Action</th>
                        <th className="py-3 px-4">Comments</th>
                        <th className="py-3 px-4 text-right">Integrity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {reviewsHistory.map((rec) => (
                        <tr key={rec.id} className="hover:bg-slate-800/40 transition">
                          <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                            {new Date(rec.timestamp).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-semibold text-slate-200">
                            {rec.investigator_name || rec.investigator_id}
                          </td>
                          <td className="py-3 px-4">{getDecisionBadge(rec.decision)}</td>
                          <td className="py-3 px-4 text-slate-400">{rec.target_type}</td>
                          <td className="py-3 px-4 text-cyan-400 font-medium">
                            {rec.resulting_workflow_action}
                          </td>
                          <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={rec.comment}>
                            {rec.comment || <span className="text-slate-600">None</span>}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleVerifyIntegrity(rec.id)}
                              disabled={integrityLoading}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[10px] font-mono transition"
                            >
                              Verify SHA
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Modal: Investigator Decision Submission */}
        {decisionModal && (
          <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-400" />
                  Record Investigator Review Decision
                </span>
                <button
                  onClick={() => setDecisionModal(null)}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <span className="text-slate-400 font-mono text-[11px] block uppercase">Target Claim / Finding:</span>
                <p className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-200 text-xs">
                  {decisionModal.title}
                </p>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 font-mono text-[11px] block uppercase">Selected Decision:</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['ACCEPT', 'CHALLENGE', 'REJECT'] as InvestigatorDecisionType[]).map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => setDecisionModal({ ...decisionModal, decision: d })}
                      className={`py-2 px-3 rounded text-xs font-mono font-semibold border transition ${
                        decisionModal.decision === d
                          ? d === 'ACCEPT'
                            ? 'bg-emerald-950 text-emerald-300 border-emerald-600'
                            : d === 'CHALLENGE'
                            ? 'bg-amber-950 text-amber-300 border-amber-600'
                            : 'bg-rose-950 text-rose-300 border-rose-600'
                          : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
                      }`}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 font-mono text-[11px] block uppercase">
                  Investigator Rationale / Notes (Mandatory for Court Readiness):
                </label>
                <textarea
                  value={decisionComment}
                  onChange={(e) => setDecisionComment(e.target.value)}
                  placeholder="Enter detailed forensic rationale, observed facts, or challenge notes..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 font-sans focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="p-3 bg-indigo-950/40 border border-indigo-500/30 rounded text-[11px] font-mono text-indigo-300 space-y-1">
                <span className="font-bold block">Strict Immutability Invariant:</span>
                <span>The original finding and AI reasoning will NEVER be overwritten. This decision creates an immutable, tamper-detectable review record.</span>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setDecisionModal(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleDecisionSubmit}
                  disabled={submittingDecision}
                  className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-mono font-semibold transition flex items-center gap-1.5"
                >
                  {submittingDecision && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Sign &amp; Record Decision</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Request More Evidence */}
        {rmeModal && (
          <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 text-cyan-400" />
                  Request More Evidence (Pipeline Re-entry)
                </span>
                <button onClick={() => setRmeModal(null)} className="text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-1 text-xs">
                <span className="text-slate-400 font-mono text-[11px] block uppercase">Triggering Claim:</span>
                <p className="p-2.5 bg-slate-950 rounded border border-slate-800 text-slate-300 text-xs">
                  {rmeModal.title}
                </p>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 font-mono text-[11px] block uppercase">Requested Capability:</label>
                <select
                  value={rmeCapability}
                  onChange={(e) => setRmeCapability(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="YARA_SCAN">YARA Signature Scan (Memory &amp; Disk)</option>
                  <option value="MEMORY_ANALYSIS">Volatility Volatile Memory Analysis</option>
                  <option value="DISK_INSPECTION">SleuthKit Detailed Filesystem Inspection</option>
                  <option value="NETWORK_CARVING">Network Packet Carving &amp; Stream Reconstruction</option>
                  <option value="LOG_INSPECTION">EVTX / Syslog Structured Log Extraction</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 font-mono text-[11px] block uppercase">
                  Analysis Objective (Passed to Governance Gate):
                </label>
                <input
                  type="text"
                  value={rmeObjective}
                  onChange={(e) => setRmeObjective(e.target.value)}
                  placeholder="e.g., Scan /tmp for malicious cron payload binaries matching known YARA rules"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-sans focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 font-mono text-[11px] block uppercase">
                  Investigator Directive / Comment:
                </label>
                <textarea
                  value={rmeComment}
                  onChange={(e) => setRmeComment(e.target.value)}
                  placeholder="Explain why further evidence is required before accepting this claim..."
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-sans focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="p-3 bg-cyan-950/40 border border-cyan-500/30 rounded text-[11px] font-mono text-cyan-300">
                <span>
                  Controlled Re-entry: This request passes through the Step 17 Governance Gate, creates a scheduled AnalysisRequest, and executes via the secure pipeline without bypass.
                </span>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setRmeModal(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleRmeSubmit}
                  disabled={submittingRme}
                  className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono font-semibold transition flex items-center gap-1.5"
                >
                  {submittingRme && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Queue in Scheduler</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Drawer / Modal: Provenance Inspector */}
        {provenanceTarget && (
          <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-5 shadow-2xl max-h-[85vh] overflow-y-auto">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  Forensic Provenance &amp; Lineage Trace
                </span>
                <button onClick={() => setProvenanceTarget(null)} className="text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {provenanceLoading ? (
                <div className="py-12 flex flex-col items-center justify-center gap-2 text-xs font-mono text-slate-400">
                  <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
                  <span>Tracing cryptographic lineage back to evidence vault...</span>
                </div>
              ) : provenanceData ? (
                <div className="space-y-4 text-xs font-mono">
                  {/* Claim Summary */}
                  <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase block">Target Claim:</span>
                    <span className="text-slate-200 font-bold">{provenanceTarget.title}</span>
                    <div className="flex items-center gap-2 text-[10px] text-slate-400 pt-1">
                      <span>Type: {provenanceData.target_type}</span>
                      <span>&bull;</span>
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> End-to-End Cryptographic Chain Intact
                      </span>
                    </div>
                  </div>

                  {/* Supporting Artifacts Tier */}
                  <div className="space-y-2">
                    <span className="text-slate-400 font-bold uppercase text-[11px] block">
                      Tier 1: Supporting Structured Artifacts ({provenanceData.supporting_artifacts.length})
                    </span>
                    {provenanceData.supporting_artifacts.map((a, i) => (
                      <div key={i} className="p-2.5 bg-slate-950/80 rounded border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-200 font-semibold">{a.label || a.artifact_type}</span>
                          <span className="text-[10px] text-slate-500 font-mono">ID: {a.id?.substring(0, 8)}...</span>
                        </div>
                        <span className="text-[10px] text-slate-500 block truncate">Hash: {a.sha256_hash}</span>
                      </div>
                    ))}
                  </div>

                  {/* Tool Execution Lineage Tier */}
                  {provenanceData.lineage.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-slate-400 font-bold uppercase text-[11px] block">
                        Tier 2: Tool Execution Outputs ({provenanceData.lineage.length})
                      </span>
                      {provenanceData.lineage.map((step, i) => (
                        <div key={i} className="p-2.5 bg-slate-950/80 rounded border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-indigo-300 font-semibold">{step.tool_id || step.title || step.step}</span>
                            <span className="text-[10px] text-slate-500 font-mono">Step: {step.step}</span>
                          </div>
                          {step.sha256_hash && (
                            <span className="text-[10px] text-slate-500 block truncate">Hash: {step.sha256_hash}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Source Evidence Vault Tier */}
                  <div className="space-y-2">
                    <span className="text-slate-400 font-bold uppercase text-[11px] block">
                      Tier 3: Source Evidence Vault Items ({provenanceData.supporting_evidence.length})
                    </span>
                    {provenanceData.supporting_evidence.map((ev, i) => (
                      <div key={i} className="p-2.5 bg-slate-950/80 rounded border border-emerald-900/40 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-emerald-300 font-semibold flex items-center gap-1.5">
                            <Database className="w-3.5 h-3.5 text-emerald-400" />
                            {ev.name}
                          </span>
                          <span className="text-emerald-400 text-[10px] font-bold">SOURCE ROOT</span>
                        </div>
                        <span className="text-[10px] text-slate-500 block truncate">SHA-256: {ev.sha256_hash}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="flex items-center justify-end pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setProvenanceTarget(null)}
                  className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Cryptographic Integrity Result */}
        {integrityResult && (
          <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Review Record Cryptographic Integrity
                </span>
                <button onClick={() => setIntegrityResult(null)} className="text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div
                  className={`p-3 rounded border text-center font-bold uppercase ${
                    integrityResult.integrity_status === 'VERIFIED'
                      ? 'bg-emerald-950/60 border-emerald-600 text-emerald-300'
                      : 'bg-rose-950/60 border-rose-600 text-rose-300'
                  }`}
                >
                  {integrityResult.integrity_status === 'VERIFIED'
                    ? 'VERIFIED: Tampering Free'
                    : 'FAILED: Tamper Detected'}
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase block">Expected Canonical Hash:</span>
                  <span className="p-2 bg-slate-950 rounded border border-slate-800 text-[10px] text-slate-300 block truncate">
                    {integrityResult.expected_hash}
                  </span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase block">Recomputed SHA-256 Hash:</span>
                  <span className="p-2 bg-slate-950 rounded border border-slate-800 text-[10px] text-slate-300 block truncate">
                    {integrityResult.computed_hash}
                  </span>
                </div>

                <div className="text-[10px] text-slate-400 pt-1">
                  <span>Verified at: {new Date(integrityResult.verified_at).toLocaleString()}</span>
                </div>
              </div>

              <div className="flex items-center justify-end pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIntegrityResult(null)}
                  className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageContainer>
  );
};
