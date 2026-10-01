import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import type { EgressPolicy } from '../types';
import {
  ShieldAlert,
  Brain,
  AlertCircle,
  Send,
  Loader2,
  Lock,
  CheckCircle2,
  FileCode,
  Sparkles
} from 'lucide-react';
import { LiquidMetalButton } from '../components/ui/LiquidMetalButton';

export const AIAnalysisPage: React.FC = () => {
  const {
    activeInvestigation,
    copilotResponse,
    copilotLoading,
    copilotError,
    copilotQuery,
    aiConfig,
    setCurrentTab
  } = useInvestigationStore();

  const [query, setQuery] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<string>(aiConfig.provider || 'local_stub');
  const [selectedModel, setSelectedModel] = useState<string>(aiConfig.model || 'adfir-deterministic-engine');
  const [egressPolicy, setEgressPolicy] = useState<EgressPolicy>('LOCAL_ONLY');

  if (!activeInvestigation) {
    return (
      <PageContainer title="Forensic AI Copilot">
        <EmptyState
          icon={AlertCircle}
          title="No Active Case Selected"
          description="Select or initialize an investigation case to perform server-grounded AI copilot analysis."
        />
      </PageContainer>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim() || !activeInvestigation || copilotLoading) return;
    try {
      await copilotQuery({
        case_id: activeInvestigation.id,
        query: query.trim(),
        provider: selectedProvider,
        model: selectedModel || undefined,
        egress_policy: egressPolicy
      });
    } catch {
      // Error captured in copilotError state
    }
  };

  return (
    <PageContainer
      title="Forensic AI Copilot Workstation"
      subtitle={`Case: ${activeInvestigation.name} | Authenticated forensic query engine grounded in verified case evidence.`}
      actions={
        <LiquidMetalButton
          label="Decision Gate →"
          onClick={() => setCurrentTab('review')}
        />
      }
    >
      <div className="space-y-6">
        {/* Forensic Authority Boundary Alert */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-indigo-400 font-bold">
              <ShieldAlert className="w-4 h-4" />
              <span>FORENSIC TRUST BOUNDARY & AUTHORIZATION</span>
            </div>
            <span className="text-[10px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
              Authority: Backend get_authorized_case()
            </span>
          </div>
          <p className="text-slate-300 leading-relaxed font-sans text-xs">
            The Copilot engine operates over server-grounded case evidence. All AI outputs are categorized into
            <span className="text-emerald-400 font-mono font-bold"> [FACT]</span> (provenance-supported),
            <span className="text-amber-400 font-mono font-bold"> [INFERENCE]</span> (probabilistic reasoning), and
            <span className="text-slate-400 font-mono font-bold"> [UNVERIFIED]</span> claims.
            The human investigator at the <strong>Investigator Decision Gate</strong> remains the sole authority for official forensic findings.
          </p>
        </div>

        {/* Copilot Query Input & Controls Panel */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-3 flex-wrap">
                <div>
                  <label className="text-slate-400 text-[10px] uppercase block mb-1">Provider</label>
                  <select
                    value={selectedProvider}
                    onChange={(e) => setSelectedProvider(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
                  >
                    <option value="local_stub">Local Engine (Default)</option>
                    <option value="openai">OpenAI</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="google">Google Gemini</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 text-[10px] uppercase block mb-1">Target Model</label>
                  <input
                    type="text"
                    placeholder="adfir-deterministic-engine"
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500 w-44"
                  />
                </div>

                <div>
                  <label className="text-slate-400 text-[10px] uppercase block mb-1">Egress Policy</label>
                  <select
                    value={egressPolicy}
                    onChange={(e) => setEgressPolicy(e.target.value as EgressPolicy)}
                    className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
                  >
                    <option value="LOCAL_ONLY">LOCAL_ONLY (Hardened)</option>
                    <option value="EXTERNAL_PROVIDER_ALLOWED">EXTERNAL_PROVIDER_ALLOWED</option>
                    <option value="EXTERNAL_PROVIDER_BLOCKED">EXTERNAL_PROVIDER_BLOCKED</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-1 text-[10px] text-slate-500">
                <Lock className="w-3 h-3 text-slate-400" />
                <span>Backend Enforced Egress Policy</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 font-semibold mb-2">
                Ask Forensic AI Copilot Question
              </label>
              <textarea
                rows={3}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g., Summarize suspicious process creations and persistence artifacts in this investigation case..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs text-slate-200 font-sans focus:outline-none focus:border-indigo-500 leading-relaxed resize-none"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-500">
                Case ID: <code className="text-slate-400">{activeInvestigation.id}</code>
              </span>
              <button
                type="submit"
                disabled={copilotLoading || !query.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-indigo-500/20 transition-all"
              >
                {copilotLoading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Query...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Query Copilot Engine</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* Backend Error State */}
        {copilotError && (
          <div className="bg-rose-950/40 border border-rose-800/80 p-4 rounded-xl flex items-start gap-3 font-mono text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold block uppercase">Backend Query Error</span>
              <p className="text-[11px] text-rose-300/90">{copilotError}</p>
            </div>
          </div>
        )}

        {/* Returned Copilot Response Rendering */}
        {copilotResponse && (
          <div className="space-y-6">
            {/* Backend Execution Metadata Header */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                <span className="font-bold text-slate-200 uppercase flex items-center gap-2">
                  <Brain className="w-4 h-4 text-indigo-400" />
                  Copilot Query Result Metadata
                </span>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] border ${
                    copilotResponse.provider_status === 'SUCCESS'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                  }`}>
                    Status: {copilotResponse.provider_status}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                    Mode: {copilotResponse.execution_mode}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
                <div>
                  <span className="text-slate-500 block uppercase text-[9px]">Provider</span>
                  <span className="text-slate-300 font-semibold">{copilotResponse.provider}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[9px]">Model</span>
                  <span className="text-slate-300 font-semibold">{copilotResponse.model}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[9px]">Fallback Status</span>
                  <span className={copilotResponse.fallback_used ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                    {copilotResponse.fallback_used ? 'Fallback Used' : 'Direct Execution'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[9px]">Context Truncated</span>
                  <span className={copilotResponse.context_truncated ? 'text-amber-400 font-semibold' : 'text-slate-400'}>
                    {copilotResponse.context_truncated ? 'Yes (>16k chars)' : 'No'}
                  </span>
                </div>
              </div>

              {/* Explicit Fallback Warning */}
              {copilotResponse.fallback_used && (
                <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-300 text-[11px] flex items-center gap-2">
                  <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span>Notice: Output executed via backend deterministic local engine fallback.</span>
                </div>
              )}

              {/* Context Truncation Warning */}
              {copilotResponse.context_truncated && (
                <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-300 text-[11px] flex items-center gap-2">
                  <FileCode className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                  <span>Warning: Case context exceeded 16,000 characters and was safely truncated by backend builder.</span>
                </div>
              )}
            </div>

            {/* Synthesized Answer Panel */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                Synthesized Forensic Response
              </h3>
              <div className="text-xs text-slate-200 leading-relaxed font-sans space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <p className="whitespace-pre-wrap">{copilotResponse.answer}</p>
              </div>
            </div>

            {/* Categorized Claims Breakdown */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Structured Claims & Provenance Links ({copilotResponse.claims.length})
                </h3>
              </div>

              {copilotResponse.claims.length === 0 ? (
                <p className="text-xs font-mono text-slate-500">No structured claim items returned for this query.</p>
              ) : (
                <div className="space-y-3 font-mono text-xs">
                  {copilotResponse.claims.map((claim, idx) => {
                    const isFact = claim.claim_type === 'FACT';
                    const isInference = claim.claim_type === 'INFERENCE';
                    return (
                      <div
                        key={idx}
                        className={`p-3.5 rounded-xl border space-y-2 ${
                          isFact
                            ? 'bg-slate-950 border-emerald-800/50'
                            : isInference
                            ? 'bg-slate-950 border-amber-800/50'
                            : 'bg-slate-950 border-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              isFact
                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                : isInference
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            [{claim.claim_type}]
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {isFact
                              ? 'Supported by persisted forensic finding/artifact provenance'
                              : isInference
                              ? 'AI-generated reasoning based on forensic context'
                              : 'Requires investigator verification'}
                          </span>
                        </div>

                        <p className="text-slate-200 text-xs font-sans leading-relaxed">{claim.statement}</p>

                        {(claim.source_finding_id || claim.source_artifact_id) && (
                          <div className="flex items-center gap-3 pt-1 border-t border-slate-800/60 text-[10px] text-slate-400">
                            {claim.source_finding_id && (
                              <span>
                                Source Finding: <code className="text-indigo-400">{claim.source_finding_id}</code>
                              </span>
                            )}
                            {claim.source_artifact_id && (
                              <span>
                                Source Artifact: <code className="text-cyan-400">{claim.source_artifact_id}</code>
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </PageContainer>
  );
};
