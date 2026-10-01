import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { FindingCard } from '../components/FindingCard';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import type { Finding } from '../types';
import {
  FileSearch,
  RefreshCw,
  Network,
  ShieldCheck,
  AlertCircle,
  Sparkles,
  X,
  Loader2,
  Brain
} from 'lucide-react';

export const FindingsPage: React.FC = () => {
  const {
    activeInvestigation,
    findings,
    correlatedGroups,
    verificationResults,
    correlateAndVerify,
    findingExplanation,
    findingExplanationLoading,
    findingExplanationError,
    explainFinding,
    aiConfig,
    loading
  } = useInvestigationStore();

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  if (!activeInvestigation) {
    return (
      <PageContainer title="Forensic Findings">
        <EmptyState
          icon={AlertCircle}
          title="No Active Investigation"
          description="Please select an investigation first to review findings."
        />
      </PageContainer>
    );
  }

  const handleExplainFinding = async (finding: Finding) => {
    setSelectedFinding(finding);
    try {
      await explainFinding({
        case_id: activeInvestigation.id,
        finding_id: finding.id,
        provider: aiConfig.provider,
        model: aiConfig.model
      });
    } catch {
      // Error captured in findingExplanationError state
    }
  };

  return (
    <PageContainer
      title="Structured Findings & Verification Matrix"
      subtitle={`Investigation: ${activeInvestigation.name} | Ground-truth findings extracted via forensic tools.`}
      actions={
        <button
          onClick={() => correlateAndVerify(activeInvestigation.id)}
          disabled={loading || findings.length === 0}
          className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-indigo-500/20"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Execute Correlation & Verification</span>
        </button>
      }
    >
      <div className="space-y-6">
        {/* Findings Grid */}
        <div>
          <h3 className="text-xs font-mono text-slate-400 uppercase font-semibold mb-3">
            Structured Findings ({findings.length})
          </h3>
          {findings.length === 0 ? (
            <EmptyState
              icon={FileSearch}
              title="No Structured Findings"
              description="Execute specialist agents to extract forensic artifacts from ingested evidence."
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {findings.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  onExplain={handleExplainFinding}
                />
              ))}
            </div>
          )}
        </div>

        {/* AI Finding Explanation Modal */}
        {selectedFinding && (
          <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 font-mono text-xs shadow-2xl relative">
              <button
                onClick={() => setSelectedFinding(null)}
                className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                <h3 className="font-bold text-slate-100 text-sm">AI Finding Explanation</h3>
              </div>

              <div className="space-y-1 bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Target Finding</span>
                <span className="font-bold text-slate-200 text-xs font-sans">{selectedFinding.title}</span>
                <span className="text-[10px] text-indigo-400 block font-mono">
                  Agent: {selectedFinding.agent} &bull; Tool: {selectedFinding.tool} &bull; Ref: {selectedFinding.evidence_reference || 'N/A'}
                </span>
              </div>

              {findingExplanationLoading && (
                <div className="py-8 flex flex-col items-center justify-center space-y-3 text-slate-400">
                  <Loader2 className="w-6 h-6 animate-spin text-indigo-400" />
                  <span>Resolving server-grounded finding explanation...</span>
                </div>
              )}

              {findingExplanationError && (
                <div className="p-3 bg-rose-950/40 border border-rose-800/80 rounded-xl text-rose-300 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>{findingExplanationError}</span>
                </div>
              )}

              {findingExplanation && !findingExplanationLoading && (
                <div className="space-y-4">
                  {/* Metadata Header */}
                  <div className="flex items-center justify-between text-[10px] bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-400">Provider: {findingExplanation.provider} ({findingExplanation.model})</span>
                    <span className="text-slate-400">Mode: {findingExplanation.execution_mode}</span>
                    <span className={findingExplanation.fallback_used ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
                      {findingExplanation.fallback_used ? 'Fallback Used' : 'Direct'}
                    </span>
                  </div>

                  {/* Explanation Content */}
                  <div className="space-y-2">
                    <span className="text-[10px] text-slate-400 uppercase font-bold block flex items-center gap-1.5">
                      <Brain className="w-3.5 h-3.5 text-indigo-400" />
                      Forensic Explanation
                    </span>
                    <p className="text-slate-200 font-sans leading-relaxed text-xs bg-slate-950 p-4 rounded-xl border border-slate-800 whitespace-pre-wrap">
                      {findingExplanation.explanation}
                    </p>
                  </div>

                  {/* MITRE ATT&CK Techniques */}
                  <div className="space-y-2">
                    <span className="text-[10px] text-slate-400 uppercase font-bold block">
                      MITRE ATT&CK Techniques ({findingExplanation.mitre_techniques.length})
                    </span>
                    {findingExplanation.mitre_techniques.length === 0 ? (
                      <p className="text-[11px] text-slate-500 italic bg-slate-950 p-3 rounded-lg border border-slate-800">
                        No MITRE techniques returned by backend for this finding.
                      </p>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {findingExplanation.mitre_techniques.map((tech, idx) => (
                          <span
                            key={idx}
                            className="px-2.5 py-1 bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 rounded-md text-[10px] font-bold"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Correlation & Verification Split */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Correlated Artifact Chains ({correlatedGroups.length})
            </h3>
            {correlatedGroups.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">No correlations identified from the available verified forensic findings.</p>
            ) : (
              <div className="space-y-2">
                {correlatedGroups.map((grp, idx) => (
                  <div key={grp.id || idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1 font-mono">
                    <div className="flex items-center justify-between font-semibold text-slate-200">
                      <div className="flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-800">
                          {grp.rule || grp.dimension}
                        </span>
                        <span className="text-slate-100">{grp.title}</span>
                      </div>
                      <span className="text-[10px] text-emerald-400">
                        {(grp.correlation_confidence * 100).toFixed(0)}% Match
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{grp.description}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Ground Truth Verification ({verificationResults.length})
            </h3>
            {verificationResults.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">Run verification to validate evidence references.</p>
            ) : (
              <div className="space-y-2">
                {verificationResults.map((ver, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
                    <div className="flex items-center justify-between font-mono font-bold text-slate-300">
                      <span>{ver.verification_status}</span>
                      <span className="text-[10px] text-indigo-400">
                        Confidence: {(ver.confidence_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{ver.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </PageContainer>
  );
};
