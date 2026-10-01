import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { FindingCard } from '../components/FindingCard';
import { useInvestigationStore } from '../stores/investigationStore';
import {
  FileSearch,
  ShieldCheck,
  Network,
  AlertCircle,
  Database
} from 'lucide-react';
import { LiquidMetalButton } from '../components/ui/LiquidMetalButton';

export const ResultsPage: React.FC = () => {
  const {
    activeInvestigation,
    artifacts,
    findings,
    correlatedGroups,
    verificationResults,
    correlateAndVerify,
    loading,
    error
  } = useInvestigationStore();

  const [activeTab, setActiveTab] = useState<'overview' | 'artifacts' | 'findings' | 'verification' | 'correlation'>('overview');

  if (!activeInvestigation) {
    return (
      <PageContainer title="Investigation Results">
        <EmptyState
          icon={AlertCircle}
          title="No Active Investigation"
          description="Select or create an investigation first to view forensic results."
        />
      </PageContainer>
    );
  }

  const supportedCount = verificationResults.filter((v) => v.verification_status === 'SUPPORTED').length;

  return (
    <PageContainer
      title="Forensic Results & Ground-Truth Matrix"
      subtitle={`Investigation: ${activeInvestigation.name} | Strict separation of raw tool artifacts from candidate findings.`}
      actions={
        <LiquidMetalButton
          label={loading ? 'Correlating...' : 'Verify & Correlate'}
          onClick={() => correlateAndVerify(activeInvestigation.id)}
        />
      }
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Results Metrics Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
            <span className="text-slate-500 text-[10px] block uppercase">Raw Artifacts</span>
            <span className="text-lg font-bold text-slate-100">{artifacts.length}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Stored in SQLite</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
            <span className="text-slate-500 text-[10px] block uppercase">Candidate Findings</span>
            <span className="text-lg font-bold text-amber-400">{findings.length}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Evidence observations</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
            <span className="text-slate-500 text-[10px] block uppercase">Ground Truth Supported</span>
            <span className="text-lg font-bold text-emerald-400">{supportedCount}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Tool reference matched</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
            <span className="text-slate-500 text-[10px] block uppercase">Correlated Chains</span>
            <span className="text-lg font-bold text-cyan-400">{correlatedGroups.length}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Cross-domain entities</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 text-xs font-mono font-medium gap-2">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-2.5 px-3 transition-colors ${activeTab === 'overview' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('artifacts')}
            className={`pb-2.5 px-3 transition-colors ${activeTab === 'artifacts' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Artifacts ({artifacts.length})
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`pb-2.5 px-3 transition-colors ${activeTab === 'findings' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Findings ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab('verification')}
            className={`pb-2.5 px-3 transition-colors ${activeTab === 'verification' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Verification ({verificationResults.length})
          </button>
          <button
            onClick={() => setActiveTab('correlation')}
            className={`pb-2.5 px-3 transition-colors ${activeTab === 'correlation' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Correlation ({correlatedGroups.length})
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Findings preview */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                    <FileSearch className="w-4 h-4 text-amber-400" />
                    Latest Candidate Findings ({findings.length})
                  </h3>
                </div>
                {findings.length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono">No findings generated yet.</p>
                ) : (
                  <div className="space-y-2.5 max-h-[300px] overflow-y-auto">
                    {findings.slice(0, 4).map((f) => (
                      <FindingCard key={f.id} finding={f} />
                    ))}
                  </div>
                )}
              </div>

              {/* Correlation & Verification preview */}
              <div className="space-y-4">
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                  <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Ground Truth Verification ({verificationResults.length})
                  </h3>
                  {verificationResults.length === 0 ? (
                    <p className="text-xs text-slate-500 font-mono">No verification executed yet. Click 'Execute Correlation & Verification'.</p>
                  ) : (
                    <div className="space-y-2 max-h-[140px] overflow-y-auto">
                      {verificationResults.slice(0, 3).map((v, idx) => (
                        <div key={idx} className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono flex items-center justify-between">
                          <span className="text-emerald-400 font-bold">{v.verification_status}</span>
                          <span className="text-slate-400 text-[11px] truncate max-w-xs">{v.reason}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                  <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                    <Network className="w-4 h-4 text-cyan-400" />
                    Correlated Chains ({correlatedGroups.length})
                  </h3>
                  {correlatedGroups.length === 0 ? (
                    <p className="text-xs text-slate-500 font-mono">No cross-tool correlations clustered yet.</p>
                  ) : (
                    <div className="space-y-2 max-h-[140px] overflow-y-auto">
                      {correlatedGroups.slice(0, 2).map((g, idx) => (
                        <div key={idx} className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono">
                          <span className="text-slate-200 font-semibold">{g.title}</span>
                          <span className="text-[10px] text-emerald-400 block mt-0.5">{(g.correlation_confidence * 100).toFixed(0)}% Confidence Match</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'artifacts' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            {artifacts.length === 0 ? (
              <EmptyState
                icon={Database}
                title="No Artifacts Extracted"
                description="Run specialist analysis engines on ingested evidence to extract forensic artifacts."
              />
            ) : (
              <div className="overflow-x-auto max-h-[600px]">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 text-[10px] uppercase border-b border-slate-800 sticky top-0">
                    <tr>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Agent / Tool</th>
                      <th className="py-2.5 px-3">Source Ref</th>
                      <th className="py-2.5 px-3">Path / Details</th>
                      <th className="py-2.5 px-3">Raw Reference</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-[11px]">
                    {artifacts.map((art) => (
                      <tr key={art.id} className="hover:bg-slate-800/30 text-slate-300">
                        <td className="py-2 px-3 text-indigo-400 font-semibold">{art.artifact_type}</td>
                        <td className="py-2 px-3 text-slate-400">{art.agent} &rarr; {art.tool}</td>
                        <td className="py-2 px-3 text-slate-300">{art.source_reference}</td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{art.path || JSON.stringify(art.metadata_json)}</td>
                        <td className="py-2 px-3 text-slate-500 truncate max-w-[180px]" title={art.raw_output_reference}>
                          {art.raw_output_reference || 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'findings' && (
          <div>
            {findings.length === 0 ? (
              <EmptyState
                icon={FileSearch}
                title="No Structured Findings"
                description="Execute specialist agents to extract forensic artifacts from ingested evidence."
              />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {findings.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'verification' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            {verificationResults.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No Findings Verified Yet"
                description="Execute the Ground-Truth Verification Engine to calibrate candidate findings against deterministic tool outputs."
                actionLabel="Execute Verification"
                onAction={() => correlateAndVerify(activeInvestigation.id)}
              />
            ) : (
              <div className="space-y-3">
                {verificationResults.map((v, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200">{v.verification_status}</span>
                      <span className="text-[10px] text-indigo-400">Score: {(v.confidence_score * 100).toFixed(0)}%</span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{v.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'correlation' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            {correlatedGroups.length === 0 ? (
              <EmptyState
                icon={Network}
                title="No Correlations Identified"
                description="No cross-source correlations identified from the available verified forensic findings. Execute correlation to analyze multi-source forensic entities across disk, memory, malware, and logs."
                actionLabel="Execute Correlation"
                onAction={() => correlateAndVerify(activeInvestigation.id)}
              />
            ) : (
              <div className="space-y-3">
                {correlatedGroups.map((grp, idx) => (
                  <div key={grp.id || idx} className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono space-y-2">
                    <div className="flex items-center justify-between font-semibold text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800">
                          {grp.rule || grp.dimension || 'CORRELATION'}
                        </span>
                        <span className="text-slate-100 font-bold">{grp.title}</span>
                      </div>
                      <span className="text-[10px] text-emerald-400">
                        {(grp.correlation_confidence * 100).toFixed(0)}% Confidence
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">{grp.description}</p>
                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-4 text-[10px] text-slate-400">
                      <div>
                        <span className="text-slate-500 uppercase">Entity:</span>{' '}
                        <span className="text-slate-200 font-bold">{grp.correlated_entity}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 uppercase">Tools:</span>{' '}
                        <span className="text-cyan-300">{grp.tools_involved.join(', ') || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 uppercase">Findings:</span>{' '}
                        <span className="text-indigo-300">{grp.supporting_finding_ids.length} linked</span>
                      </div>
                      {grp.supporting_artifact_ids && grp.supporting_artifact_ids.length > 0 && (
                        <div>
                          <span className="text-slate-500 uppercase">Artifacts:</span>{' '}
                          <span className="text-purple-300">{grp.supporting_artifact_ids.length} supporting</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </PageContainer>
  );
};
