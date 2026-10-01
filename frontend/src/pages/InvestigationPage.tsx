import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { useInvestigationStore } from '../stores/investigationStore';
import {
  FolderDot,
  CheckCircle2,
  Circle,
  Calendar,
  AlertCircle,
  Archive,
  Lock
} from 'lucide-react';
import { LiquidMetalButton } from '../components/ui/LiquidMetalButton';
import { GradientBlobCard } from '../components/ui/GradientBlobCard';

export const InvestigationPage: React.FC = () => {
  const {
    investigations,
    activeInvestigation,
    setActiveInvestigation,
    createInvestigation,
    closeActiveCase,
    archiveActiveCase,
    evidenceList,
    artifacts,
    verificationResults,
    activeReport,
    currentPlan,
    generatePlan,
    loading,
    error
  } = useInvestigationStore();

  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await createInvestigation(name, description);
      setName('');
      setDescription('');
      setShowModal(false);
    } catch {
      // Handled in store
    }
  };

  // Truthful Lifecycle Check
  const lifecycleSteps = [
    { label: 'Case Initialized', done: true },
    { label: 'Evidence Ingested', done: evidenceList.length > 0 },
    { label: 'Integrity Hashed (SHA-256)', done: evidenceList.length > 0 },
    { label: 'Plan Ready', done: currentPlan !== null },
    { label: 'Analysis Executed', done: artifacts.length > 0 },
    { label: 'Findings Verified', done: verificationResults.length > 0 },
    { label: 'Report Synthesized', done: activeReport !== null },
  ];

  return (
    <PageContainer
      title="Investigation Cases"
      subtitle="Manage forensic cases, assign scopes, and track deterministic investigation lifecycle states."
      actions={
        <div className="flex items-center gap-2">
          {activeInvestigation && activeInvestigation.status === 'OPEN' && (
            <>
              <button
                onClick={closeActiveCase}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
              >
                <Lock className="w-3.5 h-3.5 text-amber-400" />
                <span>Close Case</span>
              </button>
              <button
                onClick={archiveActiveCase}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
              >
                <Archive className="w-3.5 h-3.5 text-cyan-400" />
                <span>Archive</span>
              </button>
            </>
          )}
          <LiquidMetalButton
            label="+ Create Case"
            onClick={() => setShowModal(true)}
          />
        </div>
      }
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {investigations.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 space-y-6">
            <GradientBlobCard className="w-64 h-64">
              <div className="flex flex-col items-center justify-center p-6 text-center space-y-3">
                <div className="w-12 h-12 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
                  <FolderDot className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="font-bold text-slate-100 text-sm">No Cases Found</h4>
                  <p className="text-[11px] text-slate-400 mt-1">Initialize your first investigation workspace.</p>
                </div>
              </div>
            </GradientBlobCard>
            <LiquidMetalButton
              label="+ Initialize First Case"
              onClick={() => setShowModal(true)}
            />
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Case List Column */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase text-slate-400 font-semibold px-1">
                Active Cases ({investigations.length})
              </h3>
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    onClick={() => setActiveInvestigation(inv)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      activeInvestigation?.id === inv.id
                        ? 'bg-indigo-950/40 border-indigo-500/50 shadow-md ring-1 ring-indigo-500/30'
                        : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80 shadow-xs'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-[10px] font-mono text-slate-400">
                        {inv.id.substring(0, 8)}...
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                        inv.status === 'OPEN'
                          ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                          : inv.status === 'CLOSED'
                          ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                          : 'text-slate-400 bg-slate-800 border-slate-700'
                      }`}>
                        {inv.status}
                      </span>
                    </div>
                    <h4 className="font-bold text-slate-100 text-sm">{inv.name}</h4>
                    <p className="text-xs text-slate-400 line-clamp-2 mt-1 font-sans">
                      {inv.description || 'No description provided.'}
                    </p>
                    <div className="flex items-center gap-3 mt-3 text-[10px] font-mono text-slate-400">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(inv.created_at).toLocaleDateString()}
                      </span>
                      <span>{inv.evidence_count || 0} Evidence</span>
                      <span>{inv.findings_count || 0} Findings</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Case Detail / Lifecycle Overview */}
            {activeInvestigation && (
              <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6 shadow-xl backdrop-blur-md">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20 font-semibold">
                        CASE: {activeInvestigation.id}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        Status: {activeInvestigation.status}
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-slate-100 mt-1">{activeInvestigation.name}</h2>
                    <p className="text-xs text-slate-400 mt-1 font-sans">{activeInvestigation.description || 'No scope details recorded.'}</p>
                  </div>

                  <LiquidMetalButton
                    label={loading ? 'Planning...' : 'Generate Plan (DAG)'}
                    onClick={() => generatePlan(activeInvestigation.id)}
                  />
                </div>

                {/* Lifecycle Step Progression */}
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <h4 className="text-[10px] font-mono uppercase text-slate-400 font-semibold mb-3">
                    Case Lifecycle Status
                  </h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
                    {lifecycleSteps.map((step, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-lg border text-xs font-mono flex flex-col items-center text-center gap-1.5 ${
                          step.done
                            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 font-semibold'
                            : 'bg-slate-900/60 border-slate-800 text-slate-500'
                        }`}
                      >
                        {step.done ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <Circle className="w-4 h-4 text-slate-600 shrink-0" />
                        )}
                        <span className="text-[10px] leading-tight">{step.label}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Plan Details if generated */}
                {currentPlan && (
                  <div className="space-y-3 pt-2">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-mono text-slate-100 font-bold uppercase">
                        Investigation Plan ({currentPlan.total_tasks} Tasks)
                      </h4>
                      <span className="text-[10px] font-mono text-indigo-400 font-semibold">{currentPlan.status}</span>
                    </div>
                    <p className="text-xs text-slate-300 font-mono bg-slate-950 p-3 rounded-lg border border-slate-800">
                      {currentPlan.strategy_summary}
                    </p>
                    <div className="space-y-2">
                      {currentPlan.steps.map((s) => (
                        <div
                          key={s.step_id}
                          className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono"
                        >
                          <div className="flex items-center gap-2">
                            <span className="w-5 h-5 rounded bg-indigo-500/20 text-indigo-300 text-[10px] flex items-center justify-center font-bold border border-indigo-500/30">
                              {s.priority}
                            </span>
                            <span className="text-slate-200 font-semibold">{s.agent}</span>
                            <span className="text-slate-400">&rarr; {s.tool}</span>
                            <span className="text-slate-500 text-[11px]">({s.action})</span>
                          </div>
                          <span className="text-slate-400 text-[10px]">
                            Target: {s.evidence_name || s.evidence_id || 'All'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Case Creation Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">Initialize Investigation Case</h3>
            <form onSubmit={handleCreate} className="space-y-3 text-xs">
              <div>
                <label className="block font-mono text-slate-400 mb-1">Investigation Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Incident IR-2026-08 - Workstation Compromise"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                />
              </div>

              <div>
                <label className="block font-mono text-slate-400 mb-1">Scope & Objective</label>
                <textarea
                  rows={3}
                  placeholder="e.g. Ingest disk image and event logs to investigate unauthorized lateral movement."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 font-sans"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium shadow-md shadow-indigo-500/20"
                >
                  Initialize Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageContainer>
  );
};
