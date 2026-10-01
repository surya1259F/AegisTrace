import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { CreateCaseWizard } from '../components/CreateCaseWizard';
import { useInvestigationStore } from '../stores/investigationStore';
import { GradientBlobCard } from '../components/ui/GradientBlobCard';
import { DiaText } from '../components/ui/DiaText';
import { LiquidMetalButton } from '../components/ui/LiquidMetalButton';
import {
  FolderDot,
  Plus,
  HardDrive,
  Cpu,
  FileText,
  Clock,
  ArrowRight,
  AlertCircle,
  FolderCheck,
} from 'lucide-react';
import type { Case } from '../types';

export const HomePage: React.FC = () => {
  const {
    investigations,
    activeInvestigation,
    setActiveInvestigation,
    setCurrentTab,
    fetchInvestigations,
    evidenceList,
    findings,
    artifacts,
    error
  } = useInvestigationStore();

  const [showWizard, setShowWizard] = useState(false);

  const handleCaseCreated = async (newCase: Case) => {
    await fetchInvestigations();
    await setActiveInvestigation(newCase);
    setCurrentTab('investigation');
  };

  return (
    <PageContainer
      title="Digital Forensic Investigation Workstation"
      subtitle="Deterministic forensic tool execution, chain-of-custody integrity, and evidence-grounded incident response."
      actions={
        <LiquidMetalButton
          label="New Case"
          onClick={() => setShowWizard(true)}
          viewMode="text"
        />
      }
    >
      <div className="space-y-6">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-xl font-bold font-mono text-slate-100">Workspace Status:</h2>
          <DiaText
            text={
              activeInvestigation
                ? [
                    activeInvestigation.name,
                    `Status: ${activeInvestigation.status}`,
                    activeInvestigation.case_number ? `Case #${activeInvestigation.case_number}` : 'Active Case'
                  ]
                : ["ADFIR Forensic Workstation", "Deterministic Execution Engine", "Immutable Chain-of-Custody Core"]
            }
            className="font-mono text-indigo-400 font-bold text-xl"
          />
        </div>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-xl flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Quick Action Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <GradientBlobCard className="hover:border-indigo-500/40 cursor-pointer transition-all shadow-xs" onClick={() => setShowWizard(true)}>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-indigo-600/20 border border-indigo-500/30 rounded-xl text-indigo-400">
                <FolderDot className="w-5 h-5" />
              </div>
              <Plus className="w-4 h-4 text-slate-400" />
            </div>
            <h4 className="font-bold text-sm text-slate-100 font-mono">Create Case</h4>
            <p className="text-xs text-slate-400 mt-1">Initialize case workspace wizard</p>
          </GradientBlobCard>

          <GradientBlobCard className="hover:border-indigo-500/40 cursor-pointer transition-all shadow-xs" onClick={() => setCurrentTab('evidence')}>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-cyan-600/20 border border-cyan-500/30 rounded-xl text-cyan-400">
                <HardDrive className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400" />
            </div>
            <h4 className="font-bold text-sm text-slate-100 font-mono">Ingest Evidence</h4>
            <p className="text-xs text-slate-400 mt-1">SHA-256 hash & index disk/pcap</p>
          </GradientBlobCard>

          <GradientBlobCard className="hover:border-indigo-500/40 cursor-pointer transition-all shadow-xs" onClick={() => setCurrentTab('process')}>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-purple-600/20 border border-purple-500/30 rounded-xl text-purple-400">
                <Cpu className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400" />
            </div>
            <h4 className="font-bold text-sm text-slate-100 font-mono">Run Pipeline</h4>
            <p className="text-xs text-slate-400 mt-1">TSK, Volatility, YARA, EVTX engine</p>
          </GradientBlobCard>

          <GradientBlobCard className="hover:border-indigo-500/40 cursor-pointer transition-all shadow-xs" onClick={() => setCurrentTab('reports')}>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-emerald-600/20 border border-emerald-500/30 rounded-xl text-emerald-400">
                <FileText className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-400" />
            </div>
            <h4 className="font-bold text-sm text-slate-100 font-mono">Synthesize Report</h4>
            <p className="text-xs text-slate-400 mt-1">Court-ready DFIR documentation</p>
          </GradientBlobCard>
        </div>

        {/* Active Investigation Context Banner */}
        {activeInvestigation && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl relative overflow-hidden backdrop-blur-md">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="text-[10px] font-mono text-indigo-400 uppercase font-bold bg-indigo-500/10 px-3 py-1 rounded-full border border-indigo-500/20">
                    Active Case Workspace
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20 font-semibold">
                    {activeInvestigation.status}
                  </span>
                  {activeInvestigation.workspace_state === 'READY' && (
                    <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20 font-semibold">
                      <FolderCheck className="w-3.5 h-3.5 text-emerald-400" /> Workspace Ready
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-slate-100 font-mono">
                  {activeInvestigation.case_number ? `[${activeInvestigation.case_number}] ` : ''}
                  {activeInvestigation.name}
                </h3>
                {activeInvestigation.objective && (
                  <p className="text-xs text-indigo-400 mt-1 italic font-mono">
                    Objective: &ldquo;{activeInvestigation.objective}&rdquo;
                  </p>
                )}
              </div>

              <button
                onClick={() => setCurrentTab('investigation')}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-mono rounded-xl border border-indigo-500/30 transition-all shadow-md shadow-indigo-500/20 self-start md:self-auto"
              >
                Open Case Workspace &rarr;
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800/80">
                <span className="text-slate-400 text-[10px] block uppercase font-bold">Case ID</span>
                <span className="text-slate-200 truncate block font-mono mt-0.5">{activeInvestigation.id}</span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800/80">
                <span className="text-slate-400 text-[10px] block uppercase font-bold">Evidence Items</span>
                <span className="text-slate-100 font-bold mt-0.5 block">{evidenceList.length} Ingested</span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800/80">
                <span className="text-slate-400 text-[10px] block uppercase font-bold">Extracted Artifacts</span>
                <span className="text-indigo-400 font-bold mt-0.5 block">{artifacts.length} Stored</span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800/80">
                <span className="text-slate-400 text-[10px] block uppercase font-bold">Candidate Findings</span>
                <span className="text-amber-400 font-bold mt-0.5 block">{findings.length} Generated</span>
              </div>
            </div>
          </div>
        )}

        {/* Recent Cases Section */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-2">
              <Clock className="w-4 h-4 text-indigo-400" /> Recent Investigations ({investigations.length})
            </h3>
            {investigations.length > 0 && (
              <button
                onClick={() => setCurrentTab('cases')}
                className="text-xs font-mono text-indigo-400 hover:text-indigo-300 font-semibold"
              >
                View All Cases &rarr;
              </button>
            )}
          </div>

          {investigations.length === 0 ? (
            <EmptyState
              icon={FolderDot}
              title="No cases yet"
              description="Create your first digital forensic investigation to begin evidence intake and analysis."
              actionLabel="+ Create New Case"
              onAction={() => setShowWizard(true)}
            />
          ) : (
            <div className="overflow-x-auto bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 text-[10px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Case Details</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Workspace State</th>
                    <th className="py-3 px-4">Created Date</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-[11px]">
                  {investigations.slice(0, 5).map((inv) => (
                    <tr
                      key={inv.id}
                      onClick={() => setActiveInvestigation(inv)}
                      className="hover:bg-slate-900/40 cursor-pointer text-slate-300 transition-colors"
                    >
                      <td className="py-3.5 px-4">
                        <span className="font-bold text-slate-100 block">
                          {inv.case_number ? `[${inv.case_number}] ` : ''}
                          {inv.name}
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">{inv.id.substring(0, 8)}...</span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded-full border border-emerald-500/20 font-semibold">
                          {inv.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border font-semibold ${
                          inv.workspace_state === 'READY'
                            ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                            : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                        }`}>
                          {inv.workspace_state || 'NOT_INITIALIZED'}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">
                        {new Date(inv.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveInvestigation(inv);
                            setCurrentTab('investigation');
                          }}
                          className="px-3 py-1 bg-indigo-900/40 hover:bg-indigo-800/60 text-indigo-300 border border-indigo-700/50 rounded-lg text-[10px] font-bold font-mono transition-colors"
                        >
                          Select Workspace
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <CreateCaseWizard
        isOpen={showWizard}
        onClose={() => setShowWizard(false)}
        onCaseCreated={handleCaseCreated}
      />
    </PageContainer>
  );
};
