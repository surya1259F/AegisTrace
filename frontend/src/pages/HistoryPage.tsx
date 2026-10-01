import React, { useEffect, useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { ChainOfCustodyTimeline } from '../components/ChainOfCustodyTimeline';
import { useInvestigationStore } from '../stores/investigationStore';
import { Clock, FolderDot, Calendar, ShieldCheck, History, Hash, User } from 'lucide-react';

export const HistoryPage: React.FC = () => {
  const {
    investigations,
    activeInvestigation,
    setActiveInvestigation,
    setCurrentTab,
    custodyEvents,
    auditEvents,
    fetchAuditTrail
  } = useInvestigationStore();

  const [activeSubTab, setActiveSubTab] = useState<'audit' | 'custody' | 'cases'>('audit');

  useEffect(() => {
    fetchAuditTrail(activeInvestigation?.id);
  }, [fetchAuditTrail, activeInvestigation]);

  return (
    <PageContainer
      title="Investigation History & Security Audit Trail"
      subtitle="Authoritative chronological log of all case actions, tool executions, and cryptographic custody events."
    >
      <div className="space-y-6">
        {/* Navigation Sub-Tabs */}
        <div className="flex border-b border-slate-800 text-xs font-mono font-medium gap-2">
          <button
            onClick={() => setActiveSubTab('audit')}
            className={`pb-2.5 px-3 transition-colors ${activeSubTab === 'audit' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Security Audit Trail ({auditEvents.length})
          </button>
          <button
            onClick={() => setActiveSubTab('custody')}
            className={`pb-2.5 px-3 transition-colors ${activeSubTab === 'custody' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Chain of Custody Events ({custodyEvents.length})
          </button>
          <button
            onClick={() => setActiveSubTab('cases')}
            className={`pb-2.5 px-3 transition-colors ${activeSubTab === 'cases' ? 'text-indigo-400 border-b-2 border-indigo-500 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Historical Cases ({investigations.length})
          </button>
        </div>

        {/* Sub-Tab 1: Real Security Audit Trail */}
        {activeSubTab === 'audit' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl backdrop-blur-md">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono uppercase text-slate-100 font-bold flex items-center gap-2">
                <History className="w-4 h-4 text-indigo-400" />
                Immutable System Audit Log ({auditEvents.length})
              </h3>
              <span className="text-[10px] font-mono text-slate-400">
                SHA-256 Hashed Event Blocks
              </span>
            </div>

            {auditEvents.length === 0 ? (
              <EmptyState
                icon={Clock}
                title="No Audit Activity Recorded"
                description="Security-sensitive operations (case creation, evidence intake, tool runs, decisions) will be logged here in append-only records."
              />
            ) : (
              <div className="space-y-2.5 max-h-[600px] overflow-y-auto font-mono text-xs">
                {auditEvents.map((evt) => (
                  <div key={evt.id} className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-1.5 hover:border-slate-700 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                          {evt.event_type}
                        </span>
                        <span className="text-slate-300 text-[11px] flex items-center gap-1">
                          <User className="w-3.5 h-3.5 text-slate-400" /> {evt.actor_name}
                        </span>
                      </div>
                      <span className="text-slate-400 text-[10px]">
                        {new Date(evt.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-slate-200 text-xs font-sans">{evt.details}</p>
                    {evt.event_hash && (
                      <div className="text-[10px] text-slate-400 pt-0.5 truncate flex items-center gap-1">
                        <Hash className="w-3 h-3" /> Hash: {evt.event_hash}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Sub-Tab 2: Chain of Custody Events */}
        {activeSubTab === 'custody' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl backdrop-blur-md">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono uppercase text-slate-100 font-bold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Active Case Chain of Custody Log ({custodyEvents.length})
              </h3>
              <span className="text-[10px] font-mono text-slate-400">
                Cryptographically Chained Evidence Records
              </span>
            </div>
            {custodyEvents.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No Custody Records"
                description="Evidence ingestion and validation events for the active case will appear here."
              />
            ) : (
              <ChainOfCustodyTimeline events={custodyEvents} />
            )}
          </div>
        )}

        {/* Sub-Tab 3: Historical Cases */}
        {activeSubTab === 'cases' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl backdrop-blur-md">
            <h3 className="text-xs font-mono uppercase text-slate-100 font-bold flex items-center gap-2">
              <FolderDot className="w-4 h-4 text-indigo-400" />
              All Cases & Investigations ({investigations.length})
            </h3>

            {investigations.length === 0 ? (
              <EmptyState
                icon={FolderDot}
                title="No Investigations Recorded"
                description="Create an investigation case to establish a new forensic workspace."
              />
            ) : (
              <div className="space-y-3">
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    onClick={() => {
                      setActiveInvestigation(inv);
                      setCurrentTab('investigation');
                    }}
                    className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                      activeInvestigation?.id === inv.id
                        ? 'bg-indigo-950/40 border-indigo-500/50 shadow-md ring-1 ring-indigo-500/30'
                        : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/40'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-slate-400">ID: {inv.id}</span>
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-semibold">
                          {inv.status}
                        </span>
                      </div>
                      <h4 className="font-bold text-sm text-slate-100">{inv.name}</h4>
                      <p className="text-xs text-slate-300 font-sans">{inv.description || 'No description provided.'}</p>
                    </div>

                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400 shrink-0">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3.5 h-3.5" />
                        {new Date(inv.created_at).toLocaleDateString()}
                      </span>
                      <span className="text-slate-300 font-semibold">
                        {inv.evidence_count || 0} Ev | {inv.findings_count || 0} Findings
                      </span>
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
