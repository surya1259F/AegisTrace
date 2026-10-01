import React from 'react';
import { useInvestigationStore } from '../stores/investigationStore';
import { ShieldCheck, AlertCircle, CheckCircle2, ChevronDown } from 'lucide-react';

export const TopBar: React.FC = () => {
  const {
    investigations,
    activeInvestigation,
    setActiveInvestigation,
    systemStatus,
    currentUser,
    setCurrentTab
  } = useInvestigationStore();

  return (
    <header className="h-14 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between text-xs select-none shrink-0 font-sans z-20">
      <div className="flex items-center gap-4">
        {/* Active Investigation Selector */}
        {investigations.length > 0 ? (
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-mono text-[11px] uppercase font-semibold">Active Case:</span>
            <div className="relative">
              <select
                value={activeInvestigation?.id || ''}
                onChange={(e) => {
                  const selected = investigations.find((i) => i.id === e.target.value);
                  if (selected) setActiveInvestigation(selected);
                }}
                className="appearance-none bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 pr-8 text-xs font-semibold text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer shadow-xs"
              >
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id} className="bg-slate-900 text-slate-200">
                    {inv.name}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
            {activeInvestigation && (
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-semibold">
                {activeInvestigation.status}
              </span>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-slate-400 font-mono text-xs">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>NO ACTIVE CASE SELECTED</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-4 font-mono text-xs">
        {/* Evidence Status */}
        <div className="flex items-center gap-1.5 text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20 font-semibold">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>READ-ONLY EVIDENCE</span>
        </div>

        {/* Backend Status */}
        {systemStatus?.status === 'READY' ? (
          <div className="flex items-center gap-1.5 text-slate-300 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>CORE READY</span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 text-amber-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
            <span>CONNECTING</span>
          </div>
        )}

        {/* User Profile Button */}
        <button
          onClick={() => setCurrentTab('profile')}
          className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 text-slate-200 transition-colors shadow-xs"
          title="View Investigator Profile"
        >
          <div className="w-4 h-4 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-[10px]">
            {currentUser?.name?.charAt(0) || 'U'}
          </div>
          <span className="text-[11px] font-medium truncate max-w-[120px]">{currentUser?.name || 'Investigator'}</span>
        </button>
      </div>
    </header>
  );
};
