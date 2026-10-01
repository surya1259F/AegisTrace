import React from 'react';
import type { Investigation } from '../types';
import { StatusIndicator } from './StatusIndicator';
import { Briefcase, Calendar, HardDrive, FileSearch } from 'lucide-react';

interface InvestigationHeaderProps {
  investigation: Investigation;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({ investigation }) => {
  return (
    <div className="bg-slate-900/70 border border-slate-800 p-5 rounded-xl">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-lg">
            <Briefcase className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-base text-slate-100">{investigation.name}</h3>
              <StatusIndicator status={investigation.status} />
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">ID: {investigation.id}</p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
            <span>{investigation.evidence_count || 0} Evidence</span>
          </div>
          <div className="flex items-center gap-1.5">
            <FileSearch className="w-3.5 h-3.5 text-amber-400" />
            <span>{investigation.findings_count || 0} Findings</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-500">
            <Calendar className="w-3.5 h-3.5" />
            <span>{new Date(investigation.created_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>
      {investigation.description && (
        <p className="text-xs text-slate-300 mt-3 pt-3 border-t border-slate-800/80 leading-relaxed">
          {investigation.description}
        </p>
      )}
    </div>
  );
};
