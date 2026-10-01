import React from 'react';
import type { Evidence } from '../types';
import { StatusIndicator } from './StatusIndicator';
import { HardDrive, FileCode, Database } from 'lucide-react';

interface EvidenceItemProps {
  evidence: Evidence;
  isSelected?: boolean;
  onSelect?: () => void;
}

export const EvidenceItem: React.FC<EvidenceItemProps> = ({ evidence, isSelected, onSelect }) => {
  const getIcon = () => {
    switch (evidence.evidence_type) {
      case 'disk_image':
        return HardDrive;
      case 'memory_dump':
        return Database;
      default:
        return FileCode;
    }
  };
  const Icon = getIcon();

  return (
    <div
      onClick={onSelect}
      className={`p-4 rounded-xl border transition-all cursor-pointer ${
        isSelected
          ? 'bg-slate-900 border-indigo-500/60 shadow-lg shadow-indigo-500/10'
          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-slate-800 rounded-lg text-slate-300">
            <Icon className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <h4 className="font-semibold text-xs text-slate-200">{evidence.name}</h4>
            <span className="text-[11px] font-mono text-slate-500">{evidence.evidence_type}</span>
          </div>
        </div>
        <StatusIndicator status={evidence.integrity_status} />
      </div>

      <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>{(evidence.size_bytes / (1024 * 1024)).toFixed(2)} MB</span>
        <span className="text-indigo-400 max-w-[180px] truncate" title={evidence.sha256}>
          {evidence.sha256}
        </span>
      </div>
    </div>
  );
};
