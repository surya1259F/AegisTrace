import React, { useState } from 'react';
import type { Evidence } from '../types';
import { EvidenceItem } from './EvidenceItem';
import { EmptyState } from './EmptyState';
import { HardDrive, Filter } from 'lucide-react';

interface EvidenceListProps {
  evidenceList: Evidence[];
  selectedId?: string;
  onSelectEvidence: (ev: Evidence) => void;
  onIntakeClick?: () => void;
}

const CATEGORY_FILTERS = [
  { id: 'ALL', label: 'All Evidence' },
  { id: 'DISK_IMAGE', label: 'Disk Images' },
  { id: 'MEMORY_DUMP', label: 'Memory' },
  { id: 'WINDOWS', label: 'Windows' },
  { id: 'LINUX', label: 'Linux' },
  { id: 'EVENT_LOG', label: 'Event Logs' },
  { id: 'PCAP_CAPTURE', label: 'Network/PCAP' },
  { id: 'SQLITE_DATABASE', label: 'Browser/Database' },
  { id: 'PE_EXECUTABLE', label: 'Executables' },
];

export const EvidenceList: React.FC<EvidenceListProps> = ({
  evidenceList,
  selectedId,
  onSelectEvidence,
  onIntakeClick,
}) => {
  const [activeFilter, setActiveFilter] = useState('ALL');

  if (evidenceList.length === 0) {
    return (
      <EmptyState
        icon={HardDrive}
        title="No Evidence Ingested"
        description="Add a forensic image, memory dump, or log file to begin investigation."
        actionLabel="Intake Evidence"
        onAction={onIntakeClick}
      />
    );
  }

  const filteredList = evidenceList.filter((ev) => {
    if (activeFilter === 'ALL') return true;

    const evType = (ev.evidence_type || '').toUpperCase();
    const platform = (ev.platform_hint || '').toUpperCase();
    const intel = ev.intelligence_json || {};
    const classification = (intel.classification || evType).toUpperCase();

    if (activeFilter === 'DISK_IMAGE') return classification.includes('DISK') || evType.includes('DISK');
    if (activeFilter === 'MEMORY_DUMP') return classification.includes('MEMORY') || classification.includes('DUMP') || evType.includes('MEMORY');
    if (activeFilter === 'WINDOWS') return platform === 'WINDOWS' || classification.includes('WINDOWS') || evType.includes('WINDOWS') || evType.includes('EVTX');
    if (activeFilter === 'LINUX') return platform === 'LINUX' || classification.includes('ELF') || evType.includes('ELF');
    if (activeFilter === 'EVENT_LOG') return classification.includes('LOG') || evType.includes('LOG') || evType.includes('EVTX');
    if (activeFilter === 'PCAP_CAPTURE') return classification.includes('PCAP') || evType.includes('PCAP');
    if (activeFilter === 'SQLITE_DATABASE') return classification.includes('SQLITE') || classification.includes('BROWSER') || evType.includes('SQLITE');
    if (activeFilter === 'PE_EXECUTABLE') return classification.includes('PE_') || classification.includes('ELF_') || classification.includes('MACHO_') || evType.includes('EXECUTABLE');

    return true;
  });

  return (
    <div className="space-y-3">
      {/* Category Filter Pills */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs font-mono scrollbar-thin">
        <Filter className="w-3.5 h-3.5 text-slate-500 shrink-0 ml-1" />
        {CATEGORY_FILTERS.map((f) => (
          <button
            key={f.id}
            onClick={() => setActiveFilter(f.id)}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-medium whitespace-nowrap transition-colors ${
              activeFilter === f.id
                ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-500/30'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {filteredList.length === 0 ? (
        <div className="p-6 text-center text-xs font-mono text-slate-500 bg-slate-900/40 border border-slate-800 rounded-xl">
          No evidence items match category filter: <span className="text-indigo-400 font-bold">{activeFilter}</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {filteredList.map((ev) => (
            <EvidenceItem
              key={ev.id}
              evidence={ev}
              isSelected={ev.id === selectedId}
              onSelect={() => onSelectEvidence(ev)}
            />
          ))}
        </div>
      )}
    </div>
  );
};
