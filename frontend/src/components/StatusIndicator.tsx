import React from 'react';

interface StatusIndicatorProps {
  status: string;
  label?: string;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({ status, label }) => {
  const getColors = () => {
    switch (status.toUpperCase()) {
      case 'VERIFIED':
      case 'SUPPORTED':
      case 'OPEN':
      case 'READY':
      case 'OK':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'IN_PROGRESS':
      case 'PLANNED':
      case 'PENDING':
        return 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20';
      case 'UNVERIFIED':
      case 'UNCHECKED':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'FAILED':
      case 'UNSUPPORTED':
      case 'CONFLICTING':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border ${getColors()}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      <span>{label || status}</span>
    </span>
  );
};
