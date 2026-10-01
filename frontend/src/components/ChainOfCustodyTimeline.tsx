import React from 'react';
import type { CustodyRecord } from '../types';
import { ShieldCheck, User } from 'lucide-react';

interface ChainOfCustodyTimelineProps {
  events: CustodyRecord[];
}

export const ChainOfCustodyTimeline: React.FC<ChainOfCustodyTimelineProps> = ({ events }) => {
  if (events.length === 0) {
    return (
      <div className="p-6 text-center text-xs font-mono text-slate-500">
        No chain of custody events recorded yet.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {events.map((evt) => (
        <div
          key={evt.id}
          className="p-3.5 bg-slate-950/80 border border-slate-800/80 rounded-lg flex items-start gap-3 text-xs"
        >
          <div className="p-1.5 bg-indigo-500/10 text-indigo-400 rounded shrink-0 mt-0.5">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="flex-1 space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-mono font-bold text-slate-200">{evt.event_type}</span>
              <span className="text-[11px] font-mono text-slate-500">
                {new Date(evt.timestamp).toLocaleString()}
              </span>
            </div>
            <p className="text-slate-300 text-[11px]">{evt.description}</p>
            <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500 pt-1">
              <span className="flex items-center gap-1">
                <User className="w-3 h-3" /> {evt.actor}
              </span>
              {evt.sha256 && (
                <span className="text-indigo-400 truncate max-w-[180px]">
                  Hash: {evt.sha256}
                </span>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};
