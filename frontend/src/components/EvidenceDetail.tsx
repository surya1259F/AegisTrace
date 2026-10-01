import React, { useState } from 'react';
import type { Evidence } from '../types';
import { StatusIndicator } from './StatusIndicator';
import { Play, Cpu, Bug, FileText, AlertTriangle, Tag, Layers, RefreshCw, Server, HardDrive } from 'lucide-react';
import { api } from '../services/api';

interface EvidenceDetailProps {
  evidence: Evidence;
  onAnalyzeDisk?: (evidenceId: string) => void;
  onAnalyzeMemory?: (evidenceId: string) => void;
  onAnalyzeMalware?: (evidenceId: string) => void;
  onAnalyzeLog?: (evidenceId: string) => void;
  loading?: boolean;
}

export const EvidenceDetail: React.FC<EvidenceDetailProps> = ({
  evidence,
  onAnalyzeDisk,
  onAnalyzeMemory,
  onAnalyzeMalware,
  onAnalyzeLog,
  loading
}) => {
  const [activeTab, setActiveTab] = useState<'metadata' | 'intelligence'>('intelligence');
  const [reAnalyzing, setReAnalyzing] = useState(false);
  const [localIntelligence, setLocalIntelligence] = useState<Record<string, any> | null>(evidence.intelligence_json || null);
  const [intelError, setIntelError] = useState<string | null>(null);

  const intel = localIntelligence || evidence.intelligence_json || {};

  const handleRefreshIntelligence = async () => {
    if (!evidence.investigation_id || !evidence.id) return;
    setReAnalyzing(true);
    setIntelError(null);
    try {
      const res = await api.refreshEvidenceIntelligence(evidence.investigation_id, evidence.id);
      if (res && res.intelligence) {
        setLocalIntelligence(res.intelligence);
      }
    } catch (err: any) {
      setIntelError(err.response?.data?.detail || err.message || 'Failed to refresh intelligence profile');
    } finally {
      setReAnalyzing(false);
    }
  };

  const isDiskEvidence = ['disk_image', 'file', 'filesystem_image'].includes(evidence.evidence_type.toLowerCase());
  const isMemoryEvidence = ['memory_dump', 'raw_memory', 'vmem', 'dmp', 'minidump'].includes(evidence.evidence_type.toLowerCase());
  const isLogEvidence = ['log', 'event_log', 'evtx', 'windows_event_log', 'file', 'document', 'system_log'].includes(evidence.evidence_type.toLowerCase());
  const isScannableEvidence = ['file', 'executable', 'pe_executable', 'elf_executable', 'macho_executable', 'suspicious_file', 'document', 'log', 'archive', 'disk_image', 'memory_dump'].includes(evidence.evidence_type.toLowerCase());

  const classificationStatus = intel.classification_status || 'MATCH';
  const isMismatch = classificationStatus === 'MISMATCH';

  return (
    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div>
          <h3 className="text-sm font-bold text-slate-200 truncate max-w-[220px]">{evidence.name}</h3>
          <span className="text-[10px] font-mono text-slate-500">ID: {evidence.id.substring(0, 8)}...</span>
        </div>
        <StatusIndicator status={evidence.integrity_status} />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 font-mono text-xs">
        <button
          onClick={() => setActiveTab('intelligence')}
          className={`px-3 py-1.5 border-b-2 font-medium flex items-center gap-1.5 transition-colors ${
            activeTab === 'intelligence'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Intelligence</span>
          {isMismatch && <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />}
        </button>
        <button
          onClick={() => setActiveTab('metadata')}
          className={`px-3 py-1.5 border-b-2 font-medium flex items-center gap-1.5 transition-colors ${
            activeTab === 'metadata'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Basic Metadata</span>
        </button>
      </div>

      {intelError && (
        <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{intelError}</span>
        </div>
      )}

      {/* INTELLIGENCE TAB */}
      {activeTab === 'intelligence' && (
        <div className="space-y-4">
          {/* Extension Mismatch Banner */}
          {isMismatch && (
            <div className="p-3 bg-rose-950/80 border border-rose-600/60 rounded-lg space-y-1 font-mono">
              <div className="flex items-center gap-2 text-rose-300 text-xs font-bold">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>FORMAT MISMATCH ALERT</span>
              </div>
              <p className="text-[11px] text-rose-200 leading-snug">
                {intel.classification_basis || "Declared file extension conflicts with header magic bytes."}
              </p>
            </div>
          )}

          {/* Classification & Subtype */}
          <div className="grid grid-cols-2 gap-2.5 font-mono text-xs">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Classification</span>
              <span className="text-indigo-300 font-bold">{intel.classification || evidence.evidence_type}</span>
            </div>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Detected Format</span>
              <span className="text-slate-300">{intel.detected_format || evidence.detected_format || 'UNKNOWN'}</span>
            </div>
          </div>

          {/* Platform & Architecture */}
          <div className="grid grid-cols-2 gap-2.5 font-mono text-xs">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center gap-2">
              <Server className="w-4 h-4 text-slate-500 shrink-0" />
              <div>
                <span className="text-slate-500 block text-[10px]">PLATFORM HINT</span>
                <span className="text-emerald-400 font-semibold">{intel.platform_hint || evidence.platform_hint || 'UNKNOWN'}</span>
              </div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-slate-500 shrink-0" />
              <div>
                <span className="text-slate-500 block text-[10px]">ARCHITECTURE</span>
                <span className="text-cyan-400 font-semibold">{intel.architecture_hint || 'UNKNOWN'}</span>
              </div>
            </div>
          </div>

          {/* Filesystem & Partition Table */}
          {(intel.filesystem_type !== 'UNKNOWN' || intel.partition_table_type !== 'NONE') && (
            <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500 uppercase flex items-center gap-1">
                  <HardDrive className="w-3.5 h-3.5 text-indigo-400" /> Filesystem / Partition
                </span>
                <span className="text-slate-300 font-bold">{intel.filesystem_type || 'UNKNOWN'} ({intel.partition_table_type || 'NONE'})</span>
              </div>
              {intel.partitions && intel.partitions.length > 0 && (
                <div className="space-y-1 pt-1 border-t border-slate-800">
                  {intel.partitions.map((pt: any, idx: number) => (
                    <div key={idx} className="flex justify-between text-[10px] text-slate-400 bg-slate-900/60 p-1.5 rounded">
                      <span>Partition #{pt.partition_number} ({pt.partition_type})</span>
                      <span className="text-indigo-300">{pt.filesystem} | Start: {pt.start_sector}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Structured Tags */}
          {intel.tags && intel.tags.length > 0 && (
            <div className="space-y-1.5 font-mono">
              <span className="text-slate-500 text-[10px] uppercase block flex items-center gap-1">
                <Tag className="w-3 h-3 text-indigo-400" /> Structured Tags
              </span>
              <div className="flex flex-wrap gap-1.5">
                {intel.tags.map((tg: any, idx: number) => (
                  <span
                    key={idx}
                    title={tg.basis || tg.tag}
                    className={`px-2 py-0.5 rounded text-[10px] border ${
                      tg.category === 'anomaly'
                        ? 'bg-rose-500/20 border-rose-500/40 text-rose-300'
                        : tg.category === 'platform'
                        ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                        : tg.category === 'filesystem'
                        ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                        : 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                    }`}
                  >
                    #{tg.tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Characteristics Badges */}
          {intel.characteristics && intel.characteristics.length > 0 && (
            <div className="space-y-1.5 font-mono">
              <span className="text-slate-500 text-[10px] uppercase block">Characteristics</span>
              <div className="flex flex-wrap gap-1">
                {intel.characteristics.map((c: string, idx: number) => (
                  <span key={idx} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] border border-slate-700">
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Tools */}
          {intel.recommended_tools && intel.recommended_tools.length > 0 && (
            <div className="space-y-1.5 font-mono">
              <span className="text-slate-500 text-[10px] uppercase block">Recommended Forensic Tools</span>
              <div className="space-y-1">
                {intel.recommended_tools.map((tl: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between text-[11px] bg-slate-950 p-2 rounded border border-slate-800">
                    <span className="text-slate-200 font-semibold">{tl.tool_name}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                      tl.is_available ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'
                    }`}>
                      {tl.is_available ? 'HOST READY' : 'NOT INSTALLED'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Re-Analyze Button */}
          <button
            onClick={handleRefreshIntelligence}
            disabled={reAnalyzing || loading}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded-lg text-xs font-mono font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${reAnalyzing ? 'animate-spin text-indigo-400' : ''}`} />
            <span>{reAnalyzing ? 'Re-Verifying Integrity & Headers...' : 'Re-Analyze Evidence Intelligence'}</span>
          </button>
        </div>
      )}

      {/* METADATA TAB */}
      {activeTab === 'metadata' && (
        <div className="space-y-3 font-mono text-xs">
          <div className="grid grid-cols-2 gap-2.5">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">CATEGORY</span>
              <span className="text-slate-300">{evidence.evidence_type}</span>
            </div>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">FILE SIZE</span>
              <span className="text-slate-300">{(evidence.size_bytes / (1024 * 1024)).toFixed(2)} MB</span>
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <span className="text-slate-500 block text-[10px]">CRYPTOGRAPHIC SHA-256 HASH</span>
            <span className="text-indigo-400 break-all">{evidence.sha256}</span>
          </div>

          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <span className="text-slate-500 block text-[10px]">ORIGINAL EVIDENCE PATH</span>
            <span className="text-slate-300 break-all">{evidence.original_path}</span>
          </div>

          {evidence.storage_path && (
            <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 block text-[10px]">PRESERVED VAULT PATH</span>
              <span className="text-emerald-400 break-all">{evidence.storage_path}</span>
            </div>
          )}

          {evidence.notes && (
            <div className="text-xs text-slate-400 bg-slate-950/60 p-3 rounded border border-slate-800/60">
              <span className="text-slate-500 block text-[10px] mb-1">NOTES</span>
              {evidence.notes}
            </div>
          )}
        </div>
      )}

      {/* Forensic Tool Launchers */}
      <div className="space-y-2 pt-3 border-t border-slate-800/80">
        <span className="text-slate-500 text-[10px] font-mono uppercase block">Forensic Investigation Tools</span>
        {isDiskEvidence && onAnalyzeDisk && (
          <button
            onClick={() => onAnalyzeDisk(evidence.id)}
            disabled={loading}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-indigo-500/20 transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Run Disk Forensics (SleuthKit)</span>
          </button>
        )}

        {isMemoryEvidence && onAnalyzeMemory && (
          <button
            onClick={() => onAnalyzeMemory(evidence.id)}
            disabled={loading}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-purple-500/20 transition-colors"
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Run Memory Forensics (Volatility 3)</span>
          </button>
        )}

        {isScannableEvidence && onAnalyzeMalware && (
          <button
            onClick={() => onAnalyzeMalware(evidence.id)}
            disabled={loading}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-rose-500/20 transition-colors"
          >
            <Bug className="w-3.5 h-3.5" />
            <span>Run Malware Signature Scan (YARA)</span>
          </button>
        )}

        {isLogEvidence && onAnalyzeLog && (
          <button
            onClick={() => onAnalyzeLog(evidence.id)}
            disabled={loading}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-amber-500/20 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Run Event Log Forensics (EVTX)</span>
          </button>
        )}
      </div>
    </div>
  );
};
