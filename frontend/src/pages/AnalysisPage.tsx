import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import {
  Cpu,
  Play,
  CheckCircle2,
  AlertCircle,
  HardDrive,
  Bug,
  FileText,
  Layers,
  Database
} from 'lucide-react';

export const AnalysisPage: React.FC = () => {
  const {
    activeInvestigation,
    evidenceList,
    artifacts,
    executeDiskAnalysis,
    executeMemoryAnalysis,
    executeMalwareAnalysis,
    executeLogAnalysis,
    loading,
    error
  } = useInvestigationStore();

  const [selectedEvId, setSelectedEvId] = useState<string>('');
  const [volPlugin, setVolPlugin] = useState<string>('windows.pslist');
  const [yaraRule, setYaraRule] = useState<string>('adfir_test_rules');
  const [maxRecords, setMaxRecords] = useState<number>(5000);
  const [successMsg, setSuccessMsg] = useState<string>('');

  // Default select first evidence if not set
  React.useEffect(() => {
    if (evidenceList.length > 0 && !selectedEvId) {
      setSelectedEvId(evidenceList[0].id);
    }
  }, [evidenceList, selectedEvId]);

  if (!activeInvestigation) {
    return (
      <PageContainer title="Specialist Analysis Engines">
        <EmptyState
          icon={AlertCircle}
          title="No Active Investigation"
          description="Select or create an investigation first to execute specialist forensic tools."
        />
      </PageContainer>
    );
  }

  if (evidenceList.length === 0) {
    return (
      <PageContainer
        title="Specialist Analysis Engines"
        subtitle={`Case: ${activeInvestigation.name}`}
      >
        <EmptyState
          icon={HardDrive}
          title="No Evidence Ingested"
          description="Ingest forensic evidence (disk image, memory dump, EVTX log, or file target) before running analysis."
        />
      </PageContainer>
    );
  }

  const selectedEvidence = evidenceList.find((e) => e.id === selectedEvId) || evidenceList[0];

  const handleRunDisk = async () => {
    try {
      await executeDiskAnalysis(selectedEvidence.id);
      setSuccessMsg(`Disk analysis complete on ${selectedEvidence.name}.`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {
      // Handled in store
    }
  };

  const handleRunMemory = async () => {
    try {
      await executeMemoryAnalysis(selectedEvidence.id, volPlugin);
      setSuccessMsg(`Memory analysis (${volPlugin}) complete on ${selectedEvidence.name}.`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {
      // Handled in store
    }
  };

  const handleRunMalware = async () => {
    try {
      await executeMalwareAnalysis(selectedEvidence.id, yaraRule);
      setSuccessMsg(`YARA pattern scan complete on ${selectedEvidence.name}.`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {
      // Handled in store
    }
  };

  const handleRunLog = async () => {
    try {
      await executeLogAnalysis(selectedEvidence.id, maxRecords);
      setSuccessMsg(`Event log parsing complete on ${selectedEvidence.name}.`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {
      // Handled in store
    }
  };

  return (
    <PageContainer
      title="Specialist Forensic Analysis Station"
      subtitle={`Investigation: ${activeInvestigation.name} | Direct deterministic execution via Platform-Aware Tool Registry.`}
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Target Evidence Selection */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-indigo-400 shrink-0" />
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase font-semibold">
                Target Evidence for Analysis:
              </label>
              <select
                value={selectedEvId}
                onChange={(e) => setSelectedEvId(e.target.value)}
                className="mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
              >
                {evidenceList.map((ev) => (
                  <option key={ev.id} value={ev.id}>
                    {ev.name} ({ev.evidence_type}) — {(ev.size_bytes / (1024 * 1024)).toFixed(2)} MB
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="text-right text-[11px] font-mono text-slate-400">
            <span className="text-slate-500 block">SHA-256:</span>
            <span className="text-indigo-400">{selectedEvidence?.sha256.substring(0, 24)}...</span>
          </div>
        </div>

        {/* Tool Execution Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Disk Forensics */}
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400 font-mono text-xs font-bold">
                  <HardDrive className="w-4 h-4" />
                  <span>The Sleuth Kit (DiskAgent)</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">TSK fls 4.12</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Extracts complete directory hierarchies, metadata timestamps, and deleted FAT/NTFS inode pointers.
              </p>
            </div>
            <button
              onClick={handleRunDisk}
              disabled={loading}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-indigo-500/20"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute Disk Forensics (fls)</span>
            </button>
          </div>

          {/* Memory Forensics */}
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-purple-400 font-mono text-xs font-bold">
                  <Cpu className="w-4 h-4" />
                  <span>Volatility 3 (MemoryAgent)</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">Vol 2.28</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Dumps active process trees, injected code memory regions, and volatile network sockets from raw RAM.
              </p>
              <div className="pt-1">
                <label className="block text-[10px] font-mono text-slate-500 mb-1">Plugin Selection:</label>
                <select
                  value={volPlugin}
                  onChange={(e) => setVolPlugin(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-purple-500"
                >
                  <option value="windows.pslist">windows.pslist (Process List)</option>
                  <option value="windows.pstree">windows.pstree (Process Hierarchy)</option>
                  <option value="windows.netscan">windows.netscan (Network Sockets)</option>
                  <option value="windows.malfind">windows.malfind (Code Injection)</option>
                </select>
              </div>
            </div>
            <button
              onClick={handleRunMemory}
              disabled={loading}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-purple-500/20"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute Volatility 3 Analysis</span>
            </button>
          </div>

          {/* Malware Forensics */}
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-rose-400 font-mono text-xs font-bold">
                  <Bug className="w-4 h-4" />
                  <span>YARA Pattern Matcher (MalwareAgent)</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">YARA 4.5.5</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Scans evidence against compiled local signature repositories with exact string byte-offset extraction.
              </p>
              <div className="pt-1">
                <label className="block text-[10px] font-mono text-slate-500 mb-1">Rule Repository:</label>
                <select
                  value={yaraRule}
                  onChange={(e) => setYaraRule(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-rose-500"
                >
                  <option value="adfir_test_rules">adfir_test_rules.yar (Synthetic Marker)</option>
                  <option value="adfir_webshell_indicators">adfir_webshell_indicators.yar (Webshells)</option>
                  <option value="adfir_suspicious_commands">adfir_suspicious_commands.yar (Command Injections)</option>
                </select>
              </div>
            </div>
            <button
              onClick={handleRunMalware}
              disabled={loading}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-rose-500/20"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute YARA Pattern Scan</span>
            </button>
          </div>

          {/* Event Log Forensics */}
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-bold">
                  <FileText className="w-4 h-4" />
                  <span>EVTX Parser (LogAgent)</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">python-evtx 0.8.1</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Streams binary Windows EVTX records and extracts authentication (4624/4625), process (4688), and service (7045) events.
              </p>
              <div className="pt-1">
                <label className="block text-[10px] font-mono text-slate-500 mb-1">Max Records Limit:</label>
                <input
                  type="number"
                  value={maxRecords}
                  onChange={(e) => setMaxRecords(parseInt(e.target.value) || 5000)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>
            <button
              onClick={handleRunLog}
              disabled={loading}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-amber-500/20"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute EVTX Event Parsing</span>
            </button>
          </div>
        </div>

        {/* Extracted Artifacts Table */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              Extracted Forensic Artifacts ({artifacts.length})
            </h3>
            <span className="text-[10px] font-mono text-slate-500">
              Deterministic tool-derived objects (Stored in SQLite)
            </span>
          </div>

          {artifacts.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-slate-500 bg-slate-950/40 rounded-lg border border-slate-800/60">
              No forensic artifacts extracted yet. Execute an analysis engine above.
            </div>
          ) : (
            <div className="overflow-x-auto max-h-[400px]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 text-[10px] uppercase border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Agent / Tool</th>
                    <th className="py-2.5 px-3">Source Ref</th>
                    <th className="py-2.5 px-3">Details / Path</th>
                    <th className="py-2.5 px-3">Raw Output Ref</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-[11px]">
                  {artifacts.map((art) => (
                    <tr key={art.id} className="hover:bg-slate-800/30 text-slate-300">
                      <td className="py-2 px-3 text-indigo-400 font-semibold">{art.artifact_type}</td>
                      <td className="py-2 px-3 text-slate-400">{art.agent} &rarr; {art.tool}</td>
                      <td className="py-2 px-3 text-slate-300">{art.source_reference}</td>
                      <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{art.path || JSON.stringify(art.metadata_json)}</td>
                      <td className="py-2 px-3 text-slate-500 truncate max-w-[200px]" title={art.raw_output_reference}>
                        {art.raw_output_reference || 'N/A'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </PageContainer>
  );
};
