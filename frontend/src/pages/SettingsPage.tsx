import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { useInvestigationStore } from '../stores/investigationStore';
import { CheckCircle2 } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { settings, updateSettings } = useInvestigationStore();

  const [dataDir, setDataDir] = useState(settings.data_directory);
  const [chunkSize, setChunkSize] = useState(settings.stream_chunk_size_mb);
  const [timeout, setTimeoutVal] = useState(settings.session_timeout_minutes);
  const [auditLog, setAuditLog] = useState(settings.audit_logging_enabled);
  const [savedMsg, setSavedMsg] = useState('');

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateSettings({
      data_directory: dataDir,
      stream_chunk_size_mb: chunkSize,
      session_timeout_minutes: timeout,
      audit_logging_enabled: auditLog
    });
    setSavedMsg('Workstation preferences saved.');
    setTimeout(() => setSavedMsg(''), 3000);
  };

  return (
    <PageContainer
      title="Application & Workstation Settings"
      subtitle="Configure cryptographic hashing parameters, local storage directories, and audit logging policies."
    >
      <div className="space-y-6 max-w-3xl">
        {savedMsg && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{savedMsg}</span>
          </div>
        )}

        <form onSubmit={handleSave} className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5 text-xs">
          <div className="space-y-4">
            <div>
              <label className="block font-mono text-slate-400 mb-1 uppercase text-[11px]">
                Forensic Data Directory
              </label>
              <input
                type="text"
                value={dataDir}
                onChange={(e) => setDataDir(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
              />
              <span className="text-[10px] text-slate-500 mt-1 block font-mono">
                Stores file-backed tool stdout streams and SQLite database.
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block font-mono text-slate-400 mb-1 uppercase text-[11px]">
                  Streaming SHA-256 Buffer Size (MB)
                </label>
                <input
                  type="number"
                  value={chunkSize}
                  onChange={(e) => setChunkSize(parseInt(e.target.value) || 8)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block font-mono text-slate-400 mb-1 uppercase text-[11px]">
                  Security Session Timeout (Minutes)
                </label>
                <input
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeoutVal(parseInt(e.target.value) || 60)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="pt-2">
              <label className="flex items-center gap-2 cursor-pointer font-mono text-slate-300">
                <input
                  type="checkbox"
                  checked={auditLog}
                  onChange={(e) => setAuditLog(e.target.checked)}
                  className="rounded border-slate-800 text-indigo-600 focus:ring-indigo-500 bg-slate-950"
                />
                <span>Enable Immutable Security Audit Logging (`data/security_audit.log`)</span>
              </label>
            </div>
          </div>

          <div className="flex justify-end pt-3 border-t border-slate-800/80">
            <button
              type="submit"
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-medium rounded-lg text-xs shadow-md shadow-indigo-500/20"
            >
              Save Preferences
            </button>
          </div>
        </form>
      </div>
    </PageContainer>
  );
};
