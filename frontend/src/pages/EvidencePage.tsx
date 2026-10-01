import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EvidenceList } from '../components/EvidenceList';
import { EvidenceDetail } from '../components/EvidenceDetail';
import { ChainOfCustodyTimeline } from '../components/ChainOfCustodyTimeline';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import { FileUploadCard, type UploadedFile } from '../components/ui/FileUploadCard';
import { ShieldCheck, Plus, AlertCircle } from 'lucide-react';

export const EvidencePage: React.FC = () => {
  const {
    activeInvestigation,
    evidenceList,
    selectedEvidence,
    setSelectedEvidence,
    custodyEvents,
    intakeEvidence,
    executeDiskAnalysis,
    executeMemoryAnalysis,
    executeMalwareAnalysis,
    executeLogAnalysis,
    loading,
    error
  } = useInvestigationStore();

  const [filePath, setFilePath] = useState('');
  const [notes, setNotes] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);

  const handleFilesChange = async (files: File[]) => {
    const newItems: UploadedFile[] = files.map((f, idx) => ({
      id: `${Date.now()}-${idx}`,
      file: f,
      progress: 0,
      status: 'uploading'
    }));

    setUploadedFiles((prev) => [...prev, ...newItems]);

    for (const item of newItems) {
      const hostPath = (item.file as any).path;
      if (hostPath) {
        try {
          await intakeEvidence(hostPath, `Ingested: ${item.file.name}`);
          setUploadedFiles((prev) =>
            prev.map((u) => (u.id === item.id ? { ...u, progress: 100, status: 'completed' } : u))
          );
        } catch (err: any) {
          setUploadedFiles((prev) =>
            prev.map((u) =>
              u.id === item.id ? { ...u, status: 'error', errorText: err?.message || 'Ingestion failed' } : u
            )
          );
        }
      } else {
        // In browser sandbox without direct host path access: prefill the path input
        setFilePath(item.file.name);
        setUploadedFiles((prev) =>
          prev.map((u) =>
            u.id === item.id
              ? {
                  ...u,
                  status: 'error',
                  errorText: 'Specify full absolute host file path below to calculate SHA-256'
                }
              : u
          )
        );
      }
    }
  };

  const handleFileRemove = (id: string) => {
    setUploadedFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const handleIntake = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!filePath || !activeInvestigation) return;
    try {
      await intakeEvidence(filePath, notes);
      setSuccessMsg(`Verified & ingested: ${filePath}`);
      setFilePath('');
      setNotes('');
      setTimeout(() => setSuccessMsg(''), 4000);
    } catch {
      // Handled by store
    }
  };

  const handleAnalyzeDisk = async (evidenceId: string) => {
    try {
      await executeDiskAnalysis(evidenceId);
      setSuccessMsg('Disk analysis complete. Structured artifacts and findings recorded.');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {}
  };

  const handleAnalyzeMemory = async (evidenceId: string) => {
    try {
      await executeMemoryAnalysis(evidenceId, 'windows.pslist');
      setSuccessMsg('Memory analysis complete. Processes & sockets extracted.');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {}
  };

  const handleAnalyzeMalware = async (evidenceId: string) => {
    try {
      await executeMalwareAnalysis(evidenceId, 'adfir_test_rules');
      setSuccessMsg('Malware signature scan complete. YARA matches recorded.');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {}
  };

  const handleAnalyzeLog = async (evidenceId: string) => {
    try {
      await executeLogAnalysis(evidenceId, 5000);
      setSuccessMsg('Log analysis complete. Windows security events extracted.');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch {}
  };

  if (!activeInvestigation) {
    return (
      <PageContainer title="Evidence Management">
        <EmptyState
          icon={AlertCircle}
          title="No Active Investigation"
          description="Please select or create an investigation first before ingesting evidence."
        />
      </PageContainer>
    );
  }

  return (
    <PageContainer
      title="Evidence Intake & Custody Layer"
      subtitle={`Investigation: ${activeInvestigation.name} | Streaming 8MB SHA-256 hash validation.`}
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-xl flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-xl flex items-center gap-2 font-mono">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* 21st.dev File Upload Card component */}
        <FileUploadCard
          files={uploadedFiles}
          onFilesChange={handleFilesChange}
          onFileRemove={handleFileRemove}
        />

        {/* Manual Path Ingestion Form */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl space-y-3 font-sans">
          <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
            <Plus className="w-3.5 h-3.5 text-indigo-400" /> Manual File Path Ingestion
          </h3>
          <form onSubmit={handleIntake} className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-mono">Absolute Host File Path</label>
              <input
                type="text"
                required
                placeholder="e.g. C:\evidence\memdump.raw or /var/log/syslog"
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1 font-mono">Chain of Custody Notes</label>
              <input
                type="text"
                placeholder="Acquired from target endpoint by Lead Forensic Officer"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-mono font-bold text-xs shadow-lg shadow-indigo-500/20 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Compute Hash & Register</span>
              </button>
            </div>
          </form>
        </div>

        {/* Evidence Inventory & Detail Split */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-4">
            <h3 className="text-xs font-mono text-slate-400 uppercase font-bold">
              Evidence Inventory ({evidenceList.length})
            </h3>
            <EvidenceList
              evidenceList={evidenceList}
              selectedId={selectedEvidence?.id}
              onSelectEvidence={setSelectedEvidence}
            />
          </div>

          <div className="space-y-4">
            <h3 className="text-xs font-mono text-slate-400 uppercase font-bold">
              Cryptographic Metadata
            </h3>
            {selectedEvidence ? (
              <EvidenceDetail
                evidence={selectedEvidence}
                onAnalyzeDisk={handleAnalyzeDisk}
                onAnalyzeMemory={handleAnalyzeMemory}
                onAnalyzeMalware={handleAnalyzeMalware}
                onAnalyzeLog={handleAnalyzeLog}
                loading={loading}
              />
            ) : (
              <div className="p-6 text-center text-xs font-mono text-slate-500 bg-slate-900/40 border border-slate-800 rounded-2xl">
                Select an evidence item to view SHA-256 metadata & dispatch analysis jobs.
              </div>
            )}
          </div>
        </div>

        {/* Chain of Custody Log */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4">
          <h3 className="text-xs font-mono uppercase text-slate-200 font-bold">
            Immutable Chain of Custody Audit Log ({custodyEvents.length})
          </h3>
          <ChainOfCustodyTimeline events={custodyEvents} />
        </div>
      </div>
    </PageContainer>
  );
};
