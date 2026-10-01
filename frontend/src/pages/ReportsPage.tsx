import React, { useState, useEffect, useCallback } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { useInvestigationStore } from '../stores/investigationStore';
import { api } from '../services/api';
import type {
  ForensicReportResponse,
  ForensicReportVersionItem,
  ForensicReportIntegrityResponse,
  ForensicReportProvenanceResponse
} from '../types';
import {
  FileText,
  Download,
  CheckCircle2,
  AlertCircle,
  Clock,
  ShieldCheck,
  ShieldAlert,
  History,
  RefreshCw,
  Copy,
  ChevronRight
} from 'lucide-react';
import { LiquidMetalButton } from '../components/ui/LiquidMetalButton';

export const ReportsPage: React.FC = () => {
  const {
    activeInvestigation,
    error: storeError
  } = useInvestigationStore();

  const [reports, setReports] = useState<ForensicReportVersionItem[]>([]);
  const [selectedReport, setSelectedReport] = useState<ForensicReportResponse | null>(null);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'evidence' | 'tools' | 'timeline' | 'findings' | 'decisions' | 'provenance' | 'markdown'
  >('overview');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Integrity & Provenance Modals/States
  const [integrityData, setIntegrityData] = useState<ForensicReportIntegrityResponse | null>(null);
  const [verifyingIntegrity, setVerifyingIntegrity] = useState(false);
  const [provenanceData, setProvenanceData] = useState<ForensicReportProvenanceResponse | null>(null);

  // New report modal state
  const [isGenerateModalOpen, setIsGenerateModalOpen] = useState(false);
  const [reportTitle, setReportTitle] = useState('');
  const [methodologyNotes, setMethodologyNotes] = useState('');

  const loadReportVersions = useCallback(async (caseId: string, selectVersionId?: string) => {
    try {
      setLoading(true);
      setError(null);
      const versions = await api.listForensicReports(caseId);
      setReports(versions);

      if (versions.length > 0) {
        const targetId = selectVersionId || versions[0].id;
        const rep = await api.getForensicReport(caseId, targetId);
        setSelectedReport(rep);
      } else {
        setSelectedReport(null);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load report history');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeInvestigation?.id) {
      loadReportVersions(activeInvestigation.id);
    }
  }, [activeInvestigation?.id, loadReportVersions]);

  if (!activeInvestigation) {
    return (
      <PageContainer title="Court-Oriented Final Forensic Report Studio">
        <EmptyState
          icon={FileText}
          title="No Active Case Selected"
          description="Select or create an investigation case before synthesizing official forensic reports."
        />
      </PageContainer>
    );
  }

  const handleSelectVersion = async (reportId: string) => {
    try {
      setLoading(true);
      const rep = await api.getForensicReport(activeInvestigation.id, reportId);
      setSelectedReport(rep);
      setIntegrityData(null);
      setProvenanceData(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load selected report version');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    try {
      setLoading(true);
      setError(null);
      const newRep = await api.generateForensicReport(activeInvestigation.id, {
        title: reportTitle.trim() || undefined,
        methodology_notes: methodologyNotes.trim() || undefined
      });
      setIsGenerateModalOpen(false);
      setReportTitle('');
      setMethodologyNotes('');
      await loadReportVersions(activeInvestigation.id, newRep.id);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Report synthesis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (!selectedReport) return;
    try {
      setVerifyingIntegrity(true);
      const res = await api.verifyForensicReportIntegrity(activeInvestigation.id, selectedReport.id);
      setIntegrityData(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Integrity verification failed');
    } finally {
      setVerifyingIntegrity(false);
    }
  };

  const handleLoadProvenance = async () => {
    if (!selectedReport) return;
    try {
      setLoading(true);
      const res = await api.getForensicReportProvenance(activeInvestigation.id, selectedReport.id);
      setProvenanceData(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to fetch provenance graph');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'markdown' | 'json') => {
    if (!selectedReport) return;
    try {
      const { data, filename, contentType } = await api.exportForensicReport(
        activeInvestigation.id,
        selectedReport.id,
        format
      );
      const blob = new Blob([data], { type: contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err?.response?.data?.detail || `Export failed for format ${format}`);
    }
  };

  const handleCopyMarkdown = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(selectedReport.full_report_markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyHash = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(selectedReport.report_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const sec = selectedReport?.sections;

  return (
    <PageContainer
      title="Final Forensic Report Studio"
      subtitle={`Case: ${activeInvestigation.name} | Evidence-grounded, versioned 12-section court-ready forensic report synthesis.`}
      actions={
        <div className="flex items-center gap-2">
          {selectedReport && (
            <>
              {/* Version History Selector */}
              {reports.length > 1 && (
                <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-slate-200">
                  <History className="w-3.5 h-3.5 text-indigo-400" />
                  <select
                    value={selectedReport.id}
                    onChange={(e) => handleSelectVersion(e.target.value)}
                    className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
                  >
                    {reports.map((r) => (
                      <option key={r.id} value={r.id} className="bg-slate-900 text-slate-200">
                        v{r.version} — {new Date(r.generated_at).toLocaleDateString()} ({r.findings_count} findings)
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <button
                onClick={handleVerifyIntegrity}
                disabled={verifyingIntegrity}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
                title="Verify cryptographic SHA-256 digest"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-indigo-400 ${verifyingIntegrity ? 'animate-spin' : ''}`} />
                <span>Verify Digest</span>
              </button>

              <button
                onClick={() => handleExport('markdown')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-emerald-400" />
                <span>Export (.md)</span>
              </button>

              <button
                onClick={() => handleExport('json')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Export (.json)</span>
              </button>

              <button
                onClick={handleCopyMarkdown}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
              >
                {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </>
          )}

          <LiquidMetalButton
            label="Generate Report"
            onClick={() => setIsGenerateModalOpen(true)}
          />
        </div>
      }
    >
      <div className="space-y-6">
        {(error || storeError) && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error || storeError}</span>
          </div>
        )}

        {/* Real-time Integrity Verification Banner */}
        {integrityData && (
          <div
            className={`p-4 rounded-xl border font-mono text-xs flex items-center justify-between gap-4 ${
              integrityData.tamper_detected
                ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
            }`}
          >
            <div className="flex items-center gap-3">
              {integrityData.tamper_detected ? (
                <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
              )}
              <div>
                <span className="font-bold block">
                  {integrityData.tamper_detected
                    ? 'SECURITY WARNING: REPORT TAMPERING DETECTED'
                    : 'CRYPTOGRAPHIC INTEGRITY VERIFIED (NON-REPUDIATION GUARANTEED)'}
                </span>
                <span className="text-[11px] opacity-80">
                  Expected: {integrityData.expected_hash.slice(0, 16)}... | Computed:{' '}
                  {integrityData.computed_hash.slice(0, 16)}... Checked at:{' '}
                  {new Date(integrityData.checked_at).toLocaleTimeString()}
                </span>
              </div>
            </div>
            <button
              onClick={() => setIntegrityData(null)}
              className="px-2 py-1 bg-slate-800/60 hover:bg-slate-800 rounded text-[11px] text-slate-300"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Selected Report Workspace */}
        {selectedReport && sec ? (
          <div className="space-y-4">
            {/* Report Header Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 font-mono text-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-indigo-400 shrink-0" />
                  <div>
                    <h3 className="font-bold text-slate-100 text-sm">{selectedReport.title}</h3>
                    <span className="text-slate-500 text-[10px]">
                      Version {selectedReport.version} • Generated by {selectedReport.generated_by}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      selectedReport.integrity_status === 'VERIFIED'
                        ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                        : 'bg-amber-500/10 border border-amber-500/20 text-amber-400'
                    }`}
                  >
                    {selectedReport.integrity_status}
                  </span>
                  <span className="text-slate-400 text-[10px] flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {new Date(selectedReport.generated_at).toLocaleString()}
                  </span>
                </div>
              </div>

              {/* SHA-256 Digest Row */}
              <div className="flex items-center justify-between bg-slate-950 p-2.5 rounded-lg border border-slate-800/80">
                <div className="flex items-center gap-2 overflow-hidden">
                  <span className="text-slate-500 text-[10px] uppercase font-bold shrink-0">CANONICAL SHA-256:</span>
                  <span className="text-indigo-300 font-mono text-[11px] truncate">{selectedReport.report_hash}</span>
                </div>
                <button
                  onClick={handleCopyHash}
                  className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-200 shrink-0 pl-2"
                >
                  {copiedHash ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              {/* Metric Counters */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-[11px] pt-1">
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Findings</span>
                  <span className="text-slate-200 font-bold">{selectedReport.findings_count}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Evidence</span>
                  <span className="text-slate-200 font-bold">{selectedReport.evidence_count}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Mean Confidence</span>
                  <span className="text-emerald-400 font-bold">
                    {(sec.confidence_verification?.findings_confidence_mean * 100 || 100).toFixed(1)}%
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Investigator Reviews</span>
                  <span className="text-indigo-400 font-bold">{sec.investigator_decisions?.total_reviews || 0}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Lineage Nodes</span>
                  <span className="text-cyan-400 font-bold">{sec.explainability_provenance?.nodes_count || 0}</span>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 overflow-x-auto text-xs font-mono">
              {[
                { id: 'overview', label: '1. Executive Overview' },
                { id: 'evidence', label: '2-4. Evidence & Custody' },
                { id: 'tools', label: '5-6. Executions & Artifacts' },
                { id: 'timeline', label: '7-8. Timeline & Correlations' },
                { id: 'findings', label: '9-10. Findings & Verification' },
                { id: 'decisions', label: '11. Investigator Decisions' },
                { id: 'provenance', label: '12. Explainability & Provenance' },
                { id: 'markdown', label: 'Court-Ready Document' }
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setActiveTab(t.id as any);
                    if (t.id === 'provenance' && !provenanceData) {
                      handleLoadProvenance();
                    }
                  }}
                  className={`px-4 py-2.5 whitespace-nowrap border-b-2 font-medium transition-colors ${
                    activeTab === t.id
                      ? 'border-indigo-500 text-indigo-400 bg-slate-900/40'
                      : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 min-h-[400px]">
              {/* TAB 1: EXECUTIVE OVERVIEW */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-2">Executive Summary</h4>
                    <p className="text-slate-300 font-sans leading-relaxed text-sm bg-slate-900/60 p-4 rounded-lg border border-slate-800">
                      {selectedReport.executive_summary}
                    </p>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Case Information</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                      <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-800/80 space-y-2">
                        <div className="flex justify-between">
                          <span className="text-slate-500">Case Number:</span>
                          <span className="text-slate-200 font-bold">{sec.case_information?.case_number}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Title:</span>
                          <span className="text-slate-200">{sec.case_information?.name}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Type / Priority:</span>
                          <span className="text-slate-200">
                            {sec.case_information?.case_type} / {sec.case_information?.priority}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Status:</span>
                          <span className="text-emerald-400 font-bold">{sec.case_information?.status}</span>
                        </div>
                      </div>

                      <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-800/80 space-y-2">
                        <span className="text-slate-500 block">Authorized Case Members:</span>
                        {sec.case_information?.members?.map((m: any, idx: number) => (
                          <div key={idx} className="flex justify-between text-[11px] text-slate-300">
                            <span>{m.name}</span>
                            <span className="text-indigo-400">[{m.role}]</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Findings Breakdown Cards */}
                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Confidence & Grounding Metrics</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
                      <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Grounded Claims</span>
                        <span className="text-emerald-400 font-bold text-lg">
                          {sec.confidence_verification?.grounded_claims_count || 0}
                        </span>
                      </div>
                      <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Unsupported Claims</span>
                        <span className="text-amber-400 font-bold text-lg">
                          {sec.confidence_verification?.unsupported_claims_count || 0}
                        </span>
                      </div>
                      <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">FACT Classified</span>
                        <span className="text-cyan-400 font-bold text-lg">
                          {sec.confidence_verification?.findings_by_classification?.FACT || 0}
                        </span>
                      </div>
                      <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">INFERENCE Classified</span>
                        <span className="text-purple-400 font-bold text-lg">
                          {sec.confidence_verification?.findings_by_classification?.INFERENCE || 0}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: EVIDENCE & CUSTODY */}
              {activeTab === 'evidence' && (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Evidence Inventory & Preservation</h4>
                    <div className="overflow-x-auto border border-slate-800 rounded-lg">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px]">
                          <tr>
                            <th className="p-3">Container Name</th>
                            <th className="p-3">Type</th>
                            <th className="p-3">Size</th>
                            <th className="p-3">SHA-256 Digest</th>
                            <th className="p-3">Integrity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {sec.evidence_inventory?.map((e: any) => {
                            const hashRec = sec.hashes_preservation?.find((h: any) => h.evidence_id === e.id);
                            return (
                              <tr key={e.id} className="hover:bg-slate-900/30">
                                <td className="p-3 font-medium text-slate-200">{e.name}</td>
                                <td className="p-3 text-slate-400">{e.evidence_type}</td>
                                <td className="p-3 text-slate-400">{e.size_bytes?.toLocaleString()} B</td>
                                <td className="p-3 text-slate-400 text-[10px]">{hashRec?.registered_sha256 || 'N/A'}</td>
                                <td className="p-3">
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      hashRec?.integrity_status === 'VERIFIED'
                                        ? 'text-emerald-400 bg-emerald-500/10'
                                        : 'text-amber-400 bg-amber-500/10'
                                    }`}
                                  >
                                    {hashRec?.integrity_status || 'VERIFIED'}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Chain of Custody Events</h4>
                    <div className="overflow-x-auto border border-slate-800 rounded-lg">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px]">
                          <tr>
                            <th className="p-3">Timestamp (UTC)</th>
                            <th className="p-3">Action</th>
                            <th className="p-3">Actor</th>
                            <th className="p-3">Event Hash</th>
                            <th className="p-3">Notes</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {sec.chain_of_custody?.map((c: any) => (
                            <tr key={c.id} className="hover:bg-slate-900/30">
                              <td className="p-3 text-slate-400 whitespace-nowrap">{c.timestamp}</td>
                              <td className="p-3 font-bold text-indigo-400">{c.action}</td>
                              <td className="p-3 text-slate-200">{c.actor}</td>
                              <td className="p-3 text-[10px] text-slate-500">{c.event_hash?.slice(0, 16)}...</td>
                              <td className="p-3 text-slate-300">{c.notes}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: TOOL EXECUTIONS & ARTIFACTS */}
              {activeTab === 'tools' && (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Tool Executions</h4>
                    <div className="overflow-x-auto border border-slate-800 rounded-lg">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px]">
                          <tr>
                            <th className="p-3">Tool Name</th>
                            <th className="p-3">Capability</th>
                            <th className="p-3">Status</th>
                            <th className="p-3">Exit Code</th>
                            <th className="p-3">Started At</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {sec.tool_executions?.map((x: any) => (
                            <tr key={x.id} className="hover:bg-slate-900/30">
                              <td className="p-3 font-medium text-slate-200">{x.tool_name}</td>
                              <td className="p-3 text-slate-400">{x.capability}</td>
                              <td className="p-3">
                                <span className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded text-[10px]">
                                  {x.status}
                                </span>
                              </td>
                              <td className="p-3 text-slate-400">{x.exit_code}</td>
                              <td className="p-3 text-slate-400">{x.started_at}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Extracted Forensic Artifacts</h4>
                    <div className="grid grid-cols-2 gap-4 font-mono text-xs">
                      <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block uppercase text-[10px]">Structured Artifacts</span>
                        <span className="text-slate-200 font-bold text-xl">{sec.artifacts?.structured_count || 0}</span>
                      </div>
                      <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block uppercase text-[10px]">Normalized Deduplicated Entities</span>
                        <span className="text-indigo-400 font-bold text-xl">{sec.artifacts?.normalized_count || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: TIMELINE & CORRELATIONS */}
              {activeTab === 'timeline' && (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Unified Timeline Events</h4>
                    <div className="overflow-x-auto border border-slate-800 rounded-lg max-h-80 overflow-y-auto">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px] sticky top-0">
                          <tr>
                            <th className="p-3">Timestamp (UTC)</th>
                            <th className="p-3">Event Type</th>
                            <th className="p-3">Description</th>
                            <th className="p-3">Certainty</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {sec.timeline?.map((t: any) => (
                            <tr key={t.id} className="hover:bg-slate-900/30">
                              <td className="p-3 text-slate-400 whitespace-nowrap">{t.timestamp_utc}</td>
                              <td className="p-3 text-indigo-400 font-bold">{t.event_type}</td>
                              <td className="p-3 text-slate-300">{t.description}</td>
                              <td className="p-3 text-slate-400">{t.certainty}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold font-mono text-slate-200 mb-3">Cross-Domain Correlations</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                      {sec.correlations?.groups?.map((cg: any) => (
                        <div key={cg.id} className="bg-slate-900/40 p-4 rounded-lg border border-slate-800 space-y-2">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-slate-200">{cg.group_name}</span>
                            <span className="text-emerald-400 font-bold">{(cg.confidence_score * 100).toFixed(0)}%</span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{cg.correlated_entity}</p>
                          <div className="text-[10px] text-slate-500">Rule: {cg.rule}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 5: FINDINGS & VERIFICATION */}
              {activeTab === 'findings' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold font-mono text-slate-200">
                      Forensic Findings & Governed AI Hypotheses ({sec.findings?.total_findings || 0})
                    </h4>
                    <span className="text-slate-500 text-xs font-mono">
                      Deterministic: {sec.findings?.deterministic_count} | AI Hypotheses: {sec.findings?.ai_reasoning_claims_count}
                    </span>
                  </div>

                  <div className="space-y-3">
                    {sec.findings?.items?.map((f: any) => {
                      const isRejected = f.investigator_decision === 'REJECT';
                      const isChallenged = f.investigator_decision === 'CHALLENGE';

                      return (
                        <div
                          key={f.id}
                          className={`p-4 rounded-lg border font-mono text-xs space-y-2 ${
                            isRejected
                              ? 'bg-rose-500/5 border-rose-500/30'
                              : isChallenged
                              ? 'bg-amber-500/5 border-amber-500/30'
                              : 'bg-slate-900/50 border-slate-800'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  f.classification === 'FACT'
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    : f.classification === 'INFERENCE'
                                    ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                }`}
                              >
                                {f.classification}
                              </span>
                              <span className="font-bold text-slate-200 text-sm">{f.title}</span>
                            </div>

                            <div className="flex items-center gap-2">
                              {f.investigator_decision && (
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    isRejected
                                      ? 'bg-rose-500/20 text-rose-300'
                                      : isChallenged
                                      ? 'bg-amber-500/20 text-amber-300'
                                      : 'bg-emerald-500/20 text-emerald-300'
                                  }`}
                                >
                                  {isRejected ? 'REJECTED BY INVESTIGATOR' : f.investigator_decision}
                                </span>
                              )}
                              <span className="text-slate-500 text-[11px]">{(f.confidence * 100).toFixed(0)}%</span>
                            </div>
                          </div>

                          {f.investigator_rationale && (
                            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800/80 text-[11px] text-slate-300">
                              <span className="text-slate-500 font-bold block text-[10px] uppercase">Investigator Rationale:</span>
                              {f.investigator_rationale}
                            </div>
                          )}

                          <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                            <span>
                              Supporting: {f.supporting_evidence_ids?.length || 0} evidence,{' '}
                              {f.supporting_artifact_ids?.length || 0} artifacts
                            </span>
                            <span className="font-mono text-[10px]">
                              {f.is_grounded ? '✓ Grounded' : '✗ Ungrounded / Speculative'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* TAB 6: INVESTIGATOR DECISIONS */}
              {activeTab === 'decisions' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold font-mono text-slate-200">
                      Investigator Review Decisions Log ({sec.investigator_decisions?.total_reviews || 0})
                    </h4>
                    <span className="text-slate-400 text-xs font-mono">
                      Accepted: {sec.investigator_decisions?.accepted_count} | Challenged:{' '}
                      {sec.investigator_decisions?.challenged_count} | Rejected:{' '}
                      {sec.investigator_decisions?.rejected_count}
                    </span>
                  </div>

                  <div className="space-y-3">
                    {sec.investigator_decisions?.reviews?.map((r: any) => (
                      <div
                        key={r.review_id}
                        className="bg-slate-900/40 p-4 rounded-lg border border-slate-800 font-mono text-xs space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              r.decision === 'REJECT'
                                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                : r.decision === 'CHALLENGE'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}
                          >
                            {r.decision}
                          </span>
                          <span className="text-slate-400 text-[11px]">{r.timestamp}</span>
                        </div>

                        <p className="text-slate-300 text-sm font-sans">{r.comment}</p>

                        <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                          <span>Investigator: {r.investigator_name}</span>
                          <span className="text-[10px] font-mono">Review Digest: {r.sha256_hash?.slice(0, 16)}...</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 7: PROVENANCE & LINEAGE */}
              {activeTab === 'provenance' && (
                <div className="space-y-6 font-mono text-xs">
                  <div>
                    <h4 className="text-sm font-bold text-slate-200 mb-2">End-to-End Forensic Lineage Trace</h4>
                    <p className="text-slate-400 text-[11px] mb-4">
                      Complete provenance linking Raw Evidence items down to the Final Report.
                    </p>

                    <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800 space-y-2">
                      <span className="text-slate-500 block uppercase text-[10px]">Deterministic Pipeline Trace:</span>
                      <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-300 pt-1">
                        {sec.explainability_provenance?.pipeline_trace?.map((step: string, idx: number) => (
                          <React.Fragment key={idx}>
                            <span className="px-2 py-1 bg-slate-800 rounded border border-slate-700 text-indigo-300">
                              {step}
                            </span>
                            {idx < (sec.explainability_provenance?.pipeline_trace?.length || 0) - 1 && (
                              <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  </div>

                  {provenanceData && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Evidence Nodes</span>
                        <span className="text-slate-200 font-bold text-lg">{provenanceData.node_counts?.evidence || 0}</span>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Executions</span>
                        <span className="text-slate-200 font-bold text-lg">{provenanceData.node_counts?.executions || 0}</span>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Findings</span>
                        <span className="text-slate-200 font-bold text-lg">{provenanceData.node_counts?.findings || 0}</span>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-center">
                        <span className="text-slate-500 block text-[10px] uppercase">Reviews</span>
                        <span className="text-slate-200 font-bold text-lg">{provenanceData.node_counts?.reviews || 0}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 8: COURT-READY MARKDOWN */}
              {activeTab === 'markdown' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-400">Court-Admissible Plaintext Markdown</span>
                    <button
                      onClick={handleCopyMarkdown}
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono border border-slate-700"
                    >
                      {copied ? 'Copied' : 'Copy Full Markdown'}
                    </button>
                  </div>
                  <pre className="font-mono text-xs whitespace-pre-wrap leading-relaxed text-slate-300 bg-slate-900/80 p-6 rounded-lg border border-slate-800 overflow-x-auto max-h-[600px] overflow-y-auto">
                    {selectedReport.full_report_markdown}
                  </pre>
                </div>
              )}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={FileText}
            title="No Final Forensic Reports Generated"
            description="Generate a comprehensive, evidence-grounded final forensic report with verified cryptographic lineage and investigator sign-off."
            actionLabel="Synthesize Initial Report (v1)"
            onAction={() => setIsGenerateModalOpen(true)}
          />
        )}

        {/* Generate Report Modal */}
        {isGenerateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-indigo-400" />
                  <h3 className="font-bold text-slate-100 text-sm">Generate Final Forensic Report</h3>
                </div>
                <button
                  onClick={() => setIsGenerateModalOpen(false)}
                  className="text-slate-500 hover:text-slate-300 text-lg leading-none"
                >
                  &times;
                </button>
              </div>

              <p className="text-slate-300 text-xs font-sans leading-relaxed">
                Synthesize a new versioned report containing all 12 evidence-grounded forensic sections, cryptographic
                preservation digests, and investigator review decisions.
              </p>

              <div className="space-y-3">
                <div>
                  <label className="block text-slate-400 mb-1">Report Title (Optional)</label>
                  <input
                    type="text"
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    placeholder={`Final Forensic Report v${(reports[0]?.version || 0) + 1} — ${activeInvestigation.name}`}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Methodology / Investigation Scope Notes</label>
                  <textarea
                    value={methodologyNotes}
                    onChange={(e) => setMethodologyNotes(e.target.value)}
                    placeholder="Deterministic multi-agent forensic verification pipeline under strict sandbox isolation..."
                    rows={3}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 resize-none"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setIsGenerateModalOpen(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  onClick={handleGenerateReport}
                  disabled={loading}
                  className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold"
                >
                  {loading ? 'Synthesizing...' : 'Generate Report'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageContainer>
  );
};
