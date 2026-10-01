import React, { useState } from 'react';
import { PageContainer } from '../components/PageContainer';
import { EmptyState } from '../components/EmptyState';
import { InvestigationStrategyView } from '../components/InvestigationStrategyView';
import { useInvestigationStore } from '../stores/investigationStore';
import { ProcessingTimeline, type ProcessingStage } from '../components/ui/ProcessingTimeline';
import {
  StopCircle,
  AlertCircle,
  Terminal,
  BrainCircuit,
  Cpu
} from 'lucide-react';

export const InvestigationProcessPage: React.FC = () => {
  const {
    activeInvestigation,
    evidenceList,
    currentPlan,
    generatePlan,
    toolExecutionTracker,
    cancelActiveExecution,
    executeDiskAnalysis,
    executeMemoryAnalysis,
    executeMalwareAnalysis,
    executeLogAnalysis,
    loading,
    error
  } = useInvestigationStore();

  const [pageMode, setPageMode] = useState<'strategy' | 'execution'>('strategy');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [selectedTool, setSelectedTool] = useState<'disk' | 'memory' | 'malware' | 'log'>('disk');
  const [volatilityPlugin, setVolatilityPlugin] = useState<string>('windows.pslist');
  const [yaraRule, setYaraRule] = useState<string>('adfir_test_rules');
  const [maxEvtxRecords, setMaxEvtxRecords] = useState<number>(5000);

  if (!activeInvestigation) {
    return (
      <PageContainer title="Investigation Execution">
        <EmptyState
          icon={AlertCircle}
          title="No Active Case Selected"
          description="Select or initialize an investigation case before launching the forensic execution engine."
        />
      </PageContainer>
    );
  }

  const handleRunSelected = async () => {
    const evId = selectedEvidenceId || (evidenceList.length > 0 ? evidenceList[0].id : '');
    if (!evId) return;

    if (selectedTool === 'disk') {
      await executeDiskAnalysis(evId);
    } else if (selectedTool === 'memory') {
      await executeMemoryAnalysis(evId, volatilityPlugin);
    } else if (selectedTool === 'malware') {
      await executeMalwareAnalysis(evId, yaraRule);
    } else if (selectedTool === 'log') {
      await executeLogAnalysis(evId, maxEvtxRecords);
    }
  };

  const planSteps = currentPlan?.tasks || currentPlan?.steps || [];

  // Map DAG steps to ProcessingStage format for ProcessingTimeline component
  const timelineStages: ProcessingStage[] = planSteps.map((s: any, idx: number) => {
    const st = (s.status || 'PENDING').toLowerCase();
    let mappedStatus: any = 'pending';
    if (st === 'running' || st === 'executing') mappedStatus = 'active';
    else if (st === 'completed') mappedStatus = 'completed';
    else if (st === 'failed') mappedStatus = 'failed';
    else if (st === 'cancelled') mappedStatus = 'cancelled';
    else if (st === 'queued') mappedStatus = 'queued';

    return {
      id: s.step_id || s.task_key || `stage-${idx}`,
      label: `${s.agent || 'Specialist'} → ${s.tool || s.selected_tool_id || 'Tool'}`,
      description: s.reason || s.rationale?.selection_reason || `Execute ${s.action || 'forensic action'} on evidence`,
      status: mappedStatus,
      progress: typeof s.progress === 'number' ? s.progress : (mappedStatus === 'completed' ? 100 : undefined),
      duration: typeof s.duration_ms === 'number' ? s.duration_ms : undefined,
      error: s.error_message || s.blocking_reason,
      logs: Array.isArray(s.logs) && s.logs.length > 0 
        ? s.logs 
        : (mappedStatus === 'active' && toolExecutionTracker.toolOutputLog.length > 0 
            ? toolExecutionTracker.toolOutputLog 
            : undefined),
      skippable: Boolean(s.skippable ?? (mappedStatus !== 'completed' && mappedStatus !== 'cancelled'))
    };
  });

  return (
    <PageContainer
      title="Investigation Strategy & Execution Orchestrator"
      subtitle={`Case: ${activeInvestigation.name} | Executable DAG strategy planning, tool requirement resolution, and execution telemetry.`}
      actions={
        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 p-1 rounded-xl flex items-center gap-1">
            <button
              onClick={() => setPageMode('strategy')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-all ${
                pageMode === 'strategy' ? 'bg-indigo-600 text-white font-bold shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BrainCircuit className="w-4 h-4" />
              <span>Strategy Engine</span>
            </button>
            <button
              onClick={() => setPageMode('execution')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg transition-all ${
                pageMode === 'execution' ? 'bg-indigo-600 text-white font-bold shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Execution Control</span>
            </button>
          </div>

          {toolExecutionTracker.status === 'RUNNING' && (
            <button
              onClick={cancelActiveExecution}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 rounded-xl text-xs font-mono font-bold transition-colors"
            >
              <StopCircle className="w-4 h-4" />
              <span>Abort Process</span>
            </button>
          )}
        </div>
      }
    >
      <div className="space-y-6 font-sans">
        {pageMode === 'strategy' ? (
          <InvestigationStrategyView caseItem={activeInvestigation} />
        ) : (
          <>
            {error && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-xl flex items-center gap-2 font-mono">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* 21st.dev ProcessingTimeline component */}
            {timelineStages.length > 0 ? (
              <ProcessingTimeline
                title={`Forensic Pipeline — ${activeInvestigation.name}`}
                subtitle="Autonomous Execution Pipeline & Artifact Mining"
                stages={timelineStages}
                jobStatus={toolExecutionTracker.status === 'RUNNING' ? 'active' : 'completed'}
                onCancel={cancelActiveExecution}
                onRestart={() => generatePlan(activeInvestigation.id)}
              />
            ) : (
              <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl text-xs text-slate-400 font-mono flex items-center justify-between">
                <span>No autonomous execution pipeline created for this case.</span>
                <button
                  onClick={() => generatePlan(activeInvestigation.id)}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-bold transition-all"
                >
                  Generate Autonomous DAG Plan &rarr;
                </button>
              </div>
            )}

            {/* Manual Tool Execution Station */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
              <h3 className="text-xs font-mono uppercase text-slate-200 font-bold flex items-center gap-2">
                <Cpu className="w-4 h-4 text-purple-400" />
                Direct Specialist Tool Dispatch Engine
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                <div>
                  <label className="block text-slate-400 mb-1">1. Target Evidence</label>
                  <select
                    value={selectedEvidenceId || (evidenceList[0]?.id || '')}
                    onChange={(e) => setSelectedEvidenceId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                  >
                    {evidenceList.map((ev) => (
                      <option key={ev.id} value={ev.id}>
                        {ev.name} ({ev.evidence_type})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">2. Specialist Tool</label>
                  <select
                    value={selectedTool}
                    onChange={(e) => setSelectedTool(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="disk">The Sleuth Kit (fls Inode Scanner)</option>
                    <option value="memory">Volatility 3 (Memory Process Agent)</option>
                    <option value="malware">YARA Pattern Engine (Malware Agent)</option>
                    <option value="log">python-evtx (Log Analysis Agent)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">3. Execution Parameter</label>
                  {selectedTool === 'disk' && (
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-400">
                      Recursive Inode Traversal (`-r -p`)
                    </div>
                  )}
                  {selectedTool === 'memory' && (
                    <select
                      value={volatilityPlugin}
                      onChange={(e) => setVolatilityPlugin(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="windows.pslist">windows.pslist</option>
                      <option value="windows.pstree">windows.pstree</option>
                      <option value="windows.netscan">windows.netscan</option>
                      <option value="windows.malfind">windows.malfind</option>
                    </select>
                  )}
                  {selectedTool === 'malware' && (
                    <select
                      value={yaraRule}
                      onChange={(e) => setYaraRule(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="adfir_test_rules">adfir_test_rules</option>
                      <option value="adfir_webshell_indicators">adfir_webshell_indicators</option>
                      <option value="adfir_suspicious_commands">adfir_suspicious_commands</option>
                    </select>
                  )}
                  {selectedTool === 'log' && (
                    <input
                      type="number"
                      value={maxEvtxRecords}
                      onChange={(e) => setMaxEvtxRecords(parseInt(e.target.value) || 5000)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                      placeholder="Max Records (e.g. 5000)"
                    />
                  )}
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleRunSelected}
                  disabled={loading || evidenceList.length === 0}
                  className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-mono font-bold rounded-xl text-xs shadow-lg shadow-indigo-500/20 transition-all"
                >
                  {loading ? 'Executing Specialist Engine...' : 'Execute Selected Tool'}
                </button>
              </div>
            </div>

            {/* Subprocess Output Terminal */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3 font-mono">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2 text-slate-200 text-xs font-bold uppercase">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  Subprocess Output Console
                </div>
                <span className="text-[10px] text-slate-500">Live subprocess logs</span>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800/80 text-xs text-slate-300 space-y-1.5 max-h-[220px] overflow-y-auto">
                {toolExecutionTracker.toolOutputLog.length === 0 ? (
                  <p className="text-slate-600">No output logs recorded yet.</p>
                ) : (
                  toolExecutionTracker.toolOutputLog.map((line, idx) => (
                    <div key={idx} className="leading-relaxed">
                      <span className="text-slate-500 mr-2">[{new Date().toLocaleTimeString()}]</span>
                      <span className={line.includes('[ERROR]') ? 'text-rose-400' : line.includes('[SUCCESS]') ? 'text-emerald-400' : 'text-slate-300'}>
                        {line}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </PageContainer>
  );
};
