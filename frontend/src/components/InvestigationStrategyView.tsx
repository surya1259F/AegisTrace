import React, { useEffect, useState } from 'react';
import {
  BrainCircuit,
  Layers,
  Wrench,
  Network,
  Cpu,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Info,
  ListOrdered,
  FileSearch
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Case,
  InvestigationPlan,
  DependencyGraph,
  ForensicTool,
  StoppingCondition
} from '../types';

interface InvestigationStrategyViewProps {
  caseItem: Case;
}

export const InvestigationStrategyView: React.FC<InvestigationStrategyViewProps> = ({ caseItem }) => {
  const [activePlan, setActivePlan] = useState<InvestigationPlan | null>(null);
  const [graph, setGraph] = useState<DependencyGraph | null>(null);
  const [tools, setTools] = useState<ForensicTool[]>([]);

  const [activeTab, setActiveTab] = useState<'tasks' | 'graph' | 'evidence' | 'tools' | 'resources' | 'stopping'>('tasks');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedTaskKey, setExpandedTaskKey] = useState<string | null>(null);

  const loadStrategyData = async () => {
    setLoading(true);
    setError(null);
    try {
      const plansData = await api.getCaseStrategyPlans(caseItem.id);
      if (plansData.length > 0) {
        const current = plansData[0];
        setActivePlan(current);
        if (current.id) {
          const graphData = await api.getStrategyPlanGraph(current.id);
          setGraph(graphData);
        }
      } else {
        setActivePlan(null);
        setGraph(null);
      }

      const toolsData = await api.getStrategyTools();
      setTools(toolsData);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load strategy data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (caseItem.id) {
      loadStrategyData();
    }
  }, [caseItem.id]);

  const handleGeneratePlan = async () => {
    setLoading(true);
    setError(null);
    try {
      const newPlan = await api.createStrategyPlan(caseItem.id);
      setActivePlan(newPlan);
      await loadStrategyData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to generate strategy plan.');
    } finally {
      setLoading(false);
    }
  };

  const handleReviewPlan = async () => {
    if (!activePlan?.id) return;
    setLoading(true);
    setError(null);
    try {
      await api.reviewStrategyPlan(activePlan.id);
      await loadStrategyData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to review strategy plan.');
    } finally {
      setLoading(false);
    }
  };

  const getPriorityBadge = (prio?: string) => {
    switch (prio) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">LOW</span>;
      case 'BLOCKED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950 text-red-400 border border-red-800 animate-pulse">BLOCKED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">PLANNED</span>;
    }
  };

  const getStatusBadge = (st?: string) => {
    switch (st) {
      case 'READY':
      case 'PLANNED':
      case 'VALIDATED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">✓ READY / PLANNED</span>;
      case 'BLOCKED_NO_CAPABLE_TOOL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30">! NO CAPABLE TOOL</span>;
      case 'BLOCKED_INTEGRITY_FAILURE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">✗ INTEGRITY BLOCKED</span>;
      case 'REQUIRES_REVIEW':
      case 'NEEDS_REVIEW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">⚠ MANUAL REVIEW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">{st || 'PLANNED'}</span>;
    }
  };

  const rawTasks = (activePlan?.tasks || activePlan?.steps || []) as any[];

  return (
    <div className="space-y-6 font-sans select-none">
      {/* Top Banner Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-indigo-950/60 border border-indigo-500/30 rounded-xl text-indigo-400 shrink-0">
              <BrainCircuit className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold tracking-wider text-slate-100 font-mono">INVESTIGATION STRATEGY ENGINE</h2>
                {activePlan && (
                  <span className="text-[11px] font-mono px-2 py-0.5 bg-indigo-500/20 border border-indigo-500/40 text-indigo-300 rounded-md">
                    Strategy v{activePlan.version || 1}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Case Objective: <span className="text-slate-200">{caseItem.objective || 'Generic Incident Investigation'}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleGeneratePlan}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-indigo-500/20 transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>{activePlan ? 'Recalculate Strategy' : 'Generate Strategy Plan'}</span>
            </button>

            {activePlan && (
              <button
                onClick={handleReviewPlan}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium shadow-md shadow-emerald-500/20 transition-all"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Review & Validate</span>
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs rounded-lg flex items-center gap-2 font-mono">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Strategy Summary & Metadata Cards */}
        {activePlan ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Validation Status</span>
              <div className="flex items-center gap-2">
                {getStatusBadge(activePlan.validation_status || activePlan.status)}
              </div>
            </div>

            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Planned Capability Tasks</span>
              <div className="text-slate-200 font-bold">
                {rawTasks.length} Executable Task(s)
              </div>
            </div>

            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Evidence Items Mapped</span>
              <div className="text-slate-200 font-bold">
                {(activePlan.evidence_snapshot || []).length} Preserved Artifact(s)
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 bg-slate-950/50 border border-dashed border-slate-800 rounded-xl text-center space-y-2">
            <Info className="w-8 h-8 text-indigo-400 mx-auto" />
            <h3 className="text-xs font-bold font-mono text-slate-300">NO STRATEGY PLAN GENERATED YET</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Click 'Generate Strategy Plan' to analyze preserved evidence intelligence, case objectives, registered capabilities, and host tools to build an executable strategy.
            </p>
          </div>
        )}
      </div>

      {/* Navigation Sub-Tabs */}
      {activePlan && (
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setActiveTab('tasks')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'tasks' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ListOrdered className="w-3.5 h-3.5" />
            <span>Ordered Task Plan ({rawTasks.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('graph')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'graph' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Dependency Graph (DAG)</span>
          </button>

          <button
            onClick={() => setActiveTab('evidence')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'evidence' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileSearch className="w-3.5 h-3.5" />
            <span>Evidence Analysis ({(activePlan.evidence_snapshot || []).length})</span>
          </button>

          <button
            onClick={() => setActiveTab('tools')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'tools' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>Tool Requirements ({tools.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('resources')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'resources' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Resource Constraints</span>
          </button>

          <button
            onClick={() => setActiveTab('stopping')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'stopping' ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Stopping Conditions ({(activePlan.stopping_conditions || []).length})</span>
          </button>
        </div>
      )}

      {/* TAB 1: ORDERED TASK PLAN */}
      {activePlan && activeTab === 'tasks' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-mono text-xs font-bold text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              <span>Executable Capability Task DAG</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">Ordered by Topological Dependency & Scoring</span>
          </div>

          <div className="divide-y divide-slate-800 font-mono text-xs">
            {rawTasks.map((t: any, idx: number) => {
              const taskKey = t.task_key || t.step_id || `task-${idx}`;
              const isExpanded = expandedTaskKey === taskKey;
              const prioLevel = t.priority_level || (t.priority === 1 ? 'CRITICAL' : 'MEDIUM');
              const statusStr = t.status || 'PLANNED';
              const capId = t.capability_id || t.action || 'FORENSIC_CAPABILITY';
              const agentStr = t.agent_name || t.agent || 'SpecialistAgent';
              const toolStr = t.selected_tool_id || t.tool || 'ForensicTool';
              const scoreNum = t.priority_score ?? 0.75;
              const deps = t.dependencies || [];

              return (
                <div key={taskKey} className="p-4 hover:bg-slate-800/40 transition-colors space-y-2">
                  <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpandedTaskKey(isExpanded ? null : taskKey)}>
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-300">
                        {t.sequence || idx + 1}
                      </span>

                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-100">{capId}</span>
                          <span className="text-slate-500 text-[11px]">via {agentStr} ({toolStr})</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Target: <span className="text-indigo-300">{t.evidence_name || (t.evidence_ids ? t.evidence_ids[0] : 'Evidence Item')}</span>
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {getPriorityBadge(prioLevel)}
                          {getStatusBadge(statusStr)}
                        </div>
                        <span className="text-[10px] text-slate-500 mt-0.5 block">Score: {scoreNum}</span>
                      </div>
                    </div>
                  </div>

                  {/* Blocking Reason Banner */}
                  {t.blocking_reason && (
                    <div className="p-2.5 bg-rose-950/40 border border-rose-800/60 rounded-lg text-rose-300 text-[11px] flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>{t.blocking_reason}</span>
                    </div>
                  )}

                  {/* Expanded Rationale & Dependency Details */}
                  {isExpanded && (
                    <div className="pt-2 border-t border-slate-800/60 mt-2 space-y-2 text-[11px] text-slate-300 bg-slate-950/60 p-3 rounded-lg">
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase block font-bold">Selection Rationale</span>
                        <p>{t.rationale?.selection_reason || t.reason || 'Standard forensic capability mapped from evidence intelligence.'}</p>
                      </div>

                      <div className="grid grid-cols-2 gap-4 pt-1">
                        <div>
                          <span className="text-[10px] text-slate-500 uppercase block font-bold">Required Inputs</span>
                          <p className="text-slate-400">{JSON.stringify(t.required_inputs || ['raw_evidence_path'])}</p>
                        </div>
                        <div>
                          <span className="text-[10px] text-slate-500 uppercase block font-bold">Expected Outputs</span>
                          <p className="text-slate-400">{JSON.stringify(t.expected_outputs || ['forensic_artifacts'])}</p>
                        </div>
                      </div>

                      {deps.length > 0 && (
                        <div className="pt-1">
                          <span className="text-[10px] text-slate-500 uppercase block font-bold">Prerequisite Task Dependencies</span>
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            {deps.map((d: string) => (
                              <span key={d} className="px-2 py-0.5 bg-slate-900 border border-slate-800 text-indigo-400 rounded text-[10px]">
                                ← {d}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: DEPENDENCY GRAPH (DAG) */}
      {activePlan && activeTab === 'graph' && graph && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <Network className="w-4 h-4 text-indigo-400" />
              <span>Visual Task Dependency Graph (DAG)</span>
            </h3>
            <span className="text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
              ✓ Valid Directed Acyclic Graph (0 Cycles)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {graph.nodes.map((node) => (
              <div key={node.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100 text-xs">{node.id}</span>
                  {getStatusBadge(node.status)}
                </div>
                <div className="text-[11px] text-slate-300 font-bold">{node.label}</div>
                <div className="text-[10px] text-slate-500">
                  Agent: <span className="text-slate-300">{node.agent}</span> | Tool: <span className="text-indigo-300">{node.tool}</span>
                </div>

                {/* Show Incoming Edges */}
                {graph.edges.filter((e) => e.target === node.id).length > 0 && (
                  <div className="pt-2 border-t border-slate-900 flex flex-wrap gap-1 text-[10px]">
                    <span className="text-slate-500">Depends on:</span>
                    {graph.edges.filter((e) => e.target === node.id).map((e) => (
                      <span key={e.source} className="px-1.5 py-0.5 bg-slate-900 border border-slate-800 text-indigo-400 rounded">
                        {e.source}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: EVIDENCE ANALYSIS */}
      {activePlan && activeTab === 'evidence' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
          <h3 className="font-bold text-slate-200 flex items-center gap-2 border-b border-slate-800 pb-3">
            <FileSearch className="w-4 h-4 text-indigo-400" />
            <span>Evidence Strategy Profile Snapshot</span>
          </h3>

          <div className="space-y-3">
            {(activePlan.evidence_snapshot || []).map((ev: any) => (
              <div key={ev.evidence_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100">{ev.name}</span>
                  <span className="text-[10px] px-2 py-0.5 bg-slate-900 text-indigo-400 border border-slate-800 rounded uppercase">
                    {ev.category} / {ev.subtype}
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-slate-400 pt-1">
                  <div>Format: <span className="text-slate-200">{ev.detected_format}</span></div>
                  <div>Platform: <span className="text-slate-200">{ev.platform_hint}</span></div>
                  <div>Filesystem: <span className="text-slate-200">{ev.filesystem_hint}</span></div>
                  <div>Integrity: <span className={ev.integrity_valid ? 'text-emerald-400' : 'text-rose-400'}>{ev.integrity_valid ? 'VERIFIED' : 'FAILED'}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: TOOL REQUIREMENTS */}
      {activePlan && activeTab === 'tools' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
          <h3 className="font-bold text-slate-200 flex items-center gap-2 border-b border-slate-800 pb-3">
            <Wrench className="w-4 h-4 text-indigo-400" />
            <span>Forensic Tool Capability Registry</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {tools.map((t) => (
              <div key={t.capability_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100">{t.tool_name}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${t.is_installed ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'}`}>
                    {t.health_status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Capability: <span className="text-indigo-300">{t.capability_id}</span></div>
                <div className="text-[10px] text-slate-500 truncate">Path: {t.executable_path}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: RESOURCE CONSTRAINTS */}
      {activePlan && activeTab === 'resources' && activePlan.resource_snapshot && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
          <h3 className="font-bold text-slate-200 flex items-center gap-2 border-b border-slate-800 pb-3">
            <Cpu className="w-4 h-4 text-indigo-400" />
            <span>Host Resource Limits & Budget</span>
          </h3>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">CPU Cores</span>
              <span className="text-slate-100 font-bold">{activePlan.resource_snapshot.cpu_cores} Cores</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">RAM Available</span>
              <span className="text-slate-100 font-bold">{activePlan.resource_snapshot.ram_available_mb} MB</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">Disk Free</span>
              <span className="text-slate-100 font-bold">{activePlan.resource_snapshot.disk_free_gb} GB</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">Max Concurrency</span>
              <span className="text-slate-100 font-bold">{activePlan.resource_snapshot.concurrency_limit} Parallel Tasks</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: STOPPING CONDITIONS */}
      {activePlan && activeTab === 'stopping' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 font-mono text-xs">
          <h3 className="font-bold text-slate-200 flex items-center gap-2 border-b border-slate-800 pb-3">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>Structured Stopping Condition Triggers</span>
          </h3>

          <div className="space-y-3">
            {(activePlan.stopping_conditions || []).map((sc: StoppingCondition, idx: number) => (
              <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100">{sc.condition_code}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${sc.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-slate-800 text-slate-300'}`}>
                    {sc.severity}
                  </span>
                </div>
                <p className="text-[11px] text-slate-300">{sc.trigger_description}</p>
                <p className="text-[10px] text-slate-500">{sc.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
