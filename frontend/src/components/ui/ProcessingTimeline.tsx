import * as React from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Pause,
  SkipForward,
  RefreshCw,
  ChevronRight,
  RotateCcw,
  Ban,
  Activity
} from "lucide-react";
import { cn } from "../../lib/utils";

export type ProcessingStatus =
  | "pending"
  | "queued"
  | "active"
  | "paused"
  | "completed"
  | "warning"
  | "failed"
  | "skipped"
  | "cancelled";

export interface ProcessingStage {
  id: string;
  label: string;
  description?: string;
  status: ProcessingStatus;
  progress?: number;
  startTime?: Date | number | string;
  endTime?: Date | number | string;
  duration?: number;
  attempt?: number;
  error?: string;
  warning?: string;
  output?: unknown;
  logs?: string[];
  metadata?: Record<string, string | number>;
  skippable?: boolean;
}

export interface ProcessingTimelineProps {
  stages: ProcessingStage[];
  title: string;
  subtitle?: string;
  jobStatus?: ProcessingStatus;
  currentStageId?: string;
  layout?: "vertical" | "horizontal";
  compact?: boolean;
  activeStageId?: string;
  onActiveStageChange?: (id: string) => void;
  onRetryStage?: (id: string) => void;
  onSkipStage?: (id: string) => void;
  onCancel?: () => void;
  onRestart?: () => void;
  className?: string;
}

const STATUS_CONFIG: Record<
  ProcessingStatus,
  { label: string; bg: string; text: string; border: string; icon: React.ElementType }
> = {
  pending: { label: "Pending", bg: "bg-slate-800/50", text: "text-slate-400", border: "border-slate-700", icon: Activity },
  queued: { label: "Queued", bg: "bg-slate-800/50", text: "text-slate-400", border: "border-slate-700", icon: Activity },
  active: { label: "Processing", bg: "bg-indigo-950/60", text: "text-indigo-400", border: "border-indigo-500/40", icon: RefreshCw },
  paused: { label: "Paused", bg: "bg-amber-950/60", text: "text-amber-400", border: "border-amber-500/40", icon: Pause },
  completed: { label: "Completed", bg: "bg-emerald-950/60", text: "text-emerald-400", border: "border-emerald-500/40", icon: CheckCircle2 },
  warning: { label: "Warning", bg: "bg-amber-950/60", text: "text-amber-400", border: "border-amber-500/40", icon: AlertTriangle },
  failed: { label: "Failed", bg: "bg-rose-950/60", text: "text-rose-400", border: "border-rose-500/40", icon: XCircle },
  skipped: { label: "Skipped", bg: "bg-slate-800/50", text: "text-slate-400", border: "border-slate-700", icon: SkipForward },
  cancelled: { label: "Cancelled", bg: "bg-rose-950/60", text: "text-rose-400", border: "border-rose-500/40", icon: Ban },
};

function formatDuration(ms?: number): string {
  if (!ms || ms < 0) return "";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s - m * 60)}s`;
}

export const ProcessingTimeline: React.FC<ProcessingTimelineProps> = ({
  stages,
  title,
  subtitle,
  jobStatus,
  currentStageId,
  activeStageId,
  onActiveStageChange,
  onRetryStage,
  onSkipStage,
  onCancel,
  onRestart,
  className = "",
}) => {
  const [, setSelectedId] = React.useState<string>(
    activeStageId || currentStageId || stages[0]?.id || ""
  );

  const [expandedSet, setExpandedSet] = React.useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    setExpandedSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setSelectedId(id);
    onActiveStageChange?.(id);
  };

  const resolvedCount = stages.filter((s) =>
    ["completed", "warning", "failed", "skipped", "cancelled"].includes(s.status)
  ).length;

  const totalStages = stages.length;
  const overallPct = totalStages > 0 ? Math.round((resolvedCount / totalStages) * 100) : 0;

  return (
    <section className={cn("w-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl font-sans text-slate-100", className)}>
      <header className="p-5 bg-slate-950/70 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-600/20 border border-indigo-500/30 rounded-lg text-indigo-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-sm tracking-wider font-mono text-slate-100">{title}</h3>
              {jobStatus && (
                <span className={cn("px-2 py-0.5 text-[10px] font-mono rounded font-semibold border", STATUS_CONFIG[jobStatus].bg, STATUS_CONFIG[jobStatus].text, STATUS_CONFIG[jobStatus].border)}>
                  {STATUS_CONFIG[jobStatus].label}
                </span>
              )}
            </div>
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {onRestart && (
            <button
              onClick={onRestart}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Restart Pipeline
            </button>
          )}
          {onCancel && (
            <button
              onClick={onCancel}
              className="px-3 py-1.5 bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 text-xs font-mono rounded-lg border border-rose-800/60 flex items-center gap-1.5 transition-colors"
            >
              <Ban className="w-3.5 h-3.5" /> Abort
            </button>
          )}
        </div>

        <div className="w-full mt-2">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
            <span>Progress ({resolvedCount}/{totalStages} Stages)</span>
            <span>{overallPct}%</span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-indigo-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${overallPct}%` }}
            />
          </div>
        </div>
      </header>

      <ol className="p-4 space-y-3">
        {stages.map((stage, idx) => {
          const cfg = STATUS_CONFIG[stage.status];
          const StatusIcon = cfg.icon;
          const isExpanded = expandedSet.has(stage.id);
          const isCurrent = stage.id === currentStageId;

          return (
            <motion.li
              key={stage.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn(
                "p-3.5 bg-slate-950/40 border rounded-xl transition-all duration-200",
                isCurrent ? "border-indigo-500/60 shadow-lg shadow-indigo-500/10" : "border-slate-800 hover:border-slate-700"
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <div 
                  onClick={() => toggleExpand(stage.id)}
                  className="flex items-center gap-3 cursor-pointer flex-1 select-none"
                >
                  <div className={cn("p-2 rounded-lg border flex items-center justify-center", cfg.bg, cfg.text, cfg.border)}>
                    <StatusIcon className={cn("w-4 h-4", stage.status === "active" && "animate-spin")} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-500 font-bold">0{idx + 1}</span>
                      <h4 className="text-xs font-bold text-slate-200">{stage.label}</h4>
                      {isCurrent && (
                        <span className="px-1.5 py-0.2 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 text-[9px] font-mono font-bold rounded">
                          ACTIVE STEP
                        </span>
                      )}
                    </div>
                    {stage.description && <p className="text-[11px] text-slate-400 mt-0.5">{stage.description}</p>}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className={cn("px-2 py-0.5 text-[10px] font-mono rounded font-semibold border", cfg.bg, cfg.text, cfg.border)}>
                    {cfg.label}
                  </span>
                  {stage.status === "failed" && onRetryStage && (
                    <button
                      onClick={() => onRetryStage(stage.id)}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-mono rounded border border-slate-700 flex items-center gap-1"
                    >
                      <RotateCcw className="w-3 h-3" /> Retry
                    </button>
                  )}
                  {stage.skippable && onSkipStage && stage.status !== "completed" && (
                    <button
                      onClick={() => onSkipStage(stage.id)}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono rounded border border-slate-700 flex items-center gap-1"
                    >
                      <SkipForward className="w-3 h-3" /> Skip
                    </button>
                  )}
                  <button
                    onClick={() => toggleExpand(stage.id)}
                    className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    <ChevronRight className={cn("w-4 h-4 transition-transform duration-200", isExpanded && "rotate-90")} />
                  </button>
                </div>
              </div>

              {stage.status === "active" && typeof stage.progress === "number" && (
                <div className="mt-3 pt-2 border-t border-slate-800/60">
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                    <span>Stage Execution</span>
                    <span>{stage.progress}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-indigo-400 h-1.5 rounded-full transition-all duration-300"
                      style={{ width: `${stage.progress}%` }}
                    />
                  </div>
                </div>
              )}

              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="mt-3 pt-3 border-t border-slate-800 space-y-2 text-xs"
                  >
                    {stage.duration && (
                      <p className="text-[11px] font-mono text-slate-400">Duration: {formatDuration(stage.duration)}</p>
                    )}
                    {stage.error && (
                      <div className="p-2.5 bg-rose-950/40 border border-rose-800/50 rounded-lg text-rose-300 font-mono text-[11px]">
                        <strong>Error:</strong> {stage.error}
                      </div>
                    )}
                    {stage.logs && stage.logs.length > 0 && (
                      <div>
                        <span className="text-[10px] font-mono text-slate-400 uppercase font-bold block mb-1">Execution Console Logs</span>
                        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1 max-h-40 overflow-y-auto">
                          {stage.logs.map((log, i) => (
                            <div key={i} className="leading-relaxed truncate">• {log}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.li>
          );
        })}
      </ol>
    </section>
  );
};

export default ProcessingTimeline;
