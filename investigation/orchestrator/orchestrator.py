import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from backend.app.core.database import SessionLocal
from backend.app.models.models import (
    Case,
    EvidenceItem,
    InvestigationPlan,
    ToolExecution,
    ExecutionArtifact,
    Finding,
)
from backend.app.services.vault import validate_vault_storage_path
from backend.app.services.integrity import calculate_sha256
from backend.app.services.custody import record_custody_event
from backend.app.services.audit import log_audit_event
from agents.disk.disk_agent import DiskAgent
from agents.memory.memory_agent import MemoryAgent
from agents.malware.malware_agent import MalwareAgent
from agents.log.log_agent import LogAgent
from investigation.planner.planner import InvestigationPlanner
from investigation.scheduler.scheduler import TaskScheduler


class InvestigationOrchestrator:
    """
    Autonomous Investigation Orchestrator.
    Executes an InvestigationPlan deterministically against real evidence in the evidence vault,
    routed through the resource-aware TaskScheduler.
    Enforces pre- and post-analysis cryptographic integrity gates, truthful tool execution tracking,
    dependency ordering, resource reservation/release, bounded parallel execution, and structured artifact/finding persistence.
    """

    def __init__(
        self,
        disk_agent: Optional[DiskAgent] = None,
        memory_agent: Optional[MemoryAgent] = None,
        malware_agent: Optional[MalwareAgent] = None,
        log_agent: Optional[LogAgent] = None,
        planner: Optional[InvestigationPlanner] = None,
        task_scheduler: Optional[TaskScheduler] = None,
    ):
        self.disk_agent = disk_agent or DiskAgent()
        self.memory_agent = memory_agent or MemoryAgent()
        self.malware_agent = malware_agent or MalwareAgent()
        self.log_agent = log_agent or LogAgent()
        self.planner = planner or InvestigationPlanner()
        self.task_scheduler = task_scheduler or TaskScheduler()

    def get_plan_status(self, case_id: str, db: Session) -> Optional[Dict[str, Any]]:
        """
        Retrieves the active investigation plan and task execution statuses.
        """
        plan = (
            db.query(InvestigationPlan)
            .filter(InvestigationPlan.case_id == case_id, InvestigationPlan.is_active == True)
            .order_by(InvestigationPlan.created_at.desc())
            .first()
        )
        if not plan:
            return None

        return {
            "plan_id": plan.id,
            "case_id": plan.case_id,
            "status": plan.status,
            "strategy_summary": plan.strategy_summary,
            "tasks": plan.tasks or [],
            "version": plan.version,
            "created_at": plan.created_at,
            "completed_at": plan.completed_at,
        }

    def _execute_single_task(
        self, case_id: str, plan_id: str, task: Dict[str, Any], db: Session
    ) -> Dict[str, Any]:
        """
        Executes a single scheduled task through pre/post integrity gates and forensic specialist agents.
        """
        step_id = task["step_id"]

        # Tool availability check
        if not task.get("tool_available", True):
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": f"Forensic tool '{task.get('tool')}' is not available on this platform.",
            }

        evidence_id = task.get("evidence_id")
        if not evidence_id:
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": "Task has no associated evidence ID.",
            }

        evidence = (
            db.query(EvidenceItem)
            .filter(EvidenceItem.id == evidence_id, EvidenceItem.case_id == case_id)
            .first()
        )
        if not evidence:
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": f"Evidence '{evidence_id}' not found for case.",
            }

        # Mandatory Pre-Analysis Integrity Gate
        is_valid_vault, err_msg = validate_vault_storage_path(
            evidence.storage_path, evidence.original_path
        )
        if not is_valid_vault:
            evidence.integrity_status = "FAILED"
            record_custody_event(
                db=db,
                case_id=case_id,
                evidence_id=evidence.id,
                event_type="INTEGRITY_VIOLATION",
                description=f"Pre-analysis gate failed: {err_msg}",
                source_path=evidence.original_path,
                destination_path=evidence.storage_path,
            )
            log_audit_event(
                db=db,
                case_id=case_id,
                event_type="EVIDENCE_INTEGRITY_VIOLATION",
                details=f"Pre-analysis vault gate failed for '{evidence.name}': {err_msg}",
            )
            db.commit()
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": f"Pre-analysis vault check failed: {err_msg}",
            }

        target_path = str(Path(evidence.storage_path).resolve())
        try:
            current_hash, _ = calculate_sha256(target_path)
        except Exception as e:
            evidence.integrity_status = "FAILED"
            db.commit()
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": f"Pre-analysis hashing failed: {str(e)}",
            }

        if current_hash.lower() != evidence.sha256.lower():
            evidence.integrity_status = "FAILED"
            record_custody_event(
                db=db,
                case_id=case_id,
                evidence_id=evidence.id,
                event_type="INTEGRITY_VIOLATION",
                description=f"Pre-analysis hash mismatch. Baseline: {evidence.sha256}, Actual: {current_hash}",
                source_path=evidence.original_path,
                destination_path=evidence.storage_path,
                sha256=current_hash,
            )
            log_audit_event(
                db=db,
                case_id=case_id,
                event_type="EVIDENCE_INTEGRITY_VIOLATION",
                details=f"Pre-analysis hash mismatch for '{evidence.name}' (ID {evidence.id}). Baseline: {evidence.sha256}, Actual: {current_hash}.",
            )
            db.commit()
            return {
                "status": "FAILED",
                "execution_id": None,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": f"Pre-analysis hash mismatch. Baseline: {evidence.sha256}, Actual: {current_hash}",
            }

        record_custody_event(
            db=db,
            case_id=case_id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VERIFIED_PRE_ANALYSIS",
            description=f"Pre-analysis cryptographic integrity verified for '{evidence.name}' (SHA-256: {current_hash}).",
            destination_path=target_path,
            sha256=current_hash,
        )

        # Create ToolExecution with truthful tool_id and command_args
        tool_name_raw = str(task.get("tool", "")).strip()
        action_str = str(task.get("action", "")).strip()
        params = dict(task.get("parameters", {}))
        timeout_val = params.get("timeout_seconds", 300)

        if tool_name_raw.lower() in ["sleuthkit", "tsk"]:
            exec_tool_id = "sleuthkit_fls"
            command_args = ["fls", "-r", "-p", target_path]
        elif tool_name_raw.lower() == "exiftool":
            exec_tool_id = "exiftool"
            command_args = ["exiftool", "-j", target_path]
        elif tool_name_raw.lower() in ["volatility3", "volatility"]:
            exec_tool_id = "volatility3"
            plugin_name = params.get("plugin", "windows.pslist")
            command_args = ["vol", "-f", target_path, plugin_name]
        elif tool_name_raw.lower() == "yara":
            exec_tool_id = "yara"
            rule_name = params.get("rule_set") or params.get("rule_id", "adfir_webshell_indicators")
            command_args = ["yara", rule_name, target_path]
        elif tool_name_raw.lower() in ["python-evtx", "python_evtx"]:
            exec_tool_id = "python_evtx"
            max_rec = params.get("max_records", 5000)
            command_args = ["python-evtx", target_path, str(max_rec)]
        else:
            exec_tool_id = f"{tool_name_raw.lower()}_{action_str}"
            command_args = [action_str, target_path]

        execution = ToolExecution(
            case_id=case_id,
            evidence_id=evidence.id,
            tool_id=exec_tool_id,
            command_args=command_args,
            status="RUNNING",
            timeout_seconds=timeout_val,
            started_at=datetime.now(timezone.utc),
            operator_id="autonomous-orchestrator",
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="TOOL_EXECUTION_STARTED",
            details=f"Started autonomous execution of {task.get('agent')} ({task.get('tool')}) for task '{step_id}' on evidence '{evidence.name}'.",
        )

        ev_dict = {
            "id": evidence.id,
            "investigation_id": case_id,
            "name": evidence.name,
            "original_path": evidence.original_path,
            "storage_path": target_path,
            "evidence_type": evidence.evidence_type,
            "sha256": evidence.sha256,
        }
        agent_type = task.get("agent")

        tool_exc = None
        res = None
        try:
            if agent_type == "DiskAgent":
                disk_params = {
                    "action": action_str,
                    "tool": tool_name_raw,
                    "recursive": params.get("recursive", True),
                    "include_deleted": params.get("include_deleted", True),
                    "offset_sectors": params.get("offset_sectors", 0),
                    "timeout_seconds": timeout_val,
                    "execution_id": execution.id,
                }
                res = self.disk_agent.analyze(
                    evidence_item=ev_dict,
                    parameters=disk_params,
                )
            elif agent_type == "MemoryAgent":
                mem_params = {
                    "action": action_str,
                    "plugin": params.get("plugin", "windows.pslist"),
                    "timeout_seconds": timeout_val,
                    "execution_id": execution.id,
                }
                mem_params.update(params)
                res = self.memory_agent.analyze(
                    evidence_item=ev_dict,
                    parameters=mem_params,
                )
            elif agent_type == "MalwareAgent":
                mal_params = {
                    "action": action_str,
                    "rule_id": params.get("rule_set") or params.get("rule_id", "adfir_webshell_indicators"),
                    "timeout_seconds": timeout_val,
                    "execution_id": execution.id,
                }
                mal_params.update(params)
                res = self.malware_agent.analyze(
                    evidence_item=ev_dict,
                    parameters=mal_params,
                )
            elif agent_type == "LogAgent":
                log_params = {
                    "action": action_str,
                    "max_records": params.get("max_records", 5000),
                    "timeout_seconds": timeout_val,
                    "execution_id": execution.id,
                }
                log_params.update(params)
                res = self.log_agent.analyze(
                    evidence_item=ev_dict,
                    parameters=log_params,
                )
            else:
                raise ValueError(f"Unknown agent type: {agent_type}")

            # Ensure planned tool and actual executed tool did not silently diverge
            if isinstance(res, dict) and res.get("status") == "SUCCESS":
                executed_tool = (res.get("provenance") or {}).get("tool")
                if executed_tool and executed_tool.lower() != tool_name_raw.lower():
                    raise RuntimeError(
                        f"Forensic tool divergence detected: Task planned tool '{tool_name_raw}' but executed '{executed_tool}'."
                    )
        except Exception as e:
            tool_exc = e

        # Extract execution telemetry from provenance or result
        prov = (res.get("provenance") or {}) if isinstance(res, dict) else {}
        pid_val = prov.get("pid") or (res.get("pid") if isinstance(res, dict) else None)
        if pid_val:
            execution.pid = pid_val
        proc_start_time = prov.get("process_start_time") or (res.get("process_start_time") if isinstance(res, dict) else None)
        if proc_start_time is not None:
            execution.process_start_time = proc_start_time

        return_code = prov.get("return_code") if prov.get("return_code") is not None else (res.get("return_code") if isinstance(res, dict) else None)
        if return_code is not None:
            execution.exit_code = return_code

        raw_ref = prov.get("raw_output_reference") or (res.get("raw_output_reference") if isinstance(res, dict) else None)
        if raw_ref:
            execution.stdout_path = raw_ref
            execution.stderr_path = f"{raw_ref}.stderr"

        # Mandatory Post-Analysis Cryptographic Integrity Gate
        post_hash, _ = calculate_sha256(target_path)
        if post_hash.lower() != evidence.sha256.lower():
            evidence.integrity_status = "FAILED"
            execution.status = "FAILED"
            execution.error_message = (
                "Post-analysis integrity check failed: Evidence modified during tool execution."
            )
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()

            record_custody_event(
                db=db,
                case_id=case_id,
                evidence_id=evidence.id,
                event_type="INTEGRITY_VIOLATION",
                description=f"CRITICAL: Post-analysis tampering detected! Hash changed from {evidence.sha256} to {post_hash} during tool execution.",
                destination_path=target_path,
                sha256=post_hash,
            )
            log_audit_event(
                db=db,
                case_id=case_id,
                event_type="EVIDENCE_INTEGRITY_VIOLATION",
                details=f"Post-analysis hash mismatch for evidence '{evidence.name}' (ID {evidence.id}). Baseline: {evidence.sha256}, Post-Execution: {post_hash}.",
            )
            raise RuntimeError(
                f"CRITICAL: Evidence was modified during analysis! Baseline: {evidence.sha256}, Post-Execution: {post_hash}."
            )

        record_custody_event(
            db=db,
            case_id=case_id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VERIFIED_POST_ANALYSIS",
            description=f"Post-analysis cryptographic integrity confirmed for '{evidence.name}' (SHA-256: {post_hash}). Zero bytes altered.",
            destination_path=target_path,
            sha256=post_hash,
        )

        # Handle Timeout status
        if isinstance(res, dict) and res.get("status") == "TIMED_OUT":
            execution.status = "TIMED_OUT"
            execution.error_message = res.get("error") or f"Tool execution timed out after {timeout_val} seconds."
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()

            log_audit_event(
                db=db,
                case_id=case_id,
                event_type="TOOL_EXECUTION_TIMED_OUT",
                details=f"Task '{step_id}' timed out after {timeout_val} seconds.",
            )
            return {
                "status": "TIMED_OUT",
                "execution_id": execution.id,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": execution.error_message,
            }

        # Handle Cancelled status
        if isinstance(res, dict) and res.get("status") == "CANCELLED":
            execution.status = "CANCELLED"
            execution.cancelled_at = datetime.now(timezone.utc)
            execution.cancelled_by = "investigator"
            execution.error_message = res.get("error") or "Tool execution was cancelled."
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()

            log_audit_event(
                db=db,
                case_id=case_id,
                event_type="TOOL_EXECUTION_CANCELLED",
                details=f"Task '{step_id}' was cancelled during execution.",
            )
            return {
                "status": "CANCELLED",
                "execution_id": execution.id,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": execution.error_message,
            }

        # Tool exception handling
        if tool_exc is not None:
            execution.status = "FAILED"
            execution.error_message = str(tool_exc)
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {
                "status": "FAILED",
                "execution_id": execution.id,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": str(tool_exc),
            }

        # Agent response status handling
        if not isinstance(res, dict) or res.get("status") not in ["SUCCESS", "COMPLETED"]:
            err = (res.get("error") if isinstance(res, dict) else None) or f"Agent analysis reported non-success status: {res.get('status') if isinstance(res, dict) else 'Unknown'}"
            execution.status = "FAILED"
            execution.error_message = err
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {
                "status": "FAILED",
                "execution_id": execution.id,
                "artifacts_count": 0,
                "findings_count": 0,
                "error_message": err,
            }

        # Persist real artifacts
        artifact_objs: List[ExecutionArtifact] = []
        for art in res.get("artifacts", []):
            artifact_db = ExecutionArtifact(
                case_id=case_id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                agent=task["agent"],
                tool=task["tool"],
                artifact_type=art.get("artifact_type", "generic_artifact"),
                source_reference=art.get("source_reference", f"{task['tool']}:artifact"),
                path=art.get("path"),
                inode=art.get("inode"),
                size_bytes=art.get("size_bytes"),
                is_deleted=art.get("is_deleted", False),
                metadata_json=art.get("metadata_json", {}),
                raw_output_reference=res.get("raw_output_reference"),
            )
            db.add(artifact_db)
            artifact_objs.append(artifact_db)

        db.flush()

        # Persist real findings
        finding_objs: List[Finding] = []
        for find in res.get("findings", []):
            find_db = Finding(
                case_id=case_id,
                evidence_id=evidence.id,
                execution_id=execution.id,
                artifact_id=artifact_objs[0].id if artifact_objs else None,
                agent=task["agent"],
                tool=task["tool"],
                finding_type=find.get("finding_type", "forensic_finding"),
                title=find.get("title", f"{task['tool']} Finding"),
                description=find.get("description", ""),
                severity=find.get("severity", "MEDIUM"),
                classification="FACT",
                confidence=find.get("confidence", 0.9),
                timestamp=datetime.now(timezone.utc),
                evidence_reference=find.get("evidence_reference"),
                verification_status="UNVERIFIED",
                raw_output_reference=res.get("raw_output_reference"),
            )
            db.add(find_db)
            finding_objs.append(find_db)

        execution.status = "COMPLETED"
        execution.completed_at = datetime.now(timezone.utc)
        db.commit()

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="TOOL_EXECUTION_COMPLETED",
            details=f"Task '{step_id}' completed successfully: {len(artifact_objs)} artifact(s), {len(finding_objs)} finding(s) persisted.",
        )

        return {
            "status": "COMPLETED",
            "execution_id": execution.id,
            "artifacts_count": len(artifact_objs),
            "findings_count": len(finding_objs),
            "error_message": None,
        }

    def execute_plan(
        self, case_id: str, db: Session, plan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes an investigation plan through the resource-aware TaskScheduler.
        Supports bounded concurrent execution when multiple parallel-safe tasks are admitted.
        """
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        # 1. Retrieve or generate active plan
        if plan_id:
            plan = (
                db.query(InvestigationPlan)
                .filter(InvestigationPlan.id == plan_id, InvestigationPlan.case_id == case_id)
                .first()
            )
            if not plan:
                raise ValueError(f"Investigation plan '{plan_id}' not found for case '{case_id}'.")
        else:
            plan = (
                db.query(InvestigationPlan)
                .filter(InvestigationPlan.case_id == case_id, InvestigationPlan.is_active == True)
                .order_by(InvestigationPlan.created_at.desc())
                .first()
            )

        if not plan:
            evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case_id).all()
            ev_dicts = [
                {
                    "id": e.id,
                    "name": e.name,
                    "evidence_type": e.evidence_type,
                    "size_bytes": e.size_bytes,
                }
                for e in evidence_items
            ]
            plan_data = self.planner.plan(investigation_id=case_id, evidence_items=ev_dicts)
            plan = InvestigationPlan(
                id=str(uuid.uuid4()),
                case_id=case_id,
                title=f"Autonomous Plan for Case {case.case_number}",
                strategy_summary=plan_data.get("strategy_summary"),
                tasks=plan_data.get("tasks", []),
                status="PLANNED",
                version=1,
                is_active=True,
            )
            db.add(plan)
            db.commit()
            db.refresh(plan)

        raw_tasks: List[Dict[str, Any]] = [dict(t) for t in (plan.tasks or [])]
        tasks: List[Dict[str, Any]] = []
        for t in raw_tasks:
            task_norm = dict(t)
            s_id = str(task_norm.get("step_id") or task_norm.get("task_key") or task_norm.get("task_id") or "")
            task_norm["step_id"] = s_id
            task_norm["task_id"] = s_id
            task_norm["task_key"] = s_id

            if not task_norm.get("evidence_id"):
                ev_ids = task_norm.get("evidence_ids")
                if isinstance(ev_ids, list) and len(ev_ids) > 0:
                    task_norm["evidence_id"] = ev_ids[0]

            if not task_norm.get("tool"):
                task_norm["tool"] = task_norm.get("selected_tool_id") or task_norm.get("tool_name") or ""

            if not task_norm.get("action"):
                task_norm["action"] = task_norm.get("capability_id") or ""

            if not task_norm.get("agent"):
                task_norm["agent"] = task_norm.get("agent_name") or ""

            if "parameters" not in task_norm or not isinstance(task_norm["parameters"], dict):
                task_norm["parameters"] = {}

            if "tool_available" not in task_norm:
                task_norm["tool_available"] = True

            tasks.append(task_norm)

        if not tasks:
            plan.status = "COMPLETED"
            plan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {
                "investigation_id": case_id,
                "plan_id": plan.id,
                "status": "COMPLETED",
                "tasks_executed": 0,
                "tasks_succeeded": 0,
                "tasks_failed": 0,
                "total_artifacts": 0,
                "total_findings": 0,
                "tasks": [],
            }

        plan.status = "RUNNING"
        db.commit()

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="PLAN_EXECUTION_STARTED",
            details=f"Autonomous orchestrator started executing plan '{plan.id}' with {len(tasks)} task(s).",
        )

        # Register tasks into task scheduler
        self.task_scheduler.register_plan(tasks)

        # Scheduler-driven execution loop
        while True:
            admitted_tasks = self.task_scheduler.admit_next_tasks(max_batch=4)
            if not admitted_tasks:
                runnable_tasks = self.task_scheduler.get_runnable_tasks()
                if not runnable_tasks:
                    break
                break

            if len(admitted_tasks) == 1:
                t_item = admitted_tasks[0]
                step_id = t_item["task_id"]
                matching_task = next((t for t in tasks if t["step_id"] == step_id), None)
                if not matching_task:
                    continue

                self.task_scheduler.mark_task_running(step_id)
                matching_task["status"] = "RUNNING"
                matching_task["started_at"] = datetime.now(timezone.utc).isoformat()
                plan.tasks = list(tasks)
                flag_modified(plan, "tasks")
                db.commit()

                try:
                    res = self._execute_single_task(case_id=case_id, plan_id=plan.id, task=matching_task, db=db)
                    if res["status"] == "COMPLETED":
                        self.task_scheduler.mark_task_completed(step_id, res["artifacts_count"], res["findings_count"])
                        matching_task["status"] = "COMPLETED"
                        matching_task["execution_id"] = res["execution_id"]
                        matching_task["artifacts_count"] = res["artifacts_count"]
                        matching_task["findings_count"] = res["findings_count"]
                        matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                        matching_task["error_message"] = None
                    elif res["status"] == "TIMED_OUT":
                        self.task_scheduler.mark_task_timed_out(step_id, res["error_message"])
                        matching_task["status"] = "TIMED_OUT"
                        matching_task["execution_id"] = res["execution_id"]
                        matching_task["error_message"] = res["error_message"]
                        matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                    elif res["status"] == "CANCELLED":
                        self.task_scheduler.mark_task_cancelled(step_id, res["error_message"])
                        matching_task["status"] = "CANCELLED"
                        matching_task["execution_id"] = res["execution_id"]
                        matching_task["error_message"] = res["error_message"]
                        matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                    else:
                        self.task_scheduler.mark_task_failed(step_id, res["error_message"])
                        matching_task["status"] = "FAILED"
                        matching_task["error_message"] = res["error_message"]
                        matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                except Exception as e:
                    self.task_scheduler.mark_task_failed(step_id, str(e))
                    matching_task["status"] = "FAILED"
                    matching_task["error_message"] = str(e)
                    matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                    if "CRITICAL: Evidence was modified during analysis" in str(e):
                        plan.tasks = list(tasks)
                        flag_modified(plan, "tasks")
                        db.commit()
                        raise

                plan.tasks = list(tasks)
                flag_modified(plan, "tasks")
                db.commit()

            else:
                # Bounded parallel execution for multiple admitted parallel-safe tasks
                def _run_task_in_thread(t_item: Dict[str, Any]) -> Dict[str, Any]:
                    step_id = t_item["task_id"]
                    matching_task = next((t for t in tasks if t["step_id"] == step_id), None)
                    if not matching_task:
                        return {"status": "FAILED", "step_id": step_id, "error": "Task not found"}

                    self.task_scheduler.mark_task_running(step_id)
                    with SessionLocal() as thread_db:
                        try:
                            res = self._execute_single_task(case_id=case_id, plan_id=plan.id, task=matching_task, db=thread_db)
                            if res["status"] == "COMPLETED":
                                self.task_scheduler.mark_task_completed(step_id, res["artifacts_count"], res["findings_count"])
                                return {"status": "COMPLETED", "step_id": step_id, "res": res}
                            elif res["status"] in ["TIMED_OUT", "CANCELLED"]:
                                if res["status"] == "TIMED_OUT":
                                    self.task_scheduler.mark_task_timed_out(step_id, res["error_message"])
                                else:
                                    self.task_scheduler.mark_task_cancelled(step_id, res["error_message"])
                                return {"status": res["status"], "step_id": step_id, "res": res}
                            else:
                                self.task_scheduler.mark_task_failed(step_id, res["error_message"])
                                return {"status": "FAILED", "step_id": step_id, "error": res["error_message"]}
                        except Exception as e:
                            self.task_scheduler.mark_task_failed(step_id, str(e))
                            return {"status": "FAILED", "step_id": step_id, "error": str(e)}

                with ThreadPoolExecutor(max_workers=len(admitted_tasks)) as executor:
                    results = list(executor.map(_run_task_in_thread, admitted_tasks))

                for r in results:
                    step_id = r["step_id"]
                    matching_task = next((t for t in tasks if t["step_id"] == step_id), None)
                    if matching_task:
                        if r["status"] == "COMPLETED":
                            res_data = r["res"]
                            matching_task["status"] = "COMPLETED"
                            matching_task["execution_id"] = res_data["execution_id"]
                            matching_task["artifacts_count"] = res_data["artifacts_count"]
                            matching_task["findings_count"] = res_data["findings_count"]
                            matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                            matching_task["error_message"] = None
                        elif r["status"] in ["TIMED_OUT", "CANCELLED"]:
                            res_data = r["res"]
                            matching_task["status"] = r["status"]
                            matching_task["execution_id"] = res_data["execution_id"]
                            matching_task["error_message"] = res_data["error_message"]
                            matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()
                        else:
                            matching_task["status"] = "FAILED"
                            matching_task["error_message"] = r.get("error")
                            matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()

                plan.tasks = list(tasks)
                flag_modified(plan, "tasks")
                db.commit()

        # Update remaining tasks cancelled if dependencies failed
        for t_item in self.task_scheduler.tasks.values():
            if t_item.get("status") in ["CANCELLED", "BLOCKED"]:
                step_id = t_item["step_id"]
                matching_task = next((t for t in tasks if t["step_id"] == step_id), None)
                if matching_task and matching_task.get("status") != "COMPLETED":
                    matching_task["status"] = "CANCELLED"
                    matching_task["error_message"] = t_item.get("error_message") or "Dependency not satisfied."

        # Final Plan Status
        tasks_succeeded = sum(1 for t in tasks if t.get("status") == "COMPLETED")
        tasks_failed = sum(1 for t in tasks if t.get("status") in ["FAILED", "CANCELLED", "TIMED_OUT"])
        tasks_executed = tasks_succeeded + sum(1 for t in tasks if t.get("status") in ["FAILED", "CANCELLED", "TIMED_OUT"])
        total_artifacts = sum(t.get("artifacts_count", 0) for t in tasks)
        total_findings = sum(t.get("findings_count", 0) for t in tasks)

        if tasks_succeeded == len(tasks) and len(tasks) > 0:
            final_status = "COMPLETED"
        elif tasks_succeeded > 0:
            final_status = "PARTIALLY_COMPLETED"
        elif len(tasks) == 0:
            final_status = "COMPLETED"
        else:
            final_status = "FAILED"

        plan.status = final_status
        plan.completed_at = datetime.now(timezone.utc)
        plan.tasks = list(tasks)
        flag_modified(plan, "tasks")
        db.commit()

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="PLAN_EXECUTION_COMPLETED",
            details=f"Autonomous plan execution completed with status '{final_status}'. ({tasks_succeeded}/{len(tasks)} succeeded).",
        )

        return {
            "investigation_id": case_id,
            "plan_id": plan.id,
            "status": final_status,
            "tasks_executed": tasks_executed,
            "tasks_succeeded": tasks_succeeded,
            "tasks_failed": tasks_failed,
            "total_artifacts": total_artifacts,
            "total_findings": total_findings,
            "tasks": tasks,
        }

    def cancel_task(
        self, case_id: str, task_id: str, db: Session, cancelled_by: str = "investigator"
    ) -> Dict[str, Any]:
        """
        Cancels a scheduled or active task by ID, terminating active subprocesses,
        marking dependent tasks CANCELLED, and releasing scheduler resources.
        """
        plan = (
            db.query(InvestigationPlan)
            .filter(InvestigationPlan.case_id == case_id, InvestigationPlan.is_active == True)
            .order_by(InvestigationPlan.created_at.desc())
            .first()
        )
        tasks: List[Dict[str, Any]] = [dict(t) for t in (plan.tasks or [])] if plan else []
        matching_task = next((t for t in tasks if t.get("step_id") == task_id or t.get("task_id") == task_id), None)

        if not matching_task and not plan:
            raise ValueError(f"No active plan or task '{task_id}' found for case '{case_id}'.")

        if matching_task and matching_task.get("status") == "COMPLETED":
            return {
                "case_id": case_id,
                "task_id": task_id,
                "status": "COMPLETED",
                "message": "Task has already completed and cannot be cancelled.",
                "execution_id": matching_task.get("execution_id"),
            }

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="TOOL_EXECUTION_CANCELLATION_REQUESTED",
            details=f"Cancellation requested for task '{task_id}' by '{cancelled_by}'.",
        )

        execution = None
        if matching_task and matching_task.get("execution_id"):
            execution = db.query(ToolExecution).filter(ToolExecution.id == matching_task["execution_id"]).first()

        if not execution:
            execution = (
                db.query(ToolExecution)
                .filter(ToolExecution.case_id == case_id, ToolExecution.status == "RUNNING")
                .first()
            )

        is_terminated = True
        proc_cancelled = False
        if execution and execution.status == "RUNNING":
            if execution.pid is None:
                proc_cancelled = True
            else:
                from forensic_tools.registry import tool_registry
                proc_cancelled = tool_registry.cancel_execution_process(execution.id)

            if proc_cancelled:
                execution.status = "CANCELLED"
                execution.cancelled_at = datetime.now(timezone.utc)
                execution.cancelled_by = cancelled_by
                execution.completed_at = datetime.now(timezone.utc)
                execution.error_message = f"Cancelled by {cancelled_by} request."
                db.commit()
            elif execution.pid is not None:
                try:
                    import os
                    os.kill(execution.pid, 0)
                    is_terminated = False
                except (OSError, ProcessLookupError):
                    is_terminated = True
                    execution.status = "CANCELLED"
                    execution.cancelled_at = datetime.now(timezone.utc)
                    execution.cancelled_by = cancelled_by
                    execution.completed_at = datetime.now(timezone.utc)
                    execution.error_message = f"Cancelled by {cancelled_by} request (process no longer active)."
                    db.commit()

        reason_text = (
            f"Cancelled by {cancelled_by} request."
            if is_terminated
            else f"Cancellation requested by {cancelled_by}, but process identity could not be verified for termination; process remains active."
        )
        self.task_scheduler.mark_task_cancelled(
            task_id, reason=reason_text, process_terminated=is_terminated
        )

        if matching_task:
            matching_task["status"] = "CANCELLED"
            matching_task["error_message"] = reason_text
            matching_task["completed_at"] = datetime.now(timezone.utc).isoformat()

        for t in tasks:
            deps = t.get("dependencies", [])
            if task_id in deps and t.get("status") not in ["COMPLETED", "CANCELLED"]:
                t["status"] = "CANCELLED"
                t["error_message"] = f"Prerequisite task '{task_id}' was cancelled."
                step_id = t.get("step_id") or t.get("task_id")
                if step_id:
                    self.task_scheduler.mark_task_cancelled(step_id, reason=t["error_message"])

        if plan:
            plan.tasks = list(tasks)
            flag_modified(plan, "tasks")
            db.commit()

        log_audit_event(
            db=db,
            case_id=case_id,
            event_type="TOOL_EXECUTION_CANCELLED",
            details=f"Task '{task_id}' cancellation processed. Process terminated: {is_terminated}.",
        )

        return {
            "case_id": case_id,
            "task_id": task_id,
            "status": "CANCELLED",
            "message": "Task cancelled successfully." if is_terminated else "Task marked cancelled, but process remains running due to unverified identity.",
            "execution_id": execution.id if execution else None,
            "cancelled_at": datetime.now(timezone.utc),
            "process_terminated": is_terminated,
        }

    def reconcile_stale_executions(self, db: Session) -> List[Dict[str, Any]]:
        """
        Safely reconciles stale 'RUNNING' execution records found in database upon startup or crash recovery.
        Marks stale executions FAILED without unsafe automatic rerun to preserve forensic integrity.
        Verifies exact process start time alongside PID to protect against PID reuse by unrelated OS processes.
        """
        import os
        from forensic_tools.registry import get_process_start_time
        stale_executions = db.query(ToolExecution).filter(ToolExecution.status == "RUNNING").all()
        reconciled = []

        for exec_rec in stale_executions:
            pid_alive = False
            start_time_matched = False
            identity_unknown = False

            if exec_rec.pid:
                try:
                    os.kill(exec_rec.pid, 0)
                    pid_alive = True
                except (OSError, ProcessLookupError):
                    pid_alive = False

                if pid_alive:
                    current_start_time = get_process_start_time(exec_rec.pid)
                    if current_start_time is None or exec_rec.process_start_time is None:
                        identity_unknown = True
                    elif current_start_time == exec_rec.process_start_time:
                        start_time_matched = True

            if not pid_alive:
                exec_rec.status = "FAILED"
                exec_rec.error_message = "Backend restarted while execution was in progress."
                exec_rec.completed_at = datetime.now(timezone.utc)
                db.commit()

                log_audit_event(
                    db=db,
                    case_id=exec_rec.case_id,
                    event_type="TOOL_EXECUTION_RECOVERY_FAILED",
                    details=f"Stale RUNNING execution '{exec_rec.id}' (tool: {exec_rec.tool_id}) reconciled to FAILED after system restart.",
                )
                reconciled.append({"execution_id": exec_rec.id, "status": "FAILED"})
            elif pid_alive and identity_unknown:
                exec_rec.status = "FAILED"
                exec_rec.error_message = "Stale execution process identity could not be verified."
                exec_rec.completed_at = datetime.now(timezone.utc)
                db.commit()

                log_audit_event(
                    db=db,
                    case_id=exec_rec.case_id,
                    event_type="TOOL_EXECUTION_RECOVERY_FAILED",
                    details=f"Stale RUNNING execution '{exec_rec.id}' PID {exec_rec.pid} process identity could not be verified. Marked FAILED without terminating PID.",
                )
                reconciled.append({"execution_id": exec_rec.id, "status": "FAILED"})
            elif pid_alive and not start_time_matched:
                exec_rec.status = "FAILED"
                exec_rec.error_message = "Stale execution PID was reused by an unrelated OS process."
                exec_rec.completed_at = datetime.now(timezone.utc)
                db.commit()

                log_audit_event(
                    db=db,
                    case_id=exec_rec.case_id,
                    event_type="TOOL_EXECUTION_RECOVERY_FAILED",
                    details=f"Stale RUNNING execution '{exec_rec.id}' PID {exec_rec.pid} was reused by an unrelated OS process. Execution marked FAILED without terminating process.",
                )
                reconciled.append({"execution_id": exec_rec.id, "status": "FAILED"})

        return reconciled

    def shutdown(self):
        """
        Gracefully shuts down orchestrator and active tool subprocesses.
        """
        self.task_scheduler.shutdown()
        from forensic_tools.registry import tool_registry
        with tool_registry._process_lock:
            for exec_id, proc in list(tool_registry._active_processes.items()):
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=1.0)
                        except Exception:
                            proc.kill()
                except Exception:
                    pass
            tool_registry._active_processes.clear()
