"""ADFIR — Investigation Recovery & Reproducibility Service (Final Backend Completion)

Enforces persistent recovery after operational failures (system crash, backend restart,
interrupted investigations, tool/agent timeouts, process kills, partial completions).

Guarantees:
1. Recovers case and investigation state deterministically from persistent SQLite/disk storage.
2. Identifies stale or interrupted RUNNING runs, tasks, and requests.
3. Never blindly reruns an already completed forensic execution when its outputs are intact and valid.
4. Verifies existing output file SHA-256 digests before reuse.
5. Verifies if forensic OS processes are still running to prevent duplicate executions.
6. Safely transitions interrupted tasks to RECOVERED or READY for seamless resumption.
7. Preserves immutable evidence vault and all raw/structured forensic artifacts.
8. Preserves cryptographic audit-chain integrity and records immutable recovery audit event.
"""

import os
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.app.models.models import (
    Case,
    InvestigationRun,
    InvestigationTask,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    User
)
from backend.app.schemas.schemas import RecoveryResponse
from backend.app.services.audit import AuditService, log_audit_event
from backend.app.services.integrity import calculate_sha256
from forensic_tools.registry import get_process_start_time

logger = logging.getLogger("ADFIR_RECOVERY")


def is_execution_process_running(exec_record: Optional[ForensicExecution]) -> bool:
    """
    Reuses Step 9 PID and process-start verification to authoritatively check
    if the underlying forensic OS subprocess is still active.
    Protects against recycled PIDs.
    """
    if not exec_record or not exec_record.pid or exec_record.pid <= 0:
        return False
    current_start_time = get_process_start_time(exec_record.pid)
    if current_start_time is None:
        return False
    if exec_record.process_start_time is not None:
        return current_start_time == exec_record.process_start_time
    return True


class InvestigationRecoveryService:
    """
    Service responsible for deterministic state recovery across cases and investigation runs.
    """

    @classmethod
    def is_process_running(cls, exec_record: Optional[ForensicExecution]) -> bool:
        return is_execution_process_running(exec_record)

    @classmethod
    def recover_case(
        cls,
        db: Session,
        case_id: str,
        user: User,
        force: bool = False,
        safe_reset_stale_tasks: bool = True
    ) -> RecoveryResponse:
        """
        Scans persistent database and disk storage for the case, recovers interrupted runs and tasks,
        validates output hashes before reuse, ensures still-running processes are not duplicated,
        and logs an immutable recovery audit event.
        """
        now = datetime.now(timezone.utc)
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

        recovered_runs_count = 0
        recovered_tasks_count = 0
        interrupted_tasks_resumed = 0
        valid_outputs_preserved = 0
        still_running_processes_count = 0
        recovery_details: Dict[str, Any] = {
            "recovered_runs": [],
            "preserved_executions": [],
            "rescheduled_requests": [],
            "still_running_executions": []
        }

        # 1. Inspect Interrupted Investigation Runs
        stale_runs = db.query(InvestigationRun).filter(
            InvestigationRun.case_id == case.id,
            InvestigationRun.status.in_(["RUNNING", "INTERRUPTED", "RECOVERED"])
        ).all()

        for run in stale_runs:
            tasks = db.query(InvestigationTask).filter(
                InvestigationTask.run_id == run.id
            ).all()

            run_has_active_procs = False
            for task in tasks:
                if task.status == "RUNNING" or (force and task.status != "COMPLETED"):
                    recovered_tasks_count += 1
                    req = db.query(AnalysisRequest).filter(
                        AnalysisRequest.task_id == task.id
                    ).order_by(AnalysisRequest.created_at.desc()).first()

                    if req:
                        exec_record = db.query(ForensicExecution).filter(
                            ForensicExecution.request_id == req.id
                        ).order_by(ForensicExecution.created_at.desc()).first()

                        # Check 1: Is the OS process still running?
                        if exec_record and cls.is_process_running(exec_record):
                            # The process is still actively running in the OS.
                            # NEVER reset task to READY while its previous forensic OS process is still running.
                            run_has_active_procs = True
                            still_running_processes_count += 1
                            recovery_details["still_running_executions"].append({
                                "task_id": task.id,
                                "request_id": req.id,
                                "execution_id": exec_record.id,
                                "pid": exec_record.pid,
                                "reason": "Process is still active in operating system. Reset to READY prohibited to prevent duplicate execution."
                            })
                            continue

                        # Check 2: Verify if execution actually completed and produced valid outputs on disk
                        has_valid_outputs = False
                        if exec_record:
                            outputs = db.query(ExecutionOutput).filter(
                                ExecutionOutput.execution_id == exec_record.id
                            ).all()

                            if outputs:
                                all_outputs_intact = True
                                for out in outputs:
                                    if out.storage_path and os.path.exists(out.storage_path):
                                        try:
                                            actual_hash, _ = calculate_sha256(out.storage_path)
                                            if actual_hash.lower() != (out.sha256_hash or "").lower():
                                                all_outputs_intact = False
                                                break
                                        except Exception:
                                            all_outputs_intact = False
                                            break
                                    else:
                                        all_outputs_intact = False
                                        break

                                if all_outputs_intact:
                                    has_valid_outputs = True
                                    valid_outputs_preserved += len(outputs)
                                    exec_record.execution_status = "COMPLETED"
                                    req.scheduler_status = "COMPLETED"
                                    task.status = "COMPLETED"
                                    recovery_details["preserved_executions"].append({
                                        "execution_id": exec_record.id,
                                        "tool_id": exec_record.tool_id,
                                        "outputs_preserved": len(outputs)
                                    })

                        if not has_valid_outputs and safe_reset_stale_tasks:
                            # Safely reset task to READY only because previous process is confirmed terminated/non-running
                            task.status = "READY"
                            task.error_message = f"Recovered from interrupted state at {now.isoformat()}"
                            req.scheduler_status = "READY"
                            req.failure_reason = "Interrupted by system restart/crash. Safely reset to READY."
                            if exec_record and exec_record.execution_status == "RUNNING":
                                exec_record.execution_status = "CANCELLED"
                                exec_record.cancellation_reason = "System restart recovery."
                            interrupted_tasks_resumed += 1
                            recovery_details["rescheduled_requests"].append(req.id)

            # Transition run to RECOVERED only when all active OS processes have terminated
            if not run_has_active_procs and run.status != "RECOVERED":
                run.status = "RECOVERED"
                run.error_message = f"Recovered from operational interruption at {now.isoformat()}."
                progress = dict(run.stage_progress or {})
                progress["recovered_at"] = now.isoformat()
                run.stage_progress = progress
                db.add(run)
                recovered_runs_count += 1
                recovery_details["recovered_runs"].append(run.id)

        # 2. Inspect orphaned AnalysisRequests with RUNNING scheduler_status
        orphan_requests = db.query(AnalysisRequest).filter(
            AnalysisRequest.case_id == case.id,
            AnalysisRequest.scheduler_status == "RUNNING"
        ).all()

        for o_req in orphan_requests:
            exec_rec = db.query(ForensicExecution).filter(
                ForensicExecution.request_id == o_req.id
            ).order_by(ForensicExecution.created_at.desc()).first()

            # Process still running check on orphaned requests too!
            if exec_rec and cls.is_process_running(exec_rec):
                still_running_processes_count += 1
                recovery_details["still_running_executions"].append({
                    "request_id": o_req.id,
                    "execution_id": exec_rec.id,
                    "pid": exec_rec.pid,
                    "reason": "Process is still active in operating system."
                })
                continue

            if safe_reset_stale_tasks:
                o_req.scheduler_status = "READY"
                o_req.failure_reason = f"Recovered from interrupted state at {now.isoformat()}"
                if o_req.task_id:
                    o_task = db.query(InvestigationTask).filter(InvestigationTask.id == o_req.task_id).first()
                    if o_task and o_task.status != "COMPLETED":
                        o_task.status = "READY"
                        o_task.error_message = f"Recovered from interrupted state at {now.isoformat()}"
                interrupted_tasks_resumed += 1
                recovery_details["rescheduled_requests"].append(o_req.id)

        db.commit()

        # 3. Verify audit chain
        audit_res = AuditService.verify_chain(db, case_id=case.id)

        # 4. Log recovery audit event
        log_audit_event(
            db=db,
            event_type="INVESTIGATION_RECOVERED",
            details=(
                f"Investigation recovery executed for case {case.id}. "
                f"Recovered {recovered_runs_count} runs, preserved {valid_outputs_preserved} outputs, "
                f"resumed {interrupted_tasks_resumed} tasks, still running: {still_running_processes_count}."
            ),
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            metadata_json={
                "recovered_runs_count": recovered_runs_count,
                "recovered_tasks_count": recovered_tasks_count,
                "interrupted_tasks_resumed": interrupted_tasks_resumed,
                "valid_outputs_preserved": valid_outputs_preserved,
                "still_running_processes_count": still_running_processes_count,
                "audit_chain_verified": audit_res.is_valid and not audit_res.tamper_detected,
                "recovery_details": recovery_details
            },
            provenance_context={
                "case_id": case.id,
                "recovery_timestamp": now.isoformat()
            }
        )

        logger.info(
            f"[RECOVERY] Case {case.id} recovered successfully. "
            f"Runs: {recovered_runs_count}, Preserved: {valid_outputs_preserved}, Resumed: {interrupted_tasks_resumed}, "
            f"Still Running: {still_running_processes_count}."
        )

        return RecoveryResponse(
            case_id=case.id,
            status="RECOVERED",
            recovered_runs_count=recovered_runs_count,
            recovered_tasks_count=recovered_tasks_count,
            interrupted_tasks_resumed=interrupted_tasks_resumed,
            valid_outputs_preserved=valid_outputs_preserved,
            audit_chain_verified=audit_res.is_valid and not audit_res.tamper_detected,
            message=(
                f"Recovery completed successfully. {recovered_runs_count} runs recovered, "
                f"{valid_outputs_preserved} output artifacts preserved, "
                f"{interrupted_tasks_resumed} interrupted tasks reset to READY."
            ),
            recovery_details=recovery_details,
            timestamp=now
        )

    @classmethod
    def reconcile_all_stale_executions(cls, db: Session) -> dict:
        """
        Scans persistent database across all cases to reconcile interrupted/stale runs,
        tasks, requests, and executions after system restart or operational interruption.

        Guarantees:
        - Checks OS process activity (PID + start time) to never reset while process is alive.
        - Verifies on-disk output SHA-256 digests before reuse; marks valid outputs COMPLETED.
        - Safely transitions interrupted tasks/requests without valid outputs to READY for scheduler retry.
        - Sets interrupted runs to RECOVERED once all active OS processes terminate.
        - Idempotent and transactionally safe across multiple cases.
        """
        now = datetime.now(timezone.utc)
        stats = {
            "cases_scanned": 0,
            "runs_recovered": 0,
            "tasks_recovered": 0,
            "tasks_reset": 0,
            "outputs_preserved": 0,
            "processes_still_running": 0,
            "requests_recovered": 0,
            "errors": []
        }

        try:
            cases = db.query(Case).all()
        except Exception as e:
            logger.error(f"[RECOVERY] Failed to query cases for reconciliation: {e}", exc_info=True)
            stats["errors"].append({"case_id": None, "error": str(e)})
            return stats

        stats["cases_scanned"] = len(cases)

        for case in cases:
            case_runs_recovered = 0
            case_tasks_recovered = 0
            case_tasks_reset = 0
            case_outputs_preserved = 0
            case_requests_recovered = 0
            case_procs_running = 0

            try:
                # 1. Inspect Interrupted Investigation Runs for this case
                stale_runs = db.query(InvestigationRun).filter(
                    InvestigationRun.case_id == case.id,
                    InvestigationRun.status.in_(["RUNNING", "INTERRUPTED"])
                ).all()

                for run in stale_runs:
                    tasks = db.query(InvestigationTask).filter(
                        InvestigationTask.run_id == run.id
                    ).all()

                    run_has_active_procs = False
                    for task in tasks:
                        if task.status in ("RUNNING", "INTERRUPTED"):
                            case_tasks_recovered += 1
                            req = db.query(AnalysisRequest).filter(
                                AnalysisRequest.task_id == task.id
                            ).order_by(AnalysisRequest.created_at.desc()).first()

                            exec_record = None
                            if req:
                                exec_record = db.query(ForensicExecution).filter(
                                    ForensicExecution.request_id == req.id
                                ).order_by(ForensicExecution.created_at.desc()).first()

                            # Process safety check: is OS process still running?
                            if exec_record and cls.is_process_running(exec_record):
                                run_has_active_procs = True
                                case_procs_running += 1
                                continue

                            # Process stopped/terminated: verify outputs on disk
                            has_valid_outputs = False
                            if exec_record:
                                outputs = db.query(ExecutionOutput).filter(
                                    ExecutionOutput.execution_id == exec_record.id
                                ).all()
                                if outputs:
                                    all_intact = True
                                    for out in outputs:
                                        if out.storage_path and os.path.exists(out.storage_path):
                                            try:
                                                actual_hash, _ = calculate_sha256(out.storage_path)
                                                if actual_hash.lower() != (out.sha256_hash or "").lower():
                                                    all_intact = False
                                                    break
                                            except Exception:
                                                all_intact = False
                                                break
                                        else:
                                            all_intact = False
                                            break

                                    if all_intact:
                                        has_valid_outputs = True
                                        case_outputs_preserved += len(outputs)
                                        exec_record.execution_status = "COMPLETED"
                                        if req:
                                            req.scheduler_status = "COMPLETED"
                                        task.status = "COMPLETED"

                            if not has_valid_outputs:
                                task.status = "READY"
                                task.error_message = f"Recovered from interrupted state at {now.isoformat()}"
                                if req:
                                    req.scheduler_status = "READY"
                                    req.failure_reason = "Interrupted by system restart/crash. Safely reset to READY."
                                    case_requests_recovered += 1
                                if exec_record and exec_record.execution_status == "RUNNING":
                                    exec_record.execution_status = "CANCELLED"
                                    exec_record.cancellation_reason = "System restart recovery."
                                case_tasks_reset += 1

                    # Transition run to RECOVERED once all active OS processes have terminated
                    if not run_has_active_procs and run.status != "RECOVERED":
                        run.status = "RECOVERED"
                        run.error_message = f"Recovered from operational interruption at {now.isoformat()}."
                        progress = dict(run.stage_progress or {})
                        progress["recovered_at"] = now.isoformat()
                        run.stage_progress = progress
                        db.add(run)
                        case_runs_recovered += 1

                # 2. Inspect orphaned AnalysisRequests with RUNNING scheduler_status
                orphan_requests = db.query(AnalysisRequest).filter(
                    AnalysisRequest.case_id == case.id,
                    AnalysisRequest.scheduler_status == "RUNNING"
                ).all()

                for o_req in orphan_requests:
                    exec_rec = db.query(ForensicExecution).filter(
                        ForensicExecution.request_id == o_req.id
                    ).order_by(ForensicExecution.created_at.desc()).first()

                    if exec_rec and cls.is_process_running(exec_rec):
                        case_procs_running += 1
                        continue

                    has_valid_outputs = False
                    if exec_rec:
                        outputs = db.query(ExecutionOutput).filter(
                            ExecutionOutput.execution_id == exec_rec.id
                        ).all()
                        if outputs:
                            all_intact = True
                            for out in outputs:
                                if out.storage_path and os.path.exists(out.storage_path):
                                    try:
                                        h, _ = calculate_sha256(out.storage_path)
                                        if h.lower() != (out.sha256_hash or "").lower():
                                            all_intact = False
                                            break
                                    except Exception:
                                        all_intact = False
                                        break
                                else:
                                    all_intact = False
                                    break
                            if all_intact:
                                has_valid_outputs = True
                                case_outputs_preserved += len(outputs)
                                exec_rec.execution_status = "COMPLETED"
                                o_req.scheduler_status = "COMPLETED"
                                if o_req.task_id:
                                    o_task = db.query(InvestigationTask).filter(InvestigationTask.id == o_req.task_id).first()
                                    if o_task and o_task.status != "COMPLETED":
                                        o_task.status = "COMPLETED"

                    if not has_valid_outputs:
                        o_req.scheduler_status = "READY"
                        o_req.failure_reason = f"Recovered from interrupted state at {now.isoformat()}"
                        if exec_rec and exec_rec.execution_status == "RUNNING":
                            exec_rec.execution_status = "CANCELLED"
                            exec_rec.cancellation_reason = "System restart recovery."
                        if o_req.task_id:
                            o_task = db.query(InvestigationTask).filter(InvestigationTask.id == o_req.task_id).first()
                            if o_task and o_task.status != "COMPLETED":
                                o_task.status = "READY"
                                o_task.error_message = f"Recovered from interrupted state at {now.isoformat()}"
                                case_tasks_reset += 1
                        case_requests_recovered += 1

                # If state was modified, commit and record audit event
                if case_runs_recovered > 0 or case_tasks_reset > 0 or case_outputs_preserved > 0 or case_requests_recovered > 0:
                    db.commit()
                    log_audit_event(
                        db=db,
                        event_type="INVESTIGATION_RECOVERED",
                        details=(
                            f"Global startup recovery reconciliation executed for case {case.id}. "
                            f"Recovered {case_runs_recovered} runs, preserved {case_outputs_preserved} outputs, "
                            f"reset {case_tasks_reset} tasks, still running procs: {case_procs_running}."
                        ),
                        case_id=case.id,
                        actor_id="system",
                        actor_name="system",
                        metadata_json={
                            "case_id": case.id,
                            "runs_recovered": case_runs_recovered,
                            "tasks_recovered": case_tasks_recovered,
                            "tasks_reset": case_tasks_reset,
                            "outputs_preserved": case_outputs_preserved,
                            "processes_still_running": case_procs_running,
                            "requests_recovered": case_requests_recovered
                        },
                        provenance_context={
                            "case_id": case.id,
                            "reconciliation_timestamp": now.isoformat()
                        }
                    )
                else:
                    db.commit()

                stats["runs_recovered"] += case_runs_recovered
                stats["tasks_recovered"] += case_tasks_recovered
                stats["tasks_reset"] += case_tasks_reset
                stats["outputs_preserved"] += case_outputs_preserved
                stats["requests_recovered"] += case_requests_recovered
                stats["processes_still_running"] += case_procs_running

            except Exception as case_err:
                logger.error(f"[RECOVERY] Error during reconciliation for case {case.id}: {case_err}", exc_info=True)
                try:
                    db.rollback()
                except Exception:
                    pass
                stats["errors"].append({
                    "case_id": case.id,
                    "error": str(case_err)
                })

        logger.info(
            f"[RECOVERY] Global reconciliation finished: {stats['cases_scanned']} cases scanned, "
            f"{stats['runs_recovered']} runs recovered, {stats['tasks_reset']} tasks reset, "
            f"{stats['outputs_preserved']} outputs preserved, {stats['processes_still_running']} still running procs, "
            f"{len(stats['errors'])} errors."
        )
        return stats
