"""
ADFIR — Resource-Aware Scheduler Subsystem (Phase 2 / Step 8)

Bridges validated Step 7 Tool Selection with future Step 9 Process Execution.
Deterministically prepares, prioritizes, resource-manages, and queues analysis requests.

STRICT INVARIANTS:
- MUST NOT execute forensic tools.
- MUST NOT kill or manage OS processes.
- MUST NOT use autonomous agents or LLM reasoning.
- MUST NOT redo Step 6 planning or Step 7 tool selection.
"""

import sys
import os
import shutil
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set

from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.models.models import (
    AnalysisRequest,
    InvestigationPlan,
    InvestigationTask,
    InvestigationTaskDependency,
    ToolSelectionRecord,
    Case,
    EvidenceItem,
    User
)
from backend.app.services.audit import log_audit_event
from backend.app.services.tool_selector import get_system_resources

logger = logging.getLogger("ADFIR_SCHEDULER")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

DEFAULT_MAX_CONCURRENT_JOBS = 4
DEFAULT_TIMEOUT_SECONDS = 300
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 86400

SCHEDULER_STATUSES = {
    "QUEUED",
    "WAITING_DEPENDENCY",
    "WAITING_RESOURCE",
    "READY",
    "RUNNING",
    "CANCELLED",
    "TIMEOUT",
    "FAILED",
    "COMPLETED",
    "RETRY_PENDING",
    "BLOCKED"
}

ACTIVE_STATUSES = {"READY", "RUNNING"}
UNRESOLVED_STATUSES = {"QUEUED", "WAITING_DEPENDENCY", "WAITING_RESOURCE", "RETRY_PENDING"}
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "BLOCKED"}


# =============================================================================
# 1. RESOURCE MANAGEMENT & TRACKING
# =============================================================================

class SchedulerResourceTracker:
    """
    Tracks live host resources and active scheduler-level resource reservations.
    Prevents CPU, RAM, disk over-allocation, and concurrency limit violations.
    """

    @classmethod
    def get_max_concurrency(cls) -> int:
        cpu_count = os.cpu_count() or 2
        return max(2, min(cpu_count, 8))

    @classmethod
    def get_allocated_resources(cls, db: Session) -> Dict[str, Any]:
        """
        Calculates currently reserved resources across all active (READY / RUNNING) jobs.
        """
        active_jobs = (
            db.query(AnalysisRequest)
            .filter(AnalysisRequest.scheduler_status.in_(ACTIVE_STATUSES))
            .all()
        )

        allocated_cpu = 0
        allocated_ram_mb = 0.0
        allocated_disk_mb = 0.0

        for job in active_jobs:
            alloc = job.allocated_resources or {}
            allocated_cpu += int(alloc.get("cpu_cores", 0))
            allocated_ram_mb += float(alloc.get("ram_mb", 0.0))
            allocated_disk_mb += float(alloc.get("disk_mb", 0.0))

        return {
            "active_job_count": len(active_jobs),
            "allocated_cpu_cores": allocated_cpu,
            "allocated_ram_mb": round(allocated_ram_mb, 2),
            "allocated_disk_mb": round(allocated_disk_mb, 2)
        }

    @classmethod
    def can_allocate(
        cls,
        req_cpu: int,
        req_ram: float,
        req_disk: float,
        current_alloc: Dict[str, Any],
        host_capacity: Dict[str, Any],
        max_concurrency: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines whether requested resources can be allocated without exceeding limits.
        """
        limit_concurrency = max_concurrency or cls.get_max_concurrency()

        # 1. Concurrency limit check
        if current_alloc["active_job_count"] >= limit_concurrency:
            return False, f"Maximum concurrent jobs limit reached ({current_alloc['active_job_count']}/{limit_concurrency})"

        # 2. CPU capacity check
        total_host_cpu = int(host_capacity.get("cpu_cores", 1))
        if (current_alloc["allocated_cpu_cores"] + req_cpu) > total_host_cpu:
            return False, f"CPU cores required ({req_cpu}) exceeds available ({total_host_cpu - current_alloc['allocated_cpu_cores']})"

        # 3. RAM capacity check
        avail_host_ram = float(host_capacity.get("available_ram_mb", 4096.0))
        # Keep 512MB safety reserve
        usable_ram = max(512.0, avail_host_ram - 512.0)
        if (current_alloc["allocated_ram_mb"] + req_ram) > usable_ram:
            return False, f"RAM required ({req_ram:.1f} MB) exceeds available ({usable_ram - current_alloc['allocated_ram_mb']:.1f} MB)"

        # 4. Scratch disk capacity check
        avail_host_disk = float(host_capacity.get("available_disk_mb", 10240.0))
        usable_disk = max(1024.0, avail_host_disk - 1024.0)
        if (current_alloc["allocated_disk_mb"] + req_disk) > usable_disk:
            return False, f"Disk required ({req_disk:.1f} MB) exceeds available ({usable_disk - current_alloc['allocated_disk_mb']:.1f} MB)"

        return True, None

    @classmethod
    def get_scheduler_status(cls, db: Session) -> Dict[str, Any]:
        """
        Returns snapshot of scheduler metrics, capacity, allocations, and queue breakdown.
        """
        all_jobs = db.query(AnalysisRequest).all()
        status_counts = {s: 0 for s in SCHEDULER_STATUSES}
        for j in all_jobs:
            status_counts[j.scheduler_status] = status_counts.get(j.scheduler_status, 0) + 1

        host_cap = get_system_resources()
        alloc = cls.get_allocated_resources(db)
        max_conc = cls.get_max_concurrency()

        avail_cpu = max(0, int(host_cap["cpu_cores"]) - alloc["allocated_cpu_cores"])
        avail_ram = max(0.0, float(host_cap["available_ram_mb"]) - alloc["allocated_ram_mb"])
        avail_disk = max(0.0, float(host_cap["available_disk_mb"]) - alloc["allocated_disk_mb"])

        return {
            "total_jobs": len(all_jobs),
            "status_counts": status_counts,
            "max_concurrent_jobs": max_conc,
            "active_jobs_count": alloc["active_job_count"],
            "host_capacity": host_cap,
            "allocated_resources": alloc,
            "available_capacity": {
                "available_cpu_cores": avail_cpu,
                "available_ram_mb": round(avail_ram, 2),
                "available_disk_mb": round(avail_disk, 2),
                "remaining_concurrency_slots": max(0, max_conc - alloc["active_job_count"])
            }
        }


# =============================================================================
# 2. DEPENDENCY EVALUATOR
# =============================================================================

class SchedulerDependencyEvaluator:
    """
    Evaluates whether an analysis request's task dependencies are satisfied.
    Handles waiting dependencies, completion, failed/cancelled dependencies, and invalid refs.
    """

    @classmethod
    def evaluate(cls, db: Session, job: AnalysisRequest) -> Tuple[str, Optional[str]]:
        """
        Returns (status, reason).
        status in ["SATISFIED", "WAITING", "BLOCKED"].
        """
        deps = job.dependencies or []
        if not deps:
            return "SATISFIED", None

        # Query all jobs in the same plan
        plan_jobs = (
            db.query(AnalysisRequest)
            .filter(AnalysisRequest.plan_id == job.plan_id)
            .all()
        )
        job_map_by_key = {j.task_key: j for j in plan_jobs}
        job_map_by_id = {j.task_id: j for j in plan_jobs if j.task_id}

        for dep_ref in deps:
            parent = job_map_by_key.get(dep_ref) or job_map_by_id.get(dep_ref)
            if not parent:
                return "BLOCKED", f"Parent dependency '{dep_ref}' not found in plan"

            p_status = parent.scheduler_status

            if p_status in ["FAILED", "CANCELLED", "TIMEOUT", "BLOCKED"]:
                return "BLOCKED", f"Parent dependency '{dep_ref}' cannot succeed (status: {p_status})"

            if p_status != "COMPLETED":
                return "WAITING", f"Waiting for parent dependency '{dep_ref}' to complete (currently: {p_status})"

        return "SATISFIED", None


# =============================================================================
# 3. TIMEOUT & RETRY MANAGERS
# =============================================================================

class SchedulerTimeoutManager:
    """
    Detects expired jobs, marks them TIMEOUT, and releases reserved resources.
    Does NOT invoke external OS process kills.
    """

    @classmethod
    def check_and_apply_timeouts(cls, db: Session) -> List[AnalysisRequest]:
        now = utc_now()
        running_jobs = (
            db.query(AnalysisRequest)
            .filter(AnalysisRequest.scheduler_status == "RUNNING")
            .all()
        )

        timed_out = []
        for job in running_jobs:
            started = job.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            timeout_td = timedelta(seconds=job.timeout_seconds)
            if (now - started) > timeout_td:
                job.scheduler_status = "TIMEOUT"
                job.failure_reason = f"Execution exceeded maximum configured timeout of {job.timeout_seconds} seconds"
                job.allocated_resources = {}
                timed_out.append(job)

                log_audit_event(
                    db=db,
                    event_type="JOB_TIMEOUT",
                    case_id=job.case_id,
                    details=f"Job {job.id} (task {job.task_key}) timed out after {job.timeout_seconds}s"
                )

        if timed_out:
            db.commit()
        return timed_out


class SchedulerRetryManager:
    """
    Handles retry policies and schedules eligible failed jobs for retry.
    """

    @classmethod
    def can_retry(cls, job: AnalysisRequest) -> Tuple[bool, Optional[str]]:
        policy = job.retry_policy or {}
        max_retries = int(policy.get("max_retries", 3))
        current_retries = int(policy.get("retry_count", 0))
        is_retryable = bool(policy.get("is_retryable", True))

        if not is_retryable:
            return False, "Job failure is explicitly marked non-retryable (safety/invalid configuration)"

        if current_retries >= max_retries:
            return False, f"Maximum retries exhausted ({current_retries}/{max_retries})"

        return True, None

    @classmethod
    def schedule_retry(cls, db: Session, job: AnalysisRequest, actor_user: Optional[User] = None) -> bool:
        can_r, reason = cls.can_retry(job)
        if not can_r:
            return False

        policy = dict(job.retry_policy or {})
        policy["retry_count"] = int(policy.get("retry_count", 0)) + 1
        job.retry_policy = policy

        job.scheduler_status = "RETRY_PENDING"
        job.allocated_resources = {}
        job.ready_at = None
        job.started_at = None
        job.completed_at = None
        job.failure_reason = f"Retry #{policy['retry_count']} scheduled: previous failure was '{job.failure_reason}'"

        log_audit_event(
            db=db,
            event_type="JOB_RETRY_SCHEDULED",
            actor_id=actor_user.id if actor_user else None,
            actor_name=actor_user.name if actor_user else "scheduler",
            case_id=job.case_id,
            details=f"Job {job.id} (task {job.task_key}) scheduled for retry #{policy['retry_count']}"
        )
        db.commit()
        return True


# =============================================================================
# 4. RESOURCE-AWARE SCHEDULER ENGINE
# =============================================================================

class ResourceAwareScheduler:
    """
    Main engine for Phase 2 / Step 8: Resource-Aware Scheduler.
    Prepares, validates, queues, and promotes analysis jobs to READY.
    """

    @classmethod
    def create_analysis_request(
        cls,
        db: Session,
        plan_id: str,
        task_key: str,
        actor_user: User,
        timeout_seconds: Optional[int] = None,
        custom_retry_policy: Optional[Dict[str, Any]] = None
    ) -> AnalysisRequest:
        """
        Creates a persistent AnalysisRequest from a validated Step 7 Tool Selection.
        Rejects unselected, incompatible, unavailable, or safety-flagged tasks.
        """
        plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"InvestigationPlan '{plan_id}' not found")

        task = (
            db.query(InvestigationTask)
            .filter(InvestigationTask.plan_id == plan.id, InvestigationTask.task_key == task_key)
            .first()
        )
        if not task:
            raise ValueError(f"InvestigationTask '{task_key}' not found in plan '{plan_id}'")

        # Step 7 Tool Selection Validation Gate
        tool_sel = (
            db.query(ToolSelectionRecord)
            .filter(ToolSelectionRecord.plan_id == plan.id, ToolSelectionRecord.task_key == task_key)
            .first()
        )
        if not tool_sel:
            raise ValueError(f"Task '{task_key}' has no Step 7 tool selection record")

        if tool_sel.selection_status != "SELECTED" or not tool_sel.selected_tool_id:
            raise ValueError(
                f"Cannot schedule task '{task_key}': Step 7 tool selection status is '{tool_sel.selection_status}'. "
                f"Reason: {tool_sel.selection_rationale or 'Tool not selected'}"
            )

        # Check duplicate non-terminal request
        existing_active = (
            db.query(AnalysisRequest)
            .filter(
                AnalysisRequest.plan_id == plan.id,
                AnalysisRequest.task_key == task_key,
                AnalysisRequest.scheduler_status.notin_(TERMINAL_STATUSES)
            )
            .first()
        )
        if existing_active:
            raise ValueError(f"Task '{task_key}' already has an active analysis request: '{existing_active.id}' ({existing_active.scheduler_status})")

        # Validate timeout
        t_sec = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        if t_sec < MIN_TIMEOUT_SECONDS or t_sec > MAX_TIMEOUT_SECONDS:
            raise ValueError(f"Timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds")

        # Extract parent dependencies from Step 6 graph
        task_deps = (
            db.query(InvestigationTaskDependency)
            .filter(
                InvestigationTaskDependency.plan_id == plan.id,
                InvestigationTaskDependency.child_task_id == task.task_key
            )
            .all()
        )
        dep_keys = [d.parent_task_id for d in task_deps]

        # Retry policy
        def_policy = {
            "max_retries": 3,
            "retry_count": 0,
            "retry_delay_seconds": 60,
            "backoff_factor": 2.0,
            "is_retryable": True
        }
        if custom_retry_policy:
            def_policy.update(custom_retry_policy)

        # Resources required
        res_req = task.resource_requirements or {}
        if not res_req.get("ram_mb"):
            res_req["ram_mb"] = 512
        if not res_req.get("cpu_cores"):
            res_req["cpu_cores"] = 1
        if not res_req.get("disk_mb"):
            res_req["disk_mb"] = 100

        # Determine initial status
        initial_status = "WAITING_DEPENDENCY" if dep_keys else "QUEUED"
        initial_blocking_reason = (
            f"Waiting for parent dependency ({', '.join(dep_keys)})"
            if dep_keys else None
        )

        req = AnalysisRequest(
            case_id=plan.case_id,
            plan_id=plan.id,
            task_id=task.id,
            task_key=task.task_key,
            evidence_id=(task.evidence_ids or [None])[0],
            capability_id=task.capability_id,
            selected_tool_id=tool_sel.selected_tool_id,
            resource_requirements=res_req,
            priority_level=task.priority_level or "MEDIUM",
            priority_score=task.priority_score if task.priority_score is not None else 0.5,
            timeout_seconds=t_sec,
            retry_policy=def_policy,
            dependencies=dep_keys,
            scheduler_status=initial_status,
            blocking_reason=initial_blocking_reason,
            allocated_resources={},
            queued_at=utc_now(),
            created_at=utc_now(),
            updated_at=utc_now()
        )
        db.add(req)
        db.commit()
        db.refresh(req)

        log_audit_event(
            db=db,
            event_type="ANALYSIS_REQUEST_CREATED",
            actor_id=actor_user.id,
            actor_name=actor_user.name,
            case_id=plan.case_id,
            details=f"Analysis request {req.id} created for task {req.task_key} with tool {req.selected_tool_id}"
        )

        return req

    @classmethod
    def schedule_plan(
        cls,
        db: Session,
        plan_id: str,
        actor_user: User,
        timeout_override: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Creates AnalysisRequests for all eligible tasks in an InvestigationPlan with valid Step 7 selections.
        Then runs an evaluation pass to promote ready root tasks.
        """
        plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"InvestigationPlan '{plan_id}' not found")

        tasks = (
            db.query(InvestigationTask)
            .filter(InvestigationTask.plan_id == plan.id)
            .order_by(InvestigationTask.sequence.asc())
            .all()
        )

        # Pre-fetch existing non-terminal requests
        existing_reqs = {
            r.task_key: r for r in db.query(AnalysisRequest)
            .filter(AnalysisRequest.plan_id == plan.id, AnalysisRequest.scheduler_status.notin_(TERMINAL_STATUSES))
            .all()
        }

        # Pre-fetch tool selections
        tool_sels = {
            s.task_key: s for s in db.query(ToolSelectionRecord)
            .filter(ToolSelectionRecord.plan_id == plan.id)
            .all()
        }

        created_jobs: List[AnalysisRequest] = []
        blocked_count = 0

        for task in tasks:
            if task.task_key in existing_reqs:
                created_jobs.append(existing_reqs[task.task_key])
                continue

            sel = tool_sels.get(task.task_key)
            if not sel or sel.selection_status != "SELECTED" or not sel.selected_tool_id:
                blocked_count += 1
                continue

            try:
                job = cls.create_analysis_request(
                    db=db,
                    plan_id=plan.id,
                    task_key=task.task_key,
                    actor_user=actor_user,
                    timeout_seconds=timeout_override
                )
                created_jobs.append(job)
            except Exception as e:
                logger.warning(f"Skipping task {task.task_key} from schedule: {e}")
                blocked_count += 1

        # Run queue evaluation
        cls.evaluate_queue(db, plan_id=plan.id)

        # Refresh created jobs
        db.expire_all()
        refreshed_jobs = (
            db.query(AnalysisRequest)
            .filter(AnalysisRequest.id.in_([j.id for j in created_jobs]))
            .order_by(AnalysisRequest.priority_score.desc(), AnalysisRequest.queued_at.asc())
            .all()
        )

        return {
            "plan_id": plan.id,
            "case_id": plan.case_id,
            "total_tasks": len(tasks),
            "scheduled_jobs": len(refreshed_jobs),
            "blocked_jobs": blocked_count,
            "requests": refreshed_jobs
        }

    @classmethod
    def evaluate_queue(
        cls,
        db: Session,
        plan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Core scheduler evaluation loop.
        Evaluates timeouts, checks dependencies, checks system resource availability,
        and promotes eligible jobs to READY in priority order.
        """
        # 1. Process timeouts on active jobs
        timed_out_jobs = SchedulerTimeoutManager.check_and_apply_timeouts(db)

        # 2. Get unresolved jobs (QUEUED, WAITING_DEPENDENCY, WAITING_RESOURCE, RETRY_PENDING)
        query = db.query(AnalysisRequest).filter(AnalysisRequest.scheduler_status.in_(UNRESOLVED_STATUSES))
        if plan_id:
            query = query.filter(AnalysisRequest.plan_id == plan_id)

        # Deterministic sorting: priority score DESC, queued_at ASC
        unresolved_jobs = query.order_by(
            AnalysisRequest.priority_score.desc(),
            AnalysisRequest.queued_at.asc()
        ).all()

        host_cap = get_system_resources()
        current_alloc = SchedulerResourceTracker.get_allocated_resources(db)
        max_concurrency = SchedulerResourceTracker.get_max_concurrency()

        promoted_count = 0
        waiting_res_count = 0
        waiting_dep_count = 0
        blocked_count = 0

        for job in unresolved_jobs:
            # Stage A: Dependency check
            dep_status, dep_reason = SchedulerDependencyEvaluator.evaluate(db, job)

            if dep_status == "BLOCKED":
                job.scheduler_status = "BLOCKED"
                job.blocking_reason = dep_reason
                blocked_count += 1
                log_audit_event(
                    db=db,
                    event_type="JOB_BLOCKED",
                    case_id=job.case_id,
                    details=f"Job {job.id} (task {job.task_key}) blocked: {dep_reason}"
                )
                continue

            if dep_status == "WAITING":
                job.scheduler_status = "WAITING_DEPENDENCY"
                job.blocking_reason = dep_reason
                waiting_dep_count += 1
                continue

            # Stage B: Resource check
            reqs = job.resource_requirements or {}
            req_cpu = int(reqs.get("cpu_cores", 1))
            req_ram = float(reqs.get("ram_mb", 512.0))
            req_disk = float(reqs.get("disk_mb", 100.0))

            can_alloc, res_reason = SchedulerResourceTracker.can_allocate(
                req_cpu=req_cpu,
                req_ram=req_ram,
                req_disk=req_disk,
                current_alloc=current_alloc,
                host_capacity=host_cap,
                max_concurrency=max_concurrency
            )

            if not can_alloc:
                job.scheduler_status = "WAITING_RESOURCE"
                job.blocking_reason = res_reason
                job.allocated_resources = {}
                waiting_res_count += 1
                continue

            # Stage C: Promote to READY
            job.scheduler_status = "READY"
            job.ready_at = utc_now()
            job.blocking_reason = None
            job.allocated_resources = {
                "cpu_cores": req_cpu,
                "ram_mb": req_ram,
                "disk_mb": req_disk
            }
            promoted_count += 1

            # Update running tally so subsequent jobs in this evaluation see reduced capacity
            current_alloc["active_job_count"] += 1
            current_alloc["allocated_cpu_cores"] += req_cpu
            current_alloc["allocated_ram_mb"] += req_ram
            current_alloc["allocated_disk_mb"] += req_disk

            log_audit_event(
                db=db,
                event_type="JOB_PROMOTED_READY",
                case_id=job.case_id,
                details=f"Job {job.id} (task {job.task_key}) promoted to READY with {req_cpu} CPU, {req_ram}MB RAM"
            )

        db.commit()

        status_report = SchedulerResourceTracker.get_scheduler_status(db)

        return {
            "evaluated_jobs": len(unresolved_jobs),
            "promoted_to_ready": promoted_count,
            "waiting_resource": waiting_res_count,
            "waiting_dependency": waiting_dep_count,
            "blocked": blocked_count,
            "timed_out": len(timed_out_jobs),
            "scheduler_status": status_report
        }

    @classmethod
    def cancel_job(
        cls,
        db: Session,
        job_id: str,
        actor_user: User
    ) -> AnalysisRequest:
        """
        Cancels an eligible job, releases scheduler reservations, and propagates blocking to dependents.
        """
        job = db.query(AnalysisRequest).filter(AnalysisRequest.id == job_id).first()
        if not job:
            raise ValueError(f"AnalysisRequest '{job_id}' not found")

        if job.scheduler_status in ["COMPLETED", "CANCELLED"]:
            return job

        job.scheduler_status = "CANCELLED"
        job.cancelled_at = utc_now()
        job.allocated_resources = {}
        job.blocking_reason = f"Cancelled by user {actor_user.email}"

        # Trigger dependent jobs to be marked BLOCKED
        dependents = (
            db.query(AnalysisRequest)
            .filter(
                AnalysisRequest.plan_id == job.plan_id,
                AnalysisRequest.scheduler_status.in_(UNRESOLVED_STATUSES)
            )
            .all()
        )
        for dep in dependents:
            if job.task_key in (dep.dependencies or []):
                dep.scheduler_status = "BLOCKED"
                dep.blocking_reason = f"Parent task '{job.task_key}' was cancelled"

        log_audit_event(
            db=db,
            event_type="JOB_CANCELLED",
            actor_id=actor_user.id,
            actor_name=actor_user.name,
            case_id=job.case_id,
            details=f"AnalysisRequest {job.id} (task {job.task_key}) cancelled by {actor_user.name}"
        )

        db.commit()
        db.refresh(job)
        return job
