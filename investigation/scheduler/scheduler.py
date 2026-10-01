from abc import ABC, abstractmethod
import os
import sys
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class HostResourceProvider(ABC):
    """
    Explicit abstract base host hardware resource provider interface.
    """

    @abstractmethod
    def get_cpu_count(self) -> Optional[int]:
        pass

    @abstractmethod
    def get_total_memory_mb(self) -> Optional[int]:
        pass

    @abstractmethod
    def get_available_memory_mb(self) -> Optional[int]:
        pass


class DefaultResourceProvider(HostResourceProvider):
    """
    Standard host resource provider using Python standard library (os.cpu_count)
    and safe host inspection without fabricating metrics.
    Returns None when CPU count or RAM capacity cannot be measured.
    """

    def get_cpu_count(self) -> Optional[int]:
        return os.cpu_count()

    def get_total_memory_mb(self) -> Optional[int]:
        meminfo_path = "/proc/meminfo"
        if os.path.exists(meminfo_path):
            try:
                with open(meminfo_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            kb = int(parts[1])
                            return kb // 1024
            except Exception:
                pass
        return None

    def get_available_memory_mb(self) -> Optional[int]:
        meminfo_path = "/proc/meminfo"
        if os.path.exists(meminfo_path):
            try:
                with open(meminfo_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            parts = line.split()
                            kb = int(parts[1])
                            return kb // 1024
            except Exception:
                pass
        return None


class InjectableResourceProvider(HostResourceProvider):
    """
    Deterministic resource provider for unit tests and custom host capacity simulation.
    Supports explicitly setting None for unknown hardware specs to test conservative policies.
    """

    def __init__(
        self,
        cpu_count: Optional[int] = 4,
        total_memory_mb: Optional[int] = 8192,
        available_memory_mb: Optional[int] = None
    ):
        self._cpu_count = cpu_count
        self._total_memory_mb = total_memory_mb
        self._available_memory_mb = available_memory_mb if available_memory_mb is not None else total_memory_mb

    def get_cpu_count(self) -> Optional[int]:
        return self._cpu_count

    def get_total_memory_mb(self) -> Optional[int]:
        return self._total_memory_mb

    def get_available_memory_mb(self) -> Optional[int]:
        return self._available_memory_mb


class ResourceManager:
    """
    Thread-safe Hardware Resource Manager.
    Monitors host capacity, reserves/releases CPU & Memory, and enforces concurrency and exclusive task bounds.
    When hardware capacity is UNKNOWN (None), enforces conservative serial execution.
    """

    def __init__(
        self,
        max_concurrent_tasks: Optional[int] = None,
        resource_provider: Optional[HostResourceProvider] = None
    ):
        self.provider = resource_provider or DefaultResourceProvider()
        raw_cpus = self.provider.get_cpu_count()
        raw_mem = self.provider.get_total_memory_mb()

        self.total_cpus: Optional[float] = float(raw_cpus) if raw_cpus is not None else None
        self.total_memory_mb: Optional[int] = raw_mem

        if max_concurrent_tasks is not None:
            self.max_concurrent_tasks = max_concurrent_tasks
        elif self.total_cpus is not None:
            self.max_concurrent_tasks = max(1, int(self.total_cpus))
        else:
            self.max_concurrent_tasks = 1  # Conservative single-task execution limit when hardware is unknown

        self._lock = threading.Lock()
        self.reserved_cpus: float = 0.0
        self.reserved_memory_mb: int = 0
        self.active_exclusive_task: Optional[str] = None
        self.active_tasks: Dict[str, Dict[str, Any]] = {}

    def get_system_capacity(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "logical_cpus": int(self.total_cpus) if self.total_cpus is not None else None,
                "total_memory_mb": self.total_memory_mb,
                "available_memory_mb": self.provider.get_available_memory_mb(),
                "reserved_cpus": round(self.reserved_cpus, 2),
                "reserved_memory_mb": self.reserved_memory_mb,
                "max_concurrent_tasks": self.max_concurrent_tasks,
                "active_tasks": len(self.active_tasks),
                "active_tasks_count": len(self.active_tasks),
                "available_slots": max(0, self.max_concurrent_tasks - len(self.active_tasks)),
                "has_exclusive_task_running": self.active_exclusive_task is not None,
                "is_capacity_known": self.total_cpus is not None and self.total_memory_mb is not None,
            }

    def can_schedule_task(
        self,
        cpu_weight: float = 1.0,
        memory_mb: int = 512,
        is_exclusive: bool = False,
        parallel_safe: bool = True
    ) -> bool:
        with self._lock:
            return self._can_schedule_unlocked(cpu_weight, memory_mb, is_exclusive, parallel_safe)

    def _can_schedule_unlocked(
        self,
        cpu_weight: float,
        memory_mb: int,
        is_exclusive: bool,
        parallel_safe: bool
    ) -> bool:
        # Conservative policy for UNKNOWN capacity:
        # If CPU count or RAM capacity is UNKNOWN (None), enforce strict serial execution (max 1 task active at a time)
        if self.total_cpus is None or self.total_memory_mb is None:
            if len(self.active_tasks) > 0:
                return False

        # 1. If an exclusive task is currently running, no other task can start
        if self.active_exclusive_task is not None:
            return False

        # 2. If the new task is exclusive or not parallel-safe, it cannot start if any task is running
        if is_exclusive or not parallel_safe:
            if len(self.active_tasks) > 0:
                return False

        # 3. Check max concurrent task slots
        if len(self.active_tasks) >= self.max_concurrent_tasks:
            return False

        # 4. Check CPU capacity limit (only when total_cpus is known)
        if self.total_cpus is not None and (self.reserved_cpus + cpu_weight) > (self.total_cpus + 0.01):
            return False

        # 5. Check Memory capacity limit (only when total_memory_mb is known)
        if self.total_memory_mb is not None and (self.reserved_memory_mb + memory_mb) > self.total_memory_mb:
            return False

        return True

    def reserve(
        self,
        task_id: str,
        cpu_weight: float = 1.0,
        memory_mb: int = 512,
        is_exclusive: bool = False,
        parallel_safe: bool = True
    ) -> bool:
        with self._lock:
            if task_id in self.active_tasks:
                return True  # Already reserved

            if not self._can_schedule_unlocked(cpu_weight, memory_mb, is_exclusive, parallel_safe):
                return False

            self.reserved_cpus += cpu_weight
            self.reserved_memory_mb += memory_mb
            if is_exclusive or not parallel_safe:
                self.active_exclusive_task = task_id

            self.active_tasks[task_id] = {
                "cpu_weight": cpu_weight,
                "memory_mb": memory_mb,
                "is_exclusive": is_exclusive or not parallel_safe,
                "parallel_safe": parallel_safe,
                "reserved_at": datetime.now(timezone.utc).isoformat()
            }
            return True

    def release(self, task_id: str) -> bool:
        with self._lock:
            if task_id not in self.active_tasks:
                return False

            spec = self.active_tasks.pop(task_id)
            self.reserved_cpus = max(0.0, self.reserved_cpus - spec["cpu_weight"])
            self.reserved_memory_mb = max(0, self.reserved_memory_mb - spec["memory_mb"])

            if self.active_exclusive_task == task_id:
                self.active_exclusive_task = None

            return True


class TaskScheduler:
    """
    Controlled Task Scheduler for specialist forensic analysis tasks.
    Enforces DAG dependencies, resource reservations, starvation prevention,
    and deterministic ordering.
    """

    def __init__(self, resource_manager: Optional[ResourceManager] = None):
        self.resource_mgr = resource_manager or ResourceManager()
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.wait_passes: Dict[str, int] = {}
        self._lock = threading.Lock()

    def register_task(
        self,
        task_id: str,
        agent: str,
        tool: str,
        evidence_id: str,
        priority: int = 1,
        dependencies: Optional[List[str]] = None,
        cpu_weight: float = 1.0,
        memory_mb: int = 512,
        is_exclusive: bool = False,
        parallel_safe: bool = True,
        action: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        with self._lock:
            task = {
                "task_id": task_id,
                "step_id": task_id,
                "agent": agent,
                "tool": tool,
                "evidence_id": evidence_id,
                "action": action,
                "priority": priority,
                "dependencies": dependencies or [],
                "cpu_weight": cpu_weight,
                "memory_mb": memory_mb,
                "is_exclusive": is_exclusive,
                "parallel_safe": parallel_safe,
                "parameters": parameters or {},
                "status": "PLANNED",  # PLANNED, READY, RUNNING, COMPLETED, FAILED, CANCELLED
                "created_at": datetime.now(timezone.utc).isoformat(),
                "started_at": None,
                "completed_at": None,
                "error": None,
                "error_message": None
            }
            self.tasks[task_id] = task
            self.wait_passes[task_id] = 0
            return task

    def register_plan(self, plan_tasks: List[Dict[str, Any]]):
        with self._lock:
            for t in plan_tasks:
                task_id = str(t.get("task_id") or t.get("step_id") or t.get("task_key") or "")
                if not task_id:
                    continue

                res_cost = t.get("estimated_resource_cost") or {}
                cpu_weight = t.get("cpu_weight")
                memory_mb = t.get("memory_mb")
                is_exclusive = t.get("is_exclusive")
                parallel_safe = t.get("parallel_safe")

                if cpu_weight is None:
                    cpu_str = str(res_cost.get("cpu", "")).lower()
                    if cpu_str == "high":
                        cpu_weight = 2.0
                    elif cpu_str == "medium":
                        cpu_weight = 1.0
                    else:
                        cpu_weight = 0.5

                if memory_mb is None:
                    ram_str = str(res_cost.get("ram", "")).lower()
                    if ram_str == "high":
                        memory_mb = 2048
                    elif ram_str == "medium":
                        memory_mb = 1024
                    else:
                        memory_mb = 512

                tool_name = str(t.get("tool", "")).lower()
                action_name = str(t.get("action", "")).lower()
                if is_exclusive is None:
                    is_exclusive = (
                        tool_name in ["sleuthkit", "volatility3"]
                        or action_name in ["filesystem_structure_extraction", "process_enumeration"]
                    )

                if parallel_safe is None:
                    parallel_safe = not is_exclusive

                task = dict(t)
                task["task_id"] = task_id
                task["step_id"] = task_id
                task["cpu_weight"] = float(cpu_weight)
                task["memory_mb"] = int(memory_mb)
                task["is_exclusive"] = bool(is_exclusive)
                task["parallel_safe"] = bool(parallel_safe)
                task["status"] = t.get("status", "PLANNED")
                task["dependencies"] = list(t.get("dependencies", []))

                self.tasks[task_id] = task
                if task_id not in self.wait_passes:
                    self.wait_passes[task_id] = 0

    def get_runnable_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            runnable: List[Dict[str, Any]] = []
            completed_step_ids = {
                t_id for t_id, t in self.tasks.items()
                if t.get("status") == "COMPLETED"
            }
            failed_or_cancelled_step_ids = {
                t_id for t_id, t in self.tasks.items()
                if t.get("status") in ["FAILED", "CANCELLED"]
            }

            for task_id, task in self.tasks.items():
                curr_status = task.get("status")
                if curr_status not in ["PLANNED", "READY"]:
                    continue

                deps = [d for d in task.get("dependencies", []) if d in self.tasks]

                # If any prerequisite dependency failed/cancelled, block this task
                if any(dep in failed_or_cancelled_step_ids for dep in deps):
                    task["status"] = "CANCELLED"
                    task["error_message"] = "Dependency not satisfied: prerequisite dependency failed or was cancelled."
                    self.resource_mgr.release(task_id)
                    continue

                # Check if all dependencies are completed
                if all(dep in completed_step_ids for dep in deps):
                    runnable.append(task)

            # Deterministic sorting:
            # 1. Starvation score (highest wait pass count first)
            # 2. Priority (lower integer = higher priority)
            # 3. Evidence ID
            # 4. Task ID / Step ID
            runnable.sort(
                key=lambda t: (
                    -self.wait_passes.get(t["task_id"], 0),
                    t.get("priority", 1),
                    str(t.get("evidence_id", "")),
                    t["task_id"]
                )
            )

            return runnable

    def admit_next_tasks(self, max_batch: int = 10) -> List[Dict[str, Any]]:
        runnable = self.get_runnable_tasks()
        admitted: List[Dict[str, Any]] = []

        for task in runnable:
            if len(admitted) >= max_batch:
                break

            task_id = task["task_id"]
            cpu_w = task.get("cpu_weight", 1.0)
            mem_mb = task.get("memory_mb", 512)
            exclusive = task.get("is_exclusive", False)
            par_safe = task.get("parallel_safe", True)

            success = self.resource_mgr.reserve(
                task_id=task_id,
                cpu_weight=cpu_w,
                memory_mb=mem_mb,
                is_exclusive=exclusive,
                parallel_safe=par_safe
            )

            if success:
                task["status"] = "READY"
                self.wait_passes[task_id] = 0
                admitted.append(task)
            else:
                self.wait_passes[task_id] = self.wait_passes.get(task_id, 0) + 1

        return admitted

    def mark_task_running(self, task_id: str):
        with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "RUNNING"
                self.tasks[task_id]["started_at"] = datetime.now(timezone.utc).isoformat()

    def mark_task_completed(self, task_id: str, artifacts_count: int = 0, findings_count: int = 0):
        with self._lock:
            self.resource_mgr.release(task_id)
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "COMPLETED"
                self.tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                self.tasks[task_id]["artifacts_count"] = artifacts_count
                self.tasks[task_id]["findings_count"] = findings_count

    def mark_task_failed(self, task_id: str, error_message: str):
        with self._lock:
            self.resource_mgr.release(task_id)
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "FAILED"
                self.tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                self.tasks[task_id]["error_message"] = error_message
                self.tasks[task_id]["error"] = error_message

    def mark_task_cancelled(self, task_id: str, reason: str = "Task cancelled", process_terminated: bool = True):
        with self._lock:
            if process_terminated:
                self.resource_mgr.release(task_id)
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "CANCELLED"
                self.tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                self.tasks[task_id]["error_message"] = reason
                self.tasks[task_id]["process_terminated"] = process_terminated

    def mark_task_timed_out(self, task_id: str, error_message: str, process_terminated: bool = True):
        with self._lock:
            if process_terminated:
                self.resource_mgr.release(task_id)
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "TIMED_OUT"
                self.tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                self.tasks[task_id]["error_message"] = error_message
                self.tasks[task_id]["error"] = error_message
                self.tasks[task_id]["process_terminated"] = process_terminated

    def shutdown(self):
        with self._lock:
            for task_id in list(self.tasks.keys()):
                if self.tasks[task_id].get("status") in ["PLANNED", "READY", "RUNNING"]:
                    self.tasks[task_id]["status"] = "CANCELLED"
                    self.tasks[task_id]["error_message"] = "System shutdown initiated."
                    self.resource_mgr.release(task_id)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(t) for t in self.tasks.values()]

    def can_schedule_task(self) -> bool:
        cap = self.resource_mgr.get_system_capacity()
        return cap["available_slots"] > 0
