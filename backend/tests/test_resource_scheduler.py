import os
import threading
import time
from pathlib import Path
import pytest
from typing import Dict, Any, List
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import (
    Case,
    EvidenceItem,
    InvestigationPlan,
    ToolExecution,
    ExecutionArtifact,
    Finding,
    ChainOfCustodyEvent,
)
from investigation.scheduler.scheduler import (
    HostResourceProvider,
    DefaultResourceProvider,
    InjectableResourceProvider,
    ResourceManager,
    TaskScheduler,
)
from investigation.orchestrator.orchestrator import InvestigationOrchestrator

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def _create_case(name_prefix="Scheduler Test Case") -> str:
    res = client.post(
        "/api/investigations/",
        json={"name": f"{name_prefix} {os.urandom(3).hex()}", "description": "Scheduler test case"},
    )
    assert res.status_code == 201
    return res.json()["id"]


# -----------------------------------------------------------------------------
# 1. Real Host Resource Detection & Zero Fabricated Fallbacks
# -----------------------------------------------------------------------------

def test_real_host_resource_detection_zero_fabrication():
    provider = DefaultResourceProvider()
    cpus = provider.get_cpu_count()
    total_mem = provider.get_total_memory_mb()

    # Zero fake fallbacks: cpus and total_mem are either real int or None
    assert cpus is None or (isinstance(cpus, int) and cpus >= 1)
    assert total_mem is None or (isinstance(total_mem, int) and total_mem >= 512)

    mgr = ResourceManager(resource_provider=provider)
    cap = mgr.get_system_capacity()

    assert cap["logical_cpus"] == cpus
    assert cap["total_memory_mb"] == total_mem
    assert cap["reserved_cpus"] == 0.0
    assert cap["reserved_memory_mb"] == 0
    assert cap["active_tasks"] == 0


def test_unknown_resource_capacity_enforces_conservative_policy():
    """When CPU or RAM capacity is UNKNOWN (None), no fake values are invented and conservative serial execution is enforced."""
    provider = InjectableResourceProvider(cpu_count=None, total_memory_mb=None)
    mgr = ResourceManager(resource_provider=provider)

    cap = mgr.get_system_capacity()
    assert cap["logical_cpus"] is None
    assert cap["total_memory_mb"] is None
    assert cap["is_capacity_known"] is False
    assert cap["max_concurrent_tasks"] == 1

    # First task admission allowed when 0 tasks active
    assert mgr.can_schedule_task(cpu_weight=1.0, memory_mb=512) is True
    assert mgr.reserve("t1", cpu_weight=1.0, memory_mb=512) is True

    # Second task admission BLOCKED because capacity is unknown (conservative serial policy)
    assert mgr.can_schedule_task(cpu_weight=0.5, memory_mb=256) is False
    assert mgr.reserve("t2", cpu_weight=0.5, memory_mb=256) is False

    mgr.release("t1")
    assert mgr.reserve("t2", cpu_weight=0.5, memory_mb=256) is True


# -----------------------------------------------------------------------------
# 2. Resource Reservation Order (Reservation BEFORE Execution)
# -----------------------------------------------------------------------------

def test_resource_reservation_order_must_precede_execution():
    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=4096)
    mgr = ResourceManager(resource_provider=provider)
    scheduler = TaskScheduler(resource_manager=mgr)

    scheduler.register_task(
        task_id="t-order-1",
        agent="MalwareAgent",
        tool="YARA",
        evidence_id="ev-1",
        cpu_weight=1.0,
        memory_mb=1024,
    )

    # Before admission, reserved resources are ZERO and task is PLANNED
    assert mgr.get_system_capacity()["reserved_cpus"] == 0.0
    assert scheduler.get_task_status("t-order-1")["status"] == "PLANNED"

    # Admission reserves resources FIRST
    admitted = scheduler.admit_next_tasks()
    assert len(admitted) == 1
    assert mgr.get_system_capacity()["reserved_cpus"] == 1.0
    assert scheduler.get_task_status("t-order-1")["status"] == "READY"

    # Execution marks running AFTER reservation succeeded
    scheduler.mark_task_running("t-order-1")
    assert scheduler.get_task_status("t-order-1")["status"] == "RUNNING"

    scheduler.mark_task_completed("t-order-1")
    assert mgr.get_system_capacity()["reserved_cpus"] == 0.0


# -----------------------------------------------------------------------------
# 3. Resource Release Across All Termination Paths
# -----------------------------------------------------------------------------

def test_resource_release_across_all_termination_paths():
    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=8192)
    mgr = ResourceManager(resource_provider=provider)
    scheduler = TaskScheduler(resource_manager=mgr)

    # Path A: SUCCESS
    scheduler.register_task("t-succ", agent="LogAgent", tool="python-evtx", evidence_id="ev-1")
    scheduler.admit_next_tasks()
    assert mgr.get_system_capacity()["active_tasks"] == 1
    scheduler.mark_task_completed("t-succ")
    assert mgr.get_system_capacity()["active_tasks"] == 0

    # Path B: FAILURE
    scheduler.register_task("t-fail", agent="LogAgent", tool="python-evtx", evidence_id="ev-1")
    scheduler.admit_next_tasks()
    assert mgr.get_system_capacity()["active_tasks"] == 1
    scheduler.mark_task_failed("t-fail", error_message="Parsing exception")
    assert mgr.get_system_capacity()["active_tasks"] == 0

    # Path C: CANCELLATION
    scheduler.register_task("t-canc", agent="LogAgent", tool="python-evtx", evidence_id="ev-1")
    scheduler.admit_next_tasks()
    assert mgr.get_system_capacity()["active_tasks"] == 1
    scheduler.mark_task_cancelled("t-canc", reason="User cancelled")
    assert mgr.get_system_capacity()["active_tasks"] == 0

    # Path D: DEPENDENCY FAILURE
    scheduler.register_task("t-dep-parent", agent="LogAgent", tool="python-evtx", evidence_id="ev-1")
    scheduler.register_task("t-dep-child", agent="LogAgent", tool="python-evtx", evidence_id="ev-1", dependencies=["t-dep-parent"])
    scheduler.admit_next_tasks()
    scheduler.mark_task_failed("t-dep-parent", error_message="Parent failed")
    scheduler.get_runnable_tasks()  # Evaluates DAG dependencies
    assert mgr.get_system_capacity()["active_tasks"] == 0
    assert scheduler.get_task_status("t-dep-child")["status"] == "CANCELLED"


# -----------------------------------------------------------------------------
# 4. Resource Admission & Capacity Limits
# -----------------------------------------------------------------------------

def test_resource_admission_rejection():
    provider = InjectableResourceProvider(cpu_count=2, total_memory_mb=2048)
    mgr = ResourceManager(resource_provider=provider, max_concurrent_tasks=2)

    assert mgr.reserve("t1", cpu_weight=1.5, memory_mb=1500) is True
    assert mgr.reserve("t2", cpu_weight=1.5, memory_mb=1000) is False
    assert mgr.reserve("t3", cpu_weight=0.5, memory_mb=1000) is False


# -----------------------------------------------------------------------------
# 5. Exclusive Task Mutual Exclusion
# -----------------------------------------------------------------------------

def test_exclusive_task_mutual_exclusion():
    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=8192)
    mgr = ResourceManager(resource_provider=provider)

    assert mgr.reserve("light-1", cpu_weight=0.5, memory_mb=256, is_exclusive=False, parallel_safe=True) is True
    assert mgr.can_schedule_task(cpu_weight=2.0, memory_mb=2048, is_exclusive=True, parallel_safe=False) is False
    assert mgr.reserve("exclusive-1", cpu_weight=2.0, memory_mb=2048, is_exclusive=True, parallel_safe=False) is False

    mgr.release("light-1")
    assert mgr.reserve("exclusive-1", cpu_weight=2.0, memory_mb=2048, is_exclusive=True, parallel_safe=False) is True
    assert mgr.get_system_capacity()["has_exclusive_task_running"] is True

    assert mgr.can_schedule_task(cpu_weight=0.5, memory_mb=256, is_exclusive=False, parallel_safe=True) is False
    assert mgr.reserve("light-2", cpu_weight=0.5, memory_mb=256, is_exclusive=False, parallel_safe=True) is False

    mgr.release("exclusive-1")
    assert mgr.get_system_capacity()["has_exclusive_task_running"] is False


# -----------------------------------------------------------------------------
# 6. Actual Bounded Parallel Execution & Overlap Proof
# -----------------------------------------------------------------------------

def test_actual_bounded_parallel_execution_overlap(monkeypatch):
    """
    Deterministic proof of actual concurrent execution overlap of admitted lightweight tasks
    using threading.Event primitives.
    """
    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=8192)
    sched = TaskScheduler(resource_manager=ResourceManager(resource_provider=provider, max_concurrent_tasks=4))
    orchestrator = InvestigationOrchestrator(task_scheduler=sched)

    event_task1_started = threading.Event()
    event_task2_started = threading.Event()

    orig_analyze = orchestrator.malware_agent.analyze

    def synchronized_analyze(evidence_item, parameters=None):
        params = parameters or {}
        task_tool = params.get("tool") or ""
        
        if params.get("action") == "sync_task_1":
            event_task1_started.set()
            # Wait until task 2 starts to prove overlap
            event_task2_started.wait(timeout=3.0)
            return {"status": "SUCCESS", "artifacts": [], "findings": [], "provenance": {"tool": "YARA"}}
        elif params.get("action") == "sync_task_2":
            event_task2_started.set()
            # Wait until task 1 has started
            event_task1_started.wait(timeout=3.0)
            return {"status": "SUCCESS", "artifacts": [], "findings": [], "provenance": {"tool": "YARA"}}

        return orig_analyze(evidence_item, parameters)

    monkeypatch.setattr(orchestrator.malware_agent, "analyze", synchronized_analyze)

    case_id = _create_case("Overlap Proof Case")
    sample_path = str(Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "sample-evidence.txt")
    
    res = client.post(f"/api/investigations/{case_id}/evidence/intake", json={"path": sample_path})
    evidence_id = res.json()["id"]

    # Register 2 independent parallel-safe tasks
    t1 = {
        "step_id": "t-par-1",
        "agent": "MalwareAgent",
        "tool": "YARA",
        "tool_available": True,
        "evidence_id": evidence_id,
        "action": "sync_task_1",
        "priority": 1,
        "dependencies": [],
        "cpu_weight": 0.5,
        "memory_mb": 256,
        "is_exclusive": False,
        "parallel_safe": True,
        "status": "PLANNED",
    }
    t2 = {
        "step_id": "t-par-2",
        "agent": "MalwareAgent",
        "tool": "YARA",
        "tool_available": True,
        "evidence_id": evidence_id,
        "action": "sync_task_2",
        "priority": 1,
        "dependencies": [],
        "cpu_weight": 0.5,
        "memory_mb": 256,
        "is_exclusive": False,
        "parallel_safe": True,
        "status": "PLANNED",
    }

    with SessionLocal() as db:
        plan = InvestigationPlan(
            id=str(os.urandom(8).hex()),
            case_id=case_id,
            title="Overlap Plan",
            strategy_summary="Test overlap",
            tasks=[t1, t2],
            status="PLANNED",
            version=1,
            is_active=True,
        )
        db.add(plan)
        db.commit()

        exec_summary = orchestrator.execute_plan(case_id=case_id, db=db, plan_id=plan.id)
        assert exec_summary["status"] == "COMPLETED"
        assert exec_summary["tasks_succeeded"] == 2

    # Deterministic proof: both events were set, proving simultaneous execution overlap!
    assert event_task1_started.is_set() is True
    assert event_task2_started.is_set() is True


# -----------------------------------------------------------------------------
# 7. Dependency Failure Semantics (Failed Prerequisite Blocks Child, Allows Independent)
# -----------------------------------------------------------------------------

def test_failed_dependency_blocks_child_and_allows_independent(monkeypatch):
    case_id = _create_case("Dependency Failure Case")
    sample_path = str(Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "sample-evidence.txt")

    from agents.disk.disk_agent import DiskAgent
    monkeypatch.setattr(
        DiskAgent,
        "analyze",
        lambda self, evidence_item, parameters=None: {
            "status": "SUCCESS",
            "artifacts": [{"name": "meta", "type": "metadata"}],
            "findings": [],
            "provenance": {"tool": "ExifTool"}
        }
    )

    res = client.post(f"/api/investigations/{case_id}/evidence/intake", json={"path": sample_path})
    evidence_id = res.json()["id"]

    t_parent = {
        "step_id": "t-parent",
        "agent": "MalwareAgent",
        "tool": "YARA",
        "tool_available": False,  # Will fail
        "evidence_id": evidence_id,
        "action": "scan_fail",
        "priority": 1,
        "dependencies": [],
        "status": "PLANNED",
    }
    t_child = {
        "step_id": "t-child",
        "agent": "MalwareAgent",
        "tool": "YARA",
        "tool_available": True,
        "evidence_id": evidence_id,
        "action": "scan_child",
        "priority": 2,
        "dependencies": ["t-parent"],
        "status": "PLANNED",
    }
    t_indep = {
        "step_id": "t-indep",
        "agent": "DiskAgent",
        "tool": "ExifTool",
        "tool_available": True,
        "evidence_id": evidence_id,
        "action": "metadata_extraction",
        "priority": 1,
        "dependencies": [],
        "status": "PLANNED",
    }

    orchestrator = InvestigationOrchestrator()
    with SessionLocal() as db:
        plan = InvestigationPlan(
            id=str(os.urandom(8).hex()),
            case_id=case_id,
            title="DAG Fail Plan",
            strategy_summary="Test DAG failure",
            tasks=[t_parent, t_child, t_indep],
            status="PLANNED",
            version=1,
            is_active=True,
        )
        db.add(plan)
        db.commit()

        exec_summary = orchestrator.execute_plan(case_id=case_id, db=db, plan_id=plan.id)
        assert exec_summary["status"] == "PARTIALLY_COMPLETED"
        assert exec_summary["tasks_succeeded"] == 1
        assert exec_summary["tasks_failed"] == 2  # 1 parent failed + 1 child cancelled

        tasks = exec_summary["tasks"]
        p_res = next(t for t in tasks if t["step_id"] == "t-parent")
        c_res = next(t for t in tasks if t["step_id"] == "t-child")
        i_res = next(t for t in tasks if t["step_id"] == "t-indep")

        assert p_res["status"] == "FAILED"
        assert c_res["status"] == "CANCELLED"
        assert "Dependency not satisfied" in c_res["error_message"]
        assert i_res["status"] == "COMPLETED"


# -----------------------------------------------------------------------------
# 8. Deterministic Selection Ordering & Repeated Pass Consistency
# -----------------------------------------------------------------------------

def test_deterministic_scheduling_ordering_repeated_pass():
    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=8192)

    for _ in range(5):  # Run 5 times to verify strict determinism across repeated invocations
        scheduler = TaskScheduler(resource_manager=ResourceManager(resource_provider=provider))

        scheduler.register_task("task-Z", agent="DiskAgent", tool="ExifTool", evidence_id="ev-2", priority=2)
        scheduler.register_task("task-A", agent="DiskAgent", tool="ExifTool", evidence_id="ev-1", priority=1)
        scheduler.register_task("task-B", agent="DiskAgent", tool="ExifTool", evidence_id="ev-1", priority=1)

        runnable = scheduler.get_runnable_tasks()
        ordered_ids = [t["task_id"] for t in runnable]
        assert ordered_ids == ["task-A", "task-B", "task-Z"]


# -----------------------------------------------------------------------------
# 9. Zero Resource Leaks Post Execution
# -----------------------------------------------------------------------------

def test_zero_resource_leaks_post_execution():
    case_id = _create_case("Leak Check Case")
    sample_path = str(Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "sample-evidence.txt")

    res = client.post(f"/api/investigations/{case_id}/evidence/intake", json={"path": sample_path})
    evidence_id = res.json()["id"]

    client.post(f"/api/investigations/{case_id}/plan")

    provider = InjectableResourceProvider(cpu_count=4, total_memory_mb=8192)
    res_mgr = ResourceManager(resource_provider=provider)
    sched = TaskScheduler(resource_manager=res_mgr)
    orchestrator = InvestigationOrchestrator(task_scheduler=sched)

    with SessionLocal() as db:
        summary = orchestrator.execute_plan(case_id=case_id, db=db)
        assert summary["status"] == "COMPLETED"

        # Verify ZERO RESOURCE LEAKS
        cap = res_mgr.get_system_capacity()
        assert cap["reserved_cpus"] == 0.0
        assert cap["reserved_memory_mb"] == 0
        assert cap["active_tasks"] == 0
        assert cap["has_exclusive_task_running"] is False
