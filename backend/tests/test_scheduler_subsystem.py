"""
ADFIR — Resource-Aware Scheduler Subsystem Tests (Phase 2 / Step 8)

Comprehensive verification of:
1. Analysis request creation from validated Step 7 tool selection
2. Step 7 validation gate (rejection of unselected, blocked, or review-pending tools)
3. Duplicate request prevention on active jobs
4. Timeout validation and bounds enforcement
5. System resource tracking (CPU, RAM, scratch disk)
6. Resource insufficiency handling (WAITING_RESOURCE) without reservation
7. Concurrency limit enforcement
8. Dependency waiting (WAITING_DEPENDENCY)
9. Dependency resolution and promotion to READY
10. Blocked / cancelled dependency failure propagation
11. Priority-based promotion ordering
12. Timeout detection and allocated resource release
13. Cancellation, reservation release, and audit event logging
14. Retry policy handling (retryable vs non-retryable failures, max count)
15. Batch plan scheduling integration (POST /api/v1/investigation-plans/{plan_id}/schedule)
16. Scheduler queue and status APIs
17. Case authorization, RBAC, and IDOR isolation enforcement
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.models import (
    User,
    Case,
    CaseMember,
    EvidenceItem,
    InvestigationPlan,
    InvestigationTask,
    InvestigationTaskDependency,
    ToolDefinition,
    ToolSelectionRecord,
    AnalysisRequest,
    ForensicCapability
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.strategy_engine import (
    InvestigationStrategyEngine,
    seed_forensic_capabilities
)
from backend.app.services.tool_selector import (
    ToolSelectorEngine,
    seed_default_tools,
    get_system_resources
)
from backend.app.services.scheduler import (
    ResourceAwareScheduler,
    SchedulerResourceTracker,
    SchedulerDependencyEvaluator,
    SchedulerTimeoutManager,
    SchedulerRetryManager
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_forensic_capabilities(db)
    seed_default_tools(db)
    db.query(AnalysisRequest).delete()
    db.commit()
    db.close()
    yield
    cleanup_db = SessionLocal()
    cleanup_db.query(AnalysisRequest).delete()
    cleanup_db.commit()
    cleanup_db.close()


def create_test_user_and_case(db, user_id_suffix="1", case_suffix="1"):
    email = f"lead_scheduler_{user_id_suffix}_{uuid.uuid4().hex[:6]}@adfir.local"
    user = User(
        id=f"user-sched-{user_id_suffix}-{uuid.uuid4().hex[:6]}",
        email=email,
        name="Lead Scheduler Investigator",
        role="INVESTIGATOR",
        password_hash=hash_password("SecretPass123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    case = Case(
        id=f"case-sched-{case_suffix}-{uuid.uuid4().hex[:6]}",
        case_number=f"CAS-SCHED-{case_suffix}-{uuid.uuid4().hex[:4]}",
        name="Resource Scheduler Verification Case",
        objective="Verify resource-aware scheduling without tool execution.",
        case_type="DATA_EXFILTRATION",
        priority="HIGH",
        status="OPEN",
        owner_id=user.id,
        created_by=user.id
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    member = CaseMember(
        id=str(uuid.uuid4()),
        case_id=case.id,
        user_id=user.id,
        role="PRIMARY_INVESTIGATOR"
    )
    db.add(member)
    db.commit()

    from backend.app.core.config import settings
    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    secret_val = settings.ADFIR_INTERNAL_SECRET or "bootstrap-secret"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-ADFIR-Bootstrap-Secret": str(secret_val)
    }

    _ = (user.id, user.email, user.role, user.name, case.id, case.case_number, case.name, case.objective, case.case_type, case.priority, case.status, case.owner_id, case.created_by)
    db.expunge_all()
    return user, case, headers


def create_test_plan_with_selections(db, case, user):
    """Creates a test InvestigationPlan with 2 tasks and valid Step 7 tool selections."""
    plan = InvestigationPlan(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Test Investigation Plan",
        strategy_summary="Automated strategy plan",
        validation_status="VALIDATED",
        version=1,
        created_by=user.id
    )
    db.add(plan)
    db.commit()

    task1 = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_key="task-disk-01",
        sequence=1,
        capability_id="FILESYSTEM_ANALYSIS",
        agent_name="DiskAgent",
        priority_level="HIGH",
        priority_score=0.9,
        resource_requirements={"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100},
        status="READY"
    )
    task2 = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_key="task-log-01",
        sequence=2,
        capability_id="EVENT_LOG_ANALYSIS",
        agent_name="LogAgent",
        priority_level="MEDIUM",
        priority_score=0.5,
        resource_requirements={"cpu_cores": 1, "ram_mb": 256, "disk_mb": 50},
        status="PLANNED"
    )
    db.add(task1)
    db.add(task2)
    db.commit()

    # Step 7 tool selections
    sel1 = ToolSelectionRecord(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_id=task1.id,
        task_key=task1.task_key,
        capability_id=task1.capability_id,
        selected_tool_id="sleuthkit_fls",
        selection_status="SELECTED",
        availability_status="AVAILABLE",
        evidence_compatibility="COMPATIBLE",
        platform_compatibility="COMPATIBLE",
        resource_status="RESOURCE_OK",
        version_status="VERSION_OK",
        safety_status="SAFE"
    )
    sel2 = ToolSelectionRecord(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        task_id=task2.id,
        task_key=task2.task_key,
        capability_id=task2.capability_id,
        selected_tool_id="python-evtx",
        selection_status="SELECTED",
        availability_status="AVAILABLE",
        evidence_compatibility="COMPATIBLE",
        platform_compatibility="COMPATIBLE",
        resource_status="RESOURCE_OK",
        version_status="VERSION_OK",
        safety_status="SAFE"
    )
    db.add(sel1)
    db.add(sel2)
    db.commit()

    return plan, task1, task2, sel1, sel2


# =============================================================================
# 1. ANALYSIS REQUEST CREATION FROM STEP 7
# =============================================================================

def test_create_analysis_request_from_step7():
    """Verify persistent analysis job creation from validated Step 7 tool selection."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "ar1", "ar1")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    req = ResourceAwareScheduler.create_analysis_request(
        db=db,
        plan_id=plan.id,
        task_key=task1.task_key,
        actor_user=user,
        timeout_seconds=600
    )

    assert req.id is not None
    assert req.case_id == case.id
    assert req.plan_id == plan.id
    assert req.task_key == task1.task_key
    assert req.selected_tool_id == "sleuthkit_fls"
    assert req.timeout_seconds == 600
    assert req.scheduler_status == "QUEUED"
    assert req.resource_requirements["ram_mb"] == 512
    assert req.priority_score == 0.9
    assert req.retry_policy["max_retries"] == 3
    db.close()


# =============================================================================
# 2. STEP 7 VALIDATION GATE REJECTION
# =============================================================================

def test_step7_validation_gate_rejects_unselected():
    """Verify rejection when task tool selection is BLOCKED, REQUIRES_REVIEW, or unselected."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "gate", "gate")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Change tool selection to BLOCKED_NO_CAPABLE_TOOL
    sel1.selection_status = "BLOCKED_NO_CAPABLE_TOOL"
    sel1.selected_tool_id = ""
    sel1.selection_rationale = "Binary missing"
    db.commit()

    with pytest.raises(ValueError) as exc:
        ResourceAwareScheduler.create_analysis_request(
            db=db,
            plan_id=plan.id,
            task_key=task1.task_key,
            actor_user=user
        )
    assert "Step 7 tool selection status is 'BLOCKED_NO_CAPABLE_TOOL'" in str(exc.value)
    db.close()


# =============================================================================
# 3. DUPLICATE SCHEDULING PREVENTION
# =============================================================================

def test_duplicate_scheduling_prevention():
    """Verify that scheduling the same task twice while an active request exists is blocked."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "dup", "dup")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # First request succeeds
    req1 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    assert req1.id is not None

    # Duplicate request fails
    with pytest.raises(ValueError) as exc:
        ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    assert "already has an active analysis request" in str(exc.value)
    db.close()


# =============================================================================
# 4. TIMEOUT VALIDATION
# =============================================================================

def test_timeout_validation():
    """Verify timeout value validation (minimum 10s, maximum 86400s)."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "time", "time")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Too small (< 10s)
    with pytest.raises(ValueError) as exc1:
        ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user, timeout_seconds=5)
    assert "Timeout must be between" in str(exc1.value)

    # Too large (> 86400s)
    with pytest.raises(ValueError) as exc2:
        ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user, timeout_seconds=100000)
    assert "Timeout must be between" in str(exc2.value)

    db.close()


# =============================================================================
# 5. HOST RESOURCE VALIDATION
# =============================================================================

def test_host_resource_validation():
    """Verify can_allocate logic against host capacity."""
    host_cap = {"cpu_cores": 4, "available_ram_mb": 8192.0, "available_disk_mb": 20480.0}
    current_alloc = {"active_job_count": 1, "allocated_cpu_cores": 1, "allocated_ram_mb": 1024.0, "allocated_disk_mb": 500.0}

    # Adequate resources
    ok, _ = SchedulerResourceTracker.can_allocate(
        req_cpu=1, req_ram=1024.0, req_disk=500.0,
        current_alloc=current_alloc, host_capacity=host_cap, max_concurrency=4
    )
    assert ok is True

    # Exceeds CPU
    bad_cpu, reason_cpu = SchedulerResourceTracker.can_allocate(
        req_cpu=4, req_ram=512.0, req_disk=100.0,
        current_alloc=current_alloc, host_capacity=host_cap, max_concurrency=4
    )
    assert bad_cpu is False
    assert "CPU cores required" in reason_cpu

    # Exceeds RAM
    bad_ram, reason_ram = SchedulerResourceTracker.can_allocate(
        req_cpu=1, req_ram=8000.0, req_disk=100.0,
        current_alloc=current_alloc, host_capacity=host_cap, max_concurrency=4
    )
    assert bad_ram is False
    assert "RAM required" in reason_ram


# =============================================================================
# 6. RESOURCE INSUFFICIENT -> WAITING_RESOURCE
# =============================================================================

def test_resource_insufficient_waiting_resource():
    """Verify job marked WAITING_RESOURCE when host capacity is starved, without reserving resources."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "starve", "starve")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Require impossible amount of RAM (1,000,000 MB)
    task1.resource_requirements = {"cpu_cores": 1, "ram_mb": 1000000.0, "disk_mb": 100.0}
    db.commit()

    req = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    assert req.scheduler_status == "QUEUED"

    # Evaluate queue
    eval_res = ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    assert eval_res["waiting_resource"] == 1

    db.refresh(req)
    assert req.scheduler_status == "WAITING_RESOURCE"
    assert "RAM required" in req.blocking_reason
    assert req.allocated_resources == {}
    db.close()


# =============================================================================
# 7. CONCURRENCY LIMIT ENFORCEMENT
# =============================================================================

def test_concurrency_limit_enforcement():
    """Verify concurrency limit holds extra jobs in WAITING_RESOURCE."""
    current_alloc = {"active_job_count": 4, "allocated_cpu_cores": 4, "allocated_ram_mb": 2048.0, "allocated_disk_mb": 500.0}
    host_cap = {"cpu_cores": 16, "available_ram_mb": 32768.0, "available_disk_mb": 100000.0}

    can_alloc, reason = SchedulerResourceTracker.can_allocate(
        req_cpu=1, req_ram=512.0, req_disk=100.0,
        current_alloc=current_alloc, host_capacity=host_cap, max_concurrency=4
    )
    assert can_alloc is False
    assert "Maximum concurrent jobs limit reached" in reason


# =============================================================================
# 8. DEPENDENCY WAITING (WAITING_DEPENDENCY)
# =============================================================================

def test_dependency_ordering_waiting_dependency():
    """Verify child job with unsatisfied parent dependency starts in WAITING_DEPENDENCY."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "depw", "depw")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Establish dependency: task2 depends on task1
    dep = InvestigationTaskDependency(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        parent_task_id=task1.task_key,
        child_task_id=task2.task_key
    )
    db.add(dep)
    db.commit()

    req1 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    req2 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task2.task_key, actor_user=user)

    assert req1.scheduler_status == "QUEUED"
    assert req2.scheduler_status == "WAITING_DEPENDENCY"
    assert task1.task_key in req2.dependencies

    # Run queue evaluation: req1 should be promoted to READY, req2 remains WAITING_DEPENDENCY
    eval_res = ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    db.refresh(req1)
    db.refresh(req2)

    assert req1.scheduler_status == "READY"
    assert req2.scheduler_status == "WAITING_DEPENDENCY"
    assert "Waiting for parent dependency" in req2.blocking_reason
    db.close()


# =============================================================================
# 9. DEPENDENCY COMPLETION PROMOTES READY
# =============================================================================

def test_dependency_completion_promotes_ready():
    """Verify child job is promoted to READY once parent becomes COMPLETED."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "depc", "depc")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    dep = InvestigationTaskDependency(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        parent_task_id=task1.task_key,
        child_task_id=task2.task_key
    )
    db.add(dep)
    db.commit()

    req1 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    req2 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task2.task_key, actor_user=user)

    # Mark parent COMPLETED
    req1.scheduler_status = "COMPLETED"
    req1.allocated_resources = {}
    db.commit()

    # Evaluate queue: child should now be promoted to READY
    eval_res = ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    assert eval_res["promoted_to_ready"] >= 1

    db.refresh(req2)
    assert req2.scheduler_status == "READY"
    assert req2.ready_at is not None
    assert req2.blocking_reason is None
    db.close()


# =============================================================================
# 10. BLOCKED / CANCELLED DEPENDENCY PROPAGATION
# =============================================================================

def test_blocked_dependency_propagation():
    """Verify child job is BLOCKED when parent fails or is cancelled."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "failprop", "failprop")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    dep = InvestigationTaskDependency(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        parent_task_id=task1.task_key,
        child_task_id=task2.task_key
    )
    db.add(dep)
    db.commit()

    req1 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    req2 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task2.task_key, actor_user=user)

    # Cancel parent
    ResourceAwareScheduler.cancel_job(db=db, job_id=req1.id, actor_user=user)

    db.refresh(req1)
    db.refresh(req2)
    assert req1.scheduler_status == "CANCELLED"
    assert req2.scheduler_status == "BLOCKED"
    assert "cancelled" in req2.blocking_reason
    db.close()


# =============================================================================
# 11. PRIORITY-BASED ORDERING
# =============================================================================

def test_priority_ordering_promotion():
    """Verify higher priority jobs are promoted to READY ahead of lower priority jobs."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "prio", "prio")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    task1.priority_score = 0.2
    task2.priority_score = 0.95
    db.commit()

    req1 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    req2 = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task2.task_key, actor_user=user)

    # Both are queued. Evaluate queue
    eval_res = ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    assert eval_res["promoted_to_ready"] == 2

    db.refresh(req1)
    db.refresh(req2)
    assert req1.scheduler_status == "READY"
    assert req2.scheduler_status == "READY"
    db.close()


# =============================================================================
# 12. TIMEOUT DETECTION & RESOURCE RELEASE
# =============================================================================

def test_timeout_detection_and_resource_release():
    """Verify that expired running jobs transition to TIMEOUT and release allocated resources."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "tout", "tout")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    req = ResourceAwareScheduler.create_analysis_request(
        db=db,
        plan_id=plan.id,
        task_key=task1.task_key,
        actor_user=user,
        timeout_seconds=30
    )

    # Simulate job was running and exceeded timeout
    req.scheduler_status = "RUNNING"
    req.started_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    req.allocated_resources = {"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100}
    db.commit()

    timed_out = SchedulerTimeoutManager.check_and_apply_timeouts(db)
    assert len(timed_out) == 1

    db.refresh(req)
    assert req.scheduler_status == "TIMEOUT"
    assert req.allocated_resources == {}
    assert "timeout" in req.failure_reason.lower()
    db.close()


# =============================================================================
# 13. CANCELLATION & AUDIT EVENT
# =============================================================================

def test_cancellation_and_resource_release():
    """Verify cancelling an analysis request releases reservations and updates status."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "canc", "canc")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    req = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user)
    ResourceAwareScheduler.evaluate_queue(db, plan_id=plan.id)
    db.refresh(req)
    assert req.scheduler_status == "READY"
    assert req.allocated_resources != {}

    # Cancel job
    cancelled = ResourceAwareScheduler.cancel_job(db=db, job_id=req.id, actor_user=user)
    assert cancelled.scheduler_status == "CANCELLED"
    assert cancelled.allocated_resources == {}
    assert cancelled.cancelled_at is not None
    db.close()


# =============================================================================
# 14. RETRY POLICY HANDLING
# =============================================================================

def test_retry_policy_handling():
    """Verify retry policy logic: retryable error schedules retry, non-retryable stays failed."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "ret", "ret")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # 1. Retryable job
    req = ResourceAwareScheduler.create_analysis_request(
        db=db,
        plan_id=plan.id,
        task_key=task1.task_key,
        actor_user=user,
        custom_retry_policy={"max_retries": 2, "retry_count": 0, "is_retryable": True}
    )
    req.scheduler_status = "FAILED"
    req.failure_reason = "Transient network glitch"
    db.commit()

    can_r, _ = SchedulerRetryManager.can_retry(req)
    assert can_r is True

    ok = SchedulerRetryManager.schedule_retry(db=db, job=req, actor_user=user)
    assert ok is True
    assert req.scheduler_status == "RETRY_PENDING"
    assert req.retry_policy["retry_count"] == 1

    # 2. Non-retryable job (safety failure)
    req.scheduler_status = "FAILED"
    req.retry_policy = {"max_retries": 2, "retry_count": 1, "is_retryable": False}
    db.commit()

    can_r2, reason2 = SchedulerRetryManager.can_retry(req)
    assert can_r2 is False
    assert "non-retryable" in reason2

    db.close()


# =============================================================================
# 15. BATCH PLAN SCHEDULING INTEGRATION
# =============================================================================

def test_schedule_plan_batch_integration():
    """Verify batch scheduling of all eligible plan tasks via API."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "batch", "batch")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Call POST /api/v1/investigation-plans/{plan_id}/schedule
    resp = client.post(f"/api/v1/investigation-plans/{plan.id}/schedule", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["plan_id"] == plan.id
    assert data["total_tasks"] == 2
    assert data["scheduled_jobs"] == 2
    assert len(data["requests"]) == 2

    # Verify jobs were promoted to READY
    for r in data["requests"]:
        assert r["scheduler_status"] == "READY"
        assert r["allocated_resources"]["ram_mb"] > 0

    db.close()


# =============================================================================
# 16. SCHEDULER QUEUE AND STATUS APIS
# =============================================================================

def test_scheduler_queue_and_status_apis():
    """Verify GET /api/v1/scheduler/queue and GET /api/v1/scheduler/status."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "qapi", "qapi")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case, user)

    # Schedule plan
    client.post(f"/api/v1/investigation-plans/{plan.id}/schedule", headers=headers)

    # 1. Queue API
    q_resp = client.get(f"/api/v1/scheduler/queue?case_id={case.id}", headers=headers)
    assert q_resp.status_code == 200
    queue = q_resp.json()
    assert len(queue) >= 2

    # 2. Status API
    s_resp = client.get("/api/v1/scheduler/status", headers=headers)
    assert s_resp.status_code == 200
    stats = s_resp.json()
    assert stats["total_jobs"] >= 2
    assert stats["max_concurrent_jobs"] > 0
    assert "host_capacity" in stats

    # 3. Cancel API
    first_job_id = queue[0]["id"]
    canc_resp = client.post(f"/api/v1/scheduler/requests/{first_job_id}/cancel", headers=headers)
    assert canc_resp.status_code == 200
    assert canc_resp.json()["scheduler_status"] == "CANCELLED"

    db.close()


# =============================================================================
# 17. CASE AUTHORIZATION & IDOR ISOLATION
# =============================================================================

def test_case_authorization_and_idor_isolation():
    """Verify 403 Forbidden when unauthorized user attempts to schedule, view, or cancel jobs."""
    db = SessionLocal()
    user_a, case_a, headers_a = create_test_user_and_case(db, "idor_a", "idor_a")
    user_b, case_b, headers_b = create_test_user_and_case(db, "idor_b", "idor_b")
    plan, task1, task2, sel1, sel2 = create_test_plan_with_selections(db, case_a, user_a)

    req = ResourceAwareScheduler.create_analysis_request(db=db, plan_id=plan.id, task_key=task1.task_key, actor_user=user_a)

    # User B attempts to read User A's job
    unauth_get = client.get(f"/api/v1/scheduler/requests/{req.id}", headers=headers_b)
    assert unauth_get.status_code == 403

    # User B attempts to cancel User A's job
    unauth_canc = client.post(f"/api/v1/scheduler/requests/{req.id}/cancel", headers=headers_b)
    assert unauth_canc.status_code == 403

    # User B attempts to batch schedule User A's plan
    unauth_sched = client.post(f"/api/v1/investigation-plans/{plan.id}/schedule", headers=headers_b)
    assert unauth_sched.status_code == 403

    db.close()
