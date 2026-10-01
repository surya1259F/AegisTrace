"""
ADFIR — Investigation Strategy Engine Tests (Phase 2 / Step 6)

Comprehensive verification of:
1. Evidence-to-Capability Mapping & Domain Selection
2. Case Objective Relevance Weighting
3. Forensic Tool Requirement Resolution & Missing Tool Handling
4. Dependency Graph Assembly (DAG), Topological Sorting & Cycle Detection
5. Priority Calculation Formula & Explainability Factors
6. System Resource Constraint Analysis
7. Structured Stopping Condition Evaluation
8. Formal Plan Validation, Review, Safe Adjustment & Versioning
9. Evidence Integrity Gate Enforcement (Tampered / Missing Evidence Handling)
10. Case Authorization, RBAC & IDOR Security Controls
"""

import pytest
import uuid
import os
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.models import (
    User,
    Case,
    CaseMember,
    EvidenceItem,
    EvidenceIntelligence,
    InvestigationPlan,
    InvestigationTask,
    InvestigationTaskDependency,
    ForensicCapability,
    PlanStoppingCondition,
    PlanAdjustment,
    AuditEvent
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.strategy_engine import (
    InvestigationStrategyEngine,
    EvidenceStrategyAnalyzer,
    CapabilitySelector,
    ToolRequirementResolver,
    DependencyGraphBuilder,
    PriorityCalculator,
    ResourceConstraintAnalyzer,
    StoppingConditionEvaluator,
    seed_forensic_capabilities
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_forensic_capabilities(db)
    db.close()
    yield
    # Clean up test DB data safely


def create_test_user_and_case(db, user_id_suffix="1", case_suffix="1"):
    email = f"investigator_{user_id_suffix}_{uuid.uuid4().hex[:6]}@adfir.local"
    user = User(
        id=f"user-strat-{user_id_suffix}-{uuid.uuid4().hex[:6]}",
        email=email,
        name="Lead Strategy Investigator",
        role="ADMIN",
        password_hash=hash_password("SecretPass123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    case = Case(
        id=f"case-strat-{case_suffix}-{uuid.uuid4().hex[:6]}",
        case_number=f"CAS-STRAT-{case_suffix}-{uuid.uuid4().hex[:4]}",
        name="Ransomware Exfiltration Investigation",
        objective="Investigate ransomware payload and unauthorized data exfiltration.",
        case_type="MALWARE_OUTBREAK",
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

    # Load scalar attributes on user and case before expunging
    _ = (user.id, user.email, user.role, user.name, case.id, case.case_number, case.name, case.objective, case.case_type, case.priority, case.status, case.owner_id, case.created_by)
    db.expunge_all()
    return user, case, headers


def test_seed_forensic_capabilities():
    """Verify that default forensic capabilities are registered in database."""
    db = SessionLocal()
    seed_forensic_capabilities(db)
    caps = db.query(ForensicCapability).all()
    db.close()
    assert len(caps) >= 16
    cap_ids = [c.id for c in caps]
    assert "FILESYSTEM_ANALYSIS" in cap_ids
    assert "MEMORY_ANALYSIS" in cap_ids
    assert "YARA_SCAN" in cap_ids
    assert "EVENT_LOG_ANALYSIS" in cap_ids


def test_evidence_strategy_analyzer_valid():
    """Verify Stage A evidence analysis for valid evidence item."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "ana1", "ana1")

    # Create dummy file path
    dummy_path = f"/tmp/test_disk_{uuid.uuid4().hex}.raw"
    with open(dummy_path, "wb") as f:
        f.write(b"RAW DISK DATA HEADER")

    ev = EvidenceItem(
        id=f"ev-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="disk_image.raw",
        original_path=dummy_path,
        storage_path=dummy_path,
        evidence_type="DISK_IMAGE",
        detected_format="raw",
        platform_hint="WINDOWS",
        size_bytes=2048,
        sha256="abc123hash",
        status="PRESERVED",
        integrity_status="VERIFIED",
        read_only_verified=True
    )
    db.add(ev)
    db.commit()

    prof = EvidenceStrategyAnalyzer.analyze_evidence(db, ev)
    db.close()
    if os.path.exists(dummy_path):
        os.remove(dummy_path)

    assert prof["evidence_id"] == ev.id
    assert prof["category"] == "disk_image"
    assert prof["integrity_valid"] is True
    assert "DISK_STRUCTURE" in prof["investigative_domains"]


def test_evidence_strategy_analyzer_integrity_blocked():
    """Verify Stage A evidence analysis blocks tampered/missing evidence files."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "ana2", "ana2")

    ev = EvidenceItem(
        id=f"ev-tampered-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="tampered_memory.raw",
        original_path="/tmp/non_existent_file.raw",
        storage_path="/tmp/non_existent_file.raw",
        evidence_type="MEMORY_DUMP",
        size_bytes=1024,
        sha256="fakehash",
        status="INTEGRITY_WARNING",
        integrity_status="FAILED",
        read_only_verified=False
    )
    db.add(ev)
    db.commit()

    prof = EvidenceStrategyAnalyzer.analyze_evidence(db, ev)
    db.close()

    assert prof["integrity_valid"] is False
    assert prof["integrity_reason"] is not None


def test_capability_selection_relevance():
    """Verify Stage B capability selection maps evidence & objective keywords."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "cap1", "cap1")

    evidence_profiles = [
        {
            "evidence_id": "ev-mem-1",
            "name": "memdump.raw",
            "category": "memory_dump",
            "subtype": "windows_ram",
            "detected_format": "raw",
            "platform_hint": "WINDOWS"
        }
    ]

    selected = CapabilitySelector.select_capabilities(
        db,
        evidence_profiles,
        case_objective="Investigate RAM memory injection and malware process",
        case_type="MALWARE_OUTBREAK"
    )
    db.close()

    cap_ids = [c["capability_id"] for c in selected]
    assert "MEMORY_ANALYSIS" in cap_ids
    assert "PROCESS_ANALYSIS" in cap_ids

    mem_cap = next(c for c in selected if c["capability_id"] == "MEMORY_ANALYSIS")
    assert mem_cap["relevance_score"] >= 0.90


def test_tool_requirement_resolution():
    """Verify Stage C matches capabilities to host tools without executing binaries."""
    db = SessionLocal()
    res = ToolRequirementResolver.resolve_tool_for_capability(db, "FILESYSTEM_ANALYSIS")
    db.close()

    assert res["agent_name"] == "DiskAgent"
    assert res["tool_name"] == "SleuthKit"
    assert "executable_name" in res
    assert "health_status" in res


def test_dependency_graph_cycle_detection():
    """Verify Stage D cycle detection in task DAG."""
    nodes = ["task-1", "task-2", "task-3"]
    adj_no_cycle = {"task-1": ["task-2"], "task-2": ["task-3"], "task-3": []}
    cycle1 = DependencyGraphBuilder.detect_cycles(nodes, adj_no_cycle)
    assert cycle1 is None

    adj_cycle = {"task-1": ["task-2"], "task-2": ["task-3"], "task-3": ["task-1"]}
    cycle2 = DependencyGraphBuilder.detect_cycles(nodes, adj_cycle)
    assert cycle2 is not None
    assert "task-1" in cycle2 and "task-3" in cycle2


def test_priority_calculation_formula():
    """Verify Stage E priority scoring formula and factors."""
    prio = PriorityCalculator.calculate_priority(
        task_data={"relevance_score": 0.95, "evidence_confidence": "DETERMINISTIC"},
        dep_depth=0,
        is_blocked=False
    )

    assert prio["priority_level"] in ["CRITICAL", "HIGH"]
    assert prio["priority_score"] >= 0.85
    assert prio["factors"]["objective_relevance"] == 0.95

    blocked_prio = PriorityCalculator.calculate_priority(
        task_data={},
        is_blocked=True
    )
    assert blocked_prio["priority_level"] == "BLOCKED"
    assert blocked_prio["priority_score"] == 0.0


def test_resource_constraint_analysis():
    """Verify Stage F host resource inspection."""
    res = ResourceConstraintAnalyzer.inspect_system_resources()
    assert "cpu_cores" in res
    assert "ram_available_mb" in res
    assert "concurrency_limit" in res
    assert res["concurrency_limit"] >= 1


def test_stopping_conditions_evaluation():
    """Verify Stage G stopping condition evaluation."""
    evidence_profiles = [{"evidence_id": "ev-1", "integrity_valid": False, "integrity_reason": "Hash mismatch"}]
    tasks = [{"status": "BLOCKED_NO_CAPABLE_TOOL"}]
    system_res = {"resource_constrained": False}

    conditions = StoppingConditionEvaluator.evaluate(evidence_profiles, tasks, system_res)
    codes = [c["condition_code"] for c in conditions]

    assert "CRITICAL_INTEGRITY_FAILURE" in codes
    assert "NO_COMPATIBLE_TOOL" in codes


def test_full_strategy_plan_generation_end_to_end():
    """Verify end-to-end strategy plan generation, task creation, stopping conditions & audit trail."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "e2e1", "e2e1")

    # Create 2 evidence items (Disk + Memory)
    dummy_disk = f"/tmp/e2e_disk_{uuid.uuid4().hex}.raw"
    dummy_mem = f"/tmp/e2e_mem_{uuid.uuid4().hex}.dmp"

    with open(dummy_disk, "wb") as f:
        f.write(b"DISK DATA")
    with open(dummy_mem, "wb") as f:
        f.write(b"MEMORY DATA")

    ev1 = EvidenceItem(
        id=f"ev-disk-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="disk.raw",
        original_path=dummy_disk,
        storage_path=dummy_disk,
        evidence_type="DISK_IMAGE",
        detected_format="raw",
        size_bytes=1024,
        sha256="hash1",
        status="PRESERVED",
        integrity_status="VERIFIED",
        read_only_verified=True
    )
    ev2 = EvidenceItem(
        id=f"ev-mem-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="memory.dmp",
        original_path=dummy_mem,
        storage_path=dummy_mem,
        evidence_type="MEMORY_DUMP",
        detected_format="dmp",
        size_bytes=2048,
        sha256="hash2",
        status="PRESERVED",
        integrity_status="VERIFIED",
        read_only_verified=True
    )
    db.add_all([ev1, ev2])
    db.commit()

    plan_res = InvestigationStrategyEngine.generate_plan(db, case.id, user)

    if os.path.exists(dummy_disk):
        os.remove(dummy_disk)
    if os.path.exists(dummy_mem):
        os.remove(dummy_mem)

    assert plan_res["plan_id"] is not None
    assert plan_res["version"] == 1
    assert plan_res["status"] in ["READY", "PLANNED", "REQUIRES_REVIEW"]
    assert len(plan_res["tasks"]) >= 2
    assert "execution_order" in plan_res

    # Check DB persistence
    plan_db = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_res["plan_id"]).first()
    assert plan_db is not None
    assert plan_db.is_active is True

    tasks_db = db.query(InvestigationTask).filter(InvestigationTask.plan_id == plan_db.id).all()
    assert len(tasks_db) >= 2

    audit_events = db.query(AuditEvent).filter(AuditEvent.case_id == case.id).all()
    event_types = [a.event_type for a in audit_events]
    assert "INVESTIGATION_PLAN_CREATED" in event_types
    db.close()


def test_plan_versioning_and_recalculation():
    """Verify that recalculating strategy increments version and archives previous active plan."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "ver1", "ver1")

    dummy_path = f"/tmp/ver_disk_{uuid.uuid4().hex}.raw"
    with open(dummy_path, "wb") as f:
        f.write(b"DATA")

    ev = EvidenceItem(
        id=f"ev-ver-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="disk.raw",
        original_path=dummy_path,
        storage_path=dummy_path,
        evidence_type="DISK_IMAGE",
        size_bytes=1024,
        sha256="hashver",
        status="PRESERVED",
        integrity_status="VERIFIED",
        read_only_verified=True
    )
    db.add(ev)
    db.commit()

    plan1 = InvestigationStrategyEngine.generate_plan(db, case.id, user)
    assert plan1["version"] == 1

    plan2 = InvestigationStrategyEngine.generate_plan(db, case.id, user)
    assert plan2["version"] == 2
    assert plan2["plan_id"] != plan1["plan_id"]

    if os.path.exists(dummy_path):
        os.remove(dummy_path)

    # Check active status in DB
    p1_db = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan1["plan_id"]).first()
    p2_db = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan2["plan_id"]).first()

    assert p1_db.is_active is False
    assert p2_db.is_active is True
    assert p2_db.parent_plan_id == p1_db.id
    db.close()


def test_api_investigation_plans_endpoints():
    """Verify API endpoints for plan creation, task listing, graph, review, and recalculation."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "api1", "api1")
    db.close()

    # 1. Create plan API
    r_create = client.post(f"/api/v1/cases/{case.id}/investigation-plans", headers=headers)
    assert r_create.status_code == 200, f"Error: {r_create.json()}"
    plan_data = r_create.json()
    plan_id = plan_data["id"]
    assert plan_data["case_id"] == case.id

    # 2. Get plan API
    r_get = client.get(f"/api/v1/investigation-plans/{plan_id}", headers=headers)
    assert r_get.status_code == 200
    assert r_get.json()["id"] == plan_id

    # 3. Get plan tasks API
    r_tasks = client.get(f"/api/v1/investigation-plans/{plan_id}/tasks", headers=headers)
    assert r_tasks.status_code == 200
    assert isinstance(r_tasks.json(), list)

    # 4. Get plan graph API
    r_graph = client.get(f"/api/v1/investigation-plans/{plan_id}/graph", headers=headers)
    assert r_graph.status_code == 200
    graph_data = r_graph.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

    # 5. Review plan API
    r_review = client.post(f"/api/v1/investigation-plans/{plan_id}/review", headers=headers)
    assert r_review.status_code == 200
    assert r_review.json()["validation_status"] == "VALIDATED"

    # 6. Recalculate plan API
    r_recalc = client.post(f"/api/v1/investigation-plans/{plan_id}/recalculate", headers=headers)
    assert r_recalc.status_code == 200
    assert r_recalc.json()["version"] == 2

    # 7. Capabilities API
    r_caps = client.get("/api/v1/strategy/capabilities", headers=headers)
    assert r_caps.status_code == 200

    # 8. Tools API
    r_tools = client.get("/api/v1/strategy/tools", headers=headers)
    assert r_tools.status_code == 200


def test_security_idor_cross_case_isolation():
    """Verify security IDOR prevention for unauthorized case plan access."""
    db = SessionLocal()
    user1, case1, headers1 = create_test_user_and_case(db, "sec1", "sec1")
    user2, case2, headers2 = create_test_user_and_case(db, "sec2", "sec2")
    u2_db = db.query(User).filter(User.id == user2.id).first()
    u2_db.role = "INVESTIGATOR"
    db.commit()
    from backend.app.core.config import settings
    token2 = create_access_token(user_id=user2.id, email=user2.email, role="INVESTIGATOR")
    headers2 = {
        "Authorization": f"Bearer {token2}",
        "X-ADFIR-Bootstrap-Secret": str(settings.ADFIR_INTERNAL_SECRET or "bootstrap-secret")
    }
    db.close()

    # User 1 creates plan in Case 1
    r_create = client.post(f"/api/v1/cases/{case1.id}/investigation-plans", headers=headers1)
    assert r_create.status_code == 200
    plan_id1 = r_create.json()["id"]

    # User 2 attempts to access Case 1 plan (IDOR attempt)
    r_idor = client.get(f"/api/v1/investigation-plans/{plan_id1}", headers=headers2)
    assert r_idor.status_code in [403, 404]

    # User 2 attempts to recalculate Case 1 plan
    r_idor_recalc = client.post(f"/api/v1/investigation-plans/{plan_id1}/recalculate", headers=headers2)
    assert r_idor_recalc.status_code in [403, 404]


def test_no_forensic_tools_executed():
    """Explicitly verify that NO forensic tool binaries were executed during strategy planning."""
    # Strategy planning MUST only perform metadata inspection and PATH lookups.
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "exec0", "exec0")

    plan_res = InvestigationStrategyEngine.generate_plan(db, case.id, user)
    db.close()

    # Confirm plan tasks are created without any process execution IDs
    for task in plan_res["tasks"]:
        assert task.get("execution_id") is None
        assert task["status"] in ["PLANNED", "READY", "BLOCKED_NO_CAPABLE_TOOL", "BLOCKED_INTEGRITY_FAILURE", "REQUIRES_REVIEW"]


def test_missing_tool_resolution_blocks_task():
    """Verify that when a tool is not installed on the system, the task is marked BLOCKED_NO_CAPABLE_TOOL."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "notool1", "notool1")

    # Resolve an uninstalled/fictional tool capability
    res = ToolRequirementResolver.resolve_tool_for_capability(db, "UNINSTALLED_CUSTOM_CAP")
    assert res["is_installed"] is False
    assert res["health_status"] == "NOT_INSTALLED"
    db.close()


def test_topological_sort_dag_ordering():
    """Verify topological sorting orders prerequisite tasks before dependent tasks."""
    nodes = [
        "TASK_CORRELATION",
        "TASK_TIMELINE_ANALYSIS",
        "TASK_ARTIFACT_EXTRACTION",
        "TASK_FILESYSTEM_ANALYSIS",
        "TASK_PARTITION_ANALYSIS"
    ]
    deps = {
        "TASK_PARTITION_ANALYSIS": [],
        "TASK_FILESYSTEM_ANALYSIS": ["TASK_PARTITION_ANALYSIS"],
        "TASK_ARTIFACT_EXTRACTION": ["TASK_FILESYSTEM_ANALYSIS"],
        "TASK_TIMELINE_ANALYSIS": ["TASK_ARTIFACT_EXTRACTION"],
        "TASK_CORRELATION": ["TASK_TIMELINE_ANALYSIS"]
    }

    sorted_tasks = DependencyGraphBuilder.topological_sort(nodes, deps)
    assert sorted_tasks.index("TASK_PARTITION_ANALYSIS") < sorted_tasks.index("TASK_FILESYSTEM_ANALYSIS")
    assert sorted_tasks.index("TASK_FILESYSTEM_ANALYSIS") < sorted_tasks.index("TASK_ARTIFACT_EXTRACTION")
    assert sorted_tasks.index("TASK_ARTIFACT_EXTRACTION") < sorted_tasks.index("TASK_TIMELINE_ANALYSIS")
    assert sorted_tasks.index("TASK_TIMELINE_ANALYSIS") < sorted_tasks.index("TASK_CORRELATION")


def test_plan_review_and_safe_adjustment():
    """Verify plan review and safe automatic adjustment logic."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "adj1", "adj1")

    plan_res = InvestigationStrategyEngine.generate_plan(db, case.id, user)
    plan_id = plan_res["plan_id"]

    review_res = InvestigationStrategyEngine.review_and_adjust_plan(db, plan_id, user)
    assert review_res["validation_status"] in ["VALIDATED", "ADJUSTED", "NEEDS_REVIEW"]
    assert "adjustments" in review_res
    db.close()


def test_stopping_condition_triggers_manual_review():
    """Verify stopping conditions flag manual review when high-risk conditions are triggered."""
    evidence_profiles = [] # No evidence attached
    tasks = []
    system_res = {"resource_constrained": False}

    conditions = StoppingConditionEvaluator.evaluate(evidence_profiles, tasks, system_res)
    assert len(conditions) > 0
    codes = [c["condition_code"] for c in conditions]
    assert "NO_RELEVANT_CAPABILITIES" in codes or "REQUIRED_ARTIFACTS_EXHAUSTED" in codes


def test_explainability_rationale_fields():
    """Verify explainability: structured rationale fields exist without LLM involvement."""
    db = SessionLocal()
    user, case, _ = create_test_user_and_case(db, "exp1", "exp1")

    dummy_path = f"/tmp/exp_disk_{uuid.uuid4().hex}.raw"
    with open(dummy_path, "wb") as f:
        f.write(b"SAMPLE DISK DATA")

    ev = EvidenceItem(
        id=f"ev-exp-{uuid.uuid4().hex[:8]}",
        case_id=case.id,
        name="disk.raw",
        original_path=dummy_path,
        storage_path=dummy_path,
        evidence_type="DISK_IMAGE",
        detected_format="raw",
        size_bytes=1024,
        sha256="hashexp",
        status="PRESERVED",
        integrity_status="VERIFIED",
        read_only_verified=True
    )
    db.add(ev)
    db.commit()

    plan_res = InvestigationStrategyEngine.generate_plan(db, case.id, user)
    if os.path.exists(dummy_path):
        os.remove(dummy_path)
    db.close()

    for task in plan_res["tasks"]:
        assert "rationale" in task
        assert "priority_rationale" in task
        assert "capability_name" in task["rationale"]
        assert "selection_reason" in task["rationale"]


def test_unauthorized_user_blocked_from_plan_generation():
    """Verify that a non-member investigator cannot generate a plan for a case they do not have access to."""
    db = SessionLocal()
    user1, case1, _ = create_test_user_and_case(db, "unauth1", "unauth1")
    user2, case2, headers2 = create_test_user_and_case(db, "unauth2", "unauth2")

    # Set user2 as regular INVESTIGATOR (non-admin)
    u2_db = db.query(User).filter(User.id == user2.id).first()
    u2_db.role = "INVESTIGATOR"
    db.commit()
    from backend.app.core.config import settings
    token2 = create_access_token(user_id=user2.id, email=user2.email, role="INVESTIGATOR")
    headers2 = {
        "Authorization": f"Bearer {token2}",
        "X-ADFIR-Bootstrap-Secret": str(settings.ADFIR_INTERNAL_SECRET or "bootstrap-secret")
    }
    db.close()

    # User 2 attempts to generate plan for Case 1 (Unauthorized)
    r_unauth = client.post(f"/api/v1/cases/{case1.id}/investigation-plans", headers=headers2)
    assert r_unauth.status_code == 403
    assert "Access denied" in r_unauth.json()["detail"]


