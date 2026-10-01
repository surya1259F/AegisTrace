"""
ADFIR — Capability / Tool Selection Subsystem Tests (Phase 2 / Step 7)

Comprehensive verification of:
1. Capability registry matching against Evidence Intelligence data
2. Evidence type and format compatibility verification
3. Tool availability detection (AVAILABLE, UNAVAILABLE, DISABLED, MISSING)
4. Platform compatibility validation (Linux, Windows, macOS)
5. System resource validation (RESOURCE_OK, RESOURCE_CONSTRAINED, RESOURCE_INSUFFICIENT)
6. Tool version compatibility verification (semver constraints)
7. Safety profile enforcement (read-only, shell=False, DISALLOWED_BINARIES)
8. Incompatible tool rejection recording with structured reasons
9. Unavailable tool handling without fake execution
10. Multi-candidate tool ranking and deterministic selection
11. Unsatisfied task status handling (BLOCKED_NO_CAPABLE_TOOL, REQUIRES_REVIEW)
12. Registry validation service and API (orphaned capability/tool detection)
13. Step 6 strategy plan integration and task state updates
14. Case authorization, RBAC, and IDOR isolation enforcement
"""

import pytest
import uuid
import os
import sys
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
    ForensicCapability,
    ToolDefinition as DBToolDefinition,
    ToolSelectionRecord
)
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.strategy_engine import (
    InvestigationStrategyEngine,
    seed_forensic_capabilities
)
from backend.app.services.tool_selector import (
    ToolSelectorEngine,
    CapabilityMatcher,
    ToolEvaluator,
    seed_default_tools,
    get_system_resources,
    get_host_platform
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_forensic_capabilities(db)
    seed_default_tools(db)
    db.close()
    yield


def create_test_user_and_case(db, user_id_suffix="1", case_suffix="1"):
    email = f"lead_investigator_{user_id_suffix}_{uuid.uuid4().hex[:6]}@adfir.local"
    user = User(
        id=f"user-sel-{user_id_suffix}-{uuid.uuid4().hex[:6]}",
        email=email,
        name="Lead Forensic Evaluator",
        role="INVESTIGATOR",
        password_hash=hash_password("SecretPass123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    case = Case(
        id=f"case-sel-{case_suffix}-{uuid.uuid4().hex[:6]}",
        case_number=f"CAS-SEL-{case_suffix}-{uuid.uuid4().hex[:4]}",
        name="Disk & Memory Analysis Case",
        objective="Analyze disk filesystem and memory artifacts for threat activity.",
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


# =============================================================================
# 1. CAPABILITY REGISTRY MATCH
# =============================================================================

def test_capability_registry_match():
    """Verify that capability matches valid evidence intelligence attributes."""
    db = SessionLocal()
    cap = db.query(ForensicCapability).filter(ForensicCapability.id == "FILESYSTEM_ANALYSIS").first()
    assert cap is not None

    # Compatible evidence attributes
    is_ok, reason, status = CapabilityMatcher.match(
        cap,
        category="disk_image",
        subtype="raw_disk",
        fmt="raw",
        platform_name="linux"
    )
    assert is_ok is True
    assert status == "CAPABILITY_SUPPORTED"
    db.close()


# =============================================================================
# 2. EVIDENCE TYPE & FORMAT COMPATIBILITY REJECTION
# =============================================================================

def test_evidence_type_compatibility_rejection():
    """Verify that capability rejects evidence of incompatible category or format."""
    db = SessionLocal()
    cap = db.query(ForensicCapability).filter(ForensicCapability.id == "FILESYSTEM_ANALYSIS").first()
    assert cap is not None

    # Incompatible evidence category: memory dump for filesystem analysis
    is_ok, reason, status = CapabilityMatcher.match(
        cap,
        category="memory_dump",
        fmt="raw"
    )
    assert is_ok is False
    assert status == "CAPABILITY_UNSUPPORTED"
    assert "not supported by capability" in reason
    db.close()


# =============================================================================
# 3. TOOL AVAILABILITY DETECTION
# =============================================================================

def test_tool_availability_detection():
    """Verify detection of AVAILABLE, MISSING, and DISABLED tools."""
    tool_available = DBToolDefinition(
        tool_id="test_avail",
        name="sha256sum",
        binary_name="sha256sum",
        executable_path="sha256sum",
        enabled=True
    )
    status_a, _ = ToolEvaluator.evaluate_availability(tool_available)
    assert status_a == "AVAILABLE"

    # Missing binary
    tool_missing = DBToolDefinition(
        tool_id="test_missing",
        name="nonexistent_binary_xyz_12345",
        binary_name="nonexistent_binary_xyz_12345",
        executable_path="/opt/nonexistent/bin",
        enabled=True
    )
    status_m, reason_m = ToolEvaluator.evaluate_availability(tool_missing)
    assert status_m == "MISSING"
    assert "was not found" in reason_m

    # Disabled tool
    tool_disabled = DBToolDefinition(
        tool_id="test_disabled",
        name="sha256sum",
        binary_name="sha256sum",
        enabled=False
    )
    status_d, reason_d = ToolEvaluator.evaluate_availability(tool_disabled)
    assert status_d == "DISABLED"
    assert "explicitly disabled" in reason_d


# =============================================================================
# 4. PLATFORM COMPATIBILITY
# =============================================================================

def test_platform_compatibility_check():
    """Verify platform matching and rejection of unsupported operating systems."""
    current_os = get_host_platform()

    tool_ok = DBToolDefinition(
        tool_id="test_plat_ok",
        platforms=["linux", "windows", "darwin"]
    )
    st_ok, _ = ToolEvaluator.evaluate_platform(tool_ok, host_platform=current_os)
    assert st_ok == "COMPATIBLE"

    # Unsupported platform
    unsupported_os = "windows" if current_os != "windows" else "solaris"
    tool_bad = DBToolDefinition(
        tool_id="test_plat_bad",
        platforms=[unsupported_os]
    )
    st_bad, reason_bad = ToolEvaluator.evaluate_platform(tool_bad, host_platform="openbsd")
    assert st_bad == "INCOMPATIBLE"
    assert "is not supported by tool" in reason_bad


# =============================================================================
# 5. SYSTEM RESOURCE VALIDATION
# =============================================================================

def test_resource_validation():
    """Verify RESOURCE_OK, RESOURCE_CONSTRAINED, and RESOURCE_INSUFFICIENT states."""
    tool = DBToolDefinition(
        tool_id="test_res",
        resource_requirements={"ram_mb": 2048, "cpu_cores": 2, "disk_mb": 500}
    )

    # 1. OK: ample resources
    res_ample = {"available_ram_mb": 8192, "cpu_cores": 8, "available_disk_mb": 50000}
    st_ok, _ = ToolEvaluator.evaluate_resources(tool, sys_res=res_ample)
    assert st_ok == "RESOURCE_OK"

    # 2. Constrained: RAM between 50% and 100% of requirement
    res_tight = {"available_ram_mb": 1500, "cpu_cores": 2, "available_disk_mb": 50000}
    st_tight, reason_tight = ToolEvaluator.evaluate_resources(tool, sys_res=res_tight)
    assert st_tight == "RESOURCE_CONSTRAINED"
    assert "below recommended" in reason_tight

    # 3. Insufficient: RAM < 50% of requirement
    res_starved = {"available_ram_mb": 500, "cpu_cores": 2, "available_disk_mb": 50000}
    st_starved, reason_starved = ToolEvaluator.evaluate_resources(tool, sys_res=res_starved)
    assert st_starved == "RESOURCE_INSUFFICIENT"
    assert "critically insufficient" in reason_starved


# =============================================================================
# 6. VERSION VALIDATION
# =============================================================================

def test_version_validation():
    """Verify semver version constraint evaluation."""
    # Min version met
    tool_ok = DBToolDefinition(
        tool_id="test_ver_ok",
        version="4.12.0",
        min_version="4.0.0",
        max_version="5.0.0"
    )
    st_ok, _ = ToolEvaluator.evaluate_version(tool_ok)
    assert st_ok == "VERSION_OK"

    # Version too low
    tool_low = DBToolDefinition(
        tool_id="test_ver_low",
        version="3.8.1",
        min_version="4.0.0"
    )
    st_low, reason_low = ToolEvaluator.evaluate_version(tool_low)
    assert st_low == "VERSION_INCOMPATIBLE"
    assert "lower than required minimum" in reason_low

    # Unknown version when required
    tool_unk = DBToolDefinition(
        tool_id="test_ver_unk",
        version=None,
        min_version="1.0.0"
    )
    st_unk, _ = ToolEvaluator.evaluate_version(tool_unk)
    assert st_unk == "VERSION_UNKNOWN"


# =============================================================================
# 7. SAFETY PROFILE VALIDATION
# =============================================================================

def test_safety_profile_validation():
    """Verify rejection of non-read-only tools, shell execution, and disallowed binaries."""
    # 1. Safe tool
    tool_safe = DBToolDefinition(
        tool_id="safe_tool",
        name="sha256sum",
        binary_name="sha256sum",
        safety_profile={"read_only": True, "shell": False}
    )
    st_safe, _ = ToolEvaluator.evaluate_safety(tool_safe)
    assert st_safe == "SAFE"

    # 2. Unsafe: not read-only
    tool_write = DBToolDefinition(
        tool_id="write_tool",
        name="mod_tool",
        binary_name="mod_tool",
        safety_profile={"read_only": False, "shell": False}
    )
    st_write, _ = ToolEvaluator.evaluate_safety(tool_write)
    assert st_write == "UNSAFE"

    # 3. Unsafe: shell execution
    tool_shell = DBToolDefinition(
        tool_id="shell_tool",
        name="custom_tool",
        binary_name="custom_tool",
        safety_profile={"read_only": True, "shell": True}
    )
    st_shell, _ = ToolEvaluator.evaluate_safety(tool_shell)
    assert st_shell == "UNSAFE"

    # 4. Unsafe: disallowed system binary (bash / python)
    tool_disallowed = DBToolDefinition(
        tool_id="bash_tool",
        name="bash",
        binary_name="bash",
        safety_profile={"read_only": True, "shell": False}
    )
    st_dis, _ = ToolEvaluator.evaluate_safety(tool_disallowed)
    assert st_dis == "UNSAFE"


# =============================================================================
# 8. INCOMPATIBLE TOOL REJECTION RECORDED
# =============================================================================

def test_incompatible_tool_rejection_recorded():
    """Verify that structured rejection reasons are recorded for incompatible candidates."""
    db = SessionLocal()
    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=str(uuid.uuid4()),
        task_key="task-test-incompat",
        sequence=1,
        capability_id="FILESYSTEM_ANALYSIS",
        agent_name="DiskAgent"
    )

    # Incompatible evidence: pcap capture
    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=str(uuid.uuid4()),
        name="network_trace.pcap",
        original_path="/tmp/network_trace.pcap",
        size_bytes=1000,
        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        evidence_type="PCAP",
        detected_format="pcap"
    )

    res = ToolSelectorEngine.select_tool_for_task(db, task, evidence=ev)
    assert res["selection_status"] in ["NO_COMPATIBLE_TOOL", "TOOL_UNAVAILABLE"]
    assert len(res["rejection_reasons"]) > 0
    db.close()


# =============================================================================
# 9. UNAVAILABLE TOOL HANDLING
# =============================================================================

def test_unavailable_tool_handling():
    """Verify that uninstalled / missing candidate tools produce TOOL_UNAVAILABLE status."""
    db = SessionLocal()

    # Create dummy capability and tool that is missing
    cap_id = f"CUSTOM_CAP_{uuid.uuid4().hex[:6]}"
    cap = ForensicCapability(
        id=cap_id,
        name="Custom Obscure Capability",
        description="Testing missing tool",
        category="DISK",
        supported_evidence_categories=["disk_image"],
        supported_formats=["raw"],
        enabled=True
    )
    db.add(cap)

    tool = DBToolDefinition(
        tool_id=f"missing_tool_{uuid.uuid4().hex[:6]}",
        name="nonexistent_bin_123456",
        binary_name="nonexistent_bin_123456",
        executable_path="/nonexistent/bin/path",
        platforms=["linux", "windows", "darwin"],
        supported_evidence=["disk_image"],
        supported_formats=["raw"],
        capabilities_json=[cap_id],
        safety_profile={"read_only": True, "shell": False},
        enabled=True
    )
    db.add(tool)
    db.commit()

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=str(uuid.uuid4()),
        task_key="task-custom-missing",
        sequence=1,
        capability_id=cap_id,
        agent_name="TestAgent"
    )
    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=str(uuid.uuid4()),
        name="test.raw",
        original_path="/tmp/test.raw",
        size_bytes=1000,
        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        evidence_type="DISK_IMAGE",
        detected_format="raw"
    )

    res = ToolSelectorEngine.select_tool_for_task(db, task, evidence=ev)
    assert res["selected_tool_id"] is None
    assert res["selection_status"] == "TOOL_UNAVAILABLE"
    assert "rejection_reasons" in res
    db.close()


# =============================================================================
# 10. MULTIPLE CANDIDATE TOOLS DETERMINISTIC SELECTION
# =============================================================================

def test_multiple_candidate_tools_selection():
    """Verify that when multiple tools provide a capability, the best eligible candidate is chosen."""
    db = SessionLocal()
    cap_id = f"MULTI_CAP_{uuid.uuid4().hex[:6]}"
    cap = ForensicCapability(
        id=cap_id,
        name="Multi Candidate Capability",
        description="Testing multi-candidate selection",
        category="METADATA",
        supported_evidence_categories=["file", "document"],
        supported_formats=["pdf", "all"],
        enabled=True
    )
    db.add(cap)

    # Tool A: generic format support
    tool_a = DBToolDefinition(
        tool_id=f"cand_a_{uuid.uuid4().hex[:6]}",
        name="sha256sum",
        binary_name="sha256sum",
        executable_path="sha256sum",
        display_name="Generic Tool A",
        platforms=["linux", "windows", "darwin"],
        supported_evidence=["file", "document"],
        supported_formats=["all"],
        capabilities_json=[cap_id],
        resource_requirements={"ram_mb": 512},
        safety_profile={"read_only": True, "shell": False},
        enabled=True
    )
    # Tool B: specific PDF format support
    tool_b = DBToolDefinition(
        tool_id=f"cand_b_{uuid.uuid4().hex[:6]}",
        name="sha256sum",
        binary_name="sha256sum",
        executable_path="sha256sum",
        display_name="Specific PDF Tool B",
        platforms=["linux", "windows", "darwin"],
        supported_evidence=["file", "document"],
        supported_formats=["pdf"],
        capabilities_json=[cap_id],
        resource_requirements={"ram_mb": 256},
        safety_profile={"read_only": True, "shell": False},
        enabled=True
    )
    db.add(tool_a)
    db.add(tool_b)
    db.commit()

    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=str(uuid.uuid4()),
        task_key="task-multi-sel",
        sequence=1,
        capability_id=cap_id,
        agent_name="MetadataAgent"
    )
    ev = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=str(uuid.uuid4()),
        name="document.pdf",
        original_path="/tmp/document.pdf",
        size_bytes=1000,
        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        evidence_type="DOCUMENT",
        detected_format="pdf"
    )

    res = ToolSelectorEngine.select_tool_for_task(db, task, evidence=ev)
    assert res["selection_status"] == "SELECTED"
    # Tool B has specific format match and lower RAM requirement, so higher score
    assert res["selected_tool_id"] == tool_b.tool_id
    db.close()


# =============================================================================
# 11. NO COMPATIBLE TOOL HANDLING
# =============================================================================

def test_no_compatible_tool_task_blocked():
    """Verify that tasks without compatible tools receive NO_COMPATIBLE_TOOL status."""
    db = SessionLocal()
    task = InvestigationTask(
        id=str(uuid.uuid4()),
        plan_id=str(uuid.uuid4()),
        task_key="task-no-tool",
        sequence=1,
        capability_id="UNKNOWN_IMAGINARY_CAPABILITY",
        agent_name="GhostAgent"
    )
    res = ToolSelectorEngine.select_tool_for_task(db, task)
    assert res["selected_tool_id"] is None
    assert res["selection_status"] == "NO_COMPATIBLE_TOOL"
    db.close()


# =============================================================================
# 12. REGISTRY VALIDATION SERVICE AND API
# =============================================================================

def test_registry_validation_service_and_api():
    """Verify registry validation logic and endpoint for orphan detection and consistency."""
    db = SessionLocal()
    report = ToolSelectorEngine.validate_registries(db)
    assert "valid" in report
    assert "total_capabilities" in report
    assert "total_tools" in report
    assert "orphaned_capabilities" in report
    assert report["total_capabilities"] > 0
    assert report["total_tools"] > 0

    user, case, headers = create_test_user_and_case(db, "regval", "regval")

    # API call
    resp = client.get("/api/v1/strategy/registries/validate", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_capabilities"] == report["total_capabilities"]
    assert "orphaned_capabilities" in data
    db.close()


# =============================================================================
# 13. STEP 6 INTEGRATION & PLAN TOOL SELECTION
# =============================================================================

def test_step6_integration_and_plan_tool_selection():
    """Verify full end-to-end flow: Step 6 generates plan -> Step 7 selects & validates tools."""
    db = SessionLocal()
    user, case, headers = create_test_user_and_case(db, "step7int", "step7int")

    # Add evidence items to case
    ev1 = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        name="primary_disk.raw",
        original_path="/tmp/primary_disk.raw",
        size_bytes=1048576,
        evidence_type="DISK_IMAGE",
        detected_format="raw",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="PRESERVED",
        integrity_status="VERIFIED"
    )
    ev2 = EvidenceItem(
        id=str(uuid.uuid4()),
        case_id=case.id,
        name="system_security.evtx",
        original_path="/tmp/system_security.evtx",
        size_bytes=65536,
        evidence_type="WINDOWS_EVENT_LOG",
        detected_format="evtx",
        sha256="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        status="PRESERVED",
        integrity_status="VERIFIED"
    )
    db.add(ev1)
    db.add(ev2)
    db.commit()

    # 1. Generate Investigation Plan via Step 6 API
    plan_resp = client.post(f"/api/v1/cases/{case.id}/investigation-plans", headers=headers)
    assert plan_resp.status_code == 200
    plan_data = plan_resp.json()
    plan_id = plan_data["id"]

    # 2. Select tools for the plan via Step 7 API
    sel_resp = client.post(f"/api/v1/investigation-plans/{plan_id}/select-tools", headers=headers)
    assert sel_resp.status_code == 200
    sel_data = sel_resp.json()

    assert sel_data["plan_id"] == plan_id
    assert sel_data["total_tasks"] > 0
    assert "selections" in sel_data
    assert len(sel_data["selections"]) == sel_data["total_tasks"]

    # 3. Retrieve persisted tool selections
    get_resp = client.get(f"/api/v1/investigation-plans/{plan_id}/tool-selections", headers=headers)
    assert get_resp.status_code == 200
    get_selections = get_resp.json()
    assert len(get_selections) == sel_data["total_tasks"]

    for rec in get_selections:
        assert rec["plan_id"] == plan_id
        assert rec["task_key"] is not None
        assert rec["capability_id"] is not None
        assert rec["selection_status"] in [
            "SELECTED", "NO_COMPATIBLE_TOOL", "TOOL_UNAVAILABLE",
            "RESOURCE_INSUFFICIENT", "VERSION_INCOMPATIBLE", "SAFETY_REVIEW", "REQUIRES_REVIEW"
        ]

    # 4. Verify InvestigationTasks updated in DB
    tasks = db.query(InvestigationTask).filter(InvestigationTask.plan_id == plan_id).all()
    for t in tasks:
        assert t.status in ["READY", "PLANNED", "BLOCKED_NO_CAPABLE_TOOL", "REQUIRES_REVIEW"]

    # 5. Verify tool match validation test endpoint
    val_resp = client.post(
        "/api/v1/strategy/validate-tool-match",
        json={"capability_id": "EVENT_LOG_ANALYSIS", "evidence_id": ev2.id},
        headers=headers
    )
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["capability_id"] == "EVENT_LOG_ANALYSIS"
    assert val_data["capability_supported"] is True

    db.close()


# =============================================================================
# 14. CASE AUTHORIZATION & IDOR ISOLATION
# =============================================================================

def test_case_authorization_and_idor_isolation():
    """Verify 403 Forbidden when unauthorized user attempts to select tools on another user's plan."""
    db = SessionLocal()
    user_a, case_a, headers_a = create_test_user_and_case(db, "idor_a", "idor_a")
    user_b, case_b, headers_b = create_test_user_and_case(db, "idor_b", "idor_b")

    # Generate plan for Case A
    plan_dict = InvestigationStrategyEngine.generate_plan(db, case_a.id, user_a)
    plan_id = plan_dict["id"]

    # User B attempts to trigger tool selection on Case A's plan
    unauth_sel = client.post(f"/api/v1/investigation-plans/{plan_id}/select-tools", headers=headers_b)
    assert unauth_sel.status_code == 403
    assert "access" in unauth_sel.json()["detail"].lower()

    # User B attempts to read Case A's tool selections
    unauth_get = client.get(f"/api/v1/investigation-plans/{plan_id}/tool-selections", headers=headers_b)
    assert unauth_get.status_code == 403
    assert "access" in unauth_get.json()["detail"].lower()

    db.close()
