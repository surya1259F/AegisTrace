import hashlib
import os
import tempfile
import uuid
from pathlib import Path
import pytest
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
    AuditEvent,
)
from backend.app.services.vault import remove_os_read_only
from investigation.planner.planner import InvestigationPlanner
from investigation.orchestrator.orchestrator import InvestigationOrchestrator

client = TestClient(app)

FIXTURE_MARKER = (
    Path(__file__).resolve().parent.parent.parent
    / "tests"
    / "fixtures"
    / "malware"
    / "test_marker_file.txt"
)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def _create_case(test_client: TestClient, name_prefix="Planner Test Case") -> str:
    res = test_client.post(
        "/api/investigations/",
        json={
            "name": f"{name_prefix} {uuid.uuid4().hex[:6]}",
            "description": "Case for planner and orchestrator testing",
        },
    )
    assert res.status_code == 201
    return res.json()["id"]


def _create_temp_file(content: bytes = b"SAMPLE_FORENSIC_DATA", suffix: str = ".bin") -> str:
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name


def _cleanup_file(path_str: str):
    if path_str and os.path.exists(path_str):
        p = Path(path_str)
        remove_os_read_only(p)
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


# -----------------------------------------------------------------------------
# 1. Deterministic Planning Unit Tests
# -----------------------------------------------------------------------------


def test_planner_deterministic_disk():
    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-disk-1", "name": "disk.raw", "evidence_type": "disk_image", "size_bytes": 1024}
    ]
    plan = planner.plan(investigation_id="case-101", evidence_items=evidence)

    assert plan["total_tasks"] == 1
    task = plan["tasks"][0]
    assert task["agent"] == "DiskAgent"
    assert task["tool"] == "SleuthKit"
    assert task["action"] == "filesystem_structure_extraction"
    assert task["priority"] == 1
    assert task["status"] == "PLANNED"
    assert task["dependencies"] == []


def test_planner_deterministic_memory():
    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-mem-1", "name": "mem.dmp", "evidence_type": "memory_dump", "size_bytes": 2048}
    ]
    plan = planner.plan(investigation_id="case-102", evidence_items=evidence)

    assert plan["total_tasks"] == 2
    pslist_task = next(t for t in plan["tasks"] if t["action"] == "process_enumeration")
    netscan_task = next(t for t in plan["tasks"] if t["action"] == "network_socket_extraction")

    assert pslist_task["agent"] == "MemoryAgent"
    assert pslist_task["tool"] == "Volatility3"
    assert pslist_task["priority"] == 1
    assert pslist_task["dependencies"] == []

    assert netscan_task["agent"] == "MemoryAgent"
    assert netscan_task["tool"] == "Volatility3"
    assert netscan_task["priority"] == 2
    assert pslist_task["step_id"] in netscan_task["dependencies"]


def test_planner_deterministic_log():
    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-log-1", "name": "security.evtx", "evidence_type": "log", "size_bytes": 4096}
    ]
    plan = planner.plan(investigation_id="case-103", evidence_items=evidence)

    assert plan["total_tasks"] == 1
    task = plan["tasks"][0]
    assert task["agent"] == "LogAgent"
    assert task["tool"] == "python-evtx"
    assert task["action"] == "security_log_parsing"
    assert task["status"] == "PLANNED"


def test_planner_deterministic_malware():
    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-mal-1", "name": "sample.exe", "evidence_type": "executable", "size_bytes": 512}
    ]
    plan = planner.plan(investigation_id="case-104", evidence_items=evidence)

    assert plan["total_tasks"] == 1
    task = plan["tasks"][0]
    assert task["agent"] == "MalwareAgent"
    assert task["tool"] == "YARA"
    assert task["action"] == "signature_scan"
    assert task["status"] == "PLANNED"


def test_planner_unknown_evidence():
    planner = InvestigationPlanner()
    evidence = [
        {
            "id": "ev-unk-1",
            "name": "random.xyz",
            "evidence_type": "unknown_format",
            "size_bytes": 100,
        }
    ]
    plan = planner.plan(investigation_id="case-105", evidence_items=evidence)

    # Unknown evidence should produce no automated tool tasks
    assert plan["total_tasks"] == 0
    assert "manual triage" in plan["strategy_summary"].lower()


# -----------------------------------------------------------------------------
# 2. Plan Persistence and API Endpoint Tests
# -----------------------------------------------------------------------------


def test_plan_persistence_and_versioning():
    case_id = _create_case(client, "Persistence Case")
    tmp_path = _create_temp_file(content=b"EVIDENCE_DATA_PERSIST", suffix=".raw")
    try:
        intake_res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path, "notes": "Test persistence evidence"},
        )
        assert intake_res.status_code == 201

        # Generate first plan
        plan_res1 = client.post(f"/api/investigations/{case_id}/plan")
        assert plan_res1.status_code == 200
        data1 = plan_res1.json()
        assert data1["id"] is not None
        assert data1["status"] == "PLANNED"
        assert len(data1["tasks"]) > 0

        # Generate second plan: should deactivate the first
        plan_res2 = client.post(f"/api/investigations/{case_id}/plan")
        assert plan_res2.status_code == 200
        data2 = plan_res2.json()
        assert data2["id"] != data1["id"]

        with SessionLocal() as db:
            p1 = db.query(InvestigationPlan).filter(InvestigationPlan.id == data1["id"]).first()
            p2 = db.query(InvestigationPlan).filter(InvestigationPlan.id == data2["id"]).first()
            assert p1.is_active is False
            assert p2.is_active is True
    finally:
        _cleanup_file(tmp_path)


def test_plan_retrieval():
    case_id = _create_case(client, "Retrieval Case")
    tmp_path = _create_temp_file(content=b"EVIDENCE_DATA_RETRIEVAL", suffix=".raw")
    try:
        client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        post_res = client.post(f"/api/investigations/{case_id}/plan")
        assert post_res.status_code == 200

        get_res = client.get(f"/api/investigations/{case_id}/plan")
        assert get_res.status_code == 200
        get_data = get_res.json()
        assert get_data["id"] == post_res.json()["id"]
        assert get_data["status"] == "PLANNED"
        assert len(get_data["tasks"]) == len(post_res.json()["tasks"])
    finally:
        _cleanup_file(tmp_path)


def test_plan_tasks_endpoint():
    case_id = _create_case(client, "Tasks Endpoint Case")
    tmp_path = _create_temp_file(content=b"EVIDENCE_DATA_TASKS", suffix=".raw")
    try:
        client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        client.post(f"/api/investigations/{case_id}/plan")

        tasks_res = client.get(f"/api/investigations/{case_id}/tasks")
        assert tasks_res.status_code == 200
        tasks = tasks_res.json()
        assert isinstance(tasks, list)
        assert len(tasks) > 0
        assert "step_id" in tasks[0]
        assert "status" in tasks[0]
    finally:
        _cleanup_file(tmp_path)


# -----------------------------------------------------------------------------
# 3. Orchestration & Integrity Gate Execution Tests
# -----------------------------------------------------------------------------


def test_orchestrator_vault_enforcement():
    """Orchestrator rejects evidence whose storage_path is not inside the evidence vault."""
    case_id = _create_case(client, "Vault Enforcement Case")
    tmp_path = _create_temp_file(content=b"ROGUE_UNVAULTED_DATA", suffix=".bin")
    try:
        with SessionLocal() as db:
            # Manually inject an unvaulted evidence item
            unvaulted = EvidenceItem(
                case_id=case_id,
                name="unvaulted.bin",
                original_path=tmp_path,
                storage_path=tmp_path,  # points to original source
                sha256=hashlib.sha256(b"ROGUE_UNVAULTED_DATA").hexdigest(),
                size_bytes=len(b"ROGUE_UNVAULTED_DATA"),
                evidence_type="executable",
                integrity_status="VERIFIED",
            )
            db.add(unvaulted)
            db.commit()
            db.refresh(unvaulted)
            ev_id = unvaulted.id

        # Generate plan with this unvaulted evidence
        plan_res = client.post(f"/api/investigations/{case_id}/plan")
        assert plan_res.status_code == 200

        # Execute plan
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200
        data = exec_res.json()

        # The task must fail due to vault violation
        assert data["tasks_failed"] >= 1
        failed_task = data["tasks"][0]
        assert failed_task["status"] == "FAILED"
        assert "vault" in failed_task["error_message"].lower()

        with SessionLocal() as db:
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == ev_id).first()
            assert ev.integrity_status == "FAILED"
    finally:
        _cleanup_file(tmp_path)


def test_orchestrator_pre_analysis_tamper_detection():
    """If evidence is tampered in the vault before orchestrator runs, pre-analysis gate halts task."""
    case_id = _create_case(client, "Pre-Analysis Tamper Case")
    tmp_path = _create_temp_file(content=b"ORIGINAL_CLEAN_DATA", suffix=".exe")
    try:
        intake_res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        assert intake_res.status_code == 201
        ev_data = intake_res.json()
        storage_path = ev_data["storage_path"]
        evidence_id = ev_data["id"]

        # Generate plan
        client.post(f"/api/investigations/{case_id}/plan")

        # Tamper vault file directly
        remove_os_read_only(Path(storage_path))
        with open(storage_path, "wb") as f:
            f.write(b"CORRUPTED_TAMPERED_PAYLOAD")

        # Execute plan
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200
        summary = exec_res.json()

        assert summary["tasks_failed"] >= 1
        task = summary["tasks"][0]
        assert task["status"] == "FAILED"
        assert "mismatch" in task["error_message"].lower()

        with SessionLocal() as db:
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
            assert ev.integrity_status == "FAILED"

            # Check custody event
            custody = (
                db.query(ChainOfCustodyEvent)
                .filter(
                    ChainOfCustodyEvent.evidence_id == evidence_id,
                    ChainOfCustodyEvent.event_type == "INTEGRITY_VIOLATION",
                )
                .first()
            )
            assert custody is not None
    finally:
        _cleanup_file(tmp_path)


def test_orchestrator_execution_and_persistence():
    """Real evidence analysis produces persisted ToolExecution, ExecutionArtifact, and Finding rows."""
    case_id = _create_case(client, "Execution Persistence Case")

    # Use real marker token that matches adfir_test_rules.yar
    marker_content = b"Synthetic diagnostic artifact Token: ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"
    tmp_path = _create_temp_file(content=marker_content, suffix=".exe")
    try:
        intake_res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        assert intake_res.status_code == 201
        ev_data = intake_res.json()
        evidence_id = ev_data["id"]

        # Generate plan
        client.post(f"/api/investigations/{case_id}/plan")

        # Execute plan
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200
        summary = exec_res.json()

        assert summary["status"] in ["COMPLETED", "PARTIALLY_COMPLETED"]
        assert summary["tasks_succeeded"] >= 1

        with SessionLocal() as db:
            # 1. Verify ToolExecution row
            execs = db.query(ToolExecution).filter(ToolExecution.case_id == case_id).all()
            assert len(execs) >= 1
            assert execs[0].status == "COMPLETED"

            # 2. Verify ExecutionArtifact row
            artifacts = (
                db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == case_id).all()
            )
            assert len(artifacts) >= 1
            assert artifacts[0].evidence_id == evidence_id

            # 3. Verify Finding row
            findings = db.query(Finding).filter(Finding.case_id == case_id).all()
            assert len(findings) >= 1
            assert findings[0].evidence_id == evidence_id
            assert findings[0].tool == "YARA"

            # 4. Verify post-analysis custody event
            custody = (
                db.query(ChainOfCustodyEvent)
                .filter(
                    ChainOfCustodyEvent.evidence_id == evidence_id,
                    ChainOfCustodyEvent.event_type == "INTEGRITY_VERIFIED_POST_ANALYSIS",
                )
                .first()
            )
            assert custody is not None
            assert "Zero bytes altered" in custody.description
    finally:
        _cleanup_file(tmp_path)


def test_orchestrator_dependency_failure_cancels_subsequent_task():
    """If a task in the plan fails, any dependent tasks are marked CANCELLED."""
    case_id = _create_case(client, "Dependency Test Case")

    with SessionLocal() as db:
        plan = InvestigationPlan(
            id=str(uuid.uuid4()),
            case_id=case_id,
            strategy_summary="Test dependency DAG",
            tasks=[
                {
                    "step_id": "step-parent",
                    "agent": "DiskAgent",
                    "tool": "SleuthKit",
                    "tool_available": False,  # Will fail tool check
                    "evidence_id": "nonexistent",
                    "action": "step1",
                    "priority": 1,
                    "dependencies": [],
                    "status": "PLANNED",
                },
                {
                    "step_id": "step-child",
                    "agent": "DiskAgent",
                    "tool": "SleuthKit",
                    "tool_available": True,
                    "evidence_id": "nonexistent",
                    "action": "step2",
                    "priority": 2,
                    "dependencies": ["step-parent"],
                    "status": "PLANNED",
                },
            ],
            status="PLANNED",
            version=1,
            is_active=True,
        )
        db.add(plan)
        db.commit()

    exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
    assert exec_res.status_code == 200
    summary = exec_res.json()

    parent = next(t for t in summary["tasks"] if t["step_id"] == "step-parent")
    child = next(t for t in summary["tasks"] if t["step_id"] == "step-child")

    assert parent["status"] == "FAILED"
    assert child["status"] == "CANCELLED"
    assert "Dependency not satisfied" in child["error_message"]


def test_v1_plan_execute_endpoint():
    """Verify the /api/v1/investigation/plan/{case_id}/execute endpoint works properly."""
    case_id = _create_case(client, "V1 Execute Case")
    tmp_path = _create_temp_file(content=b"V1_EXECUTION_SAMPLE", suffix=".exe")
    try:
        client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        # Generate plan via v1
        v1_plan_res = client.post(f"/api/v1/investigation/plan/{case_id}")
        assert v1_plan_res.status_code == 200

        # Execute plan via v1
        v1_exec_res = client.post(f"/api/v1/investigation/plan/{case_id}/execute")
        assert v1_exec_res.status_code == 200
        data = v1_exec_res.json()
        assert data["investigation_id"] == case_id
        assert data["status"] in ["COMPLETED", "PARTIALLY_COMPLETED"]
        assert data["tasks_executed"] >= 1
    finally:
        _cleanup_file(tmp_path)


def test_orchestrator_post_analysis_tamper_detection(monkeypatch):
    """If evidence is mutated during tool execution, post-analysis gate detects it immediately."""
    case_id = _create_case(client, "Post-Analysis Tamper Case")
    tmp_path = _create_temp_file(content=b"UNMODIFIED_BEFORE_ANALYSIS", suffix=".exe")
    try:
        intake_res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        assert intake_res.status_code == 201
        ev_data = intake_res.json()
        storage_path = ev_data["storage_path"]
        evidence_id = ev_data["id"]

        client.post(f"/api/investigations/{case_id}/plan")

        from investigation.orchestrator.orchestrator import InvestigationOrchestrator
        from backend.app.api.endpoints import investigations as inv_mod

        # Monkeypatch malware_agent.analyze to mutate the file during analysis
        orig_analyze = inv_mod.malware_agent.analyze

        def rogue_analyze(evidence_item, parameters=None):
            # Mutate vault file directly during analysis
            sp = evidence_item.get("storage_path")
            remove_os_read_only(Path(sp))
            with open(sp, "ab") as f:
                f.write(b"_ROGUE_BYTE_MUTATION")
            return orig_analyze(evidence_item, parameters)

        monkeypatch.setattr(inv_mod.malware_agent, "analyze", rogue_analyze)

        # Execution should raise 500 (RuntimeError from orchestrator)
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 500
        assert "CRITICAL: Evidence was modified during analysis" in exec_res.json()["detail"]

        with SessionLocal() as db:
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
            assert ev.integrity_status == "FAILED"

            violation = (
                db.query(ChainOfCustodyEvent)
                .filter(
                    ChainOfCustodyEvent.evidence_id == evidence_id,
                    ChainOfCustodyEvent.event_type == "INTEGRITY_VIOLATION",
                )
                .first()
            )
            assert violation is not None
            assert "Post-analysis tampering detected" in violation.description
    finally:
        _cleanup_file(tmp_path)


def test_orchestrator_plan_lifecycle_and_idempotency():
    """Verify plan status transitions to COMPLETED with timestamps, and subsequent execution is idempotent."""
    case_id = _create_case(client, "Lifecycle Case")
    marker_content = b"Synthetic diagnostic artifact Token: ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"
    tmp_path = _create_temp_file(content=marker_content, suffix=".exe")
    try:
        client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        plan_res = client.post(f"/api/investigations/{case_id}/plan")
        assert plan_res.status_code == 200
        plan_data = plan_res.json()
        assert plan_data["status"] == "PLANNED"
        assert plan_data["completed_at"] is None

        # Execute
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200
        summary = exec_res.json()
        assert summary["status"] in ["COMPLETED", "PARTIALLY_COMPLETED"]

        with SessionLocal() as db:
            plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_data["id"]).first()
            assert plan.status in ["COMPLETED", "PARTIALLY_COMPLETED"]
            assert plan.completed_at is not None

            for t in plan.tasks:
                if t["status"] == "COMPLETED":
                    assert t["started_at"] is not None
                    assert t["completed_at"] is not None
                    assert t["execution_id"] is not None

        # Second execute: idempotent, skips already COMPLETED tasks
        exec_res2 = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res2.status_code == 200
        summary2 = exec_res2.json()
        assert summary2["status"] == summary["status"]
    finally:
        _cleanup_file(tmp_path)


# -----------------------------------------------------------------------------
# 5. Planner Capability Integrity & Truthful Tool Execution
# -----------------------------------------------------------------------------


def test_planner_capability_check_omits_unavailable_tool(monkeypatch):
    """When a required tool is marked unavailable, planner must NOT emit an executable task, but record triage notes."""
    from forensic_tools.registry import tool_registry

    orig_tool = tool_registry.get_tool("sleuthkit")
    assert orig_tool is not None

    monkeypatch.setattr(orig_tool, "is_available", False)

    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-disk-unavail", "name": "disk.raw", "evidence_type": "disk_image", "size_bytes": 1024}
    ]
    plan = planner.plan(investigation_id="case-unavail-1", evidence_items=evidence)

    assert plan["total_tasks"] == 0
    assert len(plan["tasks"]) == 0
    assert "SleuthKit tool is not installed" in plan["strategy_summary"]
    assert "Requires specialist manual triage" in plan["strategy_summary"]


def test_planner_unsupported_evidence_type_records_triage():
    """Unsupported evidence types must not create tasks and must be flagged for manual triage."""
    planner = InvestigationPlanner()
    evidence = [
        {"id": "ev-unknown-1", "name": "quantum.dump", "evidence_type": "quantum_telemetry", "size_bytes": 4096}
    ]
    plan = planner.plan(investigation_id="case-unknown-1", evidence_items=evidence)

    assert plan["total_tasks"] == 0
    assert len(plan["tasks"]) == 0
    assert "No registered forensic tool capability available. Requires specialist manual triage." in plan["strategy_summary"]


def test_exiftool_genuine_end_to_end_execution():
    """
    End-to-end execution of ExifTool on genuine file evidence:
    - Evidence is staged into vault
    - Planned as DiskAgent + ExifTool
    - Executed through ExifToolAdapter
    - Truthful ToolExecution row (tool_id='exiftool')
    - Real metadata artifact and candidate finding persisted
    - Cryptographic pre- and post-analysis gates verified
    """
    case_id = _create_case(client, "ExifTool Test Case")
    sample_path = str(Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "sample-evidence.txt")
    assert os.path.exists(sample_path)

    # Ingest file evidence
    res = client.post(
        f"/api/investigations/{case_id}/evidence/intake",
        json={"path": sample_path},
    )
    assert res.status_code == 201
    evidence_id = res.json()["id"]

    # Plan
    plan_res = client.post(f"/api/investigations/{case_id}/plan")
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert plan_data["total_tasks"] == 1

    task = plan_data["tasks"][0]
    assert task["agent"] == "DiskAgent"
    assert task["tool"] == "ExifTool"
    assert task["action"] == "metadata_extraction"
    assert task["status"] == "PLANNED"

    # Execute
    exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["tasks_succeeded"] == 1
    assert exec_data["total_artifacts"] >= 1
    assert exec_data["total_findings"] >= 1

    with SessionLocal() as db:
        # Verify ToolExecution record truthfulness
        tool_exec = (
            db.query(ToolExecution)
            .filter(ToolExecution.case_id == case_id, ToolExecution.evidence_id == evidence_id)
            .first()
        )
        assert tool_exec is not None
        assert tool_exec.tool_id == "exiftool"
        assert tool_exec.command_args[0] == "exiftool"
        assert tool_exec.command_args[1] == "-j"
        assert tool_exec.status == "COMPLETED"

        # Verify ExecutionArtifact
        art = (
            db.query(ExecutionArtifact)
            .filter(ExecutionArtifact.case_id == case_id, ExecutionArtifact.evidence_id == evidence_id)
            .first()
        )
        assert art is not None
        assert art.tool == "ExifTool"
        assert art.agent == "DiskAgent"
        assert art.artifact_type == "metadata_entry"
        assert isinstance(art.metadata_json, dict)
        assert "SourceFile" in art.metadata_json or "FileType" in art.metadata_json or "File:FileType" in art.metadata_json

        # Verify Finding
        finding = (
            db.query(Finding)
            .filter(Finding.case_id == case_id, Finding.evidence_id == evidence_id)
            .first()
        )
        assert finding is not None
        assert finding.tool == "ExifTool"
        assert finding.agent == "DiskAgent"
        assert finding.finding_type == "file_metadata"
        assert finding.confidence == 0.90

        # Verify Pre/Post Cryptographic Integrity Gates in Custody
        custody_events = (
            db.query(ChainOfCustodyEvent)
            .filter(ChainOfCustodyEvent.evidence_id == evidence_id)
            .order_by(ChainOfCustodyEvent.timestamp.asc())
            .all()
        )
        event_types = [e.event_type for e in custody_events]
        assert "EVIDENCE_REGISTERED" in event_types
        assert "INTEGRITY_VERIFIED_PRE_ANALYSIS" in event_types
        assert "INTEGRITY_VERIFIED_POST_ANALYSIS" in event_types


def test_tool_execution_truthfulness_yara():
    """Verify YARA ToolExecution records exact tool_id='yara' and command_args=['yara', rule, path]."""
    case_id = _create_case(client, "Truthful YARA Case")
    marker_content = b"Synthetic diagnostic artifact Token: ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"
    tmp_path = _create_temp_file(content=marker_content, suffix=".exe")
    try:
        res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        assert res.status_code == 201
        evidence_id = res.json()["id"]

        client.post(f"/api/investigations/{case_id}/plan")
        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200

        with SessionLocal() as db:
            tool_exec = (
                db.query(ToolExecution)
                .filter(ToolExecution.case_id == case_id, ToolExecution.evidence_id == evidence_id)
                .first()
            )
            assert tool_exec is not None
            assert tool_exec.tool_id == "yara"
            assert tool_exec.command_args[0] == "yara"
            assert tool_exec.command_args[1] in ("adfir_webshell_indicators", "adfir_test_rules")
            assert tool_exec.status == "COMPLETED"
    finally:
        _cleanup_file(tmp_path)


def test_tool_divergence_prevention(monkeypatch):
    """Verify orchestrator fails execution and raises error if agent returns tool provenance diverging from planned tool."""
    case_id = _create_case(client, "Divergence Case")
    marker_content = b"Synthetic diagnostic artifact Token: ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"
    tmp_path = _create_temp_file(content=marker_content, suffix=".exe")
    try:
        res = client.post(
            f"/api/investigations/{case_id}/evidence/intake",
            json={"path": tmp_path},
        )
        assert res.status_code == 201

        client.post(f"/api/investigations/{case_id}/plan")

        import backend.app.api.endpoints.investigations as inv_mod
        orig_analyze = inv_mod.malware_agent.analyze

        def divergent_analyze(evidence_item, parameters=None):
            result = orig_analyze(evidence_item, parameters)
            # Divergence: planned was YARA, but simulate rogue tool substitution
            result["provenance"]["tool"] = "RogueScanner"
            return result

        monkeypatch.setattr(inv_mod.malware_agent, "analyze", divergent_analyze)

        exec_res = client.post(f"/api/investigations/{case_id}/plan/execute")
        assert exec_res.status_code == 200
        data = exec_res.json()
        assert data["tasks_failed"] == 1
        assert "Forensic tool divergence detected" in data["tasks"][0]["error_message"]
    finally:
        _cleanup_file(tmp_path)


