import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, ensure_correlation_schema
from backend.app.models.models import Case, EvidenceItem, ExecutionArtifact, Finding, CorrelationGroup, ToolExecution
from investigation.correlation.engine import (
    CorrelationEngine,
    RULE_SHARED_IP,
    RULE_SHARED_PROCESS,
    RULE_SHARED_ACCOUNT,
    RULE_SHARED_HASH,
    RULE_SHARED_INDICATOR,
    RULE_SHARED_FORENSIC_OBJECT
)

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    ensure_correlation_schema(engine)
    yield

def _create_case(name_prefix="Corr Test Case") -> str:
    res = client.post("/api/investigations/", json={
        "name": f"{name_prefix} {uuid.uuid4().hex[:6]}",
        "description": "Case for correlation verification"
    })
    assert res.status_code == 201
    return res.json()["id"]

# -----------------------------------------------------------------------------
# Test 1: Deterministic Correlation (Same input -> Same output)
# -----------------------------------------------------------------------------
def test_deterministic_correlation_produces_identical_output():
    engine_instance = CorrelationEngine()

    findings = [
        {
            "id": "f-101",
            "evidence_id": "ev-1",
            "artifact_id": "art-1",
            "tool": "Volatility3",
            "title": "Outbound Connection to 198.51.100.45",
            "description": "Active TCP connection to remote C2 server at 198.51.100.45:443",
            "details": {"foreign_addr": "198.51.100.45", "process_name": "beacon.exe"},
            "evidence_reference": "ip:198.51.100.45"
        },
        {
            "id": "f-102",
            "evidence_id": "ev-2",
            "artifact_id": "art-2",
            "tool": "python-evtx",
            "title": "Logon Event with Remote IP 198.51.100.45",
            "description": "Network logon detected originating from 198.51.100.45",
            "details": {"source_ip": "198.51.100.45", "target_user": "backdoor_admin"},
            "evidence_reference": "record:102:eid:4624"
        }
    ]

    run1 = engine_instance.correlate_findings(findings)
    run2 = engine_instance.correlate_findings(findings)

    assert run1 == run2
    assert len(run1) == 1
    assert run1[0]["rule"] == RULE_SHARED_IP
    assert run1[0]["correlated_entity"] == "198.51.100.45"
    assert run1[0]["supporting_finding_ids"] == ["f-101", "f-102"]
    assert run1[0]["tools_involved"] == ["Volatility3", "python-evtx"]

# -----------------------------------------------------------------------------
# Test 2: Valid Multi-Source Relationships (All Supported Rules)
# -----------------------------------------------------------------------------
def test_valid_relationships_all_supported_rules():
    engine_instance = CorrelationEngine()

    # A. SHARED_IP
    ip_findings = [
        {"id": "f-1", "tool": "Volatility3", "details": {"foreign_addr": "203.0.113.50"}},
        {"id": "f-2", "tool": "python-evtx", "details": {"source_ip": "203.0.113.50"}}
    ]
    ip_groups = engine_instance.correlate_findings(ip_findings)
    assert any(g["rule"] == RULE_SHARED_IP and g["correlated_entity"] == "203.0.113.50" for g in ip_groups)

    # B. SHARED_PROCESS
    proc_findings = [
        {"id": "f-3", "tool": "SleuthKit", "title": "Executable Staged: nc.exe", "description": "Netcat binary nc.exe written to disk"},
        {"id": "f-4", "tool": "Volatility3", "title": "Suspicious Process: nc.exe", "details": {"process_name": "nc.exe"}}
    ]
    proc_groups = engine_instance.correlate_findings(proc_findings)
    assert any(g["rule"] == RULE_SHARED_PROCESS and g["correlated_entity"] == "nc.exe" for g in proc_groups)

    # C. SHARED_ACCOUNT
    acc_findings = [
        {"id": "f-5", "tool": "python-evtx", "details": {"target_user": "backdoor_admin"}},
        {"id": "f-6", "tool": "python-evtx", "details": {"user": "backdoor_admin"}}
    ]
    acc_groups = engine_instance.correlate_findings(acc_findings)
    assert any(g["rule"] == RULE_SHARED_ACCOUNT and g["correlated_entity"] == "backdoor_admin" for g in acc_groups)

    # D. SHARED_HASH
    hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    hash_findings = [
        {"id": "f-7", "tool": "MalwareAgent", "details": {"sha256": hash_val}},
        {"id": "f-8", "tool": "DiskAgent", "details": {"hash": hash_val}}
    ]
    hash_groups = engine_instance.correlate_findings(hash_findings)
    assert any(g["rule"] == RULE_SHARED_HASH and g["correlated_entity"] == hash_val for g in hash_groups)

    # E. SHARED_INDICATOR
    ind_findings = [
        {"id": "f-9", "tool": "YARA", "evidence_reference": "rule:CobaltStrike_Beacon_X64"},
        {"id": "f-10", "tool": "YARA", "details": {"rule_name": "CobaltStrike_Beacon_X64"}}
    ]
    ind_groups = engine_instance.correlate_findings(ind_findings)
    assert any(g["rule"] == RULE_SHARED_INDICATOR and g["correlated_entity"] == "CobaltStrike_Beacon_X64" for g in ind_groups)

    # F. SHARED_FORENSIC_OBJECT (Contextually scoped to filesystem/evidence)
    ref_findings = [
        {"id": "f-11", "tool": "SleuthKit", "evidence_id": "ev-disk-1", "evidence_reference": "inode:14920"},
        {"id": "f-12", "tool": "YARA", "evidence_id": "ev-disk-1", "evidence_reference": "inode:14920"}
    ]
    ref_groups = engine_instance.correlate_findings(ref_findings)
    assert any(g["rule"] == RULE_SHARED_FORENSIC_OBJECT and "inode:14920" in g["correlated_entity"] for g in ref_groups)

# -----------------------------------------------------------------------------
# Test 3: False-Positive Prevention (Generic Tokens Rejected)
# -----------------------------------------------------------------------------
def test_false_positive_prevention_on_generic_tokens():
    engine_instance = CorrelationEngine()

    generic_findings = [
        {
            "id": "f-gen-1",
            "tool": "ToolA",
            "title": "Windows System Process Found",
            "description": "Normal system process running under user account on windows file system",
            "details": {
                "process_name": "svchost.exe",
                "user": "system",
                "ip_address": "127.0.0.1",
                "file_name": "file.txt"
            }
        },
        {
            "id": "f-gen-2",
            "tool": "ToolB",
            "title": "Another Windows System Process",
            "description": "User login to localhost system with windows generic file process",
            "details": {
                "process_name": "svchost.exe",
                "user": "system",
                "ip_address": "127.0.0.1",
                "file_name": "file.txt"
            }
        }
    ]

    groups = engine_instance.correlate_findings(generic_findings)
    # Generic terms (system, user, windows, file, process, localhost, 127.0.0.1, svchost.exe) must NOT correlate
    assert len(groups) == 0

# -----------------------------------------------------------------------------
# Test 4: Provenance Retention
# -----------------------------------------------------------------------------
def test_correlation_retains_full_provenance():
    engine_instance = CorrelationEngine()

    findings = [
        {
            "id": "find-abc",
            "evidence_id": "ev-disk-1",
            "artifact_id": "art-disk-1",
            "tool": "SleuthKit",
            "title": "beacon.exe extracted from disk",
            "details": {"process_name": "beacon.exe"}
        },
        {
            "id": "find-def",
            "evidence_id": "ev-mem-2",
            "artifact_id": "art-mem-2",
            "tool": "Volatility3",
            "title": "Active Process beacon.exe",
            "details": {"process_name": "beacon.exe"}
        }
    ]
    artifacts = [
        {
            "id": "art-log-3",
            "evidence_id": "ev-log-3",
            "tool": "python-evtx",
            "path": "C:\\temp\\beacon.exe",
            "metadata_json": {"process_name": "beacon.exe"}
        }
    ]

    groups = engine_instance.correlate_findings(findings, artifacts)
    assert len(groups) == 1
    grp = groups[0]

    assert grp["rule"] == RULE_SHARED_PROCESS
    assert grp["correlated_entity"] == "beacon.exe"
    assert "find-abc" in grp["supporting_finding_ids"]
    assert "find-def" in grp["supporting_finding_ids"]
    assert "art-disk-1" in grp["supporting_artifact_ids"]
    assert "art-mem-2" in grp["supporting_artifact_ids"]
    assert "art-log-3" in grp["supporting_artifact_ids"]
    assert "ev-disk-1" in grp["supporting_evidence_ids"]
    assert "ev-mem-2" in grp["supporting_evidence_ids"]
    assert "ev-log-3" in grp["supporting_evidence_ids"]
    assert set(grp["tools_involved"]) == {"SleuthKit", "Volatility3", "python-evtx"}

# -----------------------------------------------------------------------------
# Test 5 & 6: Persistence, Deduplication & Database Survival
# -----------------------------------------------------------------------------
def test_correlation_persistence_and_deduplication():
    case_id = _create_case("Persistence Case")
    db = SessionLocal()
    try:
        # Create 2 findings with shared IP
        f1 = Finding(
            case_id=case_id,
            tool="Volatility3",
            agent="MemoryAgent",
            title="External Connection",
            description="Outbound socket to 198.51.100.99",
            evidence_reference="ip:198.51.100.99",
            raw_output_reference='{"details": {"ip_address": "198.51.100.99"}}'
        )
        f2 = Finding(
            case_id=case_id,
            tool="python-evtx",
            agent="LogAgent",
            title="Logon From IP",
            description="Remote access from 198.51.100.99",
            evidence_reference="ip:198.51.100.99",
            raw_output_reference='{"details": {"source_ip": "198.51.100.99"}}'
        )
        db.add_all([f1, f2])
        db.commit()
    finally:
        db.close()

    # 1. Run correlation first time via API
    res1 = client.post(f"/api/cases/{case_id}/correlate")
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1) == 1
    corr_id = data1[0]["id"]
    assert corr_id is not None
    assert data1[0]["rule"] == RULE_SHARED_IP
    assert data1[0]["correlated_entity"] == "198.51.100.99"

    # Verify directly in fresh DB session (persistence)
    fresh_db = SessionLocal()
    try:
        stored = fresh_db.query(CorrelationGroup).filter_by(case_id=case_id).all()
        assert len(stored) == 1
        assert stored[0].id == corr_id
        assert stored[0].correlated_entity == "198.51.100.99"
        assert stored[0].rule == RULE_SHARED_IP
        original_created_at = stored[0].created_at
    finally:
        fresh_db.close()

    # 2. Run correlation second time (deduplication check)
    res2 = client.post(f"/api/cases/{case_id}/correlate")
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2) == 1
    assert data2[0]["id"] == corr_id  # Same ID, not duplicated

    # Verify no duplicate rows exist in database
    verify_db = SessionLocal()
    try:
        count = verify_db.query(CorrelationGroup).filter_by(case_id=case_id).count()
        assert count == 1
        record = verify_db.query(CorrelationGroup).filter_by(id=corr_id).first()
        assert record.created_at == original_created_at
    finally:
        verify_db.close()

# -----------------------------------------------------------------------------
# Test 7: Empty Case Handling
# -----------------------------------------------------------------------------
def test_empty_case_produces_zero_correlations():
    case_id = _create_case("Empty Case")

    res = client.post(f"/api/cases/{case_id}/correlate")
    assert res.status_code == 200
    assert res.json() == []

    get_res = client.get(f"/api/cases/{case_id}/correlations")
    assert get_res.status_code == 200
    assert get_res.json() == []

# -----------------------------------------------------------------------------
# Test 8: API Endpoints (GET and POST)
# -----------------------------------------------------------------------------
def test_case_correlation_endpoints_get_and_post():
    case_id = _create_case("API Test Case")
    db = SessionLocal()
    try:
        f1 = Finding(
            case_id=case_id,
            tool="DiskAgent",
            title="Suspicious Tool: mimikatz.exe",
            description="Tool mimikatz.exe identified on disk",
            evidence_reference="inode:101",
            raw_output_reference='{"details": {"file_name": "mimikatz.exe"}}'
        )
        f2 = Finding(
            case_id=case_id,
            tool="MemoryAgent",
            title="Process Dump: mimikatz.exe",
            description="Process mimikatz.exe identified in memory",
            evidence_reference="pid:1420",
            raw_output_reference='{"details": {"process_name": "mimikatz.exe"}}'
        )
        db.add_all([f1, f2])
        db.commit()
    finally:
        db.close()

    # POST triggers generation & persistence
    post_res = client.post(f"/api/cases/{case_id}/correlate")
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert len(post_data) == 1
    assert post_data[0]["rule"] == RULE_SHARED_PROCESS
    assert post_data[0]["correlated_entity"] == "mimikatz.exe"

    # GET retrieves persisted correlations
    get_res = client.get(f"/api/cases/{case_id}/correlations")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert len(get_data) == 1
    assert get_data[0]["id"] == post_data[0]["id"]
    assert get_data[0]["correlated_entity"] == "mimikatz.exe"
    assert get_data[0]["case_id"] == case_id

# -----------------------------------------------------------------------------
# Test 9: Case Isolation (Case A vs Case B)
# -----------------------------------------------------------------------------
def test_case_isolation_correlations_do_not_leak():
    case_a = _create_case("Case A")
    case_b = _create_case("Case B")

    db = SessionLocal()
    try:
        # Case A has shared IP 198.51.100.77
        f_a1 = Finding(case_id=case_a, tool="ToolA", title="A1", description="IP 198.51.100.77")
        f_a2 = Finding(case_id=case_a, tool="ToolB", title="A2", description="IP 198.51.100.77")

        # Case B has shared IP 203.0.113.88
        f_b1 = Finding(case_id=case_b, tool="ToolC", title="B1", description="IP 203.0.113.88")
        f_b2 = Finding(case_id=case_b, tool="ToolD", title="B2", description="IP 203.0.113.88")

        db.add_all([f_a1, f_a2, f_b1, f_b2])
        db.commit()
    finally:
        db.close()

    res_a = client.post(f"/api/cases/{case_a}/correlate")
    res_b = client.post(f"/api/cases/{case_b}/correlate")

    assert res_a.status_code == 200
    assert res_b.status_code == 200

    data_a = res_a.json()
    data_b = res_b.json()

    assert len(data_a) == 1
    assert len(data_b) == 1
    assert data_a[0]["correlated_entity"] == "198.51.100.77"
    assert data_b[0]["correlated_entity"] == "203.0.113.88"

    # Query Case A GET endpoint: must never contain Case B's entity
    get_a = client.get(f"/api/cases/{case_a}/correlations")
    assert get_a.status_code == 200
    entities_in_a = [c["correlated_entity"] for c in get_a.json()]
    assert "203.0.113.88" not in entities_in_a
    assert "198.51.100.77" in entities_in_a

# -----------------------------------------------------------------------------
# Test 10: Evidence Immutability (Correlation Operates Read-Only on Persisted Data)
# -----------------------------------------------------------------------------
def test_correlation_never_touches_original_or_vault_evidence(monkeypatch):
    case_id = _create_case("Immutability Case")
    db = SessionLocal()
    try:
        f1 = Finding(case_id=case_id, tool="MemoryAgent", title="Beacon Executed", description="beacon.exe active", raw_output_reference='{"details": {"path": "C:\\\\temp\\\\beacon.exe"}}')
        f2 = Finding(case_id=case_id, tool="DiskAgent", title="Beacon Staged", description="beacon.exe on disk", raw_output_reference='{"details": {"path": "C:\\\\temp\\\\beacon.exe"}}')
        db.add_all([f1, f2])
        db.commit()
    finally:
        db.close()

    # Track open calls to verify no write operations occur during correlation
    orig_open = open
    def audit_open(path, mode="r", *args, **kwargs):
        if "w" in mode or "a" in mode or "+" in mode:
            # File writes during correlation are forbidden (except logging/sqlite if handled by python)
            path_str = str(path)
            if "evidence" in path_str.lower() or "vault" in path_str.lower():
                raise AssertionError(f"Write operation attempted on evidence during correlation: {path}")
        return orig_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", audit_open)

    res = client.post(f"/api/cases/{case_id}/correlate")
    assert res.status_code == 200
    assert len(res.json()) == 1

# -----------------------------------------------------------------------------
# Test 11: Common Executable Name Without Corroboration Does Not Correlate
# -----------------------------------------------------------------------------
def test_common_executable_name_without_corroboration_does_not_correlate():
    """
    Demonstrate that merely sharing an executable name across unrelated records
    without supporting path, hash, command line, or cross-domain staging context
    does NOT automatically create a SHARED_PROCESS correlation.
    """
    engine_instance = CorrelationEngine()

    unrelated_findings = [
        {
            "id": "f-unrelated-1",
            "tool": "ToolA",
            "title": "Software Installation",
            "description": "Installer process running: update.exe",
            "details": {"process_name": "update.exe"}
        },
        {
            "id": "f-unrelated-2",
            "tool": "ToolB",
            "title": "Application Launched",
            "description": "User started update.exe",
            "details": {"process_name": "update.exe"}
        }
    ]

    groups = engine_instance.correlate_findings(unrelated_findings)
    assert len(groups) == 0, "Uncorroborated executable names must not form a SHARED_PROCESS correlation"

# -----------------------------------------------------------------------------
# Test 12: Contextual Scoping for Forensic Objects (PID, Inode, EVTX Record)
# -----------------------------------------------------------------------------
def test_forensic_object_pid_in_different_evidence_does_not_correlate():
    """PID 1044 in Evidence A vs Evidence B must NOT correlate."""
    engine_instance = CorrelationEngine()

    pid_findings = [
        {"id": "f-p1", "evidence_id": "ev-mem-host1", "tool": "Volatility3", "evidence_reference": "pid:1044"},
        {"id": "f-p2", "evidence_id": "ev-mem-host2", "tool": "Volatility3", "evidence_reference": "pid:1044"}
    ]
    groups = engine_instance.correlate_findings(pid_findings)
    assert len(groups) == 0, "Same PID in different evidence contexts must not correlate"

def test_forensic_object_inode_in_unrelated_filesystem_contexts_does_not_correlate():
    """Inode 14920 in different filesystem/evidence contexts must NOT correlate."""
    engine_instance = CorrelationEngine()

    inode_findings = [
        {"id": "f-i1", "evidence_id": "ev-disk-alpha", "tool": "SleuthKit", "evidence_reference": "inode:14920"},
        {"id": "f-i2", "evidence_id": "ev-disk-beta", "tool": "SleuthKit", "evidence_reference": "inode:14920"}
    ]
    groups = engine_instance.correlate_findings(inode_findings)
    assert len(groups) == 0, "Same inode across distinct evidence filesystems must not correlate"

def test_forensic_object_evtx_record_without_source_log_context_does_not_correlate():
    """EVTX record without evidence ID or log context must NOT correlate."""
    engine_instance = CorrelationEngine()

    evtx_findings = [
        {"id": "f-e1", "evidence_id": None, "tool": "python-evtx", "evidence_reference": "record:102:eid:4624"},
        {"id": "f-e2", "evidence_id": None, "tool": "python-evtx", "evidence_reference": "record:102:eid:4624"}
    ]
    groups = engine_instance.correlate_findings(evtx_findings)
    assert len(groups) == 0, "EVTX record coordinate without evidence context must not correlate"

# -----------------------------------------------------------------------------
# Test 13: Report Generation Strictly Gated on Persisted Correlation State
# -----------------------------------------------------------------------------
def test_report_generation_blocked_when_correlation_not_executed():
    """Report generation must return HTTP 422 if correlation has not been executed for findings."""
    case_id = _create_case("Uncorrelated Report Gate Case")
    db = SessionLocal()
    try:
        f1 = Finding(
            case_id=case_id,
            tool="MemoryAgent",
            title="Active C2 Connection",
            description="Remote socket to 198.51.100.33",
            evidence_reference="ip:198.51.100.33",
            raw_output_reference='{"details": {"ip_address": "198.51.100.33"}}'
        )
        db.add(f1)
        db.commit()
    finally:
        db.close()

    # Submit valid CONFIRM decision
    dec_res = client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "Findings reviewed and confirmed.",
        "investigator_name": "Inspector Morse"
    })
    assert dec_res.status_code == 201

    # Attempt report generation WITHOUT running correlation
    rep_res = client.post(f"/api/investigations/{case_id}/report")
    assert rep_res.status_code == 422
    assert "Forensic correlation has not been executed" in rep_res.json()["detail"]

def test_report_generation_blocked_when_new_findings_added_after_correlation():
    """Report generation must return HTTP 422 if findings were added after the last correlation run."""
    import time
    case_id = _create_case("Stale Correlation Report Gate Case")
    db = SessionLocal()
    try:
        f1 = Finding(
            case_id=case_id,
            tool="DiskAgent",
            title="Initial Finding",
            description="Staged binary",
            evidence_reference="inode:50"
        )
        db.add(f1)
        db.commit()
    finally:
        db.close()

    # Run correlation initially
    corr_res = client.post(f"/api/cases/{case_id}/correlate")
    assert corr_res.status_code == 200

    # Ensure timestamp difference
    time.sleep(0.05)

    # Add a new finding AFTER correlation
    db = SessionLocal()
    try:
        f2 = Finding(
            case_id=case_id,
            tool="LogAgent",
            title="Later Finding",
            description="New logon event",
            evidence_reference="record:200"
        )
        db.add(f2)
        db.commit()
    finally:
        db.close()

    # Submit valid CONFIRM decision
    dec_res = client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "Findings confirmed.",
        "investigator_name": "Inspector Lewis"
    })
    assert dec_res.status_code == 201

    # Attempt report generation with stale correlation state
    rep_res = client.post(f"/api/investigations/{case_id}/report")
    assert rep_res.status_code == 422
    assert "New findings have been added since the last correlation execution" in rep_res.json()["detail"]

def test_report_generation_succeeds_only_with_persisted_correlation_and_confirm(monkeypatch):
    """Report generation consumes persisted correlation state and does NOT execute on the fly."""
    case_id = _create_case("Persisted Correlation Report Case")
    db = SessionLocal()
    try:
        f1 = Finding(
            case_id=case_id,
            tool="ToolA",
            title="Netscan C2",
            description="Outbound 198.51.100.88",
            evidence_reference="ip:198.51.100.88",
            raw_output_reference='{"details": {"foreign_addr": "198.51.100.88"}}'
        )
        f2 = Finding(
            case_id=case_id,
            tool="ToolB",
            title="Logon C2",
            description="Logon from 198.51.100.88",
            evidence_reference="ip:198.51.100.88",
            raw_output_reference='{"details": {"source_ip": "198.51.100.88"}}'
        )
        db.add_all([f1, f2])
        db.commit()
    finally:
        db.close()

    # 1. Explicitly execute and persist correlation
    corr_res = client.post(f"/api/cases/{case_id}/correlate")
    assert corr_res.status_code == 200
    corr_data = corr_res.json()
    assert len(corr_data) == 1

    # 2. Submit explicit CONFIRM decision
    dec_res = client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "All cross-evidence correlation groups and findings confirmed.",
        "investigator_name": "Chief Inspector Hathaway"
    })
    assert dec_res.status_code == 201

    # Monkeypatch correlate_findings to guarantee it is NEVER called during report generation
    def forbidden_correlate(*args, **kwargs):
        raise AssertionError("Correlation must not be executed on-the-fly during report generation!")

    monkeypatch.setattr(CorrelationEngine, "correlate_findings", forbidden_correlate)

    # 3. Generate report: must consume persisted state and succeed
    rep_res = client.post(f"/api/investigations/{case_id}/report")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["status"] == "OFFICIAL_FINAL"
    assert rep_data["generated_by"] in ("Chief Inspector Hathaway", "Default Test Investigator")


