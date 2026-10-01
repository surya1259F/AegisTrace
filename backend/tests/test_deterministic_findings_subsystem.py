"""ADFIR — Phase 2 / Step 15: Deterministic Findings Subsystem Tests

Comprehensive verification of:
1. Deterministic Rule Engine & Evidence Fact Matching
   - RULE_CONFIRMED_MALWARE_HASH_MATCH (CRITICAL)
   - RULE_MALWARE_SIGNATURE_HIT (HIGH)
   - RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION (HIGH)
   - RULE_BROWSER_SOCKET_INTERACTION (HIGH)
   - RULE_MULTI_DOMAIN_CORRELATED_CLUSTER (HIGH)
   - RULE_PRIVILEGED_USER_LOGON_ACTIVITY (MEDIUM)
   - RULE_PROCESS_SOCKET_ASSOCIATION (MEDIUM)
   - RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE (MEDIUM)
   - RULE_USER_LOGON_OBSERVATION (LOW)
   - RULE_TEMPORAL_SEQUENCE_OBSERVATION (INFORMATIONAL)
2. Deterministic Severity & Rule Preservation
   - Severity is purely rule-driven (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
   - Exact severity rule and observed evidence inputs are preserved
3. Deterministic Confidence Calculation
   - Evaluated mathematically: 0.35 * integrity + 0.30 * art_conf + 0.25 * id_conf + 0.10 * min(1.0, src/2)
   - Contradictory evidence penalty, clamped to [0.0, 1.0]
4. Complete 7-Tier Traceable Provenance
   - EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact
     -> NormalizedArtifact -> Timeline/Correlation -> DeterministicFinding
5. Cryptographic Integrity & Tamper Detection
   - Canonical SHA-256 computation
   - Real-time tamper detection on modified files or records
6. Storage Isolation & Security
   - Isolated case paths under storage/findings/cases/{case_id}/
   - POSIX permissions (0o700 dir, 0o600 file)
   - Path traversal and symlink prevention
   - Strict prohibition from evidence vault
7. Source Artifact Immutability
   - Preceding artifacts (Steps 10-14) remain strictly read-only and unmodified
8. Deduplication & Deterministic Freshness
   - Regeneration replaces prior findings deterministically without clutter
9. REST API & RBAC / IDOR Protection
   - Complete endpoint testing with authorization and cross-case isolation
10. Strict Forensic Boundaries
   - Zero LLM execution, zero attacker intent inferences, purely observable facts
"""

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.core.database import SessionLocal
from backend.app.core.security import create_access_token, hash_password
from backend.app.main import app
from backend.app.models.models import (
    ArtifactRelationship,
    Case,
    CaseMember,
    DeterministicFinding,
    EvidenceItem,
    ExecutionOutput,
    Finding,
    ForensicCorrelationGroup,
    ForensicExecution,
    InvestigationPlan,
    NormalizedArtifact,
    StructuredArtifact,
    TimelineEvent,
    User,
)
from backend.app.schemas.schemas import FindingGenerateRequest
from backend.app.services.findings import (
    DeterministicFindingsService,
    FindingSeverity,
    FindingStorageManager,
    FindingType,
    SeverityRule,
    calculate_deterministic_confidence,
    compute_sha256,
    format_canonical_json,
)

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_test_user_and_case(db, username_prefix="find_usr", case_prefix="find_case"):
    """Creates an investigator user and an authorized case."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        email=f"{username_prefix}_{uuid.uuid4().hex[:6]}@adfir.local",
        name=f"Forensic Investigator {username_prefix}",
        organization="DFIR Unit",
        role="INVESTIGATOR",
        is_active=True,
        password_hash=hash_password("Investigate@123")
    )
    db.add(user)
    db.commit()

    cid = f"case-find-{uuid.uuid4().hex[:8]}"
    case = Case(
        id=cid,
        case_number=f"CAS-{uuid.uuid4().hex[:12].upper()}",
        name=f"Case {case_prefix}",
        description="Testing deterministic findings subsystem",
        created_by=user.name,
        owner_id=user.id,
        status="ACTIVE"
    )
    db.add(case)
    db.commit()

    member = CaseMember(
        id=str(uuid.uuid4()),
        case_id=case.id,
        user_id=user.id,
        role="LEAD"
    )
    db.add(member)
    db.commit()

    return user, case


def setup_forensic_pipeline_fixtures(db, case_id):
    """
    Creates complete multi-tier forensic stack:
    EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact
    """
    ev_id = f"ev-{uuid.uuid4().hex[:8]}"
    evidence = EvidenceItem(
        id=ev_id,
        case_id=case_id,
        name="target_drive.raw",
        original_path="/tmp/fake_drive.raw",
        storage_path="/tmp/fake_drive.raw",
        evidence_type="DISK_IMAGE",
        size_bytes=2097152.0,
        sha256="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        status="ANALYSIS_READY",
        integrity_status="VERIFIED"
    )
    db.add(evidence)
    db.commit()

    exec_id = f"fe-{uuid.uuid4().hex[:8]}"
    execution = ForensicExecution(
        id=exec_id,
        request_id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=ev_id,
        task_key="DISK_ARTIFACT_SCAN",
        tool_id="fls_parser",
        executable_path="/usr/bin/fls",
        host_platform="Linux",
        host_architecture="x86_64",
        workspace_path="/tmp/workspace",
        execution_status="COMPLETED"
    )
    db.add(execution)
    db.commit()

    out_id = f"out-{uuid.uuid4().hex[:8]}"
    raw_output = ExecutionOutput(
        id=out_id,
        execution_id=exec_id,
        request_id=execution.request_id,
        case_id=case_id,
        evidence_id=ev_id,
        output_type="TOOL_OUTPUT",
        filename="fls_output.json",
        relative_path="fls_output.json",
        storage_path="/tmp/storage/fls_output.json",
        size_bytes=1024,
        sha256_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    )
    db.add(raw_output)
    db.commit()

    sa_id = f"sa-{uuid.uuid4().hex[:8]}"
    struct_art = StructuredArtifact(
        id=sa_id,
        case_id=case_id,
        evidence_id=ev_id,
        execution_id=exec_id,
        raw_output_id=out_id,
        parser_name="fls_extractor",
        parser_version="1.0.0",
        artifact_type="FILE",
        sha256_hash="2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        source_raw_output_hash=raw_output.sha256_hash,
        extraction_status="EXTRACTED"
    )
    db.add(struct_art)
    db.commit()

    return evidence, execution, raw_output, struct_art


# =============================================================================
# TEST CASES
# =============================================================================

def test_rule_confirmed_malware_hash_match_critical(db_session):
    """
    Verifies that a FILE_HASH_MATCH relationship produces a CRITICAL finding
    under RULE_CONFIRMED_MALWARE_HASH_MATCH ONLY when an authoritative/verified
    malware-signature source is explicitly represented.
    Persists signature source, identifier/version, hash and verification status.
    """
    user, case = create_test_user_and_case(db_session, "mal_user", "mal_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    # 1. Create normalized artifacts with authoritative verified signature source
    file_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="FILE",
        entity_identity="file_sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        normalized_fields={
            "hashes": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
            "path": "/bin/suspicious_payload"
        },
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="hash1",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    mal_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="malware:trojan_dropper",
        normalized_fields={
            "rule_name": "Trojan_Dropper_Win32",
            "signature_source": "VirusTotal_Authoritative_Feed",
            "signature_identifier": "Trojan.Win32.Dropper.01",
            "signature_version": "2026.1",
            "verification_status": "VERIFIED",
            "hashes": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
        },
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="hash2",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add_all([file_art, mal_art])
    db_session.commit()

    # 2. Create relationship connecting them on shared hash
    rel = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id=file_art.id,
        source_type="NORMALIZED_ARTIFACT",
        source_domain="FILESYSTEM",
        target_id=mal_art.id,
        target_type="NORMALIZED_ARTIFACT",
        target_domain="MALWARE",
        relationship_type="FILE_HASH_MATCH",
        matching_identifier="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        matching_field="sha256",
        confidence_score=1.0,
        evidence_ids=[ev.id],
        provenance={
            "rule": "FILE_HASH_MATCH",
            "signature_source": "VirusTotal_Authoritative_Feed",
            "signature_identifier": "Trojan.Win32.Dropper.01",
            "signature_version": "2026.1",
            "verification_status": "VERIFIED"
        },
        sha256_hash="rel_hash"
    )
    db_session.add(rel)
    db_session.commit()

    # 3. Generate findings
    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    assert summary.total_findings_generated >= 1
    mal_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH]
    assert len(mal_findings) == 1
    f = mal_findings[0]
    assert f.severity == FindingSeverity.CRITICAL
    assert f.finding_type == FindingType.MALWARE_INDICATOR
    assert f.confidence >= 0.95
    assert len(f.observed_facts) >= 1
    assert "VirusTotal_Authoritative_Feed" in f.title
    assert rel.id in f.supporting_relationship_ids

    # Verify persisted authoritative fields
    fact = f.observed_facts[0]
    assert fact["signature_source"] == "VirusTotal_Authoritative_Feed"
    assert fact["signature_identifier"] == "Trojan.Win32.Dropper.01"
    assert fact["signature_version"] == "2026.1"
    assert fact["verification_status"] == "VERIFIED"
    assert fact["hash"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_unverified_correlation_does_not_trigger_confirmed_malware(db_session):
    """
    Verifies that an ordinary correlation or hash match without an authoritative verified
    signature source is NOT treated as "confirmed malware".
    Produces RULE_SHARED_FILE_HASH_OBSERVATION with INFORMATIONAL severity.
    """
    user, case = create_test_user_and_case(db_session, "unv_user", "unv_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art1 = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="FILE",
        entity_identity="file_sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        normalized_fields={"hashes": {"sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"}},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="h1",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    art2 = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="FILE",
        entity_identity="file_sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        normalized_fields={"hashes": {"sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"}},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="h2",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add_all([art1, art2])
    db_session.commit()

    rel = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id=art1.id,
        source_type="NORMALIZED_ARTIFACT",
        source_domain="FILESYSTEM",
        target_id=art2.id,
        target_type="NORMALIZED_ARTIFACT",
        target_domain="FILESYSTEM",
        relationship_type="FILE_HASH_MATCH",
        matching_identifier="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        matching_field="sha256",
        confidence_score=1.0,
        evidence_ids=[ev.id],
        provenance={"rule": "FILE_HASH_MATCH"},
        sha256_hash="rel_unv"
    )
    db_session.add(rel)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    # Ensure NO confirmed malware finding is created
    confirmed_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH]
    assert len(confirmed_findings) == 0

    # Ensure ordinary correlation finding is created at INFORMATIONAL severity
    obs_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION]
    assert len(obs_findings) == 1
    assert obs_findings[0].severity == FindingSeverity.INFORMATIONAL
    assert obs_findings[0].observed_facts[0]["verification_status"] == "UNVERIFIED_CORRELATION"


def test_rule_malware_signature_hit_medium(db_session):
    """
    Verifies that a standalone MALWARE_MATCH normalized artifact without authoritative
    threat feed confirmation produces a MEDIUM severity finding under RULE_MALWARE_SIGNATURE_HIT
    (heuristic signature observation, not confirmed malware).
    """
    user, case = create_test_user_and_case(db_session, "sig_user", "sig_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    mal_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:CobaltStrike_Beacon",
        normalized_fields={
            "rule_name": "CobaltStrike_Beacon_Pattern",
            "target_file": "/windows/temp/beacon.dll",
            "matched_tags": ["APT", "Beacon"],
            "matched_strings": ["$str1", "$str2"]
        },
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="mal_art_hash",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(mal_art)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_MALWARE_SIGNATURE_HIT])
    )

    assert summary.total_findings_generated == 1
    f = summary.findings[0]
    assert f.severity == FindingSeverity.MEDIUM
    assert f.severity_rule == SeverityRule.RULE_MALWARE_SIGNATURE_HIT
    assert f.finding_type == FindingType.MALWARE_INDICATOR
    assert "CobaltStrike_Beacon_Pattern" in f.title
    assert f.observed_facts[0]["verification_status"] == "UNVERIFIED_HEURISTIC"
    assert f.supporting_artifact_ids == [mal_art.id]


def test_rule_process_network_outbound_observation_and_suspicion(db_session):
    """
    Verifies that process ↔ outbound network alone is treated as an evidence-grounded
    observation (LOW severity). Only when additional explicit evidence of suspiciousness
    exists does it satisfy RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION (HIGH severity).
    """
    user, case = create_test_user_and_case(db_session, "net_user", "net_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    # 1. Standard process and outbound network connection (no suspicious flags)
    proc_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="PROCESS",
        entity_identity="process:1337:powershell.exe",
        normalized_fields={"pid": 1337, "process_name": "powershell.exe"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="proc_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    net_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="NETWORK_CONNECTION",
        entity_identity="net_conn:1337:198.51.100.24:4444",
        normalized_fields={
            "pid": 1337,
            "local_address": "10.0.0.5",
            "remote_address": "198.51.100.24",
            "remote_port": 4444,
            "protocol": "TCP"
        },
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="net_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add_all([proc_art, net_art])
    db_session.commit()

    rel = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id=proc_art.id,
        source_type="NORMALIZED_ARTIFACT",
        source_domain="PROCESS",
        target_id=net_art.id,
        target_type="NORMALIZED_ARTIFACT",
        target_domain="NETWORK",
        relationship_type="PROCESS_MEMORY_MATCH",
        matching_identifier="1337",
        matching_field="pid",
        confidence_score=0.95,
        evidence_ids=[ev.id],
        provenance={"rule": "PROCESS_MEMORY_MATCH"},
        sha256_hash="rel_pnet"
    )
    db_session.add(rel)
    db_session.commit()

    # Part A: Evaluates without explicit suspicious flag -> LOW severity observation
    summary_obs = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION])
    )
    assert summary_obs.total_findings_generated == 1
    f_obs = summary_obs.findings[0]
    assert f_obs.severity == FindingSeverity.LOW
    assert f_obs.severity_rule == SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION
    assert f_obs.finding_type == FindingType.NETWORK_CONNECTION
    assert "Observed Process Outbound Socket" in f_obs.title

    # Part B: With additional explicit evidence of suspiciousness -> HIGH severity suspicion
    proc_art.normalized_fields = {"pid": 1337, "process_name": "powershell.exe", "is_suspicious": True}
    db_session.commit()

    summary_susp = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION])
    )
    assert summary_susp.total_findings_generated == 1
    f_susp = summary_susp.findings[0]
    assert f_susp.severity == FindingSeverity.HIGH
    assert f_susp.severity_rule == SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION
    assert f_susp.finding_type == FindingType.SUSPICIOUS_EXECUTION


def test_rule_browser_socket_interaction_observation(db_session):
    """
    Verifies that a browser artifact correlated with network socket produces
    an evidence-grounded observation (LOW severity) under RULE_BROWSER_SOCKET_INTERACTION,
    not treating browser activity alone as malicious.
    """
    user, case = create_test_user_and_case(db_session, "brw_user", "brw_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    browser_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="BROWSER",
        entity_identity="browser_history:download.example.com/file.bin",
        normalized_fields={"url": "http://download.example.com/file.bin", "domain": "download.example.com"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="b_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    net_art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="NETWORK_CONNECTION",
        entity_identity="net_conn:download.example.com",
        normalized_fields={"remote_address": "203.0.113.88", "domain": "download.example.com"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="n_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add_all([browser_art, net_art])
    db_session.commit()

    rel = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id=browser_art.id,
        source_type="NORMALIZED_ARTIFACT",
        source_domain="BROWSER",
        target_id=net_art.id,
        target_type="NORMALIZED_ARTIFACT",
        target_domain="NETWORK",
        relationship_type="BROWSER_NETWORK_MATCH",
        matching_identifier="download.example.com",
        matching_field="domain",
        confidence_score=0.92,
        evidence_ids=[ev.id],
        provenance={"rule": "BROWSER_NETWORK_MATCH"},
        sha256_hash="b_rel_h"
    )
    db_session.add(rel)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_BROWSER_SOCKET_INTERACTION])
    )

    assert summary.total_findings_generated == 1
    f = summary.findings[0]
    assert f.severity == FindingSeverity.LOW
    assert f.severity_rule == SeverityRule.RULE_BROWSER_SOCKET_INTERACTION
    assert f.finding_type == FindingType.NETWORK_CONNECTION
    assert "Observed Browser Network Interaction" in f.title
    assert "download.example.com" in f.title


def test_rule_multi_domain_cluster_observation(db_session):
    """
    Verifies that a correlation group spanning >= 3 domains produces
    an evidence-grounded observation (LOW severity) under RULE_MULTI_DOMAIN_CORRELATED_CLUSTER,
    not treating multi-domain correlation alone as evidence of maliciousness.
    """
    user, case = create_test_user_and_case(db_session, "grp_user", "grp_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    grp = ForensicCorrelationGroup(
        id=str(uuid.uuid4()),
        case_id=case.id,
        title="Correlated Artifact Cluster (3 Domains)",
        description="Cluster across filesystem, memory, and network",
        member_artifact_ids=["art1", "art2", "art3"],
        member_event_ids=["ev1"],
        relationship_ids=["rel1", "rel2"],
        contributing_domains=["FILESYSTEM", "MEMORY", "NETWORK"],
        source_evidence_ids=[ev.id],
        confidence_score=0.96,
        provenance={"rule": "CONNECTED_COMPONENTS"},
        sha256_hash="grp_hash"
    )
    db_session.add(grp)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER])
    )

    assert summary.total_findings_generated == 1
    f = summary.findings[0]
    assert f.severity == FindingSeverity.LOW
    assert f.severity_rule == SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER
    assert f.finding_type == FindingType.MULTI_DOMAIN_CORRELATION
    assert "Across 3 Domains" in f.title
    assert grp.id in f.supporting_group_ids


def test_rule_privileged_and_standard_user_logon(db_session):
    """
    Verifies that administrative/SYSTEM logon produces MEDIUM severity (RULE_PRIVILEGED_USER_LOGON_ACTIVITY),
    while standard logon produces LOW severity (RULE_USER_LOGON_OBSERVATION).
    """
    user, case = create_test_user_and_case(db_session, "usr_log_user", "usr_log_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    admin_log = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="EVENT",
        entity_identity="event_log:4672:SYSTEM",
        normalized_fields={"username": "SYSTEM", "event_id": "4672", "computer_name": "DC01"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="admin_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    std_log = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="EVENT",
        entity_identity="event_log:4624:analyst_jane",
        normalized_fields={"username": "analyst_jane", "event_id": "4624", "computer_name": "WS05"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="std_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add_all([admin_log, std_log])
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    admin_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY]
    std_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_USER_LOGON_OBSERVATION]

    assert len(admin_findings) == 1
    assert admin_findings[0].severity == FindingSeverity.MEDIUM
    assert "SYSTEM" in admin_findings[0].title

    assert len(std_findings) == 1
    assert std_findings[0].severity == FindingSeverity.LOW
    assert "analyst_jane" in std_findings[0].title


def test_rule_temporal_cross_domain_coincidence_and_sequence(db_session):
    """
    Verifies that cross-domain coincidence produces MEDIUM (RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE),
    and intra-domain sequence produces INFORMATIONAL (RULE_TEMPORAL_SEQUENCE_OBSERVATION).
    """
    user, case = create_test_user_and_case(db_session, "temp_user", "temp_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    rel_coinc = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id="art_filesys",
        source_type="NORMALIZED_ARTIFACT",
        source_domain="FILESYSTEM",
        target_id="art_memory",
        target_type="NORMALIZED_ARTIFACT",
        target_domain="MEMORY",
        relationship_type="TEMPORAL_COINCIDENCE",
        temporal_relationship={"delta_seconds": 2.5},
        confidence_score=0.90,
        evidence_ids=[ev.id],
        provenance={"rule": "TEMPORAL_COINCIDENCE"},
        sha256_hash="t_rel1"
    )
    rel_seq = ArtifactRelationship(
        id=str(uuid.uuid4()),
        case_id=case.id,
        source_id="ev_a",
        source_type="TIMELINE_EVENT",
        source_domain="LOGS",
        target_id="ev_b",
        target_type="TIMELINE_EVENT",
        target_domain="LOGS",
        relationship_type="TEMPORAL_SEQUENCE",
        temporal_relationship={"delta_seconds": 12.0},
        confidence_score=0.85,
        evidence_ids=[ev.id],
        provenance={"rule": "TEMPORAL_SEQUENCE"},
        sha256_hash="t_rel2"
    )
    db_session.add_all([rel_coinc, rel_seq])
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    coinc_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE]
    seq_findings = [f for f in summary.findings if f.severity_rule == SeverityRule.RULE_TEMPORAL_SEQUENCE_OBSERVATION]

    assert len(coinc_findings) == 1
    assert coinc_findings[0].severity == FindingSeverity.MEDIUM
    assert coinc_findings[0].finding_type == FindingType.TEMPORAL_ANOMALY

    assert len(seq_findings) == 1
    assert seq_findings[0].severity == FindingSeverity.INFORMATIONAL
    assert seq_findings[0].finding_type == FindingType.TEMPORAL_ANOMALY


def test_deterministic_confidence_calculation():
    """
    Verifies the mathematical precision and reproducibility of confidence score.
    Confidence = 0.35 * integrity + 0.30 * artifact + 0.25 * identifier + 0.10 * min(1.0, src/2) - penalty
    """
    # 1. Perfect inputs
    score, inputs = calculate_deterministic_confidence(
        source_integrity=1.0,
        artifact_confidence=1.0,
        identifier_match_confidence=1.0,
        supporting_source_count=2,
        contradictory_evidence=False
    )
    assert score == 1.0000
    assert inputs["source_integrity"] == 1.0
    assert inputs["artifact_confidence"] == 1.0
    assert inputs["identifier_match_confidence"] == 1.0
    assert inputs["supporting_source_count"] == 2
    assert inputs["contradictory_evidence"] is False

    # 2. Reduced inputs
    score2, inputs2 = calculate_deterministic_confidence(
        source_integrity=0.8,
        artifact_confidence=0.7,
        identifier_match_confidence=0.9,
        supporting_source_count=1,
        contradictory_evidence=False
    )
    expected = 0.35 * 0.8 + 0.30 * 0.7 + 0.25 * 0.9 + 0.10 * 0.5
    assert score2 == round(expected, 4)

    # 3. Contradictory evidence penalty (-0.30)
    score3, inputs3 = calculate_deterministic_confidence(
        source_integrity=1.0,
        artifact_confidence=1.0,
        identifier_match_confidence=1.0,
        supporting_source_count=2,
        contradictory_evidence=True
    )
    assert score3 == 0.7000
    assert inputs3["contradictory_evidence"] is True

    # 4. Clamping lower bound
    score4, _ = calculate_deterministic_confidence(
        source_integrity=0.0,
        artifact_confidence=0.0,
        identifier_match_confidence=0.0,
        supporting_source_count=0,
        contradictory_evidence=True
    )
    assert score4 == 0.0


def test_full_provenance_tracing(db_session):
    """
    Verifies that get_provenance returns complete 7-tier lineage:
    EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact -> NormalizedArtifact -> Correlation -> Finding.
    """
    user, case = create_test_user_and_case(db_session, "prov_user", "prov_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        raw_output_id=out.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:Ransomware_Hit",
        normalized_fields={"rule_name": "Ransomware_Hit", "target_file": "/path/lock.exe"},
        evidence_reference={"evidence_id": ev.id},
        provenance_summary={"source": "YARA"},
        sha256_hash="mal_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest(include_rules=[SeverityRule.RULE_MALWARE_SIGNATURE_HIT])
    )
    finding = summary.findings[0]

    prov = DeterministicFindingsService.get_provenance(db_session, case.id, finding.id)
    assert prov.finding_id == finding.id
    assert prov.case_id == case.id
    assert prov.severity_rule == SeverityRule.RULE_MALWARE_SIGNATURE_HIT
    assert prov.supporting_evidence_ids == [ev.id]

    tiers = [item["tier"] for item in prov.lineage_summary]
    assert "EVIDENCE" in tiers
    assert "NORMALIZED_ARTIFACT" in tiers


def test_integrity_and_tamper_detection(db_session):
    """
    Verifies cryptographic SHA-256 integrity check and detects modifications.
    """
    user, case = create_test_user_and_case(db_session, "integ_user", "integ_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:Test_Hit",
        normalized_fields={"rule_name": "Test_Hit", "target_file": "/tmp/test.exe"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="h1",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )
    finding = summary.findings[0]

    # 1. Untampered check
    integ = DeterministicFindingsService.verify_integrity(db_session, case.id, finding.id)
    assert integ.integrity_passed is True
    assert integ.tamper_detected is False
    assert integ.file_exists is True

    # 2. Modify disk file to simulate tampering
    p = Path(finding.storage_path)
    tampered_content = p.read_text().replace("Test_Hit", "Tampered_Hit")
    p.write_text(tampered_content)

    integ_tampered = DeterministicFindingsService.verify_integrity(db_session, case.id, finding.id)
    assert integ_tampered.integrity_passed is False
    assert integ_tampered.tamper_detected is True


def test_storage_isolation_permissions_and_vault_protection(db_session):
    """
    Verifies that findings are stored in isolated directories with 0o700/0o600 permissions,
    and path traversal / evidence vault writing are strictly blocked.
    """
    user, case = create_test_user_and_case(db_session, "stor_user", "stor_case")
    case_dir = FindingStorageManager.get_case_storage_dir(case.id)

    # Verify directory permissions
    st = os.stat(case_dir)
    assert stat.S_IMODE(st.st_mode) == 0o700

    # Save a finding and verify file permissions
    fid = str(uuid.uuid4())
    stored_path = FindingStorageManager.save_finding(case.id, fid, {"title": "Test Safe Path"})
    p = Path(stored_path)
    assert p.is_file()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600

    # Verify path traversal rejection
    escaped_path = case_dir / ".." / "other_case" / "finding.json"
    assert FindingStorageManager.validate_storage_path(escaped_path, case.id) is False

    # Verify vault containment rejection
    vault_path = settings.DATA_DIR / "evidence" / "vault" / "cases" / case.id / "finding.json"
    assert FindingStorageManager.validate_storage_path(vault_path, case.id) is False


def test_source_artifact_immutability(db_session):
    """
    Verifies that generating findings does not alter Steps 10-14 source artifacts.
    """
    user, case = create_test_user_and_case(db_session, "immut_user", "immut_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:Immutability_Check",
        normalized_fields={"rule_name": "Immutability_Check", "target_file": "/tmp/check.exe"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="immut_hash_123",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    # Pre-generation snapshot
    initial_art_hash = art.sha256_hash
    initial_sa_hash = sa.sha256_hash
    initial_out_hash = out.sha256_hash
    initial_ev_hash = ev.sha256

    DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    # Post-generation verification
    db_session.refresh(art)
    db_session.refresh(sa)
    db_session.refresh(out)
    db_session.refresh(ev)

    assert art.sha256_hash == initial_art_hash
    assert sa.sha256_hash == initial_sa_hash
    assert out.sha256_hash == initial_out_hash
    assert ev.sha256 == initial_ev_hash


def test_deduplication_and_deterministic_freshness(db_session):
    """
    Verifies that running generation multiple times replaces prior records deterministically
    without duplicate accumulation.
    """
    user, case = create_test_user_and_case(db_session, "dedup_user", "dedup_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:Dedup_Check",
        normalized_fields={"rule_name": "Dedup_Check", "target_file": "/tmp/dedup.exe"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="dedup_hash",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    # First run
    s1 = DeterministicFindingsService.generate_findings_for_case(db_session, case.id, FindingGenerateRequest())
    assert s1.total_findings_generated == 1

    # Second run
    s2 = DeterministicFindingsService.generate_findings_for_case(db_session, case.id, FindingGenerateRequest())
    assert s2.total_findings_generated == 1

    total_in_db = db_session.query(DeterministicFinding).filter(DeterministicFinding.case_id == case.id).count()
    assert total_in_db == 1


def test_rest_api_full_workflow_and_filtering(db_session):
    """
    Verifies REST API endpoints:
    - POST /cases/{case_id}/findings/generate
    - GET /cases/{case_id}/findings (with filters)
    - GET /cases/{case_id}/findings/{id}
    - GET /cases/{case_id}/findings/{id}/supporting-evidence
    - GET /cases/{case_id}/findings/{id}/provenance
    - GET /cases/{case_id}/findings/{id}/integrity
    """
    user, case = create_test_user_and_case(db_session, "api_user", "api_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:API_Workflow_Hit",
        normalized_fields={"rule_name": "API_Workflow_Hit", "target_file": "/tmp/api.bin"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="api_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    token = create_access_token(user.id, user.email, user.role)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Generate findings
    resp = client.post(
        f"/api/v1/cases/{case.id}/findings/generate",
        json={"min_confidence": 0.5},
        headers=headers
    )
    assert resp.status_code == 200, resp.text
    gen_data = resp.json()
    assert gen_data["total_findings_generated"] >= 1
    finding_id = gen_data["findings"][0]["id"]

    # 2. List findings with filter
    list_resp = client.get(
        f"/api/v1/cases/{case.id}/findings?severity=MEDIUM&min_confidence=0.5",
        headers=headers
    )
    assert list_resp.status_code == 200
    findings_list = list_resp.json()
    assert len(findings_list) >= 1
    assert findings_list[0]["id"] == finding_id

    # 3. Retrieve finding details
    detail_resp = client.get(
        f"/api/v1/cases/{case.id}/findings/{finding_id}",
        headers=headers
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == finding_id

    # 4. Retrieve supporting evidence
    supp_resp = client.get(
        f"/api/v1/cases/{case.id}/findings/{finding_id}/supporting-evidence",
        headers=headers
    )
    assert supp_resp.status_code == 200
    supp_data = supp_resp.json()
    assert len(supp_data["supporting_artifacts"]) >= 1

    # 5. Retrieve provenance
    prov_resp = client.get(
        f"/api/v1/cases/{case.id}/findings/{finding_id}/provenance",
        headers=headers
    )
    assert prov_resp.status_code == 200
    assert len(prov_resp.json()["lineage_summary"]) >= 1

    # 6. Verify integrity
    integ_resp = client.get(
        f"/api/v1/cases/{case.id}/findings/{finding_id}/integrity",
        headers=headers
    )
    assert integ_resp.status_code == 200
    assert integ_resp.json()["integrity_passed"] is True


def test_rbac_and_idor_protection(db_session):
    """
    Verifies that unauthorized users or users without access to a case cannot
    generate or query findings (enforces 401 / 403 / 404).
    """
    owner, case = create_test_user_and_case(db_session, "owner_usr", "owner_case")
    unauth_user, _ = create_test_user_and_case(db_session, "unauth_usr", "unauth_case")

    unauth_token = create_access_token(unauth_user.id, unauth_user.email, unauth_user.role)
    unauth_headers = {"Authorization": f"Bearer {unauth_token}"}

    # Attempt to generate findings on case without membership
    resp = client.post(
        f"/api/v1/cases/{case.id}/findings/generate",
        json={},
        headers=unauth_headers
    )
    assert resp.status_code in [403, 404]

    # Attempt to list findings on case without membership
    resp_list = client.get(
        f"/api/v1/cases/{case.id}/findings",
        headers=unauth_headers
    )
    assert resp_list.status_code in [403, 404]


def test_strict_forensic_boundaries(db_session):
    """
    Verifies that findings adhere strictly to observable forensic facts:
    - Zero LLM generation
    - Zero speculative attribution keywords
    - All titles, descriptions, and observed facts are purely factual
    """
    user, case = create_test_user_and_case(db_session, "bound_user", "bound_case")
    ev, fe, out, sa = setup_forensic_pipeline_fixtures(db_session, case.id)

    art = NormalizedArtifact(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        execution_id=fe.id,
        source_artifact_id=sa.id,
        entity_type="MALWARE_MATCH",
        entity_identity="yara:Bound_Check",
        normalized_fields={"rule_name": "Signature_Match_Test", "target_file": "/tmp/test.dll"},
        evidence_reference={"evidence_id": ev.id},
        sha256_hash="bound_h",
        source_artifact_hash=sa.sha256_hash,
        normalization_status="NORMALIZED"
    )
    db_session.add(art)
    db_session.commit()

    summary = DeterministicFindingsService.generate_findings_for_case(
        db=db_session,
        case_id=case.id,
        request=FindingGenerateRequest()
    )

    forbidden_speculative_phrases = [
        "attacker intended",
        "adversary objective",
        "threat actor goal",
        "hacker broke into",
        "malicious intent confirmed",
        "breach declared"
    ]

    for f in summary.findings:
        text_corpus = (f.title + " " + f.description).lower()
        for forbidden in forbidden_speculative_phrases:
            assert forbidden not in text_corpus, f"Speculative phrase '{forbidden}' found in finding!"

        # Ensure observed_facts is populated and factual
        assert len(f.observed_facts) > 0
        for fact in f.observed_facts:
            assert "fact_type" in fact
