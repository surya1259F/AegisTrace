import pytest
from pathlib import Path
from agents.log.log_agent import LogAgent

SAMPLE_XML_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "log" / "sample_security_events.xml"

def test_log_agent_can_handle():
    agent = LogAgent()
    assert agent.can_handle("log") is True
    assert agent.can_handle("file") is True
    assert agent.can_handle("event_log") is True
    assert agent.can_handle("evtx") is True
    assert agent.can_handle("network_capture") is False

def test_log_agent_rejects_unsupported_evidence():
    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "traffic.pcap",
        "evidence_type": "network_capture",
        "storage_path": "/vault/traffic.pcap"
    })
    assert res["status"] == "UNSUPPORTED_EVIDENCE_TYPE"
    assert len(res["artifacts"]) == 0

def test_log_agent_rejects_unvaulted_evidence():
    agent = LogAgent()
    # Case 1: missing storage_path
    res1 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "sample.evtx",
        "evidence_type": "log",
        "original_path": "/raw/sample.evtx"
    })
    assert res1["status"] == "UNVAULTED_EVIDENCE_REJECTED"

    # Case 2: storage_path == original_path
    res2 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "sample.evtx",
        "evidence_type": "log",
        "original_path": "/raw/sample.evtx",
        "storage_path": "/raw/sample.evtx"
    })
    assert res2["status"] == "UNVAULTED_EVIDENCE_REJECTED"

def test_log_agent_handles_invalid_path():
    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "missing.evtx",
        "evidence_type": "log",
        "storage_path": "/nonexistent/missing.evtx"
    })
    assert res["status"] == "INVALID_EVIDENCE_PATH"

def test_log_agent_analyzes_sample_events_and_generates_findings():
    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-sample-log",
        "investigation_id": "inv-test",
        "name": "sample_security_events.xml",
        "evidence_type": "log",
        "original_path": "/raw/source/sample_security_events.xml",
        "storage_path": str(SAMPLE_XML_FIXTURE)
    })
    assert res["status"] == "SUCCESS"
    assert res["artifacts_count"] == 5
    assert res["findings_count"] >= 4

    # Verify Artifact types
    art_types = [a["artifact_type"] for a in res["artifacts"]]
    assert "windows_logon_event" in art_types
    assert "windows_process_creation" in art_types
    assert "windows_service_installation" in art_types
    assert "windows_privilege_assignment" in art_types

    # Verify Provenance
    for a in res["artifacts"]:
        assert a["agent"] in ["LogAgent", "LogForensicsAgent"]
        assert a["tool"] == "python-evtx"
        assert "record:" in a["source_reference"]

    # Verify Findings
    for f in res["findings"]:
        assert f["agent"] in ["LogAgent", "LogForensicsAgent"]
        assert f["verification_status"] == "UNVERIFIED"
        assert "record:" in f["evidence_reference"]
