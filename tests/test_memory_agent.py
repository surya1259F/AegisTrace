import pytest
from unittest.mock import MagicMock
from agents.memory.memory_agent import MemoryAgent
from forensic_tools.registry import ToolExecutionResult
from tests.test_memory_parsers import SAMPLE_PSLIST_OUTPUT, SAMPLE_NETSCAN_OUTPUT

def test_memory_agent_can_handle():
    agent = MemoryAgent()
    assert agent.can_handle("memory_dump") is True
    assert agent.can_handle("raw_memory") is True
    assert agent.can_handle("vmem") is True
    assert agent.can_handle("dmp") is True
    assert agent.can_handle("disk_image") is False
    assert agent.can_handle("network_capture") is False

def test_memory_agent_rejects_unsupported_evidence():
    agent = MemoryAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "disk.raw",
        "evidence_type": "disk_image",
        "storage_path": "/vault/disk.raw"
    })
    assert res["status"] == "UNSUPPORTED_EVIDENCE_TYPE"
    assert len(res["artifacts"]) == 0

def test_memory_agent_rejects_unvaulted_evidence():
    agent = MemoryAgent()
    # Case 1: missing storage_path
    res1 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "mem.dmp",
        "evidence_type": "memory_dump",
        "original_path": "/raw/mem.dmp"
    })
    assert res1["status"] == "UNVAULTED_EVIDENCE_REJECTED"

    # Case 2: storage_path == original_path
    res2 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "mem.dmp",
        "evidence_type": "memory_dump",
        "original_path": "/raw/mem.dmp",
        "storage_path": "/raw/mem.dmp"
    })
    assert res2["status"] == "UNVAULTED_EVIDENCE_REJECTED"

def test_memory_agent_handles_invalid_path():
    agent = MemoryAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "mem.dmp",
        "evidence_type": "memory_dump",
        "storage_path": "/nonexistent/path/mem.dmp"
    })
    assert res["status"] == "INVALID_EVIDENCE_PATH"

def test_memory_agent_rejects_disallowed_plugin():
    agent = MemoryAgent()
    # Create fake temporary file for path validation
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        res = agent.analyze({
            "id": "ev-1",
            "investigation_id": "inv-1",
            "name": "mem.dmp",
            "evidence_type": "memory_dump",
            "original_path": "/raw/source/mem.dmp",
            "storage_path": tf.name
        }, parameters={"plugin": "malicious_unregistered_plugin"})
        assert res["status"] == "PLUGIN_UNAVAILABLE"

def test_memory_agent_pslist_artifact_and_finding_generation(monkeypatch):
    import tempfile
    agent = MemoryAgent()

    # Mock the adapter's execute_plugin to return representative pslist output
    mock_res = ToolExecutionResult(
        tool_name="volatility3",
        success=True,
        return_code=0,
        stdout=SAMPLE_PSLIST_OUTPUT,
        stderr="",
        execution_time_ms=1200.0,
        evidence_path="/tmp/fake_mem.dmp",
        tool_version="2.28.0"
    )
    monkeypatch.setattr(agent.adapter, "execute_plugin", MagicMock(return_value=mock_res))

    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        res = agent.analyze({
            "id": "ev-1",
            "investigation_id": "inv-1",
            "name": "mem.dmp",
            "evidence_type": "memory_dump",
            "original_path": "/raw/source/mem.dmp",
            "storage_path": tf.name
        }, parameters={"plugin": "windows.pslist"})

        assert res["status"] == "SUCCESS"
        assert res["artifacts_count"] == 5
        # mimikatz.exe is recognized by finding generation rule
        assert res["findings_count"] == 1
        assert "mimikatz.exe" in res["findings"][0]["title"]
        assert res["findings"][0]["evidence_reference"] == "pid:1420"
        assert res["findings"][0]["verification_status"] == "UNVERIFIED"

def test_memory_agent_netscan_finding_generation(monkeypatch):
    import tempfile
    agent = MemoryAgent()

    mock_res = ToolExecutionResult(
        tool_name="volatility3",
        success=True,
        return_code=0,
        stdout=SAMPLE_NETSCAN_OUTPUT,
        stderr="",
        execution_time_ms=1500.0,
        evidence_path="/tmp/fake_mem.dmp",
        tool_version="2.28.0"
    )
    monkeypatch.setattr(agent.adapter, "execute_plugin", MagicMock(return_value=mock_res))

    with tempfile.NamedTemporaryFile(suffix=".dmp") as tf:
        res = agent.analyze({
            "id": "ev-1",
            "investigation_id": "inv-1",
            "name": "mem.dmp",
            "evidence_type": "memory_dump",
            "original_path": "/raw/source/mem.dmp",
            "storage_path": tf.name
        }, parameters={"plugin": "windows.netscan"})

        assert res["status"] == "SUCCESS"
        assert res["artifacts_count"] == 3
        # 198.51.100.22 is a public external IP in ESTABLISHED state
        assert res["findings_count"] == 1
        assert "198.51.100.22" in res["findings"][0]["title"]
        assert res["findings"][0]["evidence_reference"] == "ip:198.51.100.22"
