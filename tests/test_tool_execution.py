import pytest
import os
from pathlib import Path
from forensic_tools.registry import tool_registry, ToolExecutionRequest

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "forensic_tools"
SAMPLE_TXT = str(FIXTURES_DIR / "sample.txt")
SAMPLE_YAR = str(FIXTURES_DIR / "sample.yar")

def test_valid_registered_tool_exiftool_execution():
    req = ToolExecutionRequest(
        tool_name="exiftool",
        evidence_path=SAMPLE_TXT,
        arguments=[],
        timeout_seconds=30
    )
    res = tool_registry.execute_tool(req)
    assert res.success is True
    assert res.return_code == 0
    assert "File Name" in res.stdout or "MIME Type" in res.stdout
    assert res.execution_time_ms > 0

def test_valid_registered_tool_yara_execution():
    req = ToolExecutionRequest(
        tool_name="yara",
        evidence_path=SAMPLE_TXT,
        arguments=[SAMPLE_YAR],
        timeout_seconds=30
    )
    res = tool_registry.execute_tool(req)
    assert res.success is True
    assert res.return_code == 0
    assert "Synthetic_Test_Rule" in res.stdout

def test_invalid_tool_name_failure():
    req = ToolExecutionRequest(
        tool_name="malicious_custom_tool",
        evidence_path=SAMPLE_TXT,
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert res.return_code == -1
    assert "Unknown or disallowed tool" in res.error_message

def test_malicious_tool_name_with_injection():
    req = ToolExecutionRequest(
        tool_name="sleuthkit; rm -rf /",
        evidence_path=SAMPLE_TXT,
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert "Unknown or disallowed tool" in res.error_message

def test_null_byte_in_arguments():
    req = ToolExecutionRequest(
        tool_name="exiftool",
        evidence_path=SAMPLE_TXT,
        arguments=["-json\0--bad"]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert "Null byte detected" in res.error_message

def test_null_byte_in_evidence_path():
    req = ToolExecutionRequest(
        tool_name="exiftool",
        evidence_path=f"{SAMPLE_TXT}\0extra",
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert "Null byte detected" in res.error_message

def test_non_zero_exit_code_and_stderr_capture():
    # Running exiftool on non-existent file
    req = ToolExecutionRequest(
        tool_name="exiftool",
        evidence_path="/tmp/non_existent_forensic_file_9999.xyz",
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert res.return_code != 0
    assert len(res.stderr) > 0 or "File not found" in res.stdout or res.error_message is not None

def test_stdout_and_stderr_captured_cleanly():
    req = ToolExecutionRequest(
        tool_name="exiftool",
        evidence_path=SAMPLE_TXT,
        arguments=["-ver"]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is True
    assert len(res.stdout.strip()) > 0
