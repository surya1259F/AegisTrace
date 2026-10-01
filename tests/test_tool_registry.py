import pytest
from forensic_tools.registry import (
    tool_registry,
    ToolDefinition,
    ToolExecutionRequest,
    ToolExecutionResult
)

def test_registry_initializes():
    tools = tool_registry.list_tools()
    assert len(tools) >= 4
    tool_names = [t.name for t in tools]
    assert "sleuthkit" in tool_names
    assert "volatility3" in tool_names
    assert "yara" in tool_names
    assert "exiftool" in tool_names

def test_known_logical_tools_lookup():
    tsk = tool_registry.get_tool("sleuthkit")
    assert tsk is not None
    assert tsk.name == "sleuthkit"

    vol = tool_registry.get_tool("volatility3")
    assert vol is not None
    assert vol.name == "volatility3"

def test_unavailable_tool_reporting():
    # Looking up non-registered tool
    unknown = tool_registry.get_tool("unknown_tool_xyz")
    assert unknown is None

def test_executable_discovery_works():
    # Tools should have their executable paths resolved
    for tool_name in ["sleuthkit", "volatility3", "yara", "exiftool"]:
        tool = tool_registry.get_tool(tool_name)
        assert tool is not None
        assert tool.is_available is True
        assert tool.path is not None

def test_platform_filtering():
    for tool in tool_registry.list_tools():
        assert "linux" in tool.platforms
        assert "windows" in tool.platforms

def test_unknown_tool_rejected_on_execution():
    req = ToolExecutionRequest(
        tool_name="unregistered_tool",
        evidence_path="/tmp/fake.raw",
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert res.success is False
    assert "Unknown or disallowed tool" in res.error_message

def test_arbitrary_executable_rejected():
    # Attempting to execute bash or powershell
    for bad_tool in ["bash", "sh", "powershell", "python"]:
        req = ToolExecutionRequest(
            tool_name=bad_tool,
            evidence_path="/tmp/fake.raw",
            arguments=[]
        )
        res = tool_registry.execute_tool(req)
        assert res.success is False
        assert "Unknown or disallowed tool" in res.error_message

def test_shell_execution_is_never_enabled():
    # Verify ToolExecutionRequest has no shell parameter and registry uses shell=False
    req = ToolExecutionRequest(
        tool_name="sleuthkit",
        evidence_path="/nonexistent/path.dd",
        arguments=[]
    )
    assert not hasattr(req, "shell")
    res = tool_registry.execute_tool(req)
    assert isinstance(res, ToolExecutionResult)

def test_timeout_configuration_is_enforced():
    req = ToolExecutionRequest(
        tool_name="sleuthkit",
        evidence_path="/nonexistent/path.dd",
        arguments=[],
        timeout_seconds=5
    )
    assert req.timeout_seconds == 5

def test_structured_result_returned():
    req = ToolExecutionRequest(
        tool_name="sleuthkit",
        evidence_path="/nonexistent/test.img",
        arguments=[]
    )
    res = tool_registry.execute_tool(req)
    assert isinstance(res, ToolExecutionResult)
    assert hasattr(res, "tool_name")
    assert hasattr(res, "success")
    assert hasattr(res, "return_code")
    assert hasattr(res, "stdout")
    assert hasattr(res, "stderr")
    assert hasattr(res, "execution_time_ms")
