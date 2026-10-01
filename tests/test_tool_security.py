import pytest
from forensic_tools.registry import tool_registry, ToolExecutionRequest

def test_shell_injection_strings_treated_as_literal_arguments():
    # Because shell=False is enforced, shell operators are passed literally to the binary
    # and cannot invoke a subshell or chained commands.
    injection_strings = [
        "; echo PWNED",
        "&& echo PWNED",
        "| echo PWNED",
        "`echo PWNED`",
        "$(echo PWNED)",
        "|| cat /etc/passwd"
    ]

    for inj in injection_strings:
        req = ToolExecutionRequest(
            tool_name="exiftool",
            evidence_path="/tmp/test.txt",
            arguments=[inj]
        )
        res = tool_registry.execute_tool(req)
        # Verify shell command was NOT executed in a subshell
        assert "PWNED" not in res.stdout

def test_null_byte_rejection_in_validation():
    req = ToolExecutionRequest(
        tool_name="sleuthkit",
        evidence_path="/tmp/file.dd\0.txt",
        arguments=[]
    )
    val_err = tool_registry.validate_request(req)
    assert val_err is not None
    assert "Null byte" in val_err

def test_unregistered_executable_rejection():
    dangerous_executables = [
        "bash", "sh", "zsh", "cmd.exe", "powershell.exe",
        "nc", "netcat", "curl", "wget", "eval"
    ]
    for exe in dangerous_executables:
        req = ToolExecutionRequest(
            tool_name=exe,
            evidence_path="/tmp/sample.dd",
            arguments=[]
        )
        val_err = tool_registry.validate_request(req)
        assert val_err is not None
        assert "Unknown or disallowed tool" in val_err

def test_path_traversal_in_tool_name_rejection():
    req = ToolExecutionRequest(
        tool_name="../../bin/sh",
        evidence_path="/tmp/sample.dd",
        arguments=[]
    )
    val_err = tool_registry.validate_request(req)
    assert val_err is not None
    assert "Unknown or disallowed tool" in val_err
