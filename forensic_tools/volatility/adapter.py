from typing import Dict, Any, List, Optional
from forensic_tools.registry import tool_registry, ToolExecutionRequest, ToolExecutionResult

ALLOWED_PLUGINS = {
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.malfind"
}

class VolatilityAdapter:
    """
    Volatility 3 forensic adapter for memory dump analysis.
    Executes exclusively through the PlatformAwareToolRegistry (shell=False).
    Enforces plugin allowlist.
    """

    def __init__(self):
        self.tool_name = "volatility3"

    def is_available(self) -> bool:
        tool = tool_registry.get_tool(self.tool_name)
        return tool is not None and tool.is_available

    def get_tool_version(self) -> Optional[str]:
        tool = tool_registry.get_tool(self.tool_name)
        return tool.version if tool else None

    def execute_plugin(
        self,
        evidence_path: str,
        plugin_name: str,
        extra_args: Optional[List[str]] = None,
        timeout_seconds: int = 120,
        execution_id: Optional[str] = None
    ) -> ToolExecutionResult:
        """
        Executes an approved Volatility 3 plugin on a target memory image.
        """
        clean_plugin = plugin_name.strip().lower()
        if clean_plugin not in ALLOWED_PLUGINS:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Plugin '{plugin_name}' is not in the allowed Volatility plugin allowlist: {sorted(ALLOWED_PLUGINS)}",
                execution_time_ms=0,
                evidence_path=evidence_path,
                error_message=f"Plugin '{plugin_name}' is disallowed or unsupported."
            )

        args = [plugin_name]
        if extra_args:
            args.extend(extra_args)

        req = ToolExecutionRequest(
            tool_name=self.tool_name,
            evidence_path=evidence_path,
            arguments=args,
            timeout_seconds=timeout_seconds,
            execution_id=execution_id
        )
        return tool_registry.execute_tool(req)
