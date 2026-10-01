from typing import Dict, Any, List, Optional
from forensic_tools.registry import tool_registry, ToolExecutionRequest, ToolExecutionResult

class SleuthKitAdapter:
    """
    SleuthKit forensic adapter for volume and filesystem analysis.
    Executes exclusively through the PlatformAwareToolRegistry (shell=False).
    """

    def __init__(self):
        self.tool_name = "sleuthkit"

    def is_available(self) -> bool:
        tool = tool_registry.get_tool(self.tool_name)
        return tool is not None and tool.is_available

    def get_tool_version(self) -> Optional[str]:
        tool = tool_registry.get_tool(self.tool_name)
        return tool.version if tool else None

    def execute_fls(
        self,
        evidence_path: str,
        recursive: bool = True,
        include_deleted: bool = True,
        offset_sectors: int = 0,
        timeout_seconds: int = 60,
        execution_id: Optional[str] = None
    ) -> ToolExecutionResult:
        """
        Executes 'fls' on a target disk/partition image.
        Builds validated argument array without shell construction.
        """
        args = []
        if recursive:
            args.append("-r")
        if include_deleted:
            args.append("-p")
        if offset_sectors > 0:
            args.extend(["-o", str(offset_sectors)])

        req = ToolExecutionRequest(
            tool_name=self.tool_name,
            evidence_path=evidence_path,
            arguments=args,
            timeout_seconds=timeout_seconds,
            execution_id=execution_id
        )
        return tool_registry.execute_tool(req)
