from typing import Optional
from forensic_tools.registry import tool_registry, ToolExecutionRequest, ToolExecutionResult


class ExifToolAdapter:
    """
    ExifTool forensic adapter for file, document, and archive metadata extraction.
    Executes exclusively through the PlatformAwareToolRegistry with shell=False.
    """

    def __init__(self):
        self.tool_name = "exiftool"

    def is_available(self) -> bool:
        tool = tool_registry.get_tool(self.tool_name)
        return tool is not None and tool.is_available

    def get_tool_version(self) -> Optional[str]:
        tool = tool_registry.get_tool(self.tool_name)
        return tool.version if tool else None

    def execute_metadata_extraction(
        self,
        evidence_path: str,
        timeout_seconds: int = 60,
        execution_id: Optional[str] = None
    ) -> ToolExecutionResult:
        """
        Executes 'exiftool -j' on the target evidence file.
        Returns structured ToolExecutionResult containing stdout JSON and execution telemetry.
        """
        req = ToolExecutionRequest(
            tool_name=self.tool_name,
            evidence_path=evidence_path,
            arguments=["-j"],
            timeout_seconds=timeout_seconds,
            execution_id=execution_id
        )
        return tool_registry.execute_tool(req)

