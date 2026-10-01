import subprocess
from pathlib import Path
from typing import Dict, Any, List
from backend.app.core.config import settings

class VolatilityRunner:
    """
    Interface for Volatility 3 Memory Forensics Framework.
    Runs memory analysis plugins against raw/dmp dumps.
    """

    def __init__(self):
        self.vol_cli = str(settings.VOLATILITY_CLI)

    def is_available(self) -> bool:
        return Path(self.vol_cli).exists()

    def run_plugin(self, image_path: str, plugin_name: str, extra_args: List[str] = None) -> Dict[str, Any]:
        """
        Executes a Volatility 3 plugin with JSON/structured output.
        Supported plugins include: windows.pslist, windows.pstree, windows.netscan, windows.malfind, windows.cmdline
        """
        if not self.is_available():
            return {"status": "error", "message": f"Volatility 3 binary not found at {self.vol_cli}"}

        cmd = [self.vol_cli, "-f", image_path, "-r", "json", plugin_name]
        if extra_args:
            cmd.extend(extra_args)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "status": "success" if res.returncode == 0 else "warning",
                "plugin": plugin_name,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "return_code": res.returncode
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
