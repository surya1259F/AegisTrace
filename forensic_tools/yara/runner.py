import subprocess
import shutil
from typing import Dict, Any, List

class YaraRunner:
    """
    Interface for YARA pattern matching.
    Scans files, directories, and memory dumps for malware signatures.
    """

    def __init__(self):
        self.yara_bin = shutil.which("yara")

    def is_available(self) -> bool:
        return self.yara_bin is not None

    def scan_target(self, rule_path: str, target_path: str) -> List[Dict[str, Any]]:
        if not self.is_available():
            return [{"warning": "yara binary not found in PATH"}]

        cmd = [self.yara_bin, "-s", "-m", rule_path, target_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            matches = []
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    rule_name = parts[0]
                    matched_target = parts[1]
                    matches.append({
                        "rule": rule_name,
                        "target": matched_target,
                        "raw": line
                    })
            return matches
        except Exception as e:
            return [{"error": str(e)}]
