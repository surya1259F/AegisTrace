import subprocess
import shutil
import json
from typing import Dict, Any, List

class SleuthKitRunner:
    """
    Interface for The Sleuth Kit (TSK) forensic tools.
    Extracts filesystem metadata, directory structures, deleted files, and file contents.
    """

    def __init__(self):
        self.fls_bin = shutil.which("fls")
        self.fsstat_bin = shutil.which("fsstat")
        self.icat_bin = shutil.which("icat")

    def is_available(self) -> bool:
        return self.fls_bin is not None

    def list_files(self, image_path: str, offset_sectors: int = 0) -> List[Dict[str, Any]]:
        """
        Runs `fls -r -p` to recursively list files and directories.
        Returns structured list of filesystem entries.
        """
        if not self.is_available():
            return [{"warning": "fls binary not found in PATH"}]

        cmd = [self.fls_bin, "-r", "-p"]
        if offset_sectors > 0:
            cmd.extend(["-o", str(offset_sectors)])
        cmd.append(image_path)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            entries = []
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    file_type = parts[0] # r/r, d/d, etc.
                    inode = parts[1].rstrip(":")
                    path = " ".join(parts[2:])
                    is_deleted = "*" in parts[0] or "(deleted)" in line.lower()
                    entries.append({
                        "type": file_type,
                        "inode": inode,
                        "path": path,
                        "is_deleted": is_deleted
                    })
            return entries
        except Exception as e:
            return [{"error": str(e)}]
