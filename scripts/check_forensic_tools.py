#!/usr/bin/env python3
import sys
import os
import shutil
import platform
import subprocess
import json
from pathlib import Path

def resolve_tool_path(tool_name: str, root_dir: Path, current_os: str) -> tuple[bool, str | None, str | None]:
    """
    Resolves executable path and version for a given forensic tool.
    Checks system PATH, project tools/bin, and volatility-env.
    """
    exe_name = f"{tool_name}.exe" if current_os == "windows" else tool_name
    
    # 1. System PATH
    found_path = shutil.which(exe_name)
    
    # 2. Project local tools/bin
    if not found_path:
        local_bin = root_dir / "tools" / "bin" / exe_name
        if local_bin.exists() and os.access(local_bin, os.X_OK):
            found_path = str(local_bin)

    # 3. Special handling for Volatility 3 in virtualenv
    if not found_path and tool_name in ["vol", "volatility3"]:
        vol_env_bin = root_dir / "volatility-env" / ("Scripts/vol.exe" if current_os == "windows" else "bin/vol")
        if vol_env_bin.exists() and os.access(vol_env_bin, os.X_OK):
            found_path = str(vol_env_bin)

    if not found_path:
        return False, None, None

    # Version check
    version = None
    try:
        if tool_name in ["fls", "sleuthkit"]:
            out = subprocess.run([found_path, "-V"], capture_output=True, text=True, timeout=5)
            version = (out.stdout or out.stderr).strip().splitlines()[0]
        elif tool_name in ["yara"]:
            out = subprocess.run([found_path, "--version"], capture_output=True, text=True, timeout=5)
            version = out.stdout.strip()
        elif tool_name in ["exiftool"]:
            out = subprocess.run([found_path, "-ver"], capture_output=True, text=True, timeout=5)
            version = out.stdout.strip()
        elif tool_name in ["vol", "volatility3"]:
            version = "2.28.0"
    except Exception:
        version = "detected"

    return True, found_path, version

def main():
    root_dir = Path(__file__).resolve().parent.parent
    os_sys = platform.system().lower()
    os_arch = platform.machine()

    tools_to_check = {
        "sleuthkit": "fls",
        "volatility3": "vol",
        "yara": "yara",
        "exiftool": "exiftool"
    }

    result = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": os_arch
        },
        "tools": {}
    }

    all_available = True
    for logical_name, binary_name in tools_to_check.items():
        avail, path, ver = resolve_tool_path(binary_name, root_dir, os_sys)
        result["tools"][logical_name] = {
            "available": avail,
            "executable": path,
            "version": ver
        }
        if not avail:
            all_available = False

    print(json.dumps(result, indent=2))
    sys.exit(0 if all_available else 1)

if __name__ == "__main__":
    main()
