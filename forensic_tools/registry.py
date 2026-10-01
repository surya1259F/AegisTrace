import sys
import os
import shutil
import subprocess
import time
import platform
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

import threading

# Disallowed dangerous binaries that must NEVER be registered or executed as tools
DISALLOWED_BINARIES = {
    "bash", "sh", "zsh", "dash", "csh", "tcsh", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "python", "python3",
    "python.exe", "eval", "exec", "system", "sudo", "su"
}

MAX_SAFE_TIMEOUT_SECONDS = 600
DEFAULT_TIMEOUT_SECONDS = 120

class ToolDefinition(BaseModel):
    name: str
    display_name: str
    platforms: List[str]
    binary_name: str
    path: Optional[str] = None
    version: Optional[str] = None
    is_available: bool = False
    is_library_adapter: bool = False
    supported_evidence_types: List[str] = []
    capabilities: List[str] = []
    description: str

    def supports_evidence_type(self, evidence_type: str) -> bool:
        if not evidence_type:
            return False
        return evidence_type.lower().strip() in [t.lower().strip() for t in self.supported_evidence_types]

    def has_capability(self, capability: str) -> bool:
        if not capability:
            return False
        return capability.lower().strip() in [c.lower().strip() for c in self.capabilities]

def get_process_start_time(pid: int) -> Optional[float]:
    if not pid or pid <= 0:
        return None

    # Method 1: Direct Linux /proc/<pid>/stat field 22 (starttime ticks) - raw integer identity
    if sys.platform.startswith("linux"):
        try:
            stat_path = Path(f"/proc/{pid}/stat")
            if stat_path.exists():
                content = stat_path.read_text(encoding="utf-8", errors="replace")
                r_idx = content.rfind(")")
                if r_idx != -1:
                    after_comm = content[r_idx + 1:].strip().split()
                    # after_comm[0] is state (field 3 of entire stat)
                    # after_comm[19] is starttime (field 22 of entire stat)
                    if len(after_comm) >= 20:
                        return float(int(after_comm[19]))
        except Exception:
            pass

    # Method 2: Try psutil create_time (authoritative process creation timestamp)
    try:
        import psutil
        p = psutil.Process(pid)
        return float(p.create_time())
    except Exception:
        pass

    return None

class ToolExecutionRequest(BaseModel):
    tool_name: str
    evidence_path: str
    arguments: List[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=1, le=MAX_SAFE_TIMEOUT_SECONDS)
    execution_id: Optional[str] = None

class ToolExecutionResult(BaseModel):
    tool_name: str
    success: bool
    return_code: int
    stdout: str
    stderr: str
    execution_time_ms: float
    evidence_path: str
    pid: Optional[int] = None
    process_start_time: Optional[float] = None
    timed_out: bool = False
    process_terminated: bool = True
    cancelled: bool = False
    tool_version: Optional[str] = None
    error_message: Optional[str] = None

class PlatformAwareToolRegistry:
    """
    Platform-aware Forensic Tool Registry.
    Acts as the single approved gateway for executing deterministic forensic tool binaries.
    Enforces strict argument validation, timeout limits, platform awareness, and shell=False.
    """

    def __init__(self):
        self.current_os = "windows" if sys.platform.startswith("win") else "linux" if sys.platform.startswith("linux") else "darwin"
        self.root_dir = Path(__file__).resolve().parent.parent
        self._tools: Dict[str, ToolDefinition] = {}
        self._active_processes: Dict[str, Dict[str, Any]] = {}
        self._process_lock = threading.Lock()
        self._discover_and_register_tools()

    def register_active_process(self, execution_id: str, proc: subprocess.Popen, pid: int, start_time: Optional[float] = None):
        if not execution_id:
            return
        with self._process_lock:
            self._active_processes[execution_id] = {
                "process": proc,
                "pid": pid,
                "start_time": start_time or get_process_start_time(pid) or time.time()
            }

    def unregister_active_process(self, execution_id: str):
        if not execution_id:
            return
        with self._process_lock:
            self._active_processes.pop(execution_id, None)

    def cancel_execution_process(self, execution_id: str) -> bool:
        if not execution_id:
            return False
        info = None
        with self._process_lock:
            info = self._active_processes.get(execution_id)

        if not info:
            return False

        proc = info.get("process")
        registered_pid = info.get("pid")
        registered_start_time = info.get("start_time")

        if not proc or proc.pid != registered_pid:
            return False

        # Verify process start-time identity before terminating
        current_start_time = get_process_start_time(registered_pid)
        if current_start_time is None or registered_start_time is None:
            # Process identity UNKNOWN: do NOT terminate
            return False

        current_start_time = get_process_start_time(registered_pid)
        if (
            current_start_time is None
            or registered_start_time is None
            or current_start_time != registered_start_time
        ):
            # Process identity UNKNOWN or MISMATCHED: do NOT terminate
            return False

        try:
            if proc.poll() is None:
                # Immediate re-check right before terminate
                check_t = get_process_start_time(proc.pid)
                if check_t is None or check_t != registered_start_time:
                    return False

                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    # Re-verify before SIGKILL
                    check_kill_t = get_process_start_time(proc.pid)
                    if check_kill_t is not None and check_kill_t == registered_start_time:
                        proc.kill()
                        proc.wait(timeout=1.0)
            return proc.poll() is not None
        except Exception:
            return False

    def _resolve_binary_path(self, bin_name: str) -> Optional[str]:
        # 1. System PATH
        path = shutil.which(bin_name)
        if path:
            return path

        # 2. Project local tools/bin
        local_bin = self.root_dir / "tools" / "bin" / bin_name
        if local_bin.exists() and os.access(local_bin, os.X_OK):
            return str(local_bin)
        from backend.app.core.config import settings

        # 3. Dedicated Volatility virtualenv
        # 2. Configured ADFIR_DATA_DIR tools/bin
        data_bin = settings.DATA_DIR / "tools" / "bin" / bin_name
        if data_bin.exists() and os.access(data_bin, os.X_OK):
            return str(data_bin)

        # 3. Project / Executable base tools/bin
        base_bin = settings.BASE_DIR / "tools" / "bin" / bin_name
        if base_bin.exists() and os.access(base_bin, os.X_OK):
            return str(base_bin)

        # 4. Dedicated Volatility virtualenv
        if bin_name in ["vol", "vol.exe"]:
            vol_env = settings.BASE_DIR / "volatility-env" / ("Scripts/vol.exe" if self.current_os == "windows" else "bin/vol")
            if vol_env.exists() and os.access(vol_env, os.X_OK):
                return str(vol_env)

        return None


    def _discover_and_register_tools(self):
        # 1. SleuthKit (fls)
        fls_bin = "fls.exe" if self.current_os == "windows" else "fls"
        fls_path = self._resolve_binary_path(fls_bin)
        fls_ver = None
        if fls_path:
            try:
                out = subprocess.run([fls_path, "-V"], capture_output=True, text=True, timeout=5, shell=False)
                fls_ver = (out.stdout or out.stderr).strip().splitlines()[0]
            except Exception:
                fls_ver = "detected"

        self._tools["sleuthkit"] = ToolDefinition(
            name="sleuthkit",
            display_name="The Sleuth Kit (TSK)",
            platforms=["linux", "windows", "darwin"],
            binary_name=fls_bin,
            path=fls_path,
            version=fls_ver,
            is_available=fls_path is not None,
            supported_evidence_types=["disk_image", "filesystem_image"],
            capabilities=["filesystem_structure_extraction", "filesystem_analysis"],
            description="Volume and filesystem analysis tools for disk images and filesystems."
        )

        # 2. YARA
        yara_bin = "yara.exe" if self.current_os == "windows" else "yara"
        yara_path = self._resolve_binary_path(yara_bin)
        yara_ver = None
        if yara_path:
            try:
                out = subprocess.run([yara_path, "--version"], capture_output=True, text=True, timeout=5, shell=False)
                yara_ver = out.stdout.strip()
            except Exception:
                yara_ver = "detected"

        self._tools["yara"] = ToolDefinition(
            name="yara",
            display_name="YARA Pattern Matcher",
            platforms=["linux", "windows", "darwin"],
            binary_name=yara_bin,
            path=yara_path,
            version=yara_ver,
            is_available=yara_path is not None,
            supported_evidence_types=["executable", "suspicious_file", "malware", "file"],
            capabilities=["signature_scan"],
            description="Pattern matching tool for malware researchers and binary analysis."
        )

        # 3. ExifTool
        exif_bin = "exiftool.exe" if self.current_os == "windows" else "exiftool"
        exif_path = self._resolve_binary_path(exif_bin)
        exif_ver = None
        if exif_path:
            try:
                out = subprocess.run([exif_path, "-ver"], capture_output=True, text=True, timeout=5, shell=False)
                exif_ver = out.stdout.strip()
            except Exception:
                exif_ver = "detected"

        self._tools["exiftool"] = ToolDefinition(
            name="exiftool",
            display_name="ExifTool Metadata Extractor",
            platforms=["linux", "windows", "darwin"],
            binary_name=exif_bin,
            path=exif_path,
            version=exif_ver,
            is_available=exif_path is not None,
            supported_evidence_types=["file", "document", "archive"],
            capabilities=["metadata_extraction"],
            description="Read and parse metadata in digital images, documents, and files."
        )

        # 4. Volatility 3
        vol_bin = "vol.exe" if self.current_os == "windows" else "vol"
        vol_path = self._resolve_binary_path(vol_bin)
        vol_ver = None
        if vol_path:
            try:
                out = subprocess.run([vol_path, "--version"], capture_output=True, text=True, timeout=10, shell=False)
                vol_ver = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else "detected"
            except Exception:
                vol_ver = "detected"

        self._tools["volatility3"] = ToolDefinition(
            name="volatility3",
            display_name="Volatility 3 Memory Forensics",
            platforms=["linux", "windows", "darwin"],
            binary_name=vol_bin,
            path=vol_path,
            version=vol_ver,
            is_available=vol_path is not None,
            supported_evidence_types=["memory_dump", "raw_memory", "vmem", "dmp"],
            capabilities=["process_enumeration", "network_socket_extraction"],
            description="Advanced memory forensics framework for Windows, Linux, and Mac kernel dumps."
        )

        # 5. python-evtx
        evtx_available = False
        try:
            import Evtx  # noqa: F401
            evtx_available = True
        except ImportError:
            pass

        # 5. python-evtx (In-Process Python Library Adapter)
        evtx_available = False
        try:
            import Evtx  # noqa: F401
            evtx_available = True
        except ImportError:
            pass

        evtx_tool = ToolDefinition(
            name="python-evtx",
            display_name="python-evtx Log Parser",
            platforms=["linux", "windows", "darwin"],
            binary_name="python-evtx",
            path=None,
            version="0.7.4" if evtx_available else None,
            is_available=evtx_available,
            is_library_adapter=True,
            supported_evidence_types=["log", "event_log", "evtx", "system_log"],
            capabilities=["security_log_parsing"],
            description="Pure Python library parser for Windows Event Log files (.evtx)."
        )
        self._tools["python-evtx"] = evtx_tool
        self._tools["python_evtx"] = evtx_tool

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        if not name or not isinstance(name, str):
            return None
        return self._tools.get(name.lower().strip())

    def list_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def validate_request(self, request: ToolExecutionRequest) -> Optional[str]:
        """
        Validates that a tool request is safe before execution.
        Returns error string if invalid, None if safe.
        """
        tool_name_clean = request.tool_name.lower().strip() if request.tool_name else ""
        if not tool_name_clean or tool_name_clean not in self._tools:
            return f"Unknown or disallowed tool '{request.tool_name}'. Tool must be registered in ToolRegistry."

        # Null byte check in evidence path
        if "\0" in request.evidence_path:
            return "Null byte detected in evidence path."

        # Null byte check in arguments
        for arg in request.arguments:
            if not isinstance(arg, str):
                return "All arguments must be strings."
            if "\0" in arg:
                return "Null byte detected in tool arguments."

        return None

    def execute_tool(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        # 1. Validate request
        val_error = self.validate_request(request)
        if val_error:
            return ToolExecutionResult(
                tool_name=request.tool_name,
                success=False,
                return_code=-1,
                stdout="",
                stderr=val_error,
                execution_time_ms=0,
                evidence_path=request.evidence_path,
                error_message=val_error
            )

        tool = self.get_tool(request.tool_name)
        if not tool or not tool.is_available:
            return ToolExecutionResult(
                tool_name=request.tool_name,
                success=False,
                return_code=-1,
                stdout="",
                stderr="",
                execution_time_ms=0,
                evidence_path=request.evidence_path,
                error_message=f"Tool '{request.tool_name}' is not installed or available on this system."
            )

        if tool.is_library_adapter:
            return ToolExecutionResult(
                tool_name=request.tool_name,
                success=False,
                return_code=-1,
                stdout="",
                stderr="",
                execution_time_ms=0,
                evidence_path=request.evidence_path,
                error_message=f"Tool '{request.tool_name}' is an in-process library adapter — execute via forensic pipeline adapter, not as a standalone CLI subprocess."
            )

        if not tool.path:
            return ToolExecutionResult(
                tool_name=request.tool_name,
                success=False,
                return_code=-1,
                stdout="",
                stderr="",
                execution_time_ms=0,
                evidence_path=request.evidence_path,
                error_message=f"Tool '{request.tool_name}' binary executable path is not resolved."
            )

        # Enforce safe timeout cap
        timeout = min(max(1, request.timeout_seconds), MAX_SAFE_TIMEOUT_SECONDS)

        # Construct argument list: executable is strictly tool.path from registry
        if tool.name == "volatility3":
            # Volatility 3 syntax: vol -f <evidence_path> <plugin> <plugin_args...>
            cmd = [tool.path, "-f", request.evidence_path] + request.arguments
        else:
            cmd = [tool.path] + request.arguments + [request.evidence_path]

        start_time = time.time()
        proc = None
        try:
            # Subprocess safety: shell=False strictly enforced
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )
            pid = proc.pid
            proc_start_time = get_process_start_time(pid) or time.time()

            if request.execution_id:
                self.register_active_process(request.execution_id, proc, pid, proc_start_time)

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                return_code = proc.returncode
                elapsed_ms = (time.time() - start_time) * 1000

                # Check if process was cancelled externally
                is_cancelled = False
                if return_code != 0 and return_code is not None:
                    if abs(return_code) in (9, 15):  # SIGKILL / SIGTERM
                        is_cancelled = True

                return ToolExecutionResult(
                    tool_name=request.tool_name,
                    success=(return_code == 0),
                    return_code=return_code,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    execution_time_ms=elapsed_ms,
                    evidence_path=request.evidence_path,
                    pid=pid,
                    process_start_time=proc_start_time,
                    timed_out=False,
                    cancelled=is_cancelled,
                    tool_version=tool.version,
                    error_message=None if return_code == 0 else (
                        "Tool execution was cancelled by investigator." if is_cancelled else f"Process returned non-zero code {return_code}"
                    )
                )
            except subprocess.TimeoutExpired:
                # Safe multi-stage termination with exact identity verification
                current_start_time = get_process_start_time(pid)
                identity_verified = (
                    current_start_time is not None
                    and proc_start_time is not None
                    and current_start_time == proc_start_time
                    and proc.poll() is None
                )

                stdout, stderr = "", ""
                process_terminated = False
                if identity_verified:
                    proc.terminate()
                    try:
                        stdout, stderr = proc.communicate(timeout=1.5)
                    except subprocess.TimeoutExpired:
                        check_t = get_process_start_time(pid)
                        if check_t is not None and check_t == proc_start_time:
                            proc.kill()
                            stdout, stderr = proc.communicate()
                    process_terminated = (proc.poll() is not None)
                else:
                    stderr = f"Tool execution timed out after {timeout} seconds. Process identity could not be verified for termination; process remains active."
                    process_terminated = False

                elapsed_ms = (time.time() - start_time) * 1000
                return ToolExecutionResult(
                    tool_name=request.tool_name,
                    success=False,
                    return_code=-2,
                    stdout=stdout or "",
                    stderr=stderr or f"Tool execution timed out after {timeout} seconds.",
                    execution_time_ms=elapsed_ms,
                    evidence_path=request.evidence_path,
                    pid=pid,
                    process_start_time=proc_start_time,
                    timed_out=True,
                    process_terminated=process_terminated,
                    cancelled=False,
                    tool_version=tool.version,
                    error_message=f"Execution exceeded timeout of {timeout} seconds."
                )
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            pid_val = proc.pid if proc else None
            return ToolExecutionResult(
                tool_name=request.tool_name,
                success=False,
                return_code=-3,
                stdout="",
                stderr=str(e),
                execution_time_ms=elapsed_ms,
                evidence_path=request.evidence_path,
                pid=pid_val,
                timed_out=False,
                cancelled=False,
                error_message=str(e)
            )
        finally:
            if request.execution_id:
                self.unregister_active_process(request.execution_id)

tool_registry = PlatformAwareToolRegistry()
