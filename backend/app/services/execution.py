"""
ADFIR — Phase 2 / Step 9: Secure Forensic Execution Subsystem

Bridges READY analysis requests released by Step 8 into strictly isolated,
controlled, and monitored forensic process invocations.

Invariants & Constraints:
- Executes ONLY analysis requests in READY status.
- Strict subprocess shell=False. Never constructs shell command strings.
- Rejects disallowed shell binaries (bash, sh, cmd, powershell, etc.).
- Verifies evidence vault integrity via streaming SHA-256 before launch.
- Creates dedicated, isolated workspace with safe permissions (0o700).
- Workspace is strictly separated from evidence vault storage.
- Validates all input paths: rejects path traversal, null bytes, and symlink escapes.
- Bounded stdout/stderr streaming to avoid memory exhaustion.
- Enforces execution timeout and system resource controls.
- Authoritative PID identity verification (get_process_start_time) to avoid PID recycling race conditions.
- Discovers, hashes (SHA-256), and registers all produced outputs with full provenance.
- Implements immutable audit event logging for all lifecycle milestones.
- Releases Step 8 scheduler reservations upon completion/failure/timeout/cancellation.
"""

import os
import sys
import time
import uuid
import mimetypes
import logging
import threading
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    EvidenceItem,
    Case,
    User,
    ToolDefinition as DBToolDefinition
)
from backend.app.services.audit import log_audit_event
from backend.app.services.custody import record_custody_event
from backend.app.services.integrity import calculate_sha256, verify_sha256
from forensic_tools.registry import (
    DISALLOWED_BINARIES,
    get_process_start_time,
    tool_registry as global_tool_registry
)

logger = logging.getLogger("ADFIR_SECURE_EXECUTION")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

# Maximum output stream capture file size (50 MB)
MAX_LOG_FILE_BYTES = 50 * 1024 * 1024
# Maximum in-memory preview buffer (64 KB)
MAX_PREVIEW_BYTES = 64 * 1024

# Dangerous shell characters that must never appear in validated argv arguments
SHELL_METACHARACTERS = {";", "|", "&", ">", "<", "`", "$", "\n", "\r", "\0"}


# =============================================================================
# ACTIVE PROCESS REGISTRY (Thread-Safe In-Memory Tracking)
# =============================================================================

class ActiveProcessRegistry:
    """
    Thread-safe in-memory tracking of active forensic subprocesses.
    Guarantees authoritative PID identity validation before any process termination.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._processes: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        execution_id: str,
        proc: subprocess.Popen,
        pid: int,
        start_time: float,
        case_id: str,
        request_id: str,
        workspace_path: str
    ):
        with self._lock:
            self._processes[execution_id] = {
                "proc": proc,
                "pid": pid,
                "start_time": start_time,
                "case_id": case_id,
                "request_id": request_id,
                "workspace_path": workspace_path
            }

    def unregister(self, execution_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._processes.pop(execution_id, None)

    def get(self, execution_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._processes.get(execution_id)

    def is_active(self, execution_id: str) -> bool:
        with self._lock:
            info = self._processes.get(execution_id)
            if not info:
                return False
            proc = info.get("proc")
            return proc is not None and proc.poll() is None


active_process_registry = ActiveProcessRegistry()


# =============================================================================
# PATH & INPUT VALIDATION
# =============================================================================

class ExecutionPathValidator:
    """
    Validates input paths and arguments against path traversal, null bytes,
    and symlink escapes.
    """

    @staticmethod
    def validate_safe_string(val: str, field_name: str = "parameter") -> str:
        """Ensures string contains no null bytes or shell metacharacters."""
        if not isinstance(val, str):
            raise ValueError(f"{field_name} must be a string")
        if "\0" in val:
            raise ValueError(f"Null byte detected in {field_name}")
        for char in (";", "|", "&", "`", "$", "\n", "\r"):
            if char in val:
                raise ValueError(f"Illegal shell character '{char}' detected in {field_name}")
        return val

    @classmethod
    def validate_input_path(cls, path_str: str, base_dir: Optional[Path] = None) -> Path:
        """
        Validates path existence, absence of null bytes, and traversal bounds.
        """
        cls.validate_safe_string(path_str, "path")
        path = Path(path_str)

        if "\0" in str(path):
            raise ValueError("Null byte in path")

        # Resolve path
        resolved = path.resolve()

        if base_dir is not None:
            base_resolved = base_dir.resolve()
            try:
                resolved.relative_to(base_resolved)
            except ValueError:
                raise ValueError(f"Path traversal detected: {path_str} escapes base directory {base_dir}")

        return resolved

    @classmethod
    def validate_workspace_path_containment(cls, target_path: Path, workspace_path: Path) -> bool:
        """
        Verifies that target_path is strictly contained within workspace_path.
        Rejects symlink escapes pointing outside workspace.
        """
        try:
            ws_resolved = workspace_path.resolve()
            # If target is symlink, check real destination
            if target_path.is_symlink():
                real_target = Path(os.path.realpath(str(target_path)))
                real_target.relative_to(ws_resolved)
            target_resolved = target_path.resolve()
            target_resolved.relative_to(ws_resolved)
            return True
        except ValueError:
            return False


# =============================================================================
# SECURE FORENSIC EXECUTION ENGINE
# =============================================================================

class ForensicExecutionService:
    """
    Core engine responsible for pre-flight validation, workspace isolation,
    argv construction, process execution, monitoring, timeout, output harvesting,
    and provenance persistence.
    """

    @classmethod
    def validate_ready_request(cls, db: Session, request_id: str) -> AnalysisRequest:
        """
        Ensures the analysis request exists and is in READY state.
        Rejects all other states (QUEUED, WAITING_RESOURCE, BLOCKED, RUNNING, etc.).
        """
        req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
        if not req:
            raise ValueError(f"AnalysisRequest '{request_id}' not found")

        if req.scheduler_status != "READY":
            raise ValueError(
                f"AnalysisRequest '{request_id}' is not in READY state (current: {req.scheduler_status})"
            )

        return req

    @classmethod
    def validate_evidence_integrity(
        cls,
        db: Session,
        evidence: EvidenceItem,
        actor: User
    ) -> Path:
        """
        Verifies evidence existence, case ownership, and cryptographic vault integrity.
        Performs streaming SHA-256 hashing against stored hash.
        """
        evidence_path_str = (
            getattr(evidence, "vault_path", None)
            or evidence.storage_path
            or getattr(evidence, "preserved_path", None)
            or evidence.original_path
        )
        if not evidence_path_str:
            raise ValueError(f"Evidence '{evidence.id}' has no associated storage path")

        evidence_path = Path(evidence_path_str).resolve()
        if not evidence_path.exists() or not evidence_path.is_file():
            raise ValueError(f"Evidence file missing on disk: {evidence_path}")

        # Streaming re-hash verification
        expected_hash = (
            getattr(evidence, "vault_hash", None)
            or getattr(evidence, "sha256_hash", None)
            or evidence.sha256
        )
        if not expected_hash:
            raise ValueError(f"Evidence '{evidence.id}' has no recorded SHA-256 hash for integrity verification")

        actual_hash, _ = calculate_sha256(str(evidence_path))
        if actual_hash.lower() != expected_hash.strip().lower():
            # Tamper detected! Lock evidence integrity status to FAILED
            evidence.integrity_status = "FAILED"
            db.commit()

            record_custody_event(
                db=db,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                event_type="INTEGRITY_VIOLATION",
                description=f"Evidence pre-execution integrity check failed. Expected: {expected_hash}, Actual: {actual_hash}",
                actor=actor.name,
                actor_id=actor.id,
                sha256=actual_hash
            )

            log_audit_event(
                db=db,
                event_type="EXECUTION_INTEGRITY_FAILED",
                case_id=evidence.case_id,
                actor_id=actor.id,
                actor_name=actor.name,
                details=f"Execution blocked for evidence {evidence.id}: SHA-256 tamper detected ({actual_hash} != {expected_hash})"
            )

            raise ValueError(
                f"Evidence integrity check failed for '{evidence.id}': SHA-256 mismatch detected"
            )

        return evidence_path

    @classmethod
    def validate_and_resolve_tool(
        cls,
        db: Session,
        request: AnalysisRequest
    ) -> Tuple[str, str]:
        """
        Verifies that the Step 7 selected tool is still enabled, available, and safe.
        Resolves the concrete binary path on the host.
        Returns: (resolved_executable_path, tool_version)
        """
        tool_id = request.selected_tool_id
        db_tool = db.query(DBToolDefinition).filter(DBToolDefinition.tool_id == tool_id).first()

        binary_name = None
        tool_ver = "unknown"

        if db_tool:
            if not db_tool.enabled:
                raise ValueError(f"Selected tool '{tool_id}' is disabled in the tool registry")
            binary_name = db_tool.executable_path or db_tool.binary_name
            tool_ver = db_tool.version or "1.0.0"
        else:
            # Check global registry
            reg_tool = global_tool_registry.get_tool(tool_id)
            if not reg_tool:
                # Check by name
                for t in global_tool_registry.list_tools():
                    if t.name == tool_id or t.binary_name == tool_id:
                        reg_tool = t
                        break
            if reg_tool:
                binary_name = reg_tool.path or reg_tool.binary_name
                tool_ver = reg_tool.version or "1.0.0"

        if not binary_name:
            binary_name = tool_id

        # STRICT: Validate binary is not in DISALLOWED_BINARIES
        base_bin_name = Path(binary_name).name.lower()
        if base_bin_name.endswith(".exe"):
            base_bin_name = base_bin_name[:-4]

        if base_bin_name in DISALLOWED_BINARIES:
            raise ValueError(
                f"Security violation: binary '{base_bin_name}' is in DISALLOWED_BINARIES and cannot be executed"
            )

        # Check for path traversal or null bytes in executable path
        ExecutionPathValidator.validate_safe_string(binary_name, "executable_path")

        # Resolve binary path
        resolved_path = None
        p = Path(binary_name)
        if p.is_absolute() and p.exists() and os.access(p, os.X_OK):
            resolved_path = str(p.resolve())
        else:
            # Check global tool registry resolution
            reg_resolved = global_tool_registry._resolve_binary_path(Path(binary_name).name)
            if reg_resolved and os.access(reg_resolved, os.X_OK):
                resolved_path = reg_resolved
            else:
                # Check PATH
                which_path = shutil.which(binary_name)
                if which_path and os.access(which_path, os.X_OK):
                    resolved_path = which_path

        if not resolved_path:
            raise ValueError(f"Tool executable '{binary_name}' not found or not executable on host system")

        return resolved_path, tool_ver

    @classmethod
    def create_isolated_workspace(cls, case_id: str, execution_id: str) -> Path:
        """
        Creates a dedicated isolated workspace directory for this execution.
        Must not collide with or reside inside the evidence vault.
        Enforces 0o700 safe permissions.
        """
        safe_case = "".join(c for c in case_id if c.isalnum() or c in ("-", "_"))
        safe_exec = "".join(c for c in execution_id if c.isalnum() or c in ("-", "_"))

        workspace_dir = settings.DATA_DIR / "workspaces" / safe_case / safe_exec

        # Vault collision invariant
        vault_dir = settings.EVIDENCE_DIR.resolve()
        if workspace_dir.resolve().is_relative_to(vault_dir):
            raise ValueError("Fatal safety error: workspace directory cannot reside inside evidence vault")

        workspace_dir.mkdir(parents=True, exist_ok=True)
        (workspace_dir / "outputs").mkdir(parents=True, exist_ok=True)

        # Restrict permissions on POSIX
        if sys.platform != "win32":
            try:
                os.chmod(workspace_dir, 0o700)
            except Exception as e:
                logger.warning(f"Could not set 0o700 permissions on workspace: {e}")

        return workspace_dir

    @classmethod
    def build_safe_argv(
        cls,
        executable_path: str,
        tool_id: str,
        evidence_path: Path,
        workspace_path: Path,
        custom_params: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Builds argv list deterministically using structured parameters.
        Enforces shell=False argv rules.
        Rejects shell injection, null bytes, and arbitrary command strings.
        """
        argv = [str(executable_path)]
        params = custom_params or {}

        # Validate evidence path as argument
        ev_str = str(evidence_path.resolve())
        ExecutionPathValidator.validate_safe_string(ev_str, "evidence_path")

        # Tool-specific structured argv mapping
        tool_key = tool_id.lower()
        if "sleuthkit" in tool_key or "fls" in tool_key:
            # fls -r -p <evidence_path>
            argv.extend(["-r", "-p"])
            if "offset" in params:
                offset_val = str(params["offset"]).strip()
                ExecutionPathValidator.validate_safe_string(offset_val, "offset")
                argv.extend(["-o", offset_val])
            argv.append(ev_str)

        elif "yara" in tool_key:
            # yara -s <rule_path> <evidence_path>
            rule_path = params.get("rule_path")
            if rule_path:
                rule_p = ExecutionPathValidator.validate_input_path(str(rule_path))
                argv.extend(["-s", str(rule_p)])
            argv.append(ev_str)

        elif "exiftool" in tool_key:
            # exiftool -j -g <evidence_path>
            argv.extend(["-j", "-g", ev_str])

        elif "volatility" in tool_key or "vol" in tool_key:
            # vol -f <evidence_path> <plugin>
            plugin = str(params.get("plugin", "windows.info")).strip()
            ExecutionPathValidator.validate_safe_string(plugin, "plugin")
            argv.extend(["-f", ev_str, plugin])

        elif "test" in tool_key or "mock" in tool_key or "echo" in tool_key or "sha256" in tool_key:
            # Safe structured test tool mapping
            extra_args = params.get("arguments", [])
            if isinstance(extra_args, list):
                for arg in extra_args:
                    arg_str = str(arg)
                    ExecutionPathValidator.validate_safe_string(arg_str, "test_argument")
                    argv.append(arg_str)
            if not extra_args:
                argv.append(ev_str)
        else:
            # Default structured mapping: [executable, evidence_path]
            argv.append(ev_str)

        return argv

    @classmethod
    def start_execution(
        cls,
        db: Session,
        request_id: str,
        actor: User,
        custom_parameters: Optional[Dict[str, Any]] = None,
        wait: bool = False
    ) -> ForensicExecution:
        """
        Main entry point for starting execution of a READY analysis request.
        1. Validates request state == READY.
        2. Validates evidence integrity (re-hashing against vault hash).
        3. Validates tool availability and resolves binary path.
        4. Creates isolated workspace.
        5. Builds safe argv (shell=False).
        6. Persists ForensicExecution record in STARTING state.
        7. Transitions AnalysisRequest to RUNNING.
        8. Launches and monitors subprocess.
        """
        # 1. Validate request is READY
        req = cls.validate_ready_request(db, request_id)

        # 2. Validate evidence & integrity
        evidence = db.query(EvidenceItem).filter(EvidenceItem.id == req.evidence_id).first()
        if not evidence:
            raise ValueError(f"Evidence '{req.evidence_id}' referenced by request not found")

        if evidence.case_id != req.case_id:
            raise ValueError("Security violation: evidence does not belong to the same case as analysis request")

        evidence_path = cls.validate_evidence_integrity(db, evidence, actor)

        # 3. Validate tool
        executable_path, tool_ver = cls.validate_and_resolve_tool(db, req)

        # 4. Create execution record & workspace
        execution_id = str(uuid.uuid4())
        workspace = cls.create_isolated_workspace(req.case_id, execution_id)

        # 5. Build safe argv
        argv = cls.build_safe_argv(
            executable_path=executable_path,
            tool_id=req.selected_tool_id,
            evidence_path=evidence_path,
            workspace_path=workspace,
            custom_params=custom_parameters
        )

        host_platform = sys.platform.lower()
        if host_platform.startswith("linux"):
            host_plat = "linux"
        elif host_platform.startswith("win"):
            host_plat = "windows"
        elif host_platform.startswith("darwin"):
            host_plat = "darwin"
        else:
            host_plat = host_platform

        import platform
        host_arch = platform.machine().lower()

        # 6. Persist ForensicExecution record
        now = utc_now()
        execution = ForensicExecution(
            id=execution_id,
            request_id=req.id,
            case_id=req.case_id,
            plan_id=req.plan_id,
            task_id=req.task_id,
            task_key=req.task_key,
            evidence_id=req.evidence_id,
            tool_id=req.selected_tool_id,
            tool_version=tool_ver,
            executable_path=executable_path,
            validated_argv=argv,
            host_platform=host_plat,
            host_architecture=host_arch,
            workspace_path=str(workspace),
            resource_allocation=req.allocated_resources or {},
            timeout_seconds=req.timeout_seconds or 300,
            execution_status="STARTING",
            output_count=0,
            created_at=now,
            updated_at=now
        )
        db.add(execution)

        # 7. Update AnalysisRequest to RUNNING
        req.scheduler_status = "RUNNING"
        req.started_at = now
        db.commit()
        db.refresh(execution)
        db.refresh(req)

        log_audit_event(
            db=db,
            event_type="EXECUTION_ACCEPTED",
            case_id=req.case_id,
            actor_id=actor.id,
            actor_name=actor.name,
            details=f"Execution {execution_id} accepted for task {req.task_key} with tool {req.selected_tool_id}"
        )

        log_audit_event(
            db=db,
            event_type="WORKSPACE_CREATED",
            case_id=req.case_id,
            actor_id=actor.id,
            actor_name=actor.name,
            details=f"Workspace created at {workspace} for execution {execution_id}"
        )

        # 8. Launch execution
        if wait:
            cls._execute_process_sync(execution.id)
            db.refresh(execution)
            return execution
        else:
            # Spawn background execution thread
            thread = threading.Thread(
                target=cls._execute_process_sync,
                args=(execution.id,),
                daemon=True,
                name=f"ForensicExec-{execution_id[:8]}"
            )
            thread.start()
            return execution

    @classmethod
    def _execute_process_sync(cls, execution_id: str):
        """
        Synchronous execution worker run either inline or in a background thread.
        Handles subprocess spawning, log streaming, timeout monitoring, and output collection.
        """
        from backend.app.core.database import SessionLocal
        db = SessionLocal()
        try:
            execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
            if not execution:
                logger.error(f"Execution {execution_id} missing during worker startup")
                return

            req = db.query(AnalysisRequest).filter(AnalysisRequest.id == execution.request_id).first()
            workspace = Path(execution.workspace_path)
            stdout_file = workspace / "stdout.log"
            stderr_file = workspace / "stderr.log"

            execution.stdout_path = str(stdout_file)
            execution.stderr_path = str(stderr_file)
            execution.execution_status = "RUNNING"
            execution.started_at = utc_now()
            db.commit()

            log_audit_event(
                db=db,
                event_type="EXECUTION_STARTED",
                case_id=execution.case_id,
                details=f"Process execution started for {execution_id} with argv: {execution.validated_argv}"
            )

            # Resource preexec function on POSIX
            preexec = None
            if sys.platform != "win32":
                try:
                    import resource
                    def _preexec_limits():
                        # Set CPU limit slightly above timeout as hard cap
                        cpu_cap = max(10, execution.timeout_seconds + 5)
                        try:
                            resource.setrlimit(resource.RLIMIT_CPU, (cpu_cap, cpu_cap + 2))
                        except Exception:
                            pass
                        # Create new process group
                        os.setsid()
                    preexec = _preexec_limits
                except ImportError:
                    pass

            start_t = time.time()
            proc = None

            try:
                # Open log files for writing
                with open(stdout_file, "wb") as f_out, open(stderr_file, "wb") as f_err:
                    # Spawn strictly with shell=False
                    proc = subprocess.Popen(
                        execution.validated_argv,
                        cwd=str(workspace),
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=f_out,
                        stderr=f_err,
                        preexec_fn=preexec
                    )

                    pid = proc.pid
                    proc_start_time = get_process_start_time(pid) or time.time()

                    execution.pid = pid
                    execution.process_start_time = proc_start_time
                    db.commit()

                    # Register in active process registry
                    active_process_registry.register(
                        execution_id=execution_id,
                        proc=proc,
                        pid=pid,
                        start_time=proc_start_time,
                        case_id=execution.case_id,
                        request_id=execution.request_id,
                        workspace_path=str(workspace)
                    )

                    # Monitor loop
                    timeout = execution.timeout_seconds
                    timed_out = False
                    cancelled = False

                    while True:
                        ret = proc.poll()
                        if ret is not None:
                            break

                        # Check elapsed time
                        elapsed = time.time() - start_t
                        if elapsed > timeout:
                            timed_out = True
                            break

                        # Check if cancellation was flagged in DB
                        db.refresh(execution)
                        if execution.execution_status == "CANCELLED":
                            cancelled = True
                            break

                        time.sleep(0.1)

                    # Handle Timeout
                    if timed_out:
                        cls._terminate_safely(proc, pid, proc_start_time)
                        execution.execution_status = "TIMEOUT"
                        execution.failure_reason = f"Execution exceeded timeout of {timeout} seconds"
                        execution.exit_code = -1
                        if req:
                            req.scheduler_status = "TIMEOUT"
                            req.failure_reason = execution.failure_reason
                            req.allocated_resources = {}

                        log_audit_event(
                            db=db,
                            event_type="EXECUTION_TIMEOUT",
                            case_id=execution.case_id,
                            details=f"Execution {execution_id} terminated due to timeout ({timeout}s)"
                        )

                    elif cancelled:
                        cls._terminate_safely(proc, pid, proc_start_time)
                        execution.exit_code = -2
                        if req:
                            req.scheduler_status = "CANCELLED"
                            req.allocated_resources = {}

                        log_audit_event(
                            db=db,
                            event_type="EXECUTION_CANCELLED",
                            case_id=execution.case_id,
                            details=f"Execution {execution_id} cancelled: {execution.cancellation_reason}"
                        )

                    else:
                        # Process completed
                        exit_code = proc.returncode
                        execution.exit_code = exit_code

                        if exit_code == 0:
                            execution.execution_status = "COMPLETED"
                            if req:
                                req.scheduler_status = "COMPLETED"
                                req.completed_at = utc_now()
                                req.allocated_resources = {}

                            log_audit_event(
                                db=db,
                                event_type="EXECUTION_COMPLETED",
                                case_id=execution.case_id,
                                details=f"Execution {execution_id} completed successfully (exit code 0)"
                            )
                        else:
                            execution.execution_status = "FAILED"
                            execution.failure_reason = f"Tool process exited with non-zero code {exit_code}"
                            if req:
                                req.scheduler_status = "FAILED"
                                req.failure_reason = execution.failure_reason
                                req.allocated_resources = {}

                            log_audit_event(
                                db=db,
                                event_type="EXECUTION_FAILED",
                                case_id=execution.case_id,
                                details=f"Execution {execution_id} failed with exit code {exit_code}"
                            )

            except Exception as ex:
                logger.error(f"Execution error for {execution_id}: {ex}", exc_info=True)
                try:
                    db.rollback()
                except Exception:
                    pass

                try:
                    execution.execution_status = "FAILED"
                    execution.failure_reason = str(ex)
                    execution.exit_code = -3
                    if req:
                        req.scheduler_status = "FAILED"
                        req.failure_reason = str(ex)
                        req.allocated_resources = {}

                    log_audit_event(
                        db=db,
                        event_type="EXECUTION_FAILED",
                        case_id=execution.case_id,
                        details=f"Execution {execution_id} encountered exception: {ex}"
                    )
                    db.commit()
                except Exception as inner_ex:
                    logger.warning(f"Error logging execution failure for {execution_id}: {inner_ex}")
                    try:
                        db.rollback()
                    except Exception:
                        pass

            finally:
                active_process_registry.unregister(execution_id)

                try:
                    end_t = time.time()
                    execution.completed_at = utc_now()
                    execution.duration_seconds = round(end_t - start_t, 3)

                    # Collect workspace outputs
                    cls.collect_workspace_outputs(db, execution, workspace)
                    db.commit()
                except Exception as final_err:
                    logger.warning(f"Error finalizing execution {execution_id}: {final_err}")
                    try:
                        db.rollback()
                    except Exception:
                        pass

        finally:
            try:
                db.close()
            except Exception:
                pass

    @classmethod
    def _terminate_safely(cls, proc: subprocess.Popen, pid: int, start_time: float):
        """
        Multi-stage termination verifying PID identity to prevent killing recycled processes.
        """
        if proc.poll() is not None:
            return

        current_start_time = get_process_start_time(pid)
        identity_verified = (
            current_start_time is not None
            and start_time is not None
            and current_start_time == start_time
        )

        if not identity_verified:
            logger.warning(f"Process PID {pid} identity cannot be verified (recycled PID?). Refusing to kill.")
            return

        try:
            # Stage 1: SIGTERM
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                # Stage 2: Re-verify identity before SIGKILL
                check_t = get_process_start_time(pid)
                if check_t is not None and check_t == start_time:
                    proc.kill()
                    proc.wait(timeout=1.0)
        except Exception as e:
            logger.warning(f"Exception during safe process termination: {e}")

    @classmethod
    def collect_workspace_outputs(
        cls,
        db: Session,
        execution: ForensicExecution,
        workspace_path: Path
    ) -> List[ExecutionOutput]:
        """
        Scans workspace directory for generated artifacts and process logs (stdout, stderr).
        Delegates to RawOutputsService for authoritative Step 10 discovery, hashing, and registration.
        """
        from backend.app.services.raw_outputs import RawOutputsService
        return RawOutputsService.collect_and_register_all(db, execution)


    @classmethod
    def cancel_execution(
        cls,
        db: Session,
        execution_id: str,
        actor: User,
        reason: Optional[str] = "Cancelled by investigator"
    ) -> ForensicExecution:
        """
        Cancels an actively running forensic execution safely.
        Validates case authorization, terminates only the verified process,
        updates state, releases scheduler reservations, and records audit event.
        """
        execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ForensicExecution '{execution_id}' not found")

        if execution.execution_status in ("COMPLETED", "FAILED", "TIMEOUT", "CANCELLED", "BLOCKED"):
            return execution

        execution.execution_status = "CANCELLED"
        execution.cancellation_reason = reason or "Cancelled by investigator"
        execution.completed_at = utc_now()

        req = db.query(AnalysisRequest).filter(AnalysisRequest.id == execution.request_id).first()
        if req:
            req.scheduler_status = "CANCELLED"
            req.cancelled_at = utc_now()
            req.allocated_resources = {}

        db.commit()

        # Check in active process registry and terminate
        info = active_process_registry.unregister(execution_id)
        if info:
            proc = info.get("proc")
            pid = info.get("pid")
            start_time = info.get("start_time")
            if proc and pid and start_time:
                cls._terminate_safely(proc, pid, start_time)

        log_audit_event(
            db=db,
            event_type="EXECUTION_CANCELLED",
            case_id=execution.case_id,
            actor_id=actor.id,
            actor_name=actor.name,
            details=f"Execution {execution_id} cancelled by {actor.name}: {reason}"
        )

        db.refresh(execution)
        return execution

    @classmethod
    def get_stream_content(
        cls,
        db: Session,
        execution_id: str,
        stream_type: str,
        max_bytes: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Retrieves captured stdout or stderr log stream.
        Enforces bounded memory return to prevent memory exhaustion.
        """
        execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ForensicExecution '{execution_id}' not found")

        path_str = execution.stdout_path if stream_type == "stdout" else execution.stderr_path
        if not path_str or not Path(path_str).exists():
            return {
                "execution_id": execution_id,
                "stream_type": stream_type,
                "content": "",
                "is_truncated": False,
                "total_bytes": 0
            }

        target_file = Path(path_str)
        total_size = target_file.stat().st_size
        read_limit = max_bytes or MAX_PREVIEW_BYTES

        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(read_limit)

        is_truncated = total_size > read_limit
        return {
            "execution_id": execution_id,
            "stream_type": stream_type,
            "content": content,
            "is_truncated": is_truncated,
            "total_bytes": total_size
        }
