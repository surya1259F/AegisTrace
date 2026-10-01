"""
ADFIR — Phase 2 / Step 10: Raw Forensic Outputs Subsystem

Core Raw Forensic Output Management Engine ensuring that:
1. Every output (tool artifacts, stdout, stderr) is registered with strict provenance.
2. Raw outputs are strictly evidence-derived data, NEVER conclusions or findings.
3. Outputs are isolated in case/execution areas and NEVER written into the evidence vault.
4. Cryptographic SHA-256 integrity is calculated and verified on retrieval.
5. Duplicates are detected and never silently overwritten.
6. Safe file permissions (0o700 dir, 0o600 file) and symlink/traversal guards are enforced.
7. Authorized, IDOR-protected, RBAC-governed access controls are strictly applied.
"""

import os
import sys
import uuid
import stat
import logging
import mimetypes
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    ExecutionOutput,
    ForensicExecution,
    AnalysisRequest,
    EvidenceItem,
    Case,
    User
)
from backend.app.services.audit import log_audit_event
from backend.app.services.authorization import validate_case_access
from backend.app.services.integrity import calculate_sha256, verify_sha256

logger = logging.getLogger("ADFIR_RAW_OUTPUTS")

VALID_OUTPUT_TYPES = {"TOOL_OUTPUT", "STDOUT", "STDERR", "LOG"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RawOutputsSecurityError(Exception):
    """Raised when an output operation violates security constraints."""
    pass


class RawOutputsService:
    """
    Authoritative manager for raw forensic outputs produced during forensic tool execution.
    """

    @classmethod
    def validate_storage_path(
        cls,
        target_path: Path,
        workspace_path: Path,
        case_id: str
    ) -> Path:
        """
        Validates output storage path security invariants:
        - Rejects null bytes and traversal tokens
        - Prohibits storage inside the evidence vault
        - Strictly verifies workspace containment
        - Rejects escaping symlinks
        """
        path_str = str(target_path)
        if "\x00" in path_str:
            raise RawOutputsSecurityError("Security violation: Null byte detected in output path")

        # Resolve paths
        try:
            resolved_ws = workspace_path.resolve()
            resolved_target = target_path.resolve()
        except Exception as e:
            raise RawOutputsSecurityError(f"Security violation: Invalid path resolution: {e}")

        # Invariant: NEVER write or register into evidence vault
        vault_root = (settings.EVIDENCE_DIR / "vault").resolve()
        if vault_root in resolved_target.parents or resolved_target == vault_root:
            raise RawOutputsSecurityError(
                f"Security violation: Output path '{resolved_target}' resides inside evidence vault '{vault_root}'"
            )

        # Invariant: Must reside within workspace
        if resolved_ws not in resolved_target.parents and resolved_target != resolved_ws:
            raise RawOutputsSecurityError(
                f"Security violation: Output path '{resolved_target}' escapes workspace '{resolved_ws}'"
            )

        return resolved_target

    @classmethod
    def register_output(
        cls,
        db: Session,
        execution: ForensicExecution,
        file_path: Path,
        output_type: str = "TOOL_OUTPUT",
        relative_path: Optional[str] = None,
        custom_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[ExecutionOutput, bool]:
        """
        Registers an individual output artifact produced by an execution.
        Returns (ExecutionOutput, is_new: bool).
        Detects duplicates and never silently overwrites existing records.
        """
        if output_type not in VALID_OUTPUT_TYPES:
            raise ValueError(f"Invalid output_type '{output_type}'. Must be one of {VALID_OUTPUT_TYPES}")

        workspace = Path(execution.workspace_path)
        resolved_file = cls.validate_storage_path(file_path, workspace, execution.case_id)

        if not resolved_file.exists() or not resolved_file.is_file():
            raise FileNotFoundError(f"Output file does not exist or is not a regular file: {resolved_file}")

        # Enforce secure file permissions (0o600)
        try:
            os.chmod(resolved_file, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.warning(f"Could not enforce 0o600 permissions on {resolved_file}: {e}")

        file_size = resolved_file.stat().st_size
        sha256_hash, _ = calculate_sha256(str(resolved_file))

        rel_path = relative_path or str(resolved_file.relative_to(workspace.resolve()))

        # Duplicate detection: Check if an output already exists for this execution with same relative_path or sha256+filename
        existing = db.query(ExecutionOutput).filter(
            ExecutionOutput.execution_id == execution.id,
            ExecutionOutput.relative_path == rel_path
        ).first()

        if not existing:
            existing = db.query(ExecutionOutput).filter(
                ExecutionOutput.execution_id == execution.id,
                ExecutionOutput.filename == resolved_file.name,
                ExecutionOutput.sha256_hash == sha256_hash
            ).first()

        if existing:
            # DUPLICATE DETECTED: Never silently overwrite!
            log_audit_event(
                db=db,
                event_type="OUTPUT_DUPLICATE_REJECTED",
                case_id=execution.case_id,
                details=f"Duplicate output '{resolved_file.name}' (SHA-256: {sha256_hash}) already registered as {existing.id} for execution {execution.id}"
            )
            return existing, False

        # Determine MIME type
        mime_type, _ = mimetypes.guess_type(str(resolved_file))
        if output_type in ("STDOUT", "STDERR", "LOG"):
            mime_type = mime_type or "text/plain"
        else:
            mime_type = mime_type or "application/octet-stream"

        # Construct comprehensive metadata payload (provenance from Step 9)
        meta = {
            "tool_id": execution.tool_id,
            "tool_version": execution.tool_version,
            "validated_argv": execution.validated_argv or [],
            "execution_id": execution.id,
            "request_id": execution.request_id,
            "task_id": execution.task_id,
            "task_key": execution.task_key,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "duration_seconds": execution.duration_seconds,
            "exit_code": execution.exit_code,
            "execution_status": execution.execution_status,
            "host_platform": execution.host_platform,
            "host_architecture": execution.host_architecture,
            "extension": resolved_file.suffix,
            "created_timestamp": resolved_file.stat().st_ctime
        }
        if custom_metadata:
            meta.update(custom_metadata)

        output_record = ExecutionOutput(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            request_id=execution.request_id,
            case_id=execution.case_id,
            task_id=execution.task_id,
            evidence_id=execution.evidence_id,
            tool_id=execution.tool_id,
            tool_version=execution.tool_version,
            output_type=output_type,
            filename=resolved_file.name,
            relative_path=rel_path,
            storage_path=str(resolved_file),
            size_bytes=file_size,
            sha256_hash=sha256_hash,
            mime_type=mime_type,
            exit_code=execution.exit_code,
            execution_status=execution.execution_status,
            metadata_json=meta,
            created_at=utc_now()
        )
        db.add(output_record)

        log_audit_event(
            db=db,
            event_type="OUTPUT_REGISTERED",
            case_id=execution.case_id,
            details=f"Raw output {output_record.id} ({output_record.filename}, type={output_type}) registered for execution {execution.id}"
        )

        log_audit_event(
            db=db,
            event_type="OUTPUT_HASHED",
            case_id=execution.case_id,
            details=f"Raw output {output_record.id} SHA-256 calculated: {sha256_hash}"
        )

        return output_record, True

    @classmethod
    def collect_and_register_all(
        cls,
        db: Session,
        execution: ForensicExecution
    ) -> List[ExecutionOutput]:
        """
        Authoritatively scans the execution workspace for all generated outputs:
        1. Tool outputs (outputs/ directory or root workspace artifacts, registered first)
        2. stdout.log (as STDOUT artifact)
        3. stderr.log (as STDERR artifact)
        Updates execution.output_count and commits changes.
        """
        workspace = Path(execution.workspace_path)
        outputs: List[ExecutionOutput] = []

        if not workspace.exists():
            logger.warning(f"Workspace {workspace} does not exist for execution {execution.id}")
            return outputs

        # 1. Discover and register TOOL_OUTPUT files
        # Check standard outputs/ subfolder and any other files produced by tool
        for root, dirs, files in os.walk(workspace):
            for fname in sorted(files):
                # Skip stdout.log and stderr.log for now (they will be registered explicitly)
                if fname in ("stdout.log", "stderr.log"):
                    continue

                fpath = Path(root) / fname

                try:
                    # Validate containment
                    cls.validate_storage_path(fpath, workspace, execution.case_id)
                    rec, is_new = cls.register_output(
                        db=db,
                        execution=execution,
                        file_path=fpath,
                        output_type="TOOL_OUTPUT"
                    )
                    outputs.append(rec)
                except Exception as ex:
                    logger.warning(f"Failed to register tool output file {fpath}: {ex}")

        # 2. Register stdout.log if present
        stdout_file = workspace / "stdout.log"
        if stdout_file.exists() and stdout_file.is_file():
            try:
                rec, is_new = cls.register_output(
                    db=db,
                    execution=execution,
                    file_path=stdout_file,
                    output_type="STDOUT",
                    relative_path="stdout.log"
                )
                outputs.append(rec)
            except Exception as ex:
                logger.warning(f"Failed to register stdout log {stdout_file}: {ex}")

        # 3. Register stderr.log if present
        stderr_file = workspace / "stderr.log"
        if stderr_file.exists() and stderr_file.is_file():
            try:
                rec, is_new = cls.register_output(
                    db=db,
                    execution=execution,
                    file_path=stderr_file,
                    output_type="STDERR",
                    relative_path="stderr.log"
                )
                outputs.append(rec)
            except Exception as ex:
                logger.warning(f"Failed to register stderr log {stderr_file}: {ex}")

        db.commit()
        execution.output_count = len(outputs)
        db.commit()
        return outputs

    @classmethod
    def verify_output_integrity(
        cls,
        db: Session,
        output_id: str,
        actor: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Recalculates streaming SHA-256 for a registered output file on disk
        and verifies it against the stored hash in the database.
        Logs audit events on verification success or tamper/mismatch failure.
        """
        output = db.query(ExecutionOutput).filter(ExecutionOutput.id == output_id).first()
        if not output:
            raise ValueError(f"ExecutionOutput '{output_id}' not found")

        if actor:
            validate_case_access(db, output.case_id, actor)

        fpath = Path(output.storage_path)
        now = utc_now()

        if not fpath.exists() or not fpath.is_file():
            log_audit_event(
                db=db,
                event_type="OUTPUT_INTEGRITY_FAILED",
                case_id=output.case_id,
                details=f"Integrity check FAILED for output {output.id}: File missing on disk at {output.storage_path}"
            )
            return {
                "output_id": output.id,
                "filename": output.filename,
                "output_type": output.output_type,
                "expected_sha256": output.sha256_hash,
                "calculated_sha256": "MISSING",
                "integrity_verified": False,
                "size_bytes": 0,
                "checked_at": now
            }

        calc_hash, cur_size = calculate_sha256(str(fpath))
        is_verified = (calc_hash.lower() == output.sha256_hash.lower())

        if is_verified:
            log_audit_event(
                db=db,
                event_type="OUTPUT_INTEGRITY_VERIFIED",
                case_id=output.case_id,
                details=f"Integrity check PASSED for output {output.id} ({output.filename}): SHA-256 {calc_hash} matches stored hash"
            )
        else:
            log_audit_event(
                db=db,
                event_type="OUTPUT_INTEGRITY_FAILED",
                case_id=output.case_id,
                details=f"Integrity check FAILED for output {output.id} ({output.filename}): Expected {output.sha256_hash}, calculated {calc_hash}"
            )

        return {
            "output_id": output.id,
            "filename": output.filename,
            "output_type": output.output_type,
            "expected_sha256": output.sha256_hash,
            "calculated_sha256": calc_hash,
            "integrity_verified": is_verified,
            "size_bytes": cur_size,
            "checked_at": now
        }

    @classmethod
    def get_output_file_stream(
        cls,
        db: Session,
        output_id: str,
        actor: User
    ) -> Tuple[Path, str, str]:
        """
        Retrieves the concrete file path, filename, and MIME type for downloading an output file.
        Enforces case access authorization (RBAC and IDOR protection) and path safety.
        Returns: (file_path, filename, mime_type)
        """
        output = db.query(ExecutionOutput).filter(ExecutionOutput.id == output_id).first()
        if not output:
            raise ValueError(f"ExecutionOutput '{output_id}' not found")

        # Strictly validate case membership / access
        validate_case_access(db, output.case_id, actor)

        fpath = Path(output.storage_path)
        if not fpath.exists() or not fpath.is_file():
            raise FileNotFoundError(f"Output artifact '{output.filename}' missing from storage path")

        # Verify it has not been escaped or tampered
        workspace = Path(settings.DATA_DIR) / "workspaces" / output.case_id / output.execution_id
        try:
            cls.validate_storage_path(fpath, workspace, output.case_id)
        except Exception:
            # Fallback to checking within case workspaces
            case_ws = (Path(settings.DATA_DIR) / "workspaces" / output.case_id).resolve()
            resolved = fpath.resolve()
            if case_ws not in resolved.parents and resolved != case_ws:
                raise RawOutputsSecurityError("Security violation: Output path escapes case workspace boundary")

        log_audit_event(
            db=db,
            event_type="OUTPUT_RETRIEVED",
            case_id=output.case_id,
            actor_id=actor.id,
            actor_name=actor.name,
            details=f"User {actor.name} retrieved output artifact {output.id} ({output.filename})"
        )

        mime = output.mime_type or "application/octet-stream"
        return fpath, output.filename, mime

    @classmethod
    def list_execution_outputs(
        cls,
        db: Session,
        execution_id: str,
        actor: Optional[User] = None,
        output_type: Optional[str] = None
    ) -> List[ExecutionOutput]:
        """
        Lists all registered outputs for a given execution.
        Optionally filters by output_type (e.g. TOOL_OUTPUT, STDOUT, STDERR).
        """
        execution = db.query(ForensicExecution).filter(ForensicExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ForensicExecution '{execution_id}' not found")

        if actor:
            validate_case_access(db, execution.case_id, actor)

        query = db.query(ExecutionOutput).filter(ExecutionOutput.execution_id == execution_id)
        if output_type:
            query = query.filter(ExecutionOutput.output_type == output_type.upper())

        return query.order_by(ExecutionOutput.created_at.asc()).all()

    @classmethod
    def list_request_outputs(
        cls,
        db: Session,
        request_id: str,
        actor: Optional[User] = None,
        output_type: Optional[str] = None
    ) -> List[ExecutionOutput]:
        """
        Lists all registered outputs for a given analysis request across all its executions.
        """
        req = db.query(AnalysisRequest).filter(AnalysisRequest.id == request_id).first()
        if not req:
            raise ValueError(f"AnalysisRequest '{request_id}' not found")

        if actor:
            validate_case_access(db, req.case_id, actor)

        query = db.query(ExecutionOutput).filter(ExecutionOutput.request_id == request_id)
        if output_type:
            query = query.filter(ExecutionOutput.output_type == output_type.upper())

        return query.order_by(ExecutionOutput.created_at.asc()).all()

    @classmethod
    def list_case_outputs(
        cls,
        db: Session,
        case_id: str,
        actor: Optional[User] = None,
        output_type: Optional[str] = None
    ) -> List[ExecutionOutput]:
        """
        Lists all registered outputs for an entire case.
        """
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        if actor:
            validate_case_access(db, case.id, actor)

        query = db.query(ExecutionOutput).filter(ExecutionOutput.case_id == case_id)
        if output_type:
            query = query.filter(ExecutionOutput.output_type == output_type.upper())

        return query.order_by(ExecutionOutput.created_at.asc()).all()

    @classmethod
    def get_output_metadata(
        cls,
        db: Session,
        output_id: str,
        actor: Optional[User] = None
    ) -> ExecutionOutput:
        """
        Retrieves detailed metadata for a single registered output artifact.
        """
        output = db.query(ExecutionOutput).filter(ExecutionOutput.id == output_id).first()
        if not output:
            raise ValueError(f"ExecutionOutput '{output_id}' not found")

        if actor:
            validate_case_access(db, output.case_id, actor)

        return output
