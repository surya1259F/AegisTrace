"""
ADFIR — Structured Artifact Extraction Subsystem (Phase 2 / Step 11)

Converts Step 10 raw forensic outputs into structured forensic artifacts.
Strict forensic boundaries:
- Structured forensic artifacts represent evidence-derived data, NOT conclusions or findings.
- DO NOT: detect attacks, correlate artifacts, infer attacker behavior, generate findings, generate conclusions.
- DO NOT modify raw forensic outputs or the evidence vault.
- Unsupported raw outputs must be recorded as UNSUPPORTED, never silently ignored.
- Full cryptographic SHA-256 calculation and provenance back to EvidenceItem -> Execution -> Raw Output -> Artifact.
"""

import os
import re
import json
import stat
import uuid
import hashlib
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    ForensicExecution,
    ExecutionOutput,
    EvidenceItem,
    StructuredArtifact,
    AuditEvent,
    User
)
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_ARTIFACT_EXTRACTION")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# 1. BASE PARSER CONTRACT
# =============================================================================

class BaseArtifactParser(ABC):
    """
    Abstract contract for tool-specific output parsers.
    Parsers extract structured records and normalize fields without inventing values.
    """
    parser_name: str = "BaseParser"
    parser_version: str = "1.0.0"
    artifact_type: str = "GENERIC_RECORD"
    supported_tools: List[str] = []

    @abstractmethod
    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        """Determines if this parser can interpret the given raw output."""
        pass

    @abstractmethod
    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        """
        Parses raw forensic content into a list of normalized structured artifact dicts.
        Returns entries:
            {
                "artifact_type": str,
                "source_reference": str,
                "normalized_data": Dict[str, Any],
                "raw_record": str
            }
        """
        pass


# =============================================================================
# 2. CONCRETE FORENSIC PARSERS
# =============================================================================

class FlsArtifactParser(BaseArtifactParser):
    """
    Parses The Sleuth Kit (fls) bodyfile / directory listing outputs.
    Extracts FILESYSTEM_RECORD artifacts.
    """
    parser_name = "FlsArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "FILESYSTEM_RECORD"
    supported_tools = ["fls", "sleuthkit_fls", "tsk_fls"]

    # Typical fls line patterns:
    # r/r 1024-128-3: dir/file.ext
    # d/d * 2048-144-1: deleted_dir
    # + r/r 3000-128-1: allocated_file
    FLS_PATTERN = re.compile(r"^([+\-\*]?\s*)?([rdbclsp\-]/[rdbclsp\-])\s+(\*?\s*)([\d\-]+):\s+(.*)$")

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if any(t in tool_id for t in self.supported_tools):
            return True
        filename = (raw_output.filename or "").lower()
        if "fls" in filename or "bodyfile" in filename:
            return True
        for line in content_sample.splitlines()[:10]:
            if self.FLS_PATTERN.match(line.strip()):
                return True
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            m = self.FLS_PATTERN.match(line_str)
            if m:
                _, file_mode, del_flag, inode, file_path = m.groups()
                is_deleted = bool(del_flag and "*" in del_flag)
                
                # Normalize file type from fls type indicators
                ftype_code = file_mode.split("/")[0] if "/" in file_mode else file_mode
                ftype_map = {
                    "r": "REGULAR_FILE",
                    "d": "DIRECTORY",
                    "b": "BLOCK_DEVICE",
                    "c": "CHARACTER_DEVICE",
                    "l": "SYMLINK",
                    "s": "SOCKET",
                    "p": "NAMED_PIPE",
                    "-": "UNKNOWN"
                }
                file_type = ftype_map.get(ftype_code.lower(), "UNKNOWN")

                norm_data = {
                    "filename": file_path.strip(),
                    "inode": inode.strip(),
                    "file_type": file_type,
                    "is_deleted": is_deleted,
                    "mode_string": file_mode.strip()
                }

                results.append({
                    "artifact_type": self.artifact_type,
                    "source_reference": f"inode:{inode}:{file_path.strip()}",
                    "normalized_data": norm_data,
                    "raw_record": line_str
                })
        return results


class EvtxArtifactParser(BaseArtifactParser):
    """
    Parses Windows Event Log (EVTX) dumps (JSON formatted lines or JSON array).
    Extracts EVENT_LOG_RECORD artifacts.
    """
    parser_name = "EvtxArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "EVENT_LOG_RECORD"
    supported_tools = ["winevtx", "evtx_dump", "python_evtx"]

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if any(t in tool_id for t in self.supported_tools):
            return True
        filename = (raw_output.filename or "").lower()
        if "evtx" in filename or "event" in filename:
            return True
        if '"EventID"' in content_sample or '"Event"' in content_sample:
            return True
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        lines = content.splitlines()

        # Handle full JSON array or line-delimited JSON
        parsed_objects = []
        try:
            full_json = json.loads(content)
            if isinstance(full_json, list):
                parsed_objects = full_json
            elif isinstance(full_json, dict):
                parsed_objects = [full_json]
        except Exception:
            for l in lines:
                l_str = l.strip()
                if l_str.startswith("{") and l_str.endswith("}"):
                    try:
                        parsed_objects.append(json.loads(l_str))
                    except Exception:
                        pass

        for entry in parsed_objects:
            event_obj = entry.get("Event", entry)
            system_data = event_obj.get("System", {})
            event_data = event_obj.get("EventData", {})

            # Extract fields deterministically without inventing values
            event_id = system_data.get("EventID")
            if isinstance(event_id, dict):
                event_id = event_id.get("#text")
            try:
                event_id = int(event_id) if event_id is not None else None
            except Exception:
                pass

            time_created = system_data.get("TimeCreated", {})
            timestamp = time_created.get("@SystemTime") if isinstance(time_created, dict) else str(time_created)

            provider = system_data.get("Provider", {})
            provider_name = provider.get("@Name") if isinstance(provider, dict) else str(provider)

            computer = system_data.get("Computer")
            channel = system_data.get("Channel")

            norm = {
                "event_id": event_id,
                "timestamp": timestamp or None,
                "provider": provider_name or None,
                "computer": computer or None,
                "channel": channel or None,
                "event_data": event_data if isinstance(event_data, dict) else {}
            }

            src_ref = f"event:{event_id}:{computer or 'unknown'}:{timestamp or 'unknown'}"
            results.append({
                "artifact_type": self.artifact_type,
                "source_reference": src_ref,
                "normalized_data": norm,
                "raw_record": json.dumps(entry, sort_keys=True)
            })

        return results


class YaraArtifactParser(BaseArtifactParser):
    """
    Parses YARA malware scanner output.
    Extracts MALWARE_MATCH artifacts.
    """
    parser_name = "YaraArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "MALWARE_MATCH"
    supported_tools = ["yara", "yara_scanner"]

    # Pattern: rule_name [tag1,tag2] /path/to/target or rule_name /path/to/target
    YARA_LINE = re.compile(r"^([a-zA-Z0-9_\-]+)\s*(?:\[(.*?)\])?\s+(.*)$")

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if any(t in tool_id for t in self.supported_tools):
            return True
        filename = (raw_output.filename or "").lower()
        if "yara" in filename:
            return True

        # Do not match if the tool or filename clearly belongs to another domain
        other_tool_indicators = ["pslist", "netscan", "fls", "bodyfile", "evtx", "exif", "metadata"]
        if any(ind in tool_id or ind in filename for ind in other_tool_indicators):
            return False

        for line in content_sample.splitlines()[:5]:
            line_str = line.strip()
            if self.YARA_LINE.match(line_str) and ("/" in line_str or "\\" in line_str or "[" in line_str):
                return True
        return False


    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            m = self.YARA_LINE.match(line_str)
            if m:
                rule_name, tags_raw, target_path = m.groups()
                tags = [t.strip() for t in tags_raw.split(",")] if tags_raw else []

                norm = {
                    "rule_name": rule_name,
                    "target_path": target_path.strip(),
                    "tags": tags
                }

                results.append({
                    "artifact_type": self.artifact_type,
                    "source_reference": f"yara:{rule_name}:{target_path.strip()}",
                    "normalized_data": norm,
                    "raw_record": line_str
                })
        return results


class PsListArtifactParser(BaseArtifactParser):
    """
    Parses Volatility 2 / 3 pslist process output tables.
    Extracts PROCESS_RECORD artifacts.
    """
    parser_name = "PsListArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "PROCESS_RECORD"
    supported_tools = ["volatility_pslist", "pslist", "volatility3_pslist"]

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if "pslist" in tool_id:
            return True
        filename = (raw_output.filename or "").lower()
        if "pslist" in filename:
            return True
        if "ImageFileName" in content_sample and "PID" in content_sample:
            return True
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        lines = content.splitlines()
        header_idx = -1
        col_names = []

        for idx, line in enumerate(lines):
            if "PID" in line and ("ImageFileName" in line or "PPID" in line):
                header_idx = idx
                col_names = [c.strip() for c in re.split(r"\t+|\s{2,}", line.strip()) if c.strip()]
                break

        if header_idx == -1:
            return results

        for line in lines[header_idx + 1:]:
            line_str = line.strip()
            if not line_str or line_str.startswith("-") or line_str.startswith("="):
                continue
            cols = [c.strip() for c in re.split(r"\t+|\s{2,}", line_str) if c.strip()]
            if len(cols) >= 3:
                try:
                    pid = int(cols[0])
                    ppid = int(cols[1]) if len(cols) > 1 and cols[1].isdigit() else 0
                    img_name = cols[2] if len(cols) > 2 else "UNKNOWN"

                    norm = {
                        "pid": pid,
                        "ppid": ppid,
                        "image_name": img_name,
                        "raw_columns": cols
                    }

                    results.append({
                        "artifact_type": self.artifact_type,
                        "source_reference": f"process:{pid}:{img_name}",
                        "normalized_data": norm,
                        "raw_record": line_str
                    })
                except Exception:
                    continue
        return results


class NetScanArtifactParser(BaseArtifactParser):
    """
    Parses Volatility netscan network connection tables.
    Extracts NETWORK_RECORD artifacts.
    """
    parser_name = "NetScanArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "NETWORK_RECORD"
    supported_tools = ["volatility_netscan", "netscan", "volatility3_netscan"]

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if "netscan" in tool_id:
            return True
        filename = (raw_output.filename or "").lower()
        if "netscan" in filename:
            return True
        if "Local Address" in content_sample and "Foreign Address" in content_sample:
            return True
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        lines = content.splitlines()
        header_idx = -1

        for idx, line in enumerate(lines):
            if "Proto" in line and "Local Address" in line:
                header_idx = idx
                break

        if header_idx == -1:
            return results

        for line in lines[header_idx + 1:]:
            line_str = line.strip()
            if not line_str or line_str.startswith("-") or line_str.startswith("="):
                continue
            cols = [c.strip() for c in re.split(r"\t+|\s{2,}", line_str) if c.strip()]
            if len(cols) >= 5:
                # Format: Offset, Proto, Local Address, Foreign Address, State, PID, Owner...
                offset = cols[0]
                proto = cols[1] if len(cols) > 1 else "UNKNOWN"
                local_addr = cols[2] if len(cols) > 2 else "UNKNOWN"
                foreign_addr = cols[3] if len(cols) > 3 else "UNKNOWN"
                state = cols[4] if len(cols) > 4 else "UNKNOWN"
                pid = int(cols[5]) if len(cols) > 5 and cols[5].isdigit() else None

                norm = {
                    "offset": offset,
                    "protocol": proto,
                    "local_address": local_addr,
                    "foreign_address": foreign_addr,
                    "state": state,
                    "pid": pid
                }

                results.append({
                    "artifact_type": self.artifact_type,
                    "source_reference": f"net:{proto}:{local_addr}->{foreign_addr}",
                    "normalized_data": norm,
                    "raw_record": line_str
                })
        return results


class ExifToolArtifactParser(BaseArtifactParser):
    """
    Parses ExifTool JSON file metadata output.
    Extracts METADATA_RECORD artifacts.
    """
    parser_name = "ExifToolArtifactParser"
    parser_version = "1.0.0"
    artifact_type = "METADATA_RECORD"
    supported_tools = ["exiftool", "image_metadata"]

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        tool_id = (raw_output.tool_id or "").lower()
        if "exiftool" in tool_id:
            return True
        filename = (raw_output.filename or "").lower()
        if "exif" in filename:
            return True
        if "SourceFile" in content_sample and ("MIMEType" in content_sample or "FileType" in content_sample):
            return True
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        try:
            data = json.loads(content)
            entries = data if isinstance(data, list) else [data]
        except Exception:
            return results

        for entry in entries:
            src_file = entry.get("SourceFile", "unknown")
            file_type = entry.get("FileType")
            mime_type = entry.get("MIMEType")

            norm = {
                "source_file": src_file,
                "file_type": file_type,
                "mime_type": mime_type,
                "metadata": entry
            }

            results.append({
                "artifact_type": self.artifact_type,
                "source_reference": f"metadata:{src_file}",
                "normalized_data": norm,
                "raw_record": json.dumps(entry, sort_keys=True)
            })
        return results


class GenericStructuredTextParser(BaseArtifactParser):
    """
    Fallback parser for structured outputs (valid JSON objects or lists)
    produced by forensic tools without a specialized parser.
    """
    parser_name = "GenericStructuredTextParser"
    parser_version = "1.0.0"
    artifact_type = "GENERIC_RECORD"
    supported_tools = []

    def is_compatible(self, raw_output: ExecutionOutput, content_sample: str) -> bool:
        sample = content_sample.strip()
        if (sample.startswith("{") and sample.endswith("}")) or (sample.startswith("[") and sample.endswith("]")):
            try:
                json.loads(sample)
                return True
            except Exception:
                return False
        return False

    def parse(self, raw_output: ExecutionOutput, raw_file: Path, content: str) -> List[Dict[str, Any]]:
        results = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else [data]
        except Exception:
            return results

        for idx, item in enumerate(items):
            if isinstance(item, dict):
                results.append({
                    "artifact_type": self.artifact_type,
                    "source_reference": f"item:{idx}",
                    "normalized_data": item,
                    "raw_record": json.dumps(item, sort_keys=True)
                })
        return results


# =============================================================================
# 3. PARSER REGISTRY
# =============================================================================

class ArtifactParserRegistry:
    """
    Registry of forensic output parsers.
    Determines parser selection deterministically from registered capabilities.
    """
    def __init__(self):
        self._parsers: List[BaseArtifactParser] = []
        self._register_defaults()

    def _register_defaults(self):
        self.register(FlsArtifactParser())
        self.register(EvtxArtifactParser())
        self.register(YaraArtifactParser())
        self.register(PsListArtifactParser())
        self.register(NetScanArtifactParser())
        self.register(ExifToolArtifactParser())
        self.register(GenericStructuredTextParser())

    def register(self, parser: BaseArtifactParser):
        self._parsers.append(parser)

    def select_parser(self, raw_output: ExecutionOutput, content_sample: str) -> Optional[BaseArtifactParser]:
        """
        Selects first matching parser in order of specificity.
        """
        for parser in self._parsers:
            try:
                if parser.is_compatible(raw_output, content_sample):
                    return parser
            except Exception as e:
                logger.warning(f"Error checking parser compatibility {parser.parser_name}: {e}")
        return None


parser_registry = ArtifactParserRegistry()


# =============================================================================
# 4. STORAGE MANAGER & ISOLATION CONTROLS
# =============================================================================

class ArtifactStorageManager:
    """
    Manages structured artifact storage.
    Enforces path isolation outside the evidence vault and safe POSIX permissions (0o600 / 0o700).
    """

    @classmethod
    def get_artifact_base_dir(cls, case_id: str, execution_id: str) -> Path:
        base_dir = settings.DATA_DIR / "storage" / "artifacts" / "cases" / case_id / execution_id
        base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass
        return base_dir

    @classmethod
    def validate_storage_path(cls, candidate_path: Path, case_id: str, execution_id: str) -> bool:
        """
        Ensures storage path is strictly within the allowed directory and NOT inside the evidence vault.
        """
        canonical = candidate_path.resolve()
        base_dir = (settings.DATA_DIR / "storage" / "artifacts" / "cases" / case_id / execution_id).resolve()

        vault_candidates = [
            settings.EVIDENCE_DIR.resolve(),
            (settings.EVIDENCE_DIR / "vault").resolve()
        ]
        for v in vault_candidates:
            if canonical == v or canonical.is_relative_to(v):
                raise ValueError(f"CRITICAL: Artifact storage cannot be located inside evidence vault: {canonical}")

        if not canonical.is_relative_to(base_dir):
            raise ValueError(f"Path traversal detected: {candidate_path} outside base {base_dir}")

        return True


    @classmethod
    def persist_artifact_file(
        cls,
        case_id: str,
        execution_id: str,
        artifact_id: str,
        payload: Dict[str, Any]
    ) -> Path:
        """
        Persists serialized artifact JSON to disk with 0o600 permissions.
        """
        out_dir = cls.get_artifact_base_dir(case_id, execution_id)
        out_file = out_dir / f"{artifact_id}.json"
        cls.validate_storage_path(out_file, case_id, execution_id)

        canonical_json = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
        out_file.write_text(canonical_json, encoding="utf-8")

        try:
            os.chmod(out_file, 0o600)
        except Exception:
            pass

        return out_file


# =============================================================================
# 5. ARTIFACT EXTRACTION SERVICE
# =============================================================================

class ArtifactExtractionService:
    """
    Core service converting Step 10 raw forensic outputs into structured forensic artifacts.
    Enforces parser selection, field normalization, SHA-256 calculation, and provenance chaining.
    """

    @classmethod
    def extract_from_output(
        cls,
        db: Session,
        raw_output: ExecutionOutput,
        actor_user: Optional[User] = None
    ) -> List[StructuredArtifact]:
        """
        Extracts structured artifacts from a single Step 10 raw output artifact.
        Handles unsupported outputs explicitly by recording an UNSUPPORTED StructuredArtifact.
        """
        raw_file = Path(raw_output.storage_path)
        if not raw_file.exists():
            raise FileNotFoundError(f"Raw output file '{raw_output.storage_path}' not found on disk")

        try:
            content = raw_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""

        content_sample = content[:4096]

        # 1. Parser Selection
        parser = parser_registry.select_parser(raw_output, content_sample)
        now = utc_now()
        extracted_artifacts: List[StructuredArtifact] = []

        # 2. Handle Unsupported Output
        if not parser:
            logger.info(f"Raw output {raw_output.id} ({raw_output.filename}) has no compatible parser. Recording as UNSUPPORTED.")
            unsupported_id = str(uuid.uuid4())
            normalized_payload = {
                "status": "UNSUPPORTED",
                "filename": raw_output.filename,
                "size_bytes": raw_output.size_bytes,
                "tool_id": raw_output.tool_id,
                "output_type": raw_output.output_type,
                "reason": f"No compatible parser registered for tool '{raw_output.tool_id}' (filename: '{raw_output.filename}')"
            }
            canonical_bytes = json.dumps(normalized_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            art_hash = hashlib.sha256(canonical_bytes).hexdigest()

            storage_path = ArtifactStorageManager.persist_artifact_file(
                case_id=raw_output.case_id,
                execution_id=raw_output.execution_id,
                artifact_id=unsupported_id,
                payload={
                    "id": unsupported_id,
                    "artifact_type": "UNSUPPORTED_OUTPUT",
                    "normalized_data": normalized_payload,
                    "sha256_hash": art_hash,
                    "source_raw_output_hash": raw_output.sha256_hash
                }
            )

            art = StructuredArtifact(
                id=unsupported_id,
                case_id=raw_output.case_id,
                evidence_id=raw_output.evidence_id,
                execution_id=raw_output.execution_id,
                raw_output_id=raw_output.id,
                request_id=raw_output.request_id,
                task_id=raw_output.task_id,
                tool_id=raw_output.tool_id,
                tool_version=raw_output.tool_version,
                parser_name="UNSUPPORTED",
                parser_version="N/A",
                artifact_type="UNSUPPORTED_OUTPUT",
                source_reference=f"output:{raw_output.filename}",
                normalized_data=normalized_payload,
                raw_record=None,
                sha256_hash=art_hash,
                source_raw_output_hash=raw_output.sha256_hash,
                storage_path=str(storage_path),
                extraction_status="UNSUPPORTED",
                error_message=normalized_payload["reason"],
                created_at=now
            )
            db.add(art)
            db.commit()
            db.refresh(art)

            log_audit_event(
                db=db,
                event_type="ARTIFACT_EXTRACTION_UNSUPPORTED",
                case_id=raw_output.case_id,
                actor_id=actor_user.id if actor_user else "system",
                actor_name=actor_user.name if actor_user else "system",
                details=f"Raw output {raw_output.id} recorded as UNSUPPORTED: {normalized_payload['reason']}"
            )
            return [art]

        # 3. Parser Execution & Extraction
        try:
            parsed_entries = parser.parse(raw_output, raw_file, content)
        except Exception as parse_err:
            logger.error(f"Parser {parser.parser_name} encountered error parsing {raw_output.id}: {parse_err}")
            err_id = str(uuid.uuid4())
            err_payload = {
                "status": "PARSE_ERROR",
                "filename": raw_output.filename,
                "error": str(parse_err)
            }
            canonical_bytes = json.dumps(err_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            err_hash = hashlib.sha256(canonical_bytes).hexdigest()

            err_art = StructuredArtifact(
                id=err_id,
                case_id=raw_output.case_id,
                evidence_id=raw_output.evidence_id,
                execution_id=raw_output.execution_id,
                raw_output_id=raw_output.id,
                request_id=raw_output.request_id,
                task_id=raw_output.task_id,
                tool_id=raw_output.tool_id,
                tool_version=raw_output.tool_version,
                parser_name=parser.parser_name,
                parser_version=parser.parser_version,
                artifact_type="PARSE_ERROR",
                source_reference=f"error:{raw_output.filename}",
                normalized_data=err_payload,
                raw_record=None,
                sha256_hash=err_hash,
                source_raw_output_hash=raw_output.sha256_hash,
                storage_path=None,
                extraction_status="PARSE_ERROR",
                error_message=str(parse_err),
                created_at=now
            )
            db.add(err_art)
            db.commit()
            db.refresh(err_art)
            return [err_art]

        # 4. Process Successfully Extracted Records
        for item in parsed_entries:
            art_id = str(uuid.uuid4())
            norm_data = item.get("normalized_data", {})
            src_ref = item.get("source_reference")
            raw_rec = item.get("raw_record")
            art_type = item.get("artifact_type") or parser.artifact_type

            canonical_bytes = json.dumps(norm_data, sort_keys=True, separators=(',', ':')).encode("utf-8")
            art_hash = hashlib.sha256(canonical_bytes).hexdigest()

            storage_path = ArtifactStorageManager.persist_artifact_file(
                case_id=raw_output.case_id,
                execution_id=raw_output.execution_id,
                artifact_id=art_id,
                payload={
                    "id": art_id,
                    "case_id": raw_output.case_id,
                    "evidence_id": raw_output.evidence_id,
                    "execution_id": raw_output.execution_id,
                    "raw_output_id": raw_output.id,
                    "tool_id": raw_output.tool_id,
                    "parser_name": parser.parser_name,
                    "parser_version": parser.parser_version,
                    "artifact_type": art_type,
                    "source_reference": src_ref,
                    "normalized_data": norm_data,
                    "raw_record": raw_rec,
                    "sha256_hash": art_hash,
                    "source_raw_output_hash": raw_output.sha256_hash,
                    "created_at": now.isoformat()
                }
            )

            art = StructuredArtifact(
                id=art_id,
                case_id=raw_output.case_id,
                evidence_id=raw_output.evidence_id,
                execution_id=raw_output.execution_id,
                raw_output_id=raw_output.id,
                request_id=raw_output.request_id,
                task_id=raw_output.task_id,
                tool_id=raw_output.tool_id,
                tool_version=raw_output.tool_version,
                parser_name=parser.parser_name,
                parser_version=parser.parser_version,
                artifact_type=art_type,
                source_reference=src_ref,
                normalized_data=norm_data,
                raw_record=raw_rec,
                sha256_hash=art_hash,
                source_raw_output_hash=raw_output.sha256_hash,
                storage_path=str(storage_path),
                extraction_status="EXTRACTED",
                error_message=None,
                created_at=now
            )
            db.add(art)
            extracted_artifacts.append(art)

        db.commit()
        for a in extracted_artifacts:
            db.refresh(a)

        log_audit_event(
            db=db,
            event_type="ARTIFACTS_EXTRACTED",
            case_id=raw_output.case_id,
            actor_id=actor_user.id if actor_user else "system",
            actor_name=actor_user.name if actor_user else "system",
            details=f"Extracted {len(extracted_artifacts)} artifacts from raw output {raw_output.id} using {parser.parser_name}"
        )

        return extracted_artifacts

    @classmethod
    def extract_for_execution(
        cls,
        db: Session,
        execution_id: str,
        case_id: str,
        actor_user: Optional[User] = None
    ) -> List[StructuredArtifact]:
        """
        Discovers all outputs for an execution, extracts structured artifacts, and returns them.
        """
        outputs = (
            db.query(ExecutionOutput)
            .filter(
                ExecutionOutput.execution_id == execution_id,
                ExecutionOutput.case_id == case_id
            )
            .order_by(ExecutionOutput.created_at.asc())
            .all()
        )

        all_artifacts: List[StructuredArtifact] = []
        for out in outputs:
            if out.output_type in ["TOOL_OUTPUT", "STDOUT"]:
                arts = cls.extract_from_output(db=db, raw_output=out, actor_user=actor_user)
                all_artifacts.extend(arts)

        return all_artifacts

    @classmethod
    def list_execution_artifacts(
        cls,
        db: Session,
        execution_id: str,
        case_id: str,
        artifact_type: Optional[str] = None,
        extraction_status: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[StructuredArtifact]:
        query = db.query(StructuredArtifact).filter(
            StructuredArtifact.execution_id == execution_id,
            StructuredArtifact.case_id == case_id
        )
        if artifact_type:
            query = query.filter(StructuredArtifact.artifact_type == artifact_type)
        if extraction_status:
            query = query.filter(StructuredArtifact.extraction_status == extraction_status)
        return query.order_by(StructuredArtifact.created_at.asc()).offset(skip).limit(limit).all()

    @classmethod
    def list_evidence_artifacts(
        cls,
        db: Session,
        evidence_id: str,
        case_id: str,
        artifact_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[StructuredArtifact]:
        query = db.query(StructuredArtifact).filter(
            StructuredArtifact.evidence_id == evidence_id,
            StructuredArtifact.case_id == case_id
        )
        if artifact_type:
            query = query.filter(StructuredArtifact.artifact_type == artifact_type)
        return query.order_by(StructuredArtifact.created_at.asc()).offset(skip).limit(limit).all()

    @classmethod
    def get_artifact_details(
        cls,
        db: Session,
        artifact_id: str,
        case_id: str
    ) -> StructuredArtifact:
        art = (
            db.query(StructuredArtifact)
            .filter(StructuredArtifact.id == artifact_id, StructuredArtifact.case_id == case_id)
            .first()
        )
        if not art:
            raise ValueError(f"StructuredArtifact '{artifact_id}' not found for case '{case_id}'")
        return art

    @classmethod
    def verify_artifact_integrity(
        cls,
        db: Session,
        artifact_id: str,
        case_id: str
    ) -> Dict[str, Any]:
        """
        Cryptographically verifies structured artifact integrity and provenance back to raw output.
        """
        art = cls.get_artifact_details(db, artifact_id, case_id)

        canonical_bytes = json.dumps(art.normalized_data or {}, sort_keys=True, separators=(',', ':')).encode("utf-8")
        calc_hash = hashlib.sha256(canonical_bytes).hexdigest()

        disk_ok = True
        if art.storage_path:
            p = Path(art.storage_path)
            if not p.exists():
                disk_ok = False

        raw_out = (
            db.query(ExecutionOutput)
            .filter(ExecutionOutput.id == art.raw_output_id, ExecutionOutput.case_id == case_id)
            .first()
        )
        raw_out_hash = raw_out.sha256_hash if raw_out else None
        raw_match = (raw_out_hash == art.source_raw_output_hash) if raw_out else False

        if not disk_ok and art.storage_path:
            status = "FILE_MISSING"
        elif calc_hash != art.sha256_hash:
            status = "TAMPERED"
        elif not raw_match:
            status = "RAW_OUTPUT_MISMATCH"
        else:
            status = "VALID"

        provenance = {
            "case_id": art.case_id,
            "evidence_id": art.evidence_id,
            "execution_id": art.execution_id,
            "raw_output_id": art.raw_output_id,
            "request_id": art.request_id,
            "task_id": art.task_id,
            "tool_id": art.tool_id,
            "tool_version": art.tool_version,
            "parser_name": art.parser_name,
            "parser_version": art.parser_version,
            "extraction_status": art.extraction_status
        }

        return {
            "artifact_id": art.id,
            "artifact_type": art.artifact_type,
            "expected_sha256": art.sha256_hash,
            "calculated_sha256": calc_hash,
            "source_raw_output_hash": art.source_raw_output_hash,
            "raw_output_current_hash": raw_out_hash,
            "integrity_status": status,
            "provenance_chain": provenance,
            "checked_at": utc_now()
        }
