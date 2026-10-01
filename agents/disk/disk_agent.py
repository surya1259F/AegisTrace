import uuid
import os
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from agents.base.agent import Agent, AgentAnalysisResult, CapabilityRequest
from forensic_tools.sleuthkit.adapter import SleuthKitAdapter
from forensic_tools.exiftool.adapter import ExifToolAdapter
from agents.disk.parsers.fls_parser import FlsParser, FlsParserResult

SUSPICIOUS_EXTENSIONS = {".bat", ".ps1", ".vbs", ".cmd", ".scr", ".pif", ".exe", ".dll", ".hta"}
SUSPICIOUS_PATHS = {"temp", "tmp", "appdata", "public", "downloads", "perflogs"}

class DiskAgent(Agent):
    """
    Specialist Disk Forensics Agent.
    Analyzes raw, dd, and E01 disk images using SleuthKit via ToolRegistry,
    and extracts structured metadata from files, documents, and archives using ExifTool.
    Extracts structured filesystem artifacts and produces evidence-backed candidate findings.
    """

    def __init__(self):
        super().__init__(
            name="DiskAgent",
            description="Analyzes filesystem structures, directory trees, deleted files, and file metadata.",
            capabilities=["filesystem_analysis", "deleted_file_carving", "inode_lookup", "metadata_extraction"],
            agent_id="agent-disk-forensics",
            version="1.0.0",
            supported_domains=["DISK", "FILESYSTEM", "STORAGE"],
            supported_artifact_types=[
                "FILE", "FILESYSTEM", "METADATA", "DIRECTORY", "DELETED_FILE", "DISK_IMAGE"
            ]
        )
        self.adapter = SleuthKitAdapter()
        self.exiftool_adapter = ExifToolAdapter()

    def can_handle(self, evidence_type: str) -> bool:
        if not evidence_type or not isinstance(evidence_type, str):
            return False
        et = evidence_type.lower()
        return et in [
            "disk_image", "file", "filesystem_image", "document", "archive",
            "text", "generic_binary", "malware_sample", "browser_db", "browser_artifact",
            "sqlite_database", "event_log", "windows_event_log", "pe_executable",
            "elf_executable", "macho_executable", "unknown"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "evidence")
        ev_type = str(evidence_item.get("evidence_type", "")).lower()
        if ev_type in ["file", "document", "archive"]:
            return [
                {
                    "step_id": "disk-exif-01",
                    "agent": self.name,
                    "tool": "ExifTool",
                    "action": "metadata_extraction",
                    "priority": 1,
                    "description": f"Extract file and EXIF metadata for {ev_name}."
                }
            ]
        return [
            {
                "step_id": "disk-fls-01",
                "agent": self.name,
                "tool": "SleuthKit",
                "action": "filesystem_structure_extraction",
                "priority": 1,
                "description": f"Extract directory tree and identify deleted entries for {ev_name}."
            }
        ]

    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AgentAnalysisResult:
        normalized_artifacts = structured_data.get("normalized_artifacts") or []
        evidence_items = structured_data.get("evidence_items") or []

        observations = []
        cap_requests = []
        supporting_art_ids = []
        supporting_ev_ids = []

        for art in normalized_artifacts:
            entity_type = str(art.get("entity_type", "")).upper()
            fields = art.get("normalized_fields") or {}
            art_id = art.get("id")
            ev_id = art.get("evidence_id")
            if ev_id and ev_id not in supporting_ev_ids:
                supporting_ev_ids.append(ev_id)

            file_path = str(fields.get("path") or fields.get("file_path") or fields.get("filename") or "")
            path_lower = file_path.lower()
            is_del = fields.get("is_deleted") or fields.get("deleted") or "deleted" in str(fields.get("status", "")).lower()

            if any(k in entity_type for k in ["FILE", "FILESYSTEM", "DIRECTORY", "DELETED", "METADATA"]) or file_path:
                supporting_art_ids.append(art_id)

                # 1. Deleted file
                if is_del:
                    observations.append({
                        "fact_type": "DELETED_FILE_OBSERVED",
                        "description": f"Deleted filesystem artifact detected: '{file_path}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"file_path": file_path, "inode": fields.get("inode"), "status": "deleted"},
                        "confidence": 0.95
                    })

                # 2. Suspicious path
                if any(p in path_lower for p in SUSPICIOUS_PATHS):
                    observations.append({
                        "fact_type": "SUSPICIOUS_FILE_LOCATION",
                        "description": f"Filesystem entry located in suspicious/temporary directory: '{file_path}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"file_path": file_path, "suspicious_paths_matched": [p for p in SUSPICIOUS_PATHS if p in path_lower]},
                        "confidence": 0.85
                    })

                # 3. Suspicious extension
                ext = Path(file_path).suffix.lower() if file_path else ""
                if ext in SUSPICIOUS_EXTENSIONS:
                    observations.append({
                        "fact_type": "SUSPICIOUS_FILE_EXTENSION",
                        "description": f"Filesystem entry possesses executable/script extension '{ext}': '{file_path}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"file_path": file_path, "extension": ext},
                        "confidence": 0.85
                    })

        # Generate capability requests for disk/file evidence items
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["disk", "file", "image", "raw", "dd", "e01", "filesystem"]):
                cap_requests.append({
                    "capability_id": "SLEUTHKIT_FLS_LISTING",
                    "evidence_id": ev_id,
                    "parameters": {"extract_deleted": True},
                    "rationale": f"Filesystem directory tree and deleted file carving requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="DISK_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Disk forensics analyzed {len(supporting_art_ids)} filesystem artifacts; identified {len(observations)} observations.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )

    def _save_raw_output(
        self,
        investigation_id: str,
        execution_id: str,
        stdout: str,
        stderr: str
    ) -> str:
        """
        Saves raw tool execution output to file-backed storage to avoid database bloat.
        Returns the relative path reference.
        """
        base_dir = Path(__file__).resolve().parent.parent.parent / "data" / "investigations" / investigation_id / "tool-output"
        from backend.app.core.config import settings
        base_dir = settings.DATA_DIR / "investigations" / investigation_id / "tool-output"
        base_dir.mkdir(parents=True, exist_ok=True)


        stdout_file = base_dir / f"{execution_id}.stdout"
        stderr_file = base_dir / f"{execution_id}.stderr"

        with open(stdout_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(stdout)
        with open(stderr_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(stderr)

        return str(stdout_file)

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Performs structured disk analysis on the provided evidence item.
        Returns a structured result containing extracted artifacts, candidate findings, and provenance.
        """
        params = parameters or {}
        inv_id = evidence_item.get("investigation_id") or evidence_item.get("case_id") or "UNKNOWN"
        ev_id = evidence_item.get("id") or "UNKNOWN"
        ev_path = evidence_item.get("storage_path")
        orig_path = evidence_item.get("original_path")
        ev_type = evidence_item.get("evidence_type", "unknown")
        execution_id = str(uuid.uuid4())

        # 1. Evidence Type Validation
        if not self.can_handle(ev_type):
            return {
                "status": "UNSUPPORTED_EVIDENCE_TYPE",
                "execution_id": execution_id,
                "error": f"Evidence type '{ev_type}' is not supported by DiskAgent.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        # 2. Evidence Storage Path Validation: Prohibit un-vaulted or missing storage_path
        if not ev_path:
            return {
                "status": "UNVAULTED_EVIDENCE_REJECTED",
                "execution_id": execution_id,
                "error": "Forensic analysis blocked: Evidence item does not have a valid vault storage_path. Direct execution against original_path is prohibited.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        if orig_path and str(Path(ev_path).resolve()) == str(Path(orig_path).resolve()):
            return {
                "status": "UNVAULTED_EVIDENCE_REJECTED",
                "execution_id": execution_id,
                "error": "Forensic analysis blocked: storage_path matches original_path. Direct execution against un-vaulted original evidence is prohibited.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        if not os.path.exists(ev_path):
            return {
                "status": "INVALID_EVIDENCE_PATH",
                "execution_id": execution_id,
                "error": f"Evidence file path '{ev_path}' does not exist on host.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        # 3. Determine Execution Path: Metadata Extraction (ExifTool) vs Filesystem Analysis (SleuthKit)
        action = params.get("action")
        tool_req = params.get("tool")
        is_metadata_action = (
            action == "metadata_extraction"
            or tool_req == "ExifTool"
            or (ev_type in ["file", "document", "archive"] and action != "filesystem_structure_extraction")
        )

        if is_metadata_action:
            if not self.exiftool_adapter.is_available():
                return {
                    "status": "TOOL_UNAVAILABLE",
                    "execution_id": execution_id,
                    "error": "ExifTool binary is not installed or available on this system.",
                    "artifacts": [],
                    "findings": [],
                    "provenance": {}
                }

            timeout = params.get("timeout_seconds", 60)
            exec_id_target = params.get("execution_id") or execution_id
            exec_res = self.exiftool_adapter.execute_metadata_extraction(
                evidence_path=ev_path,
                timeout_seconds=timeout,
                execution_id=exec_id_target
            )

            raw_output_path = self._save_raw_output(inv_id, execution_id, exec_res.stdout, exec_res.stderr)

            if exec_res.timed_out:
                return {
                    "status": "TIMED_OUT",
                    "execution_id": execution_id,
                    "error": exec_res.error_message or f"ExifTool execution timed out after {timeout}s.",
                    "artifacts": [],
                    "findings": [],
                    "provenance": {
                        "tool": "ExifTool",
                        "pid": exec_res.pid,
                        "timed_out": True,
                        "execution_time_ms": exec_res.execution_time_ms,
                        "return_code": exec_res.return_code,
                        "raw_output_reference": raw_output_path
                    }
                }

            if exec_res.cancelled:
                return {
                    "status": "CANCELLED",
                    "execution_id": execution_id,
                    "error": exec_res.error_message or "ExifTool execution was cancelled.",
                    "artifacts": [],
                    "findings": [],
                    "provenance": {
                        "tool": "ExifTool",
                        "pid": exec_res.pid,
                        "cancelled": True,
                        "execution_time_ms": exec_res.execution_time_ms,
                        "return_code": exec_res.return_code,
                        "raw_output_reference": raw_output_path
                    }
                }

            if not exec_res.success:
                return {
                    "status": "TOOL_EXECUTION_FAILED",
                    "execution_id": execution_id,
                    "error": exec_res.error_message or exec_res.stderr or f"Tool exited with code {exec_res.return_code}",
                    "artifacts": [],
                    "findings": [],
                    "provenance": {
                        "tool": "ExifTool",
                        "pid": exec_res.pid,
                        "execution_time_ms": exec_res.execution_time_ms,
                        "return_code": exec_res.return_code,
                        "raw_output_reference": raw_output_path
                    }
                }

            parsed_entries = []
            try:
                if exec_res.stdout.strip():
                    parsed_entries = json.loads(exec_res.stdout)
            except Exception:
                pass

            artifacts = []
            findings = []

            metadata_dict = {}
            if isinstance(parsed_entries, list) and len(parsed_entries) > 0:
                metadata_dict = parsed_entries[0]
            elif isinstance(parsed_entries, dict):
                metadata_dict = parsed_entries

            art_id = str(uuid.uuid4())
            file_name = os.path.basename(ev_path)
            source_ref = f"file:{file_name}"

            size_val = metadata_dict.get("File:FileSize") or metadata_dict.get("FileSize")
            size_bytes = None
            if isinstance(size_val, int):
                size_bytes = size_val
            elif isinstance(size_val, str) and size_val.isdigit():
                size_bytes = int(size_val)

            art = {
                "id": art_id,
                "investigation_id": inv_id,
                "evidence_id": ev_id,
                "agent": self.name,
                "tool": "ExifTool",
                "artifact_type": "metadata_entry",
                "source_reference": source_ref,
                "path": ev_path,
                "inode": None,
                "size_bytes": size_bytes,
                "is_deleted": False,
                "metadata_json": metadata_dict,
                "raw_output_reference": f"{raw_output_path}:metadata"
            }
            artifacts.append(art)

            if metadata_dict:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "ExifTool",
                    "finding_type": "file_metadata",
                    "title": f"Extracted File Metadata: {file_name}",
                    "description": f"ExifTool extracted {len(metadata_dict)} metadata attributes for {file_name}.",
                    "confidence": 0.90,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": raw_output_path
                })

            return {
                "status": "SUCCESS",
                "execution_id": execution_id,
                "artifacts_count": len(artifacts),
                "findings_count": len(findings),
                "execution_time_ms": exec_res.execution_time_ms,
                "tool_version": self.exiftool_adapter.get_tool_version(),
                "raw_output_reference": raw_output_path,
                "artifacts": artifacts,
                "findings": findings,
                "provenance": {
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "ExifTool",
                    "pid": exec_res.pid,
                    "tool_version": self.exiftool_adapter.get_tool_version(),
                    "operation": "metadata_extraction",
                    "execution_time_ms": exec_res.execution_time_ms,
                }
            }

        # 4. Tool Availability Check (SleuthKit)
        if not self.adapter.is_available():
            return {
                "status": "TOOL_UNAVAILABLE",
                "execution_id": execution_id,
                "error": "SleuthKit (fls) binary is not installed or available on this system.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        # 5. Execute fls via SleuthKitAdapter -> ToolRegistry
        offset = params.get("offset_sectors", 0)
        recursive = params.get("recursive", True)
        include_deleted = params.get("include_deleted", True)
        timeout = params.get("timeout_seconds", 60)
        exec_id_target = params.get("execution_id") or execution_id

        exec_res = self.adapter.execute_fls(
            evidence_path=ev_path,
            recursive=recursive,
            include_deleted=include_deleted,
            offset_sectors=offset,
            timeout_seconds=timeout,
            execution_id=exec_id_target
        )

        # 5. Save raw tool output
        raw_output_path = self._save_raw_output(inv_id, execution_id, exec_res.stdout, exec_res.stderr)

        if exec_res.timed_out:
            return {
                "status": "TIMED_OUT",
                "execution_id": execution_id,
                "error": exec_res.error_message or f"SleuthKit execution timed out after {timeout}s.",
                "artifacts": [],
                "findings": [],
                "provenance": {
                    "tool": "SleuthKit",
                    "pid": exec_res.pid,
                    "timed_out": True,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "return_code": exec_res.return_code,
                    "raw_output_reference": raw_output_path
                }
            }

        if exec_res.cancelled:
            return {
                "status": "CANCELLED",
                "execution_id": execution_id,
                "error": exec_res.error_message or "SleuthKit execution was cancelled.",
                "artifacts": [],
                "findings": [],
                "provenance": {
                    "tool": "SleuthKit",
                    "pid": exec_res.pid,
                    "cancelled": True,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "return_code": exec_res.return_code,
                    "raw_output_reference": raw_output_path
                }
            }

        if not exec_res.success:
            return {
                "status": "TOOL_EXECUTION_FAILED",
                "execution_id": execution_id,
                "error": exec_res.error_message or exec_res.stderr or f"Tool exited with code {exec_res.return_code}",
                "artifacts": [],
                "findings": [],
                "provenance": {
                    "tool": "SleuthKit",
                    "pid": exec_res.pid,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "return_code": exec_res.return_code,
                    "raw_output_reference": raw_output_path
                }
            }

        # 6. Parse stdout using dedicated FlsParser
        parse_result: FlsParserResult = FlsParser.parse(exec_res.stdout)

        artifacts = []
        findings = []

        # 7. Convert parsed entries into structured Artifacts & candidate Findings
        for entry in parse_result.entries:
            art_id = str(uuid.uuid4())
            source_ref = f"inode:{entry.inode}"

            # Create Artifact (All discovered filesystem objects)
            art = {
                "id": art_id,
                "investigation_id": inv_id,
                "evidence_id": ev_id,
                "agent": self.name,
                "tool": "SleuthKit",
                "artifact_type": "deleted_file" if entry.is_deleted else f"filesystem_{entry.entry_type}",
                "source_reference": source_ref,
                "path": entry.file_path,
                "inode": entry.inode,
                "size_bytes": None,
                "is_deleted": entry.is_deleted,
                "metadata_json": {
                    "entry_type_raw": entry.entry_type_raw,
                    "raw_line": entry.raw_line
                },
                "raw_output_reference": f"{raw_output_path}:{entry.inode}"
            }
            artifacts.append(art)

            # Generate Evidence-Backed Candidate Findings
            file_name = entry.file_path.split("/")[-1].split("\\")[-1].lower()
            file_ext = os.path.splitext(file_name)[1].lower()
            path_parts = set(entry.file_path.lower().replace("\\", "/").split("/"))

            # Case A: Deleted File
            if entry.is_deleted:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "SleuthKit",
                    "finding_type": "deleted_artifact",
                    "title": f"Deleted Filesystem Entry: {entry.file_path}",
                    "description": f"Deleted {entry.entry_type} identified at inode {entry.inode} ({entry.raw_line}).",
                    "confidence": 0.95,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": entry.raw_line
                })

            # Case B: Executable/Script in Suspicious Path
            elif file_ext in SUSPICIOUS_EXTENSIONS and (path_parts & SUSPICIOUS_PATHS):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "SleuthKit",
                    "finding_type": "suspicious_file_location",
                    "title": f"Suspicious Executable Location: {entry.file_path}",
                    "description": f"Executable file '{file_name}' located in temporary/suspicious directory path at inode {entry.inode}.",
                    "confidence": 0.85,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": entry.raw_line
                })

        return {
            "status": "SUCCESS",
            "execution_id": execution_id,
            "artifacts_count": len(artifacts),
            "findings_count": len(findings),
            "execution_time_ms": exec_res.execution_time_ms,
            "tool_version": self.adapter.get_tool_version(),
            "raw_output_reference": raw_output_path,
            "artifacts": artifacts,
            "findings": findings,
            "provenance": {
                "investigation_id": inv_id,
                "evidence_id": ev_id,
                "agent": self.name,
                "tool": "SleuthKit",
                "tool_version": self.adapter.get_tool_version(),
                "operation": "fls_listing",
                "execution_time_ms": exec_res.execution_time_ms,
                "parse_errors": parse_result.parse_errors
            }
        }


DiskForensicsAgent = DiskAgent
