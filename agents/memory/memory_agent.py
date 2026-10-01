import uuid
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile
from forensic_tools.volatility.adapter import VolatilityAdapter, ALLOWED_PLUGINS
from agents.memory.parsers.pslist_parser import PsListParser
from agents.memory.parsers.pstree_parser import PsTreeParser
from agents.memory.parsers.netscan_parser import NetScanParser

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "nc.exe", "ncat.exe", "psexec.exe",
    "procdump.exe", "whoami.exe", "lazagne.exe", "meterpreter"
}

PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                       "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                       "127.", "0.0.0.0", "::1", "*")

class MemoryAgent(Agent):
    """
    Specialist Memory Forensics Agent (Phase 2 / Step 16).
    Analyzes physical/raw RAM dumps using Volatility 3 via ToolRegistry.
    Extracts structured memory artifacts and generates evidence-backed candidate findings.
    """

    def __init__(self):
        super().__init__(
            name="MemoryForensicsAgent",
            description="Analyzes memory dumps to extract process listings, process trees, and active network connections.",
            capabilities=["process_listing", "process_tree_analysis", "network_connection_extraction", "injection_detection"],
            agent_id="agent-memory-forensics",
            version="1.0.0",
            supported_domains=["MEMORY"],
            supported_artifact_types=["PROCESS", "NETWORK_SOCKET", "HANDLE", "INJECTION", "DLL"],
            safety_profile=AgentSafetyProfile(
                allow_direct_execution=False,
                allow_shell_commands=False,
                allow_evidence_modification=False,
                read_only_access=True,
                requires_capability_gating=True
            )
        )
        self.adapter = VolatilityAdapter()

    def can_handle(self, evidence_type: str) -> bool:
        if not evidence_type or not isinstance(evidence_type, str):
            return False
        return evidence_type.lower() in ["memory_dump", "raw_memory", "vmem", "dmp"]
        return evidence_type.lower() in ["memory_dump", "raw_memory", "vmem", "dmp", "minidump"]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "memory_dump")
        return [
            {
                "step_id": "mem-pslist-01",
                "agent": self.name,
                "tool": "Volatility3",
                "plugin": "windows.pslist",
                "action": "process_enumeration",
                "priority": 1,
                "description": f"Enumerate active and terminated processes in {ev_name}."
            },
            {
                "step_id": "mem-netscan-02",
                "agent": self.name,
                "tool": "Volatility3",
                "plugin": "windows.netscan",
                "action": "network_socket_extraction",
                "priority": 2,
                "description": f"Extract active network connections and listening sockets for {ev_name}."
            }
        ]

    def _save_raw_output(
        self,
        investigation_id: str,
        execution_id: str,
        stdout: str,
        stderr: str
    ) -> str:
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
        Performs structured memory forensics on the evidence item.
        """
        params = parameters or {}
        inv_id = evidence_item.get("investigation_id") or evidence_item.get("case_id") or "UNKNOWN"
        ev_id = evidence_item.get("id") or "UNKNOWN"
        ev_path = evidence_item.get("storage_path")
        orig_path = evidence_item.get("original_path")
        ev_type = evidence_item.get("evidence_type", "unknown")
        plugin_name = params.get("plugin", "windows.pslist")
        execution_id = str(uuid.uuid4())

        # 1. Evidence Type Validation
        if not self.can_handle(ev_type):
            return {
                "status": "UNSUPPORTED_EVIDENCE_TYPE",
                "execution_id": execution_id,
                "error": f"Evidence type '{ev_type}' is not supported by MemoryAgent.",
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

        # 3. Tool Availability Check
        if not self.adapter.is_available():
            return {
                "status": "TOOL_UNAVAILABLE",
                "execution_id": execution_id,
                "error": "Volatility 3 binary is not installed or available on this system.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        # 4. Plugin Validation
        clean_plugin = plugin_name.strip().lower()
        if clean_plugin not in ALLOWED_PLUGINS:
            return {
                "status": "PLUGIN_UNAVAILABLE",
                "execution_id": execution_id,
                "error": f"Plugin '{plugin_name}' is not in the allowed Volatility plugin allowlist.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        # 5. Execute Volatility Plugin via Adapter -> ToolRegistry
        timeout = params.get("timeout_seconds", 120)
        exec_id_target = params.get("execution_id") or execution_id
        exec_res = self.adapter.execute_plugin(
            evidence_path=ev_path,
            plugin_name=clean_plugin,
            timeout_seconds=timeout,
            execution_id=exec_id_target
        )

        # 6. Save raw output
        raw_output_path = self._save_raw_output(inv_id, execution_id, exec_res.stdout, exec_res.stderr)

        if exec_res.timed_out:
            return {
                "status": "TIMED_OUT",
                "execution_id": execution_id,
                "error": exec_res.error_message or f"Volatility3 execution timed out after {timeout}s.",
                "artifacts": [],
                "findings": [],
                "provenance": {
                    "tool": "Volatility3",
                    "plugin": clean_plugin,
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
                "error": exec_res.error_message or "Volatility3 execution was cancelled.",
                "artifacts": [],
                "findings": [],
                "provenance": {
                    "tool": "Volatility3",
                    "plugin": clean_plugin,
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
                    "tool": "Volatility3",
                    "plugin": clean_plugin,
                    "pid": exec_res.pid,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "return_code": exec_res.return_code,
                    "raw_output_reference": raw_output_path
                }
            }

        # 7. Parse stdout with dedicated parser
        artifacts = []
        findings = []
        parse_errors = []

        if clean_plugin == "windows.pslist":
            p_res = PsListParser.parse(exec_res.stdout)
            parse_errors = p_res.parse_errors
            for entry in p_res.entries:
                art_id = str(uuid.uuid4())
                source_ref = f"pid:{entry.pid}"
                artifacts.append({
                    "id": art_id,
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "Volatility3",
                    "artifact_type": "memory_process",
                    "source_reference": source_ref,
                    "path": entry.image_file_name,
                    "inode": str(entry.pid),
                    "size_bytes": None,
                    "is_deleted": False,
                    "metadata_json": {
                        "plugin": clean_plugin,
                        "pid": entry.pid,
                        "ppid": entry.ppid,
                        "offset": entry.offset,
                        "threads": entry.threads,
                        "handles": entry.handles,
                        "session_id": entry.session_id,
                        "create_time": entry.create_time,
                        "exit_time": entry.exit_time,
                        "raw_line": entry.raw_line
                    },
                    "raw_output_reference": f"{raw_output_path}:pid:{entry.pid}"
                })

                # Finding Rule 1: Suspicious process binary name
                if entry.image_file_name.lower() in SUSPICIOUS_PROCESS_NAMES:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "investigation_id": inv_id,
                        "evidence_id": ev_id,
                        "agent": self.name,
                        "tool": "Volatility3",
                        "finding_type": "suspicious_process",
                        "title": f"Suspicious Process Executed: {entry.image_file_name} (PID {entry.pid})",
                        "description": f"Process '{entry.image_file_name}' identified in volatile memory at offset {entry.offset} with PID {entry.pid} (PPID {entry.ppid}).",
                        "confidence": 0.90,
                        "evidence_reference": source_ref,
                        "verification_status": "UNVERIFIED",
                        "raw_output_reference": entry.raw_line
                    })

        elif clean_plugin == "windows.pstree":
            t_res = PsTreeParser.parse(exec_res.stdout)
            parse_errors = t_res.parse_errors
            for entry in t_res.entries:
                art_id = str(uuid.uuid4())
                source_ref = f"pid:{entry.pid}"
                artifacts.append({
                    "id": art_id,
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "Volatility3",
                    "artifact_type": "memory_process_tree",
                    "source_reference": source_ref,
                    "path": entry.image_file_name,
                    "inode": str(entry.pid),
                    "size_bytes": None,
                    "is_deleted": False,
                    "metadata_json": {
                        "plugin": clean_plugin,
                        "depth": entry.depth,
                        "pid": entry.pid,
                        "ppid": entry.ppid,
                        "offset": entry.offset,
                        "threads": entry.threads,
                        "create_time": entry.create_time,
                        "raw_line": entry.raw_line
                    },
                    "raw_output_reference": f"{raw_output_path}:pid:{entry.pid}"
                })

                if entry.image_file_name.lower() in SUSPICIOUS_PROCESS_NAMES:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "investigation_id": inv_id,
                        "evidence_id": ev_id,
                        "agent": self.name,
                        "tool": "Volatility3",
                        "finding_type": "suspicious_process_tree",
                        "title": f"Suspicious Process in Tree: {entry.image_file_name} (PID {entry.pid})",
                        "description": f"Process '{entry.image_file_name}' at tree depth {entry.depth} under PPID {entry.ppid}.",
                        "confidence": 0.90,
                        "evidence_reference": source_ref,
                        "verification_status": "UNVERIFIED",
                        "raw_output_reference": entry.raw_line
                    })

        elif clean_plugin == "windows.netscan":
            n_res = NetScanParser.parse(exec_res.stdout)
            parse_errors = n_res.parse_errors
            for entry in n_res.entries:
                art_id = str(uuid.uuid4())
                source_ref = f"ip:{entry.foreign_addr}"
                artifacts.append({
                    "id": art_id,
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "Volatility3",
                    "artifact_type": "memory_network_connection",
                    "source_reference": source_ref,
                    "path": f"{entry.local_addr}:{entry.local_port} -> {entry.foreign_addr}:{entry.foreign_port}",
                    "inode": str(entry.pid) if entry.pid else None,
                    "size_bytes": None,
                    "is_deleted": False,
                    "metadata_json": {
                        "plugin": clean_plugin,
                        "proto": entry.proto,
                        "local_addr": entry.local_addr,
                        "local_port": entry.local_port,
                        "foreign_addr": entry.foreign_addr,
                        "foreign_port": entry.foreign_port,
                        "state": entry.state,
                        "pid": entry.pid,
                        "owner": entry.owner,
                        "raw_line": entry.raw_line
                    },
                    "raw_output_reference": f"{raw_output_path}:{entry.foreign_addr}"
                })

                # Finding Rule 2: Established connection to external public IP
                is_private = any(entry.foreign_addr.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)
                if entry.state.upper() == "ESTABLISHED" and not is_private:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "investigation_id": inv_id,
                        "evidence_id": ev_id,
                        "agent": self.name,
                        "tool": "Volatility3",
                        "finding_type": "external_network_connection",
                        "title": f"Active External Socket: {entry.owner} (PID {entry.pid}) -> {entry.foreign_addr}:{entry.foreign_port}",
                        "description": f"Established network connection to external IP {entry.foreign_addr} on port {entry.foreign_port} by owner process '{entry.owner}'.",
                        "confidence": 0.85,
                        "evidence_reference": source_ref,
                        "verification_status": "UNVERIFIED",
                        "raw_output_reference": entry.raw_line
                    })

        return {
            "status": "SUCCESS",
            "execution_id": execution_id,
            "plugin": clean_plugin,
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
                "tool": "Volatility3",
                "plugin": clean_plugin,
                "tool_version": self.adapter.get_tool_version(),
                "execution_time_ms": exec_res.execution_time_ms,
                "parse_errors": parse_errors
            }
        }

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

            # Process Analysis
            if "PROCESS" in entity_type:
                supporting_art_ids.append(art_id)
                pname = str(fields.get("process_name") or fields.get("name") or fields.get("image_name") or "").lower()
                pid = str(fields.get("pid") or fields.get("process_id") or "N/A")
                ppid = str(fields.get("ppid") or fields.get("parent_pid") or "N/A")

                if pname in SUSPICIOUS_PROCESS_NAMES:
                    observations.append({
                        "fact_type": "SUSPICIOUS_PROCESS_EXECUTION",
                        "description": f"Known suspicious process observed in memory: '{pname}' (PID {pid}, PPID {ppid}).",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"process_name": pname, "pid": pid, "ppid": ppid},
                        "confidence": 0.95
                    })

            # Network Socket Analysis from Memory
            elif "SOCKET" in entity_type or "NETWORK" in entity_type:
                supporting_art_ids.append(art_id)
                rem_ip = str(fields.get("remote_ip") or fields.get("foreign_addr") or "")
                rem_port = str(fields.get("remote_port") or fields.get("foreign_port") or "")
                owner_pid = str(fields.get("pid") or "N/A")

                if rem_ip and not any(rem_ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
                    observations.append({
                        "fact_type": "MEMORY_EXTERNAL_SOCKET_OBSERVATION",
                        "description": f"Active memory-resident socket to external IP '{rem_ip}:{rem_port}' (PID {owner_pid}).",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"remote_ip": rem_ip, "remote_port": rem_port, "pid": owner_pid},
                        "confidence": 0.90
                    })

            # Injected code / unbacked memory regions
            elif "INJECTION" in entity_type or "MALFIND" in entity_type:
                supporting_art_ids.append(art_id)
                observations.append({
                    "fact_type": "MEMORY_INJECTION_INDICATOR",
                    "description": f"Injected or unbacked executable memory region observed in process (PID {fields.get('pid', 'N/A')}).",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": fields,
                    "confidence": 0.95
                })

        # Request memory capabilities for memory dump evidence items
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["mem", "dump", "vmem", "dmp"]):
                cap_requests.append({
                    "capability_id": "MEMORY_PROCESS_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"plugin": "windows.pslist"},
                    "rationale": f"Kernel process tree extraction requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })
                cap_requests.append({
                    "capability_id": "MEMORY_NETWORK_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"plugin": "windows.netscan"},
                    "rationale": f"Memory-resident socket extraction requested by {self.name}",
                    "priority": 2,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="MEMORY_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=supporting_art_ids,
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Memory forensics analyzed {len(supporting_art_ids)} memory artifacts; identified {len(observations)} observations.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )


MemoryForensicsAgent = MemoryAgent

