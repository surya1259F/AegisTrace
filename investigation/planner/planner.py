from typing import List, Dict, Any, Optional
from forensic_tools.registry import PlatformAwareToolRegistry, tool_registry as global_tool_registry


class InvestigationPlanner:
    """
    Capability-Driven Deterministic Investigation Planner.
    Analyzes real persisted evidence metadata and registered/available forensic tools/agents
    to construct an actionable, ordered, and explainable investigation plan.
    Strictly verifies that tools exist, are available on the host, and possess the required
    capability before emitting any executable task.
    """

    def __init__(self, registry: Optional[PlatformAwareToolRegistry] = None):
        self.registry = registry or global_tool_registry

    def plan(self, investigation_id: str, evidence_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        tasks: List[Dict[str, Any]] = []
        summary_points: List[str] = []

        for item in evidence_items:
            ev_id = str(item.get("id") or "")
            ev_name = str(item.get("name") or item.get("file_name") or "evidence")
            ev_type = str(item.get("evidence_type") or "").strip().lower()
            src_kind = str(item.get("source_kind") or "").strip().lower()

            # 1. Disk Image Evidence -> SleuthKit (fls) -> filesystem_structure_extraction
            if ev_type in ["disk_image", "filesystem_image"] or src_kind == "disk_image":
                tsk = self.registry.get_tool("sleuthkit")
                req_cap = "filesystem_structure_extraction"
                if tsk and tsk.is_available and tsk.has_capability(req_cap):
                    tasks.append({
                        "step_id": f"task-disk-{ev_id[:8]}",
                        "agent": "DiskAgent",
                        "tool": "SleuthKit",
                        "tool_available": True,
                        "evidence_id": ev_id,
                        "evidence_name": ev_name,
                        "action": req_cap,
                        "reason": "Filesystem directory tree and deleted entry extraction via The Sleuth Kit (fls).",
                        "priority": 1,
                        "dependencies": [],
                        "status": "PLANNED",
                        "parameters": {"recursive": True, "include_deleted": True},
                        "estimated_resource_cost": {"cpu": "medium", "ram": "medium"},
                        "cpu_weight": 1.0,
                        "memory_mb": 1024,
                        "is_exclusive": True,
                        "parallel_safe": False,
                        "execution_id": None,
                        "artifacts_count": 0,
                        "findings_count": 0,
                        "error_message": None,
                    })
                    summary_points.append(f"Disk filesystem analysis planned for '{ev_name}' via SleuthKit.")
                else:
                    status_reason = "not installed" if (not tsk or not tsk.is_available) else f"missing capability '{req_cap}'"
                    summary_points.append(
                        f"Evidence '{ev_name}' ({ev_type}): SleuthKit tool is {status_reason}. Cannot plan filesystem analysis. Requires specialist manual triage."
                    )

            # 2. Memory Dump Evidence -> Volatility 3 -> process_enumeration, network_socket_extraction
            elif ev_type in ["memory_dump", "raw_memory", "vmem", "dmp"] or src_kind == "memory_dump":
                vol = self.registry.get_tool("volatility3")
                if vol and vol.is_available:
                    created_mem_tasks = 0
                    pslist_step_id = f"task-mem-pslist-{ev_id[:8]}"

                    if vol.has_capability("process_enumeration"):
                        tasks.append({
                            "step_id": pslist_step_id,
                            "agent": "MemoryAgent",
                            "tool": "Volatility3",
                            "tool_available": True,
                            "evidence_id": ev_id,
                            "evidence_name": ev_name,
                            "action": "process_enumeration",
                            "reason": "Physical memory active and terminated process listing via Volatility 3 pslist.",
                            "priority": 1,
                            "dependencies": [],
                            "status": "PLANNED",
                            "parameters": {"plugin": "windows.pslist"},
                            "estimated_resource_cost": {"cpu": "high", "ram": "high"},
                            "cpu_weight": 2.0,
                            "memory_mb": 2048,
                            "is_exclusive": True,
                            "parallel_safe": False,
                            "execution_id": None,
                            "artifacts_count": 0,
                            "findings_count": 0,
                            "error_message": None,
                        })
                        created_mem_tasks += 1

                    if vol.has_capability("network_socket_extraction"):
                        netscan_step_id = f"task-mem-netscan-{ev_id[:8]}"
                        tasks.append({
                            "step_id": netscan_step_id,
                            "agent": "MemoryAgent",
                            "tool": "Volatility3",
                            "tool_available": True,
                            "evidence_id": ev_id,
                            "evidence_name": ev_name,
                            "action": "network_socket_extraction",
                            "reason": "Active network socket and listening connection extraction via Volatility 3 netscan.",
                            "priority": 2,
                            "dependencies": [pslist_step_id] if created_mem_tasks > 0 else [],
                            "status": "PLANNED",
                            "parameters": {"plugin": "windows.netscan"},
                            "estimated_resource_cost": {"cpu": "medium", "ram": "medium"},
                            "cpu_weight": 1.0,
                            "memory_mb": 1024,
                            "is_exclusive": True,
                            "parallel_safe": False,
                            "execution_id": None,
                            "artifacts_count": 0,
                            "findings_count": 0,
                            "error_message": None,
                        })
                        created_mem_tasks += 1

                    if created_mem_tasks > 0:
                        summary_points.append(f"Memory process and network socket introspection planned for '{ev_name}' via Volatility 3.")
                    else:
                        summary_points.append(
                            f"Evidence '{ev_name}' ({ev_type}): Volatility 3 lacks required memory analysis capabilities. Requires specialist manual triage."
                        )
                else:
                    summary_points.append(
                        f"Evidence '{ev_name}' ({ev_type}): Volatility 3 tool is not available on host. Cannot plan memory introspection. Requires specialist manual triage."
                    )

            # 3. Windows Event Log Evidence -> python-evtx -> security_log_parsing
            elif ev_type in ["log", "event_log", "evtx", "system_log"] or src_kind == "event_log":
                evtx = self.registry.get_tool("python-evtx") or self.registry.get_tool("python_evtx")
                req_cap = "security_log_parsing"
                if evtx and evtx.is_available and evtx.has_capability(req_cap):
                    tasks.append({
                        "step_id": f"task-log-evtx-{ev_id[:8]}",
                        "agent": "LogAgent",
                        "tool": "python-evtx",
                        "tool_available": True,
                        "evidence_id": ev_id,
                        "evidence_name": ev_name,
                        "action": req_cap,
                        "reason": "Windows Event Log security authentication, process creation, and service installation record parsing via python-evtx.",
                        "priority": 1,
                        "dependencies": [],
                        "status": "PLANNED",
                        "parameters": {"max_records": 5000},
                        "estimated_resource_cost": {"cpu": "medium", "ram": "medium"},
                        "cpu_weight": 1.0,
                        "memory_mb": 512,
                        "is_exclusive": False,
                        "parallel_safe": True,
                        "execution_id": None,
                        "artifacts_count": 0,
                        "findings_count": 0,
                        "error_message": None,
                    })
                    summary_points.append(f"Security event log parsing planned for '{ev_name}' via python-evtx.")
                else:
                    status_reason = "not installed" if (not evtx or not evtx.is_available) else f"missing capability '{req_cap}'"
                    summary_points.append(
                        f"Evidence '{ev_name}' ({ev_type}): python-evtx parser is {status_reason}. Cannot plan event log analysis. Requires specialist manual triage."
                    )

            # 4. Executable / Malware Evidence -> YARA -> signature_scan
            elif ev_type in ["executable", "suspicious_file", "malware", "pe_executable", "elf_executable"] or src_kind == "malware_sample":
                yara = self.registry.get_tool("yara")
                req_cap = "signature_scan"
                if yara and yara.is_available and yara.has_capability(req_cap):
                    tasks.append({
                        "step_id": f"task-mal-yara-{ev_id[:8]}",
                        "agent": "MalwareAgent",
                        "tool": "YARA",
                        "tool_available": True,
                        "evidence_id": ev_id,
                        "evidence_name": ev_name,
                        "action": req_cap,
                        "reason": "Threat signature scanning and malware pattern matching via YARA.",
                        "priority": 1,
                        "dependencies": [],
                        "status": "PLANNED",
                        "parameters": {"rule_set": "adfir_webshell_indicators"},
                        "estimated_resource_cost": {"cpu": "high", "ram": "low"},
                        "cpu_weight": 1.0,
                        "memory_mb": 512,
                        "is_exclusive": False,
                        "parallel_safe": True,
                        "execution_id": None,
                        "artifacts_count": 0,
                        "findings_count": 0,
                        "error_message": None,
                    })
                    summary_points.append(f"Malware signature pattern matching planned for '{ev_name}' via YARA.")
                else:
                    status_reason = "not installed" if (not yara or not yara.is_available) else f"missing capability '{req_cap}'"
                    summary_points.append(
                        f"Evidence '{ev_name}' ({ev_type}): YARA tool is {status_reason}. Cannot plan signature scanning. Requires specialist manual triage."
                    )

            # 5. File / Document / Archive / Text / Generic Binary Metadata Evidence -> ExifTool -> metadata_extraction
            elif ev_type in ["file", "document", "archive", "text", "generic_binary", "unknown", "image", "browser_artifact", "sqlite_database"] or src_kind in ["file", "archive", "browser_db", "unknown"]:
                exif = self.registry.get_tool("exiftool")
                req_cap = "metadata_extraction"
                if exif and exif.is_available and exif.has_capability(req_cap):
                    tasks.append({
                        "step_id": f"task-meta-exif-{ev_id[:8]}",
                        "agent": "DiskAgent",
                        "tool": "ExifTool",
                        "tool_available": True,
                        "evidence_id": ev_id,
                        "evidence_name": ev_name,
                        "action": req_cap,
                        "reason": "File metadata and EXIF record extraction via ExifTool.",
                        "priority": 2,
                        "dependencies": [],
                        "status": "PLANNED",
                        "parameters": {},
                        "estimated_resource_cost": {"cpu": "low", "ram": "low"},
                        "cpu_weight": 0.5,
                        "memory_mb": 256,
                        "is_exclusive": False,
                        "parallel_safe": True,
                        "execution_id": None,
                        "artifacts_count": 0,
                        "findings_count": 0,
                        "error_message": None,
                    })
                    summary_points.append(f"Metadata extraction planned for '{ev_name}' via ExifTool.")
                else:
                    status_reason = "not installed" if (not exif or not exif.is_available) else f"missing capability '{req_cap}'"
                    summary_points.append(
                        f"Evidence '{ev_name}' ({ev_type}): ExifTool is {status_reason}. Cannot plan metadata extraction. Requires specialist manual triage."
                    )

            # 6. Unknown / Unsupported Evidence Types
            else:
                summary_points.append(
                    f"Evidence '{ev_name}' classified as '{ev_type or 'unclassified'}': "
                    f"No registered forensic tool capability available. Requires specialist manual triage."
                )

        for t in tasks:
            t["task_id"] = t.get("step_id")
            t["agent_name"] = t.get("agent")
            t["tool_name"] = t.get("tool")

        # Deterministic sort order by priority, evidence_id, step_id
        tasks.sort(key=lambda t: (t["priority"], t["evidence_id"], t["step_id"]))
        execution_order = [f"{t['agent']}::{t['tool']}" for t in tasks]

        return {
            "investigation_id": investigation_id,
            "case_id": investigation_id,
            "strategy_summary": " | ".join(summary_points) if summary_points else "No evidence registered for investigation planning.",
            "total_tasks": len(tasks),
            "tasks": tasks,
            "steps": tasks,
            "execution_order": execution_order,
            "status": "PLANNED",
            "version": 1,
        }

    def plan_investigation(self, case_id: str, evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Backward-compatibility alias for v1 router."""
        res = self.plan(investigation_id=case_id, evidence_items=evidence_list)
        res["case_id"] = case_id
        res["identified_evidence"] = evidence_list
        res["planned_tasks"] = res["tasks"]
        return res
