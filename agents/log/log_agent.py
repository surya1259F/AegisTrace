import uuid
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile
from agents.log.parsers.evtx_parser import EvtxParser

class LogAgent(Agent):
    """
    Specialist Log Forensics Agent (Phase 2 / Step 16).
    Parses Windows Event Logs (.evtx) and XML event exports using python-evtx.
    Extracts structured event artifacts (logons, process creations, service installations, account changes)
    and generates evidence-backed candidate findings.
    """

    def __init__(self):
        super().__init__(
            name="LogForensicsAgent",
            description="Parses Windows Event Logs (.evtx) and security event exports for authentication, process creation, service installation, and account changes.",
            capabilities=["evtx_parsing", "security_event_audit", "logon_analysis", "process_creation_audit", "account_audit"],
            agent_id="agent-windows-forensics",
            version="1.0.0",
            supported_domains=["WINDOWS", "LOGS", "SYSTEM"],
            supported_artifact_types=["EVENT_LOG", "EVTX", "DEFENDER_ALERT"],
            safety_profile=AgentSafetyProfile(
                allow_direct_execution=False,
                allow_shell_commands=False,
                allow_evidence_modification=False,
                read_only_access=True,
                requires_capability_gating=True
            )
        )

    def can_handle(self, evidence_type: str) -> bool:
        if not evidence_type or not isinstance(evidence_type, str):
            return False
        et = evidence_type.lower()
        return et in [
            "log", "file", "event_log", "evtx", "system_log", "unknown", "text", "document"
            "log", "file", "event_log", "evtx", "windows_event_log", "system_log", "unknown", "text", "document"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "event_log")
        return [
            {
                "step_id": "log-evtx-01",
                "agent": self.name,
                "tool": "python-evtx",
                "action": "parse_security_events",
                "priority": 1,
                "description": f"Parse Windows Event records and extract security events from {ev_name}."
            }
        ]

    def _save_raw_output(
        self,
        investigation_id: str,
        execution_id: str,
        stdout_summary: str,
        stderr_summary: str
    ) -> str:
        base_dir = Path(__file__).resolve().parent.parent.parent / "data" / "investigations" / investigation_id / "tool-output"
        from backend.app.core.config import settings
        base_dir = settings.DATA_DIR / "investigations" / investigation_id / "tool-output"
        base_dir.mkdir(parents=True, exist_ok=True)


        stdout_file = base_dir / f"{execution_id}.stdout"
        stderr_file = base_dir / f"{execution_id}.stderr"

        with open(stdout_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(stdout_summary)
        with open(stderr_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(stderr_summary)

        return str(stdout_file)

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        params = parameters or {}
        inv_id = evidence_item.get("investigation_id") or evidence_item.get("case_id") or "UNKNOWN"
        ev_id = evidence_item.get("id") or "UNKNOWN"
        ev_name = evidence_item.get("name", "unknown_log")
        ev_path = evidence_item.get("storage_path")
        orig_path = evidence_item.get("original_path")
        ev_type = evidence_item.get("evidence_type", "unknown")
        max_records = params.get("max_records", 5000)
        execution_id = str(uuid.uuid4())

        # 1. Evidence Type Validation
        if not self.can_handle(ev_type):
            return {
                "status": "UNSUPPORTED_EVIDENCE_TYPE",
                "execution_id": execution_id,
                "error": f"Evidence type '{ev_type}' is not supported by LogAgent.",
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

        # 3. Parse EVTX / XML File
        import time
        start_t = time.time()
        parse_result = EvtxParser.parse_file(ev_path, max_records=max_records)
        exec_time_ms = round((time.time() - start_t) * 1000, 2)

        # 4. Save file-backed raw output summary
        stdout_summary = f"Parsed {parse_result.parsed_events_count} event(s) from {parse_result.total_records_scanned} scanned record(s).\n"
        for ev in parse_result.events[:30]:
            stdout_summary += f"RecordID={ev.record_id} EventID={ev.event_id} Time={ev.time_created} Computer={ev.computer} Category={ev.event_category}\n"
        stderr_summary = "\n".join(parse_result.parse_errors)

        raw_output_path = self._save_raw_output(inv_id, execution_id, stdout_summary, stderr_summary)

        artifacts = []
        findings = []

        # 5. Extract structured Artifacts and candidate Findings
        for idx, event in enumerate(parse_result.events, start=1):
            art_id = str(uuid.uuid4())
            record_num = event.record_id if event.record_id is not None else idx
            source_ref = f"record:{record_num}:eid:{event.event_id}"

            # Determine Artifact Type
            if event.event_id in [4624, 4625]:
                art_type = "windows_logon_event"
            elif event.event_id == 4688:
                art_type = "windows_process_creation"
            elif event.event_id in [4697, 7045]:
                art_type = "windows_service_installation"
            elif event.event_id == 4672:
                art_type = "windows_privilege_assignment"
            elif event.event_id == 4720:
                art_type = "windows_account_change"
            elif event.event_id in [4728, 4732]:
                art_type = "windows_group_membership_change"
            else:
                art_type = "windows_event"

            # Create Artifact
            art = {
                "id": art_id,
                "investigation_id": inv_id,
                "evidence_id": ev_id,
                "agent": self.name,
                "tool": "python-evtx",
                "artifact_type": art_type,
                "source_reference": source_ref,
                "path": event.process_name or event.service_file_name or ev_path,
                "inode": None,
                "size_bytes": None,
                "is_deleted": False,
                "metadata_json": {
                    "event_id": event.event_id,
                    "record_id": event.record_id,
                    "provider_name": event.provider_name,
                    "channel": event.channel,
                    "computer": event.computer,
                    "time_created": event.time_created,
                    "user": event.user,
                    "domain": event.domain,
                    "target_user": event.target_user,
                    "target_domain": event.target_domain,
                    "group_name": event.group_name,
                    "member_name": event.member_name,
                    "logon_type": event.logon_type,
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "process_name": event.process_name,
                    "process_id": event.process_id,
                    "parent_process_name": event.parent_process_name,
                    "command_line": event.command_line,
                    "service_name": event.service_name,
                    "service_file_name": event.service_file_name,
                    "event_category": event.event_category,
                    "raw_data": event.event_data
                },
                "raw_output_reference": f"{raw_output_path}:{source_ref}"
            }
            artifacts.append(art)

            # Generate Evidence-Backed Candidate Findings
            # Rule: Factual observations only. Never claim "Confirmed Compromise".
            if event.event_id == 4625:
                # Failed Logon
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "python-evtx",
                    "finding_type": "windows_logon_failure",
                    "title": f"Failed Logon Attempt (Event 4625) for {event.user or 'Unknown User'} on {event.computer or 'Host'}",
                    "description": f"Windows Event 4625 recorded logon failure for account '{event.user or 'N/A'}' (Domain: '{event.domain or 'N/A'}') from source IP '{event.source_ip or 'Local'}'.",
                    "confidence": 0.80,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": f"{raw_output_path}:{source_ref}"
                })
            elif event.event_id == 4672:
                # Special Privileges Assigned
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "python-evtx",
                    "finding_type": "windows_privilege_escalation_marker",
                    "title": f"Special Privileges Assigned (Event 4672) to {event.user or 'Account'} on {event.computer or 'Host'}",
                    "description": f"Windows Event 4672: Special administrator/system privileges assigned to logon session for user '{event.user or 'N/A'}'.",
                    "confidence": 0.75,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": f"{raw_output_path}:{source_ref}"
                })
            elif event.event_id in [4697, 7045]:
                # Service Installation
                svc_title = event.service_name or "Unknown Service"
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "python-evtx",
                    "finding_type": "windows_service_installation",
                    "title": f"New Service Installed (Event {event.event_id}): {svc_title} on {event.computer or 'Host'}",
                    "description": f"Windows Event {event.event_id}: Service '{svc_title}' installed with binary image path '{event.service_file_name or 'N/A'}'.",
                    "confidence": 0.85,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": f"{raw_output_path}:{source_ref}"
                })
            elif event.event_id == 4720:
                # User Account Created
                tgt = event.target_user or "Unknown Account"
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "python-evtx",
                    "finding_type": "windows_account_creation",
                    "title": f"New User Account Created (Event 4720): {tgt} on {event.computer or 'Host'}",
                    "description": f"Windows Event 4720: User account '{tgt}' created by subject user '{event.user or 'System'}'.",
                    "confidence": 0.85,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": f"{raw_output_path}:{source_ref}"
                })
            elif event.event_id in [4728, 4732]:
                # Member Added to Security Group
                grp = event.group_name or "Security Group"
                mbr = event.member_name or "Member"
                findings.append({
                    "id": str(uuid.uuid4()),
                    "investigation_id": inv_id,
                    "evidence_id": ev_id,
                    "agent": self.name,
                    "tool": "python-evtx",
                    "finding_type": "windows_group_membership_change",
                    "title": f"Member Added to Security Group (Event {event.event_id}): {mbr} to {grp} on {event.computer or 'Host'}",
                    "description": f"Windows Event {event.event_id}: Member '{mbr}' added to group '{grp}' by subject user '{event.user or 'System'}'.",
                    "confidence": 0.85,
                    "evidence_reference": source_ref,
                    "verification_status": "UNVERIFIED",
                    "raw_output_reference": f"{raw_output_path}:{source_ref}"
                })
            elif event.event_id == 4688:
                # Process Creation
                proc = (event.process_name or "").lower()
                is_suspicious_proc = any(p in proc for p in [
                    "powershell.exe", "cmd.exe", "whoami.exe", "net.exe", "psexec.exe",
                    "certutil.exe", "vssadmin.exe", "mimikatz.exe", "procdump.exe"
                ])
                if is_suspicious_proc or event.command_line:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "investigation_id": inv_id,
                        "evidence_id": ev_id,
                        "agent": self.name,
                        "tool": "python-evtx",
                        "finding_type": "windows_process_execution",
                        "title": f"Process Execution (Event 4688): {event.process_name or 'Unknown'} on {event.computer or 'Host'}",
                        "description": f"Windows Event 4688: Process '{event.process_name}' executed with command line: '{event.command_line or 'N/A'}' by user '{event.user or 'N/A'}'.",
                        "confidence": 0.80,
                        "evidence_reference": source_ref,
                        "verification_status": "UNVERIFIED",
                        "raw_output_reference": f"{raw_output_path}:{source_ref}"
                    })

        return {
            "status": "SUCCESS",
            "execution_id": execution_id,
            "artifacts_count": len(artifacts),
            "findings_count": len(findings),
            "execution_time_ms": exec_time_ms,
            "tool_version": "python-evtx-0.8.1",
            "raw_output_reference": raw_output_path,
            "artifacts": artifacts,
            "findings": findings,
            "provenance": {
                "investigation_id": inv_id,
                "evidence_id": ev_id,
                "agent": self.name,
                "tool": "python-evtx",
                "tool_version": "python-evtx-0.8.1",
                "records_scanned": parse_result.total_records_scanned,
                "events_parsed": parse_result.parsed_events_count,
                "execution_time_ms": exec_time_ms,
                "parse_errors": parse_result.parse_errors
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

            if any(k in entity_type for k in ["EVENT", "LOG", "EVTX"]):
                supporting_art_ids.append(art_id)
                event_id = str(fields.get("event_id") or "")
                message = str(fields.get("message") or fields.get("description") or "")
                user = str(fields.get("username") or fields.get("user") or "")

                observations.append({
                    "fact_type": "EVENT_LOG_ENTRY_OBSERVED",
                    "description": f"Event log entry observed (EventID: {event_id or 'N/A'}, User: {user or 'N/A'}): {message[:100]}",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"event_id": event_id, "user": user},
                    "confidence": 0.90
                })

        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["log", "evtx"]):
                cap_requests.append({
                    "capability_id": "WINDOWS_EVTX_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"max_records": 5000},
                    "rationale": f"Event log parsing requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="LOG_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Log forensics analyzed {len(supporting_art_ids)} log artifacts; identified {len(observations)} observations.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )


LogForensicsAgent = LogAgent

