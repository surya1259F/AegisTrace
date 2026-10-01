from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile

SUSPICIOUS_SHELL_PATTERNS = [
    "curl", "wget", "| bash", "| sh", "chmod +x", "base64 -d",
    "/dev/tcp/", "nc -e", "ncat", "useradd", "visudo", "iptables -F"
]


class LinuxAgent(Agent):
    """
    Specialist Linux Forensics Agent (Phase 2 / Step 16).
    Analyzes Linux authentication logs, systemd/journal logs, shell history,
    scheduled cron jobs, and persistence mechanisms.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="LinuxForensicsAgent",
            description="Analyzes Linux forensic artifacts including auth logs, journal/systemd, shell history, cron, and persistence.",
            capabilities=[
                "auth_log_analysis",
                "journal_analysis",
                "shell_history_audit",
                "cron_audit",
                "linux_persistence_check"
            ],
            agent_id="agent-linux-forensics",
            version="1.0.0",
            supported_domains=["LINUX", "LOGS", "AUTH", "SYSTEMD", "SHELL", "CRON"],
            supported_artifact_types=[
                "AUTH_LOG", "SYSLOG", "JOURNALD", "BASH_HISTORY",
                "SHELL_HISTORY", "CRON_JOB", "SYSTEMD_SERVICE", "LINUX_PERSISTENCE"
            ],
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
            "log", "file", "linux_log", "auth_log", "syslog",
            "shell_history", "cron", "system_log", "text"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "linux_evidence")
        ev_type = str(evidence_item.get("evidence_type", "")).lower()

        if "history" in ev_type:
            return [{
                "step_id": "linux-shell-01",
                "agent": self.name,
                "capability_id": "SHELL_HISTORY_AUDIT",
                "tool": "SHELL_HISTORY_AUDIT",
                "action": "audit_shell_commands",
                "priority": 1,
                "description": f"Audit command history in {ev_name} for suspicious execution patterns."
            }]
        elif "cron" in ev_type:
            return [{
                "step_id": "linux-cron-01",
                "agent": self.name,
                "capability_id": "CRON_AUDIT",
                "tool": "CRON_AUDIT",
                "action": "audit_cron_schedules",
                "priority": 1,
                "description": f"Audit cron schedules and persistence in {ev_name}."
            }]
        return [{
            "step_id": "linux-log-01",
            "agent": self.name,
            "capability_id": "LINUX_LOG_ANALYSIS",
            "tool": "LINUX_LOG_ANALYSIS",
            "action": "parse_auth_and_syslog",
            "priority": 1,
            "description": f"Parse Linux auth/syslog records in {ev_name}."
        }]

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

            # 1. Shell History
            if any(k in entity_type for k in ["SHELL", "BASH", "COMMAND"]):
                supporting_art_ids.append(art_id)
                command = str(fields.get("command") or fields.get("line") or "")
                line_no = fields.get("line_number") or 1
                matched_patterns = [p for p in SUSPICIOUS_SHELL_PATTERNS if p in command]
                if matched_patterns:
                    observations.append({
                        "fact_type": "SUSPICIOUS_SHELL_COMMAND",
                        "description": f"Suspicious shell command pattern observed: '{command}' (matched {matched_patterns}).",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"command": command, "matched_patterns": matched_patterns, "line_number": line_no},
                        "confidence": 0.90
                    })

            # 2. Auth / Sudo / Login Logs
            elif any(k in entity_type for k in ["AUTH", "LOG", "SYSLOG", "JOURNAL"]):
                supporting_art_ids.append(art_id)
                message = str(fields.get("message") or fields.get("log_message") or "")
                user = str(fields.get("username") or fields.get("user") or "")

                if "Failed password" in message or "authentication failure" in message.lower():
                    observations.append({
                        "fact_type": "FAILED_AUTHENTICATION_ATTEMPT",
                        "description": f"Failed authentication attempt observed for user '{user or 'unknown'}': {message[:120]}.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"message": message, "user": user},
                        "confidence": 0.95
                    })
                elif "sudo:" in message or "COMMAND=" in message:
                    observations.append({
                        "fact_type": "SUDO_PRIVILEGE_EXECUTION",
                        "description": f"Sudo privilege elevation observed: {message[:120]}.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"message": message, "user": user},
                        "confidence": 0.90
                    })

            # 3. Cron & Persistence
            elif any(k in entity_type for k in ["CRON", "PERSISTENCE", "SYSTEMD"]):
                supporting_art_ids.append(art_id)
                schedule = str(fields.get("schedule") or fields.get("cron_expression") or "")
                command = str(fields.get("command") or fields.get("exec_start") or "")
                observations.append({
                    "fact_type": "LINUX_PERSISTENCE_MECHANISM",
                    "description": f"Linux persistence mechanism ({entity_type}) observed: schedule '{schedule}', command '{command}'.",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"schedule": schedule, "command": command, "entity_type": entity_type},
                    "confidence": 0.90
                })

        # Request capabilities for Linux evidence
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["log", "linux", "auth", "cron", "shell"]):
                cap_requests.append({
                    "capability_id": "LINUX_LOG_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"parse_auth": True, "parse_cron": True},
                    "rationale": f"Linux log and persistence analysis requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="LINUX_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Linux forensics analyzed {len(supporting_art_ids)} Linux artifacts; identified {len(observations)} observations.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        params = parameters or {}
        inv_id = evidence_item.get("investigation_id") or evidence_item.get("case_id") or "UNKNOWN"
        ev_id = evidence_item.get("id") or "UNKNOWN"
        ev_path = evidence_item.get("storage_path")
        ev_type = evidence_item.get("evidence_type", "unknown")
        execution_id = str(uuid.uuid4())

        if not self.can_handle(ev_type):
            return {
                "status": "UNSUPPORTED_EVIDENCE_TYPE",
                "execution_id": execution_id,
                "error": f"Evidence type '{ev_type}' is not supported by {self.name}.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        if not ev_path:
            return {
                "status": "UNVAULTED_EVIDENCE_REJECTED",
                "execution_id": execution_id,
                "error": "Forensic analysis blocked: Evidence item does not have a valid vault storage_path.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        if not os.path.exists(ev_path):
            return {
                "status": "INVALID_EVIDENCE_PATH",
                "execution_id": execution_id,
                "error": f"Vault path '{ev_path}' does not exist on disk.",
                "artifacts": [],
                "findings": [],
                "provenance": {}
            }

        return {
            "status": "NOT_IMPLEMENTED",
            "execution_id": execution_id,
            "message": "Direct Linux evidence parsing is not implemented; use structured artifact analysis pipeline or SleuthKit tool adapter.",
            "artifacts_count": 0,
            "findings_count": 0,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "evidence_id": ev_id, "timestamp": datetime.now(timezone.utc).isoformat()}
        }


LinuxForensicsAgent = LinuxAgent
