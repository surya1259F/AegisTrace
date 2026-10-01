from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile
from agents.log.parsers.evtx_parser import EvtxParser


class WindowsForensicsAgent(Agent):
    """
    Specialist Windows Forensics Agent (Phase 2 / Step 16).
    Analyzes Windows-specific forensic artifacts:
    - EVTX Security, System, and Application event logs (Logons, Services, Defender)
    - Registry persistence, USB, and configuration hives
    - Execution artifacts (Prefetch, Amcache, Shimcache)
    - User activity artifacts (SRUM, LNK files, Jump Lists)
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="WindowsForensicsAgent",
            description="Analyzes Windows artifacts including EVTX event logs, Registry, Prefetch, Amcache, Shimcache, SRUM, LNK, Jump Lists, and Defender.",
            capabilities=[
                "evtx_analysis",
                "registry_analysis",
                "prefetch_analysis",
                "amcache_analysis",
                "shimcache_analysis",
                "srum_analysis",
                "lnk_analysis",
                "jumplist_analysis",
                "defender_alert_analysis",
                "security_event_audit"
            ],
            agent_id="agent-windows-forensics",
            version="1.0.0",
            supported_domains=["WINDOWS", "LOGS", "REGISTRY", "SYSTEM"],
            supported_artifact_types=[
                "EVENT_LOG", "EVTX", "REGISTRY", "PREFETCH", "AMCACHE",
                "SHIMCACHE", "SRUM", "LNK", "JUMPLIST", "DEFENDER_ALERT"
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
            "log", "file", "event_log", "evtx", "windows_event_log",
            "registry_hive", "prefetch", "system_log", "windows_artifact",
            "lnk", "jumplist", "amcache", "shimcache", "srum"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "windows_evidence")
        ev_type = str(evidence_item.get("evidence_type", "")).lower()

        if "registry" in ev_type:
            return [{
                "step_id": "win-reg-01",
                "agent": self.name,
                "capability_id": "REGISTRY_ANALYSIS",
                "tool": "REGISTRY_ANALYSIS",
                "action": "parse_registry_persistence",
                "priority": 1,
                "description": f"Extract Run keys and configuration from {ev_name}."
            }]
        elif "prefetch" in ev_type:
            return [{
                "step_id": "win-pf-01",
                "agent": self.name,
                "capability_id": "PREFETCH_EXECUTION_ANALYSIS",
                "tool": "PREFETCH_EXECUTION_ANALYSIS",
                "action": "parse_prefetch_execution",
                "priority": 1,
                "description": f"Extract execution timestamps and run counts from {ev_name}."
            }]
        return [{
            "step_id": "win-evtx-01",
            "agent": self.name,
            "capability_id": "WINDOWS_EVTX_ANALYSIS",
            "tool": "python-evtx",
            "action": "parse_security_events",
            "priority": 1,
            "description": f"Audit Windows Event log records in {ev_name}."
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

            # 1. EVTX Event Logs (Authentication, Privilege, Services, Defender)
            if any(k in entity_type for k in ["EVENT", "LOG", "AUTH", "DEFENDER", "SERVICE"]):
                supporting_art_ids.append(art_id)
                event_id = str(fields.get("event_id") or "")
                username = str(fields.get("username") or fields.get("user") or "")

                # Defender Alert (1116, 1117)
                if event_id in ["1116", "1117"] or "DEFENDER" in entity_type:
                    threat_name = fields.get("threat_name") or fields.get("threat") or "UnknownThreat"
                    observations.append({
                        "fact_type": "DEFENDER_MALWARE_DETECTION",
                        "description": f"Windows Defender alert (EventID {event_id}): Detected threat '{threat_name}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"event_id": event_id, "threat_name": threat_name, "raw_fields": fields},
                        "confidence": 0.95
                    })

                # Service Installation (7045)
                elif event_id == "7045":
                    service_name = fields.get("service_name") or "UnknownService"
                    image_path = fields.get("image_path") or fields.get("path") or ""
                    observations.append({
                        "fact_type": "NEW_SERVICE_INSTALLED",
                        "description": f"New Windows service installed (EventID 7045): '{service_name}' ({image_path}).",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"service_name": service_name, "image_path": image_path},
                        "confidence": 0.90
                    })

                # Privileged / Admin Logon (4672, SYSTEM/Admin)
                elif event_id == "4672" or (username.upper() in ["SYSTEM", "ADMINISTRATOR", "ROOT"]):
                    observations.append({
                        "fact_type": "PRIVILEGED_LOGON_OBSERVED",
                        "description": f"Privileged administrative account logon observed for user '{username or 'SYSTEM'}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"username": username, "event_id": event_id},
                        "confidence": 0.90
                    })

            # 2. Registry Persistence
            elif "REGISTRY" in entity_type:
                supporting_art_ids.append(art_id)
                key_path = str(fields.get("key_path") or fields.get("path") or "")
                value_data = str(fields.get("value_data") or fields.get("data") or "")
                if "RUN" in key_path.upper() or "SERVICES" in key_path.upper():
                    observations.append({
                        "fact_type": "REGISTRY_PERSISTENCE_KEY",
                        "description": f"Registry persistence configuration key observed: '{key_path}' -> '{value_data}'.",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"key_path": key_path, "value_data": value_data},
                        "confidence": 0.90
                    })

            # 3. Prefetch / Execution Tracking
            elif any(k in entity_type for k in ["PREFETCH", "SHIMCACHE", "AMCACHE"]):
                supporting_art_ids.append(art_id)
                app_name = str(fields.get("executable") or fields.get("app_name") or fields.get("path") or "")
                run_count = fields.get("run_count", 1)
                observations.append({
                    "fact_type": "APPLICATION_EXECUTION_EVIDENCE",
                    "description": f"Execution artifact ({entity_type}) observed for '{app_name}' (run count {run_count}).",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"application": app_name, "run_count": run_count, "entity_type": entity_type},
                    "confidence": 0.90
                })

            # 4. SRUM / LNK / Jump Lists
            elif any(k in entity_type for k in ["SRUM", "LNK", "JUMPLIST"]):
                supporting_art_ids.append(art_id)
                target_path = str(fields.get("target_path") or fields.get("path") or "")
                observations.append({
                    "fact_type": "USER_ACTIVITY_ARTIFACT",
                    "description": f"User interaction artifact ({entity_type}) pointing to target '{target_path}'.",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"target_path": target_path, "entity_type": entity_type},
                    "confidence": 0.85
                })

        # Generate capability requests for Windows evidence items
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["evtx", "log", "windows"]):
                cap_requests.append({
                    "capability_id": "WINDOWS_EVTX_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"max_records": 5000},
                    "rationale": f"Windows event log security audit requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="WINDOWS_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Windows forensics analyzed {len(supporting_art_ids)} Windows artifacts; identified {len(observations)} observations.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Delegates to EVTX parser for .evtx files or returns structured plan/artifacts.
        """
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

        # If it's an evtx file, run parser safely
        if ev_path.endswith(".evtx") or ev_path.endswith(".xml") or "evtx" in ev_type.lower():
            try:
                parse_res = EvtxParser.parse_file(ev_path, max_records=params.get("max_records", 5000))
                artifacts = []
                for ev in parse_res.events:
                    artifacts.append({
                        "event_id": ev.event_id,
                        "time_created": ev.time_created,
                        "channel": ev.channel,
                        "computer": ev.computer,
                        "event_data": ev.event_data
                    })
                return {
                    "status": "SUCCESS",
                    "execution_id": execution_id,
                    "artifacts_count": len(artifacts),
                    "findings_count": 0,
                    "artifacts": artifacts,
                    "findings": [],
                    "provenance": {
                        "agent": self.name,
                        "evidence_id": ev_id,
                        "tool": "python-evtx",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            except Exception as e:
                return {
                    "status": "FAILED",
                    "execution_id": execution_id,
                    "error": str(e),
                    "artifacts": [],
                    "findings": [],
                    "provenance": {"agent": self.name}
                }

        return {
            "status": "NOT_IMPLEMENTED",
            "execution_id": execution_id,
            "message": f"Specialized parser for Windows artifact '{ev_path}' is not implemented. Supported types: .evtx, .xml.",
            "artifacts_count": 0,
            "findings_count": 0,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "timestamp": datetime.now(timezone.utc).isoformat()}
        }
