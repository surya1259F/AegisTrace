from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile


class BrowserAgent(Agent):
    """
    Specialist Browser Forensics Agent (Phase 2 / Step 16).
    Analyzes web navigation history, downloads, cookies, cache, and session data.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="BrowserForensicsAgent",
            description="Extracts and analyzes web navigation history, downloads, cookies, and session artifacts across Chrome, Edge, and Firefox.",
            capabilities=[
                "history_extraction",
                "download_history",
                "cookie_analysis",
                "cache_analysis",
                "session_analysis",
                "browser_url_audit"
            ],
            agent_id="agent-browser-forensics",
            version="1.0.0",
            supported_domains=["BROWSER", "HISTORY", "DOWNLOADS", "WEB", "NETWORK"],
            supported_artifact_types=[
                "BROWSER_HISTORY", "BROWSER_DOWNLOAD", "BROWSER_COOKIE",
                "BROWSER_CACHE", "BROWSER_SESSION", "URL", "WEB_VISIT"
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
            "browser_db", "browser_artifact", "sqlite_database",
            "file", "disk_image", "directory", "browser_history"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "browser_evidence")
        return [{
            "step_id": "browser-hist-01",
            "agent": self.name,
            "capability_id": "BROWSER_HISTORY_ANALYSIS",
            "tool": "SQLiteParser",
            "action": "extract_browser_history",
            "priority": 1,
            "description": f"Extract web browsing history, bookmarks, and downloads from {ev_name}."
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

            # 1. Browser History / URL Visits
            if any(k in entity_type for k in ["BROWSER", "HISTORY", "URL", "WEB"]):
                supporting_art_ids.append(art_id)
                url = str(fields.get("url") or fields.get("target_url") or "")
                title = str(fields.get("title") or "")
                visit_count = fields.get("visit_count", 1)

                if url:
                    observations.append({
                        "fact_type": "BROWSER_URL_VISIT",
                        "description": f"Web navigation observed: URL '{url}' (title: '{title or 'N/A'}', visit count: {visit_count}).",
                        "supporting_evidence_ids": [ev_id] if ev_id else [],
                        "supporting_artifact_ids": [art_id],
                        "details": {"url": url, "title": title, "visit_count": visit_count},
                        "confidence": 0.95
                    })

            # 2. Browser Downloads
            elif "DOWNLOAD" in entity_type:
                supporting_art_ids.append(art_id)
                target_path = str(fields.get("target_path") or fields.get("path") or "")
                source_url = str(fields.get("source_url") or fields.get("url") or "")
                bytes_received = fields.get("bytes_received") or fields.get("file_size") or 0

                observations.append({
                    "fact_type": "BROWSER_DOWNLOAD_EVENT",
                    "description": f"Browser download observed: '{target_path}' from source '{source_url}' ({bytes_received} bytes).",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"target_path": target_path, "source_url": source_url, "bytes_received": bytes_received},
                    "confidence": 0.95
                })

            # 3. Cookies / Sessions
            elif any(k in entity_type for k in ["COOKIE", "SESSION"]):
                supporting_art_ids.append(art_id)
                domain = str(fields.get("domain") or fields.get("host") or "")
                cookie_name = str(fields.get("name") or "")

                observations.append({
                    "fact_type": "BROWSER_SESSION_ARTIFACT",
                    "description": f"Browser session/cookie artifact observed for domain '{domain}' (name: '{cookie_name}').",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"domain": domain, "cookie_name": cookie_name},
                    "confidence": 0.90
                })

        # Generate capability requests for browser evidence items
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["browser", "history", "sqlite"]):
                cap_requests.append({
                    "capability_id": "BROWSER_HISTORY_ANALYSIS",
                    "evidence_id": ev_id,
                    "parameters": {"extract_cookies": True, "extract_downloads": True},
                    "rationale": f"Browser artifact parsing requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="BROWSER_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Browser forensics analyzed {len(supporting_art_ids)} browser artifacts; identified {len(observations)} observations.",
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
            "message": "Direct binary artifact parsing for browser evidence is not implemented; use structured artifact analysis pipeline.",
            "artifacts_count": 0,
            "findings_count": 0,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "evidence_id": ev_id, "timestamp": datetime.now(timezone.utc).isoformat()}
        }


BrowserForensicsAgent = BrowserAgent
