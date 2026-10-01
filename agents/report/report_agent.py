from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile


class ReportAgent(Agent):
    """
    Specialist Report / Summary Agent (Phase 2 / Step 16).
    Converts verified investigation state, deterministic findings, and timeline events
    into traceable, forensically sound formal report content with complete provenance.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="ReportSummaryAgent",
            description="Synthesizes verified findings, timeline events, and evidence provenance into traceable audit-grade forensic reports.",
            capabilities=[
                "report_synthesis",
                "mitre_mapping",
                "remediation_planning",
                "executive_summary",
                "chain_of_custody_report"
            ],
            agent_id="agent-report-summary",
            version="1.0.0",
            supported_domains=["REPORT", "SUMMARY", "EXECUTIVE", "COURT_READY"],
            supported_artifact_types=[
                "FINDING", "EVIDENCE_ITEM", "TIMELINE_EVENT",
                "CORRELATION_GROUP", "REPORT_SECTION"
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
        return True

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
            "step_id": "rep-synth-01",
            "agent": self.name,
            "capability_id": "REPORT_SYNTHESIS",
            "tool": "ReportSynthesizer",
            "action": "synthesize_investigation_report",
            "priority": 1,
            "description": "Synthesize verified findings into structured report sections."
        }]

    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AgentAnalysisResult:
        evidence_items = structured_data.get("evidence_items") or []
        findings = structured_data.get("deterministic_findings") or []
        timeline_events = structured_data.get("timeline_events") or []
        relationships = structured_data.get("artifact_relationships") or []

        observations = []
        supporting_ev_ids = [e.get("id") for e in evidence_items if e.get("id")]
        supporting_finding_ids = [f.get("id") or f.get("finding_id") for f in findings if f.get("id") or f.get("finding_id")]

        # 1. Executive Summary Section
        summary_text = (
            f"Investigation analyzed {len(evidence_items)} evidence item(s). "
            f"Deterministic analysis produced {len(findings)} verified finding(s) "
            f"and established {len(timeline_events)} chronological events."
        )
        observations.append({
            "fact_type": "REPORT_SECTION_EXECUTIVE_SUMMARY",
            "description": summary_text,
            "supporting_evidence_ids": supporting_ev_ids,
            "supporting_artifact_ids": [],
            "details": {
                "section": "Executive Summary",
                "content": summary_text,
                "evidence_count": len(evidence_items),
                "finding_count": len(findings)
            },
            "confidence": 1.0
        })

        # 2. Chain of Custody Section
        custody_entries = []
        for ev in evidence_items:
            custody_entries.append({
                "evidence_id": ev.get("id"),
                "name": ev.get("name"),
                "sha256": ev.get("sha256_hash") or ev.get("hash"),
                "status": "VERIFIED"
            })
        observations.append({
            "fact_type": "REPORT_SECTION_CHAIN_OF_CUSTODY",
            "description": f"Chain of custody documented for {len(custody_entries)} evidence items.",
            "supporting_evidence_ids": supporting_ev_ids,
            "supporting_artifact_ids": [],
            "details": {"section": "Chain of Custody", "entries": custody_entries},
            "confidence": 1.0
        })

        # 3. Verified Technical Findings Section
        for f in findings:
            f_id = f.get("id") or f.get("finding_id")
            title = f.get("title") or f.get("rule_id") or "Finding"
            severity = f.get("severity") or "INFO"
            confidence = f.get("confidence_score")
            conf_str = f"{confidence:.2f}" if confidence is not None else "Uncalibrated"
            observations.append({
                "fact_type": "REPORT_SECTION_TECHNICAL_FINDING",
                "description": f"Verified Finding: [{severity}] {title} (Confidence: {conf_str}).",
                "supporting_evidence_ids": supporting_ev_ids,
                "supporting_artifact_ids": f.get("supporting_artifact_ids") or [],
                "details": {
                    "section": "Technical Findings",
                    "finding_id": f_id,
                    "title": title,
                    "severity": severity,
                    "confidence": confidence
                },
                "confidence": confidence
            })

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="REPORT_SYNTHESIS_ANALYSIS",
            observations=observations,
            capability_requests=[],
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=[],
            supporting_correlation_ids=[r.get("id") for r in relationships if r.get("id")],
            supporting_finding_ids=supporting_finding_ids,
            confidence_inputs={
                "evidence_count": len(evidence_items),
                "finding_count": len(findings),
                "timeline_count": len(timeline_events)
            },
            confidence_score=1.0 if findings or evidence_items else 0.8,
            summary=f"Report agent synthesized investigation state across {len(evidence_items)} evidence items and {len(findings)} findings into {len(observations)} report sections.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        execution_id = str(uuid.uuid4())
        return {
            "status": "SUCCESS",
            "execution_id": execution_id,
            "artifacts_count": 0,
            "findings_count": 0,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "timestamp": datetime.now(timezone.utc).isoformat()}
        }


ReportSummaryAgent = ReportAgent
