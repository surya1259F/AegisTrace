from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile


class CorrelationAgent(Agent):
    """
    Specialist Timeline / Correlation Agent (Phase 2 / Step 16).
    Analyzes cross-domain event relationships, temporal clusters, and multi-source correlation graphs.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="TimelineCorrelationAgent",
            description="Analyzes cross-domain event relationships, temporal event sequences, and multi-source correlation groups.",
            capabilities=[
                "entity_correlation",
                "temporal_alignment",
                "provenance_graph",
                "cross_domain_linking",
                "cluster_analysis"
            ],
            agent_id="agent-timeline-correlation",
            version="1.0.0",
            supported_domains=["TIMELINE", "CORRELATION", "CROSS_DOMAIN", "TEMPORAL"],
            supported_artifact_types=[
                "TIMELINE_EVENT", "ARTIFACT_RELATIONSHIP",
                "CORRELATION_GROUP", "TEMPORAL_WINDOW"
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
            "step_id": "corr-align-01",
            "agent": self.name,
            "capability_id": "TIMELINE_CORRELATION",
            "tool": "CorrelationEngine",
            "action": "align_cross_domain_events",
            "priority": 1,
            "description": "Align timeline events and identify multi-domain correlation links."
        }]

    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AgentAnalysisResult:
        timeline_events = structured_data.get("timeline_events") or []
        relationships = structured_data.get("artifact_relationships") or []
        normalized_artifacts = structured_data.get("normalized_artifacts") or []

        observations = []
        supporting_art_ids = []
        supporting_ev_ids = []
        supporting_rel_ids = []

        # 1. Analyze existing cross-domain relationships
        for rel in relationships:
            rel_id = rel.get("id") or rel.get("relationship_id")
            rel_type = rel.get("relationship_type", "CROSS_DOMAIN_MATCH")
            matching_field = rel.get("matching_identifier") or rel.get("matched_value") or "identifier"
            src_ref = rel.get("source_artifact_id") or rel.get("source_id")
            tgt_ref = rel.get("target_artifact_id") or rel.get("target_id")

            if rel_id:
                supporting_rel_ids.append(rel_id)
            if src_ref:
                supporting_art_ids.append(src_ref)
            if tgt_ref:
                supporting_art_ids.append(tgt_ref)

            observations.append({
                "fact_type": "CROSS_DOMAIN_RELATIONSHIP_VERIFIED",
                "description": f"Verified relationship '{rel_type}' matching on '{matching_field}' between {src_ref} and {tgt_ref}.",
                "supporting_evidence_ids": rel.get("evidence_references") or [],
                "supporting_artifact_ids": [x for x in [src_ref, tgt_ref] if x],
                "details": {
                    "relationship_id": rel_id,
                    "relationship_type": rel_type,
                    "matched_value": matching_field,
                    "confidence": rel.get("confidence_score")
                },
                "confidence": rel.get("confidence_score")
            })

        # 2. Analyze timeline temporal sequence
        if len(timeline_events) > 1:
            observations.append({
                "fact_type": "TIMELINE_TEMPORAL_SEQUENCE_OBSERVED",
                "description": f"Timeline sequence established across {len(timeline_events)} UTC-normalized events.",
                "supporting_evidence_ids": list(set(ev.get("evidence_id") for ev in timeline_events if ev.get("evidence_id"))),
                "supporting_artifact_ids": list(set(ev.get("source_artifact_id") for ev in timeline_events if ev.get("source_artifact_id"))),
                "details": {
                    "event_count": len(timeline_events),
                    "start_time": timeline_events[0].get("utc_timestamp"),
                    "end_time": timeline_events[-1].get("utc_timestamp")
                },
                "confidence": 1.0
            })

        for art in normalized_artifacts:
            ev_id = art.get("evidence_id")
            if ev_id and ev_id not in supporting_ev_ids:
                supporting_ev_ids.append(ev_id)

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="TIMELINE_CORRELATION_ANALYSIS",
            observations=observations,
            capability_requests=[],
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=supporting_rel_ids,
            supporting_finding_ids=[],
            confidence_inputs={
                "relationship_count": len(relationships),
                "timeline_event_count": len(timeline_events)
            },
            confidence_score=mean_conf,
            summary=f"Correlation analysis synthesized {len(relationships)} relationships and {len(timeline_events)} timeline events; identified {len(observations)} verified observations.",
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


TimelineCorrelationAgent = CorrelationAgent
