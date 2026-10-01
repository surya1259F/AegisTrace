from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime, timezone
from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile


class InvestigationStrategyAgent(Agent):
    """
    Specialist Investigation Strategy Agent (Phase 2 / Step 16).
    Plans evidence-driven analysis across specialist agents and registered capabilities.
    Evaluates case objectives, evidence profiles, and investigation milestones.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="InvestigationStrategyAgent",
            description="Plans evidence-driven analysis and formulates capability requests based on case objectives and evidence intelligence.",
            capabilities=[
                "investigation_planning",
                "capability_request_generation",
                "strategy_formulation",
                "triage",
                "task_planning",
                "tool_selection"
            ],
            agent_id="agent-investigation-strategy",
            version="1.0.0",
            supported_domains=["ALL", "STRATEGY", "PLANNING"],
            supported_artifact_types=["EVIDENCE_ITEM", "FINDING", "OBJECTIVE", "CORRELATION_GROUP"],
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
        ev_type = str(evidence_item.get("evidence_type", "")).lower()
        ev_name = evidence_item.get("name", "evidence_item")
        ev_id = evidence_item.get("id") or "UNKNOWN_EVIDENCE"
        steps = []

        if any(t in ev_type for t in ["disk", "image", "filesystem", "raw", "e01", "vmdk"]):
            steps.append({
                "step_id": "strat-disk-01",
                "agent": "DiskForensicsAgent",
                "capability_id": "FILESYSTEM_ANALYSIS",
                "tool": "FILESYSTEM_ANALYSIS",
                "action": "filesystem_structure",
                "priority": 1,
                "description": f"Extract directory tree and filesystem metadata from {ev_name}."
            })
            steps.append({
                "step_id": "strat-disk-02",
                "agent": "DiskForensicsAgent",
                "capability_id": "PARTITION_ANALYSIS",
                "tool": "PARTITION_ANALYSIS",
                "action": "partition_layout",
                "priority": 2,
                "description": f"Inspect partition layout and volume offsets for {ev_name}."
            })
        elif any(t in ev_type for t in ["mem", "dump", "vmem", "dmp"]):
            steps.append({
                "step_id": "strat-mem-01",
                "agent": "MemoryForensicsAgent",
                "capability_id": "MEMORY_PROCESS_ANALYSIS",
                "tool": "MEMORY_PROCESS_ANALYSIS",
                "action": "process_listing",
                "priority": 1,
                "description": f"Analyze active and terminated process tree from {ev_name}."
            })
            steps.append({
                "step_id": "strat-mem-02",
                "agent": "MemoryForensicsAgent",
                "capability_id": "MEMORY_NETWORK_ANALYSIS",
                "tool": "MEMORY_NETWORK_ANALYSIS",
                "action": "network_sockets",
                "priority": 2,
                "description": f"Scan memory-resident network connections and sockets in {ev_name}."
            })
        elif any(t in ev_type for t in ["exe", "bin", "malware", "pe", "elf", "suspicious"]):
            steps.append({
                "step_id": "strat-mal-01",
                "agent": "MalwareAnalysisAgent",
                "capability_id": "YARA_SIGNATURE_SCANNING",
                "tool": "YARA_SIGNATURE_SCANNING",
                "action": "yara_scan",
                "priority": 1,
                "description": f"Perform verified YARA signature scanning against {ev_name}."
            })
        elif any(t in ev_type for t in ["evtx", "event", "windows_log"]):
            steps.append({
                "step_id": "strat-win-01",
                "agent": "WindowsForensicsAgent",
                "capability_id": "WINDOWS_EVTX_ANALYSIS",
                "tool": "WINDOWS_EVTX_ANALYSIS",
                "action": "security_events",
                "priority": 1,
                "description": f"Audit Windows authentication, process creation, and service events in {ev_name}."
            })
        elif any(t in ev_type for t in ["pcap", "network", "capture"]):
            steps.append({
                "step_id": "strat-net-01",
                "agent": "NetworkForensicsAgent",
                "capability_id": "PCAP_PACKET_ANALYSIS",
                "tool": "PCAP_PACKET_ANALYSIS",
                "action": "flow_inspection",
                "priority": 1,
                "description": f"Extract packet flows and protocol breakdown from {ev_name}."
            })
        elif any(t in ev_type for t in ["browser", "history", "sqlite"]):
            steps.append({
                "step_id": "strat-browser-01",
                "agent": "BrowserForensicsAgent",
                "capability_id": "BROWSER_HISTORY_ANALYSIS",
                "tool": "BROWSER_HISTORY_ANALYSIS",
                "action": "history_downloads",
                "priority": 1,
                "description": f"Extract web visits and download records from {ev_name}."
            })
        elif any(t in ev_type for t in ["linux", "auth", "secure", "journal"]):
            steps.append({
                "step_id": "strat-linux-01",
                "agent": "LinuxForensicsAgent",
                "capability_id": "LINUX_AUTH_ANALYSIS",
                "tool": "LINUX_AUTH_ANALYSIS",
                "action": "auth_audit",
                "priority": 1,
                "description": f"Audit Linux authentication and privilege elevation in {ev_name}."
            })
        else:
            steps.append({
                "step_id": "strat-gen-01",
                "agent": "DiskForensicsAgent",
                "capability_id": "FILE_METADATA_ANALYSIS",
                "tool": "FILE_METADATA_ANALYSIS",
                "action": "metadata_extraction",
                "priority": 1,
                "description": f"Extract file metadata and cryptographic hashes for {ev_name}."
            })

        return steps

    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AgentAnalysisResult:
        evidence_items = structured_data.get("evidence_items") or []
        findings = structured_data.get("deterministic_findings") or []
        correlations = structured_data.get("artifact_relationships") or []
        observations = []
        cap_requests = []
        supporting_ev_ids = []

        # 1. Evidence Capability Assessment
        for ev in evidence_items:
            ev_id = ev.get("id") or "UNKNOWN"
            supporting_ev_ids.append(ev_id)
            plan_steps = self.plan(ev)
            for step in plan_steps:
                cap_requests.append({
                    "capability_id": step["capability_id"],
                    "evidence_id": ev_id,
                    "parameters": step.get("parameters", {}),
                    "rationale": step["description"],
                    "priority": step["priority"],
                    "requested_by_agent": step["agent"]
                })

        # 2. Findings Follow-up Assessment
        high_critical_findings = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
        if high_critical_findings:
            observations.append({
                "fact_type": "STRATEGY_ALERT_EVALUATION",
                "description": f"Identified {len(high_critical_findings)} high/critical findings requiring corroborative timeline and cross-domain correlation.",
                "supporting_evidence_ids": supporting_ev_ids[:5],
                "supporting_artifact_ids": [],
                "details": {"high_critical_count": len(high_critical_findings)},
                "confidence": 1.0
            })

        # 3. Overall Strategy Summary
        observations.append({
            "fact_type": "INVESTIGATION_STRATEGY_FORMULATED",
            "description": f"Formulated investigation plan with {len(cap_requests)} capability requests across {len(evidence_items)} evidence items.",
            "supporting_evidence_ids": supporting_ev_ids,
            "supporting_artifact_ids": [],
            "details": {
                "evidence_count": len(evidence_items),
                "planned_capability_count": len(cap_requests),
                "existing_findings_count": len(findings),
                "existing_correlations_count": len(correlations)
            },
            "confidence": 1.0
        })

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="INVESTIGATION_STRATEGY_PLAN",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=[],
            supporting_correlation_ids=[c.get("id") for c in correlations if c.get("id")],
            supporting_finding_ids=[f.get("id") for f in findings if f.get("id")],
            confidence_inputs={"evidence_coverage": 1.0, "deterministic_rule_count": len(observations)},
            confidence_score=1.0,
            summary=f"Investigation strategy formulated with {len(cap_requests)} capability requests.",
            provenance={"agent": self.name, "version": self.version, "timestamp": datetime.now(timezone.utc).isoformat()}
        )

    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        plan_steps = self.plan(evidence_item)
        return {
            "status": "SUCCESS",
            "agent": self.name,
            "plan": plan_steps,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "timestamp": utc_now().isoformat()}
        }


# Backwards compatibility alias
PlannerAgent = InvestigationStrategyAgent
