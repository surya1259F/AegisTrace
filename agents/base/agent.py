from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class CapabilityRequest:
    """
    Step 16 Controlled Capability Request.
    Agents formulate structured capability requests to the Step 7 Capability Registry.
    Direct subprocess execution and arbitrary shell commands are strictly prohibited.
    """
    capability_id: str
    evidence_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    priority: int = 1
    requested_by_agent: str = ""
    request_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "evidence_id": self.evidence_id,
            "parameters": self.parameters,
            "rationale": self.rationale,
            "priority": self.priority,
            "requested_by_agent": self.requested_by_agent,
            "request_id": self.request_id,
            "created_at": self.created_at
        }


@dataclass
class AgentObservation:
    """
    Evidence-grounded observation produced by a specialist agent.
    Never invents unobserved facts or intent.
    """
    fact_type: str
    description: str
    supporting_evidence_ids: List[str] = field(default_factory=list)
    supporting_artifact_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fact_type": self.fact_type,
            "description": self.description,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "supporting_artifact_ids": self.supporting_artifact_ids,
            "details": self.details,
            "confidence": self.confidence
        }


@dataclass
class AgentAnalysisResult:
    """
    Structured, auditable result produced by a specialist agent.
    Grounds all claims in observable artifacts, timeline events, and evidence references.
    """
    agent_id: str
    agent_version: str
    analysis_type: str
    observations: List[Dict[str, Any]] = field(default_factory=list)
    capability_requests: List[Dict[str, Any]] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    supporting_artifact_ids: List[str] = field(default_factory=list)
    supporting_correlation_ids: List[str] = field(default_factory=list)
    supporting_finding_ids: List[str] = field(default_factory=list)
    confidence_inputs: Dict[str, Any] = field(default_factory=dict)
    confidence_score: Optional[float] = None
    summary: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "analysis_type": self.analysis_type,
            "observations": self.observations,
            "capability_requests": self.capability_requests,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "supporting_artifact_ids": self.supporting_artifact_ids,
            "supporting_correlation_ids": self.supporting_correlation_ids,
            "supporting_finding_ids": self.supporting_finding_ids,
            "confidence_inputs": self.confidence_inputs,
            "confidence_score": self.confidence_score,
            "summary": self.summary,
            "provenance": self.provenance
        }


@dataclass
class AgentSafetyProfile:
    """
    Security and permission profile enforced on all specialist agents.
    Strictly forbids direct command execution and evidence modification.
    """
    allow_direct_execution: bool = False
    allow_shell_commands: bool = False
    allow_evidence_modification: bool = False
    read_only_access: bool = True
    requires_capability_gating: bool = True
    max_artifacts_per_analysis: int = 10000
    timeout_seconds: int = 300

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow_direct_execution": self.allow_direct_execution,
            "allow_shell_commands": self.allow_shell_commands,
            "allow_evidence_modification": self.allow_evidence_modification,
            "read_only_access": self.read_only_access,
            "requires_capability_gating": self.requires_capability_gating,
            "max_artifacts_per_analysis": self.max_artifacts_per_analysis,
            "timeout_seconds": self.timeout_seconds
        }


class Agent(ABC):
    """
    Abstract Base Class for all Specialist Forensic Agents in ADFIR (Phase 2 / Step 16).
    Enforces deterministic contracts for evidence analysis, provenance, and validation.
    Strictly forbids direct subprocess execution, arbitrary shell commands, and evidence invention.
    """

    def __init__(
        self,
        name: str,
        description: str,
        capabilities: List[str],
        agent_id: Optional[str] = None,
        version: str = "1.0.0",
        supported_domains: Optional[List[str]] = None,
        supported_artifact_types: Optional[List[str]] = None,
        safety_profile: Optional[AgentSafetyProfile] = None
    ):
        self.id: str = agent_id or str(uuid.uuid4())
        self.name: str = name
        self.version: str = version
        self.description: str = description
        self.capabilities: List[str] = capabilities
        self.supported_domains: List[str] = supported_domains or []
        self.supported_artifact_types: List[str] = supported_artifact_types or []
        self.safety_profile: AgentSafetyProfile = safety_profile or AgentSafetyProfile()
        self.is_enabled: bool = True

    @abstractmethod
    def can_handle(self, evidence_type: str) -> bool:
        """Determines if the specialist agent supports the given evidence type."""
        pass

    def can_analyze_domain(self, domain: str) -> bool:
        """Determines if the specialist agent supports the forensic domain."""
        if not domain:
            return False
        d_clean = domain.upper().strip()
        if "ALL" in [d.upper() for d in self.supported_domains]:
            return True
        return d_clean in [d.upper() for d in self.supported_domains]

    @abstractmethod
    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formulates an agent-specific execution plan without running tools."""
        pass

    def request_capabilities(
        self,
        evidence_item: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[CapabilityRequest]:
        """
        Formulates structured CapabilityRequests routed through the Step 7 capability registry.
        Agents MUST NOT execute tools directly or run shell commands.
        """
        plan_steps = self.plan(evidence_item)
        requests: List[CapabilityRequest] = []
        ev_id = evidence_item.get("id") or evidence_item.get("evidence_id") or "UNKNOWN_EVIDENCE"
        for step in plan_steps:
            cap_id = step.get("capability_id") or step.get("tool") or (self.capabilities[0] if self.capabilities else "GENERIC_ANALYSIS")
            requests.append(CapabilityRequest(
                capability_id=cap_id,
                evidence_id=ev_id,
                parameters=step.get("parameters") or {},
                rationale=step.get("description") or f"Analysis requested by {self.name}",
                priority=step.get("priority", 1),
                requested_by_agent=self.name
            ))
        return requests

    @abstractmethod
    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AgentAnalysisResult:
        """
        Analyzes approved case-scoped structured forensic artifacts (normalized artifacts,
        timeline events, correlations, findings) without executing shell commands or inventing evidence.
        """
        pass

    @abstractmethod
    def analyze(
        self,
        evidence_item: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Backward-compatible analysis execution routed through tool adapters (where applicable)
        or structured analysis fallback.
        """
        pass

    def validate(self, findings: List[Dict[str, Any]]) -> bool:
        """Validates that findings adhere to required schema and have evidence references."""
        for f in findings:
            if not f.get("tool") or not f.get("title") or "evidence_reference" not in f:
                return False
        return True
