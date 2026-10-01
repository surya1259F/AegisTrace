"""
Legacy base agent module preserved for backward compatibility.
The canonical production base agent contract is `Agent` in `agents.base.agent`.
"""

from agents.base.agent import (
    Agent,
    CapabilityRequest,
    AgentObservation,
    AgentAnalysisResult,
    AgentSafetyProfile,
)

# Canonical contract unification: BaseSpecialistAgent is an alias to Agent
BaseSpecialistAgent = Agent

__all__ = [
    "BaseSpecialistAgent",
    "Agent",
    "CapabilityRequest",
    "AgentObservation",
    "AgentAnalysisResult",
    "AgentSafetyProfile",
]
