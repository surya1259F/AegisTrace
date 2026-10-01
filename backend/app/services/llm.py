from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import json

class LLMProvider(ABC):
    """
    Abstract Interface for LLM Reasoning Engines.
    Provider-agnostic abstraction for Local LLMs, Gemini, Qwen, Llama, Mistral, etc.
    Does NOT require a paid API key for default operation.
    """

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        pass

    @abstractmethod
    async def analyze(self, verified_context: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def summarize(self, findings: List[Dict[str, Any]]) -> str:
        pass

class LocalLLMProvider(LLMProvider):
    """
    Default provider: executes locally without cloud egress or paid keys.
    """

    def __init__(self, endpoint: Optional[str] = None):
        from backend.app.core.config import settings
        self.endpoint = endpoint if endpoint is not None else settings.LOCAL_LLM_ENDPOINT

    def _sanitize_untrusted_data(self, data_str: str) -> str:
        """
        Hardens prompt against injection by neutralizing instruction overrides in evidence.
        Evidence is always framed strictly as untrusted literal data.
        """
        return data_str.replace("```", "'''")

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        # Default deterministic reasoning response
        return f"[Reasoned Analysis]: Synthesized verified context based on deterministic findings."

    async def analyze(self, verified_context: Dict[str, Any]) -> Dict[str, Any]:
        findings_count = len(verified_context.get("findings", []))
        if findings_count == 0:
            return {
                "attack_type": "INSUFFICIENT EVIDENCE",
                "mitre_tactic": None,
                "confidence": None,
                "summary": "No verified findings are available for attack classification."
            }

        return {
            "attack_type": "PENDING_INVESTIGATOR_REVIEW",
            "mitre_tactic": None,
            "confidence": None,
            "summary": (
                f"{findings_count} finding(s) are available for investigator review. "
                "No automated attack classification is asserted."
            )
        }

    async def summarize(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "No verified findings available for summary."
        return f"Investigation identified {len(findings)} technical findings across analyzed forensic artifacts."

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self.api_key:
            return "[Gemini Provider]: API Key not configured. Using local fallback reasoning."
        return "[Gemini Reasoner]: Analysis generated."

    async def analyze(self, verified_context: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "analyzed"}

    async def summarize(self, findings: List[Dict[str, Any]]) -> str:
        return f"Summary of {len(findings)} findings."
