from typing import List, Dict, Any
from investigation.correlation.engine import CorrelationEngine

class EvidenceCorrelationEngine:
    """
    Correlates multi-source forensic findings across Disk, Memory, Malware, and Logs.
    Wraps the deterministic CorrelationEngine for backward compatibility with v1 API endpoints.
    """
    def __init__(self):
        self._engine = CorrelationEngine()

    def correlate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = self._engine.correlate_findings(findings)
        # Adapt output to include legacy keys for v1 compatibility
        adapted = []
        for r in results:
            item = dict(r)
            item["entity"] = r["correlated_entity"]
            item["confidence"] = r["correlation_confidence"]
            adapted.append(item)
        return adapted
