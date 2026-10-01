from typing import Dict, Any, List, Optional
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid

from agents.base.agent import Agent, CapabilityRequest, AgentAnalysisResult, AgentSafetyProfile


class NetworkAgent(Agent):
    """
    Specialist Network Forensics Agent (Phase 2 / Step 16).
    Analyzes PCAP network captures, flow records, DNS requests, HTTP transactions, and TLS sessions.
    Does NOT directly execute arbitrary shell commands or invent evidence.
    """

    def __init__(self):
        super().__init__(
            name="NetworkForensicsAgent",
            description="Analyzes network captures (PCAP), DNS queries, HTTP/TLS traffic, and socket connections.",
            capabilities=[
                "packet_dissection",
                "dns_lookup_analysis",
                "flow_reconstruction",
                "tls_metadata_extraction",
                "http_request_analysis"
            ],
            agent_id="agent-network-forensics",
            version="1.0.0",
            supported_domains=["NETWORK", "PCAP", "FLOW", "DNS", "HTTP", "TLS"],
            supported_artifact_types=[
                "PACKET", "NETWORK_FLOW", "DNS_QUERY", "HTTP_REQUEST",
                "TLS_HANDSHAKE", "NETWORK_CONNECTION", "IP_ENDPOINT"
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
            "network_capture", "pcap", "pcapng", "cap", "network_log",
            "file", "generic_binary"
        ]

    def plan(self, evidence_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        ev_name = evidence_item.get("name", "network_evidence")
        return [{
            "step_id": "net-pcap-01",
            "agent": self.name,
            "capability_id": "PCAP_PACKET_DISSECTION",
            "tool": "PcapParser",
            "action": "dissect_packets_and_flows",
            "priority": 1,
            "description": f"Extract IP conversations, DNS queries, and HTTP/TLS flows from {ev_name}."
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

            # 1. DNS Queries
            if "DNS" in entity_type:
                supporting_art_ids.append(art_id)
                query_name = str(fields.get("query_name") or fields.get("domain") or fields.get("hostname") or "")
                response_ip = str(fields.get("response_ip") or fields.get("ip") or "")
                qtype = str(fields.get("query_type") or "A")

                observations.append({
                    "fact_type": "DNS_RESOLUTION_OBSERVED",
                    "description": f"DNS query observed: '{query_name}' (type: {qtype}, resolved to: '{response_ip or 'unresolved'}').",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"domain": query_name, "query_type": qtype, "response_ip": response_ip},
                    "confidence": 0.95
                })

            # 2. Network Flows / Connections
            elif any(k in entity_type for k in ["FLOW", "CONNECTION", "SOCKET", "NETWORK"]):
                supporting_art_ids.append(art_id)
                src_ip = str(fields.get("src_ip") or fields.get("local_ip") or "")
                dst_ip = str(fields.get("dst_ip") or fields.get("remote_ip") or "")
                dst_port = fields.get("dst_port") or fields.get("remote_port") or ""
                proto = str(fields.get("protocol") or fields.get("proto") or "TCP")

                observations.append({
                    "fact_type": "NETWORK_CONNECTION_OBSERVED",
                    "description": f"Network traffic observed: {src_ip} -> {dst_ip}:{dst_port} ({proto}).",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": proto},
                    "confidence": 0.95
                })

            # 3. HTTP / TLS Transactions
            elif any(k in entity_type for k in ["HTTP", "TLS", "WEB"]):
                supporting_art_ids.append(art_id)
                host = str(fields.get("host") or fields.get("sni") or "")
                uri = str(fields.get("uri") or fields.get("path") or "")
                method = str(fields.get("method") or "GET")

                observations.append({
                    "fact_type": "APPLICATION_TRAFFIC_OBSERVED",
                    "description": f"Web application traffic observed: {method} host '{host}' uri '{uri}'.",
                    "supporting_evidence_ids": [ev_id] if ev_id else [],
                    "supporting_artifact_ids": [art_id],
                    "details": {"host": host, "uri": uri, "method": method},
                    "confidence": 0.90
                })

        # Request capabilities for network evidence items
        for ev in evidence_items:
            ev_type = str(ev.get("evidence_type", "")).lower()
            ev_id = ev.get("id")
            if any(t in ev_type for t in ["pcap", "network", "cap"]):
                cap_requests.append({
                    "capability_id": "PCAP_PACKET_DISSECTION",
                    "evidence_id": ev_id,
                    "parameters": {"extract_dns": True, "extract_flows": True},
                    "rationale": f"PCAP flow dissection requested by {self.name}",
                    "priority": 1,
                    "requested_by_agent": self.name
                })

        obs_confs = [o.get("confidence") for o in observations if isinstance(o, dict) and o.get("confidence") is not None]
        mean_conf = round(sum(obs_confs) / len(obs_confs), 4) if obs_confs else None

        return AgentAnalysisResult(
            agent_id=self.id,
            agent_version=self.version,
            analysis_type="NETWORK_FORENSICS_ANALYSIS",
            observations=observations,
            capability_requests=cap_requests,
            supporting_evidence_ids=supporting_ev_ids,
            supporting_artifact_ids=list(set(supporting_art_ids)),
            supporting_correlation_ids=[],
            supporting_finding_ids=[],
            confidence_inputs={"matching_artifact_count": len(supporting_art_ids)},
            confidence_score=mean_conf,
            summary=f"Network forensics analyzed {len(supporting_art_ids)} network artifacts; identified {len(observations)} observations.",
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
            "message": "Direct PCAP/network packet parsing is not implemented; use structured artifact analysis pipeline.",
            "artifacts_count": 0,
            "findings_count": 0,
            "artifacts": [],
            "findings": [],
            "provenance": {"agent": self.name, "evidence_id": ev_id, "timestamp": datetime.now(timezone.utc).isoformat()}
        }


NetworkForensicsAgent = NetworkAgent
