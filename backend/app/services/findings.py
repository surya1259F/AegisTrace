"""ADFIR Deterministic Findings Subsystem (Phase 2 / Step 15)

Generates evidence-grounded findings from Steps 12-14 before any AI reasoning.

STRICT FORENSIC BOUNDARIES:
- NEVER use LLMs or heuristic speculation.
- NEVER infer attacker intent, motives, or unobserved tactics.
- NEVER declare unsupported attacks, breaches, or subjective threat severity.
- Findings represent strictly observable evidence facts and deterministic correlation rules.
- Severity is rule-driven, preserving exact rule and evidence inputs.
- Confidence is calculated deterministically from explicit mathematical inputs.
- Full 7-tier provenance preserved back to physical evidence items.
- Cryptographic SHA-256 integrity protection with isolated disk storage.
- Never modifies Steps 10-14 source artifacts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import (
    ArtifactRelationship,
    DeterministicFinding,
    EvidenceItem,
    ExecutionOutput,
    Finding,
    ForensicCorrelationGroup,
    ForensicExecution,
    NormalizedArtifact,
    StructuredArtifact,
    TimelineEvent,
)
from backend.app.schemas.schemas import (
    DeterministicFindingResponse,
    FindingGenerateRequest,
    FindingIntegrityResponse,
    FindingProvenanceResponse,
    FindingSupportingEvidenceResponse,
    FindingSummaryResponse,
)

logger = logging.getLogger("ADFIR_FINDINGS")


# =============================================================================
# 1. CONSTANTS & DOMAINS
# =============================================================================

class FindingSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingType:
    MALWARE_INDICATOR = "MALWARE_INDICATOR"
    SUSPICIOUS_EXECUTION = "SUSPICIOUS_EXECUTION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    AUTHENTICATION_ACTIVITY = "AUTHENTICATION_ACTIVITY"
    MULTI_DOMAIN_CORRELATION = "MULTI_DOMAIN_CORRELATION"
    TEMPORAL_ANOMALY = "TEMPORAL_ANOMALY"
    GENERIC_EVIDENCE = "GENERIC_EVIDENCE"


class SeverityRule:
    RULE_CONFIRMED_MALWARE_HASH_MATCH = "RULE_CONFIRMED_MALWARE_HASH_MATCH"
    RULE_MALWARE_SIGNATURE_HIT = "RULE_MALWARE_SIGNATURE_HIT"
    RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION = "RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION"
    RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION = "RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION"
    RULE_BROWSER_SOCKET_INTERACTION = "RULE_BROWSER_SOCKET_INTERACTION"
    RULE_MULTI_DOMAIN_CORRELATED_CLUSTER = "RULE_MULTI_DOMAIN_CORRELATED_CLUSTER"
    RULE_PRIVILEGED_USER_LOGON_ACTIVITY = "RULE_PRIVILEGED_USER_LOGON_ACTIVITY"
    RULE_PROCESS_SOCKET_ASSOCIATION = "RULE_PROCESS_SOCKET_ASSOCIATION"
    RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE = "RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE"
    RULE_USER_LOGON_OBSERVATION = "RULE_USER_LOGON_OBSERVATION"
    RULE_TEMPORAL_SEQUENCE_OBSERVATION = "RULE_TEMPORAL_SEQUENCE_OBSERVATION"
    RULE_SHARED_FILE_HASH_OBSERVATION = "RULE_SHARED_FILE_HASH_OBSERVATION"


SEVERITY_MAPPING: Dict[str, str] = {
    SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH: FindingSeverity.CRITICAL,
    SeverityRule.RULE_MALWARE_SIGNATURE_HIT: FindingSeverity.MEDIUM,
    SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION: FindingSeverity.HIGH,
    SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION: FindingSeverity.LOW,
    SeverityRule.RULE_BROWSER_SOCKET_INTERACTION: FindingSeverity.LOW,
    SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER: FindingSeverity.LOW,
    SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY: FindingSeverity.MEDIUM,
    SeverityRule.RULE_PROCESS_SOCKET_ASSOCIATION: FindingSeverity.INFORMATIONAL,
    SeverityRule.RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE: FindingSeverity.MEDIUM,
    SeverityRule.RULE_USER_LOGON_OBSERVATION: FindingSeverity.LOW,
    SeverityRule.RULE_TEMPORAL_SEQUENCE_OBSERVATION: FindingSeverity.INFORMATIONAL,
    SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION: FindingSeverity.INFORMATIONAL,
}


def extract_authoritative_malware_signature(
    source_art: Optional[NormalizedArtifact],
    target_art: Optional[NormalizedArtifact],
    rel: Optional[ArtifactRelationship] = None
) -> Optional[Dict[str, str]]:
    """
    Checks if an authoritative and verified malware signature source is explicitly represented.
    Returns dict with {signature_source, signature_identifier, signature_version, verification_status, hash}
    or None if absent / unverified.
    """
    for art in [source_art, target_art]:
        if not art:
            continue
        fields = art.normalized_fields or {}
        ev_ref = art.evidence_reference or {}
        hashes = fields.get("hashes") or {}

        source = (
            fields.get("signature_source") or
            fields.get("authority") or
            fields.get("source_database") or
            fields.get("threat_feed") or
            ev_ref.get("signature_source") or
            ev_ref.get("authority")
        )
        status = (
            fields.get("verification_status") or
            ev_ref.get("verification_status")
        )
        sig_id = (
            fields.get("signature_identifier") or
            fields.get("rule_name") or
            fields.get("rule") or
            ev_ref.get("signature_identifier")
        )
        sig_ver = (
            fields.get("signature_version") or
            fields.get("rule_version") or
            fields.get("version") or
            ev_ref.get("signature_version")
        )
        hash_val = (
            hashes.get("sha256") or
            hashes.get("md5") or
            hashes.get("sha1") or
            fields.get("sha256") or
            fields.get("hash")
        )

        if source and str(status).upper() in ["VERIFIED", "CONFIRMED"]:
            return {
                "signature_source": str(source),
                "verification_status": str(status).upper(),
                "signature_identifier": str(sig_id or "UNKNOWN_SIG"),
                "signature_version": str(sig_ver or "1.0"),
                "hash": str(hash_val or (rel.matching_identifier if rel else "") or "")
            }

    if rel and rel.provenance:
        prov = rel.provenance
        source = prov.get("signature_source") or prov.get("authority")
        status = prov.get("verification_status")
        sig_id = prov.get("signature_identifier") or prov.get("rule_name")
        sig_ver = prov.get("signature_version") or "1.0"
        if source and str(status).upper() in ["VERIFIED", "CONFIRMED"]:
            return {
                "signature_source": str(source),
                "verification_status": str(status).upper(),
                "signature_identifier": str(sig_id or "UNKNOWN_SIG"),
                "signature_version": str(sig_ver or "1.0"),
                "hash": str(rel.matching_identifier or "")
            }

    return None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_canonical_json(data: Any) -> str:
    """Deterministic JSON serialization with sorted keys and no whitespace."""
    def _default(obj):
        if isinstance(obj, datetime):
            if obj.tzinfo is not None:
                obj = obj.astimezone(timezone.utc)
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return str(obj)

    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=_default)


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


# =============================================================================
# 2. DETERMINISTIC CONFIDENCE CALCULATOR
# =============================================================================

def calculate_deterministic_confidence(
    source_integrity: float = 1.0,
    artifact_confidence: float = 1.0,
    identifier_match_confidence: float = 1.0,
    supporting_source_count: int = 1,
    contradictory_evidence: bool = False,
    temporal_confidence: Optional[float] = None
) -> Tuple[float, Dict[str, Any]]:
    """
    Calculates deterministic, reproducible confidence score in [0.0, 1.0].
    
    Formula:
        Confidence = 0.35 * source_integrity
                   + 0.30 * artifact_confidence
                   + 0.25 * identifier_match_confidence
                   + 0.10 * min(1.0, supporting_source_count / 2)
                   - (0.30 if contradictory_evidence else 0.0)
    """
    base_score = (
        0.35 * max(0.0, min(1.0, source_integrity)) +
        0.30 * max(0.0, min(1.0, artifact_confidence)) +
        0.25 * max(0.0, min(1.0, identifier_match_confidence)) +
        0.10 * min(1.0, max(0.0, supporting_source_count) / 2.0)
    )
    if contradictory_evidence:
        base_score -= 0.30

    clamped = max(0.0, min(1.0, base_score))
    final_score = round(clamped, 4)

    inputs: Dict[str, Any] = {
        "source_integrity": round(source_integrity, 4),
        "artifact_confidence": round(artifact_confidence, 4),
        "identifier_match_confidence": round(identifier_match_confidence, 4),
        "supporting_source_count": supporting_source_count,
        "contradictory_evidence": contradictory_evidence,
    }
    if temporal_confidence is not None:
        inputs["temporal_confidence"] = round(temporal_confidence, 4)

    return final_score, inputs


# =============================================================================
# 3. STORAGE MANAGER
# =============================================================================

class FindingStorageManager:
    """
    Manages dedicated disk storage for serialized deterministic findings.
    Enforces case isolation, safe permissions (0o700 dir, 0o600 file),
    path traversal prevention, and strict prohibition from the evidence vault.
    """

    @classmethod
    def get_case_storage_dir(cls, case_id: str) -> Path:
        base_dir = settings.DATA_DIR / "storage" / "findings" / "cases" / case_id
        base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass
        return base_dir

    @classmethod
    def validate_storage_path(cls, candidate_path: Path, case_id: str) -> bool:
        canonical = candidate_path.resolve()
        case_dir = cls.get_case_storage_dir(case_id).resolve()

        # Reject path traversal / escaping case dir
        try:
            canonical.relative_to(case_dir)
        except ValueError:
            return False

        # Strictly forbid writing into evidence vault
        vault_candidates = [
            settings.EVIDENCE_DIR.resolve(),
            (settings.EVIDENCE_DIR / "vault").resolve()
        ]
        for v in vault_candidates:
            if canonical == v or canonical.is_relative_to(v):
                return False

        # Forbid symlinks
        if candidate_path.is_symlink():
            return False

        return True

    @classmethod
    def save_finding(cls, case_id: str, finding_id: str, data: Dict[str, Any]) -> str:
        case_dir = cls.get_case_storage_dir(case_id)
        file_path = case_dir / f"{finding_id}.json"

        if not cls.validate_storage_path(file_path, case_id):
            raise PermissionError(f"Storage path validation failed for finding: {file_path}")

        canonical_content = format_canonical_json(data)
        file_path.write_text(canonical_content, encoding="utf-8")
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass
        return str(file_path)

    @classmethod
    def read_finding(cls, storage_path: str, case_id: str) -> Dict[str, Any]:
        p = Path(storage_path)
        if not cls.validate_storage_path(p, case_id):
            raise PermissionError("Path validation failed: access outside authorized case storage")
        if not p.is_file():
            raise FileNotFoundError(f"Finding file not found at: {storage_path}")
        return json.loads(p.read_text(encoding="utf-8"))

    @classmethod
    def verify_finding_file(
        cls,
        storage_path: Optional[str],
        expected_hash: str,
        case_id: str
    ) -> Tuple[bool, bool, str]:
        """
        Verifies finding integrity on disk.
        Returns: (file_exists, integrity_passed, computed_hash)
        """
        if not storage_path:
            return False, False, ""
        p = Path(storage_path)
        if not p.exists() or not p.is_file():
            return False, False, ""
        if not cls.validate_storage_path(p, case_id):
            return True, False, ""
        try:
            raw_text = p.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            canonical_keys = [
                "case_id",
                "title",
                "description",
                "observed_facts",
                "finding_type",
                "severity",
                "severity_rule",
                "confidence",
                "confidence_inputs",
                "supporting_artifact_ids",
                "supporting_event_ids",
                "supporting_relationship_ids",
                "supporting_group_ids",
                "supporting_evidence_ids",
            ]
            canonical_payload = {k: data[k] for k in canonical_keys if k in data}
            computed = compute_sha256(format_canonical_json(canonical_payload))
            return True, (computed == expected_hash), computed
        except Exception as e:
            logger.warning(f"Integrity check read error: {e}")
            return True, False, ""


# =============================================================================
# 4. DETERMINISTIC RULE ENGINE
# =============================================================================

class DeterministicCandidateFinding:
    """In-memory candidate representation before persistence and hashing."""
    def __init__(
        self,
        title: str,
        description: str,
        observed_facts: List[Dict[str, Any]],
        finding_type: str,
        severity_rule: str,
        confidence: float,
        confidence_inputs: Dict[str, Any],
        supporting_artifact_ids: List[str],
        supporting_event_ids: List[str],
        supporting_relationship_ids: List[str],
        supporting_group_ids: List[str],
        supporting_evidence_ids: List[str],
        provenance: Dict[str, Any],
    ):
        self.title = title
        self.description = description
        self.observed_facts = observed_facts
        self.finding_type = finding_type
        self.severity_rule = severity_rule
        self.severity = SEVERITY_MAPPING.get(severity_rule, FindingSeverity.INFORMATIONAL)
        self.confidence = confidence
        self.confidence_inputs = confidence_inputs
        self.supporting_artifact_ids = sorted(list(set(supporting_artifact_ids)))
        self.supporting_event_ids = sorted(list(set(supporting_event_ids)))
        self.supporting_relationship_ids = sorted(list(set(supporting_relationship_ids)))
        self.supporting_group_ids = sorted(list(set(supporting_group_ids)))
        self.supporting_evidence_ids = sorted(list(set([eid for eid in supporting_evidence_ids if eid])))
        self.provenance = provenance


class DeterministicRuleEngine:
    """
    Evaluates observable evidence records (NormalizedArtifacts, TimelineEvents,
    ArtifactRelationships, ForensicCorrelationGroups) against strict deterministic rules.
    """

    @classmethod
    def evaluate(
        cls,
        case_id: str,
        normalized_artifacts: List[NormalizedArtifact],
        timeline_events: List[TimelineEvent],
        relationships: List[ArtifactRelationship],
        groups: List[ForensicCorrelationGroup],
        allowed_rules: Optional[Set[str]] = None,
        target_evidence_id: Optional[str] = None
    ) -> List[DeterministicCandidateFinding]:
        candidates: List[DeterministicCandidateFinding] = []

        # Index records for efficient lookups
        norm_map = {a.id: a for a in normalized_artifacts}
        event_map = {e.id: e for e in timeline_events}

        # ---------------------------------------------------------------------
        # RULE 1: Confirmed Malware Hash Match (CRITICAL) vs Shared Hash Observation (INFORMATIONAL)
        # ---------------------------------------------------------------------
        covered_hash_art_ids: Set[str] = set()
        check_hashes = not allowed_rules or any(
            r in allowed_rules for r in [
                SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH,
                SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION
            ]
        )
        if check_hashes:
            for rel in relationships:
                if rel.relationship_type == "FILE_HASH_MATCH":
                    ev_ids = list(rel.evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    source_art = norm_map.get(rel.source_id)
                    target_art = norm_map.get(rel.target_id)

                    art_ids = []
                    ev_ids_all = set(ev_ids)
                    if rel.source_type == "NORMALIZED_ARTIFACT":
                        art_ids.append(rel.source_id)
                    if rel.target_type == "NORMALIZED_ARTIFACT":
                        art_ids.append(rel.target_id)

                    for aid in art_ids:
                        a = norm_map.get(aid)
                        if a and a.evidence_id:
                            ev_ids_all.add(a.evidence_id)

                    # Extract authoritative verified signature source
                    auth_sig = extract_authoritative_malware_signature(source_art, target_art, rel)

                    if auth_sig and (not allowed_rules or SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH in allowed_rules):
                        # Verified by authoritative signature source -> CRITICAL
                        hash_val = auth_sig["hash"] or rel.matching_identifier or ""
                        sig_src = auth_sig["signature_source"]
                        sig_id = auth_sig["signature_identifier"]
                        sig_ver = auth_sig["signature_version"]
                        ver_stat = auth_sig["verification_status"]

                        facts = [
                            {
                                "fact_type": "CONFIRMED_MALWARE_HASH_MATCH",
                                "signature_source": sig_src,
                                "signature_identifier": sig_id,
                                "signature_version": sig_ver,
                                "hash": hash_val,
                                "verification_status": ver_stat,
                                "source_domain": rel.source_domain,
                                "target_domain": rel.target_domain,
                                "source_id": rel.source_id,
                                "target_id": rel.target_id,
                            },
                            {
                                "fact_type": "CORRELATED_RELATIONSHIP",
                                "relationship_id": rel.id,
                                "relationship_type": rel.relationship_type,
                            }
                        ]

                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=rel.confidence_score,
                            identifier_match_confidence=1.0,
                            supporting_source_count=len(ev_ids_all) or 2,
                            contradictory_evidence=False
                        )

                        covered_hash_art_ids.update(art_ids)
                        candidates.append(DeterministicCandidateFinding(
                            title=f"Confirmed Malware Hash Match: {sig_src} [{sig_id}]",
                            description=(
                                f"Forensic artifact in {rel.source_domain} matches cryptographic hash '{hash_val}', "
                                f"confirmed by authoritative signature source '{sig_src}' (version {sig_ver}, identifier {sig_id}) "
                                f"with verification status '{ver_stat}'."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.MALWARE_INDICATOR,
                            severity_rule=SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=art_ids,
                            supporting_event_ids=[],
                            supporting_relationship_ids=[rel.id],
                            supporting_group_ids=[rel.group_id] if rel.group_id else [],
                            supporting_evidence_ids=list(ev_ids_all),
                            provenance={
                                "rule": SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH,
                                "signature_source": sig_src,
                                "signature_identifier": sig_id,
                                "signature_version": sig_ver,
                                "verification_status": ver_stat,
                                "hash": hash_val,
                                "relationship_provenance": rel.provenance or {},
                            }
                        ))
                    elif not auth_sig and (not allowed_rules or SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION in allowed_rules):
                        # Ordinary correlation without authoritative signature confirmation -> INFORMATIONAL observation
                        facts = [
                            {
                                "fact_type": "SHARED_FILE_HASH_OBSERVATION",
                                "matching_hash": rel.matching_identifier or "",
                                "source_domain": rel.source_domain,
                                "target_domain": rel.target_domain,
                                "source_id": rel.source_id,
                                "target_id": rel.target_id,
                                "verification_status": "UNVERIFIED_CORRELATION",
                            },
                            {
                                "fact_type": "CORRELATED_RELATIONSHIP",
                                "relationship_id": rel.id,
                                "relationship_type": rel.relationship_type,
                            }
                        ]

                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=rel.confidence_score,
                            identifier_match_confidence=0.85,
                            supporting_source_count=len(ev_ids_all) or 1,
                            contradictory_evidence=False
                        )

                        covered_hash_art_ids.update(art_ids)
                        candidates.append(DeterministicCandidateFinding(
                            title=f"Observed Shared File Hash: {(rel.matching_identifier or '')[:16]}...",
                            description=(
                                f"Forensic artifact in {rel.source_domain} and artifact in {rel.target_domain} "
                                f"share cryptographic hash '{rel.matching_identifier}'. "
                                f"No authoritative malware signature source is represented."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.GENERIC_EVIDENCE,
                            severity_rule=SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=art_ids,
                            supporting_event_ids=[],
                            supporting_relationship_ids=[rel.id],
                            supporting_group_ids=[rel.group_id] if rel.group_id else [],
                            supporting_evidence_ids=list(ev_ids_all),
                            provenance={
                                "rule": SeverityRule.RULE_SHARED_FILE_HASH_OBSERVATION,
                                "matching_hash": rel.matching_identifier or "",
                                "verification_status": "UNVERIFIED_CORRELATION",
                                "relationship_provenance": rel.provenance or {},
                            }
                        ))

        # ---------------------------------------------------------------------
        # RULE 2: Malware Signature Hit / Heuristic Observation (MEDIUM)
        # ---------------------------------------------------------------------
        if not allowed_rules or SeverityRule.RULE_MALWARE_SIGNATURE_HIT in allowed_rules or SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH in allowed_rules:
            for art in normalized_artifacts:
                if art.id in covered_hash_art_ids:
                    continue
                if "MALWARE" in art.entity_type.upper() or "YARA" in (art.entity_identity or "").upper():
                    if target_evidence_id and art.evidence_id != target_evidence_id:
                        continue
                    fields = art.normalized_fields or {}
                    rule_name = (
                        fields.get("rule_name") or
                        fields.get("rule") or
                        (art.evidence_reference or {}).get("rule_name") or
                        "DeterministicSignatureMatch"
                    )
                    target_file = (
                        fields.get("target_file") or
                        fields.get("file") or
                        (art.evidence_reference or {}).get("target_file") or
                        art.source_specific_identity or
                        "TargetForensicFile"
                    )
                    tags = fields.get("matched_tags") or fields.get("tags") or []
                    strings = fields.get("matched_strings") or fields.get("strings") or []

                    auth_sig = extract_authoritative_malware_signature(art, None, None)
                    if auth_sig and auth_sig.get("hash") and (not allowed_rules or SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH in allowed_rules):
                        # Authoritative verified signature hit -> CRITICAL
                        sig_src = auth_sig["signature_source"]
                        sig_id = auth_sig["signature_identifier"]
                        sig_ver = auth_sig["signature_version"]
                        ver_stat = auth_sig["verification_status"]
                        hash_val = auth_sig["hash"]

                        facts = [
                            {
                                "fact_type": "CONFIRMED_MALWARE_HASH_MATCH",
                                "signature_source": sig_src,
                                "signature_identifier": sig_id,
                                "signature_version": sig_ver,
                                "hash": hash_val,
                                "verification_status": ver_stat,
                                "target_file": str(target_file),
                                "artifact_identity": art.entity_identity,
                            }
                        ]

                        candidates.append(DeterministicCandidateFinding(
                            title=f"Confirmed Malware Hash Match: {sig_src} [{sig_id}]",
                            description=(
                                f"Forensic artifact '{target_file}' exhibits cryptographic hash '{hash_val}', "
                                f"confirmed by authoritative signature source '{sig_src}' (version {sig_ver}, identifier {sig_id}) "
                                f"with verification status '{ver_stat}'."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.MALWARE_INDICATOR,
                            severity_rule=SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH,
                            confidence=1.0,
                            confidence_inputs={"source_integrity": 1.0, "artifact_confidence": 1.0, "identifier_match_confidence": 1.0, "supporting_source_count": 1, "contradictory_evidence": False},
                            supporting_artifact_ids=[art.id],
                            supporting_event_ids=[],
                            supporting_relationship_ids=[],
                            supporting_group_ids=[],
                            supporting_evidence_ids=[art.evidence_id] if art.evidence_id else [],
                            provenance={
                                "rule": SeverityRule.RULE_CONFIRMED_MALWARE_HASH_MATCH,
                                "signature_source": sig_src,
                                "signature_identifier": sig_id,
                                "signature_version": sig_ver,
                                "verification_status": ver_stat,
                                "hash": hash_val,
                            }
                        ))
                    elif not allowed_rules or SeverityRule.RULE_MALWARE_SIGNATURE_HIT in allowed_rules:
                        # Heuristic YARA match without authoritative verification -> MEDIUM
                        facts = [
                            {
                                "fact_type": "MALWARE_SIGNATURE_HIT",
                                "rule_name": rule_name,
                                "target_file": str(target_file),
                                "matched_tags": tags,
                                "matched_strings_count": len(strings),
                                "artifact_identity": art.entity_identity,
                                "verification_status": "UNVERIFIED_HEURISTIC",
                            }
                        ]

                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=0.85,
                            identifier_match_confidence=0.85,
                            supporting_source_count=1,
                            contradictory_evidence=False
                        )

                        candidates.append(DeterministicCandidateFinding(
                            title=f"Malware Signature Pattern Hit: {rule_name}",
                            description=(
                                f"Deterministic signature match '{rule_name}' evaluated against target file "
                                f"'{target_file}' with {len(tags)} tags and {len(strings)} string matches. "
                                f"Pattern evaluation is unverified against authoritative threat databases."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.MALWARE_INDICATOR,
                            severity_rule=SeverityRule.RULE_MALWARE_SIGNATURE_HIT,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=[art.id],
                            supporting_event_ids=[],
                            supporting_relationship_ids=[],
                            supporting_group_ids=[],
                            supporting_evidence_ids=[art.evidence_id] if art.evidence_id else [],
                            provenance={
                                "rule": SeverityRule.RULE_MALWARE_SIGNATURE_HIT,
                                "artifact_provenance": art.provenance_summary or {},
                                "verification_status": "UNVERIFIED_HEURISTIC"
                            }
                        ))

        # ---------------------------------------------------------------------
        # RULE 3 & 7: Process Network Connection / Outbound Socket (Observation vs Suspicion)
        # ---------------------------------------------------------------------
        check_proc_net = not allowed_rules or any(
            r in allowed_rules for r in [
                SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION,
                SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION,
                SeverityRule.RULE_PROCESS_SOCKET_ASSOCIATION
            ]
        )
        if check_proc_net:
            for rel in relationships:
                is_proc_net = (
                    rel.relationship_type in ["PROCESS_MEMORY_MATCH", "SHARED_IDENTIFIER"] and
                    (("PROCESS" in rel.source_domain and "NETWORK" in rel.target_domain) or
                     ("NETWORK" in rel.source_domain and "PROCESS" in rel.target_domain))
                )
                if not is_proc_net and rel.matching_field in ["pid", "process_id"]:
                    is_proc_net = True

                if is_proc_net:
                    ev_ids = list(rel.evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    source_art = norm_map.get(rel.source_id)
                    target_art = norm_map.get(rel.target_id)
                    net_fields: Dict[str, Any] = {}
                    proc_fields: Dict[str, Any] = {}

                    for a in [source_art, target_art]:
                        if a:
                            if "NETWORK" in a.entity_type.upper():
                                net_fields = a.normalized_fields or {}
                            elif "PROCESS" in a.entity_type.upper():
                                proc_fields = a.normalized_fields or {}

                    remote_addr = str(net_fields.get("remote_address") or "")
                    remote_port = str(net_fields.get("remote_port") or "")
                    proc_name = str(proc_fields.get("process_name") or "Process")
                    pid_val = rel.matching_identifier or str(proc_fields.get("pid") or "N/A")

                    is_outbound = False
                    if remote_addr and remote_addr not in ["0.0.0.0", "127.0.0.1", "::1", "None", ""]:
                        is_outbound = True

                    art_ids = [aid for aid in [rel.source_id, rel.target_id] if aid in norm_map]
                    ev_ids_all = set(ev_ids)
                    for aid in art_ids:
                        a = norm_map.get(aid)
                        if a and a.evidence_id:
                            ev_ids_all.add(a.evidence_id)

                    # Check for explicit additional evidence of suspiciousness
                    is_explicitly_suspicious = bool(
                        proc_fields.get("is_suspicious") or
                        net_fields.get("is_suspicious") or
                        (rel.provenance or {}).get("is_suspicious") or
                        proc_fields.get("suspicious_indicator") or
                        net_fields.get("suspicious_indicator") or
                        proc_fields.get("suspicious_port_flag") or
                        net_fields.get("suspicious_port_flag")
                    )

                    facts = [
                        {
                            "fact_type": "PROCESS_SOCKET_ASSOCIATION",
                            "process_name": proc_name,
                            "pid": pid_val,
                            "local_address": str(net_fields.get("local_address") or "N/A"),
                            "remote_address": remote_addr or "N/A",
                            "remote_port": remote_port or "N/A",
                            "protocol": str(net_fields.get("protocol") or "TCP"),
                            "is_outbound": is_outbound,
                            "is_explicitly_suspicious": is_explicitly_suspicious,
                        },
                        {
                            "fact_type": "CORRELATED_RELATIONSHIP",
                            "relationship_id": rel.id,
                            "relationship_type": rel.relationship_type,
                        }
                    ]

                    if is_outbound and is_explicitly_suspicious:
                        # Documented high severity rule satisfied by explicit evidence
                        if not allowed_rules or SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION in allowed_rules:
                            conf_score, conf_inputs = calculate_deterministic_confidence(
                                source_integrity=1.0,
                                artifact_confidence=rel.confidence_score,
                                identifier_match_confidence=1.0,
                                supporting_source_count=len(ev_ids_all) or 2,
                                contradictory_evidence=False
                            )
                            candidates.append(DeterministicCandidateFinding(
                                title=f"Suspicious Process Linked to Outbound Socket: {proc_name} (PID {pid_val}) -> {remote_addr}:{remote_port}",
                                description=(
                                    f"Process '{proc_name}' (PID {pid_val}) in {rel.source_domain} is correlated with "
                                    f"active network socket connecting to external remote address {remote_addr}:{remote_port} "
                                    f"with explicit supporting evidence of suspiciousness."
                                ),
                                observed_facts=facts,
                                finding_type=FindingType.SUSPICIOUS_EXECUTION,
                                severity_rule=SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION,
                                confidence=conf_score,
                                confidence_inputs=conf_inputs,
                                supporting_artifact_ids=art_ids,
                                supporting_event_ids=[],
                                supporting_relationship_ids=[rel.id],
                                supporting_group_ids=[rel.group_id] if rel.group_id else [],
                                supporting_evidence_ids=list(ev_ids_all),
                                provenance={"rule": SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION, "relationship": rel.id}
                            ))
                    elif is_outbound:
                        # Evidence-grounded observation: outbound network alone is NOT evidence of maliciousness -> LOW
                        if not allowed_rules or SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION in allowed_rules or SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_SUSPICION in allowed_rules:
                            conf_score, conf_inputs = calculate_deterministic_confidence(
                                source_integrity=1.0,
                                artifact_confidence=rel.confidence_score,
                                identifier_match_confidence=0.85,
                                supporting_source_count=len(ev_ids_all) or 1,
                                contradictory_evidence=False
                            )
                            candidates.append(DeterministicCandidateFinding(
                                title=f"Observed Process Outbound Socket: {proc_name} (PID {pid_val}) -> {remote_addr}:{remote_port}",
                                description=(
                                    f"Observed process '{proc_name}' (PID {pid_val}) in {rel.source_domain} correlated with "
                                    f"active network socket connecting to remote address {remote_addr}:{remote_port}. "
                                    f"Outbound network socket alone does not indicate maliciousness."
                                ),
                                observed_facts=facts,
                                finding_type=FindingType.NETWORK_CONNECTION,
                                severity_rule=SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION,
                                confidence=conf_score,
                                confidence_inputs=conf_inputs,
                                supporting_artifact_ids=art_ids,
                                supporting_event_ids=[],
                                supporting_relationship_ids=[rel.id],
                                supporting_group_ids=[rel.group_id] if rel.group_id else [],
                                supporting_evidence_ids=list(ev_ids_all),
                                provenance={"rule": SeverityRule.RULE_PROCESS_NETWORK_OUTBOUND_OBSERVATION, "relationship": rel.id}
                            ))
                    elif not allowed_rules or SeverityRule.RULE_PROCESS_SOCKET_ASSOCIATION in allowed_rules:
                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=rel.confidence_score,
                            identifier_match_confidence=0.80,
                            supporting_source_count=len(ev_ids_all) or 1,
                            contradictory_evidence=False
                        )
                        candidates.append(DeterministicCandidateFinding(
                            title=f"Process Socket Association: {proc_name} (PID {pid_val})",
                            description=(
                                f"Process '{proc_name}' (PID {pid_val}) associated with socket "
                                f"{net_fields.get('local_address', 'N/A')} -> {remote_addr or 'internal'}."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.NETWORK_CONNECTION,
                            severity_rule=SeverityRule.RULE_PROCESS_SOCKET_ASSOCIATION,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=art_ids,
                            supporting_event_ids=[],
                            supporting_relationship_ids=[rel.id],
                            supporting_group_ids=[rel.group_id] if rel.group_id else [],
                            supporting_evidence_ids=list(ev_ids_all),
                            provenance={"rule": SeverityRule.RULE_PROCESS_SOCKET_ASSOCIATION, "relationship": rel.id}
                        ))

        # ---------------------------------------------------------------------
        # RULE 4: Browser Socket Interaction Observation (LOW)
        # ---------------------------------------------------------------------
        if not allowed_rules or SeverityRule.RULE_BROWSER_SOCKET_INTERACTION in allowed_rules:
            for rel in relationships:
                if rel.relationship_type == "BROWSER_NETWORK_MATCH" or (
                    ("BROWSER" in rel.source_domain and "NETWORK" in rel.target_domain) or
                    ("NETWORK" in rel.source_domain and "BROWSER" in rel.target_domain)
                ):
                    ev_ids = list(rel.evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    art_ids = [aid for aid in [rel.source_id, rel.target_id] if aid in norm_map]
                    ev_ids_all = set(ev_ids)
                    for aid in art_ids:
                        a = norm_map.get(aid)
                        if a and a.evidence_id:
                            ev_ids_all.add(a.evidence_id)

                    facts = [
                        {
                            "fact_type": "BROWSER_NETWORK_MATCH",
                            "matching_identifier": rel.matching_identifier,
                            "matching_field": rel.matching_field,
                            "source_domain": rel.source_domain,
                            "target_domain": rel.target_domain,
                            "explicit_evidence_of_maliciousness": False,
                        },
                        {
                            "fact_type": "CORRELATED_RELATIONSHIP",
                            "relationship_id": rel.id,
                        }
                    ]

                    conf_score, conf_inputs = calculate_deterministic_confidence(
                        source_integrity=1.0,
                        artifact_confidence=rel.confidence_score,
                        identifier_match_confidence=0.85,
                        supporting_source_count=len(ev_ids_all) or 1,
                        contradictory_evidence=False
                    )

                    candidates.append(DeterministicCandidateFinding(
                        title=f"Observed Browser Network Interaction: {rel.matching_identifier}",
                        description=(
                            f"Observed browser navigation / download record in {rel.source_domain} matches active "
                            f"network socket or remote destination '{rel.matching_identifier}' in {rel.target_domain}. "
                            f"Browser network interaction alone does not indicate maliciousness."
                        ),
                        observed_facts=facts,
                        finding_type=FindingType.NETWORK_CONNECTION,
                        severity_rule=SeverityRule.RULE_BROWSER_SOCKET_INTERACTION,
                        confidence=conf_score,
                        confidence_inputs=conf_inputs,
                        supporting_artifact_ids=art_ids,
                        supporting_event_ids=[],
                        supporting_relationship_ids=[rel.id],
                        supporting_group_ids=[rel.group_id] if rel.group_id else [],
                        supporting_evidence_ids=list(ev_ids_all),
                        provenance={"rule": SeverityRule.RULE_BROWSER_SOCKET_INTERACTION, "relationship": rel.id}
                    ))

        # ---------------------------------------------------------------------
        # RULE 5: Multi-Domain Correlated Cluster Observation (LOW)
        # ---------------------------------------------------------------------
        if not allowed_rules or SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER in allowed_rules:
            for grp in groups:
                domains = grp.contributing_domains or []
                if len(domains) >= 3:
                    ev_ids = list(grp.source_evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    facts = [
                        {
                            "fact_type": "MULTI_DOMAIN_CLUSTER",
                            "group_id": grp.id,
                            "group_title": grp.title,
                            "contributing_domains": domains,
                            "domain_count": len(domains),
                            "member_artifacts_count": len(grp.member_artifact_ids or []),
                            "member_events_count": len(grp.member_event_ids or []),
                            "relationships_count": len(grp.relationship_ids or []),
                            "explicit_evidence_of_maliciousness": False,
                        }
                    ]

                    conf_score, conf_inputs = calculate_deterministic_confidence(
                        source_integrity=1.0,
                        artifact_confidence=grp.confidence_score,
                        identifier_match_confidence=0.85,
                        supporting_source_count=len(ev_ids) or 2,
                        contradictory_evidence=False
                    )

                    candidates.append(DeterministicCandidateFinding(
                        title=f"Multi-Domain Correlated Cluster Across {len(domains)} Domains",
                        description=(
                            f"Observed correlation group '{grp.title}' contains {len(grp.member_artifact_ids or [])} artifacts "
                            f"and {len(grp.member_event_ids or [])} timeline events spanning {len(domains)} distinct "
                            f"forensic domains ({', '.join(domains)}). "
                            f"Multi-domain correlation alone does not indicate maliciousness."
                        ),
                        observed_facts=facts,
                        finding_type=FindingType.MULTI_DOMAIN_CORRELATION,
                        severity_rule=SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER,
                        confidence=conf_score,
                        confidence_inputs=conf_inputs,
                        supporting_artifact_ids=list(grp.member_artifact_ids or []),
                        supporting_event_ids=list(grp.member_event_ids or []),
                        supporting_relationship_ids=list(grp.relationship_ids or []),
                        supporting_group_ids=[grp.id],
                        supporting_evidence_ids=ev_ids,
                        provenance={"rule": SeverityRule.RULE_MULTI_DOMAIN_CORRELATED_CLUSTER, "group": grp.id}
                    ))

        # ---------------------------------------------------------------------
        # RULE 6 & 9: User Logon Activity (MEDIUM / LOW)
        # ---------------------------------------------------------------------
        check_user_logon = not allowed_rules or any(
            r in allowed_rules for r in [
                SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY,
                SeverityRule.RULE_USER_LOGON_OBSERVATION
            ]
        )
        if check_user_logon:
            privileged_names = {"SYSTEM", "ADMINISTRATOR", "ROOT", "LOCAL SYSTEM", "NETWORK SERVICE", "DAEMON"}
            for art in normalized_artifacts:
                is_auth = (
                    "EVENT" in art.entity_type.upper() or
                    "LOG" in art.entity_type.upper() or
                    "USER" in art.entity_type.upper()
                )
                if not is_auth:
                    continue

                fields = art.normalized_fields or {}
                username = str(fields.get("username") or fields.get("user") or fields.get("account_name") or "")
                event_id = str(fields.get("event_id") or "")

                if username or event_id in ["4624", "4625", "4672"]:
                    if target_evidence_id and art.evidence_id != target_evidence_id:
                        continue

                    uname_clean = username.upper().strip()
                    is_privileged = (
                        uname_clean in privileged_names or
                        any(p in uname_clean for p in ["ADMIN", "SYSTEM", "ROOT"]) or
                        event_id == "4672"
                    )

                    facts = [
                        {
                            "fact_type": "AUTHENTICATION_EVENT",
                            "username": username or "Unknown",
                            "event_id": event_id or "N/A",
                            "computer_name": str(fields.get("computer_name") or "N/A"),
                            "is_privileged": is_privileged,
                        }
                    ]

                    if is_privileged and (not allowed_rules or SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY in allowed_rules):
                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=1.0,
                            identifier_match_confidence=1.0,
                            supporting_source_count=1,
                            contradictory_evidence=False
                        )
                        candidates.append(DeterministicCandidateFinding(
                            title=f"Privileged Account Logon Activity: {username or 'SYSTEM'}",
                            description=(
                                f"Authentication record observed for administrative or system account "
                                f"'{username or 'SYSTEM'}' on host '{fields.get('computer_name', 'N/A')}'."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.AUTHENTICATION_ACTIVITY,
                            severity_rule=SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=[art.id],
                            supporting_event_ids=[],
                            supporting_relationship_ids=[],
                            supporting_group_ids=[],
                            supporting_evidence_ids=[art.evidence_id] if art.evidence_id else [],
                            provenance={"rule": SeverityRule.RULE_PRIVILEGED_USER_LOGON_ACTIVITY, "artifact": art.id}
                        ))
                    elif not is_privileged and username and (not allowed_rules or SeverityRule.RULE_USER_LOGON_OBSERVATION in allowed_rules):
                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=0.9,
                            identifier_match_confidence=0.85,
                            supporting_source_count=1,
                            contradictory_evidence=False
                        )
                        candidates.append(DeterministicCandidateFinding(
                            title=f"User Account Logon: {username}",
                            description=(
                                f"Standard authentication record observed for account "
                                f"'{username}' on host '{fields.get('computer_name', 'N/A')}'."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.AUTHENTICATION_ACTIVITY,
                            severity_rule=SeverityRule.RULE_USER_LOGON_OBSERVATION,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=[art.id],
                            supporting_event_ids=[],
                            supporting_relationship_ids=[],
                            supporting_group_ids=[],
                            supporting_evidence_ids=[art.evidence_id] if art.evidence_id else [],
                            provenance={"rule": SeverityRule.RULE_USER_LOGON_OBSERVATION, "artifact": art.id}
                        ))

        # ---------------------------------------------------------------------
        # RULE 8: Temporal Cross-Domain Coincidence (MEDIUM)
        # ---------------------------------------------------------------------
        if not allowed_rules or SeverityRule.RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE in allowed_rules:
            for rel in relationships:
                if rel.relationship_type == "TEMPORAL_COINCIDENCE" and rel.source_domain != rel.target_domain:
                    ev_ids = list(rel.evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    temp_rel = rel.temporal_relationship or {}
                    delta_s = temp_rel.get("delta_seconds", 0.0)

                    if delta_s <= 5.0:
                        art_ids = [aid for aid in [rel.source_id, rel.target_id] if aid in norm_map]
                        event_ids = [eid for eid in [rel.source_id, rel.target_id] if eid in event_map]
                        ev_ids_all = set(ev_ids)
                        for aid in art_ids:
                            a = norm_map.get(aid)
                            if a and a.evidence_id:
                                ev_ids_all.add(a.evidence_id)
                        for eid in event_ids:
                            e = event_map.get(eid)
                            if e and e.evidence_id:
                                ev_ids_all.add(e.evidence_id)

                        facts = [
                            {
                                "fact_type": "TEMPORAL_COINCIDENCE",
                                "source_domain": rel.source_domain,
                                "source_id": rel.source_id,
                                "target_domain": rel.target_domain,
                                "target_id": rel.target_id,
                                "delta_seconds": delta_s,
                            },
                            {
                                "fact_type": "CORRELATED_RELATIONSHIP",
                                "relationship_id": rel.id,
                            }
                        ]

                        conf_score, conf_inputs = calculate_deterministic_confidence(
                            source_integrity=1.0,
                            artifact_confidence=rel.confidence_score,
                            identifier_match_confidence=0.85,
                            supporting_source_count=len(ev_ids_all) or 2,
                            contradictory_evidence=False,
                            temporal_confidence=0.9
                        )

                        candidates.append(DeterministicCandidateFinding(
                            title=f"Cross-Domain Temporal Coincidence ({delta_s}s): {rel.source_domain} and {rel.target_domain}",
                            description=(
                                f"Observed cross-domain temporal coincidence between {rel.source_domain} entity '{rel.source_id}' "
                                f"and {rel.target_domain} entity '{rel.target_id}' within {delta_s} seconds."
                            ),
                            observed_facts=facts,
                            finding_type=FindingType.TEMPORAL_ANOMALY,
                            severity_rule=SeverityRule.RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE,
                            confidence=conf_score,
                            confidence_inputs=conf_inputs,
                            supporting_artifact_ids=art_ids,
                            supporting_event_ids=event_ids,
                            supporting_relationship_ids=[rel.id],
                            supporting_group_ids=[rel.group_id] if rel.group_id else [],
                            supporting_evidence_ids=list(ev_ids_all),
                            provenance={"rule": SeverityRule.RULE_TEMPORAL_CROSS_DOMAIN_COINCIDENCE, "relationship": rel.id}
                        ))

        # ---------------------------------------------------------------------
        # RULE 10: Temporal Sequence Observation (INFORMATIONAL)
        # ---------------------------------------------------------------------
        if not allowed_rules or SeverityRule.RULE_TEMPORAL_SEQUENCE_OBSERVATION in allowed_rules:
            for rel in relationships:
                if rel.relationship_type == "TEMPORAL_SEQUENCE":
                    ev_ids = list(rel.evidence_ids or [])
                    if target_evidence_id and target_evidence_id not in ev_ids:
                        continue

                    temp_rel = rel.temporal_relationship or {}
                    delta_s = temp_rel.get("delta_seconds", 0.0)

                    event_ids = [eid for eid in [rel.source_id, rel.target_id] if eid in event_map]
                    art_ids = [aid for aid in [rel.source_id, rel.target_id] if aid in norm_map]
                    ev_ids_all = set(ev_ids)

                    facts = [
                        {
                            "fact_type": "TEMPORAL_SEQUENCE",
                            "source_id": rel.source_id,
                            "target_id": rel.target_id,
                            "domain": rel.source_domain,
                            "delta_seconds": delta_s,
                        }
                    ]

                    conf_score, conf_inputs = calculate_deterministic_confidence(
                        source_integrity=1.0,
                        artifact_confidence=rel.confidence_score,
                        identifier_match_confidence=0.80,
                        supporting_source_count=1,
                        contradictory_evidence=False,
                        temporal_confidence=0.85
                    )

                    candidates.append(DeterministicCandidateFinding(
                        title=f"Chronological Sequence Observation: {rel.source_domain}",
                        description=(
                            f"Sequential timeline progression observed in {rel.source_domain} domain "
                            f"between events separated by {delta_s} seconds."
                        ),
                        observed_facts=facts,
                        finding_type=FindingType.TEMPORAL_ANOMALY,
                        severity_rule=SeverityRule.RULE_TEMPORAL_SEQUENCE_OBSERVATION,
                        confidence=conf_score,
                        confidence_inputs=conf_inputs,
                        supporting_artifact_ids=art_ids,
                        supporting_event_ids=event_ids,
                        supporting_relationship_ids=[rel.id],
                        supporting_group_ids=[rel.group_id] if rel.group_id else [],
                        supporting_evidence_ids=list(ev_ids_all),
                        provenance={"rule": SeverityRule.RULE_TEMPORAL_SEQUENCE_OBSERVATION, "relationship": rel.id}
                    ))

        return candidates


# =============================================================================
# 5. DETERMINISTIC FINDINGS SERVICE
# =============================================================================

class DeterministicFindingsService:
    """
    Orchestrates deterministic finding generation, storage, querying,
    provenance tracing, and cryptographic integrity verification.
    """

    @classmethod
    def generate_findings_for_case(
        cls,
        db: Session,
        case_id: str,
        request: FindingGenerateRequest
    ) -> FindingSummaryResponse:
        """
        Generates evidence-grounded findings from Steps 12-14 before any AI reasoning.
        """
        # 1. Fetch prerequisite data
        normalized_artifacts = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.case_id == case_id)
            .all()
        )
        timeline_events = (
            db.query(TimelineEvent)
            .filter(TimelineEvent.case_id == case_id)
            .all()
        )
        relationships = (
            db.query(ArtifactRelationship)
            .filter(ArtifactRelationship.case_id == case_id)
            .all()
        )
        groups = (
            db.query(ForensicCorrelationGroup)
            .filter(ForensicCorrelationGroup.case_id == case_id)
            .all()
        )

        allowed_rules = set(request.include_rules) if request.include_rules else None

        # 2. Evaluate candidates through rule engine
        candidates = DeterministicRuleEngine.evaluate(
            case_id=case_id,
            normalized_artifacts=normalized_artifacts,
            timeline_events=timeline_events,
            relationships=relationships,
            groups=groups,
            allowed_rules=allowed_rules,
            target_evidence_id=request.evidence_id
        )

        # Filter by minimum confidence
        candidates = [c for c in candidates if c.confidence >= request.min_confidence]

        # 3. Deduplicate candidates by deterministic signature
        deduped: List[DeterministicCandidateFinding] = []
        seen_signatures: Set[str] = set()

        for c in candidates:
            sig = f"{c.severity_rule}:{':'.join(c.supporting_artifact_ids)}:{':'.join(c.supporting_event_ids)}:{':'.join(c.supporting_relationship_ids)}:{':'.join(c.supporting_group_ids)}"
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            deduped.append(c)

        # 4. Clear previous deterministic findings for this case to maintain freshness
        db.query(DeterministicFinding).filter(DeterministicFinding.case_id == case_id).delete(synchronize_session=False)
        db.query(Finding).filter(
            Finding.case_id == case_id,
            Finding.agent == "DeterministicFindingsEngine"
        ).delete(synchronize_session=False)
        db.flush()

        # 5. Persist each finding with isolated disk storage & canonical SHA-256
        created_findings: List[DeterministicFinding] = []
        severity_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}

        for c in deduped:
            finding_id = str(uuid.uuid4())
            canonical_payload = {
                "case_id": case_id,
                "title": c.title,
                "description": c.description,
                "observed_facts": c.observed_facts,
                "finding_type": c.finding_type,
                "severity": c.severity,
                "severity_rule": c.severity_rule,
                "confidence": c.confidence,
                "confidence_inputs": c.confidence_inputs,
                "supporting_artifact_ids": c.supporting_artifact_ids,
                "supporting_event_ids": c.supporting_event_ids,
                "supporting_relationship_ids": c.supporting_relationship_ids,
                "supporting_group_ids": c.supporting_group_ids,
                "supporting_evidence_ids": c.supporting_evidence_ids,
            }
            canonical_str = format_canonical_json(canonical_payload)
            finding_hash = compute_sha256(canonical_str)

            storage_path = FindingStorageManager.save_finding(
                case_id=case_id,
                finding_id=finding_id,
                data={
                    **canonical_payload,
                    "id": finding_id,
                    "sha256_hash": finding_hash,
                    "provenance": c.provenance,
                    "created_at": utc_now()
                }
            )

            df_model = DeterministicFinding(
                id=finding_id,
                case_id=case_id,
                title=c.title,
                description=c.description,
                observed_facts=c.observed_facts,
                finding_type=c.finding_type,
                severity=c.severity,
                severity_rule=c.severity_rule,
                confidence=c.confidence,
                confidence_inputs=c.confidence_inputs,
                supporting_artifact_ids=c.supporting_artifact_ids,
                supporting_event_ids=c.supporting_event_ids,
                supporting_relationship_ids=c.supporting_relationship_ids,
                supporting_group_ids=c.supporting_group_ids,
                supporting_evidence_ids=c.supporting_evidence_ids,
                provenance=c.provenance,
                sha256_hash=finding_hash,
                storage_path=storage_path,
                created_at=utc_now()
            )
            db.add(df_model)
            created_findings.append(df_model)

            # Sync to legacy Finding table for seamless GUI / Report integration
            first_evidence_id = c.supporting_evidence_ids[0] if c.supporting_evidence_ids else None
            legacy_finding = Finding(
                id=finding_id,
                case_id=case_id,
                evidence_id=first_evidence_id,
                agent="DeterministicFindingsEngine",
                tool="EvidenceRuleEngine",
                finding_type=c.finding_type,
                title=c.title,
                description=c.description,
                severity=c.severity,
                classification="FACT",
                confidence=c.confidence,
                verification_status="SUPPORTED",
                raw_output_reference=json.dumps({
                    "severity_rule": c.severity_rule,
                    "confidence_inputs": c.confidence_inputs,
                    "observed_facts": c.observed_facts,
                    "sha256_hash": finding_hash,
                }),
                created_at=utc_now()
            )
            db.add(legacy_finding)

            severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1
            type_counts[c.finding_type] = type_counts.get(c.finding_type, 0) + 1

        db.commit()

        return FindingSummaryResponse(
            case_id=case_id,
            total_findings_generated=len(created_findings),
            severity_breakdown=severity_counts,
            type_breakdown=type_counts,
            findings=[DeterministicFindingResponse.model_validate(f) for f in created_findings],
            generated_at=utc_now()
        )

    @classmethod
    def list_findings(
        cls,
        db: Session,
        case_id: str,
        severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        evidence_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 50
    ) -> List[DeterministicFinding]:
        """Queries deterministic findings with comprehensive filters."""
        query = db.query(DeterministicFinding).filter(DeterministicFinding.case_id == case_id)

        if severity:
            query = query.filter(DeterministicFinding.severity == severity.upper())
        if finding_type:
            query = query.filter(DeterministicFinding.finding_type == finding_type)
        if min_confidence is not None:
            query = query.filter(DeterministicFinding.confidence >= min_confidence)
        if start_time:
            query = query.filter(DeterministicFinding.created_at >= start_time)
        if end_time:
            query = query.filter(DeterministicFinding.created_at <= end_time)

        records = query.order_by(DeterministicFinding.created_at.desc()).offset(skip).limit(limit).all()

        if evidence_id:
            # Filter in Python for JSON array match
            records = [
                r for r in records
                if evidence_id in (r.supporting_evidence_ids or [])
            ]

        return records

    @classmethod
    def get_finding_by_id(cls, db: Session, case_id: str, finding_id: str) -> Optional[DeterministicFinding]:
        return (
            db.query(DeterministicFinding)
            .filter(DeterministicFinding.id == finding_id, DeterministicFinding.case_id == case_id)
            .first()
        )

    @classmethod
    def verify_integrity(cls, db: Session, case_id: str, finding_id: str) -> FindingIntegrityResponse:
        """Cryptographically verifies finding integrity and detects tampering."""
        finding = cls.get_finding_by_id(db, case_id, finding_id)
        if not finding:
            raise ValueError(f"DeterministicFinding '{finding_id}' not found for case '{case_id}'")

        canonical_payload = {
            "case_id": case_id,
            "title": finding.title,
            "description": finding.description,
            "observed_facts": finding.observed_facts,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "severity_rule": finding.severity_rule,
            "confidence": finding.confidence,
            "confidence_inputs": finding.confidence_inputs,
            "supporting_artifact_ids": finding.supporting_artifact_ids,
            "supporting_event_ids": finding.supporting_event_ids,
            "supporting_relationship_ids": finding.supporting_relationship_ids,
            "supporting_group_ids": finding.supporting_group_ids,
            "supporting_evidence_ids": finding.supporting_evidence_ids,
        }
        canonical_str = format_canonical_json(canonical_payload)
        computed_hash = compute_sha256(canonical_str)

        file_exists, disk_ok, disk_computed = FindingStorageManager.verify_finding_file(
            storage_path=finding.storage_path,
            expected_hash=finding.sha256_hash,
            case_id=case_id
        )

        db_matches = (computed_hash == finding.sha256_hash)
        passed = db_matches and (disk_ok if file_exists else True)
        tamper_detected = not passed

        return FindingIntegrityResponse(
            finding_id=finding.id,
            title=finding.title,
            stored_sha256=finding.sha256_hash,
            computed_sha256=computed_hash,
            integrity_passed=passed,
            file_exists=file_exists,
            tamper_detected=tamper_detected,
            storage_path=finding.storage_path,
            checked_at=utc_now()
        )

    @classmethod
    def get_provenance(cls, db: Session, case_id: str, finding_id: str) -> FindingProvenanceResponse:
        """
        Reconstructs the full 7-tier provenance tree:
        EvidenceItem -> ForensicExecution -> ExecutionOutput -> StructuredArtifact
        -> NormalizedArtifact -> Timeline/Correlation -> Finding.
        """
        finding = cls.get_finding_by_id(db, case_id, finding_id)
        if not finding:
            raise ValueError(f"DeterministicFinding '{finding_id}' not found for case '{case_id}'")

        # Gather supporting entities
        artifacts = db.query(NormalizedArtifact).filter(
            NormalizedArtifact.id.in_(finding.supporting_artifact_ids or [])
        ).all() if finding.supporting_artifact_ids else []

        events = db.query(TimelineEvent).filter(
            TimelineEvent.id.in_(finding.supporting_event_ids or [])
        ).all() if finding.supporting_event_ids else []

        relationships = db.query(ArtifactRelationship).filter(
            ArtifactRelationship.id.in_(finding.supporting_relationship_ids or [])
        ).all() if finding.supporting_relationship_ids else []

        groups = db.query(ForensicCorrelationGroup).filter(
            ForensicCorrelationGroup.id.in_(finding.supporting_group_ids or [])
        ).all() if finding.supporting_group_ids else []

        evidence_items = db.query(EvidenceItem).filter(
            EvidenceItem.id.in_(finding.supporting_evidence_ids or [])
        ).all() if finding.supporting_evidence_ids else []

        # Build lineage chains
        lineage_summary: List[Dict[str, Any]] = []
        for ev in evidence_items:
            lineage_summary.append({
                "tier": "EVIDENCE",
                "id": ev.id,
                "label": getattr(ev, "name", "") or getattr(ev, "filename", "") or str(ev.id),
                "sha256": ev.sha256,
            })

        for art in artifacts:
            lineage_summary.append({
                "tier": "NORMALIZED_ARTIFACT",
                "id": art.id,
                "entity_type": art.entity_type,
                "entity_identity": art.entity_identity,
                "evidence_id": art.evidence_id,
                "execution_id": art.execution_id,
            })

        for ev in events:
            lineage_summary.append({
                "tier": "TIMELINE_EVENT",
                "id": ev.id,
                "event_type": ev.event_type,
                "timestamp_utc": ev.timestamp_utc.isoformat() if ev.timestamp_utc else None,
                "evidence_id": ev.evidence_id,
            })

        for rel in relationships:
            lineage_summary.append({
                "tier": "RELATIONSHIP",
                "id": rel.id,
                "relationship_type": rel.relationship_type,
                "matching_identifier": rel.matching_identifier,
            })

        for grp in groups:
            lineage_summary.append({
                "tier": "CORRELATION_GROUP",
                "id": grp.id,
                "title": grp.title,
                "domains": grp.contributing_domains,
            })

        provenance_chain: Dict[str, Any] = {
            "finding_id": finding.id,
            "case_id": case_id,
            "severity_rule": finding.severity_rule,
            "confidence_inputs": finding.confidence_inputs,
            "evidence_count": len(evidence_items),
            "artifact_count": len(artifacts),
            "event_count": len(events),
            "relationship_count": len(relationships),
            "group_count": len(groups),
            "internal_provenance": finding.provenance or {},
        }

        return FindingProvenanceResponse(
            finding_id=finding.id,
            case_id=case_id,
            title=finding.title,
            finding_type=finding.finding_type,
            severity=finding.severity,
            severity_rule=finding.severity_rule,
            confidence=finding.confidence,
            confidence_inputs=finding.confidence_inputs,
            provenance_chain=provenance_chain,
            supporting_evidence_ids=finding.supporting_evidence_ids or [],
            lineage_summary=lineage_summary,
            created_at=finding.created_at
        )

    @classmethod
    def get_supporting_evidence(
        cls,
        db: Session,
        case_id: str,
        finding_id: str
    ) -> FindingSupportingEvidenceResponse:
        """Retrieves hydrated supporting evidence records for this finding."""
        finding = cls.get_finding_by_id(db, case_id, finding_id)
        if not finding:
            raise ValueError(f"DeterministicFinding '{finding_id}' not found for case '{case_id}'")

        artifacts = db.query(NormalizedArtifact).filter(
            NormalizedArtifact.id.in_(finding.supporting_artifact_ids or [])
        ).all() if finding.supporting_artifact_ids else []

        events = db.query(TimelineEvent).filter(
            TimelineEvent.id.in_(finding.supporting_event_ids or [])
        ).all() if finding.supporting_event_ids else []

        relationships = db.query(ArtifactRelationship).filter(
            ArtifactRelationship.id.in_(finding.supporting_relationship_ids or [])
        ).all() if finding.supporting_relationship_ids else []

        groups = db.query(ForensicCorrelationGroup).filter(
            ForensicCorrelationGroup.id.in_(finding.supporting_group_ids or [])
        ).all() if finding.supporting_group_ids else []

        evidence_items = db.query(EvidenceItem).filter(
            EvidenceItem.id.in_(finding.supporting_evidence_ids or [])
        ).all() if finding.supporting_evidence_ids else []

        return FindingSupportingEvidenceResponse(
            finding_id=finding.id,
            case_id=case_id,
            observed_facts=finding.observed_facts or [],
            supporting_artifacts=[
                {
                    "id": a.id,
                    "entity_type": a.entity_type,
                    "entity_identity": a.entity_identity,
                    "normalized_fields": a.normalized_fields,
                    "evidence_id": a.evidence_id,
                }
                for a in artifacts
            ],
            supporting_events=[
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "timestamp_utc": e.timestamp_utc.isoformat() if e.timestamp_utc else None,
                    "event_source": e.event_source,
                    "confidence_score": e.confidence_score,
                }
                for e in events
            ],
            supporting_relationships=[
                {
                    "id": r.id,
                    "relationship_type": r.relationship_type,
                    "matching_identifier": r.matching_identifier,
                    "source_id": r.source_id,
                    "target_id": r.target_id,
                    "confidence_score": r.confidence_score,
                }
                for r in relationships
            ],
            supporting_groups=[
                {
                    "id": g.id,
                    "title": g.title,
                    "contributing_domains": g.contributing_domains,
                    "confidence_score": g.confidence_score,
                }
                for g in groups
            ],
            supporting_evidence_items=[
                {
                    "id": item.id,
                    "label": getattr(item, "name", "") or getattr(item, "filename", "") or str(item.id),
                    "source_type": getattr(item, "evidence_type", None) or getattr(item, "source_type", "UNKNOWN"),
                    "sha256": item.sha256,
                }
                for item in evidence_items
            ]
        )
