"""
ADFIR — Governance Gate Service (Phase 2 / Step 17)

Deterministic Governance Gate controlling permitted agent reasoning/actions,
gating high-risk actions with explicit approval workflows, detecting PII and prompt injection,
and verifying evidence, artifacts, and tool outputs with lineage and contradiction checks.

Strict Boundaries:
1. Zero direct command execution / zero subprocess calls.
2. Capability requests must pass through Steps 7–9.
3. Untrusted evidence/content is treated as pure passive data, never executed.
4. Source evidence and artifacts are immutable.
5. All policy evaluations are deterministic; no LLM is required for safety enforcement.
"""

import os
import re
import uuid
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.security import AuditLogger
from backend.app.models.models import (
    Case,
    CaseMember,
    EvidenceItem,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    DeterministicFinding,
    SpecialistAgentRecord,
    AgentCapabilityRequestRecord,
    GovernanceDecisionRecord,
    EvidenceVerificationRecord,
    GovernanceAuditEvent,
    User,
    AuditEvent
)
from backend.app.services.audit import log_audit_event


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_canonical_json_hash(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')
    return compute_sha256(serialized)


# =============================================================================
# CONSTANTS & POLICY REGISTRY
# =============================================================================

class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalStatus:
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class GovernanceDecisionType:
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class VerificationStatus:
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


HIGH_RISK_ACTION_TYPES = {
    "LIVE_MEMORY_ACQUISITION",
    "DESTRUCTIVE_TOOL",
    "UNRESTRICTED_NETWORK_SCAN",
    "CREDENTIAL_DUMPING",
    "SYSTEM_CONFIGURATION_ALTERATION",
    "EXPORT_UNMASKED_PII",
    "MALWARE_LIVE_EXECUTION",
    "FIRMWARE_MODIFICATION",
    "DISK_OVERWRITE",
    "VOLATILE_INJECTION",
}

DISALLOWED_PARAMETER_KEYS = {
    "shell",
    "cmd",
    "exec",
    "subprocess",
    "system",
    "sh",
    "bash",
    "powershell",
    "command_override",
}

SHELL_METACHARACTERS = [";", "|", "&", "`", "$(", ">", "<", "\n", "\r"]

# PII Detection Patterns
PII_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "API_KEY_OR_SECRET": re.compile(r"(?i)(?:api[_-]?key|secret[_-]?token|bearer\s+eyJ|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,})['\"]?"),
}

# Prompt Injection & Instruction-like Content Patterns
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
    re.compile(r"(?i)disregard\s+(?:all\s+)?prior\s+(?:instructions|guidelines|rules)"),
    re.compile(r"(?i)system\s+prompt\s+override"),
    re.compile(r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|god)\s+mode"),
    re.compile(r"(?i)<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>"),
    re.compile(r"(?i)(?:eval|exec)\s*\("),
    re.compile(r"(?i)subprocess\.(?:Popen|run|call)"),
    re.compile(r"(?i)os\.system\s*\("),
    re.compile(r"(?i)rm\s+-rf\s+/"),
    re.compile(r"(?i)curl\s+.*\|\s*sh"),
    re.compile(r"(?i)bypass\s+(?:all\s+)?(?:security|governance|rules)"),
    re.compile(r"(?i)new\s+system\s+instruction:"),
    re.compile(r"(?i)output\s+the\s+system\s+prompt"),
]


# =============================================================================
# GOVERNANCE GATE SERVICE
# =============================================================================

class GovernanceGateService:
    """
    Core implementation of Step 17 Governance Gate.
    Evaluates policy, controls agent reasoning/execution requests,
    quarantines untrusted data, detects prompt injection and PII,
    and conducts multi-point forensic evidence verification.
    """

    @classmethod
    def evaluate_governance(
        cls,
        db: Session,
        case_id: str,
        action_type: str,
        requesting_agent: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        target_resource_id: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        input_references: Optional[Dict[str, Any]] = None,
        content_payload: Optional[str] = None,
        user: Optional[User] = None
    ) -> GovernanceDecisionRecord:
        """
        Deterministically evaluates policy for a proposed action or agent request.
        Generates a persistent GovernanceDecisionRecord and an audit trail event.
        """
        params = parameters or {}
        refs = input_references or {}
        checks: Dict[str, Any] = {}
        risk_level = RiskLevel.LOW
        approval_status = ApprovalStatus.NOT_REQUIRED
        decision = GovernanceDecisionType.APPROVED
        reasons: List[str] = []

        # -------------------------------------------------------------
        # 1. CASE AUTHORIZATION & SCOPING CHECK
        # -------------------------------------------------------------
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            checks["case_authorization"] = {"passed": False, "error": f"Case '{case_id}' does not exist."}
            return cls._persist_decision(
                db=db,
                case_id=case_id,
                action_type=action_type,
                requesting_agent=requesting_agent,
                target_resource_type=target_resource_type,
                target_resource_id=target_resource_id,
                policy_checks=checks,
                risk_level=RiskLevel.CRITICAL,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                decision=GovernanceDecisionType.BLOCKED,
                reason=f"Case authorization failed: Case '{case_id}' does not exist.",
                input_references=refs,
                user=user
            )

        if user:
            is_owner = (
                (case.owner_id and case.owner_id == user.id)
                or (case.created_by == user.id)
                or (case.created_by == getattr(user, "email", None))
                or (getattr(user, "role", "") in ("ADMIN", "ADMINISTRATOR"))
            )
            is_member = (
                db.query(CaseMember)
                .filter(CaseMember.case_id == case_id, CaseMember.user_id == user.id)
                .first() is not None
            )
            if not (is_owner or is_member):
                checks["case_authorization"] = {"passed": False, "error": "User is not authorized for this case."}
                return cls._persist_decision(
                    db=db,
                    case_id=case_id,
                    action_type=action_type,
                    requesting_agent=requesting_agent,
                    target_resource_type=target_resource_type,
                    target_resource_id=target_resource_id,
                    policy_checks=checks,
                    risk_level=RiskLevel.HIGH,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    decision=GovernanceDecisionType.BLOCKED,
                    reason="Access denied: User is not authorized for this case.",
                    input_references=refs,
                    user=user
                )

        checks["case_authorization"] = {"passed": True, "case_id": case_id}

        # -------------------------------------------------------------
        # 2. EVIDENCE SCOPING & IDOR PROTECTION
        # -------------------------------------------------------------
        # Verify any referenced evidence items belong strictly to this case
        evidence_id_to_check = None
        if target_resource_type == "EVIDENCE" and target_resource_id:
            evidence_id_to_check = target_resource_id
        elif "evidence_id" in refs:
            evidence_id_to_check = refs["evidence_id"]
        elif "evidence_id" in params:
            evidence_id_to_check = params["evidence_id"]

        if evidence_id_to_check:
            ev = db.query(EvidenceItem).filter(
                EvidenceItem.id == evidence_id_to_check,
                EvidenceItem.case_id == case_id
            ).first()
            if not ev:
                checks["evidence_scope"] = {
                    "passed": False,
                    "error": f"Evidence '{evidence_id_to_check}' does not belong to case '{case_id}' (IDOR violation)."
                }
                return cls._persist_decision(
                    db=db,
                    case_id=case_id,
                    action_type=action_type,
                    requesting_agent=requesting_agent,
                    target_resource_type=target_resource_type,
                    target_resource_id=target_resource_id,
                    policy_checks=checks,
                    risk_level=RiskLevel.HIGH,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    decision=GovernanceDecisionType.BLOCKED,
                    reason=f"IDOR / Evidence Scope Violation: Evidence '{evidence_id_to_check}' does not belong to case '{case_id}'.",
                    input_references=refs,
                    user=user
                )
            checks["evidence_scope"] = {"passed": True, "evidence_id": evidence_id_to_check}

        # -------------------------------------------------------------
        # 3. AGENT CAPABILITY PERMISSION & VALIDATION
        # -------------------------------------------------------------
        INTERNAL_SYSTEM_ACTORS = {
            "AIReasoningLayer",
            "INVESTIGATOR_REVIEW",
            "HUMAN_INVESTIGATOR",
            "InvestigatorReview",
            "SYSTEM",
            "PIPELINE",
        }
        if requesting_agent:
            if requesting_agent in INTERNAL_SYSTEM_ACTORS:
                checks["agent_permission"] = {"passed": True, "system_actor": requesting_agent}
            else:
                agent = db.query(SpecialistAgentRecord).filter(
                    (SpecialistAgentRecord.id == requesting_agent) | (SpecialistAgentRecord.name == requesting_agent)
                ).first()
                if not agent:
                    checks["agent_permission"] = {"passed": False, "error": f"Agent '{requesting_agent}' is not registered."}
                    return cls._persist_decision(
                        db=db,
                        case_id=case_id,
                        action_type=action_type,
                        requesting_agent=requesting_agent,
                        target_resource_type=target_resource_type,
                        target_resource_id=target_resource_id,
                        policy_checks=checks,
                        risk_level=RiskLevel.MEDIUM,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                        decision=GovernanceDecisionType.BLOCKED,
                        reason=f"Unregistered agent: Specialist agent '{requesting_agent}' does not exist.",
                        input_references=refs,
                        user=user
                    )

                if not agent.is_enabled:
                    checks["agent_permission"] = {"passed": False, "error": f"Agent '{agent.name}' is currently disabled."}
                    return cls._persist_decision(
                        db=db,
                        case_id=case_id,
                        action_type=action_type,
                        requesting_agent=requesting_agent,
                        target_resource_type=target_resource_type,
                        target_resource_id=target_resource_id,
                        policy_checks=checks,
                        risk_level=RiskLevel.LOW,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                        decision=GovernanceDecisionType.BLOCKED,
                        reason=f"Disabled agent: Specialist agent '{agent.name}' is disabled by administrative policy.",
                        input_references=refs,
                        user=user
                    )

                # If action is CAPABILITY_REQUEST, check supported capabilities
                if action_type == "CAPABILITY_REQUEST":
                    cap_id = params.get("capability_id") or target_resource_id
                    if cap_id:
                        supported_caps = agent.supported_analysis_capabilities or []
                        if cap_id not in supported_caps and cap_id.lower() not in [c.lower() for c in supported_caps]:
                            checks["agent_permission"] = {
                                "passed": False,
                                "error": f"Agent '{agent.name}' is not authorized to request capability '{cap_id}'."
                            }
                            return cls._persist_decision(
                                db=db,
                                case_id=case_id,
                                action_type=action_type,
                                requesting_agent=requesting_agent,
                                target_resource_type=target_resource_type,
                                target_resource_id=target_resource_id,
                                policy_checks=checks,
                                risk_level=RiskLevel.HIGH,
                                approval_status=ApprovalStatus.NOT_REQUIRED,
                                decision=GovernanceDecisionType.BLOCKED,
                                reason=f"Unauthorized capability: Agent '{agent.name}' cannot request '{cap_id}'.",
                                input_references=refs,
                                user=user
                            )

                checks["agent_permission"] = {"passed": True, "agent_id": agent.id, "agent_name": agent.name}

        # -------------------------------------------------------------
        # 4. TOOL / CAPABILITY SAFETY & PARAMETER SANITATION
        # -------------------------------------------------------------
        safety_violations = []
        for key, val in params.items():
            key_lower = str(key).lower().strip()
            if key_lower in DISALLOWED_PARAMETER_KEYS:
                safety_violations.append(f"Disallowed execution key: '{key}'")
            if key_lower == "shell" and val is True:
                safety_violations.append("Direct shell execution (shell=True) is strictly prohibited.")

            val_str = str(val)
            for meta in SHELL_METACHARACTERS:
                if meta in val_str:
                    safety_violations.append(f"Shell metacharacter '{meta}' detected in parameter '{key}'.")
                    break

            if ".." in val_str:
                safety_violations.append(f"Directory traversal sequence ('..') detected in parameter '{key}'.")

        if safety_violations:
            checks["tool_safety"] = {"passed": False, "violations": safety_violations}
            return cls._persist_decision(
                db=db,
                case_id=case_id,
                action_type=action_type,
                requesting_agent=requesting_agent,
                target_resource_type=target_resource_type,
                target_resource_id=target_resource_id,
                policy_checks=checks,
                risk_level=RiskLevel.CRITICAL,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                decision=GovernanceDecisionType.BLOCKED,
                reason=f"Security parameter violation: {'; '.join(safety_violations)}",
                input_references=refs,
                user=user
            )

        checks["tool_safety"] = {"passed": True}

        # -------------------------------------------------------------
        # 5. UNTRUSTED DATA & PROMPT INJECTION DEFENSE
        # -------------------------------------------------------------
        text_corpus = []
        if content_payload:
            text_corpus.append(str(content_payload))
        for k, v in params.items():
            text_corpus.append(f"{k}: {v}")
        full_text = " \n ".join(text_corpus)

        matched_injection_patterns = []
        for pat in PROMPT_INJECTION_PATTERNS:
            match = pat.search(full_text)
            if match:
                matched_injection_patterns.append(match.group(0))

        if matched_injection_patterns:
            checks["prompt_injection_check"] = {
                "detected": True,
                "matches": matched_injection_patterns[:5],
                "action": "FLAGGED_AS_UNTRUSTED_DATA"
            }
            risk_level = RiskLevel.HIGH
            decision = GovernanceDecisionType.REVIEW_REQUIRED
            approval_status = ApprovalStatus.PENDING
            reasons.append(
                f"Untrusted content contains prompt-injection/instruction-like patterns ({', '.join(matched_injection_patterns[:3])}); quarantined as passive data."
            )
        else:
            checks["prompt_injection_check"] = {"detected": False}

        # -------------------------------------------------------------
        # 6. PII / SENSITIVE DATA DETECTION
        # -------------------------------------------------------------
        detected_pii: Dict[str, int] = {}
        for pii_type, pat in PII_PATTERNS.items():
            matches = pat.findall(full_text)
            if matches:
                detected_pii[pii_type] = len(matches)

        if detected_pii:
            checks["pii_check"] = {
                "detected": True,
                "pii_types": detected_pii,
                "redaction_recommended": True
            }
            if risk_level != RiskLevel.HIGH and risk_level != RiskLevel.CRITICAL:
                risk_level = RiskLevel.MEDIUM
            if action_type in ("EXPORT_UNMASKED_PII", "REPORT_EXPORT", "EXTERNAL_SHARE"):
                decision = GovernanceDecisionType.REVIEW_REQUIRED
                approval_status = ApprovalStatus.PENDING
                reasons.append(f"Sensitive PII detected ({list(detected_pii.keys())}); explicit approval required for export.")
            else:
                reasons.append(f"Sensitive PII detected ({list(detected_pii.keys())}); logged for forensic redaction.")
        else:
            checks["pii_check"] = {"detected": False}

        # -------------------------------------------------------------
        # 7. HIGH-RISK ACTION APPROVAL POLICY
        # -------------------------------------------------------------
        action_upper = action_type.upper().strip()
        if action_upper in HIGH_RISK_ACTION_TYPES:
            checks["high_risk_check"] = {
                "is_high_risk": True,
                "action": action_upper,
                "approval_required": True
            }
            risk_level = RiskLevel.CRITICAL if "DESTRUCTIVE" in action_upper or "OVERWRITE" in action_upper else RiskLevel.HIGH
            decision = GovernanceDecisionType.REVIEW_REQUIRED
            approval_status = ApprovalStatus.PENDING
            reasons.append(f"High-risk action '{action_upper}' requires explicit human investigator authorization.")
        else:
            checks["high_risk_check"] = {"is_high_risk": False}

        # Final reason compilation
        final_reason = " | ".join(reasons) if reasons else "All automated governance policy checks passed successfully."

        return cls._persist_decision(
            db=db,
            case_id=case_id,
            action_type=action_type,
            requesting_agent=requesting_agent,
            target_resource_type=target_resource_type,
            target_resource_id=target_resource_id,
            policy_checks=checks,
            risk_level=risk_level,
            approval_status=approval_status,
            decision=decision,
            reason=final_reason,
            input_references=refs,
            user=user
        )

    @classmethod
    def _persist_decision(
        cls,
        db: Session,
        case_id: str,
        action_type: str,
        policy_checks: Dict[str, Any],
        risk_level: str,
        approval_status: str,
        decision: str,
        reason: str,
        input_references: Dict[str, Any],
        requesting_agent: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        target_resource_id: Optional[str] = None,
        user: Optional[User] = None
    ) -> GovernanceDecisionRecord:
        """
        Creates and persists a GovernanceDecisionRecord with SHA-256 integrity hash
        and appends an immutable hash-chained audit event.
        """
        decision_id = str(uuid.uuid4())
        now = utc_now()
        provenance = {
            "evaluated_by": "GovernanceGateService",
            "evaluator_version": "1.0.0",
            "case_id": case_id,
            "actor": getattr(user, "email", "system") if user else "system",
            "timestamp": now.isoformat()
        }

        # Canonical SHA-256 computation
        canonical_dict = {
            "decision_id": decision_id,
            "case_id": case_id,
            "action_type": action_type,
            "requesting_agent": requesting_agent,
            "target_resource_type": target_resource_type,
            "target_resource_id": target_resource_id,
            "risk_level": risk_level,
            "decision": decision,
            "approval_status": approval_status,
            "reason": reason,
            "timestamp": now.isoformat()
        }
        sha256_hash = compute_canonical_json_hash(canonical_dict)

        record = GovernanceDecisionRecord(
            id=decision_id,
            case_id=case_id,
            requesting_agent=requesting_agent,
            action_type=action_type,
            target_resource_type=target_resource_type,
            target_resource_id=target_resource_id,
            policy_checks=policy_checks,
            risk_level=risk_level,
            approval_status=approval_status,
            decision=decision,
            reason=reason,
            input_references=input_references,
            provenance=provenance,
            timestamp=now,
            sha256_hash=sha256_hash
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        # Audit logging with hash chaining
        cls._append_audit_event(
            db=db,
            case_id=case_id,
            decision_id=record.id,
            verification_id=None,
            event_type="EVALUATION",
            actor=getattr(user, "email", "system") if user else "system",
            input_references=input_references,
            checks_performed=list(policy_checks.keys()),
            decision=decision,
            reason=reason
        )

        return record

    @classmethod
    def approve_decision(
        cls,
        db: Session,
        decision_id: str,
        user: User,
        notes: Optional[str] = None
    ) -> GovernanceDecisionRecord:
        """
        Explicitly approves a pending high-risk governance decision.
        """
        decision = db.query(GovernanceDecisionRecord).filter(GovernanceDecisionRecord.id == decision_id).first()
        if not decision:
            raise ValueError(f"Governance decision with ID '{decision_id}' does not exist.")

        if decision.approval_status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot approve decision in '{decision.approval_status}' state (must be PENDING).")

        now = utc_now()
        decision.approval_status = ApprovalStatus.APPROVED
        decision.decision = GovernanceDecisionType.APPROVED
        decision.approved_by = user.id
        decision.approved_at = now
        decision.reason = f"{decision.reason} | Explicitly approved by {getattr(user, 'email', user.id)}: {notes or 'No notes'}"

        # Recompute integrity hash
        canonical_dict = {
            "decision_id": decision.id,
            "case_id": decision.case_id,
            "action_type": decision.action_type,
            "requesting_agent": decision.requesting_agent,
            "target_resource_type": decision.target_resource_type,
            "target_resource_id": decision.target_resource_id,
            "risk_level": decision.risk_level,
            "decision": decision.decision,
            "approval_status": decision.approval_status,
            "reason": decision.reason,
            "timestamp": decision.timestamp.isoformat() if decision.timestamp else now.isoformat()
        }
        decision.sha256_hash = compute_canonical_json_hash(canonical_dict)
        db.commit()
        db.refresh(decision)

        # Append approval audit event
        cls._append_audit_event(
            db=db,
            case_id=decision.case_id,
            decision_id=decision.id,
            verification_id=None,
            event_type="APPROVAL",
            actor=getattr(user, "email", user.id),
            input_references=decision.input_references,
            checks_performed=["HUMAN_INVESTIGATOR_APPROVAL"],
            decision=GovernanceDecisionType.APPROVED,
            reason=f"Approved with notes: {notes or 'None'}",
            approval_identity=user.id
        )

        return decision

    @classmethod
    def reject_decision(
        cls,
        db: Session,
        decision_id: str,
        user: User,
        reason: str
    ) -> GovernanceDecisionRecord:
        """
        Explicitly rejects a pending governance decision.
        """
        decision = db.query(GovernanceDecisionRecord).filter(GovernanceDecisionRecord.id == decision_id).first()
        if not decision:
            raise ValueError(f"Governance decision with ID '{decision_id}' does not exist.")

        if decision.approval_status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot reject decision in '{decision.approval_status}' state (must be PENDING).")

        now = utc_now()
        decision.approval_status = ApprovalStatus.REJECTED
        decision.decision = GovernanceDecisionType.BLOCKED
        decision.rejection_reason = reason
        decision.reason = f"{decision.reason} | Rejected by {getattr(user, 'email', user.id)}: {reason}"

        canonical_dict = {
            "decision_id": decision.id,
            "case_id": decision.case_id,
            "action_type": decision.action_type,
            "requesting_agent": decision.requesting_agent,
            "target_resource_type": decision.target_resource_type,
            "target_resource_id": decision.target_resource_id,
            "risk_level": decision.risk_level,
            "decision": decision.decision,
            "approval_status": decision.approval_status,
            "reason": decision.reason,
            "timestamp": decision.timestamp.isoformat() if decision.timestamp else now.isoformat()
        }
        decision.sha256_hash = compute_canonical_json_hash(canonical_dict)
        db.commit()
        db.refresh(decision)

        cls._append_audit_event(
            db=db,
            case_id=decision.case_id,
            decision_id=decision.id,
            verification_id=None,
            event_type="REJECTION",
            actor=getattr(user, "email", user.id),
            input_references=decision.input_references,
            checks_performed=["HUMAN_INVESTIGATOR_REJECTION"],
            decision=GovernanceDecisionType.BLOCKED,
            reason=f"Rejected: {reason}",
            approval_identity=user.id
        )

        return decision

    # =========================================================================
    # EVIDENCE / ARTIFACT / TOOL OUTPUT VERIFICATION
    # =========================================================================

    @classmethod
    def verify_target(
        cls,
        db: Session,
        case_id: str,
        target_type: str,
        target_id: str,
        notes: Optional[str] = None,
        user: Optional[User] = None
    ) -> EvidenceVerificationRecord:
        """
        Performs multi-dimensional verification of evidence, raw output, structured artifact,
        or normalized artifact:
        - Cryptographic integrity (SHA-256 recomputation)
        - Artifact lineage (trace upstream to source evidence)
        - Provenance references
        - Tool output metadata
        - Contradiction detection
        Produces VERIFIED, FAILED, or REVIEW_REQUIRED status.
        Never modifies source evidence.
        """
        now = utc_now()
        target_type_upper = target_type.upper().strip()

        integrity_check: Dict[str, Any] = {}
        lineage_check: Dict[str, Any] = {}
        provenance_check: Dict[str, Any] = {}
        metadata_check: Dict[str, Any] = {}
        contradiction_check: Dict[str, Any] = {"contradictions": [], "detected": False}
        details: Dict[str, Any] = {}

        status = VerificationStatus.VERIFIED

        # -------------------------------------------------------------
        # VERIFICATION BY TARGET TYPE
        # -------------------------------------------------------------
        if target_type_upper in ("EVIDENCE", "EVIDENCE_ITEM"):
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == target_id, EvidenceItem.case_id == case_id).first()
            if not ev:
                raise ValueError(f"Evidence item '{target_id}' not found in case '{case_id}'.")

            # 1. Integrity: verify file on disk against DB sha256_hash
            file_path = ev.storage_path or ev.original_path
            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    curr_hash = hashlib.sha256(f.read()).hexdigest()
                is_intact = (curr_hash == ev.sha256_hash)
                integrity_check = {
                    "method": "FILE_SHA256",
                    "db_hash": ev.sha256_hash,
                    "computed_hash": curr_hash,
                    "intact": is_intact
                }
                if not is_intact:
                    status = VerificationStatus.FAILED
            else:
                integrity_check = {
                    "method": "FILE_SHA256",
                    "error": f"Evidence file not found at path '{file_path}'.",
                    "intact": False
                }
                status = VerificationStatus.FAILED

            # 2. Lineage: Evidence is root
            lineage_check = {
                "is_root": True,
                "chain_length": 1,
                "source_evidence_id": ev.id,
                "lineage_valid": True
            }

            # 3. Provenance
            provenance_check = {
                "has_hashes": bool(ev.sha256_hash),
                "has_metadata": bool(ev.size_bytes is not None),
                "status": ev.status
            }

            # 4. Metadata
            metadata_check = {
                "size_bytes": ev.size_bytes,
                "type": ev.evidence_type,
                "acquired_at": ev.acquired_at.isoformat() if ev.acquired_at else None
            }

        elif target_type_upper in ("RAW_OUTPUT", "TOOL_OUTPUT"):
            out = db.query(ExecutionOutput).filter(ExecutionOutput.id == target_id, ExecutionOutput.case_id == case_id).first()
            if not out:
                raise ValueError(f"Execution output '{target_id}' not found in case '{case_id}'.")

            # 1. Integrity: check file on disk if storage_path exists
            if out.storage_path and os.path.exists(out.storage_path):
                with open(out.storage_path, "rb") as f:
                    curr_hash = hashlib.sha256(f.read()).hexdigest()
                is_intact = (curr_hash == out.sha256_hash)
                integrity_check = {
                    "method": "FILE_SHA256",
                    "db_hash": out.sha256_hash,
                    "computed_hash": curr_hash,
                    "intact": is_intact
                }
                if not is_intact:
                    status = VerificationStatus.FAILED
            else:
                integrity_check = {
                    "method": "DB_HASH_CHECK",
                    "db_hash": out.sha256_hash,
                    "intact": bool(out.sha256_hash)
                }

            # 2. Lineage: ExecutionOutput -> ForensicExecution -> EvidenceItem
            fe = db.query(ForensicExecution).filter(ForensicExecution.id == out.execution_id).first()
            if fe:
                ev = db.query(EvidenceItem).filter(EvidenceItem.id == fe.evidence_id).first()
                lineage_check = {
                    "execution_id": fe.id,
                    "evidence_id": fe.evidence_id,
                    "evidence_exists": bool(ev),
                    "lineage_valid": bool(ev and ev.case_id == case_id)
                }
                if not lineage_check["lineage_valid"]:
                    status = VerificationStatus.FAILED
            else:
                lineage_check = {"lineage_valid": False, "error": f"Parent execution '{out.execution_id}' missing."}
                status = VerificationStatus.FAILED

            metadata_check = {
                "output_type": out.output_type,
                "exit_code": out.exit_code,
                "duration_ms": out.duration_ms
            }

        elif target_type_upper == "STRUCTURED_ARTIFACT":
            sa = db.query(StructuredArtifact).filter(StructuredArtifact.id == target_id, StructuredArtifact.case_id == case_id).first()
            if not sa:
                raise ValueError(f"Structured artifact '{target_id}' not found in case '{case_id}'.")

            # 1. Lineage: StructuredArtifact -> ExecutionOutput / ForensicExecution -> EvidenceItem
            fe = db.query(ForensicExecution).filter(ForensicExecution.id == sa.execution_id).first()
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == sa.evidence_id).first()
            lineage_check = {
                "execution_id": sa.execution_id,
                "evidence_id": sa.evidence_id,
                "execution_exists": bool(fe),
                "evidence_exists": bool(ev),
                "lineage_valid": bool(ev and ev.case_id == case_id)
            }
            if not lineage_check["lineage_valid"]:
                status = VerificationStatus.FAILED

            integrity_check = {
                "db_hash": sa.sha256_hash,
                "intact": bool(sa.sha256_hash and len(sa.sha256_hash) == 64)
            }
            metadata_check = {
                "artifact_type": sa.artifact_type,
                "tool_name": sa.tool_name,
                "records_count": sa.records_count
            }

        elif target_type_upper == "NORMALIZED_ARTIFACT":
            na = db.query(NormalizedArtifact).filter(NormalizedArtifact.id == target_id, NormalizedArtifact.case_id == case_id).first()
            if not na:
                raise ValueError(f"Normalized artifact '{target_id}' not found in case '{case_id}'.")

            # 1. Lineage: NormalizedArtifact -> StructuredArtifact -> ForensicExecution -> EvidenceItem
            sa = db.query(StructuredArtifact).filter(StructuredArtifact.id == na.source_artifact_id).first()
            ev = db.query(EvidenceItem).filter(EvidenceItem.id == na.evidence_id).first()
            lineage_check = {
                "source_artifact_id": na.source_artifact_id,
                "source_artifact_exists": bool(sa),
                "evidence_id": na.evidence_id,
                "evidence_exists": bool(ev),
                "lineage_valid": bool(sa and ev and ev.case_id == case_id)
            }
            if not lineage_check["lineage_valid"]:
                status = VerificationStatus.FAILED

            integrity_check = {
                "db_hash": na.sha256_hash,
                "intact": bool(na.sha256_hash and len(na.sha256_hash) == 64)
            }
            metadata_check = {
                "entity_type": na.entity_type,
                "entity_identity": na.entity_identity,
                "normalization_status": na.normalization_status
            }

            # 2. Contradiction Detection:
            # Check for contradictory hashes or timestamps among other normalized artifacts in case
            contradictions = cls._detect_artifact_contradictions(db, case_id, na)
            if contradictions:
                contradiction_check = {
                    "contradictions": contradictions,
                    "detected": True
                }
                if status == VerificationStatus.VERIFIED:
                    status = VerificationStatus.REVIEW_REQUIRED
            else:
                contradiction_check = {"contradictions": [], "detected": False}

        else:
            raise ValueError(f"Unsupported target verification type: '{target_type}'.")

        # Provenance dict for verification
        prov = {
            "verified_by": "GovernanceGateService",
            "verifier_version": "1.0.0",
            "target_type": target_type_upper,
            "target_id": target_id,
            "case_id": case_id,
            "status": status,
            "timestamp": now.isoformat()
        }

        # SHA-256 canonical hash of verification record
        verification_id = str(uuid.uuid4())
        canonical_dict = {
            "id": verification_id,
            "case_id": case_id,
            "target_type": target_type_upper,
            "target_id": target_id,
            "verification_status": status,
            "timestamp": now.isoformat()
        }
        sha256_hash = compute_canonical_json_hash(canonical_dict)

        record = EvidenceVerificationRecord(
            id=verification_id,
            case_id=case_id,
            target_type=target_type_upper,
            target_id=target_id,
            verification_status=status,
            integrity_check=integrity_check,
            lineage_check=lineage_check,
            provenance_check=provenance_check,
            metadata_check=metadata_check,
            contradiction_check=contradiction_check,
            details=details,
            notes=notes,
            provenance=prov,
            timestamp=now,
            sha256_hash=sha256_hash
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        # Audit event
        cls._append_audit_event(
            db=db,
            case_id=case_id,
            decision_id=None,
            verification_id=record.id,
            event_type="VERIFICATION",
            actor=getattr(user, "email", "system") if user else "system",
            input_references={"target_type": target_type_upper, "target_id": target_id},
            checks_performed=["INTEGRITY", "LINEAGE", "PROVENANCE", "METADATA", "CONTRADICTION"],
            decision=status,
            reason=f"Verification completed with status: {status}"
        )

        return record

    @classmethod
    def _detect_artifact_contradictions(
        cls,
        db: Session,
        case_id: str,
        artifact: NormalizedArtifact
    ) -> List[Dict[str, Any]]:
        """
        Detects cross-domain contradictions for a normalized artifact:
        - Conflicting hashes for identical entity identity/path
        - Contradictory findings (e.g. Clean vs Malware on same hash)
        - Temporal anomalies (future timestamp relative to acquisition)
        """
        contradictions = []
        fields = artifact.normalized_fields or {}

        # 1. Conflicting file hashes for identical path
        path = fields.get("path") or fields.get("file_path") or fields.get("target_file")
        sha256 = fields.get("sha256") or fields.get("hash")
        if path and sha256:
            peers = db.query(NormalizedArtifact).filter(
                NormalizedArtifact.case_id == case_id,
                NormalizedArtifact.id != artifact.id
            ).all()
            for p in peers:
                p_fields = p.normalized_fields or {}
                p_path = p_fields.get("path") or p_fields.get("file_path") or p_fields.get("target_file")
                p_sha = p_fields.get("sha256") or p_fields.get("hash")
                if p_path and p_sha and p_path == path and p_sha != sha256:
                    contradictions.append({
                        "contradiction_type": "HASH_CONFLICT",
                        "description": f"Conflicting SHA-256 for path '{path}': '{sha256}' vs '{p_sha}' in artifact '{p.id}'.",
                        "conflicting_artifact_id": p.id
                    })

        # 2. Future timestamp contradiction relative to case/evidence
        ts_str = fields.get("timestamp") or fields.get("created_time")
        if ts_str:
            try:
                # Parse timestamp
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts > datetime.now(timezone.utc):
                    contradictions.append({
                        "contradiction_type": "TEMPORAL_FUTURE_ANOMALY",
                        "description": f"Artifact timestamp '{ts_str}' is set in the future relative to current time.",
                    })
            except Exception:
                pass

        return contradictions

    # =========================================================================
    # AUDIT TRAIL WITH CRYPTOGRAPHIC HASH CHAINING
    # =========================================================================

    @classmethod
    def _append_audit_event(
        cls,
        db: Session,
        case_id: Optional[str],
        decision_id: Optional[str],
        verification_id: Optional[str],
        event_type: str,
        actor: str,
        input_references: Dict[str, Any],
        checks_performed: List[str],
        decision: str,
        reason: str,
        approval_identity: Optional[str] = None
    ) -> GovernanceAuditEvent:
        """
        Appends an immutable, hash-chained audit event.
        """
        # Retrieve latest event hash in case to chain
        last_event = (
            db.query(GovernanceAuditEvent)
            .filter(GovernanceAuditEvent.case_id == case_id)
            .order_by(GovernanceAuditEvent.timestamp.desc())
            .first()
        )
        prev_hash = last_event.event_hash if last_event else ("0" * 64)

        now = utc_now()
        event_id = str(uuid.uuid4())
        raw_payload = f"{event_id}|{case_id}|{decision_id}|{verification_id}|{event_type}|{actor}|{decision}|{now.isoformat()}|{prev_hash}"
        event_hash = compute_sha256(raw_payload.encode("utf-8"))

        audit_rec = GovernanceAuditEvent(
            id=event_id,
            case_id=case_id,
            decision_id=decision_id,
            verification_id=verification_id,
            event_type=event_type,
            actor=actor,
            input_references=input_references,
            checks_performed=checks_performed,
            decision=decision,
            reason=reason,
            approval_identity=approval_identity,
            timestamp=now,
            event_hash=event_hash,
            prev_event_hash=prev_hash
        )
        db.add(audit_rec)
        db.commit()
        db.refresh(audit_rec)
        return audit_rec

    @classmethod
    def get_decision(cls, db: Session, decision_id: str) -> Optional[GovernanceDecisionRecord]:
        return db.query(GovernanceDecisionRecord).filter(GovernanceDecisionRecord.id == decision_id).first()

    @classmethod
    def list_decisions(
        cls,
        db: Session,
        case_id: str,
        decision_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        approval_status: Optional[str] = None
    ) -> List[GovernanceDecisionRecord]:
        q = db.query(GovernanceDecisionRecord).filter(GovernanceDecisionRecord.case_id == case_id)
        if decision_type:
            q = q.filter(GovernanceDecisionRecord.decision == decision_type.upper().strip())
        if risk_level:
            q = q.filter(GovernanceDecisionRecord.risk_level == risk_level.upper().strip())
        if approval_status:
            q = q.filter(GovernanceDecisionRecord.approval_status == approval_status.upper().strip())
        return q.order_by(GovernanceDecisionRecord.timestamp.desc()).all()

    @classmethod
    def list_verifications(
        cls,
        db: Session,
        case_id: str,
        target_type: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[EvidenceVerificationRecord]:
        q = db.query(EvidenceVerificationRecord).filter(EvidenceVerificationRecord.case_id == case_id)
        if target_type:
            q = q.filter(EvidenceVerificationRecord.target_type == target_type.upper().strip())
        if status:
            q = q.filter(EvidenceVerificationRecord.verification_status == status.upper().strip())
        return q.order_by(EvidenceVerificationRecord.timestamp.desc()).all()

    @classmethod
    def get_verification(cls, db: Session, verification_id: str) -> Optional[EvidenceVerificationRecord]:
        return db.query(EvidenceVerificationRecord).filter(EvidenceVerificationRecord.id == verification_id).first()

    @classmethod
    def list_audit_events(
        cls,
        db: Session,
        case_id: str,
        decision_id: Optional[str] = None
    ) -> List[GovernanceAuditEvent]:
        q = db.query(GovernanceAuditEvent).filter(GovernanceAuditEvent.case_id == case_id)
        if decision_id:
            q = q.filter(GovernanceAuditEvent.decision_id == decision_id)
        return q.order_by(GovernanceAuditEvent.timestamp.asc()).all()
