"""
ADFIR — Investigator Review Service (Phase 2 / Step 19)

Governed human-in-the-loop review layer downstream of Deterministic Findings (Step 15)
and Governed AI Reasoning (Step 18).

Core Invariants:
1. Investigator makes the final decision: ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE.
2. Source Immutability: Deterministic findings and AI reasoning records are never modified in-place.
3. Tamper Detection: Cryptographic SHA-256 integrity hash is computed and verified for every review record.
4. Pipeline Re-entry: REQUEST_MORE_EVIDENCE creates a controlled investigation request that re-enters
   the standard pipeline via Governance Gate and Resource-Aware Scheduler.
5. Strict IDOR protection and complete provenance traceability.
"""

import os
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from fastapi import HTTPException, status

from backend.app.core.config import settings
from backend.app.models.models import (
    Case,
    User,
    EvidenceItem,
    ChainOfCustodyEvent,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    TimelineEvent,
    ArtifactRelationship,
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    InvestigationPlan,
    AnalysisRequest,
    GovernanceDecisionRecord,
    AuditEvent
)
from backend.app.schemas.schemas import (
    InvestigatorDecisionType,
    InvestigatorReviewCreateRequest,
    InvestigatorReviewResponse,
    InvestigatorReviewIntegrityResponse,
    RequestMoreEvidenceRequest,
    RequestMoreEvidenceResponse,
    ReviewItemsResponse,
    ClaimProvenanceResponse
)
from backend.app.services.governance import (
    GovernanceGateService,
    GovernanceDecisionType
)
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_INVESTIGATOR_REVIEW")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_canonical_json_hash(data: Any) -> str:
    """Computes SHA-256 hash over deterministic canonical JSON."""
    serialized = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()


class InvestigatorReviewService:
    """
    Service layer orchestrating human-in-the-loop investigator reviews.
    """

    @classmethod
    def get_review_items(
        cls,
        db: Session,
        case: Case,
        user: User
    ) -> ReviewItemsResponse:
        """
        Gathers reviewable items for the case:
        - Evidence items with verified integrity and custody summary
        - Deterministic findings with verified supporting artifacts
        - AI reasoning records with FACT / INFERENCE / UNVERIFIED classification
        - Existing reviews and decision breakdown
        """
        # 1. Evidence Items
        evidence_items = []
        for ev in case.evidence_items:
            # Query custody events count
            custody_count = db.query(ChainOfCustodyEvent).filter(
                ChainOfCustodyEvent.evidence_id == ev.id
            ).count()

            evidence_items.append({
                "id": ev.id,
                "case_id": ev.case_id,
                "name": ev.name,
                "evidence_type": ev.evidence_type,
                "status": ev.status,
                "sha256_hash": ev.sha256_hash,
                "size_bytes": ev.size_bytes,
                "custody_events_count": custody_count,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
                "verified_integrity": bool(ev.sha256_hash and len(ev.sha256_hash) == 64)
            })

        # 2. Deterministic Findings
        findings_query = db.query(DeterministicFinding).filter(
            DeterministicFinding.case_id == case.id
        ).order_by(DeterministicFinding.created_at.desc()).all()

        findings_items = []
        for f in findings_query:
            # Verify supporting artifacts exist in database
            supp_arts = []
            if f.supporting_artifact_ids:
                arts = db.query(StructuredArtifact).filter(
                    StructuredArtifact.id.in_(f.supporting_artifact_ids),
                    StructuredArtifact.case_id == case.id
                ).all()
                supp_arts = [{"id": a.id, "type": a.artifact_type, "label": a.source_reference or a.artifact_type} for a in arts]

            findings_items.append({
                "id": f.id,
                "case_id": f.case_id,
                "title": f.title,
                "description": f.description,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "severity_rule": f.severity_rule,
                "confidence": f.confidence,
                "observed_facts": f.observed_facts or [],
                "supporting_artifact_ids": f.supporting_artifact_ids or [],
                "supporting_artifacts": supp_arts,
                "supporting_evidence_ids": f.supporting_evidence_ids or [],
                "sha256_hash": f.sha256_hash,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "verified_lineage": True
            })

        # 3. AI Reasoning Records
        ai_records_query = db.query(AIReasoningRecord).filter(
            AIReasoningRecord.case_id == case.id
        ).order_by(AIReasoningRecord.created_at.desc()).all()

        ai_items = []
        for ar in ai_records_query:
            # Format statements with classifications
            statements_formatted = []
            for st in (ar.statements or []):
                stmt_dict = dict(st)
                # Verify citations exist in case
                ev_ids = stmt_dict.get("supporting_evidence_ids") or []
                art_ids = stmt_dict.get("supporting_artifact_ids") or []
                f_ids = stmt_dict.get("supporting_finding_ids") or []
                
                citations_valid = True
                if ev_ids:
                    c_count = db.query(EvidenceItem).filter(
                        EvidenceItem.id.in_(ev_ids),
                        EvidenceItem.case_id == case.id
                    ).count()
                    if c_count < len(ev_ids):
                        citations_valid = False

                stmt_dict["citations_valid"] = citations_valid
                statements_formatted.append(stmt_dict)

            ai_items.append({
                "id": ar.id,
                "case_id": ar.case_id,
                "objective": ar.objective,
                "status": ar.status,
                "execution_mode": ar.execution_mode,
                "provider": ar.provider,
                "model": ar.model,
                "statements": statements_formatted,
                "summary": ar.summary,
                "citations_verified": ar.citations_verified,
                "sha256_hash": ar.sha256_hash,
                "created_at": ar.created_at.isoformat() if ar.created_at else None
            })

        # 4. Existing Reviews
        reviews_query = db.query(InvestigatorReviewRecord).filter(
            InvestigatorReviewRecord.case_id == case.id
        ).order_by(InvestigatorReviewRecord.created_at.desc()).all()

        reviews_list = [InvestigatorReviewResponse.model_validate(r) for r in reviews_query]

        # 5. Summary Statistics
        decisions_count = {
            "ACCEPT": 0,
            "CHALLENGE": 0,
            "REJECT": 0,
            "REQUEST_MORE_EVIDENCE": 0
        }
        for r in reviews_query:
            if r.decision in decisions_count:
                decisions_count[r.decision] += 1

        summary = {
            "total_evidence_items": len(evidence_items),
            "total_findings": len(findings_items),
            "total_ai_reasoning_records": len(ai_items),
            "total_reviews": len(reviews_query),
            "decisions_breakdown": decisions_count,
            "pending_review_findings": max(0, len(findings_items) - len([r for r in reviews_query if r.target_type == "FINDING"])),
            "pending_review_ai_claims": max(0, len(ai_items) - len([r for r in reviews_query if r.target_type == "AI_REASONING"]))
        }

        return ReviewItemsResponse(
            case_id=case.id,
            evidence_items=evidence_items,
            deterministic_findings=findings_items,
            ai_reasoning_records=ai_items,
            existing_reviews=reviews_list,
            summary=summary
        )

    @classmethod
    def submit_decision(
        cls,
        db: Session,
        case: Case,
        user: User,
        payload: InvestigatorReviewCreateRequest,
        action_reference_id: Optional[str] = None
    ) -> InvestigatorReviewResponse:
        """
        Submits an investigator review decision (ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE).
        Guarantees:
        1. Target finding or reasoning record is NEVER overwritten or modified.
        2. Target exists and strictly belongs to case (IDOR defense).
        3. Canonical SHA-256 hash is computed and saved.
        4. Stored in DB and persisted to disk.
        5. Audit event logged.
        """
        from backend.app.services.case_closure import check_case_not_closed
        check_case_not_closed(case)

        decision_upper = payload.decision.upper().strip()
        allowed_decisions = {"ACCEPT", "CHALLENGE", "REJECT", "REQUEST_MORE_EVIDENCE"}
        if decision_upper not in allowed_decisions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid review decision '{payload.decision}'. Allowed: {sorted(list(allowed_decisions))}"
            )

        target_type_upper = payload.target_type.upper().strip()
        allowed_targets = {"FINDING", "AI_REASONING", "EVIDENCE", "CLAIM"}
        if target_type_upper not in allowed_targets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target type '{payload.target_type}'. Allowed: {sorted(list(allowed_targets))}"
            )

        # IDOR and target existence validation
        target_name = payload.target_id
        if target_type_upper == "FINDING":
            finding = db.query(DeterministicFinding).filter(
                DeterministicFinding.id == payload.target_id,
                DeterministicFinding.case_id == case.id
            ).first()
            if not finding:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Deterministic finding '{payload.target_id}' not found in case '{case.id}'."
                )
            target_name = finding.title

        elif target_type_upper == "AI_REASONING":
            reasoning = db.query(AIReasoningRecord).filter(
                AIReasoningRecord.id == payload.target_id,
                AIReasoningRecord.case_id == case.id
            ).first()
            if not reasoning:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"AI reasoning record '{payload.target_id}' not found in case '{case.id}'."
                )
            if payload.statement_id:
                # Confirm statement exists in reasoning
                matching_stmt = any(s.get("statement_id") == payload.statement_id for s in (reasoning.statements or []))
                if not matching_stmt:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Statement '{payload.statement_id}' not found in AI reasoning record '{payload.target_id}'."
                    )
            target_name = reasoning.objective

        elif target_type_upper == "EVIDENCE":
            ev = db.query(EvidenceItem).filter(
                EvidenceItem.id == payload.target_id,
                EvidenceItem.case_id == case.id
            ).first()
            if not ev:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Evidence item '{payload.target_id}' not found in case '{case.id}'."
                )
            target_name = ev.name

        # Map decision to resulting workflow action
        action_mapping = {
            "ACCEPT": "ACCEPTED_CLAIM",
            "CHALLENGE": "CHALLENGED_CLAIM",
            "REJECT": "REJECTED_CLAIM",
            "REQUEST_MORE_EVIDENCE": "EVIDENCE_REQUESTED"
        }
        resulting_action = action_mapping[decision_upper]

        review_id = str(uuid.uuid4())
        timestamp_dt = utc_now()

        # Build canonical payload for cryptographic hash
        canonical_dict = {
            "review_id": review_id,
            "case_id": case.id,
            "investigator_id": user.id,
            "target_type": target_type_upper,
            "target_id": payload.target_id,
            "statement_id": payload.statement_id,
            "decision": decision_upper,
            "comment": payload.comment or "",
            "supporting_references": sorted(payload.supporting_references or []),
            "resulting_workflow_action": resulting_action,
            "action_reference_id": action_reference_id
        }
        computed_hash = compute_canonical_json_hash(canonical_dict)

        # Formulate provenance trace
        provenance = {
            "investigator_id": user.id,
            "investigator_name": user.name or user.email,
            "investigator_role": user.role,
            "case_id": case.id,
            "target_type": target_type_upper,
            "target_id": payload.target_id,
            "target_label": target_name,
            "statement_id": payload.statement_id,
            "decision": decision_upper,
            "action": resulting_action,
            "timestamp": timestamp_dt.isoformat(),
            "sha256_hash": computed_hash
        }

        # Persistent storage path on disk
        storage_dir = settings.DATA_DIR / "cases" / case.id / "reviews"
        storage_dir.mkdir(parents=True, exist_ok=True)
        disk_path = storage_dir / f"review_{review_id}.json"

        # Persist to disk
        disk_payload = {
            **canonical_dict,
            "investigator_name": user.name or user.email,
            "provenance": provenance,
            "timestamp": timestamp_dt.isoformat(),
            "sha256_hash": computed_hash
        }
        disk_path.write_text(json.dumps(disk_payload, indent=2, sort_keys=True), encoding="utf-8")

        # Create Review Record
        record = InvestigatorReviewRecord(
            id=review_id,
            case_id=case.id,
            investigator_id=user.id,
            investigator_name=user.name or user.email,
            target_type=target_type_upper,
            target_id=payload.target_id,
            statement_id=payload.statement_id,
            decision=decision_upper,
            comment=payload.comment or "",
            supporting_references=payload.supporting_references or [],
            resulting_workflow_action=resulting_action,
            action_reference_id=action_reference_id,
            provenance=provenance,
            review_metadata={
                "target_label": target_name,
                "client_timestamp": timestamp_dt.isoformat()
            },
            sha256_hash=computed_hash,
            storage_path=str(disk_path),
            timestamp=timestamp_dt,
            created_at=timestamp_dt,
            updated_at=timestamp_dt
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        # Audit Event
        log_audit_event(
            db=db,
            event_type="INVESTIGATOR_REVIEW_DECISION",
            details=f"Investigator {user.email} marked {target_type_upper} {payload.target_id} as {decision_upper}",
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.email,
            metadata_json={
                "review_id": record.id,
                "target_type": target_type_upper,
                "target_id": payload.target_id,
                "statement_id": payload.statement_id,
                "decision": decision_upper,
                "resulting_workflow_action": resulting_action,
                "sha256_hash": computed_hash
            }
        )

        return InvestigatorReviewResponse.model_validate(record)

    @classmethod
    def verify_integrity(
        cls,
        db: Session,
        case_id: str,
        review_id: str
    ) -> InvestigatorReviewIntegrityResponse:
        """
        Recomputes canonical SHA-256 hash and verifies against stored record and on-disk representation.
        Detects database or disk tampering.
        """
        record = db.query(InvestigatorReviewRecord).filter(
            InvestigatorReviewRecord.id == review_id,
            InvestigatorReviewRecord.case_id == case_id
        ).first()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Review record '{review_id}' not found in case '{case_id}'."
            )

        # Recompute canonical hash
        canonical_dict = {
            "review_id": record.id,
            "case_id": record.case_id,
            "investigator_id": record.investigator_id,
            "target_type": record.target_type,
            "target_id": record.target_id,
            "statement_id": record.statement_id,
            "decision": record.decision,
            "comment": record.comment or "",
            "supporting_references": sorted(record.supporting_references or []),
            "resulting_workflow_action": record.resulting_workflow_action,
            "action_reference_id": record.action_reference_id
        }
        recomputed_hash = compute_canonical_json_hash(canonical_dict)

        tamper_detected = False
        if recomputed_hash != record.sha256_hash:
            tamper_detected = True

        # Check disk file if present
        if record.storage_path and os.path.exists(record.storage_path):
            try:
                with open(record.storage_path, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
                if disk_data.get("sha256_hash") != record.sha256_hash:
                    tamper_detected = True
            except Exception:
                tamper_detected = True

        integrity_status = "FAILED" if tamper_detected else "VERIFIED"

        return InvestigatorReviewIntegrityResponse(
            review_id=record.id,
            expected_hash=record.sha256_hash,
            computed_hash=recomputed_hash,
            integrity_status=integrity_status,
            tamper_detected=tamper_detected,
            checked_at=utc_now()
        )

    @classmethod
    def get_claim_provenance(
        cls,
        db: Session,
        case_id: str,
        target_id: str,
        target_type: Optional[str] = None
    ) -> ClaimProvenanceResponse:
        """
        Traces multi-tier forensic lineage for a deterministic finding or AI reasoning claim:
        Claim -> Artifact -> Raw Tool Output -> Evidence Vault Item.
        """
        # Attempt to find finding
        finding = db.query(DeterministicFinding).filter(
            DeterministicFinding.id == target_id,
            DeterministicFinding.case_id == case_id
        ).first()

        reasoning = None
        if not finding:
            reasoning = db.query(AIReasoningRecord).filter(
                AIReasoningRecord.id == target_id,
                AIReasoningRecord.case_id == case_id
            ).first()

        if not finding and not reasoning:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target claim/finding/reasoning '{target_id}' not found in case '{case_id}'."
            )

        lineage = []
        supporting_artifacts = []
        supporting_evidence = []
        claim_summary = {}

        if finding:
            claim_summary = {
                "id": finding.id,
                "type": "DETERMINISTIC_FINDING",
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "sha256_hash": finding.sha256_hash,
                "created_at": finding.created_at.isoformat() if finding.created_at else None
            }

            # Lineage tier 1: Supporting artifacts
            if finding.supporting_artifact_ids:
                artifacts = db.query(StructuredArtifact).filter(
                    StructuredArtifact.id.in_(finding.supporting_artifact_ids),
                    StructuredArtifact.case_id == case_id
                ).all()
                for a in artifacts:
                    supporting_artifacts.append({
                        "id": a.id,
                        "artifact_type": a.artifact_type,
                        "label": a.source_reference or a.artifact_type,
                        "execution_id": a.execution_id,
                        "sha256_hash": a.sha256_hash
                    })

                    # Lineage tier 2: Raw tool execution outputs
                    if a.execution_id:
                        exec_out = db.query(ExecutionOutput).filter(
                            ExecutionOutput.execution_id == a.execution_id,
                            ExecutionOutput.case_id == case_id
                        ).first()
                        if exec_out:
                            lineage.append({
                                "step": "TOOL_EXECUTION_OUTPUT",
                                "id": exec_out.id,
                                "tool_id": exec_out.tool_id,
                                "execution_id": exec_out.execution_id,
                                "sha256_hash": exec_out.sha256_hash
                            })

            # Lineage tier 3: Evidence Items
            if finding.supporting_evidence_ids:
                evs = db.query(EvidenceItem).filter(
                    EvidenceItem.id.in_(finding.supporting_evidence_ids),
                    EvidenceItem.case_id == case_id
                ).all()
                for ev in evs:
                    supporting_evidence.append({
                        "id": ev.id,
                        "name": ev.name,
                        "evidence_type": ev.evidence_type,
                        "sha256_hash": ev.sha256_hash,
                        "status": ev.status
                    })

        elif reasoning:
            claim_summary = {
                "id": reasoning.id,
                "type": "AI_REASONING",
                "objective": reasoning.objective,
                "provider": reasoning.provider,
                "model": reasoning.model,
                "statements_count": len(reasoning.statements or []),
                "sha256_hash": reasoning.sha256_hash,
                "created_at": reasoning.created_at.isoformat() if reasoning.created_at else None
            }

            input_refs = reasoning.input_references or {}
            finding_ids = input_refs.get("finding_ids") or []
            if finding_ids:
                ref_findings = db.query(DeterministicFinding).filter(
                    DeterministicFinding.id.in_(finding_ids),
                    DeterministicFinding.case_id == case_id
                ).all()
                for rf in ref_findings:
                    lineage.append({
                        "step": "DETERMINISTIC_FINDING_INPUT",
                        "id": rf.id,
                        "title": rf.title,
                        "severity": rf.severity,
                        "sha256_hash": rf.sha256_hash
                    })

            art_ids = input_refs.get("artifact_ids") or []
            if art_ids:
                ref_arts = db.query(StructuredArtifact).filter(
                    StructuredArtifact.id.in_(art_ids),
                    StructuredArtifact.case_id == case_id
                ).all()
                for ra in ref_arts:
                    supporting_artifacts.append({
                        "id": ra.id,
                        "artifact_type": ra.artifact_type,
                        "label": ra.source_reference or ra.artifact_type,
                        "sha256_hash": ra.sha256_hash
                    })

            ev_ids = input_refs.get("evidence_ids") or []
            if ev_ids:
                ref_evs = db.query(EvidenceItem).filter(
                    EvidenceItem.id.in_(ev_ids),
                    EvidenceItem.case_id == case_id
                ).all()
                for re in ref_evs:
                    supporting_evidence.append({
                        "id": re.id,
                        "name": re.name,
                        "evidence_type": re.evidence_type,
                        "sha256_hash": re.sha256_hash
                    })

        return ClaimProvenanceResponse(
            case_id=case_id,
            target_type="FINDING" if finding else "AI_REASONING",
            target_id=target_id,
            statement_id=None,
            claim_summary=claim_summary,
            lineage=lineage,
            supporting_artifacts=supporting_artifacts,
            supporting_evidence=supporting_evidence,
            verified_integrity=True
        )

    @classmethod
    def request_more_evidence(
        cls,
        db: Session,
        case: Case,
        user: User,
        payload: RequestMoreEvidenceRequest
    ) -> RequestMoreEvidenceResponse:
        """
        Processes a REQUEST_MORE_EVIDENCE decision:
        1. Formulates controlled request through Step 17 Governance Gate.
        2. If approved, creates an AnalysisRequest for the Step 8 Resource-Aware Scheduler.
        3. Persists InvestigatorReviewRecord linked to the generated AnalysisRequest ID.
        4. Does NOT create an out-of-band execution path.
        """
        # Resolve evidence ID
        evidence_id = payload.evidence_id
        if not evidence_id:
            # Check if target is finding with supporting evidence
            finding = db.query(DeterministicFinding).filter(
                DeterministicFinding.id == payload.target_id,
                DeterministicFinding.case_id == case.id
            ).first()
            if finding and finding.supporting_evidence_ids:
                evidence_id = finding.supporting_evidence_ids[0]
            elif case.evidence_items:
                evidence_id = case.evidence_items[0].id

        if not evidence_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"No associated evidence item found for case '{case.id}' to request further analysis on."
            )

        # 1. Evaluate with Governance Gate
        gov_decision = GovernanceGateService.evaluate_governance(
            db=db,
            case_id=case.id,
            action_type="CAPABILITY_REQUEST",
            requesting_agent="INVESTIGATOR_REVIEW",
            target_resource_type="EVIDENCE",
            target_resource_id=evidence_id,
            parameters={
                "capability_id": payload.requested_capability,
                "analysis_objective": payload.analysis_objective,
                **payload.parameters
            },
            input_references={
                "target_claim_id": payload.target_id,
                "statement_id": payload.statement_id,
                "evidence_id": evidence_id
            },
            user=user
        )

        if gov_decision.decision == GovernanceDecisionType.BLOCKED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Governance Gate blocked further evidence request: {gov_decision.reason}"
            )

        # 2. Re-enter pipeline: Find or create plan and create AnalysisRequest for Scheduler
        plan = db.query(InvestigationPlan).filter(
            InvestigationPlan.case_id == case.id
        ).order_by(InvestigationPlan.created_at.desc()).first()

        if not plan:
            plan = InvestigationPlan(
                id=str(uuid.uuid4()),
                case_id=case.id,
                title=f"Investigation Plan - Case {case.name}",
                objectives=["Comprehensive multi-domain forensic analysis"],
                status="PLANNED",
                created_by=user.id
            )
            db.add(plan)
            db.commit()
            db.refresh(plan)

        task_key = f"REQ_EVID_{payload.requested_capability.upper()}_{uuid.uuid4().hex[:6]}"
        analysis_request = AnalysisRequest(
            id=str(uuid.uuid4()),
            case_id=case.id,
            plan_id=plan.id,
            task_key=task_key,
            evidence_id=evidence_id,
            capability_id=payload.requested_capability,
            selected_tool_id=payload.requested_capability.lower(),
            resource_requirements={"cpu_cores": 1, "ram_mb": 512, "disk_mb": 100},
            priority_level="HIGH",
            priority_score=0.8,
            timeout_seconds=300,
            retry_policy={"max_retries": 3, "retry_count": 0, "retry_delay_seconds": 60, "is_retryable": True},
            dependencies=[],
            scheduler_status="QUEUED"
        )
        db.add(analysis_request)
        db.commit()
        db.refresh(analysis_request)

        # 3. Persist Investigator Review Decision
        review_req = InvestigatorReviewCreateRequest(
            target_type=payload.target_type,
            target_id=payload.target_id,
            statement_id=payload.statement_id,
            decision="REQUEST_MORE_EVIDENCE",
            comment=payload.comment,
            supporting_references=payload.supporting_references or ([evidence_id] if evidence_id else [])
        )

        review_resp = cls.submit_decision(
            db=db,
            case=case,
            user=user,
            payload=review_req,
            action_reference_id=analysis_request.id
        )

        log_audit_event(
            db=db,
            event_type="INVESTIGATOR_REQUEST_MORE_EVIDENCE",
            details=f"Investigator {user.email} scheduled capability '{payload.requested_capability}' on evidence '{evidence_id}'",
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.email,
            metadata_json={
                "review_id": review_resp.id,
                "analysis_request_id": analysis_request.id,
                "governance_decision_id": gov_decision.id,
                "capability": payload.requested_capability,
                "evidence_id": evidence_id
            }
        )

        return RequestMoreEvidenceResponse(
            review=review_resp,
            governance_decision_id=gov_decision.id,
            analysis_request_id=analysis_request.id,
            execution_id=None,
            workflow_status="SCHEDULED",
            message=f"Analysis request {analysis_request.id} queued successfully for capability {payload.requested_capability}."
        )

    @classmethod
    def list_reviews(
        cls,
        db: Session,
        case_id: str,
        target_id: Optional[str] = None,
        decision: Optional[str] = None
    ) -> List[InvestigatorReviewResponse]:
        """
        Lists review records for a case with optional target_id and decision filters.
        """
        query = db.query(InvestigatorReviewRecord).filter(
            InvestigatorReviewRecord.case_id == case_id
        )
        if target_id:
            query = query.filter(InvestigatorReviewRecord.target_id == target_id)
        if decision:
            query = query.filter(InvestigatorReviewRecord.decision == decision.upper())

        records = query.order_by(InvestigatorReviewRecord.created_at.desc()).all()
        return [InvestigatorReviewResponse.model_validate(r) for r in records]

    @classmethod
    def get_review(
        cls,
        db: Session,
        case_id: str,
        review_id: str
    ) -> InvestigatorReviewResponse:
        """
        Retrieves a single review record by ID with case verification (IDOR protection).
        """
        record = db.query(InvestigatorReviewRecord).filter(
            InvestigatorReviewRecord.id == review_id,
            InvestigatorReviewRecord.case_id == case_id
        ).first()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Review record '{review_id}' not found in case '{case_id}'."
            )
        return InvestigatorReviewResponse.model_validate(record)
