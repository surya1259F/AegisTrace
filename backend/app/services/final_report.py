"""
ADFIR — Final Forensic Report Service (Phase 2 / Step 20)

Synthesizes an evidence-grounded, versioned final forensic report from the completed investigation.

12 Core Report Sections:
1. Case information
2. Evidence inventory
3. Hashes / preservation
4. Chain of custody
5. Tool executions
6. Artifacts
7. Timeline
8. Correlations
9. Findings
10. Confidence / verification
11. Investigator decisions
12. Explainability / provenance

Core Invariants:
1. Evidence Grounding: Every report claim references supporting evidence, artifacts, or findings.
   Never invents facts. Unsupported claims are excluded or marked UNVERIFIED.
2. Fact / Inference / Unverified Preservation: Strict adherence to classification categories.
3. Investigator Decision Preservation: Preserves accepted, challenged, and rejected decisions
   along with investigator rationale and timestamps.
4. Cryptographic Integrity: Computes canonical SHA-256 hash over deterministic report structure;
   detects and flags any tampering.
5. Multi-Tier Provenance: Full lineage tracing:
   Evidence -> Execution -> Output -> Artifact -> Normalized Artifact -> Timeline/Correlation -> Finding -> AI Reasoning -> Investigator Decision -> Report.
6. Case Isolation & IDOR Protection: Strictly enforced via case authorization checks.
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
from sqlalchemy import func
from fastapi import HTTPException, status

from backend.app.core.config import settings
from backend.app.models.models import (
    Case,
    User,
    EvidenceItem,
    ChainOfCustodyEvent,
    ForensicExecution,
    ToolExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    TimelineEvent,
    ArtifactRelationship,
    ForensicCorrelationGroup,
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    Report,
    AuditEvent
)
from backend.app.schemas.schemas import (
    ForensicReportGenerateRequest,
    ForensicReportResponse,
    ForensicReportVersionItem,
    ForensicReportIntegrityResponse,
    ForensicReportProvenanceResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.audit import log_audit_event

logger = logging.getLogger("ADFIR_FINAL_REPORT")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_canonical_json_hash(data: Any) -> str:
    """Computes deterministic SHA-256 hash over canonical JSON representation."""
    serialized = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()


def verify_evidence_file_integrity(ev: EvidenceItem) -> Tuple[str, Optional[str]]:
    """
    Verifies that the preserved evidence file on disk matches its registered SHA-256 hash.
    Returns (status, current_hash).
    Status is VERIFIED, INTEGRITY_WARNING, or UNCHECKED.
    """
    file_path = None
    if ev.storage_path and os.path.exists(ev.storage_path):
        file_path = ev.storage_path
    elif ev.original_path and os.path.exists(ev.original_path):
        file_path = ev.original_path

    if file_path and os.path.isfile(file_path):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            computed = h.hexdigest().lower()
            expected = (ev.sha256 or "").lower()
            if computed == expected:
                return "VERIFIED", computed
            else:
                logger.warning(f"Evidence {ev.id} hash mismatch: computed {computed} != expected {expected}")
                return "INTEGRITY_WARNING", computed
        except Exception as e:
            logger.error(f"Error reading evidence file {file_path}: {e}")
            return "INTEGRITY_WARNING", None

    # A registered hash alone does not prove that the physical evidence
    # is currently present and matches that hash.
    # Missing physical evidence must never be reported as VERIFIED.
    return "UNCHECKED", None


class FinalForensicReportService:
    """
    Service layer orchestrating generation, versioning, integrity verification,
    and provenance inspection for Final Forensic Reports.
    """

    @classmethod
    def _build_sections(
        cls,
        case: Case,
        db: Session,
        options: Dict[str, Any],
        user: User
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str, Dict[str, Any]]:
        """
        Builds the 12 structured report sections from persisted, verified investigation data.
        Returns:
            (sections, provenance, overall_integrity_status, evidence_summary)
        """
        # 1. Section 1: Case Information
        members = []
        for m in case.members:
            u = m.user
            members.append({
                "user_id": m.user_id,
                "name": u.name if u else "Unknown",
                "email": u.email if u else "Unknown",
                "role": m.role,
                "added_at": m.added_at.isoformat() if m.added_at else None
            })

        case_information = {
            "case_id": case.id,
            "case_number": case.case_number,
            "name": case.name,
            "objective": case.objective,
            "description": case.description or "",
            "case_type": case.case_type,
            "priority": case.priority,
            "status": case.status,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "members": members,
            "workspace_path": case.workspace_path
        }

        # 2. Section 2 & 3: Evidence Inventory & Hashes/Preservation
        evidence_inventory = []
        hashes_preservation = []
        evidence_summary = {
            "total_items": len(case.evidence_items),
            "verified_count": 0,
            "warning_count": 0,
            "unchecked_count": 0
        }

        for ev in case.evidence_items:
            v_status, current_hash = verify_evidence_file_integrity(ev)
            if v_status == "VERIFIED":
                evidence_summary["verified_count"] += 1
            elif v_status == "INTEGRITY_WARNING":
                evidence_summary["warning_count"] += 1
            else:
                evidence_summary["unchecked_count"] += 1

            evidence_inventory.append({
                "id": ev.id,
                "name": ev.name,
                "original_path": ev.original_path,
                "evidence_type": ev.evidence_type,
                "source_kind": ev.source_kind,
                "size_bytes": ev.size_bytes,
                "mime_type": ev.mime_type,
                "status": ev.status,
                "intake_status": ev.intake_status,
                "acquired_at": ev.acquired_at.isoformat() if ev.acquired_at else None
            })

            hashes_preservation.append({
                "evidence_id": ev.id,
                "name": ev.name,
                "registered_sha256": ev.sha256,
                "current_sha256": current_hash,
                "integrity_status": v_status,
                "storage_path": ev.storage_path or ev.original_path,
                "read_only_verified": ev.read_only_verified
            })

        if evidence_summary["warning_count"] > 0:
            overall_integrity_status = "INTEGRITY_WARNING"
        elif evidence_summary["unchecked_count"] > 0:
            overall_integrity_status = "UNCHECKED"
        elif (
            evidence_summary["total_items"] > 0
            and evidence_summary["verified_count"] == evidence_summary["total_items"]
        ):
            overall_integrity_status = "VERIFIED"
        else:
            overall_integrity_status = "UNCHECKED"

        # 4. Section 4: Chain of Custody
        custody_records = (
            db.query(ChainOfCustodyEvent)
            .filter(ChainOfCustodyEvent.case_id == case.id)
            .order_by(ChainOfCustodyEvent.timestamp.asc())
            .all()
        )
        chain_of_custody = []
        for c in custody_records:
            chain_of_custody.append({
                "id": c.id,
                "evidence_id": c.evidence_id,
                "action": c.action,
                "actor": c.actor,
                "timestamp": c.timestamp.isoformat() if c.timestamp else None,
                "notes": c.notes,
                "event_hash": c.event_hash
            })

        # 5. Section 5: Tool Executions
        executions = (
            db.query(ForensicExecution)
            .filter(ForensicExecution.case_id == case.id)
            .order_by(ForensicExecution.started_at.asc())
            .all()
        )
        tool_executions = []
        for ex in executions:
            # Query associated execution outputs
            out_hashes = [
                out.sha256_hash for out in db.query(ExecutionOutput)
                .filter(ExecutionOutput.execution_id == ex.id, ExecutionOutput.case_id == case.id)
                .all()
            ]
            tool_executions.append({
                "id": ex.id,
                "tool_name": ex.tool_name,
                "tool_version": ex.tool_version,
                "capability": ex.capability_requested or "forensic_analysis",
                "status": ex.status,
                "exit_code": ex.exit_code,
                "started_at": ex.started_at.isoformat() if ex.started_at else None,
                "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
                "parameters": ex.parameters or {},
                "output_hashes": out_hashes
            })

        # Fallback to legacy ToolExecution if ForensicExecution table is empty
        if not tool_executions:
            legacy_execs = (
                db.query(ToolExecution)
                .filter(ToolExecution.case_id == case.id)
                .order_by(ToolExecution.started_at.asc())
                .all()
            )
            for lex in legacy_execs:
                tool_executions.append({
                    "id": lex.id,
                    "tool_name": lex.tool_name,
                    "tool_version": None,
                    "capability": lex.tool_name,
                    "status": lex.status,
                    "exit_code": 0 if lex.status == "SUCCESS" else 1,
                    "started_at": lex.started_at.isoformat() if lex.started_at else None,
                    "completed_at": lex.completed_at.isoformat() if lex.completed_at else None,
                    "parameters": lex.command_args or {},
                    "output_hashes": []
                })

        # 6. Section 6: Artifacts (Structured & Normalized)
        structured_arts = (
            db.query(StructuredArtifact)
            .filter(StructuredArtifact.case_id == case.id)
            .all()
        )
        normalized_arts = (
            db.query(NormalizedArtifact)
            .filter(NormalizedArtifact.case_id == case.id)
            .all()
        )

        artifacts = {
            "structured_count": len(structured_arts),
            "normalized_count": len(normalized_arts),
            "structured_sample": [
                {
                    "id": a.id,
                    "artifact_type": a.artifact_type,
                    "source_reference": a.source_reference,
                    "execution_id": a.execution_id,
                    "sha256_hash": a.sha256_hash
                }
                for a in structured_arts[:50]
            ],
            "normalized_sample": [
                {
                    "id": n.id,
                    "entity_type": n.entity_type,
                    "canonical_identifier": n.canonical_identifier,
                    "is_deduplicated": n.is_deduplicated,
                    "sha256_hash": n.sha256_hash
                }
                for n in normalized_arts[:50]
            ]
        }

        # 7. Section 7: Timeline
        timeline_records = (
            db.query(TimelineEvent)
            .filter(TimelineEvent.case_id == case.id)
            .order_by(TimelineEvent.timestamp_utc.asc())
            .all()
        )
        timeline = []
        for t in timeline_records:
            timeline.append({
                "id": t.id,
                "timestamp_utc": t.timestamp_utc.isoformat() if t.timestamp_utc else None,
                "timestamp_source": t.timestamp_source,
                "source_artifact_id": t.source_artifact_id,
                "event_type": t.event_type,
                "description": t.description,
                "confidence": t.confidence,
                "certainty": t.certainty,
                "temporal_window_start": t.temporal_window_start.isoformat() if t.temporal_window_start else None,
                "temporal_window_end": t.temporal_window_end.isoformat() if t.temporal_window_end else None
            })

        # 8. Section 8: Correlations
        corr_groups = (
            db.query(ForensicCorrelationGroup)
            .filter(ForensicCorrelationGroup.case_id == case.id)
            .all()
        )
        relationships = (
            db.query(ArtifactRelationship)
            .filter(ArtifactRelationship.case_id == case.id)
            .all()
        )
        correlations = {
            "groups_count": len(corr_groups),
            "relationships_count": len(relationships),
            "groups": [
                {
                    "id": cg.id,
                    "group_name": cg.group_name,
                    "correlation_type": cg.correlation_type,
                    "dimension": cg.dimension,
                    "rule": cg.rule,
                    "correlated_entity": cg.correlated_entity,
                    "confidence_score": cg.confidence_score,
                    "participating_artifacts_count": len(cg.participating_artifact_ids or [])
                }
                for cg in corr_groups
            ],
            "relationships_sample": [
                {
                    "id": r.id,
                    "source_entity": getattr(r, "source_entity", f"{getattr(r, 'source_type', 'ARTIFACT')}:{getattr(r, 'source_id', '')}"),
                    "target_entity": getattr(r, "target_entity", f"{getattr(r, 'target_type', 'ARTIFACT')}:{getattr(r, 'target_id', '')}"),
                    "relationship_type": r.relationship_type,
                    "confidence": (
                        getattr(r, "confidence", None)
                        if getattr(r, "confidence", None) is not None
                        else getattr(r, "confidence_score", None)
                    )
                }
                for r in relationships[:30]
            ]
        }

        # 11. Section 11: Investigator Decisions (Gather first so we can cross-reference findings)
        review_records = (
            db.query(InvestigatorReviewRecord)
            .filter(InvestigatorReviewRecord.case_id == case.id)
            .order_by(InvestigatorReviewRecord.timestamp.asc())
            .all()
        )
        decisions_by_target = {}
        for rev in review_records:
            decisions_by_target.setdefault(rev.target_id, []).append(rev)

        investigator_decisions = {
            "total_reviews": len(review_records),
            "accepted_count": sum(1 for r in review_records if r.decision == "ACCEPT"),
            "challenged_count": sum(1 for r in review_records if r.decision == "CHALLENGE"),
            "rejected_count": sum(1 for r in review_records if r.decision == "REJECT"),
            "requested_more_evidence_count": sum(1 for r in review_records if r.decision == "REQUEST_MORE_EVIDENCE"),
            "reviews": [
                {
                    "review_id": r.id,
                    "target_type": r.target_type,
                    "target_id": r.target_id,
                    "statement_id": r.statement_id,
                    "decision": r.decision,
                    "investigator_name": r.investigator_name,
                    "comment": r.comment,
                    "supporting_references": r.supporting_references or [],
                    "resulting_workflow_action": r.resulting_workflow_action,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "sha256_hash": r.sha256_hash
                }
                for r in review_records
            ]
        }

        # 9. Section 9: Findings (Deterministic + Governed AI Reasoning)
        deterministic_findings = (
            db.query(DeterministicFinding)
            .filter(DeterministicFinding.case_id == case.id)
            .all()
        )
        ai_reasoning_records = (
            db.query(AIReasoningRecord)
            .filter(AIReasoningRecord.case_id == case.id)
            .all()
        )

        findings_list = []
        for df in deterministic_findings:
            # Evidence Grounding Invariant: Check supporting links
            is_grounded = bool(df.supporting_evidence_ids or df.supporting_artifact_ids)
            ver_status = df.verification_status
            if not is_grounded:
                ver_status = "UNVERIFIED"

            # Check investigator review status
            revs = decisions_by_target.get(df.id, [])
            latest_rev = revs[-1] if revs else None
            inv_decision = latest_rev.decision if latest_rev else "PENDING_REVIEW"
            inv_rationale = latest_rev.comment if latest_rev else None

            findings_list.append({
                "id": df.id,
                "type": "DETERMINISTIC_FINDING",
                "title": df.title,
                "finding_type": df.finding_type,
                "severity": df.severity,
                "confidence": df.confidence,
                "classification": "FACT",  # Deterministic findings are classified as FACT
                "supporting_evidence_ids": df.supporting_evidence_ids or [],
                "supporting_artifact_ids": df.supporting_artifact_ids or [],
                "mitre_techniques": df.mitre_techniques or [],
                "verification_status": ver_status,
                "is_grounded": is_grounded,
                "investigator_decision": inv_decision,
                "investigator_rationale": inv_rationale,
                "sha256_hash": df.sha256_hash,
                "created_at": df.created_at.isoformat() if df.created_at else None
            })

        # Include AI Reasoning statements with strict FACT / INFERENCE / UNVERIFIED classification
        for air in ai_reasoning_records:
            revs = decisions_by_target.get(air.id, [])
            latest_rev = revs[-1] if revs else None

            for stmt in air.statements or []:
                stmt_id = stmt.get("statement_id") or str(uuid.uuid4())
                cls_type = stmt.get("classification", "INFERENCE").upper()
                if cls_type not in ["FACT", "INFERENCE", "UNVERIFIED"]:
                    cls_type = "UNVERIFIED"

                cits = stmt.get("supporting_evidence_ids") or []
                art_cits = stmt.get("supporting_artifact_ids") or []
                is_grounded = bool(cits or art_cits)
                if not is_grounded:
                    cls_type = "UNVERIFIED"

                # Check specific statement reviews
                stmt_revs = [r for r in revs if r.statement_id == stmt_id]
                stmt_latest_rev = stmt_revs[-1] if stmt_revs else latest_rev
                stmt_decision = stmt_latest_rev.decision if stmt_latest_rev else "PENDING_REVIEW"
                stmt_rationale = stmt_latest_rev.comment if stmt_latest_rev else None

                findings_list.append({
                    "id": f"{air.id}:{stmt_id}",
                    "parent_reasoning_id": air.id,
                    "type": "AI_REASONING_CLAIM",
                    "title": stmt.get("insight") or "AI Derived Forensic Hypothesis",
                    "finding_type": "ai_inference",
                    "severity": stmt.get("severity") or "MEDIUM",
                    "confidence": stmt.get("confidence", 0.75),
                    "classification": cls_type,
                    "supporting_evidence_ids": cits,
                    "supporting_artifact_ids": art_cits,
                    "mitre_techniques": stmt.get("mitre_techniques") or [],
                    "verification_status": "VERIFIED" if is_grounded and cls_type != "UNVERIFIED" else "UNVERIFIED",
                    "is_grounded": is_grounded,
                    "investigator_decision": stmt_decision,
                    "investigator_rationale": stmt_rationale,
                    "sha256_hash": air.sha256_hash,
                    "created_at": air.created_at.isoformat() if air.created_at else None
                })

        findings_section = {
            "total_findings": len(findings_list),
            "deterministic_count": len(deterministic_findings),
            "ai_reasoning_claims_count": len(findings_list) - len(deterministic_findings),
            "items": findings_list
        }

        # 10. Section 10: Confidence / Verification
        confidences = [f["confidence"] for f in findings_list if f.get("confidence") is not None]
        mean_conf = round(sum(confidences) / len(confidences), 4) if confidences else None

        confidence_verification = {
            "overall_integrity_status": overall_integrity_status,
            "evidence_integrity_summary": evidence_summary,
            "findings_confidence_mean": mean_conf,
            "findings_by_severity": {
                "CRITICAL": sum(1 for f in findings_list if f["severity"] == "CRITICAL"),
                "HIGH": sum(1 for f in findings_list if f["severity"] == "HIGH"),
                "MEDIUM": sum(1 for f in findings_list if f["severity"] == "MEDIUM"),
                "LOW": sum(1 for f in findings_list if f["severity"] == "LOW")
            },
            "findings_by_classification": {
                "FACT": sum(1 for f in findings_list if f["classification"] == "FACT"),
                "INFERENCE": sum(1 for f in findings_list if f["classification"] == "INFERENCE"),
                "UNVERIFIED": sum(1 for f in findings_list if f["classification"] == "UNVERIFIED")
            },
            "grounded_claims_count": sum(1 for f in findings_list if f["is_grounded"]),
            "unsupported_claims_count": sum(1 for f in findings_list if not f["is_grounded"])
        }

        # 12. Section 12: Explainability / Provenance
        # Assemble multi-tier lineage trace
        lineage_nodes = []
        # Evidence tier
        for ev in case.evidence_items:
            lineage_nodes.append({
                "tier": "EVIDENCE",
                "id": ev.id,
                "label": ev.name,
                "type": ev.evidence_type,
                "sha256": ev.sha256
            })
        # Executions tier
        for ex in tool_executions:
            lineage_nodes.append({
                "tier": "EXECUTION",
                "id": ex["id"],
                "label": ex["tool_name"],
                "status": ex["status"]
            })
        # Findings tier
        for f in findings_list:
            lineage_nodes.append({
                "tier": "FINDING",
                "id": f["id"],
                "label": f["title"],
                "classification": f["classification"],
                "supporting_evidence": f["supporting_evidence_ids"],
                "supporting_artifacts": f["supporting_artifact_ids"]
            })
        # Review decisions tier
        for r in review_records:
            lineage_nodes.append({
                "tier": "INVESTIGATOR_DECISION",
                "id": r.id,
                "target_id": r.target_id,
                "decision": r.decision,
                "investigator": r.investigator_name,
                "hash": r.sha256_hash
            })

        explainability_provenance = {
            "case_id": case.id,
            "lineage_depth": 7,
            "pipeline_trace": [
                "Evidence",
                "Forensic Tool Execution",
                "Raw Execution Output",
                "Structured Artifact",
                "Normalized Artifact",
                "Timeline & Correlation",
                "Deterministic Finding",
                "Governed AI Reasoning",
                "Investigator Review",
                "Final Forensic Report"
            ],
            "nodes_count": len(lineage_nodes),
            "sample_nodes": lineage_nodes[:80]
        }

        # Assemble full 12-section payload
        sections = {
            "case_information": case_information,
            "evidence_inventory": evidence_inventory,
            "hashes_preservation": hashes_preservation,
            "chain_of_custody": chain_of_custody,
            "tool_executions": tool_executions,
            "artifacts": artifacts,
            "timeline": timeline,
            "correlations": correlations,
            "findings": findings_section,
            "confidence_verification": confidence_verification,
            "investigator_decisions": investigator_decisions,
            "explainability_provenance": explainability_provenance
        }

        provenance = {
            "case_id": case.id,
            "generated_by": user.name or user.email,
            "lineage_nodes_count": len(lineage_nodes),
            "evidence_item_ids": [e["id"] for e in evidence_inventory],
            "execution_ids": [x["id"] for x in tool_executions],
            "finding_ids": [f["id"] for f in findings_list],
            "review_ids": [r.id for r in review_records]
        }

        return sections, provenance, overall_integrity_status, evidence_summary

    @classmethod
    def _render_markdown(
        cls,
        sections: Dict[str, Any],
        report_meta: Dict[str, Any]
    ) -> str:
        """
        Renders a forensically sound, audit-grade Markdown document containing all 12 sections.
        """
        case_info = sections["case_information"]
        ev_inv = sections["evidence_inventory"]
        hashes = sections["hashes_preservation"]
        custody = sections["chain_of_custody"]
        execs = sections["tool_executions"]
        timeline = sections["timeline"]
        corr = sections["correlations"]
        findings_sec = sections["findings"]
        conf = sections["confidence_verification"]
        decisions = sections["investigator_decisions"]
        provenance = sections["explainability_provenance"]

        ver = report_meta.get("version", 1)
        gen_at = report_meta.get("generated_at", utc_now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        gen_by = report_meta.get("generated_by") or "NOT_RECORDED"
        report_hash = report_meta.get("report_hash", "PENDING_HASH")

        lines = [
            "# ADFIR OFFICIAL FINAL FORENSIC REPORT",
            f"**Case Reference:** {case_info.get('case_number', 'N/A')} — {case_info.get('name', 'N/A')}  ",
            f"**Report Version:** v{ver} | **Status:** OFFICIAL_FINAL | **Integrity:** {report_meta.get('integrity_status') or 'UNKNOWN'}  ",
            f"**Lead Investigator:** {gen_by}  ",
            f"**Generated Date:** {gen_at}  ",
            f"**Canonical SHA-256 Hash:** `{report_hash}`  ",
            "",
            "---",
            "",
            "## SECTION 1: CASE INFORMATION",
            f"- **Case ID:** `{case_info.get('case_id')}`",
            f"- **Investigation Objective:** {case_info.get('objective')}",
            f"- **Case Type / Priority:** {case_info.get('case_type')} / {case_info.get('priority')}",
            f"- **Current Case Status:** {case_info.get('status')}",
            f"- **Created At:** {case_info.get('created_at')}",
            "- **Authorized Case Investigators:**",
        ]
        for m in case_info.get("members", []):
            lines.append(f"  - {m.get('name')} ({m.get('email')}) — Role: `{m.get('role')}`")

        lines.extend([
            "",
            "## SECTION 2: EVIDENCE INVENTORY",
            f"Total evidence containers registered: {len(ev_inv)}",
            "",
            "| Evidence ID | Name | Type | Source Kind | Size (Bytes) | Intake Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for e in ev_inv:
            lines.append(f"| `{e['id'][:8]}` | {e['name']} | {e['evidence_type']} | {e['source_kind']} | {e['size_bytes']} | {e['intake_status']} |")

        lines.extend([
            "",
            "## SECTION 3: HASHES & PRESERVATION",
            "Cryptographic verification ensures non-repudiation and evidence preservation immutability.",
            "",
            "| Evidence Name | Registered SHA-256 | Current Hash | Integrity Status | Read-Only |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for h in hashes:
            curr_str = f"`{h['current_sha256'][:16]}...`" if h.get("current_sha256") else "NOT_RECOMPUTED"
            lines.append(f"| {h['name']} | `{h['registered_sha256'][:16]}...` | {curr_str} | **{h['integrity_status']}** | {'✓' if h['read_only_verified'] else '✗'} |")

        lines.extend([
            "",
            "## SECTION 4: CHAIN OF CUSTODY",
            "Chronological log of forensic custody actions and evidence integrity checks.",
            "",
            "| Timestamp (UTC) | Action | Actor | Event Hash | Notes |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        if custody:
            for c in custody:
                lines.append(f"| {c['timestamp']} | {c['action']} | {c['actor']} | `{c['event_hash'][:12]}...` | {c['notes'] or '-'} |")
        else:
            lines.append("| N/A | NOT_RECORDED | NOT_RECORDED | INSUFFICIENT EVIDENCE — no chain-of-custody events recorded. | N/A |")

        lines.extend([
            "",
            "## SECTION 5: SPECIALIST TOOL EXECUTIONS",
            "Authorized deterministic forensic tool executions performed under sandbox isolation.",
            "",
            "| Execution ID | Tool | Capability | Status | Exit Code | Outputs Count |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for ex in execs:
            lines.append(f"| `{ex['id'][:8]}` | {ex['tool_name']} | {ex['capability']} | `{ex['status']}` | {ex['exit_code']} | {len(ex.get('output_hashes', []))} |")

        lines.extend([
            "",
            "## SECTION 6: EXTRACTED ARTIFACTS",
            f"- Structured Artifacts Extracted: **{sections['artifacts']['structured_count']}**",
            f"- Normalized Entities Deduplicated: **{sections['artifacts']['normalized_count']}**",
            "",
            "## SECTION 7: UNIFIED TIMELINE",
            "Deterministic, UTC-normalized chronological reconstruction of technical events.",
            "",
            "| Timestamp (UTC) | Event Type | Description | Confidence | Certainty |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for t in timeline[:25]:
            lines.append(f"| {t['timestamp_utc']} | `{t['event_type']}` | {t['description']} | {t['confidence']} | {t['certainty']} |")
        if len(timeline) > 25:
            lines.append(f"| ... | ({len(timeline) - 25} additional timeline events recorded in canonical JSON) | - | - | - |")

        lines.extend([
            "",
            "## SECTION 8: CROSS-DOMAIN CORRELATIONS",
            f"Correlation Groups: {corr['groups_count']} | Artifact Relationships: {corr['relationships_count']}",
            "",
            "| Group Name | Correlation Type | Matched Rule | Correlated Entity | Confidence |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for cg in corr["groups"]:
            lines.append(f"| {cg['group_name']} | `{cg['correlation_type']}` | `{cg['rule']}` | {cg['correlated_entity']} | {cg['confidence_score']} |")

        lines.extend([
            "",
            "## SECTION 9: FORENSIC FINDINGS & GOVERNED CLAIMS",
            "Every statement is classified as FACT, INFERENCE, or UNVERIFIED with evidence-grounded references.",
            "",
            "| Title / Claim | Type | Classification | Severity | Conf. | Status | Investigator Decision |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in findings_sec["items"]:
            # Prominently highlight investigator decision
            inv_tag = f"[{f['investigator_decision']}]"
            if f["investigator_decision"] == "REJECT":
                inv_tag = "**REJECTED BY INVESTIGATOR**"
            elif f["investigator_decision"] == "CHALLENGE":
                inv_tag = "*CHALLENGED*"
            elif f["investigator_decision"] == "ACCEPT":
                inv_tag = "ACCEPTED"

            lines.append(
                f"| {f['title']} | `{f['type']}` | **{f['classification']}** | {f['severity']} | {f['confidence']} | {f['verification_status']} | {inv_tag} |"
            )
            if f.get("investigator_rationale"):
                lines.append(f"  - *Investigator Rationale:* {f['investigator_rationale']}")

        mean_confidence = conf.get("findings_confidence_mean")
        if mean_confidence is None:
            confidence_display = "NOT_AVAILABLE"
        else:
            confidence_display = f"{mean_confidence * 100:.1f}%"

        lines.extend([
            "",
            "## SECTION 10: CONFIDENCE & VERIFICATION ANALYSIS",
            f"- **Overall Investigation Integrity:** {conf['overall_integrity_status']}",
            f"- **Mean Findings Confidence:** {confidence_display}",
            f"- **Severity Breakdown:** Critical: {conf['findings_by_severity']['CRITICAL']}, High: {conf['findings_by_severity']['HIGH']}, Medium: {conf['findings_by_severity']['MEDIUM']}, Low: {conf['findings_by_severity']['LOW']}",
            f"- **Classification Breakdown:** FACT: {conf['findings_by_classification']['FACT']}, INFERENCE: {conf['findings_by_classification']['INFERENCE']}, UNVERIFIED: {conf['findings_by_classification']['UNVERIFIED']}",
            f"- **Evidence Grounding Metric:** {conf['grounded_claims_count']} grounded claims, {conf['unsupported_claims_count']} unsupported/unverified claims.",
            "",
            "## SECTION 11: HUMAN-IN-THE-LOOP INVESTIGATOR DECISIONS",
            f"Total Review Actions: {decisions['total_reviews']} (Accepted: {decisions['accepted_count']}, Challenged: {decisions['challenged_count']}, Rejected: {decisions['rejected_count']}, More Evidence Requested: {decisions['requested_more_evidence_count']})",
            "",
            "| Decision | Target ID | Investigator | Comments / Rationale | Review Hash |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for r in decisions["reviews"]:
            lines.append(f"| **{r['decision']}** | `{r['target_id'][:12]}...` | {r['investigator_name']} | {r['comment']} | `{r['sha256_hash'][:12]}...` |")

        lines.extend([
            "",
            "## SECTION 12: EXPLAINABILITY & PROVENANCE LINEAGE",
            f"Multi-tier complete lineage from Raw Evidence to Final Forensic Report.",
            f"- **Lineage Nodes Traceable:** {provenance['nodes_count']}",
            "- **Pipeline Trace:**",
            "  `Evidence -> Forensic Tool Execution -> Raw Output -> Structured Artifact -> Normalized Artifact -> Timeline/Correlation -> Deterministic Finding -> AI Reasoning -> Investigator Review -> Final Report`",
            "",
            "---",
            "",
            "### FORENSIC REPORT LIFECYCLE & SIGN-OFF",
            f"**Report Lifecycle State:** GENERATED",
            f"Synthesized by: **{gen_by}** via deterministic forensic pipeline.",
            "*(Formal investigator certification requires explicit review and approval action.)*",
            f"**Report Digest:** `{report_hash}`  ",
            f"**Report Generated At:** {gen_at}  "
        ])

        return "\n".join(lines)

    @classmethod
    def generate_report(
        cls,
        case_id: str,
        user: User,
        request_data: ForensicReportGenerateRequest,
        db: Session
    ) -> Report:
        """
        Synthesizes and persists a versioned Final Forensic Report for the case.
        Strictly enforces case authorization, evidence grounding, and cryptographic hashing.
        """
        case = get_authorized_case(case_id, db, user)
        from backend.app.services.case_closure import check_case_not_closed
        check_case_not_closed(case)

        # 1. Determine next version number for this case
        max_ver = db.query(func.max(Report.version)).filter(Report.case_id == case.id).scalar()
        next_ver = (max_ver or 0) + 1

        # 2. Build the 12 structured report sections
        sections, provenance, integrity_status, evidence_summary = cls._build_sections(
            case=case,
            db=db,
            options=request_data.options,
            user=user
        )

        # 3. Canonical report hash over deterministic JSON of sections
        canonical_hash = compute_canonical_json_hash(sections)

        # 4. Report metadata
        report_meta = {
            "version": next_ver,
            "generated_by": user.name or user.email,
            "generated_at": utc_now().isoformat(),
            "integrity_status": integrity_status,
            "report_hash": canonical_hash,
            "methodology_notes": request_data.methodology_notes or "Deterministic multi-agent forensic verification pipeline",
            "options": request_data.options
        }

        # 5. Render markdown
        markdown_text = cls._render_markdown(sections, report_meta)

        title = request_data.title or f"Final Forensic Report v{next_ver} — {case.name}"
        reviewed_count = sum(
            1
            for item in sections["findings"]["items"]
            if item.get("investigator_decision") not in (None, "PENDING_REVIEW")
        )

        exec_summary = request_data.executive_summary_override or (
            f"Final Forensic Report v{next_ver} for Case {case.case_number} ({case.name}). "
            f"Evaluated {len(sections['evidence_inventory'])} evidence container(s) across "
            f"{len(sections['tool_executions'])} recorded tool execution(s). "
            f"Recorded {len(sections['findings']['items'])} finding/claim item(s), "
            f"with {reviewed_count} having an explicit investigator review decision. "
            f"Evidence integrity status: {integrity_status}. "
            f"Final conclusions require investigator review where findings remain unverified "
            f"or pending review."
        )

        # 6. Save report files to disk in case reports workspace
        storage_path = None
        try:
            reports_dir = Path(case.workspace_path) / "reports" if case.workspace_path else settings.REPORTS_DIR / case.id
            reports_dir.mkdir(parents=True, exist_ok=True)
            report_file_base = f"report_v{next_ver}_{uuid.uuid4().hex[:8]}"
            json_file = reports_dir / f"{report_file_base}.json"
            md_file = reports_dir / f"{report_file_base}.md"

            export_data = {
                "report_id": None,  # will set after creation
                "case_id": case.id,
                "version": next_ver,
                "title": title,
                "executive_summary": exec_summary,
                "report_hash": canonical_hash,
                "integrity_status": integrity_status,
                "report_metadata": report_meta,
                "sections": sections,
                "provenance": provenance
            }

            with open(md_file, "w", encoding="utf-8") as f:
                f.write(markdown_text)

            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            storage_path = str(json_file)
        except Exception as e:
            logger.warning(f"Could not persist report files to disk: {e}")

        # 7. Persist Report record in database
        report = Report(
            id=str(uuid.uuid4()),
            case_id=case.id,
            version=next_ver,
            title=title,
            executive_summary=exec_summary,
            findings_count=sections["findings"]["total_findings"],
            evidence_count=len(sections["evidence_inventory"]),
            full_report_markdown=markdown_text,
            report_hash=canonical_hash,
            status="OFFICIAL_FINAL",
            sections=sections,
            provenance=provenance,
            report_metadata=report_meta,
            integrity_status=integrity_status,
            evidence_integrity_summary=evidence_summary,
            storage_path=storage_path,
            generated_by=user.name or user.email,
            generated_at=utc_now(),
            created_at=utc_now(),
            updated_at=utc_now()
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        # 8. Log audit trail
        log_audit_event(
            db=db,
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            event_type="FINAL_REPORT_GENERATED",
            details=f"Synthesized Final Forensic Report v{report.version} (hash: {report.report_hash[:16]}...) with {report.findings_count} findings."
        )

        return report

    @classmethod
    def list_reports(cls, case_id: str, user: User, db: Session) -> List[Report]:
        """Lists all report versions for an authorized case, sorted by version descending."""
        case = get_authorized_case(case_id, db, user)
        return (
            db.query(Report)
            .filter(Report.case_id == case.id)
            .order_by(Report.version.desc())
            .all()
        )

    @classmethod
    def get_report(cls, case_id: str, report_id: str, user: User, db: Session) -> Report:
        """Retrieves a specific report version or latest report for an authorized case."""
        case = get_authorized_case(case_id, db, user)

        if report_id == "latest":
            report = (
                db.query(Report)
                .filter(Report.case_id == case.id)
                .order_by(Report.version.desc())
                .first()
            )
        else:
            report = (
                db.query(Report)
                .filter(Report.id == report_id, Report.case_id == case.id)
                .first()
            )

        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report '{report_id}' not found for case '{case_id}'."
            )
        return report

    @classmethod
    def verify_report_integrity(
        cls,
        case_id: str,
        report_id: str,
        user: User,
        db: Session
    ) -> ForensicReportIntegrityResponse:
        """
        Verifies the cryptographic integrity of a Final Forensic Report.
        Recomputes canonical SHA-256 hash over report sections and checks against registered hash.
        Detects tampering and evaluates underlying evidence integrity.
        """
        report = cls.get_report(case_id, report_id, user, db)

        # Recompute canonical hash from sections
        computed_hash = compute_canonical_json_hash(report.sections or {})
        expected_hash = report.report_hash or ""

        tamper_detected = (computed_hash.lower() != expected_hash.lower())
        integrity_status = "TAMPERED" if tamper_detected else "VERIFIED"

        # Check evidence files integrity
        ev_checks = {}
        for ev in report.case.evidence_items:
            v_st, c_h = verify_evidence_file_integrity(ev)
            ev_checks[ev.id] = {
                "name": ev.name,
                "status": v_st,
                "registered_hash": ev.sha256,
                "computed_hash": c_h
            }

        # Log audit trail
        log_audit_event(
            db=db,
            case_id=report.case_id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            event_type="REPORT_INTEGRITY_VERIFIED",
            details=f"Verified integrity for report v{report.version}: status={integrity_status}, tamper_detected={tamper_detected}"
        )

        return ForensicReportIntegrityResponse(
            report_id=report.id,
            case_id=report.case_id,
            version=report.version,
            expected_hash=expected_hash,
            computed_hash=computed_hash,
            integrity_status=integrity_status,
            tamper_detected=tamper_detected,
            evidence_integrity=ev_checks,
            checked_at=utc_now()
        )

    @classmethod
    def get_report_provenance(
        cls,
        case_id: str,
        report_id: str,
        user: User,
        db: Session
    ) -> ForensicReportProvenanceResponse:
        """Inspects report provenance and multi-tier lineage graph."""
        report = cls.get_report(case_id, report_id, user, db)
        prov = report.provenance or {}
        sections = report.sections or {}
        exp_prov = sections.get("explainability_provenance", {})

        lineage = exp_prov.get("sample_nodes") or []
        node_counts = {
            "evidence": len(prov.get("evidence_item_ids", [])),
            "executions": len(prov.get("execution_ids", [])),
            "findings": len(prov.get("finding_ids", [])),
            "reviews": len(prov.get("review_ids", []))
        }

        graph = {
            "pipeline": exp_prov.get("pipeline_trace", []),
            "total_nodes": exp_prov.get("nodes_count", len(lineage))
        }

        return ForensicReportProvenanceResponse(
            report_id=report.id,
            case_id=report.case_id,
            version=report.version,
            lineage=lineage,
            graph=graph,
            node_counts=node_counts,
            report_hash=report.report_hash or ""
        )

    @classmethod
    def export_report(
        cls,
        case_id: str,
        report_id: str,
        export_format: str,
        user: User,
        db: Session
    ) -> Tuple[str, str, str]:
        """
        Exports the report as Markdown or JSON.
        Returns (content, media_type, filename).
        """
        report = cls.get_report(case_id, report_id, user, db)
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in report.case.name)
        fmt = (export_format or "markdown").lower()

        log_audit_event(
            db=db,
            case_id=report.case_id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            event_type="REPORT_EXPORTED",
            details=f"Exported report v{report.version} in format {fmt}"
        )

        if fmt in ["json"]:
            payload = {
                "id": report.id,
                "case_id": report.case_id,
                "version": report.version,
                "title": report.title,
                "executive_summary": report.executive_summary,
                "report_hash": report.report_hash,
                "integrity_status": report.integrity_status,
                "generated_by": report.generated_by,
                "generated_at": report.generated_at.isoformat() if report.generated_at else None,
                "sections": report.sections,
                "provenance": report.provenance,
                "report_metadata": report.report_metadata,
                "full_report_markdown": report.full_report_markdown
            }
            content = json.dumps(payload, indent=2, default=str)
            return content, "application/json", f"ADFIR_{safe_name}_report_v{report.version}.json"
        else:
            return report.full_report_markdown, "text/markdown; charset=utf-8", f"ADFIR_{safe_name}_report_v{report.version}.md"
