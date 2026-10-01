"""ADFIR — Case Closure & Forensic Data Immutability Service (Final Backend Completion)

Enforces strict backend case-closure gates:
1. Verifies case exists and is not already closed or archived.
2. Verifies raw evidence cryptographic integrity against preserved files.
3. Verifies tamper-free status of the hash-chained audit trail.
4. Verifies presence and canonical SHA-256 digest of the official final forensic report.
5. Verifies no active/running investigation runs or tasks remain open.
6. Verifies human investigator authorization and rationale.
7. Computes immutable canonical closure digest.
8. Persists closure state and records immutable closure audit event.
9. Enforces forensic data immutability on closed cases (rejecting any subsequent modifications).
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.models import (
    Case,
    EvidenceItem,
    Report,
    AuditEvent,
    InvestigationPlan,
    InvestigationRun,
    InvestigationTask,
    AnalysisRequest,
    ForensicExecution,
    User
)
from backend.app.schemas.schemas import CaseClosureRequest, CaseClosureResponse
from backend.app.services.audit import AuditService, log_audit_event
from backend.app.services.integrity import calculate_sha256

logger = logging.getLogger("ADFIR_CASE_CLOSURE")


def check_case_not_closed(case: Case) -> None:
    """
    Enforces forensic data immutability on closed cases.
    Raises HTTPException 400 if the case is already CLOSED or ARCHIVED.
    """
    if case.status in ("CLOSED", "ARCHIVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Forensic operation rejected: Case '{case.id}' ({case.case_number}) is {case.status} and immutable."
        )


class CaseClosureService:
    """
    Validates and executes formal case closure.
    """

    @classmethod
    def validate_and_close_case(
        cls,
        db: Session,
        case_id: str,
        user: User,
        request_data: CaseClosureRequest
    ) -> CaseClosureResponse:
        """
        Executes formal case closure with full pre-closure verification gates.
        """
        now = datetime.now(timezone.utc)
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
        from backend.app.services.authorization import get_authorized_case
        case = get_authorized_case(case_id, db, user)

        user_role = (user.role or "").upper().strip()
        if user_role not in ("ADMIN", "ADMINISTRATOR", "ORG_ADMIN", "INVESTIGATOR", "LEAD_INVESTIGATOR"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: User role '{user.role}' lacks permission to close cases."
            )

        # Check not already closed
        if case.status in ("CLOSED", "ARCHIVED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Case '{case_id}' is already {case.status}."
            )

        # Gate 1: Check no active investigation runs
        active_runs = db.query(InvestigationRun).filter(
            InvestigationRun.case_id == case.id,
            InvestigationRun.status.in_(["RUNNING", "PENDING", "INTERRUPTED", "RECOVERED"])
        ).all()
        if active_runs:
            run_ids = [r.id for r in active_runs]
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: {len(active_runs)} active investigation run(s) are in progress ({', '.join(run_ids)})."
            )

        # Gate 1b: Check no active investigation tasks
        active_tasks = db.query(InvestigationTask).join(InvestigationPlan).filter(
            InvestigationPlan.case_id == case.id,
            InvestigationTask.status.in_(["RUNNING", "READY"])
        ).all()
        if active_tasks:
            task_ids = [t.id for t in active_tasks]
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: {len(active_tasks)} active investigation task(s) remain open ({', '.join(task_ids)})."
            )

        # Gate 2: Check no active analysis requests or executions
        active_requests = db.query(AnalysisRequest).filter(
            AnalysisRequest.case_id == case.id,
            AnalysisRequest.scheduler_status.in_(["RUNNING", "READY", "QUEUED", "WAITING_DEPENDENCY", "WAITING_RESOURCE"])
        ).all()
        if active_requests:
            req_ids = [r.id for r in active_requests]
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: {len(active_requests)} analysis requests are active or queued ({', '.join(req_ids)})."
            )

        active_executions = db.query(ForensicExecution).filter(
            ForensicExecution.case_id == case.id,
            ForensicExecution.execution_status.in_(["STARTING", "RUNNING"])
        ).all()
        if active_executions:
            exec_ids = [e.id for e in active_executions]
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: {len(active_executions)} forensic tool execution(s) are running ({', '.join(exec_ids)})."
            )

        # Gate 3: Evidence Cryptographic Integrity Verification
        evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
        evidence_verified_count = 0
        for ev in evidence_items:
            path_to_check = ev.storage_path or ev.original_path
            if path_to_check:
                try:
                    recomputed_hash, _ = calculate_sha256(path_to_check)
                    if recomputed_hash.lower() != ev.sha256.lower():
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=(
                                f"Cannot close case: Evidence integrity check failed for evidence '{ev.id}' "
                                f"({ev.name}). Expected hash '{ev.sha256}', recomputed '{recomputed_hash}'."
                            )
                        )
                    evidence_verified_count += 1
                except FileNotFoundError:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Cannot close case: Evidence file missing on disk for evidence '{ev.id}' ({ev.name})."
                    )

        # Gate 4: Audit Chain Integrity Verification
        audit_verification = AuditService.verify_chain(db, case_id=case.id)
        if not audit_verification.is_valid or audit_verification.tamper_detected:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: Audit chain tampering detected! {audit_verification.verification_message}"
            )

        # Gate 5: Final Report Verification
        latest_report = db.query(Report).filter(
            Report.case_id == case.id,
            Report.status == "OFFICIAL_FINAL"
        ).order_by(Report.version.desc()).first()

        if not latest_report:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Cannot close case: Official Final Forensic Report has not been generated for this case."
            )

        if not latest_report.report_hash:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cannot close case: Official report '{latest_report.id}' lacks a canonical SHA-256 digest."
            )

        # Compute Canonical Case Closure Hash
        closure_payload = {
            "case_id": case.id,
            "case_number": case.case_number,
            "closed_at": now.isoformat(),
            "closed_by": user.email,
            "closure_rationale": request_data.rationale,
            "evidence_count": len(evidence_items),
            "evidence_verified_count": evidence_verified_count,
            "report_id": latest_report.id,
            "report_version": latest_report.version,
            "report_hash": latest_report.report_hash,
            "audit_events_count": audit_verification.total_events,
            "audit_latest_hash": audit_verification.latest_hash
        }
        raw_closure_str = json.dumps(closure_payload, sort_keys=True)
        closure_hash = hashlib.sha256(raw_closure_str.encode("utf-8")).hexdigest()

        # Update Case State
        case.status = "CLOSED"
        case.closed_at = now
        case.closed_by = user.email
        case.closure_rationale = request_data.rationale
        case.closure_metadata = closure_payload
        case.closure_hash = closure_hash
        db.add(case)
        db.commit()
        db.refresh(case)

        # Log Immutable CASE_CLOSED Event into Audit Chain
        log_audit_event(
            db=db,
            event_type="CASE_CLOSED",
            details=f"Case {case.case_number} closed by {user.email}. Closure hash: {closure_hash}",
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            metadata_json={
                "closure_hash": closure_hash,
                "closure_rationale": request_data.rationale,
                "evidence_verified_count": evidence_verified_count,
                "report_id": latest_report.id,
                "report_hash": latest_report.report_hash,
                "audit_total_events": audit_verification.total_events
            },
            provenance_context={
                "case_id": case.id,
                "report_id": latest_report.id,
                "closure_hash": closure_hash
            }
        )

        logger.info(f"[CASE_CLOSURE] Case {case.id} closed successfully. Hash: {closure_hash}")

        return CaseClosureResponse(
            case_id=case.id,
            status=case.status,
            closed_at=now,
            closed_by=user.email,
            closure_rationale=request_data.rationale,
            closure_hash=closure_hash,
            evidence_verified_count=evidence_verified_count,
            audit_chain_verified=True,
            final_report_verified=True,
            closure_metadata=closure_payload
        )
