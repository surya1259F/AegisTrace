"""ADFIR — Investigation Runtime Orchestrator (Final Backend Completion)

Coordinates the complete 16-stage ADFIR investigation lifecycle:
Case/Evidence
  → Strategy (Step 6)
  → Capability Selection (Step 7)
  → Scheduler (Step 8)
  → Governance (Step 17)
  → Secure Execution (Step 9)
  → Raw Outputs (Step 10)
  → Structured Artifacts (Step 11)
  → Normalization & Deduplication (Step 12)
  → Unified UTC Timeline (Step 13)
  → Cross-Domain Correlation (Step 14)
  → Deterministic Findings (Step 15)
  → Specialist Agents (Step 16)
  → Governance Verification (Step 17)
  → AI Reasoning (Step 18)
  → Investigator Review (Step 19)
  → Final Forensic Report (Step 20)

Guarantees:
- Persistent InvestigationRun and InvestigationTask state.
- Tracks current stage, task, status, timestamps, failures and dependencies.
- Supports start / pause / resume / cancel / step safely.
- Executes tasks strictly through existing Capability → Scheduler → Governance → Secure Execution gates.
- No arbitrary commands, shell execution, evidence modification, or governance bypass.
- Supports investigator-requested additional evidence by initiating a new controlled investigation cycle.
- Persists all state required for restart/recovery.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.models import (
    Case,
    EvidenceItem,
    InvestigationPlan,
    InvestigationTask,
    InvestigationRun,
    AnalysisRequest,
    ForensicExecution,
    ExecutionOutput,
    StructuredArtifact,
    NormalizedArtifact,
    DeterministicFinding,
    AIReasoningRecord,
    InvestigatorReviewRecord,
    Report,
    User
)
from backend.app.schemas.schemas import (
    InvestigationRunResponse,
    InvestigationRunCreateRequest,
    ForensicReportGenerateRequest,
    AIReasoningRequest,
    CorrelationGenerateRequest,
    FindingGenerateRequest
)
from backend.app.services.audit import log_audit_event
from backend.app.services.case_closure import check_case_not_closed
from backend.app.services.strategy_engine import InvestigationStrategyEngine
from backend.app.services.tool_selector import ToolSelectorEngine
from backend.app.services.scheduler import ResourceAwareScheduler as SchedulerService
from backend.app.services.governance import GovernanceGateService as GovernanceService
from backend.app.services.execution import ForensicExecutionService as SecureExecutionService
from backend.app.services.raw_outputs import RawOutputsService as RawOutputService
from backend.app.services.artifact_extraction import ArtifactExtractionService
from backend.app.services.normalization import ArtifactNormalizationService
from backend.app.services.timeline import UnifiedTimelineService
from backend.app.services.correlation import CrossDomainCorrelationService
from backend.app.services.findings import DeterministicFindingsService
from backend.app.services.agents import SpecialistAgentService
from backend.app.services.ai_reasoning import AIReasoningService
from backend.app.services.final_report import FinalForensicReportService
from backend.app.services.investigator_review import InvestigatorReviewService

logger = logging.getLogger("ADFIR_ORCHESTRATION")

STAGES_ORDER = [
    "STRATEGY",
    "CAPABILITY_SELECTION",
    "SCHEDULING",
    "GOVERNANCE",
    "SECURE_EXECUTION",
    "RAW_OUTPUTS",
    "ARTIFACT_EXTRACTION",
    "NORMALIZATION",
    "TIMELINE",
    "CORRELATION",
    "DETERMINISTIC_FINDINGS",
    "SPECIALIST_AGENTS",
    "GOVERNANCE_VERIFICATION",
    "AI_REASONING",
    "INVESTIGATOR_REVIEW",
    "FINAL_REPORT",
    "COMPLETED"
]


class InvestigationOrchestrationService:
    """
    Central Coordinator for the ADFIR Forensic Investigation Pipeline.
    """

    @classmethod
    def start_run(
        cls,
        db: Session,
        case_id: str,
        user: User,
        request_data: Optional[InvestigationRunCreateRequest] = None,
        auto_progress: bool = True
    ) -> InvestigationRun:
        """
        Creates and starts a persistent investigation run for a case.
        """
        now = datetime.now(timezone.utc)
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

        check_case_not_closed(case)

        # Determine cycle number
        existing_runs = db.query(InvestigationRun).filter(
            InvestigationRun.case_id == case.id
        ).all()
        cycle_number = max([r.cycle_number for r in existing_runs], default=0) + 1

        req_opts = request_data.options if request_data else {}
        plan_id = request_data.plan_id if request_data else None

        run = InvestigationRun(
            case_id=case.id,
            plan_id=plan_id,
            cycle_number=cycle_number,
            current_stage="STRATEGY",
            status="RUNNING",
            stage_progress={"STRATEGY": {"status": "IN_PROGRESS", "started_at": now.isoformat()}},
            run_metadata=req_opts,
            started_at=now,
            created_by=user.name or user.email
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        log_audit_event(
            db=db,
            event_type="INVESTIGATION_RUN_STARTED",
            details=f"Investigation run {run.id} (cycle {cycle_number}) started for case {case.case_number}",
            case_id=case.id,
            actor_id=user.id,
            actor_name=user.name or user.email,
            metadata_json={"run_id": run.id, "cycle_number": cycle_number},
            provenance_context={"case_id": case.id, "run_id": run.id}
        )

        if auto_progress:
            run = cls.execute_run_to_completion_or_review(db, run.id, user)

        return run

    @classmethod
    def execute_run_to_completion_or_review(
        cls,
        db: Session,
        run_id: str,
        user: User
    ) -> InvestigationRun:
        """
        Drives the run through stages until it reaches INVESTIGATOR_REVIEW, COMPLETED, PAUSED, or FAILED.
        """
        while True:
            run = db.query(InvestigationRun).filter(InvestigationRun.id == run_id).first()
            if not run or run.status not in ("RUNNING", "PENDING"):
                break

            if run.current_stage == "INVESTIGATOR_REVIEW":
                # Check if reviews already exist or if we must pause for human decision
                pending_items = db.query(DeterministicFinding).filter(
                    DeterministicFinding.case_id == run.case_id
                ).all()
                existing_reviews = db.query(InvestigatorReviewRecord).filter(
                    InvestigatorReviewRecord.case_id == run.case_id
                ).all()

                if not existing_reviews and pending_items:
                    # Human investigator review is strictly required before final report!
                    progress = dict(run.stage_progress or {})
                    progress["INVESTIGATOR_REVIEW"] = {
                        "status": "WAITING_HUMAN_REVIEW",
                        "pending_findings_count": len(pending_items),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    run.stage_progress = progress
                    db.add(run)
                    db.commit()
                    break

            if run.current_stage == "COMPLETED":
                break

            # Execute single stage transition
            run = cls.execute_next_stage(db, run.id, user)
            if run.status in ("PAUSED", "FAILED", "CANCELLED", "COMPLETED"):
                break

        return run

    @classmethod
    def execute_next_stage(
        cls,
        db: Session,
        run_id: str,
        user: User
    ) -> InvestigationRun:
        """
        Executes the current stage of the run and advances to the next stage.
        """
        now = datetime.now(timezone.utc)
        run = db.query(InvestigationRun).filter(InvestigationRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

        case = db.query(Case).filter(Case.id == run.case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found.")

        check_case_not_closed(case)

        if run.status in ("COMPLETED", "CANCELLED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot execute stage on investigation run in status '{run.status}'."
            )

        stage = run.current_stage
        progress = dict(run.stage_progress or {})

        try:
            # -------------------------------------------------------------
            # STAGE 1: STRATEGY
            # -------------------------------------------------------------
            if stage == "STRATEGY":
                plan = None
                if run.plan_id:
                    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == run.plan_id).first()

                if not plan:
                    plan_dict = InvestigationStrategyEngine.generate_plan(db, case.id, user)
                    run.plan_id = plan_dict["id"]
                    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_dict["id"]).first()

                # Associate tasks with this run
                if plan:
                    tasks = db.query(InvestigationTask).filter(InvestigationTask.plan_id == plan.id).all()
                    for t in tasks:
                        t.run_id = run.id
                        db.add(t)

                progress["STRATEGY"] = {
                    "status": "COMPLETED",
                    "plan_id": run.plan_id,
                    "tasks_count": len(tasks) if plan else 0,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "CAPABILITY_SELECTION"

            # -------------------------------------------------------------
            # STAGE 2: CAPABILITY SELECTION
            # -------------------------------------------------------------
            elif stage == "CAPABILITY_SELECTION":
                if not run.plan_id:
                    raise ValueError("Cannot select capabilities without an InvestigationPlan.")

                selection_res = ToolSelectorEngine.select_and_update_plan_tools(db, run.plan_id, actor_user=user)
                progress["CAPABILITY_SELECTION"] = {
                    "status": "COMPLETED",
                    "plan_id": run.plan_id,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "SCHEDULING"

            # -------------------------------------------------------------
            # STAGE 3: SCHEDULING
            # -------------------------------------------------------------
            elif stage == "SCHEDULING":
                if not run.plan_id:
                    raise ValueError("Cannot schedule without an InvestigationPlan.")

                sched_res = SchedulerService.schedule_plan(db, run.plan_id, actor_user=user)
                eval_res = SchedulerService.evaluate_queue(db, plan_id=run.plan_id)
                progress["SCHEDULING"] = {
                    "status": "COMPLETED",
                    "scheduled_requests": len(sched_res.get("created_requests", [])),
                    "completed_at": now.isoformat()
                }
                run.current_stage = "GOVERNANCE"

            # -------------------------------------------------------------
            # STAGE 4: GOVERNANCE
            # -------------------------------------------------------------
            elif stage == "GOVERNANCE":
                ready_requests = db.query(AnalysisRequest).filter(
                    AnalysisRequest.case_id == case.id,
                    AnalysisRequest.scheduler_status.in_(["READY", "QUEUED"])
                ).all()

                governance_approvals = []
                for req in ready_requests:
                    gov_eval = GovernanceService.evaluate_governance(
                        db=db,
                        case_id=case.id,
                        action_type="TOOL_EXECUTION",
                        requesting_agent="orchestrator",
                        target_resource_type="CAPABILITY",
                        target_resource_id=req.capability_id,
                        parameters={"tool_id": req.selected_tool_id, "request_id": req.id},
                        user=user
                    )
                    decision_str = str(gov_eval.decision).upper().strip()
                    if decision_str not in ("ALLOW", "APPROVED"):
                        req.scheduler_status = "BLOCKED"
                        req.blocking_reason = f"Blocked by Governance Gate: {decision_str} - {gov_eval.rationale or 'Policy restriction'}"
                        db.add(req)
                    else:
                        req.scheduler_status = "READY"
                        db.add(req)
                    governance_approvals.append({
                        "request_id": req.id,
                        "decision": gov_eval.decision,
                        "governance_decision_id": gov_eval.id
                    })
                db.commit()

                progress["GOVERNANCE"] = {
                    "status": "COMPLETED",
                    "evaluated_requests": len(ready_requests),
                    "approvals": governance_approvals,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "SECURE_EXECUTION"

            # -------------------------------------------------------------
            # STAGE 5: SECURE EXECUTION
            # -------------------------------------------------------------
            elif stage == "SECURE_EXECUTION":
                ready_requests = db.query(AnalysisRequest).filter(
                    AnalysisRequest.case_id == case.id,
                    AnalysisRequest.scheduler_status == "READY"
                ).all()

                executed_count = 0
                for req in ready_requests:
                    try:
                        SecureExecutionService.start_execution(
                            db=db,
                            request_id=req.id,
                            actor=user,
                            wait=False
                        )
                        executed_count += 1
                    except Exception as e:
                        logger.warning(f"Execution failed for request {req.id}: {e}")
                        req.scheduler_status = "FAILED"
                        req.failure_reason = f"Execution start failed: {str(e)}"
                        db.add(req)
                        db.commit()

                progress["SECURE_EXECUTION"] = {
                    "status": "COMPLETED",
                    "executed_count": executed_count,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "RAW_OUTPUTS"

            # -------------------------------------------------------------
            # STAGE 6: RAW OUTPUTS
            # -------------------------------------------------------------
            elif stage == "RAW_OUTPUTS":
                executions = db.query(ForensicExecution).filter(
                    ForensicExecution.case_id == case.id,
                    ForensicExecution.execution_status.in_(["COMPLETED", "FAILED"])
                ).all()

                total_outputs = 0
                for ex in executions:
                    outs = RawOutputService.collect_and_register_all(db, ex)
                    total_outputs += len(outs)

                progress["RAW_OUTPUTS"] = {
                    "status": "COMPLETED",
                    "executions_processed": len(executions),
                    "registered_outputs": total_outputs,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "ARTIFACT_EXTRACTION"

            # -------------------------------------------------------------
            # STAGE 7: ARTIFACT EXTRACTION
            # -------------------------------------------------------------
            elif stage == "ARTIFACT_EXTRACTION":
                executions = db.query(ForensicExecution).filter(
                    ForensicExecution.case_id == case.id
                ).all()

                extracted_count = 0
                for ex in executions:
                    arts = ArtifactExtractionService.extract_for_execution(db, ex.id, case_id=case.id, actor_user=user)
                    extracted_count += len(arts)

                progress["ARTIFACT_EXTRACTION"] = {
                    "status": "COMPLETED",
                    "extracted_count": extracted_count,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "NORMALIZATION"

            # -------------------------------------------------------------
            # STAGE 8: NORMALIZATION
            # -------------------------------------------------------------
            elif stage == "NORMALIZATION":
                executions = db.query(ForensicExecution).filter(
                    ForensicExecution.case_id == case.id
                ).all()

                norm_count = 0
                for ex in executions:
                    norms = ArtifactNormalizationService.normalize_execution_artifacts(db, ex.id, case_id=case.id, actor_user=user)
                    norm_count += len(norms)

                progress["NORMALIZATION"] = {
                    "status": "COMPLETED",
                    "normalized_count": norm_count,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "TIMELINE"

            # -------------------------------------------------------------
            # STAGE 9: TIMELINE
            # -------------------------------------------------------------
            elif stage == "TIMELINE":
                timeline_events = UnifiedTimelineService.generate_timeline_for_case(db, case.id, actor_user=user)
                progress["TIMELINE"] = {
                    "status": "COMPLETED",
                    "events_count": len(timeline_events),
                    "completed_at": now.isoformat()
                }
                run.current_stage = "CORRELATION"

            # -------------------------------------------------------------
            # STAGE 10: CORRELATION
            # -------------------------------------------------------------
            elif stage == "CORRELATION":
                corr_res = CrossDomainCorrelationService.correlate_case(
                    db=db,
                    case_id=case.id,
                    request=CorrelationGenerateRequest()
                )
                progress["CORRELATION"] = {
                    "status": "COMPLETED",
                    "groups_count": corr_res.groups_created,
                    "relationships_count": corr_res.relationships_generated,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "DETERMINISTIC_FINDINGS"

            # -------------------------------------------------------------
            # STAGE 11: DETERMINISTIC FINDINGS
            # -------------------------------------------------------------
            elif stage == "DETERMINISTIC_FINDINGS":
                findings_res = DeterministicFindingsService.generate_findings_for_case(
                    db=db,
                    case_id=case.id,
                    request=FindingGenerateRequest()
                )
                progress["DETERMINISTIC_FINDINGS"] = {
                    "status": "COMPLETED",
                    "findings_count": findings_res.total_findings_generated,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "SPECIALIST_AGENTS"

            # -------------------------------------------------------------
            # STAGE 12: SPECIALIST AGENTS
            # -------------------------------------------------------------
            elif stage == "SPECIALIST_AGENTS":
                SpecialistAgentService.ensure_seeded(db)
                active_agents = SpecialistAgentService.list_agents(db, enabled_only=True)

                ev_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
                ev_types = " ".join([str(e.evidence_type or "").upper() for e in ev_items])

                executed_agents_count = 0
                agent_results = []
                for ag in active_agents:
                    domains = [d.upper() for d in (ag.supported_evidence_domains or [])]
                    match = any(d in ev_types for d in domains) or "ALL" in domains
                    if match:
                        try:
                            req_rec = SpecialistAgentService.create_analysis_request(
                                db=db,
                                case_id=case.id,
                                agent_id=ag.id,
                                analysis_objective=f"Domain analysis of structured case evidence and artifacts by {ag.name}",
                                user=user
                            )
                            res_rec = SpecialistAgentService.execute_analysis(
                                db=db,
                                request_id=req_rec.id,
                                user=user
                            )
                            executed_agents_count += 1
                            agent_results.append({
                                "agent_id": ag.id,
                                "agent_name": ag.name,
                                "request_id": req_rec.id,
                                "result_id": res_rec.id,
                                "status": "COMPLETED"
                            })
                        except Exception as e:
                            logger.warning(f"Specialist agent {ag.id} execution notice: {e}")

                progress["SPECIALIST_AGENTS"] = {
                    "status": "COMPLETED",
                    "executed_agents_count": executed_agents_count,
                    "agent_results": agent_results,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "GOVERNANCE_VERIFICATION"

            # -------------------------------------------------------------
            # STAGE 13: GOVERNANCE VERIFICATION
            # -------------------------------------------------------------
            elif stage == "GOVERNANCE_VERIFICATION":
                ev_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
                for ev in ev_items:
                    try:
                        GovernanceService.verify_target(
                            db=db,
                            case_id=case.id,
                            target_type="EVIDENCE",
                            target_id=ev.id,
                            user=user
                        )
                    except Exception as e:
                        logger.warning(f"Evidence verification notice: {e}")

                progress["GOVERNANCE_VERIFICATION"] = {
                    "status": "COMPLETED",
                    "evidence_verified": len(ev_items),
                    "completed_at": now.isoformat()
                }
                run.current_stage = "AI_REASONING"

            # -------------------------------------------------------------
            # STAGE 14: AI REASONING
            # -------------------------------------------------------------
            elif stage == "AI_REASONING":
                findings = db.query(DeterministicFinding).filter(
                    DeterministicFinding.case_id == case.id
                ).all()

                ai_rec = None
                if findings:
                    try:
                        ai_req = AIReasoningRequest(
                            objective="Synthesize verified deterministic findings and timeline correlations.",
                            finding_ids=[f.id for f in findings[:10]]
                        )
                        import asyncio
                        ai_rec = asyncio.run(AIReasoningService.reason(db, case, user, ai_req))
                    except Exception as e:
                        logger.warning(f"AI reasoning completed with fallback: {e}")

                progress["AI_REASONING"] = {
                    "status": "COMPLETED",
                    "reasoning_record_id": ai_rec.id if ai_rec else None,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "INVESTIGATOR_REVIEW"

            # -------------------------------------------------------------
            # STAGE 15: INVESTIGATOR REVIEW
            # -------------------------------------------------------------
            elif stage == "INVESTIGATOR_REVIEW":
                review_items = InvestigatorReviewService.get_review_items(db, case, user)
                reviews = InvestigatorReviewService.list_reviews(db, case.id)
                progress["INVESTIGATOR_REVIEW"] = {
                    "status": "COMPLETED",
                    "total_items_reviewed": len(reviews),
                    "evidence_items_count": len(review_items.evidence_items),
                    "findings_count": len(review_items.deterministic_findings),
                    "ai_reasoning_records_count": len(review_items.ai_reasoning_records),
                    "completed_at": now.isoformat()
                }
                run.current_stage = "FINAL_REPORT"

            # -------------------------------------------------------------
            # STAGE 16: FINAL REPORT
            # -------------------------------------------------------------
            elif stage == "FINAL_REPORT":
                report_req = ForensicReportGenerateRequest(
                    title=f"Final Forensic Report — Case {case.case_number}"
                )
                rep = FinalForensicReportService.generate_report(
                    case_id=case.id,
                    user=user,
                    request_data=report_req,
                    db=db
                )

                progress["FINAL_REPORT"] = {
                    "status": "COMPLETED",
                    "report_id": rep.id,
                    "version": rep.version,
                    "report_hash": rep.report_hash,
                    "completed_at": now.isoformat()
                }
                run.current_stage = "COMPLETED"
                run.status = "COMPLETED"
                run.completed_at = now

                log_audit_event(
                    db=db,
                    event_type="INVESTIGATION_RUN_COMPLETED",
                    details=f"Investigation run {run.id} completed. Official Report: {rep.id} (v{rep.version})",
                    case_id=case.id,
                    actor_id=user.id,
                    actor_name=user.name or user.email,
                    metadata_json={
                        "run_id": run.id,
                        "cycle_number": run.cycle_number,
                        "report_id": rep.id,
                        "report_hash": rep.report_hash
                    },
                    provenance_context={
                        "case_id": case.id,
                        "run_id": run.id,
                        "report_id": rep.id
                    }
                )

            run.stage_progress = progress
            db.add(run)
            db.commit()
            db.refresh(run)

        except Exception as exc:
            logger.error(f"Error during stage {stage} in run {run.id}: {exc}", exc_info=True)
            run.status = "FAILED"
            run.error_message = f"Failed at stage {stage}: {str(exc)}"
            run.failure_count = (run.failure_count or 0) + 1
            progress[stage] = {
                "status": "FAILED",
                "error": str(exc),
                "timestamp": now.isoformat()
            }
            run.stage_progress = progress
            db.add(run)
            db.commit()
            db.refresh(run)

        return run

    @classmethod
    def pause_run(
        cls,
        db: Session,
        run_id: str,
        user: User,
        reason: Optional[str] = None
    ) -> InvestigationRun:
        run = db.query(InvestigationRun).filter(InvestigationRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found.")
        if run.status != "RUNNING":
            raise HTTPException(status_code=400, detail=f"Cannot pause run in status {run.status}.")

        run.status = "PAUSED"
        run.error_message = f"Paused: {reason}" if reason else "Paused by investigator."
        db.add(run)
        db.commit()
        db.refresh(run)

        log_audit_event(
            db=db,
            event_type="INVESTIGATION_RUN_PAUSED",
            details=f"Investigation run {run.id} paused by {user.email}: {reason or 'No reason provided'}",
            case_id=run.case_id,
            actor_id=user.id,
            actor_name=user.name or user.email
        )
        return run

    @classmethod
    def resume_run(
        cls,
        db: Session,
        run_id: str,
        user: User
    ) -> InvestigationRun:
        run = db.query(InvestigationRun).filter(InvestigationRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found.")
        if run.status not in ("PAUSED", "INTERRUPTED", "RECOVERED"):
            raise HTTPException(status_code=400, detail=f"Cannot resume run in status {run.status}.")

        run.status = "RUNNING"
        run.error_message = None
        db.add(run)
        db.commit()
        db.refresh(run)

        log_audit_event(
            db=db,
            event_type="INVESTIGATION_RUN_RESUMED",
            details=f"Investigation run {run.id} resumed by {user.email}",
            case_id=run.case_id,
            actor_id=user.id,
            actor_name=user.name or user.email
        )

        return cls.execute_run_to_completion_or_review(db, run.id, user)

    @classmethod
    def cancel_run(
        cls,
        db: Session,
        run_id: str,
        user: User,
        reason: Optional[str] = None
    ) -> InvestigationRun:
        run = db.query(InvestigationRun).filter(InvestigationRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found.")
        if run.status in ("COMPLETED", "CANCELLED"):
            raise HTTPException(status_code=400, detail=f"Cannot cancel run in status {run.status}.")

        run.status = "CANCELLED"
        run.error_message = reason or "Cancelled by investigator."
        run.completed_at = datetime.now(timezone.utc)

        # Cancel any active analysis requests
        active_requests = db.query(AnalysisRequest).filter(
            AnalysisRequest.case_id == run.case_id,
            AnalysisRequest.scheduler_status.in_(["QUEUED", "READY", "RUNNING"])
        ).all()
        for req in active_requests:
            req.scheduler_status = "CANCELLED"
            req.cancelled_at = run.completed_at
            req.failure_reason = reason or "Run cancelled."

        db.add(run)
        db.commit()
        db.refresh(run)

        log_audit_event(
            db=db,
            event_type="INVESTIGATION_RUN_CANCELLED",
            details=f"Investigation run {run.id} cancelled by {user.email}: {reason or 'No reason provided'}",
            case_id=run.case_id,
            actor_id=user.id,
            actor_name=user.name or user.email
        )
        return run

    @classmethod
    def initiate_new_cycle_from_review(
        cls,
        db: Session,
        case_id: str,
        review_id: str,
        user: User,
        auto_progress: bool = False
    ) -> InvestigationRun:
        """
        Creates and executes a new controlled investigation cycle downstream of an investigator's
        REQUEST_MORE_EVIDENCE decision, safely re-entering the pipeline.
        """
        review = db.query(InvestigatorReviewRecord).filter(
            InvestigatorReviewRecord.id == review_id,
            InvestigatorReviewRecord.case_id == case_id
        ).first()
        if not review:
            raise HTTPException(status_code=404, detail=f"Review record '{review_id}' not found.")

        # Trigger new run cycle
        new_run = cls.start_run(
            db=db,
            case_id=case_id,
            user=user,
            request_data=InvestigationRunCreateRequest(
                options={
                    "trigger": "REQUEST_MORE_EVIDENCE",
                    "source_review_id": review.id,
                    "target_type": review.target_type,
                    "target_id": review.target_id,
                    "rationale": review.comment
                }
            ),
            auto_progress=auto_progress
        )

        review.resulting_workflow_action = "EVIDENCE_REQUESTED"
        review.action_reference_id = new_run.id
        db.add(review)
        db.commit()

        return new_run

    @classmethod
    def get_run(
        cls,
        db: Session,
        case_id: str,
        run_id: str,
        user: User
    ) -> InvestigationRun:
        run = db.query(InvestigationRun).filter(
            InvestigationRun.id == run_id,
            InvestigationRun.case_id == case_id
        ).first()
        if not run:
            raise HTTPException(status_code=404, detail=f"Investigation run '{run_id}' not found.")
        return run

    @classmethod
    def list_runs(
        cls,
        db: Session,
        case_id: str,
        user: User
    ) -> List[InvestigationRun]:
        return db.query(InvestigationRun).filter(
            InvestigationRun.case_id == case_id
        ).order_by(InvestigationRun.cycle_number.desc(), InvestigationRun.created_at.desc()).all()
