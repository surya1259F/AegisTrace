from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import uuid
import json

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import Case, EvidenceItem, Finding, InvestigationPlan, Report, ExecutionArtifact, CorrelationGroup, ToolExecution, User
from backend.app.schemas.schemas import InvestigationPlanResponse, PlanExecutionResponse, FindingCreate, FindingResponse, TaskCancelResponse, ToolExecutionResponse
from backend.app.services.authorization import get_authorized_case
from investigation.planner.planner_engine import InvestigationPlanner
from investigation.orchestrator.orchestrator import InvestigationOrchestrator
from investigation.correlation.correlation_engine import EvidenceCorrelationEngine
from investigation.verification.verification_engine import VerificationEngine
from agents.report.report_synthesizer import ReportSynthesizer
from backend.app.services.audit import log_audit_event

router = APIRouter()
planner_engine = InvestigationPlanner()
orchestrator = InvestigationOrchestrator()
correlation_engine = EvidenceCorrelationEngine()
verification_engine = VerificationEngine()
report_synthesizer = ReportSynthesizer()


@router.post("/plan/{case_id}", response_model=InvestigationPlanResponse)
def generate_plan(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.strategy_engine import InvestigationStrategyEngine
    plan_dict = InvestigationStrategyEngine.generate_plan(db, case.id, current_user)
    return InvestigationPlanResponse(**plan_dict)

@router.post("/plan/{case_id}/execute", response_model=PlanExecutionResponse)
def execute_plan(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)

    try:
        exec_summary = orchestrator.execute_plan(case_id=case.id, db=db)
        return PlanExecutionResponse(**exec_summary)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))

@router.post("/findings", response_model=FindingResponse)
def record_finding(
    finding_in: FindingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(finding_in.case_id, db, current_user)

    finding_dict = finding_in.model_dump()
    if "id" not in finding_dict or not finding_dict["id"]:
        finding_dict["id"] = str(uuid.uuid4())
    if not finding_dict.get("raw_output_reference"):
        raw_meta = {}
        if finding_dict.get("details"):
            if isinstance(finding_dict["details"], dict):
                raw_meta.update(finding_dict["details"])
            else:
                raw_meta["details"] = finding_dict["details"]
        if finding_dict.get("mitre_techniques"):
            raw_meta["mitre_techniques"] = finding_dict["mitre_techniques"]
        if raw_meta:
            finding_dict["raw_output_reference"] = json.dumps(raw_meta)

    finding = Finding(**finding_dict)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding

@router.get("/findings/{case_id}", response_model=List[FindingResponse])
def get_findings_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return db.query(Finding).filter(Finding.case_id == case.id).all()

@router.post("/correlate/{case_id}")
def correlate_case_evidence(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)

    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    artifacts = db.query(ExecutionArtifact).filter(ExecutionArtifact.case_id == case.id).all()

    finding_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "source_tool": f.source_tool,
            "tool": f.tool,
            "agent": f.agent,
            "category": f.category,
            "details": f.details,
            "evidence_reference": f.evidence_reference,
            "confidence_score": f.confidence_score
        } for f in findings
    ]
    artifact_dicts = [
        {
            "id": a.id,
            "evidence_id": a.evidence_id,
            "tool": a.tool,
            "agent": a.agent,
            "artifact_type": a.artifact_type,
            "source_reference": a.source_reference,
            "path": a.path,
            "inode": a.inode,
            "metadata_json": a.metadata_json or {}
        }
        for a in artifacts
    ]

    correlated_events = correlation_engine.correlate(finding_dicts)

    # Persist and deduplicate
    existing_groups = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).all()
    existing_map = {(eg.dimension, eg.correlated_entity): eg for eg in existing_groups}
    active_keys = set()

    for ce in correlated_events:
        dim = ce.get("dimension", "entity_overlap")
        ent = ce.get("correlated_entity") or ce.get("entity")
        if not ent:
            continue
        key = (dim, ent)
        active_keys.add(key)
        if key in existing_map:
            eg = existing_map[key]
            eg.rule = ce.get("rule")
            eg.title = ce["title"]
            eg.description = ce["description"]
            eg.tools_involved = ce["tools_involved"]
            eg.supporting_finding_ids = ce["supporting_finding_ids"]
            eg.supporting_artifact_ids = ce.get("supporting_artifact_ids", [])
            eg.supporting_evidence_ids = ce.get("supporting_evidence_ids", [])
            eg.correlation_confidence = ce.get("correlation_confidence") or ce.get("confidence", 1.0)
        else:
            new_grp = CorrelationGroup(
                case_id=case.id,
                dimension=dim,
                rule=ce.get("rule"),
                correlated_entity=ent,
                title=ce["title"],
                description=ce["description"],
                tools_involved=ce["tools_involved"],
                supporting_finding_ids=ce["supporting_finding_ids"],
                supporting_artifact_ids=ce.get("supporting_artifact_ids", []),
                supporting_evidence_ids=ce.get("supporting_evidence_ids", []),
                correlation_confidence=ce.get("correlation_confidence") or ce.get("confidence", 1.0)
            )
            db.add(new_grp)

    for eg in existing_groups:
        if (eg.dimension, eg.correlated_entity) not in active_keys:
            db.delete(eg)

    db.commit()

    log_audit_event(
        db=db,
        case_id=case.id,
        actor_id=current_user.id,
        actor_name=current_user.name or current_user.email,
        event_type="CORRELATION_EXECUTED",
        details=f"Explicit forensic correlation executed (v1): {len(active_keys)} correlation group(s) persisted across {len(findings)} findings and {len(artifacts)} artifacts."
    )

    return {"case_id": case.id, "correlated_events": correlated_events}

@router.post("/verify/{case_id}")
def verify_case_findings(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    finding_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description or f.title,
            "tool": f.tool or f.source_tool,
            "source_tool": f.source_tool,
            "evidence_id": f.evidence_id,
            "supporting_evidence_ids": [f.evidence_id] if f.evidence_id else [],
            "execution_id": f.execution_id,
            "artifact_id": f.artifact_id,
            "supporting_artifact_ids": [f.artifact_id] if f.artifact_id else [],
            "evidence_reference": f.evidence_reference,
            "details": f.details,
            "confidence_score": f.confidence_score,
            "confidence": f.confidence,
        } for f in findings
    ]
    verified = verification_engine.verify_findings(finding_dicts)
    return {"case_id": case.id, "verification_results": verified}

@router.post("/{case_id}/tasks/{task_id}/cancel", response_model=TaskCancelResponse)
def cancel_task(
    case_id: str,
    task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    try:
        res = orchestrator.cancel_task(case_id=case.id, task_id=task_id, db=db)
        return TaskCancelResponse(**res)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{case_id}/executions/{execution_id}", response_model=ToolExecutionResponse)
def get_execution(
    case_id: str,
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    exec_rec = (
        db.query(ToolExecution)
        .filter(ToolExecution.id == execution_id, ToolExecution.case_id == case.id)
        .first()
    )
    if not exec_rec:
        raise HTTPException(status_code=404, detail="Tool execution not found")
    return exec_rec

@router.get("/{case_id}/executions", response_model=List[ToolExecutionResponse])
def list_executions_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return db.query(ToolExecution).filter(ToolExecution.case_id == case.id).all()
