from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import Case, EvidenceItem, Finding, Report, InvestigatorDecision, AuditEvent, CorrelationGroup, User
from backend.app.schemas.schemas import (
    ReportResponse,
    ForensicReportResponse,
    ForensicReportVersionItem,
    ForensicReportGenerateRequest,
    ForensicReportIntegrityResponse,
    ForensicReportProvenanceResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.final_report import FinalForensicReportService
from agents.report.report_synthesizer import ReportSynthesizer

router = APIRouter()
case_reports_router = APIRouter()
report_synthesizer = ReportSynthesizer()


# =============================================================================
# LEGACY PHASE 1 REPORT ROUTES (Preserved for full backward compatibility)
# =============================================================================

@router.post("/generate/{case_id}", response_model=ReportResponse)
def generate_case_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    from backend.app.services.case_closure import check_case_not_closed
    check_case_not_closed(case)

    latest_decision = db.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == case.id).order_by(InvestigatorDecision.timestamp.desc()).first()

    # Mandatory Investigator Decision Gate: Report generation strictly requires an explicit CONFIRM decision
    if not latest_decision:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Report generation blocked: Mandatory investigator decision required before report synthesis."
        )

    if latest_decision.decision != "CONFIRM":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Report generation blocked by mandatory forensic gate: Current investigator decision is {latest_decision.decision}."
        )

    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    findings = db.query(Finding).filter(Finding.case_id == case.id).all()

    # Mandatory Correlation State Gate
    correlation_event = db.query(AuditEvent).filter(
        AuditEvent.case_id == case.id,
        AuditEvent.event_type == "CORRELATION_EXECUTED"
    ).order_by(AuditEvent.timestamp.desc()).first()
    persisted_corr = db.query(CorrelationGroup).filter(CorrelationGroup.case_id == case.id).all()

    if findings:
        if not correlation_event and not persisted_corr:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Report generation blocked: Forensic correlation has not been executed for this investigation. Correlation must be explicitly executed before report synthesis."
            )
        if correlation_event:
            latest_finding = max(findings, key=lambda f: f.created_at)
            if latest_finding.created_at > correlation_event.timestamp:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Report generation blocked: New findings have been added since the last correlation execution. Correlation must be re-executed for the current investigation state."
                )

    ev_dicts = [{"file_name": e.file_name, "evidence_type": e.evidence_type, "sha256_hash": e.sha256_hash} for e in evidence_items]
    finding_dicts = [{"id": f.id, "title": f.title, "source_tool": f.source_tool, "category": f.category, "details": f.details, "confidence_score": f.confidence_score, "mitre_techniques": f.mitre_techniques, "timestamp": f.timestamp} for f in findings]

    correlated = [
        {
            "title": c.title,
            "description": c.description,
            "dimension": c.dimension,
            "rule": c.rule,
            "correlated_entity": c.correlated_entity,
            "tools_involved": c.tools_involved,
            "supporting_finding_ids": c.supporting_finding_ids,
            "correlation_confidence": c.correlation_confidence
        }
        for c in persisted_corr
    ]
    case_info = {"title": case.title, "case_number": case.case_number, "investigator": current_user.name or current_user.email}

    report_data = report_synthesizer.generate_report(
        case_info=case_info,
        evidence_list=ev_dicts,
        findings=finding_dicts,
        correlated_groups=correlated
    )

    new_report = Report(
        id=str(uuid.uuid4()),
        case_id=case.id,
        decision_id=latest_decision.id,
        title=report_data["title"],
        executive_summary=report_data["executive_summary"],
        attack_summary=report_data["attack_summary"],
        timeline_events=report_data["timeline_events"],
        indicators_of_compromise=report_data["indicators_of_compromise"],
        remediation_recommendations=report_data["remediation_recommendations"],
        full_report_markdown=report_data["full_report_markdown"],
        generated_by=latest_decision.investigator_name or current_user.name or current_user.email,
        status="OFFICIAL_FINAL"
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

@router.get("/case/{case_id}", response_model=ReportResponse)
def get_latest_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    report = db.query(Report).filter(Report.case_id == case.id).order_by(Report.generated_at.desc()).first()
    if not report:
        raise HTTPException(status_code=404, detail="No report generated yet for this case")
    return report


# =============================================================================
# STEP 20 FINAL FORENSIC REPORT CORE ROUTE HANDLERS
# =============================================================================

def handle_generate_report(
    case_id: str,
    request_data: Optional[ForensicReportGenerateRequest],
    db: Session,
    current_user: User
) -> Report:
    req = request_data or ForensicReportGenerateRequest()
    return FinalForensicReportService.generate_report(
        case_id=case_id,
        user=current_user,
        request_data=req,
        db=db
    )


def handle_list_reports(
    case_id: str,
    db: Session,
    current_user: User
) -> List[Report]:
    return FinalForensicReportService.list_reports(
        case_id=case_id,
        user=current_user,
        db=db
    )


def handle_get_report(
    case_id: str,
    report_id: str,
    db: Session,
    current_user: User
) -> Report:
    return FinalForensicReportService.get_report(
        case_id=case_id,
        report_id=report_id,
        user=current_user,
        db=db
    )


def handle_verify_report_integrity(
    case_id: str,
    report_id: str,
    db: Session,
    current_user: User
) -> ForensicReportIntegrityResponse:
    return FinalForensicReportService.verify_report_integrity(
        case_id=case_id,
        report_id=report_id,
        user=current_user,
        db=db
    )


def handle_get_report_provenance(
    case_id: str,
    report_id: str,
    db: Session,
    current_user: User
) -> ForensicReportProvenanceResponse:
    return FinalForensicReportService.get_report_provenance(
        case_id=case_id,
        report_id=report_id,
        user=current_user,
        db=db
    )


def handle_export_report(
    case_id: str,
    report_id: str,
    format: str,
    db: Session,
    current_user: User
) -> Response:
    content, media_type, filename = FinalForensicReportService.export_report(
        case_id=case_id,
        report_id=report_id,
        export_format=format,
        user=current_user,
        db=db
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# =============================================================================
# CASE-CENTRIC ROUTES: /cases/{case_id}/reports/...
# =============================================================================

@case_reports_router.post("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
def api_generate_case_report_v2(
    case_id: str,
    request_data: Optional[ForensicReportGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_generate_report(case_id, request_data, db, current_user)


@case_reports_router.get("/cases/{case_id}/reports", response_model=List[ForensicReportVersionItem])
def api_list_case_reports(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_list_reports(case_id, db, current_user)


@case_reports_router.get("/cases/{case_id}/reports/latest", response_model=ForensicReportResponse)
def api_get_latest_case_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report(case_id, "latest", db, current_user)


@case_reports_router.get("/cases/{case_id}/reports/{report_id}", response_model=ForensicReportResponse)
def api_get_case_report_by_id(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report(case_id, report_id, db, current_user)


@case_reports_router.get("/cases/{case_id}/reports/{report_id}/integrity", response_model=ForensicReportIntegrityResponse)
def api_verify_case_report_integrity(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_verify_report_integrity(case_id, report_id, db, current_user)


@case_reports_router.get("/cases/{case_id}/reports/{report_id}/provenance", response_model=ForensicReportProvenanceResponse)
def api_get_case_report_provenance(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report_provenance(case_id, report_id, db, current_user)


@case_reports_router.get("/cases/{case_id}/reports/{report_id}/export")
def api_export_case_report(
    case_id: str,
    report_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|md|json)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_export_report(case_id, report_id, format, db, current_user)


# =============================================================================
# ALIAS ROUTES UNDER /reports/{case_id}/...
# =============================================================================

@router.post("/{case_id}/generate", response_model=ForensicReportResponse)
def alias_generate_case_report(
    case_id: str,
    request_data: Optional[ForensicReportGenerateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_generate_report(case_id, request_data, db, current_user)


@router.get("/{case_id}/versions", response_model=List[ForensicReportVersionItem])
def alias_list_case_reports(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_list_reports(case_id, db, current_user)


@router.get("/{case_id}/latest", response_model=ForensicReportResponse)
def alias_get_latest_case_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report(case_id, "latest", db, current_user)


@router.get("/{case_id}/{report_id}", response_model=ForensicReportResponse)
def alias_get_case_report_by_id(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report(case_id, report_id, db, current_user)


@router.get("/{case_id}/{report_id}/integrity", response_model=ForensicReportIntegrityResponse)
def alias_verify_case_report_integrity(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_verify_report_integrity(case_id, report_id, db, current_user)


@router.get("/{case_id}/{report_id}/provenance", response_model=ForensicReportProvenanceResponse)
def alias_get_case_report_provenance(
    case_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_get_report_provenance(case_id, report_id, db, current_user)


@router.get("/{case_id}/{report_id}/export")
def alias_export_case_report(
    case_id: str,
    report_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|md|json)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return handle_export_report(case_id, report_id, format, db, current_user)
