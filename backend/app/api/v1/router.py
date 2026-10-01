from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    ai,
    agents,
    artifacts,
    audit,
    auth,
    cases,
    correlation,
    evidence,
    executions,
    findings,
    governance,
    investigation,
    normalization,
    orchestration,
    raw_outputs,
    recovery,
    reports,
    review,
    scheduler,
    strategy,
    system,
    timeline,
    users,
)

api_router = APIRouter()

# System
api_router.include_router(
    system.router,
    prefix="",
    tags=["System"],
)

# Authentication / users
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)
api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"],
)

# Case / evidence lifecycle
api_router.include_router(
    cases.router,
    prefix="/cases",
    tags=["Cases"],
)
api_router.include_router(
    evidence.router,
    prefix="/evidence",
    tags=["Evidence"],
)

# Investigation planning / execution
api_router.include_router(
    investigation.router,
    prefix="/investigation",
    tags=["Investigation"],
)
api_router.include_router(
    strategy.router,
    prefix="",
    tags=["Strategy"],
)
api_router.include_router(
    scheduler.router,
    prefix="",
    tags=["Scheduler"],
)
api_router.include_router(
    executions.router,
    prefix="",
    tags=["Executions"],
)

# Forensic processing
api_router.include_router(
    raw_outputs.router,
    prefix="",
    tags=["Raw Outputs"],
)
api_router.include_router(
    artifacts.router,
    prefix="",
    tags=["Artifacts"],
)
api_router.include_router(
    normalization.router,
    prefix="",
    tags=["Normalization"],
)
api_router.include_router(
    timeline.router,
    prefix="",
    tags=["Timeline"],
)
api_router.include_router(
    correlation.router,
    prefix="",
    tags=["Correlation"],
)
api_router.include_router(
    findings.router,
    prefix="",
    tags=["Findings"],
)

# Specialist agents / governance / AI
api_router.include_router(
    agents.router,
    prefix="",
    tags=["Agents"],
)
api_router.include_router(
    governance.router,
    prefix="",
    tags=["Governance"],
)
api_router.include_router(
    ai.router,
    prefix="",
    tags=["AI"],
)

# Investigator review / reporting
api_router.include_router(
    review.router,
    prefix="",
    tags=["Investigator Review"],
)
api_router.include_router(
    reports.case_reports_router,
    prefix="",
    tags=["Case Reports"],
)
api_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["Reports"],
)

# Runtime / audit / recovery
api_router.include_router(
    orchestration.router,
    prefix="",
    tags=["Orchestration"],
)
api_router.include_router(
    audit.router,
    prefix="",
    tags=["Audit"],
)
api_router.include_router(
    recovery.router,
    prefix="/cases",
    tags=["Recovery"],
)
