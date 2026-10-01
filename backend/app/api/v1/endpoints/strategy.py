"""
ADFIR — Investigation Strategy Engine API Endpoints (Phase 2 / Step 6)

Case-scoped, RBAC-authorized REST endpoints for generating, inspecting, validating,
reviewing, recalculating, and querying Investigation Strategy Plans, Task Dependency Graphs,
Forensic Capability Registries, and Host Tool Registries.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import (
    Case,
    InvestigationPlan,
    InvestigationTask,
    InvestigationTaskDependency,
    ForensicCapability,
    ToolDefinition,
    ToolSelectionRecord,
    PlanStoppingCondition,
    PlanAdjustment,
    User,
    EvidenceItem,
    EvidenceIntelligence
)
from backend.app.schemas.schemas import (
    InvestigationPlanResponse,
    DependencyGraphResponse,
    PlanReviewResponse,
    ToolSelectionItemResponse,
    PlanToolSelectionSummaryResponse,
    ToolValidationRequest,
    ToolValidationResponse,
    RegistryValidationResponse
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.strategy_engine import (
    InvestigationStrategyEngine,
    ToolRequirementResolver,
    DependencyGraphBuilder,
    DEFAULT_CAPABILITIES,
    seed_forensic_capabilities
)
from backend.app.services.tool_selector import (
    ToolSelectorEngine,
    CapabilityMatcher,
    ToolEvaluator,
    get_system_resources,
    seed_default_tools
)
from forensic_tools.registry import tool_registry as global_tool_registry

router = APIRouter()


@router.post("/cases/{case_id}/investigation-plans", response_model=InvestigationPlanResponse)
def create_investigation_plan(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Creates/generates a deterministic, explainable Investigation Strategy Plan for an authorized case.
    """
    case = get_authorized_case(case_id, db, current_user)
    try:
        plan_dict = InvestigationStrategyEngine.generate_plan(db, case.id, current_user)
        return InvestigationPlanResponse(**plan_dict)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate investigation plan: {str(e)}")


@router.get("/cases/{case_id}/investigation-plans", response_model=List[InvestigationPlanResponse])
def list_investigation_plans_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all historical and active Investigation Strategy Plans for an authorized case.
    """
    case = get_authorized_case(case_id, db, current_user)
    plans = (
        db.query(InvestigationPlan)
        .filter(InvestigationPlan.case_id == case.id)
        .order_by(InvestigationPlan.version.desc())
        .all()
    )
    return plans


@router.get("/investigation-plans/{plan_id}", response_model=InvestigationPlanResponse)
def get_investigation_plan_details(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves full details of a specific Investigation Strategy Plan.
    Enforces case authorization to prevent IDOR.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    # Authorize case access
    get_authorized_case(plan.case_id, db, current_user)
    return plan


@router.get("/investigation-plans/{plan_id}/tasks")
def get_investigation_plan_tasks(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves ordered tasks for a specific plan.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    tasks_db = (
        db.query(InvestigationTask)
        .filter(InvestigationTask.plan_id == plan.id)
        .order_by(InvestigationTask.sequence.asc())
        .all()
    )

    if tasks_db:
        return [
            {
                "id": t.id,
                "task_key": t.task_key,
                "sequence": t.sequence,
                "capability_id": t.capability_id,
                "agent_name": t.agent_name,
                "evidence_ids": t.evidence_ids,
                "candidate_tool_ids": t.candidate_tool_ids,
                "selected_tool_id": t.selected_tool_id,
                "priority_level": t.priority_level,
                "priority_score": t.priority_score,
                "status": t.status,
                "required_inputs": t.required_inputs,
                "expected_outputs": t.expected_outputs,
                "resource_requirements": t.resource_requirements,
                "rationale": t.rationale,
                "blocking_reason": t.blocking_reason
            }
            for t in tasks_db
        ]
    return plan.tasks or []


@router.get("/investigation-plans/{plan_id}/graph", response_model=DependencyGraphResponse)
def get_investigation_plan_dependency_graph(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns the task dependency graph (nodes and directed edges) for visualization.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    tasks = (
        db.query(InvestigationTask)
        .filter(InvestigationTask.plan_id == plan.id)
        .order_by(InvestigationTask.sequence.asc())
        .all()
    )
    nodes = []
    edges = []

    deps_db = db.query(InvestigationTaskDependency).filter(InvestigationTaskDependency.plan_id == plan.id).all()

    for t in tasks:
        task_key = t.task_key
        nodes.append({
            "id": task_key,
            "label": f"{t.capability_id} ({t.selected_tool_id or 'BLOCKED'})",
            "agent": t.agent_name,
            "tool": t.selected_tool_id,
            "priority": t.priority_level,
            "status": t.status,
            "evidence_id": (t.evidence_ids or [None])[0]
        })

    task_keys = {task.task_key for task in tasks}
    adjacency = {task_key: [] for task_key in task_keys}
    is_valid_dag = True
    for dependency in deps_db:
        if dependency.parent_task_id not in task_keys or dependency.child_task_id not in task_keys:
            is_valid_dag = False
        else:
            adjacency[dependency.parent_task_id].append(dependency.child_task_id)
        edges.append({
            "source": dependency.parent_task_id,
            "target": dependency.child_task_id,
            "type": dependency.dependency_type
        })

    is_valid_dag = is_valid_dag and DependencyGraphBuilder.detect_cycles(list(task_keys), adjacency) is None

    return DependencyGraphResponse(
        plan_id=plan.id,
        case_id=plan.case_id,
        nodes=nodes,
        edges=edges,
        is_valid_dag=is_valid_dag
    )


@router.post("/investigation-plans/{plan_id}/review", response_model=PlanReviewResponse)
def review_and_validate_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Executes a formal validation and review pass on a plan, applying safe adjustments.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    res = InvestigationStrategyEngine.review_and_adjust_plan(db, plan.id, current_user)
    return PlanReviewResponse(**res)


@router.post("/investigation-plans/{plan_id}/recalculate", response_model=InvestigationPlanResponse)
def recalculate_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Recalculates an Investigation Strategy Plan based on current evidence intelligence & capabilities,
    creating a new immutable plan version.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    case = get_authorized_case(plan.case_id, db, current_user)

    plan_dict = InvestigationStrategyEngine.generate_plan(db, case.id, current_user)
    return InvestigationPlanResponse(**plan_dict)


@router.get("/strategy/capabilities")
def list_forensic_capabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists registered forensic capabilities.
    """
    seed_forensic_capabilities(db)
    return db.query(ForensicCapability).all()


@router.get("/strategy/tools")
def list_forensic_tools(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists registered forensic tools and host availability status.
    """
    tools = []
    for cap_id in ToolRequirementResolver.TOOL_MAPPINGS.keys():
        t_info = ToolRequirementResolver.resolve_tool_for_capability(db, cap_id)
        tools.append({
            "capability_id": cap_id,
            "tool_name": t_info["tool_name"],
            "executable_name": t_info["executable_name"],
            "is_installed": t_info["is_installed"],
            "executable_path": t_info["executable_path"],
            "health_status": t_info["health_status"]
        })
    return tools


@router.post("/investigation-plans/{plan_id}/select-tools", response_model=PlanToolSelectionSummaryResponse)
def select_tools_for_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Deterministically evaluates and selects forensic tools for all tasks in an investigation plan.
    Updates task statuses (READY, BLOCKED_NO_CAPABLE_TOOL, REQUIRES_REVIEW) and persists ToolSelectionRecord.
    Enforces RBAC case authorization.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    try:
        summary = ToolSelectorEngine.select_and_update_plan_tools(db, plan.id, current_user)
        return PlanToolSelectionSummaryResponse(**summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute tool selection: {str(e)}")


@router.get("/investigation-plans/{plan_id}/tool-selections", response_model=List[ToolSelectionItemResponse])
def get_plan_tool_selections(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves all persisted tool selection evaluation records for a specific investigation plan.
    Enforces RBAC case authorization.
    """
    plan = db.query(InvestigationPlan).filter(InvestigationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Investigation plan not found")

    get_authorized_case(plan.case_id, db, current_user)

    records = (
        db.query(ToolSelectionRecord)
        .filter(ToolSelectionRecord.plan_id == plan.id)
        .order_by(ToolSelectionRecord.task_key.asc())
        .all()
    )
    return records


@router.post("/strategy/validate-tool-match", response_model=ToolValidationResponse)
def validate_tool_match(
    request: ToolValidationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Evaluates compatibility between a requested capability, evidence attributes,
    and registered forensic tools without modifying persistent tasks.
    """
    seed_default_tools(db)
    seed_forensic_capabilities(db)

    cap = db.query(ForensicCapability).filter(ForensicCapability.id == request.capability_id).first()
    sys_res = get_system_resources()

    if not cap:
        return ToolValidationResponse(
            capability_id=request.capability_id,
            capability_supported=False,
            capability_reason=f"Capability '{request.capability_id}' is not registered",
            candidate_tools=[],
            selected_tool_id=None,
            selection_status="NO_COMPATIBLE_TOOL",
            system_resources=sys_res
        )

    ev_item = None
    ev_intel = None
    if request.evidence_id:
        ev_item = db.query(EvidenceItem).filter(EvidenceItem.id == request.evidence_id).first()
        if ev_item:
            ev_intel = db.query(EvidenceIntelligence).filter(EvidenceIntelligence.evidence_id == ev_item.id).first()

    cap_ok, cap_reason, _ = CapabilityMatcher.match(
        cap,
        evidence=ev_item,
        intel=ev_intel,
        category=request.evidence_category,
        subtype=request.evidence_subtype,
        fmt=request.evidence_format
    )

    if not cap_ok:
        return ToolValidationResponse(
            capability_id=request.capability_id,
            capability_supported=False,
            capability_reason=cap_reason,
            candidate_tools=[],
            selected_tool_id=None,
            selection_status="NO_COMPATIBLE_TOOL",
            system_resources=sys_res
        )

    # Find candidates
    tools = db.query(ToolDefinition).all()
    candidate_evals = []
    eligible_tools = []

    for t in tools:
        caps = t.capabilities_json or []
        if request.capability_id in caps or request.capability_id.lower() in [c.lower() for c in caps]:
            avail_st, _ = ToolEvaluator.evaluate_availability(t)
            plat_st, _ = ToolEvaluator.evaluate_platform(t, host_platform=sys_res["platform"])
            ev_st, _ = ToolEvaluator.evaluate_evidence_compatibility(t, evidence=ev_item, category=request.evidence_category, fmt=request.evidence_format)
            res_st, _ = ToolEvaluator.evaluate_resources(t, sys_res=sys_res)
            ver_st, _ = ToolEvaluator.evaluate_version(t)
            safe_st, _ = ToolEvaluator.evaluate_safety(t)

            is_eligible = (
                avail_st in ["AVAILABLE", "REQUIRES_REVIEW"] and
                plat_st == "COMPATIBLE" and
                ev_st == "COMPATIBLE" and
                res_st != "RESOURCE_INSUFFICIENT" and
                ver_st != "VERSION_INCOMPATIBLE" and
                safe_st != "UNSAFE"
            )

            cand_info = {
                "tool_id": t.tool_id,
                "name": t.name,
                "display_name": t.display_name,
                "availability": avail_st,
                "platform": plat_st,
                "evidence_compatibility": ev_st,
                "resources": res_st,
                "version": ver_st,
                "safety": safe_st,
                "is_eligible": is_eligible
            }
            candidate_evals.append(cand_info)
            if is_eligible:
                eligible_tools.append(cand_info)

    selected_id = eligible_tools[0]["tool_id"] if eligible_tools else None
    selection_st = "SELECTED" if selected_id else "NO_COMPATIBLE_TOOL"
    if candidate_evals and not selected_id:
        if any(c["safety"] == "UNSAFE" for c in candidate_evals):
            selection_st = "SAFETY_REVIEW"
        elif any(c["resources"] == "RESOURCE_INSUFFICIENT" for c in candidate_evals):
            selection_st = "RESOURCE_INSUFFICIENT"
        elif any(c["version"] == "VERSION_INCOMPATIBLE" for c in candidate_evals):
            selection_st = "VERSION_INCOMPATIBLE"
        elif any(c["availability"] in ["UNAVAILABLE", "MISSING", "DISABLED"] for c in candidate_evals):
            selection_st = "TOOL_UNAVAILABLE"

    return ToolValidationResponse(
        capability_id=request.capability_id,
        capability_supported=True,
        capability_reason="Capability matches evidence and registered tools",
        candidate_tools=candidate_evals,
        selected_tool_id=selected_id,
        selection_status=selection_st,
        system_resources=sys_res
    )


@router.get("/strategy/registries/validate", response_model=RegistryValidationResponse)
def validate_registries_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Validates capability and tool registries for consistency:
    detects orphaned capabilities, orphaned tools, missing fields, or safety violations.
    """
    report = ToolSelectorEngine.validate_registries(db)
    return RegistryValidationResponse(**report)
