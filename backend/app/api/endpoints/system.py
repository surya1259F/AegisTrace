from fastapi import APIRouter
import sys
from backend.app.schemas.schemas import SystemStatusResponse
from forensic_tools.registry import tool_registry
from investigation.scheduler.scheduler import ResourceManager

router = APIRouter()
resource_mgr = ResourceManager()

@router.get("/system/status", response_model=SystemStatusResponse)
@router.get("/system/info")
def get_system_status():
    tools = tool_registry.list_tools()
    tools_dict = {
        t.name: {
            "name": t.display_name,
            "available": t.is_available,
            "version": t.version,
            "supported_evidence": t.supported_evidence_types
        } for t in tools
    }
    cap = resource_mgr.get_system_capacity()

    return SystemStatusResponse(
        application="ADFIR",
        version="0.1.0",
        status="READY",
        platform=sys.platform,
        logical_cpus=cap["logical_cpus"],
        max_concurrent_tasks=cap["max_concurrent_tasks"],
        active_tasks=cap["active_tasks"],
        forensic_tools=tools_dict
    )
