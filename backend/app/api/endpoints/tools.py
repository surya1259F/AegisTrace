from typing import List
from fastapi import APIRouter
from backend.app.schemas.schemas import ToolDefinitionResponse
from forensic_tools.registry import tool_registry

router = APIRouter()

@router.get("/tools", response_model=List[ToolDefinitionResponse])
def list_registered_tools():
    """
    Returns the real registered forensic tool definitions and their live availability.
    """
    tools = tool_registry.list_tools()
    res = []
    for t in tools:
        res.append(ToolDefinitionResponse(
            tool_id=t.name.lower().replace(" ", "_"),
            name=t.display_name or t.name,
            version=t.version,
            executable_path=str(t.path or "Not installed"),
            supported_evidence=t.supported_evidence_types,
            capabilities_json={"description": t.description, "platforms": t.platforms},
            is_available=t.is_available
        ))
    return res
