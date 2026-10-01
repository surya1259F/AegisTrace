from fastapi import APIRouter
from backend.app.schemas.schemas import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
@router.get("/system/health")
def get_health():
    return HealthResponse(status="ok", application="ADFIR", version="0.1.0")
