from fastapi import APIRouter, Request, HTTPException, status, Header
import shutil
import os
import hmac
import signal
import asyncio
from typing import Optional
from pathlib import Path
from backend.app.core.config import settings

router = APIRouter()

@router.get("/health")
def health_check():
    return {"status": "online", "project": settings.PROJECT_NAME, "version": settings.VERSION}

@router.get("/system/health")
def health_check_alias():
    return health_check()

@router.get("/info")
@router.get("/system/info")
def system_info():
    fls_path = shutil.which("fls")
    yara_path = shutil.which("yara")
    vol_path = str(settings.VOLATILITY_CLI) if Path(settings.VOLATILITY_CLI).exists() else None

    return {
        "app_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "forensic_tools": {
            "sleuthkit": {"available": fls_path is not None, "path": fls_path},
            "yara": {"available": yara_path is not None, "path": yara_path},
            "volatility3": {"available": vol_path is not None, "path": vol_path},
        },
        "llm_providers_available": ["gemini", "local_llm", "openrouter"]
    }

@router.post("/shutdown")
@router.post("/system/shutdown")
async def shutdown_backend(
    request: Request,
    x_adfir_bootstrap_secret: Optional[str] = Header(None, alias="X-ADFIR-Bootstrap-Secret")
):
    secret = os.getenv("ADFIR_INTERNAL_SECRET") or settings.ADFIR_INTERNAL_SECRET
    if not secret or not secret.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Shutdown endpoint is only available when desktop bootstrap secret is configured."
        )

    if not x_adfir_bootstrap_secret or not hmac.compare_digest(x_adfir_bootstrap_secret.encode("utf-8"), secret.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing desktop bootstrap secret."
        )

    async def delayed_shutdown():
        await asyncio.sleep(0.3)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(delayed_shutdown())

    return {
        "status": "SHUTTING_DOWN",
        "message": "Backend shutdown initiated cleanly for this process.",
        "pid": os.getpid()
    }
