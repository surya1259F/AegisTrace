import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import engine, Base
from backend.app.api.endpoints import health, system, investigations, audit, tools

# Configure logging cleanly without adding duplicate handlers on reload/tests
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ADFIR_API")

import os
import hmac
from backend.app.core.config import settings, get_backend_port


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan: runs startup logic (directory creation, DB migrations,
    RevokedToken table bootstrap) only when the server actually starts,
    not at import time.
    """
    # Ensure required workspace data directories exist
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    settings.CASES_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Run Alembic migrations
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(engine)

    # Ensure RevokedToken table exists (created if missing, safe on existing DBs)
    try:
        from backend.app.models.models import RevokedToken
        RevokedToken.__table__.create(bind=engine, checkfirst=True)
    except Exception as exc:
        logger.warning(f"Could not ensure revoked_tokens table: {exc}")

    yield
    # (shutdown logic goes here if needed in the future)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Assisted Digital Forensic Investigation Platform (ADFIR) Desktop Backend",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    lifespan=lifespan,
)


def get_allowed_origins() -> list:
    custom_origins = os.getenv("ADFIR_ALLOWED_ORIGINS")
    if custom_origins:
        return [o.strip() for o in custom_origins.split(",") if o.strip()]
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ]

# Hardened Cross-Origin Resource Sharing for Desktop/Tauri
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-ADFIR-Bootstrap-Secret", "Accept"],
)

# Desktop Bootstrap Secret Trust Boundary Middleware
@app.middleware("http")
async def desktop_bootstrap_middleware(request: Request, call_next):
    secret = os.getenv("ADFIR_INTERNAL_SECRET") or settings.ADFIR_INTERNAL_SECRET
    if secret and secret.strip():
        if request.method != "OPTIONS":
            path = request.url.path.rstrip("/")
            is_health = path in ["/health", "/api/health", "/api/v1/health", "/api/v1/system/health"]
            if not is_health:
                provided_header = request.headers.get("X-ADFIR-Bootstrap-Secret")
                if not provided_header or not hmac.compare_digest(provided_header.encode("utf-8"), secret.encode("utf-8")):
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Forbidden: Invalid or missing desktop bootstrap secret."}
                    )
    response = await call_next(request)
    return response

# Global Security Exception Handler: Never expose raw stack traces to users
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal Exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred during forensic processing. Please contact your system administrator."}
    )


# Legacy Compatibility Routers for /api prefix (pure compatibility shims for legacy clients and root test suites)
app.include_router(health.router, prefix="/api", tags=["Health"], include_in_schema=False)
app.include_router(investigations.router, prefix="/api/cases", tags=["Legacy Cases"], include_in_schema=False)
app.include_router(investigations.router, prefix="/api/investigations", tags=["Legacy Investigations"], include_in_schema=False)
app.include_router(system.router, prefix="/api", tags=["System"], include_in_schema=False)
app.include_router(audit.router, prefix="/api", tags=["Audit"], include_in_schema=False)
app.include_router(tools.router, prefix="/api", tags=["Tools"], include_in_schema=False)

# Canonical API Router: authoritative /api/v1 prefix and compatibility /api alias (excluded from schema to avoid duplicate operation IDs)
from backend.app.api.v1.router import api_router
app.include_router(api_router, prefix="/api/v1")
app.include_router(api_router, prefix="/api", include_in_schema=False)


@app.get("/")
def root():
    return {
        "status": "ok",
        "application": "ADFIR",
        "version": settings.VERSION,
        "docs_url": "/api/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=get_backend_port(), reload=True)
