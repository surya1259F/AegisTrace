from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional, Any
import os

import sys

def get_user_data_dir() -> Path:
    if sys.platform.startswith("win"):
        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "adfir"
        return Path.home() / "AppData" / "Local" / "adfir"
    elif sys.platform.startswith("darwin"):
        return Path.home() / "Library" / "Application Support" / "adfir"
    else:
        xdg_data = os.getenv("XDG_DATA_HOME")
        if xdg_data:
            return Path(xdg_data) / "adfir"
        return Path.home() / ".local" / "share" / "adfir"

class Settings(BaseSettings):
    PROJECT_NAME: str = "ADFIR - Autonomous DFIR Platform"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment control variables for standalone desktop mode
    ADFIR_DATA_DIR: Optional[str] = None
    ADFIR_PORT: Optional[int] = None
    ADFIR_INTERNAL_SECRET: Optional[str] = None
    
    # Base directory (repository or installation root)
    BASE_DIR: Path = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent.parent.parent.parent

    # Dynamic application data path properties
    @property
    def DATA_DIR(self) -> Path:
        env_val = os.getenv("ADFIR_DATA_DIR") or self.ADFIR_DATA_DIR
        if env_val and str(env_val).strip():
            p = Path(env_val).resolve()
        elif getattr(sys, 'frozen', False):
            p = get_user_data_dir()
        else:
            p = self.BASE_DIR / "data"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def EVIDENCE_DIR(self) -> Path:
        p = self.DATA_DIR / "evidence"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def CASES_DIR(self) -> Path:
        p = self.DATA_DIR / "cases"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def REPORTS_DIR(self) -> Path:
        p = self.DATA_DIR / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def LOGS_DIR(self) -> Path:
        p = self.DATA_DIR / "logs"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def DATABASE_URL(self) -> str:
        env_val = os.getenv("ADFIR_DATA_DIR") or self.ADFIR_DATA_DIR
        if env_val and str(env_val).strip():
            data_p = Path(env_val).resolve()
            data_p.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{data_p / 'adfir.db'}"
        elif getattr(sys, 'frozen', False):
            data_p = get_user_data_dir()
            data_p.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{data_p / 'adfir.db'}"
        return f"sqlite:///{self.BASE_DIR / 'adfir.db'}"


    # Forensic tool paths
    @property
    def VOLATILITY_PYTHON(self) -> Path:
        return self.BASE_DIR / "volatility-env" / "bin" / "python"

    @property
    def VOLATILITY_CLI(self) -> Path:
        return self.BASE_DIR / "volatility-env" / "bin" / "vol"
    
    # LLM Settings (Provider Abstraction)
    DEFAULT_LLM_PROVIDER: str = "gemini"
    GEMINI_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    LOCAL_LLM_ENDPOINT: str = ""
    
    # Authentication & Session Security
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    PASSWORD_MIN_LENGTH: int = 8

    # Evidence Acquisition Resource Limits
    MAX_EVIDENCE_FILE_SIZE_BYTES: int = 100 * 1024 * 1024 * 1024  # 100 GB
    MAX_DIRECTORY_ACQUISITION_SIZE_BYTES: int = 500 * 1024 * 1024 * 1024  # 500 GB
    MAX_DIRECTORY_FILE_COUNT: int = 50000
    MAX_DIRECTORY_RECURSION_DEPTH: int = 20
    MIN_FREE_DISK_SPACE_BYTES: int = 5 * 1024 * 1024 * 1024  # 5 GB

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()

def validate_port(port_val: Any) -> int:
    try:
        port_int = int(port_val)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid ADFIR_PORT '{port_val}': port must be an integer.")
    if not (1 <= port_int <= 65535):
        raise ValueError(f"Invalid ADFIR_PORT {port_int}: port must be between 1 and 65535.")
    return port_int

def get_backend_port() -> int:
    port_env = os.getenv("ADFIR_PORT")
    if port_env is not None and str(port_env).strip() != "":
        return validate_port(port_env)
    if settings.ADFIR_PORT is not None:
        return validate_port(settings.ADFIR_PORT)
    return 8000

# Dynamic secret key fallback: cryptographically random and securely persisted to data directory
import secrets
import logging as _cfg_logging

_cfg_logger = _cfg_logging.getLogger("ADFIR_CONFIG")

def get_jwt_secret() -> str:
    """
    Returns the configured JWT secret key, or a cryptographically random secret
    persisted to settings.DATA_DIR / 'jwt_secret.key' so that restarts reuse the same key.
    """
    if settings.JWT_SECRET_KEY:
        return settings.JWT_SECRET_KEY

    secret_path = settings.DATA_DIR / "jwt_secret.key"

    try:
        if secret_path.exists():
            secret = secret_path.read_text(encoding="utf-8").strip()
            if secret:
                return secret

        secret = secrets.token_urlsafe(64)

        secret_path.parent.mkdir(parents=True, exist_ok=True)

        secret_path.write_text(secret, encoding="utf-8")

        try:
            secret_path.chmod(0o600)
        except OSError:
            pass

        return secret

    except Exception as exc:
        _cfg_logger.error(
            "Unable to securely load or persist JWT signing secret: %s",
            exc,
        )
        raise RuntimeError(
            "JWT signing secret is unavailable; authentication cannot start safely."
        ) from exc
