from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from backend.app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Backward compatibility shims (route schema evolution exclusively through Alembic)
def ensure_correlation_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_planner_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_execution_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_user_auth_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_case_auth_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_evidence_acquisition_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_evidence_intelligence_profile_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)


def ensure_evidence_schema(target_engine=None):
    from backend.app.core.migrations import run_db_migrations
    run_db_migrations(target_engine or engine)
