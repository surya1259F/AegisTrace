from pathlib import Path
import logging
from sqlalchemy import inspect, text
from alembic.config import Config
from alembic import command
from backend.app.core.config import settings

logger = logging.getLogger("ADFIR_MIGRATIONS")

def get_alembic_config(engine=None) -> Config:
    backend_dir = Path(__file__).resolve().parent.parent.parent
    candidates = [
        backend_dir / "alembic.ini",
        backend_dir.parent / "alembic.ini",
        backend_dir.parent / "backend" / "alembic.ini",
        Path.cwd() / "alembic.ini",
        Path.cwd() / "backend" / "alembic.ini",
    ]
    ini_path = None
    for cand in candidates:
        if cand.exists():
            ini_path = cand
            break
            
    if not ini_path:
        raise FileNotFoundError(f"Alembic configuration file not found in candidates: {candidates}")

    alembic_dir_candidates = [
        ini_path.parent / "alembic",
        backend_dir / "alembic",
        backend_dir.parent / "alembic",
    ]
    alembic_dir = None
    for cand in alembic_dir_candidates:
        if cand.exists():
            alembic_dir = cand
            break

    if not alembic_dir:
        raise FileNotFoundError(f"Alembic directory not found in candidates: {alembic_dir_candidates}")

    alembic_cfg = Config(str(ini_path))
    db_url = str(engine.url) if engine else str(settings.DATABASE_URL)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_cfg.set_main_option("script_location", str(alembic_dir))
    return alembic_cfg

def run_db_migrations(target_engine=None):
    """
    Applies Alembic schema migrations deterministically and non-destructively.
    Handles fresh databases, existing unversioned databases, and upgraded databases.
    """
    from backend.app.core.database import engine as default_engine
    eng = target_engine or default_engine
    alembic_cfg = get_alembic_config(eng)

    with eng.connect() as connection:
        alembic_cfg.attributes["connection"] = connection
        try:
            inspector = inspect(connection)
            tables = set(inspector.get_table_names())

            if "alembic_version" not in tables:
                if "evidence_items" in tables or "users" in tables or "cases" in tables:
                    # Pre-existing database created before Alembic version tracking.
                    cols = set()
                    if "evidence_items" in tables:
                        cols = {c["name"] for c in inspector.get_columns("evidence_items")}

                    if "forensic_executions" in tables and "execution_outputs" in tables:
                        exec_out_cols = {c["name"] for c in inspector.get_columns("execution_outputs")}
                        if "investigator_reviews" in tables:
                            logger.info("Existing database possesses Step 19 investigator review schema. Stamping revision 018_investigator_review_schema.")
                            command.stamp(alembic_cfg, "018_investigator_review_schema")
                        elif "ai_reasoning_records" in tables:
                            logger.info("Existing database possesses Step 18 AI reasoning layer schema. Stamping revision 017_ai_reasoning_layer_schema.")
                            command.stamp(alembic_cfg, "017_ai_reasoning_layer_schema")
                        elif "governance_decisions" in tables:
                            logger.info("Existing database possesses Step 17 governance gate schema. Stamping revision 016_governance_gate_schema.")
                            command.stamp(alembic_cfg, "016_governance_gate_schema")
                        elif "specialist_agents" in tables:
                            logger.info("Existing database possesses Step 16 specialist agent schema. Stamping revision 015_specialist_agent_layer_schema.")
                            command.stamp(alembic_cfg, "015_specialist_agent_layer_schema")
                        elif "deterministic_findings" in tables:
                            logger.info("Existing database possesses Step 15 deterministic findings schema. Stamping revision 014_deterministic_findings_schema.")
                            command.stamp(alembic_cfg, "014_deterministic_findings_schema")
                        elif "artifact_relationships" in tables:
                            logger.info("Existing database possesses Step 14 cross-domain correlation schema. Stamping revision 013_cross_domain_correlation_schema.")
                            command.stamp(alembic_cfg, "013_cross_domain_correlation_schema")
                        elif "timeline_events" in tables:
                            logger.info("Existing database possesses Step 13 unified timeline schema. Stamping revision 012_unified_timeline_schema.")
                            command.stamp(alembic_cfg, "012_unified_timeline_schema")
                        elif "normalized_artifacts" in tables:
                            logger.info("Existing database possesses Step 12 normalized artifacts schema. Stamping revision 011_normalized_artifacts_schema.")
                            command.stamp(alembic_cfg, "011_normalized_artifacts_schema")
                        elif "structured_artifacts" in tables:
                            logger.info("Existing database possesses Step 11 structured artifacts schema. Stamping revision 010_structured_artifacts_schema.")
                            command.stamp(alembic_cfg, "010_structured_artifacts_schema")
                        elif "output_type" in exec_out_cols:
                            logger.info("Existing database possesses Step 10 raw outputs schema. Stamping revision 009_raw_outputs_schema.")
                            command.stamp(alembic_cfg, "009_raw_outputs_schema")
                        else:
                            logger.info("Existing database possesses Step 9 secure execution schema. Stamping revision 008_secure_execution_schema.")
                            command.stamp(alembic_cfg, "008_secure_execution_schema")
                    elif "analysis_requests" in tables:
                        logger.info("Existing database possesses Step 8 scheduler schema. Stamping revision 007_scheduler_schema.")
                        command.stamp(alembic_cfg, "007_scheduler_schema")
                    elif "tool_selections" in tables:
                        logger.info("Existing database possesses Step 7 tool selection schema. Stamping revision 006_tool_selection_schema.")
                        command.stamp(alembic_cfg, "006_tool_selection_schema")
                    elif "forensic_capabilities" in tables:
                        logger.info("Existing database possesses Step 6 strategy schema. Stamping revision 005_investigation_strategy_schema.")
                        command.stamp(alembic_cfg, "005_investigation_strategy_schema")
                    elif "evidence_intelligence" in tables:
                        logger.info("Existing database possesses Step 5 intelligence profile schema. Stamping Alembic version 004_evidence_intelligence_profile_schema.")
                        command.stamp(alembic_cfg, "004_evidence_intelligence_profile_schema")
                    elif "parent_acquisition_id" in cols:
                        logger.info("Existing database possesses Step 4 acquisition schema. Stamping Alembic version 003_evidence_acquisition_schema.")
                        command.stamp(alembic_cfg, "003_evidence_acquisition_schema")
                    elif "source_kind" in cols and "intelligence_json" in cols:
                        logger.info("Existing database possesses Task 2 schema. Stamping Alembic version 002_evidence_intelligence_schema.")
                        command.stamp(alembic_cfg, "002_evidence_intelligence_schema")
                    else:
                        logger.info("Existing database possesses base schema. Stamping revision 001_initial_base_schema.")
                        command.stamp(alembic_cfg, "001_initial_base_schema")

            # Upgrade to head (applies missing migrations deterministically)
            command.upgrade(alembic_cfg, "head")
            connection.commit()
            logger.info("Alembic schema migration completed successfully.")
        except Exception:
            connection.rollback()
            logger.exception("Alembic schema migration failed.")
            raise
