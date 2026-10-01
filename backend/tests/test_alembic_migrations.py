import os
import uuid
import tempfile
from pathlib import Path
import pytest
from sqlalchemy import create_engine, text, inspect
from backend.app.core.migrations import run_db_migrations, get_alembic_config
from alembic import command


def test_fresh_database_alembic_migration(tmp_path):
    """
    Tests running Alembic migrations from scratch on a completely fresh database.
    Verifies that all tables and Task 2 columns exist and relationships work.
    """
    db_file = tmp_path / "fresh_test.db"
    db_url = f"sqlite:///{db_file}"
    test_engine = create_engine(db_url)

    # 1. Run migrations from scratch
    run_db_migrations(test_engine)

    # 2. Inspect table structure
    inspector = inspect(test_engine)
    tables = set(inspector.get_table_names())

    assert "alembic_version" in tables
    assert "users" in tables
    assert "cases" in tables
    assert "evidence_items" in tables
    assert "chain_of_custody_events" in tables or "custody_events" in tables
    assert "findings" in tables
    assert "execution_artifacts" in tables or "artifacts" in tables
    assert "investigation_plans" in tables

    # 3. Verify Task 2 Evidence Intelligence columns on evidence_items
    cols = {c["name"] for c in inspector.get_columns("evidence_items")}
    expected_task2_cols = {
        "evidence_subtype",
        "source_kind",
        "acquisition_method",
        "detected_format",
        "filesystem_type",
        "platform_hint",
        "status",
        "metadata_json",
        "intelligence_json",
        "error_message",
    }
    assert expected_task2_cols.issubset(cols), f"Missing columns: {expected_task2_cols - cols}"

    # 4. Verify insertion and queries work against fresh migrated DB
    with test_engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id, email, name, role, is_active) VALUES ('u1', 'test@adfir.local', 'Test User', 'INVESTIGATOR', 1)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO cases (id, case_number, name, description, owner_id, status) VALUES ('c1', 'CASE-001', 'Test Case', 'Fresh DB Migration Test', 'u1', 'ACTIVE')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO evidence_items (id, case_id, name, original_path, evidence_type, size_bytes, sha256, source_kind, status, created_by) "
                "VALUES ('e1', 'c1', 'sample.txt', '/tmp/sample.txt', 'file', 100, 'a'*64, 'FILE', 'REGISTERED', 'u1')"
            )
        )
        conn.commit()

        res = conn.execute(text("SELECT name, source_kind, status FROM evidence_items WHERE id='e1'")).fetchone()
        assert res[0] == "sample.txt"
        assert res[1] == "FILE"
        assert res[2] == "REGISTERED"

    test_engine.dispose()


def test_existing_database_alembic_migration(tmp_path):
    """
    Tests upgrading a pre-existing database from 001_initial_base_schema to 002_evidence_intelligence_schema.
    Verifies that all pre-existing cases, evidence records, users, and custody events survive with zero data loss.
    """
    db_file = tmp_path / "existing_pre_task2.db"
    db_url = f"sqlite:///{db_file}"
    test_engine = create_engine(db_url)

    # 1. Apply baseline 001 revision
    with test_engine.connect() as conn:
        cfg = get_alembic_config(test_engine)
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "001_initial_base_schema")
        conn.commit()

    # 2. Populate pre-existing records (Users, Cases, Evidence, Custody)
    case_id = str(uuid.uuid4())
    ev_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    existing_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    custody_tbl = "chain_of_custody_events"

    with test_engine.connect() as conn:
        conn.execute(
            text(
                f"INSERT INTO users (id, email, name, role, is_active) VALUES ('{user_id}', 'existing@adfir.local', 'Pre-Task2 User', 'INVESTIGATOR', 1)"
            )
        )
        conn.execute(
            text(
                f"INSERT INTO cases (id, case_number, name, description, owner_id, status) VALUES ('{case_id}', 'CASE-PRE-2', 'Legacy Case', 'Pre-existing database test', '{user_id}', 'ACTIVE')"
            )
        )
        conn.execute(
            text(
                f"INSERT INTO evidence_items (id, case_id, name, original_path, storage_path, evidence_type, size_bytes, sha256, intake_status, integrity_status) "
                f"VALUES ('{ev_id}', '{case_id}', 'legacy_evidence.bin', '/vault/orig.bin', '/vault/staged.bin', 'file', 512, '{existing_sha}', 'INTAKE_COMPLETE', 'VERIFIED')"
            )
        )
        conn.execute(
            text(
                f"INSERT INTO {custody_tbl} (id, evidence_id, case_id, event_type, actor_id, actor, description, timestamp, sha256) "
                f"VALUES ('cust1', '{ev_id}', '{case_id}', 'EVIDENCE_REGISTERED', '{user_id}', 'Pre-Task2 User', 'Legacy evidence intake', '2026-09-19 12:00:00', '{existing_sha}')"
            )
        )
        conn.commit()

    # Verify baseline contents before migration
    with test_engine.connect() as conn:
        cursor = conn.execute(text("PRAGMA table_info(evidence_items)"))
        pre_cols = {row[1] for row in cursor.fetchall()}
        assert "source_kind" not in pre_cols

    # 3. Apply migration upgrade to head (002)
    run_db_migrations(test_engine)

    # 4. Verify pre-existing data survives intact and new columns have defaults
    with test_engine.connect() as conn:
        # Check User
        u = conn.execute(text(f"SELECT email, name FROM users WHERE id='{user_id}'")).fetchone()
        assert u[0] == "existing@adfir.local"
        assert u[1] == "Pre-Task2 User"

        # Check Case
        c = conn.execute(text(f"SELECT case_number, name FROM cases WHERE id='{case_id}'")).fetchone()
        assert c[0] == "CASE-PRE-2"
        assert c[1] == "Legacy Case"

        # Check Evidence Item
        e = conn.execute(
            text(f"SELECT name, sha256, source_kind, acquisition_method, status FROM evidence_items WHERE id='{ev_id}'")
        ).fetchone()
        assert e[0] == "legacy_evidence.bin"
        assert e[1] == existing_sha
        assert e[2] == "FILE"  # Default value
        assert e[3] == "INVESTIGATOR_IMPORT"  # Default value
        assert e[4] == "REGISTERED"  # Default value

        # Check Custody Event
        cust = conn.execute(text(f"SELECT event_type, sha256 FROM {custody_tbl} WHERE id='cust1'")).fetchone()
        assert cust[0] == "EVIDENCE_REGISTERED"
        assert cust[1] == existing_sha

    test_engine.dispose()
