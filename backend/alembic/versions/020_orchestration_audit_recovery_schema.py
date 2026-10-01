"""Orchestration, Audit Chain, and Recovery Schema (Final Backend Completion)

Revision ID: 020_orchestration_audit_recovery_schema
Revises: 019_final_forensic_report_schema
Create Date: 2026-09-27 12:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '020_orchestration_audit_recovery_schema'
down_revision: Union[str, None] = '019_final_forensic_report_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    # 1. Create investigation_runs table if not exists
    if 'investigation_runs' not in tables:
        op.create_table(
            'investigation_runs',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
            sa.Column('plan_id', sa.String(36), sa.ForeignKey('investigation_plans.id', ondelete='SET NULL'), nullable=True),
            sa.Column('cycle_number', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('current_stage', sa.String(64), nullable=False, server_default='STRATEGY'),
            sa.Column('status', sa.String(32), nullable=False, server_default='PENDING'),
            sa.Column('stage_progress', sa.JSON(), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('failure_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('run_metadata', sa.JSON(), nullable=True),
            sa.Column('sha256_hash', sa.String(64), nullable=True),
            sa.Column('started_at', sa.DateTime(), nullable=True),
            sa.Column('completed_at', sa.DateTime(), nullable=True),
            sa.Column('created_by', sa.String(128), nullable=False, server_default='system'),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_investigation_runs_case_id', 'investigation_runs', ['case_id'])
        op.create_index('ix_investigation_runs_current_stage', 'investigation_runs', ['current_stage'])
        op.create_index('ix_investigation_runs_status', 'investigation_runs', ['status'])

    # 2. Add columns to investigation_tasks table
    if 'investigation_tasks' in tables:
        existing_cols = {c['name'] for c in insp.get_columns('investigation_tasks')}
        with op.batch_alter_table('investigation_tasks') as batch_op:
            if 'run_id' not in existing_cols:
                batch_op.add_column(sa.Column('run_id', sa.String(36), nullable=True))
                batch_op.create_index('ix_investigation_tasks_run_id', ['run_id'])
            if 'started_at' not in existing_cols:
                batch_op.add_column(sa.Column('started_at', sa.DateTime(), nullable=True))
            if 'completed_at' not in existing_cols:
                batch_op.add_column(sa.Column('completed_at', sa.DateTime(), nullable=True))
            if 'error_message' not in existing_cols:
                batch_op.add_column(sa.Column('error_message', sa.Text(), nullable=True))

    # 3. Add cryptographic hash-chaining columns to audit_events table
    if 'audit_events' in tables:
        existing_cols = {c['name'] for c in insp.get_columns('audit_events')}
        with op.batch_alter_table('audit_events') as batch_op:
            if 'previous_hash' not in existing_cols:
                batch_op.add_column(sa.Column('previous_hash', sa.String(64), nullable=True))
            if 'chain_index' not in existing_cols:
                batch_op.add_column(sa.Column('chain_index', sa.Integer(), nullable=True))
                batch_op.create_index('ix_audit_events_chain_index', ['chain_index'])
            if 'provenance_context' not in existing_cols:
                batch_op.add_column(sa.Column('provenance_context', sa.JSON(), nullable=True))

    # 4. Add case closure and workspace columns to cases table
    if 'cases' in tables:
        existing_cols = {c['name'] for c in insp.get_columns('cases')}
        with op.batch_alter_table('cases') as batch_op:
            if 'objective' not in existing_cols:
                batch_op.add_column(sa.Column('objective', sa.Text(), nullable=True))
            if 'case_type' not in existing_cols:
                batch_op.add_column(sa.Column('case_type', sa.String(64), nullable=False, server_default='GENERIC_INCIDENT'))
            if 'priority' not in existing_cols:
                batch_op.add_column(sa.Column('priority', sa.String(32), nullable=False, server_default='MEDIUM'))
            if 'workspace_state' not in existing_cols:
                batch_op.add_column(sa.Column('workspace_state', sa.String(64), nullable=False, server_default='NOT_INITIALIZED'))
            if 'workspace_path' not in existing_cols:
                batch_op.add_column(sa.Column('workspace_path', sa.String(512), nullable=True))
            if 'case_permissions' not in existing_cols:
                batch_op.add_column(sa.Column('case_permissions', sa.JSON(), nullable=True))
            if 'closed_by' not in existing_cols:
                batch_op.add_column(sa.Column('closed_by', sa.String(128), nullable=True))
            if 'closure_rationale' not in existing_cols:
                batch_op.add_column(sa.Column('closure_rationale', sa.Text(), nullable=True))
            if 'closure_metadata' not in existing_cols:
                batch_op.add_column(sa.Column('closure_metadata', sa.JSON(), nullable=True))
            if 'closure_hash' not in existing_cols:
                batch_op.add_column(sa.Column('closure_hash', sa.String(64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'cases' in tables:
        with op.batch_alter_table('cases') as batch_op:
            for col in ['closed_by', 'closure_rationale', 'closure_metadata', 'closure_hash']:
                batch_op.drop_column(col)

    if 'audit_events' in tables:
        with op.batch_alter_table('audit_events') as batch_op:
            batch_op.drop_index('ix_audit_events_chain_index')
            for col in ['previous_hash', 'chain_index', 'provenance_context']:
                batch_op.drop_column(col)

    if 'investigation_tasks' in tables:
        with op.batch_alter_table('investigation_tasks') as batch_op:
            batch_op.drop_index('ix_investigation_tasks_run_id')
            for col in ['run_id', 'started_at', 'completed_at', 'error_message']:
                batch_op.drop_column(col)

    if 'investigation_runs' in tables:
        op.drop_table('investigation_runs')
