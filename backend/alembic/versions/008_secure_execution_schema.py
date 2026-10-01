"""Secure Forensic Execution Subsystem Schema (Phase 2 / Step 9)

Revision ID: 008_secure_execution_schema
Revises: 007_scheduler_schema
Create Date: 2026-09-25 21:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '008_secure_execution_schema'
down_revision: Union[str, None] = '007_scheduler_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create forensic_executions table
    op.create_table(
        'forensic_executions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('request_id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=True),
        sa.Column('task_id', sa.String(), nullable=True),
        sa.Column('task_key', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('tool_id', sa.String(), nullable=False),
        sa.Column('tool_version', sa.String(), nullable=True),
        sa.Column('executable_path', sa.String(), nullable=False),
        sa.Column('validated_argv', sa.JSON(), nullable=False),
        sa.Column('host_platform', sa.String(), nullable=False),
        sa.Column('host_architecture', sa.String(), nullable=False),
        sa.Column('workspace_path', sa.String(), nullable=False),
        sa.Column('resource_allocation', sa.JSON(), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), server_default='300', nullable=False),
        sa.Column('execution_status', sa.String(), server_default='STARTING', nullable=False),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('process_start_time', sa.Float(), nullable=True),
        sa.Column('stdout_path', sa.String(), nullable=True),
        sa.Column('stderr_path', sa.String(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('cancellation_reason', sa.Text(), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('output_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['request_id'], ['analysis_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['task_id'], ['investigation_tasks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ondelete='SET NULL')
    )
    op.create_index('ix_forensic_executions_request_id', 'forensic_executions', ['request_id'])
    op.create_index('ix_forensic_executions_case_id', 'forensic_executions', ['case_id'])
    op.create_index('ix_forensic_executions_plan_id', 'forensic_executions', ['plan_id'])
    op.create_index('ix_forensic_executions_task_id', 'forensic_executions', ['task_id'])
    op.create_index('ix_forensic_executions_task_key', 'forensic_executions', ['task_key'])
    op.create_index('ix_forensic_executions_evidence_id', 'forensic_executions', ['evidence_id'])
    op.create_index('ix_forensic_executions_tool_id', 'forensic_executions', ['tool_id'])
    op.create_index('ix_forensic_executions_execution_status', 'forensic_executions', ['execution_status'])

    # 2. Create execution_outputs table
    op.create_table(
        'execution_outputs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('execution_id', sa.String(), nullable=False),
        sa.Column('request_id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('relative_path', sa.String(), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('sha256_hash', sa.String(), nullable=False),
        sa.Column('mime_type', sa.String(), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['execution_id'], ['forensic_executions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['request_id'], ['analysis_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ondelete='SET NULL')
    )
    op.create_index('ix_execution_outputs_execution_id', 'execution_outputs', ['execution_id'])
    op.create_index('ix_execution_outputs_request_id', 'execution_outputs', ['request_id'])
    op.create_index('ix_execution_outputs_case_id', 'execution_outputs', ['case_id'])
    op.create_index('ix_execution_outputs_evidence_id', 'execution_outputs', ['evidence_id'])
    op.create_index('ix_execution_outputs_sha256_hash', 'execution_outputs', ['sha256_hash'])


def downgrade() -> None:
    op.drop_table('execution_outputs')
    op.drop_table('forensic_executions')
