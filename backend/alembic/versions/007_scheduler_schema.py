"""Resource-Aware Scheduler Subsystem Schema (Phase 2 / Step 8)

Revision ID: 007_scheduler_schema
Revises: 006_tool_selection_schema
Create Date: 2026-09-25 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '007_scheduler_schema'
down_revision: Union[str, None] = '006_tool_selection_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create analysis_requests table
    op.create_table(
        'analysis_requests',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('task_id', sa.String(), nullable=True),
        sa.Column('task_key', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('capability_id', sa.String(), nullable=False),
        sa.Column('selected_tool_id', sa.String(), nullable=False),
        sa.Column('resource_requirements', sa.JSON(), nullable=True),
        sa.Column('priority_level', sa.String(), server_default='MEDIUM', nullable=False),
        sa.Column('priority_score', sa.Float(), server_default='0.5', nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), server_default='300', nullable=False),
        sa.Column('retry_policy', sa.JSON(), nullable=True),
        sa.Column('dependencies', sa.JSON(), nullable=True),
        sa.Column('scheduler_status', sa.String(), server_default='QUEUED', nullable=False),
        sa.Column('allocated_resources', sa.JSON(), nullable=True),
        sa.Column('blocking_reason', sa.Text(), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('queued_at', sa.DateTime(), nullable=False),
        sa.Column('ready_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['task_id'], ['investigation_tasks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ondelete='SET NULL')
    )
    op.create_index('ix_analysis_requests_case_id', 'analysis_requests', ['case_id'])
    op.create_index('ix_analysis_requests_plan_id', 'analysis_requests', ['plan_id'])
    op.create_index('ix_analysis_requests_task_id', 'analysis_requests', ['task_id'])
    op.create_index('ix_analysis_requests_task_key', 'analysis_requests', ['task_key'])
    op.create_index('ix_analysis_requests_capability_id', 'analysis_requests', ['capability_id'])
    op.create_index('ix_analysis_requests_selected_tool_id', 'analysis_requests', ['selected_tool_id'])
    op.create_index('ix_analysis_requests_scheduler_status', 'analysis_requests', ['scheduler_status'])


def downgrade() -> None:
    op.drop_index('ix_analysis_requests_scheduler_status', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_selected_tool_id', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_capability_id', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_task_key', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_task_id', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_plan_id', table_name='analysis_requests')
    op.drop_index('ix_analysis_requests_case_id', table_name='analysis_requests')
    op.drop_table('analysis_requests')
