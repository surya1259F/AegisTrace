"""Tool Selection Subsystem Schema (Phase 2 / Step 7)

Revision ID: 006_tool_selection_schema
Revises: 005_investigation_strategy_schema
Create Date: 2026-09-25 20:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '006_tool_selection_schema'
down_revision: Union[str, None] = '005_investigation_strategy_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update tool_definitions table
    with op.batch_alter_table('tool_definitions') as batch_op:
        batch_op.add_column(sa.Column('display_name', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('binary_name', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('platforms', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('supported_formats', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('resource_requirements', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('min_version', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('max_version', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('dependencies', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('safety_profile', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('enabled', sa.Boolean(), server_default='1', nullable=False))

    # 2. Create tool_selections table
    op.create_table(
        'tool_selections',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('task_id', sa.String(), nullable=True),
        sa.Column('task_key', sa.String(), nullable=False),
        sa.Column('capability_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('candidate_tools', sa.JSON(), nullable=True),
        sa.Column('selected_tool_id', sa.String(), nullable=True),
        sa.Column('selection_status', sa.String(), nullable=False),
        sa.Column('availability_status', sa.String(), nullable=False),
        sa.Column('evidence_compatibility', sa.String(), nullable=False),
        sa.Column('platform_compatibility', sa.String(), nullable=False),
        sa.Column('resource_status', sa.String(), nullable=False),
        sa.Column('version_status', sa.String(), nullable=False),
        sa.Column('safety_status', sa.String(), nullable=False),
        sa.Column('rejection_reasons', sa.JSON(), nullable=True),
        sa.Column('selection_rationale', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['task_id'], ['investigation_tasks.id'], ondelete='CASCADE')
    )
    op.create_index('ix_tool_selections_plan_id', 'tool_selections', ['plan_id'])
    op.create_index('ix_tool_selections_task_key', 'tool_selections', ['task_key'])
    op.create_index('ix_tool_selections_capability_id', 'tool_selections', ['capability_id'])
    op.create_index('ix_tool_selections_selection_status', 'tool_selections', ['selection_status'])


def downgrade() -> None:
    op.drop_index('ix_tool_selections_selection_status', table_name='tool_selections')
    op.drop_index('ix_tool_selections_capability_id', table_name='tool_selections')
    op.drop_index('ix_tool_selections_task_key', table_name='tool_selections')
    op.drop_index('ix_tool_selections_plan_id', table_name='tool_selections')
    op.drop_table('tool_selections')

    with op.batch_alter_table('tool_definitions') as batch_op:
        batch_op.drop_column('enabled')
        batch_op.drop_column('safety_profile')
        batch_op.drop_column('dependencies')
        batch_op.drop_column('max_version')
        batch_op.drop_column('min_version')
        batch_op.drop_column('resource_requirements')
        batch_op.drop_column('supported_formats')
        batch_op.drop_column('platforms')
        batch_op.drop_column('binary_name')
        batch_op.drop_column('display_name')
