"""Investigation Strategy Engine Schema

Revision ID: 005_investigation_strategy_schema
Revises: 004_evidence_intelligence_profile_schema
Create Date: 2026-09-25 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '005_investigation_strategy_schema'
down_revision: Union[str, None] = '004_evidence_intelligence_profile_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Forensic Capabilities
    op.create_table(
        'forensic_capabilities',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('supported_evidence_categories', sa.JSON(), nullable=True),
        sa.Column('supported_evidence_subtypes', sa.JSON(), nullable=True),
        sa.Column('supported_formats', sa.JSON(), nullable=True),
        sa.Column('supported_platforms', sa.JSON(), nullable=True),
        sa.Column('required_inputs', sa.JSON(), nullable=True),
        sa.Column('expected_outputs', sa.JSON(), nullable=True),
        sa.Column('prerequisites', sa.JSON(), nullable=True),
        sa.Column('resource_profile', sa.JSON(), nullable=True),
        sa.Column('priority_hints', sa.JSON(), nullable=True),
        sa.Column('version', sa.String(), server_default='1.0.0', nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 2. Add columns to investigation_plans if not existing
    with op.batch_alter_table('investigation_plans') as batch_op:
        batch_op.add_column(sa.Column('parent_plan_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('validation_status', sa.String(), server_default='VALIDATED', nullable=False))
        batch_op.add_column(sa.Column('evidence_snapshot', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('resource_snapshot', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('stopping_conditions_summary', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('change_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('created_by', sa.String(), server_default='strategy-engine', nullable=False))

    # 3. Investigation Tasks
    op.create_table(
        'investigation_tasks',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('task_key', sa.String(), nullable=False),
        sa.Column('sequence', sa.Integer(), nullable=False),
        sa.Column('capability_id', sa.String(), nullable=False),
        sa.Column('agent_name', sa.String(), nullable=False),
        sa.Column('evidence_ids', sa.JSON(), nullable=True),
        sa.Column('candidate_tool_ids', sa.JSON(), nullable=True),
        sa.Column('selected_tool_id', sa.String(), nullable=True),
        sa.Column('priority_level', sa.String(), server_default='MEDIUM', nullable=False),
        sa.Column('priority_score', sa.Float(), server_default='0.5', nullable=False),
        sa.Column('priority_rationale', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), server_default='PLANNED', nullable=False),
        sa.Column('required_inputs', sa.JSON(), nullable=True),
        sa.Column('expected_outputs', sa.JSON(), nullable=True),
        sa.Column('resource_requirements', sa.JSON(), nullable=True),
        sa.Column('estimated_cost', sa.JSON(), nullable=True),
        sa.Column('rationale', sa.JSON(), nullable=True),
        sa.Column('blocking_reason', sa.Text(), nullable=True),
        sa.Column('stopping_conditions_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_investigation_tasks_plan_id', 'investigation_tasks', ['plan_id'], unique=False)
    op.create_index('ix_investigation_tasks_task_key', 'investigation_tasks', ['task_key'], unique=False)
    op.create_index('ix_investigation_tasks_capability_id', 'investigation_tasks', ['capability_id'], unique=False)
    op.create_index('ix_investigation_tasks_status', 'investigation_tasks', ['status'], unique=False)

    # 4. Task Dependencies
    op.create_table(
        'investigation_task_dependencies',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('parent_task_id', sa.String(), nullable=False),
        sa.Column('child_task_id', sa.String(), nullable=False),
        sa.Column('dependency_type', sa.String(), server_default='TASK_TO_TASK', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_investigation_task_deps_plan_id', 'investigation_task_dependencies', ['plan_id'], unique=False)

    # 5. Stopping Conditions
    op.create_table(
        'plan_stopping_conditions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('condition_code', sa.String(), nullable=False),
        sa.Column('trigger_description', sa.Text(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(), server_default='INFO', nullable=False),
        sa.Column('human_review_required', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('triggered_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_plan_stopping_conditions_plan_id', 'plan_stopping_conditions', ['plan_id'], unique=False)

    # 6. Plan Adjustments
    op.create_table(
        'plan_adjustments',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False),
        sa.Column('adjustment_type', sa.String(), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('previous_state', sa.JSON(), nullable=True),
        sa.Column('new_state', sa.JSON(), nullable=True),
        sa.Column('actor_id', sa.String(), server_default='strategy-engine', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['plan_id'], ['investigation_plans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_plan_adjustments_plan_id', 'plan_adjustments', ['plan_id'], unique=False)


def downgrade() -> None:
    op.drop_table('plan_adjustments')
    op.drop_table('plan_stopping_conditions')
    op.drop_table('investigation_task_dependencies')
    op.drop_table('investigation_tasks')
    with op.batch_alter_table('investigation_plans') as batch_op:
        batch_op.drop_column('created_by')
        batch_op.drop_column('change_reason')
        batch_op.drop_column('stopping_conditions_summary')
        batch_op.drop_column('resource_snapshot')
        batch_op.drop_column('evidence_snapshot')
        batch_op.drop_column('validation_status')
        batch_op.drop_column('parent_plan_id')
    op.drop_table('forensic_capabilities')
