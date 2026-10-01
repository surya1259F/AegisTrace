"""Raw Forensic Outputs Subsystem Schema (Phase 2 / Step 10)

Revision ID: 009_raw_outputs_schema
Revises: 008_secure_execution_schema
Create Date: 2026-09-25 22:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '009_raw_outputs_schema'
down_revision: Union[str, None] = '008_secure_execution_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('execution_outputs') as batch_op:
        batch_op.add_column(sa.Column('output_type', sa.String(), server_default='TOOL_OUTPUT', nullable=False))
        batch_op.add_column(sa.Column('task_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('tool_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('tool_version', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('exit_code', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('execution_status', sa.String(), nullable=True))
        batch_op.create_index('ix_execution_outputs_output_type', ['output_type'])
        batch_op.create_index('ix_execution_outputs_task_id', ['task_id'])


def downgrade() -> None:
    with op.batch_alter_table('execution_outputs') as batch_op:
        batch_op.drop_index('ix_execution_outputs_task_id')
        batch_op.drop_index('ix_execution_outputs_output_type')
        batch_op.drop_column('execution_status')
        batch_op.drop_column('exit_code')
        batch_op.drop_column('tool_version')
        batch_op.drop_column('tool_id')
        batch_op.drop_column('task_id')
        batch_op.drop_column('output_type')

