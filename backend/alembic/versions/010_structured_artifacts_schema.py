"""Structured Artifact Extraction Subsystem Schema (Phase 2 / Step 11)

Revision ID: 010_structured_artifacts_schema
Revises: 009_raw_outputs_schema
Create Date: 2026-09-26 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '010_structured_artifacts_schema'
down_revision: Union[str, None] = '009_raw_outputs_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'structured_artifacts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('execution_id', sa.String(), sa.ForeignKey('forensic_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('raw_output_id', sa.String(), sa.ForeignKey('execution_outputs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('request_id', sa.String(), sa.ForeignKey('analysis_requests.id', ondelete='SET NULL'), nullable=True),
        sa.Column('task_id', sa.String(), nullable=True),
        sa.Column('tool_id', sa.String(), nullable=True),
        sa.Column('tool_version', sa.String(), nullable=True),
        sa.Column('parser_name', sa.String(), nullable=False),
        sa.Column('parser_version', sa.String(), server_default='1.0.0', nullable=False),
        sa.Column('artifact_type', sa.String(), nullable=False),
        sa.Column('source_reference', sa.String(), nullable=True),
        sa.Column('normalized_data', sa.JSON(), nullable=False),
        sa.Column('raw_record', sa.Text(), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('source_raw_output_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('extraction_status', sa.String(), server_default='EXTRACTED', nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False)
    )
    with op.batch_alter_table('structured_artifacts') as batch_op:
        batch_op.create_index('ix_structured_artifacts_case_id', ['case_id'])
        batch_op.create_index('ix_structured_artifacts_evidence_id', ['evidence_id'])
        batch_op.create_index('ix_structured_artifacts_execution_id', ['execution_id'])
        batch_op.create_index('ix_structured_artifacts_raw_output_id', ['raw_output_id'])
        batch_op.create_index('ix_structured_artifacts_request_id', ['request_id'])
        batch_op.create_index('ix_structured_artifacts_task_id', ['task_id'])
        batch_op.create_index('ix_structured_artifacts_tool_id', ['tool_id'])
        batch_op.create_index('ix_structured_artifacts_parser_name', ['parser_name'])
        batch_op.create_index('ix_structured_artifacts_artifact_type', ['artifact_type'])
        batch_op.create_index('ix_structured_artifacts_sha256_hash', ['sha256_hash'])
        batch_op.create_index('ix_structured_artifacts_extraction_status', ['extraction_status'])


def downgrade() -> None:
    op.drop_table('structured_artifacts')
