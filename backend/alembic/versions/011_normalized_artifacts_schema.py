"""Artifact Normalization Subsystem Schema (Phase 2 / Step 12)

Revision ID: 011_normalized_artifacts_schema
Revises: 010_structured_artifacts_schema
Create Date: 2026-09-26 13:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '011_normalized_artifacts_schema'
down_revision: Union[str, None] = '010_structured_artifacts_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'normalized_artifacts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('execution_id', sa.String(), sa.ForeignKey('forensic_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_artifact_id', sa.String(), sa.ForeignKey('structured_artifacts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('raw_output_id', sa.String(), sa.ForeignKey('execution_outputs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('request_id', sa.String(), sa.ForeignKey('analysis_requests.id', ondelete='SET NULL'), nullable=True),
        sa.Column('task_id', sa.String(), nullable=True),
        sa.Column('entity_type', sa.String(), nullable=False),
        sa.Column('entity_identity', sa.String(length=128), nullable=False),
        sa.Column('source_specific_identity', sa.String(), nullable=True),
        sa.Column('normalized_fields', sa.JSON(), nullable=False),
        sa.Column('evidence_reference', sa.JSON(), nullable=False),
        sa.Column('provenance_summary', sa.JSON(), nullable=False),
        sa.Column('contributing_source_artifact_ids', sa.JSON(), nullable=False),
        sa.Column('occurrence_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('entity_timestamp', sa.DateTime(), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('source_artifact_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('normalization_status', sa.String(), server_default='NORMALIZED', nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False)
    )
    with op.batch_alter_table('normalized_artifacts') as batch_op:
        batch_op.create_index('ix_normalized_artifacts_case_id', ['case_id'])
        batch_op.create_index('ix_normalized_artifacts_evidence_id', ['evidence_id'])
        batch_op.create_index('ix_normalized_artifacts_execution_id', ['execution_id'])
        batch_op.create_index('ix_normalized_artifacts_source_artifact_id', ['source_artifact_id'])
        batch_op.create_index('ix_normalized_artifacts_raw_output_id', ['raw_output_id'])
        batch_op.create_index('ix_normalized_artifacts_request_id', ['request_id'])
        batch_op.create_index('ix_normalized_artifacts_task_id', ['task_id'])
        batch_op.create_index('ix_normalized_artifacts_entity_type', ['entity_type'])
        batch_op.create_index('ix_normalized_artifacts_entity_identity', ['entity_identity'])
        batch_op.create_index('ix_normalized_artifacts_entity_timestamp', ['entity_timestamp'])
        batch_op.create_index('ix_normalized_artifacts_sha256_hash', ['sha256_hash'])
        batch_op.create_index('ix_normalized_artifacts_normalization_status', ['normalization_status'])


def downgrade() -> None:
    op.drop_table('normalized_artifacts')
