"""Unified Investigation Timeline Schema (Phase 2 / Step 13)

Revision ID: 012_unified_timeline_schema
Revises: 011_normalized_artifacts_schema
Create Date: 2026-09-26 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '012_unified_timeline_schema'
down_revision: Union[str, None] = '011_normalized_artifacts_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'timeline_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('execution_id', sa.String(), sa.ForeignKey('forensic_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('normalized_artifact_id', sa.String(), sa.ForeignKey('normalized_artifacts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('structured_artifact_id', sa.String(), sa.ForeignKey('structured_artifacts.id', ondelete='SET NULL'), nullable=True),
        sa.Column('timestamp_utc', sa.DateTime(), nullable=False),
        sa.Column('original_timestamp', sa.String(), nullable=False),
        sa.Column('original_timezone', sa.String(), nullable=True),
        sa.Column('timezone_offset', sa.String(), nullable=True),
        sa.Column('timezone_source', sa.String(), nullable=True),
        sa.Column('timezone_status', sa.String(), server_default='EXPLICIT', nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('event_source', sa.String(), nullable=False),
        sa.Column('event_data', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('temporal_precision', sa.String(), server_default='SECOND', nullable=False),
        sa.Column('window_start_utc', sa.DateTime(), nullable=True),
        sa.Column('window_end_utc', sa.DateTime(), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('source_artifact_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False)
    )
    with op.batch_alter_table('timeline_events') as batch_op:
        batch_op.create_index('ix_timeline_events_case_id', ['case_id'])
        batch_op.create_index('ix_timeline_events_evidence_id', ['evidence_id'])
        batch_op.create_index('ix_timeline_events_execution_id', ['execution_id'])
        batch_op.create_index('ix_timeline_events_normalized_artifact_id', ['normalized_artifact_id'])
        batch_op.create_index('ix_timeline_events_structured_artifact_id', ['structured_artifact_id'])
        batch_op.create_index('ix_timeline_events_timestamp_utc', ['timestamp_utc'])
        batch_op.create_index('ix_timeline_events_event_type', ['event_type'])
        batch_op.create_index('ix_timeline_events_event_source', ['event_source'])
        batch_op.create_index('ix_timeline_events_confidence_score', ['confidence_score'])
        batch_op.create_index('ix_timeline_events_temporal_precision', ['temporal_precision'])
        batch_op.create_index('ix_timeline_events_sha256_hash', ['sha256_hash'])


def downgrade() -> None:
    op.drop_table('timeline_events')
