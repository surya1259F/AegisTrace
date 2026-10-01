"""Cross-Domain Correlation Schema (Phase 2 / Step 14)

Revision ID: 013_cross_domain_correlation_schema
Revises: 012_unified_timeline_schema
Create Date: 2026-09-26 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '013_cross_domain_correlation_schema'
down_revision: Union[str, None] = '012_unified_timeline_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Forensic Correlation Groups (Clusters)
    op.create_table(
        'forensic_correlation_groups',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('member_artifact_ids', sa.JSON(), nullable=False),
        sa.Column('member_event_ids', sa.JSON(), nullable=False),
        sa.Column('relationship_ids', sa.JSON(), nullable=False),
        sa.Column('contributing_domains', sa.JSON(), nullable=False),
        sa.Column('source_evidence_ids', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_forensic_correlation_groups_case_id', 'forensic_correlation_groups', ['case_id'])
    op.create_index('ix_forensic_correlation_groups_sha256_hash', 'forensic_correlation_groups', ['sha256_hash'])
    op.create_index('ix_forensic_correlation_groups_confidence_score', 'forensic_correlation_groups', ['confidence_score'])

    # 2. Artifact Relationships (Edges)
    op.create_table(
        'artifact_relationships',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('group_id', sa.String(), sa.ForeignKey('forensic_correlation_groups.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source_id', sa.String(), nullable=False),
        sa.Column('source_type', sa.String(), nullable=False),
        sa.Column('source_domain', sa.String(), nullable=False),
        sa.Column('target_id', sa.String(), nullable=False),
        sa.Column('target_type', sa.String(), nullable=False),
        sa.Column('target_domain', sa.String(), nullable=False),
        sa.Column('relationship_type', sa.String(), nullable=False),
        sa.Column('matching_identifier', sa.String(), nullable=True),
        sa.Column('matching_field', sa.String(), nullable=True),
        sa.Column('temporal_relationship', sa.JSON(), nullable=True),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('evidence_ids', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_artifact_relationships_case_id', 'artifact_relationships', ['case_id'])
    op.create_index('ix_artifact_relationships_group_id', 'artifact_relationships', ['group_id'])
    op.create_index('ix_artifact_relationships_source_id', 'artifact_relationships', ['source_id'])
    op.create_index('ix_artifact_relationships_target_id', 'artifact_relationships', ['target_id'])
    op.create_index('ix_artifact_relationships_relationship_type', 'artifact_relationships', ['relationship_type'])
    op.create_index('ix_artifact_relationships_matching_identifier', 'artifact_relationships', ['matching_identifier'])
    op.create_index('ix_artifact_relationships_sha256_hash', 'artifact_relationships', ['sha256_hash'])
    op.create_index('ix_artifact_relationships_confidence_score', 'artifact_relationships', ['confidence_score'])


def downgrade() -> None:
    op.drop_table('artifact_relationships')
    op.drop_table('forensic_correlation_groups')
