"""Deterministic Findings Schema (Phase 2 / Step 15)

Revision ID: 014_deterministic_findings_schema
Revises: 013_cross_domain_correlation_schema
Create Date: 2026-09-26 17:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '014_deterministic_findings_schema'
down_revision: Union[str, None] = '013_cross_domain_correlation_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'deterministic_findings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('observed_facts', sa.JSON(), nullable=False),
        sa.Column('finding_type', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('severity_rule', sa.String(), nullable=False),
        sa.Column('confidence', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('confidence_inputs', sa.JSON(), nullable=False),
        sa.Column('supporting_artifact_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_event_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_relationship_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_group_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_evidence_ids', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_deterministic_findings_case_id', 'deterministic_findings', ['case_id'])
    op.create_index('ix_deterministic_findings_finding_type', 'deterministic_findings', ['finding_type'])
    op.create_index('ix_deterministic_findings_severity', 'deterministic_findings', ['severity'])
    op.create_index('ix_deterministic_findings_confidence', 'deterministic_findings', ['confidence'])
    op.create_index('ix_deterministic_findings_sha256_hash', 'deterministic_findings', ['sha256_hash'])


def downgrade() -> None:
    op.drop_table('deterministic_findings')
