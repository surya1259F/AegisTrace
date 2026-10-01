"""Evidence Intelligence Profile Subsystem Schema

Revision ID: 004_evidence_intelligence_profile_schema
Revises: 003_evidence_acquisition_schema
Create Date: 2026-09-25 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '004_evidence_intelligence_profile_schema'
down_revision: Union[str, None] = '003_evidence_acquisition_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'evidence_intelligence',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('engine_version', sa.String(), server_default='1.0.0', nullable=False),
        sa.Column('analysis_version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('classification', sa.String(), nullable=False),
        sa.Column('subtype', sa.String(), nullable=True),
        sa.Column('classification_status', sa.String(), server_default='MATCH', nullable=False),
        sa.Column('classification_confidence', sa.String(), server_default='DETERMINISTIC', nullable=False),
        sa.Column('classification_basis', sa.Text(), nullable=True),
        sa.Column('detected_format', sa.String(), nullable=False),
        sa.Column('detected_mime', sa.String(), server_default='application/octet-stream', nullable=False),
        sa.Column('platform_hint', sa.String(), server_default='UNKNOWN', nullable=False),
        sa.Column('platform_basis', sa.Text(), nullable=True),
        sa.Column('platform_confidence', sa.String(), server_default='UNKNOWN', nullable=False),
        sa.Column('architecture_hint', sa.String(), server_default='UNKNOWN', nullable=False),
        sa.Column('filesystem_type', sa.String(), server_default='UNKNOWN', nullable=False),
        sa.Column('filesystem_version', sa.String(), nullable=True),
        sa.Column('filesystem_basis', sa.Text(), nullable=True),
        sa.Column('filesystem_detection_status', sa.String(), server_default='NOT_PRESENT', nullable=False),
        sa.Column('partition_table_type', sa.String(), server_default='NONE', nullable=False),
        sa.Column('partitions_json', sa.JSON(), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('characteristics_json', sa.JSON(), nullable=True),
        sa.Column('detection_methods', sa.JSON(), nullable=True),
        sa.Column('tags_json', sa.JSON(), nullable=True),
        sa.Column('resource_profile_json', sa.JSON(), nullable=True),
        sa.Column('recommended_tools_json', sa.JSON(), nullable=True),
        sa.Column('recommended_families_json', sa.JSON(), nullable=True),
        sa.Column('limitations_json', sa.JSON(), nullable=True),
        sa.Column('evidence_sha256_verified', sa.String(), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('evidence_id', name='uq_evidence_intelligence_evidence_id')
    )
    op.create_index(op.f('ix_evidence_intelligence_evidence_id'), 'evidence_intelligence', ['evidence_id'], unique=True)
    op.create_index(op.f('ix_evidence_intelligence_case_id'), 'evidence_intelligence', ['case_id'], unique=False)
    op.create_index(op.f('ix_evidence_intelligence_classification'), 'evidence_intelligence', ['classification'], unique=False)
    op.create_index(op.f('ix_evidence_intelligence_subtype'), 'evidence_intelligence', ['subtype'], unique=False)
    op.create_index(op.f('ix_evidence_intelligence_detected_format'), 'evidence_intelligence', ['detected_format'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_evidence_intelligence_detected_format'), table_name='evidence_intelligence')
    op.drop_index(op.f('ix_evidence_intelligence_subtype'), table_name='evidence_intelligence')
    op.drop_index(op.f('ix_evidence_intelligence_classification'), table_name='evidence_intelligence')
    op.drop_index(op.f('ix_evidence_intelligence_case_id'), table_name='evidence_intelligence')
    op.drop_index(op.f('ix_evidence_intelligence_evidence_id'), table_name='evidence_intelligence')
    op.drop_table('evidence_intelligence')

