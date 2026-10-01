"""Investigator Review Schema (Phase 2 / Step 19)

Revision ID: 018_investigator_review_schema
Revises: 017_ai_reasoning_layer_schema
Create Date: 2026-09-26 22:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '018_investigator_review_schema'
down_revision: Union[str, None] = '017_ai_reasoning_layer_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'investigator_reviews' not in tables:
        op.create_table(
            'investigator_reviews',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
            sa.Column('investigator_id', sa.String(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('investigator_name', sa.String(), nullable=False),
            sa.Column('target_type', sa.String(), nullable=False),
            sa.Column('target_id', sa.String(), nullable=False),
            sa.Column('statement_id', sa.String(), nullable=True),
            sa.Column('decision', sa.String(), nullable=False),
            sa.Column('comment', sa.Text(), nullable=False),
            sa.Column('supporting_references', sa.JSON(), nullable=False),
            sa.Column('resulting_workflow_action', sa.String(), nullable=False),
            sa.Column('action_reference_id', sa.String(), nullable=True),
            sa.Column('provenance', sa.JSON(), nullable=False),
            sa.Column('review_metadata', sa.JSON(), nullable=False),
            sa.Column('sha256_hash', sa.String(length=64), nullable=False),
            sa.Column('storage_path', sa.String(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_inv_rev_case_id', 'investigator_reviews', ['case_id'])
        op.create_index('ix_inv_rev_inv_id', 'investigator_reviews', ['investigator_id'])
        op.create_index('ix_inv_rev_target_type', 'investigator_reviews', ['target_type'])
        op.create_index('ix_inv_rev_target_id', 'investigator_reviews', ['target_id'])
        op.create_index('ix_inv_rev_decision', 'investigator_reviews', ['decision'])
        op.create_index('ix_inv_rev_action', 'investigator_reviews', ['resulting_workflow_action'])
        op.create_index('ix_inv_rev_hash', 'investigator_reviews', ['sha256_hash'])
        op.create_index('ix_inv_rev_timestamp', 'investigator_reviews', ['timestamp'])


def downgrade() -> None:
    op.drop_table('investigator_reviews')
