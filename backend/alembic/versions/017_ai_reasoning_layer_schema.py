"""AI Reasoning Layer Schema (Phase 2 / Step 18)

Revision ID: 017_ai_reasoning_layer_schema
Revises: 016_governance_gate_schema
Create Date: 2026-09-26 21:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '017_ai_reasoning_layer_schema'
down_revision: Union[str, None] = '016_governance_gate_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'ai_provider_configs' not in tables:
        op.create_table(
            'ai_provider_configs',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('provider', sa.String(), nullable=False),
            sa.Column('model', sa.String(), nullable=False),
            sa.Column('endpoint', sa.String(), nullable=True),
            sa.Column('api_key_encrypted', sa.Text(), nullable=True),
            sa.Column('api_key_masked', sa.String(), nullable=True),
            sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('status', sa.String(), nullable=False, server_default='ACTIVE'),
            sa.Column('last_tested_at', sa.DateTime(), nullable=True),
            sa.Column('last_test_status', sa.String(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_ai_prov_cfg_case_id', 'ai_provider_configs', ['case_id'])
        op.create_index('ix_ai_prov_cfg_user_id', 'ai_provider_configs', ['user_id'])
        op.create_index('ix_ai_prov_cfg_provider', 'ai_provider_configs', ['provider'])

    if 'ai_reasoning_records' not in tables:
        op.create_table(
            'ai_reasoning_records',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
            sa.Column('request_user_id', sa.String(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('governance_decision_id', sa.String(), sa.ForeignKey('governance_decisions.id', ondelete='SET NULL'), nullable=True),
            sa.Column('objective', sa.Text(), nullable=False),
            sa.Column('status', sa.String(), nullable=False, server_default='COMPLETED'),
            sa.Column('execution_mode', sa.String(), nullable=False),
            sa.Column('provider', sa.String(), nullable=False),
            sa.Column('model', sa.String(), nullable=False),
            sa.Column('input_references', sa.JSON(), nullable=False),
            sa.Column('raw_evidence_egress_blocked', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('egress_approved', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('statements', sa.JSON(), nullable=False),
            sa.Column('citations_verified', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('summary', sa.Text(), nullable=True),
            sa.Column('provenance', sa.JSON(), nullable=False),
            sa.Column('reasoning_metadata', sa.JSON(), nullable=False),
            sa.Column('sha256_hash', sa.String(length=64), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('completed_at', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_ai_reas_rec_case_id', 'ai_reasoning_records', ['case_id'])
        op.create_index('ix_ai_reas_rec_user_id', 'ai_reasoning_records', ['request_user_id'])
        op.create_index('ix_ai_reas_rec_gov_id', 'ai_reasoning_records', ['governance_decision_id'])
        op.create_index('ix_ai_reas_rec_status', 'ai_reasoning_records', ['status'])
        op.create_index('ix_ai_reas_rec_hash', 'ai_reasoning_records', ['sha256_hash'])


def downgrade() -> None:
    op.drop_table('ai_reasoning_records')
    op.drop_table('ai_provider_configs')

