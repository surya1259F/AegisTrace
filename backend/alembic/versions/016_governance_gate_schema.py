"""Governance Gate Schema (Phase 2 / Step 17)

Revision ID: 016_governance_gate_schema
Revises: 015_specialist_agent_layer_schema
Create Date: 2026-09-26 21:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '016_governance_gate_schema'
down_revision: Union[str, None] = '015_specialist_agent_layer_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. governance_decisions table
    op.create_table(
        'governance_decisions',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requesting_agent', sa.String(), nullable=True),
        sa.Column('action_type', sa.String(), nullable=False),
        sa.Column('target_resource_type', sa.String(), nullable=True),
        sa.Column('target_resource_id', sa.String(), nullable=True),
        sa.Column('policy_checks', sa.JSON(), nullable=False),
        sa.Column('risk_level', sa.String(), nullable=False, server_default='LOW'),
        sa.Column('approval_status', sa.String(), nullable=False, server_default='NOT_REQUIRED'),
        sa.Column('decision', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('approved_by', sa.String(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('input_references', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_gov_dec_case_id', 'governance_decisions', ['case_id'])
    op.create_index('ix_gov_dec_req_agent', 'governance_decisions', ['requesting_agent'])
    op.create_index('ix_gov_dec_action_type', 'governance_decisions', ['action_type'])
    op.create_index('ix_gov_dec_risk_level', 'governance_decisions', ['risk_level'])
    op.create_index('ix_gov_dec_appr_status', 'governance_decisions', ['approval_status'])
    op.create_index('ix_gov_dec_decision', 'governance_decisions', ['decision'])
    op.create_index('ix_gov_dec_hash', 'governance_decisions', ['sha256_hash'])

    # 2. evidence_verifications table
    op.create_table(
        'evidence_verifications',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_type', sa.String(), nullable=False),
        sa.Column('target_id', sa.String(), nullable=False),
        sa.Column('verification_status', sa.String(), nullable=False),
        sa.Column('integrity_check', sa.JSON(), nullable=False),
        sa.Column('lineage_check', sa.JSON(), nullable=False),
        sa.Column('provenance_check', sa.JSON(), nullable=False),
        sa.Column('metadata_check', sa.JSON(), nullable=False),
        sa.Column('contradiction_check', sa.JSON(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_ev_ver_case_id', 'evidence_verifications', ['case_id'])
    op.create_index('ix_ev_ver_target_type', 'evidence_verifications', ['target_type'])
    op.create_index('ix_ev_ver_target_id', 'evidence_verifications', ['target_id'])
    op.create_index('ix_ev_ver_status', 'evidence_verifications', ['verification_status'])
    op.create_index('ix_ev_ver_hash', 'evidence_verifications', ['sha256_hash'])

    # 3. governance_audit_events table
    op.create_table(
        'governance_audit_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True),
        sa.Column('decision_id', sa.String(), sa.ForeignKey('governance_decisions.id', ondelete='CASCADE'), nullable=True),
        sa.Column('verification_id', sa.String(), sa.ForeignKey('evidence_verifications.id', ondelete='CASCADE'), nullable=True),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('actor', sa.String(), nullable=False),
        sa.Column('input_references', sa.JSON(), nullable=False),
        sa.Column('checks_performed', sa.JSON(), nullable=False),
        sa.Column('decision', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('approval_identity', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_event_hash', sa.String(length=64), nullable=True),
    )
    op.create_index('ix_gov_audit_case_id', 'governance_audit_events', ['case_id'])
    op.create_index('ix_gov_audit_decision_id', 'governance_audit_events', ['decision_id'])
    op.create_index('ix_gov_audit_event_type', 'governance_audit_events', ['event_type'])


def downgrade() -> None:
    op.drop_table('governance_audit_events')
    op.drop_table('evidence_verifications')
    op.drop_table('governance_decisions')
