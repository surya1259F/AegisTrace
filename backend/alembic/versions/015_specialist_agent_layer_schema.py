"""Specialist Agent Layer Schema (Phase 2 / Step 16)

Revision ID: 015_specialist_agent_layer_schema
Revises: 014_deterministic_findings_schema
Create Date: 2026-09-26 17:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '015_specialist_agent_layer_schema'
down_revision: Union[str, None] = '014_deterministic_findings_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. specialist_agents table
    op.create_table(
        'specialist_agents',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('version', sa.String(), server_default='1.0.0', nullable=False),
        sa.Column('agent_type', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('supported_evidence_domains', sa.JSON(), nullable=False),
        sa.Column('supported_artifact_types', sa.JSON(), nullable=False),
        sa.Column('supported_analysis_capabilities', sa.JSON(), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), server_default=sa.text('1'), nullable=False),
        sa.Column('status', sa.String(), server_default='REGISTERED', nullable=False),
        sa.Column('safety_permission_profile', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_specialist_agents_name', 'specialist_agents', ['name'], unique=True)
    op.create_index('ix_specialist_agents_agent_type', 'specialist_agents', ['agent_type'])

    # 2. agent_analysis_requests table
    op.create_table(
        'agent_analysis_requests',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_id', sa.String(), sa.ForeignKey('specialist_agents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_version', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('analysis_objective', sa.Text(), nullable=False),
        sa.Column('lifecycle_state', sa.String(), server_default='REGISTERED', nullable=False),
        sa.Column('input_references', sa.JSON(), nullable=False),
        sa.Column('requested_capabilities', sa.JSON(), nullable=False),
        sa.Column('results_summary', sa.JSON(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_agent_analysis_requests_case_id', 'agent_analysis_requests', ['case_id'])
    op.create_index('ix_agent_analysis_requests_agent_id', 'agent_analysis_requests', ['agent_id'])
    op.create_index('ix_agent_analysis_requests_evidence_id', 'agent_analysis_requests', ['evidence_id'])
    op.create_index('ix_agent_analysis_requests_lifecycle_state', 'agent_analysis_requests', ['lifecycle_state'])
    op.create_index('ix_agent_analysis_requests_sha256_hash', 'agent_analysis_requests', ['sha256_hash'])

    # 3. agent_analysis_results table
    op.create_table(
        'agent_analysis_results',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('request_id', sa.String(), sa.ForeignKey('agent_analysis_requests.id', ondelete='CASCADE'), nullable=False),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('agent_version', sa.String(), nullable=False),
        sa.Column('analysis_type', sa.String(), nullable=False),
        sa.Column('observations', sa.JSON(), nullable=False),
        sa.Column('capability_requests', sa.JSON(), nullable=False),
        sa.Column('supporting_evidence_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_artifact_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_correlation_ids', sa.JSON(), nullable=False),
        sa.Column('supporting_finding_ids', sa.JSON(), nullable=False),
        sa.Column('confidence_inputs', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_agent_analysis_results_request_id', 'agent_analysis_results', ['request_id'])
    op.create_index('ix_agent_analysis_results_case_id', 'agent_analysis_results', ['case_id'])
    op.create_index('ix_agent_analysis_results_agent_id', 'agent_analysis_results', ['agent_id'])
    op.create_index('ix_agent_analysis_results_analysis_type', 'agent_analysis_results', ['analysis_type'])
    op.create_index('ix_agent_analysis_results_sha256_hash', 'agent_analysis_results', ['sha256_hash'])

    # 4. agent_capability_requests table
    op.create_table(
        'agent_capability_requests',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('request_id', sa.String(), sa.ForeignKey('agent_analysis_requests.id', ondelete='CASCADE'), nullable=False),
        sa.Column('capability_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='1', nullable=False),
        sa.Column('validation_status', sa.String(), server_default='PENDING', nullable=False),
        sa.Column('validation_error', sa.Text(), nullable=True),
        sa.Column('execution_id', sa.String(), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_agent_capability_requests_case_id', 'agent_capability_requests', ['case_id'])
    op.create_index('ix_agent_capability_requests_agent_id', 'agent_capability_requests', ['agent_id'])
    op.create_index('ix_agent_capability_requests_request_id', 'agent_capability_requests', ['request_id'])
    op.create_index('ix_agent_capability_requests_capability_id', 'agent_capability_requests', ['capability_id'])
    op.create_index('ix_agent_capability_requests_evidence_id', 'agent_capability_requests', ['evidence_id'])
    op.create_index('ix_agent_capability_requests_validation_status', 'agent_capability_requests', ['validation_status'])
    op.create_index('ix_agent_capability_requests_sha256_hash', 'agent_capability_requests', ['sha256_hash'])

    # 5. agent_lifecycle_events table
    op.create_table(
        'agent_lifecycle_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_id', sa.String(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('request_id', sa.String(), sa.ForeignKey('agent_analysis_requests.id', ondelete='CASCADE'), nullable=True),
        sa.Column('from_state', sa.String(), nullable=False),
        sa.Column('to_state', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_agent_lifecycle_events_case_id', 'agent_lifecycle_events', ['case_id'])
    op.create_index('ix_agent_lifecycle_events_agent_id', 'agent_lifecycle_events', ['agent_id'])
    op.create_index('ix_agent_lifecycle_events_request_id', 'agent_lifecycle_events', ['request_id'])


def downgrade() -> None:
    op.drop_table('agent_lifecycle_events')
    op.drop_table('agent_capability_requests')
    op.drop_table('agent_analysis_results')
    op.drop_table('agent_analysis_requests')
    op.drop_table('specialist_agents')
