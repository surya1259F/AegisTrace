"""Initial Base Schema

Revision ID: 001_initial_base_schema
Revises: 
Create Date: 2026-09-19 14:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_base_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('organization', sa.String(), server_default='Digital Forensics Unit', nullable=False),
        sa.Column('badge_id', sa.String(), nullable=True),
        sa.Column('role', sa.String(), server_default='INVESTIGATOR', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)

    # 2. Cases
    op.create_table(
        'cases',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_number', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(), server_default='local-investigator', nullable=False),
        sa.Column('investigator', sa.String(), nullable=True),
        sa.Column('owner_id', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='ACTIVE', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cases_case_number'), 'cases', ['case_number'], unique=True)
    op.create_index(op.f('ix_cases_id'), 'cases', ['id'], unique=False)

    # 3. Case Members
    op.create_table(
        'case_members',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('role', sa.String(), server_default='ANALYSIS_LEAD', nullable=False),
        sa.Column('added_at', sa.DateTime(), nullable=True),
        sa.Column('assigned_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 4. Base Evidence Items
    op.create_table(
        'evidence_items',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('original_path', sa.String(), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=True),
        sa.Column('evidence_type', sa.String(), nullable=False),
        sa.Column('size_bytes', sa.Float(), nullable=False),
        sa.Column('sha256', sa.String(), nullable=False),
        sa.Column('md5', sa.String(), nullable=True),
        sa.Column('mime_type', sa.String(), nullable=True),
        sa.Column('intake_status', sa.String(), server_default='INTAKE_COMPLETE', nullable=False),
        sa.Column('integrity_status', sa.String(), server_default='VERIFIED', nullable=False),
        sa.Column('read_only_verified', sa.Boolean(), server_default=sa.text('1'), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('acquired_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('modified_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_items_id'), 'evidence_items', ['id'], unique=False)

    # 5. Chain of Custody Events
    op.create_table(
        'chain_of_custody_events',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=False),
        sa.Column('actor_id', sa.String(), nullable=False),
        sa.Column('actor', sa.String(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('source_path', sa.String(), nullable=True),
        sa.Column('destination_path', sa.String(), nullable=True),
        sa.Column('sha256', sa.String(), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('previous_event_hash', sa.String(), nullable=True),
        sa.Column('event_hash', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 6. Tool Definitions
    op.create_table(
        'tool_definitions',
        sa.Column('tool_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('executable_path', sa.String(), nullable=False),
        sa.Column('supported_evidence', sa.JSON(), nullable=True),
        sa.Column('capabilities_json', sa.JSON(), nullable=True),
        sa.Column('is_available', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('tool_id')
    )

    # 7. Tool Executions
    op.create_table(
        'tool_executions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=False),
        sa.Column('tool_id', sa.String(), nullable=False),
        sa.Column('command_args', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('stdout_path', sa.String(), nullable=True),
        sa.Column('stderr_path', sa.String(), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), nullable=True),
        sa.Column('operator_id', sa.String(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('process_start_time', sa.Float(), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(), nullable=True),
        sa.Column('cancelled_by', sa.String(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 8. Execution Artifacts
    op.create_table(
        'execution_artifacts',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=False),
        sa.Column('execution_id', sa.String(), nullable=True),
        sa.Column('agent', sa.String(), nullable=False),
        sa.Column('tool', sa.String(), nullable=False),
        sa.Column('artifact_type', sa.String(), nullable=False),
        sa.Column('source_reference', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=True),
        sa.Column('inode', sa.String(), nullable=True),
        sa.Column('size_bytes', sa.Float(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('raw_output_reference', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 9. Findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('execution_id', sa.String(), nullable=True),
        sa.Column('artifact_id', sa.String(), nullable=True),
        sa.Column('agent', sa.String(), nullable=False),
        sa.Column('tool', sa.String(), nullable=False),
        sa.Column('finding_type', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('classification', sa.String(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('evidence_reference', sa.String(), nullable=True),
        sa.Column('verification_status', sa.String(), nullable=False),
        sa.Column('raw_output_reference', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence_items.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 10. Correlation Groups
    op.create_table(
        'correlation_groups',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('dimension', sa.String(), nullable=False),
        sa.Column('rule', sa.String(), nullable=True),
        sa.Column('correlated_entity', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('tools_involved', sa.JSON(), nullable=True),
        sa.Column('supporting_finding_ids', sa.JSON(), nullable=True),
        sa.Column('supporting_artifact_ids', sa.JSON(), nullable=True),
        sa.Column('supporting_evidence_ids', sa.JSON(), nullable=True),
        sa.Column('correlation_confidence', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 11. Investigator Decisions
    op.create_table(
        'investigator_decisions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('investigator_id', sa.String(), nullable=True),
        sa.Column('investigator_name', sa.String(), nullable=False),
        sa.Column('decision', sa.String(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('finding_ids', sa.JSON(), nullable=True),
        sa.Column('evidence_ids', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 12. Investigation Plans
    op.create_table(
        'investigation_plans',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('strategy_summary', sa.Text(), nullable=True),
        sa.Column('tasks', sa.JSON(), nullable=True),
        sa.Column('objectives', sa.JSON(), nullable=True),
        sa.Column('scope_definition', sa.Text(), nullable=True),
        sa.Column('priority', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='PLANNED', nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 13. Reports
    op.create_table(
        'reports',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('decision_id', sa.String(), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('executive_summary', sa.Text(), nullable=False),
        sa.Column('findings_count', sa.Integer(), nullable=False),
        sa.Column('evidence_count', sa.Integer(), nullable=False),
        sa.Column('full_report_markdown', sa.Text(), nullable=False),
        sa.Column('report_hash', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('generated_by', sa.String(), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # 14. Audit Events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=True),
        sa.Column('actor_id', sa.String(), nullable=True),
        sa.Column('actor_name', sa.String(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('details', sa.Text(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_hash', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('reports')
    op.drop_table('investigation_plans')
    op.drop_table('investigator_decisions')
    op.drop_table('correlation_groups')
    op.drop_table('findings')
    op.drop_table('execution_artifacts')
    op.drop_table('tool_executions')
    op.drop_table('tool_definitions')
    op.drop_table('chain_of_custody_events')
    op.drop_table('evidence_items')
    op.drop_table('case_members')
    op.drop_table('cases')
    op.drop_table('users')

