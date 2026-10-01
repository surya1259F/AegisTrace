"""Final Forensic Report Schema (Phase 2 / Step 20)

Revision ID: 019_final_forensic_report_schema
Revises: 018_investigator_review_schema
Create Date: 2026-09-27 11:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '019_final_forensic_report_schema'
down_revision: Union[str, None] = '018_investigator_review_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'reports' in tables:
        existing_cols = {c['name'] for c in insp.get_columns('reports')}

        # Add Step 20 Final Forensic Report columns safely
        if 'sections' not in existing_cols:
            op.add_column('reports', sa.Column('sections', sa.JSON(), nullable=True))
        if 'provenance' not in existing_cols:
            op.add_column('reports', sa.Column('provenance', sa.JSON(), nullable=True))
        if 'report_metadata' not in existing_cols:
            op.add_column('reports', sa.Column('report_metadata', sa.JSON(), nullable=True))
        if 'integrity_status' not in existing_cols:
            op.add_column('reports', sa.Column('integrity_status', sa.String(), nullable=True, server_default='VERIFIED'))
        if 'evidence_integrity_summary' not in existing_cols:
            op.add_column('reports', sa.Column('evidence_integrity_summary', sa.JSON(), nullable=True))
        if 'storage_path' not in existing_cols:
            op.add_column('reports', sa.Column('storage_path', sa.String(), nullable=True))
        if 'created_at' not in existing_cols:
            op.add_column('reports', sa.Column('created_at', sa.DateTime(), nullable=True))
        if 'updated_at' not in existing_cols:
            op.add_column('reports', sa.Column('updated_at', sa.DateTime(), nullable=True))

        # Check and add indexes
        existing_indexes = {ix['name'] for ix in insp.get_indexes('reports')}
        if 'ix_reports_version' not in existing_indexes:
            op.create_index('ix_reports_version', 'reports', ['version'])
        if 'ix_reports_report_hash' not in existing_indexes:
            op.create_index('ix_reports_report_hash', 'reports', ['report_hash'])
        if 'ix_reports_integrity_status' not in existing_indexes:
            op.create_index('ix_reports_integrity_status', 'reports', ['integrity_status'])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'reports' in tables:
        existing_cols = {c['name'] for c in insp.get_columns('reports')}
        # SQLite does not support drop_column directly in batch without copy,
        # but in standard alembic batch operations can be used.
        with op.batch_alter_table('reports') as batch_op:
            if 'ix_reports_integrity_status' in [ix['name'] for ix in insp.get_indexes('reports')]:
                batch_op.drop_index('ix_reports_integrity_status')
            if 'ix_reports_report_hash' in [ix['name'] for ix in insp.get_indexes('reports')]:
                batch_op.drop_index('ix_reports_report_hash')
            if 'ix_reports_version' in [ix['name'] for ix in insp.get_indexes('reports')]:
                batch_op.drop_index('ix_reports_version')

            for col in [
                'sections',
                'provenance',
                'report_metadata',
                'integrity_status',
                'evidence_integrity_summary',
                'storage_path',
                'created_at',
                'updated_at'
            ]:
                if col in existing_cols:
                    batch_op.drop_column(col)
