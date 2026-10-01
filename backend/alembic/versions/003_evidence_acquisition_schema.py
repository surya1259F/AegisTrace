"""Evidence Acquisition Subsystem Schema

Revision ID: 003_evidence_acquisition_schema
Revises: 002_evidence_intelligence_schema
Create Date: 2026-09-25 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_evidence_acquisition_schema'
down_revision: Union[str, None] = '002_evidence_intelligence_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create evidence_acquisitions table
    op.create_table(
        'evidence_acquisitions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('case_id', sa.String(), nullable=False),
        sa.Column('acquisition_type', sa.String(), nullable=False),
        sa.Column('source_path', sa.String(), nullable=False),
        sa.Column('total_files', sa.Integer(), server_default='1', nullable=False),
        sa.Column('total_bytes', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('successful_files', sa.Integer(), server_default='0', nullable=False),
        sa.Column('failed_files', sa.Integer(), server_default='0', nullable=False),
        sa.Column('manifest_hash', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='IN_PROGRESS', nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_by_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_acquisitions_case_id'), 'evidence_acquisitions', ['case_id'], unique=False)
    op.create_index(op.f('ix_evidence_acquisitions_created_by_id'), 'evidence_acquisitions', ['created_by_id'], unique=False)
    op.create_index(op.f('ix_evidence_acquisitions_status'), 'evidence_acquisitions', ['status'], unique=False)

    # 2. Add parent_acquisition_id to evidence_items table
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_acquisition_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_evidence_items_parent_acquisition_id'), ['parent_acquisition_id'], unique=False)
        batch_op.create_foreign_key('fk_evidence_items_parent_acquisition_id', 'evidence_acquisitions', ['parent_acquisition_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.drop_constraint('fk_evidence_items_parent_acquisition_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_evidence_items_parent_acquisition_id'))
        batch_op.drop_column('parent_acquisition_id')

    op.drop_index(op.f('ix_evidence_acquisitions_status'), table_name='evidence_acquisitions')
    op.drop_index(op.f('ix_evidence_acquisitions_created_by_id'), table_name='evidence_acquisitions')
    op.drop_index(op.f('ix_evidence_acquisitions_case_id'), table_name='evidence_acquisitions')
    op.drop_table('evidence_acquisitions')

