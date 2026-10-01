"""Evidence Acquisition & Evidence Intelligence Schema

Revision ID: 002_evidence_intelligence_schema
Revises: 001_initial_base_schema
Create Date: 2026-09-19 14:21:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_evidence_intelligence_schema'
down_revision: Union[str, None] = '001_initial_base_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('evidence_subtype', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('source_kind', sa.String(), server_default='FILE', nullable=True))
        batch_op.add_column(sa.Column('acquisition_method', sa.String(), server_default='INVESTIGATOR_IMPORT', nullable=True))
        batch_op.add_column(sa.Column('detected_format', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('filesystem_type', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('platform_hint', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(), server_default='REGISTERED', nullable=True))
        batch_op.add_column(sa.Column('metadata_json', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('intelligence_json', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('error_message', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.drop_column('error_message')
        batch_op.drop_column('intelligence_json')
        batch_op.drop_column('metadata_json')
        batch_op.drop_column('status')
        batch_op.drop_column('platform_hint')
        batch_op.drop_column('filesystem_type')
        batch_op.drop_column('detected_format')
        batch_op.drop_column('acquisition_method')
        batch_op.drop_column('source_kind')
        batch_op.drop_column('evidence_subtype')

