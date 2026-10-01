"""Token Revocation Persistence Schema

Revision ID: 021_token_revocation_persistence_schema
Revises: 020_orchestration_audit_recovery_schema
Create Date: 2026-10-01 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '021_token_revocation_persistence_schema'
down_revision: Union[str, None] = '020_orchestration_audit_recovery_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'revoked_tokens' not in tables:
        op.create_table(
            'revoked_tokens',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('jti', sa.String(64), unique=True, nullable=False),
            sa.Column('revoked_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_revoked_tokens_jti', 'revoked_tokens', ['jti'])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    if 'revoked_tokens' in tables:
        op.drop_table('revoked_tokens')
