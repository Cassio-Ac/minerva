"""add_otx_api_keys_table

Revision ID: a4d5f6a2a444
Revises: 6847286b8ed4
Create Date: 2025-11-22 16:12:06.972727+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4d5f6a2a444'
down_revision: Union[str, None] = '6847286b8ed4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create otx_api_keys table
    op.create_table(
        'otx_api_keys',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('api_key', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('requests_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('requests_today', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_request_at', sa.DateTime(), nullable=True),
        sa.Column('last_error_at', sa.DateTime(), nullable=True),
        sa.Column('error_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('daily_limit', sa.Integer(), nullable=False, server_default='9000'),
        sa.Column('current_usage', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_health_check', sa.DateTime(), nullable=True),
        sa.Column('health_status', sa.String(50), nullable=True, server_default='unknown'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('api_key')
    )

    # Create indexes
    op.create_index('ix_otx_api_keys_is_active', 'otx_api_keys', ['is_active'])

    # Insert initial key (provided by user)
    op.execute("""
        INSERT INTO otx_api_keys (
            id, name, api_key, description, is_active, is_primary, daily_limit
        ) VALUES (
            gen_random_uuid(),
            'Production Key 1',
            '2080ce1b2515cbfe5bab804175fb1ca96f11a52cbc61b718ef34f12ec1b4bac5',
            'Primary OTX API key for production use',
            true,
            true,
            9000
        )
    """)


def downgrade() -> None:
    op.drop_index('ix_otx_api_keys_is_active', 'otx_api_keys')
    op.drop_table('otx_api_keys')
