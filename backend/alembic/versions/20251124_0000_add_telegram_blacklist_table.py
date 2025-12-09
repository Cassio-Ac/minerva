"""add telegram blacklist table

Revision ID: 20251124_0000
Revises: ea1cc794c2ad
Create Date: 2025-11-24 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = '20251124_0000'
down_revision = 'ea1cc794c2ad'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'telegram_message_blacklist',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('pattern', sa.String(500), nullable=False, comment='String pattern to filter from search results'),
        sa.Column('description', sa.String(1000), nullable=True, comment='Description of why this pattern is blacklisted'),
        sa.Column('is_regex', sa.Boolean(), default=False, nullable=False, comment='Whether the pattern is a regular expression'),
        sa.Column('case_sensitive', sa.Boolean(), default=False, nullable=False, comment='Whether matching should be case sensitive'),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False, comment='Whether this filter is active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.Column('created_by', UUID(as_uuid=True), nullable=True, comment='User who created this filter'),
    )

    # Create index for faster lookups
    op.create_index('ix_telegram_blacklist_pattern', 'telegram_message_blacklist', ['pattern'])
    op.create_index('ix_telegram_blacklist_is_active', 'telegram_message_blacklist', ['is_active'])


def downgrade():
    op.drop_index('ix_telegram_blacklist_is_active', table_name='telegram_message_blacklist')
    op.drop_index('ix_telegram_blacklist_pattern', table_name='telegram_message_blacklist')
    op.drop_table('telegram_message_blacklist')
