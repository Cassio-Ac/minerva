"""add_misp_feeds_and_iocs_tables

Revision ID: 89c585eb75f3
Revises: 479b1e648500
Create Date: 2025-11-21 01:18:24.719234+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '89c585eb75f3'
down_revision: Union[str, None] = '479b1e648500'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create misp_feeds table
    op.create_table(
        'misp_feeds',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('feed_type', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_public', sa.Boolean(), nullable=True),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_iocs_imported', sa.Integer(), nullable=True),
        sa.Column('sync_frequency', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_misp_feeds_is_active'), 'misp_feeds', ['is_active'], unique=False)
    op.create_index(op.f('ix_misp_feeds_name'), 'misp_feeds', ['name'], unique=False)

    # Create misp_iocs table
    op.create_table(
        'misp_iocs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('feed_id', sa.UUID(), nullable=False),
        sa.Column('ioc_type', sa.String(), nullable=False),
        sa.Column('ioc_subtype', sa.String(), nullable=True),
        sa.Column('ioc_value', sa.Text(), nullable=False),
        sa.Column('context', sa.Text(), nullable=True),
        sa.Column('malware_family', sa.String(), nullable=True),
        sa.Column('threat_actor', sa.String(), nullable=True),
        sa.Column('tags', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tlp', sa.String(), nullable=True),
        sa.Column('confidence', sa.String(), nullable=True),
        sa.Column('to_ids', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['feed_id'], ['misp_feeds.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_misp_iocs_ioc_type'), 'misp_iocs', ['ioc_type'], unique=False)
    op.create_index(op.f('ix_misp_iocs_ioc_value'), 'misp_iocs', ['ioc_value'], unique=False)
    op.create_index(op.f('ix_misp_iocs_malware_family'), 'misp_iocs', ['malware_family'], unique=False)
    op.create_index(op.f('ix_misp_iocs_threat_actor'), 'misp_iocs', ['threat_actor'], unique=False)

    # Create unique constraint for deduplication
    op.create_index('idx_misp_iocs_unique', 'misp_iocs', ['ioc_value', 'feed_id'], unique=True)


def downgrade() -> None:
    op.drop_index('idx_misp_iocs_unique', table_name='misp_iocs')
    op.drop_index(op.f('ix_misp_iocs_threat_actor'), table_name='misp_iocs')
    op.drop_index(op.f('ix_misp_iocs_malware_family'), table_name='misp_iocs')
    op.drop_index(op.f('ix_misp_iocs_ioc_value'), table_name='misp_iocs')
    op.drop_index(op.f('ix_misp_iocs_ioc_type'), table_name='misp_iocs')
    op.drop_table('misp_iocs')
    op.drop_index(op.f('ix_misp_feeds_name'), table_name='misp_feeds')
    op.drop_index(op.f('ix_misp_feeds_is_active'), table_name='misp_feeds')
    op.drop_table('misp_feeds')
