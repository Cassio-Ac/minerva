"""Deprecate IOC data tables - move to Elasticsearch

Revision ID: 20251210_1500
Revises: 20251126_1420
Create Date: 2025-12-10 15:00:00.000000

This migration removes IOC data tables from PostgreSQL as part of the
architecture change to store all intel data directly in Elasticsearch.

Tables removed:
- misp_iocs (data moved to unified_iocs ES index)
- otx_pulses (data moved to unified_iocs ES index)
- otx_pulse_indicators (data moved to unified_iocs ES index)

Tables kept (configs only):
- misp_feeds (feed configuration)
- otx_api_keys (API key management)
- otx_sync_history (sync history)

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '20251210_1500'
down_revision: Union[str, None] = '20251126_1420'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop misp_iocs table (data now in Elasticsearch unified_iocs)
    op.execute("DROP TABLE IF EXISTS misp_iocs CASCADE")

    # Drop otx_pulse_indicators table (data now in Elasticsearch unified_iocs)
    op.execute("DROP TABLE IF EXISTS otx_pulse_indicators CASCADE")

    # Drop otx_pulses table (data now in Elasticsearch unified_iocs)
    op.execute("DROP TABLE IF EXISTS otx_pulses CASCADE")

    # Note: misp_feeds, otx_api_keys, otx_sync_history are KEPT
    # They store configuration data, not intel data


def downgrade() -> None:
    # Recreate misp_iocs table
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
    op.create_index('ix_misp_iocs_ioc_type', 'misp_iocs', ['ioc_type'], unique=False)
    op.create_index('ix_misp_iocs_ioc_value', 'misp_iocs', ['ioc_value'], unique=False)
    op.create_index('ix_misp_iocs_malware_family', 'misp_iocs', ['malware_family'], unique=False)
    op.create_index('ix_misp_iocs_threat_actor', 'misp_iocs', ['threat_actor'], unique=False)
    op.create_index('idx_misp_iocs_unique', 'misp_iocs', ['ioc_value', 'feed_id'], unique=True)

    # Recreate otx_pulses table
    op.create_table(
        'otx_pulses',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('pulse_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('author_name', sa.String(), nullable=True),
        sa.Column('created', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revision', sa.Integer(), nullable=True),
        sa.Column('tlp', sa.String(), nullable=True),
        sa.Column('adversary', sa.String(), nullable=True),
        sa.Column('targeted_countries', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('industries', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('tags', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('references', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('indicator_count', sa.Integer(), nullable=True),
        sa.Column('attack_ids', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('malware_families', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('raw_data', postgresql.JSONB(), nullable=True),
        sa.Column('synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('synced_by_key_id', sa.UUID(), nullable=True),
        sa.Column('exported_to_misp', sa.Boolean(), nullable=True),
        sa.Column('misp_event_uuid', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_otx_pulses_pulse_id', 'otx_pulses', ['pulse_id'], unique=True)
    op.create_index('ix_otx_pulses_adversary', 'otx_pulses', ['adversary'], unique=False)
    op.create_index('ix_otx_pulses_synced_at', 'otx_pulses', ['synced_at'], unique=False)

    # Recreate otx_pulse_indicators table
    op.create_table(
        'otx_pulse_indicators',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('pulse_id', sa.UUID(), nullable=False),
        sa.Column('indicator', sa.Text(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('role', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['pulse_id'], ['otx_pulses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_otx_indicators_indicator', 'otx_pulse_indicators', ['indicator'], unique=False)
    op.create_index('ix_otx_indicators_type', 'otx_pulse_indicators', ['type'], unique=False)
    op.create_index('idx_otx_indicators_unique', 'otx_pulse_indicators', ['pulse_id', 'indicator'], unique=True)
