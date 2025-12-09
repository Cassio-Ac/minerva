"""add_otx_pulses_tables

Revision ID: ea1cc794c2ad
Revises: a4d5f6a2a444
Create Date: 2025-11-22 16:35:20.831936+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ea1cc794c2ad'
down_revision: Union[str, None] = 'a4d5f6a2a444'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create otx_pulses table
    op.create_table(
        'otx_pulses',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('pulse_id', sa.String(100), nullable=False),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('author_name', sa.String(200)),

        # Pulse metadata
        sa.Column('created', sa.DateTime()),
        sa.Column('modified', sa.DateTime()),
        sa.Column('revision', sa.Integer(), server_default='1'),

        # Threat info
        sa.Column('tlp', sa.String(20)),
        sa.Column('adversary', sa.String(200)),
        sa.Column('targeted_countries', sa.ARRAY(sa.String()), server_default='{}'),
        sa.Column('industries', sa.ARRAY(sa.String()), server_default='{}'),
        sa.Column('tags', sa.ARRAY(sa.String()), server_default='{}'),
        sa.Column('references', sa.ARRAY(sa.String()), server_default='{}'),

        # Indicators count
        sa.Column('indicator_count', sa.Integer(), server_default='0'),

        # Attack patterns
        sa.Column('attack_ids', sa.ARRAY(sa.String()), server_default='{}'),
        sa.Column('malware_families', sa.ARRAY(sa.String()), server_default='{}'),

        # Raw data
        sa.Column('raw_data', sa.JSON()),

        # Sync metadata
        sa.Column('synced_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('synced_by_key_id', sa.UUID(), sa.ForeignKey('otx_api_keys.id')),

        # MISP integration
        sa.Column('exported_to_misp', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('misp_event_id', sa.String(100)),
        sa.Column('exported_to_misp_at', sa.DateTime()),

        # Status
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),

        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('pulse_id')
    )

    # Indexes for otx_pulses
    op.create_index('ix_otx_pulses_pulse_id', 'otx_pulses', ['pulse_id'])
    op.create_index('ix_otx_pulses_is_active', 'otx_pulses', ['is_active'])
    op.create_index('ix_otx_pulses_created', 'otx_pulses', ['created'])
    op.create_index('ix_otx_pulses_synced_at', 'otx_pulses', ['synced_at'])
    op.create_index('ix_otx_pulses_exported_to_misp', 'otx_pulses', ['exported_to_misp'])
    op.create_index('ix_otx_pulses_tags', 'otx_pulses', ['tags'], postgresql_using='gin')
    op.create_index('ix_otx_pulses_attack_ids', 'otx_pulses', ['attack_ids'], postgresql_using='gin')

    # Create otx_pulse_indicators table
    op.create_table(
        'otx_pulse_indicators',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('pulse_id', sa.UUID(), sa.ForeignKey('otx_pulses.id', ondelete='CASCADE'), nullable=False),

        # Indicator data
        sa.Column('indicator', sa.String(500), nullable=False),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('title', sa.String(500)),
        sa.Column('description', sa.Text()),

        # Context
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('role', sa.String(50)),

        # Enrichment data
        sa.Column('otx_enrichment', sa.JSON()),
        sa.Column('enriched_at', sa.DateTime()),

        # MISP integration
        sa.Column('exported_to_misp', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('misp_attribute_id', sa.String(100)),

        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for otx_pulse_indicators
    op.create_index('ix_otx_pulse_indicators_pulse_id', 'otx_pulse_indicators', ['pulse_id'])
    op.create_index('ix_otx_pulse_indicators_indicator', 'otx_pulse_indicators', ['indicator'])
    op.create_index('ix_otx_pulse_indicators_type', 'otx_pulse_indicators', ['type'])
    op.create_index('ix_otx_pulse_indicators_type_indicator', 'otx_pulse_indicators', ['type', 'indicator'])
    op.create_index('ix_otx_pulse_indicators_enriched', 'otx_pulse_indicators', ['enriched_at'])

    # Create otx_sync_history table
    op.create_table(
        'otx_sync_history',
        sa.Column('id', sa.UUID(), nullable=False),

        # Sync metadata
        sa.Column('sync_type', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('completed_at', sa.DateTime()),

        # Stats
        sa.Column('pulses_fetched', sa.Integer(), server_default='0'),
        sa.Column('pulses_new', sa.Integer(), server_default='0'),
        sa.Column('pulses_updated', sa.Integer(), server_default='0'),
        sa.Column('indicators_processed', sa.Integer(), server_default='0'),
        sa.Column('indicators_enriched', sa.Integer(), server_default='0'),

        # Status
        sa.Column('status', sa.String(20), nullable=False, server_default='running'),
        sa.Column('error_message', sa.Text()),

        # Key used
        sa.Column('api_key_id', sa.UUID(), sa.ForeignKey('otx_api_keys.id')),

        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for otx_sync_history
    op.create_index('ix_otx_sync_history_started_at', 'otx_sync_history', ['started_at'])


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('otx_sync_history')
    op.drop_table('otx_pulse_indicators')
    op.drop_table('otx_pulses')
