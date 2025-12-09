"""add_rss_tables

Revision ID: 479b1e648500
Revises: 8ac66d253837
Create Date: 2025-11-14 20:55:19.261740+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision: str = '479b1e648500'
down_revision: Union[str, None] = '8ac66d253837'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # RSS Categories
    op.create_table(
        'rss_categories',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True, index=True),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('color', sa.String(7), nullable=True),
        sa.Column('icon', sa.String(50), nullable=True),
        sa.Column('sort_order', sa.Integer, default=0),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('idx_rss_categories_active', 'rss_categories', ['is_active', 'sort_order'])

    # RSS Sources
    op.create_table(
        'rss_sources',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False, index=True),
        sa.Column('url', sa.String(1000), nullable=False),
        sa.Column('category_id', UUID(as_uuid=True), sa.ForeignKey('rss_categories.id', ondelete='CASCADE'), nullable=False),
        sa.Column('refresh_interval_hours', sa.Integer, default=6, nullable=False),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('feed_title', sa.String(500), nullable=True),
        sa.Column('feed_link', sa.String(1000), nullable=True),
        sa.Column('last_collected_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_collection_status', sa.String(50), nullable=True),
        sa.Column('last_error_message', sa.Text, nullable=True),
        sa.Column('total_articles_collected', sa.Integer, default=0, nullable=False),
        sa.Column('extra_config', JSONB, nullable=True),
        sa.Column('created_by', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('idx_rss_sources_active_category', 'rss_sources', ['is_active', 'category_id'])
    op.create_index('idx_rss_sources_last_collected', 'rss_sources', ['last_collected_at'])

    # RSS Collection Runs
    op.create_table(
        'rss_collection_runs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('source_id', UUID(as_uuid=True), sa.ForeignKey('rss_sources.id', ondelete='CASCADE'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer, nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('articles_found', sa.Integer, default=0),
        sa.Column('articles_new', sa.Integer, default=0),
        sa.Column('articles_duplicate', sa.Integer, default=0),
        sa.Column('error_message', sa.Text, nullable=True),
        sa.Column('triggered_by', sa.String(50), nullable=True),
        sa.Column('executed_by', sa.String(100), nullable=True),
        sa.Column('feed_metadata', JSONB, nullable=True),
    )
    op.create_index('idx_rss_runs_source_started', 'rss_collection_runs', ['source_id', 'started_at'])
    op.create_index('idx_rss_runs_status', 'rss_collection_runs', ['status'])

    # RSS Settings (singleton table)
    op.create_table(
        'rss_settings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('scheduler_enabled', sa.Boolean, default=True, nullable=False),
        sa.Column('default_refresh_interval_hours', sa.Integer, default=6, nullable=False),
        sa.Column('scheduler_cron', sa.String(100), nullable=True),
        sa.Column('max_articles_per_feed', sa.Integer, default=100, nullable=False),
        sa.Column('days_to_keep_articles', sa.Integer, default=180, nullable=False),
        sa.Column('enable_deduplication', sa.Boolean, default=True, nullable=False),
        sa.Column('enable_nlp_enrichment', sa.Boolean, default=False, nullable=False),
        sa.Column('es_index_alias', sa.String(100), default='rss-articles', nullable=False),
        sa.Column('es_shards', sa.Integer, default=1, nullable=False),
        sa.Column('es_replicas', sa.Integer, default=1, nullable=False),
        sa.Column('notify_on_errors', sa.Boolean, default=True, nullable=False),
        sa.Column('notification_webhook', sa.String(1000), nullable=True),
        sa.Column('extra_config', JSONB, nullable=True),
        sa.Column('updated_by', sa.String(100), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Insert default settings
    op.execute("""
        INSERT INTO rss_settings (id, scheduler_enabled, default_refresh_interval_hours,
                                   max_articles_per_feed, days_to_keep_articles,
                                   enable_deduplication, enable_nlp_enrichment,
                                   es_index_alias, es_shards, es_replicas, notify_on_errors)
        VALUES (gen_random_uuid(), true, 6, 100, 180, true, false, 'rss-articles', 1, 1, true)
    """)


def downgrade() -> None:
    op.drop_table('rss_settings')
    op.drop_table('rss_collection_runs')
    op.drop_table('rss_sources')
    op.drop_table('rss_categories')
