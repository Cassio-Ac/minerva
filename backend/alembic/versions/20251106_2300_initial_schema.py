"""Initial schema - dashboards, conversations, es_servers

Revision ID: 001_initial
Revises:
Create Date: 2025-11-06 23:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create es_servers table
    op.create_table(
        'es_servers',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('username', sa.String(100), nullable=True),
        sa.Column('password_encrypted', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_es_servers_name', 'es_servers', ['name'], unique=True)
    op.create_index('ix_es_servers_is_active', 'es_servers', ['is_active'])
    op.create_index('idx_es_servers_active_name', 'es_servers', ['is_active', 'name'])

    # Create dashboards table
    op.create_table(
        'dashboards',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('index', sa.String(255), nullable=False),
        sa.Column('server_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('es_servers.id', ondelete='SET NULL'), nullable=True),
        sa.Column('layout', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('widgets', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('is_public', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('version', sa.String(20), nullable=False, server_default='1.0.0'),
        sa.Column('created_by', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_dashboards_title', 'dashboards', ['title'])
    op.create_index('ix_dashboards_index', 'dashboards', ['index'])
    op.create_index('ix_dashboards_is_public', 'dashboards', ['is_public'])
    op.create_index('ix_dashboards_created_by', 'dashboards', ['created_by'])
    op.create_index('idx_dashboards_index_active', 'dashboards', ['index', 'is_public'])
    op.create_index('idx_dashboards_updated_at', 'dashboards', ['updated_at'])

    # Create conversations table
    op.create_table(
        'conversations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('index', sa.String(255), nullable=False),
        sa.Column('server_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('es_servers.id', ondelete='SET NULL'), nullable=True),
        sa.Column('messages', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('created_by', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_conversations_title', 'conversations', ['title'])
    op.create_index('ix_conversations_index', 'conversations', ['index'])
    op.create_index('ix_conversations_created_by', 'conversations', ['created_by'])
    op.create_index('idx_conversations_updated_at', 'conversations', ['updated_at'])

    # Users table will be created in migration 20251110_0100


def downgrade() -> None:
    # users table dropped in migration 20251110_0100
    op.drop_table('conversations')
    op.drop_table('dashboards')
    op.drop_table('es_servers')
