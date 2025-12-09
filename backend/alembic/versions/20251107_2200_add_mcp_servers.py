"""add mcp servers table

Revision ID: 003_mcp_servers
Revises: 002_llm_providers
Create Date: 2025-11-07 22:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_mcp_servers'
down_revision = '002_llm_providers'
branch_labels = None
depends_on = None


def upgrade():
    """Create mcp_servers table"""
    op.create_table(
        'mcp_servers',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),  # 'stdio', 'http', or 'sse'
        sa.Column('command', sa.String(), nullable=True),
        sa.Column('args', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('env', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('url', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mcp_servers_id'), 'mcp_servers', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_servers_name'), 'mcp_servers', ['name'], unique=True)


def downgrade():
    """Drop mcp_servers table"""
    op.drop_index(op.f('ix_mcp_servers_name'), table_name='mcp_servers')
    op.drop_index(op.f('ix_mcp_servers_id'), table_name='mcp_servers')
    op.drop_table('mcp_servers')
