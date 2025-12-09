"""add index MCP configuration table

Revision ID: 20251110_1500
Revises: 20251110_1445
Create Date: 2025-11-10 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251110_1500'
down_revision = '6a320382c619'  # merge_heads
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema"""

    # Create index_mcp_config table
    op.create_table(
        'index_mcp_config',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('es_server_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('index_name', sa.String(255), nullable=False, index=True),
        sa.Column('mcp_server_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('auto_inject_context', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('config', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['es_server_id'], ['es_servers.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['mcp_server_id'], ['mcp_servers.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
    )

    # Create unique constraint (one config per index + MCP server combination)
    op.create_index(
        'ix_index_mcp_unique',
        'index_mcp_config',
        ['es_server_id', 'index_name', 'mcp_server_id'],
        unique=True
    )

    # Single-column indexes already created via index=True in column definitions
    # Only need the priority index since that column doesn't have index=True
    op.create_index('ix_index_mcp_config_priority', 'index_mcp_config', ['priority'])


def downgrade() -> None:
    """Downgrade database schema"""

    # Drop indexes
    op.drop_index('ix_index_mcp_config_priority', 'index_mcp_config')
    op.drop_index('ix_index_mcp_config_mcp_server_id', 'index_mcp_config')
    op.drop_index('ix_index_mcp_config_index_name', 'index_mcp_config')
    op.drop_index('ix_index_mcp_config_es_server_id', 'index_mcp_config')
    op.drop_index('ix_index_mcp_unique', 'index_mcp_config')

    # Drop table
    op.drop_table('index_mcp_config')
