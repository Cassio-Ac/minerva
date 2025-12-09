"""add system metrics table

Revision ID: 20251110_1730
Revises: 20251110_1500
Create Date: 2025-11-10 17:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251110_1730'
down_revision = '20251110_1500'  # points to add_index_mcp_config
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Criar tabela system_metrics
    op.create_table(
        'system_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('metric_type', sa.String(50), nullable=False, index=True),
        sa.Column('metric_name', sa.String(100), nullable=False, index=True),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('unit', sa.String(20), nullable=True),
        sa.Column('labels', postgresql.JSONB(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True, server_default=sa.text('now()')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )

    # Criar índice composto para queries mais eficientes
    op.create_index(
        'idx_system_metrics_type_name_timestamp',
        'system_metrics',
        ['metric_type', 'metric_name', 'timestamp']
    )


def downgrade() -> None:
    op.drop_index('idx_system_metrics_type_name_timestamp', table_name='system_metrics')
    op.drop_table('system_metrics')
