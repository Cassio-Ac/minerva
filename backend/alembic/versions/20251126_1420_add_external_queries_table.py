"""Add external_queries table for Credentials module

Revision ID: 20251126_1420
Revises:
Create Date: 2025-11-26 14:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '20251126_1420'
down_revision: Union[str, None] = '20251124_0000'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Criar tabela external_queries se não existir
    op.execute("""
        CREATE TABLE IF NOT EXISTS external_queries (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            query_type VARCHAR(50) NOT NULL,
            query_value VARCHAR(500) NOT NULL,
            bot_id VARCHAR(50) NOT NULL,
            bot_name VARCHAR(100),
            found BOOLEAN DEFAULT FALSE,
            result_count INTEGER DEFAULT 0,
            result_preview TEXT,
            result_html_path VARCHAR(500),
            result_file_path VARCHAR(500),
            raw_response JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(100),
            telegram_account VARCHAR(100),
            status VARCHAR(20) DEFAULT 'pending',
            error_message TEXT
        )
    """)

    # Criar índices
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_external_queries_query_type
        ON external_queries(query_type)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_external_queries_created_at
        ON external_queries(created_at DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_external_queries_found
        ON external_queries(found)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS external_queries CASCADE")
