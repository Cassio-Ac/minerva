"""make_index_optional_and_created_by_required_in_conversations

Revision ID: 52b0d7511db7
Revises: 004_knowledge_system
Create Date: 2025-11-09 19:50:55.153805+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '52b0d7511db7'
down_revision: Union[str, None] = '004_knowledge_system'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Mudanças para tornar conversas user-based:
    1. Tornar campo 'index' opcional (pode ser NULL)
    2. Tornar campo 'created_by' obrigatório (NOT NULL)
    3. Atualizar registros existentes com user_id padrão
    """
    # Primeiro, atualizar registros existentes que têm created_by NULL
    # Definir um user_id padrão para conversas antigas
    op.execute(
        "UPDATE conversations SET created_by = 'legacy_user' WHERE created_by IS NULL"
    )

    # Agora podemos tornar created_by NOT NULL
    op.alter_column('conversations', 'created_by',
                    existing_type=sa.String(length=100),
                    nullable=False)

    # Tornar index opcional (pode ser NULL)
    op.alter_column('conversations', 'index',
                    existing_type=sa.String(length=255),
                    nullable=True)


def downgrade() -> None:
    """
    Reverter mudanças:
    1. Tornar 'index' obrigatório novamente
    2. Tornar 'created_by' opcional
    """
    # Antes de tornar index NOT NULL, precisamos garantir que nenhum registro tenha NULL
    op.execute(
        "UPDATE conversations SET index = 'unknown' WHERE index IS NULL"
    )

    # Tornar index obrigatório
    op.alter_column('conversations', 'index',
                    existing_type=sa.String(length=255),
                    nullable=False)

    # Tornar created_by opcional
    op.alter_column('conversations', 'created_by',
                    existing_type=sa.String(length=100),
                    nullable=True)
