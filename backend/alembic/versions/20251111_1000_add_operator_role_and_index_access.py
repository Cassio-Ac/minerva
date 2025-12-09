"""add operator role and index access control

Revision ID: 20251111_1000
Revises: 20251110_1730
Create Date: 2025-11-11 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251111_1000'
down_revision = '20251110_1730'  # points to add_system_metrics
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema"""

    # 1. Adicionar novo role OPERATOR ao enum UserRole
    op.execute("ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'operator'")

    # 2. Adicionar campo assigned_es_server_id na tabela users
    op.add_column(
        'users',
        sa.Column('assigned_es_server_id', postgresql.UUID(as_uuid=True), nullable=True)
    )

    # 3. Criar tabela user_index_accesses
    op.create_table(
        'user_index_accesses',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('es_server_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('index_name', sa.String(255), nullable=False, index=True),
        sa.Column('can_read', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('can_write', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('can_create', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
    )

    # 4. Criar unique constraint para evitar duplicatas
    op.create_index(
        'uix_user_server_index',
        'user_index_accesses',
        ['user_id', 'es_server_id', 'index_name'],
        unique=True
    )

    # Single-column indexes already created via index=True in column definitions above


def downgrade() -> None:
    """Downgrade database schema"""

    # 1. Remover índices
    op.drop_index('ix_user_index_accesses_index_name', table_name='user_index_accesses')
    op.drop_index('ix_user_index_accesses_es_server_id', table_name='user_index_accesses')
    op.drop_index('ix_user_index_accesses_user_id', table_name='user_index_accesses')
    op.drop_index('uix_user_server_index', table_name='user_index_accesses')

    # 2. Remover tabela
    op.drop_table('user_index_accesses')

    # 3. Remover campo da tabela users
    op.drop_column('users', 'assigned_es_server_id')

    # 4. Remover role OPERATOR do enum
    # NOTA: Remover valores de um enum no PostgreSQL é complexo e pode causar problemas
    # se já existirem usuários com este role. Por segurança, vamos deixar o valor no enum.
    # Se necessário fazer rollback completo, será preciso migração manual.
    pass
