"""add sso support

Revision ID: 20251112_1400
Revises: 20251111_1000
Create Date: 2025-11-12 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251112_1400'
down_revision = '20251111_1000'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Criar tabela sso_providers
    op.create_table(
        'sso_providers',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('provider_type', sa.String(50), nullable=False),  # 'entra_id', 'google', 'okta'

        # OAuth2/OIDC Config
        sa.Column('client_id', sa.String(255), nullable=False),
        sa.Column('client_secret_encrypted', sa.Text(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=True),  # Para Entra ID
        sa.Column('authority_url', sa.Text(), nullable=True),
        sa.Column('redirect_uri', sa.Text(), nullable=False),

        # Scopes
        sa.Column('scopes', sa.Text(), nullable=True),  # JSON array como string

        # Role Mapping
        sa.Column('role_mapping', postgresql.JSONB(), nullable=True),
        sa.Column('default_role', sa.String(50), server_default='reader'),

        # Settings
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('auto_provision', sa.Boolean(), server_default='true', nullable=False),

        # Metadata
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True), nullable=True),

        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
    )

    # Índices para sso_providers
    op.create_index('idx_sso_providers_type', 'sso_providers', ['provider_type'])
    op.create_index('idx_sso_providers_active', 'sso_providers', ['is_active'])

    # 2. Adicionar campos SSO na tabela users
    op.add_column('users', sa.Column('sso_provider_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('users', sa.Column('external_id', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('sso_email', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('last_sso_login', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_ad_sync', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('ad_account_enabled', sa.Boolean(), nullable=True))
    op.add_column('users', sa.Column('sync_status', sa.String(50), nullable=True))

    # Foreign key para sso_provider
    op.create_foreign_key(
        'fk_users_sso_provider',
        'users', 'sso_providers',
        ['sso_provider_id'], ['id'],
        ondelete='SET NULL'
    )

    # Índice único para external_id (evitar duplicatas)
    op.create_index(
        'idx_users_external_id_unique',
        'users',
        ['sso_provider_id', 'external_id'],
        unique=True,
        postgresql_where=sa.text('sso_provider_id IS NOT NULL AND external_id IS NOT NULL')
    )

    # Índices para queries de sincronização
    op.create_index('idx_users_sso_provider', 'users', ['sso_provider_id'])
    op.create_index('idx_users_external_id', 'users', ['external_id'])
    op.create_index('idx_users_last_ad_sync', 'users', ['last_ad_sync'])


def downgrade() -> None:
    # Remover índices de users
    op.drop_index('idx_users_last_ad_sync', 'users')
    op.drop_index('idx_users_external_id', 'users')
    op.drop_index('idx_users_sso_provider', 'users')
    op.drop_index('idx_users_external_id_unique', 'users')

    # Remover FK
    op.drop_constraint('fk_users_sso_provider', 'users', type_='foreignkey')

    # Remover colunas SSO de users
    op.drop_column('users', 'sync_status')
    op.drop_column('users', 'ad_account_enabled')
    op.drop_column('users', 'last_ad_sync')
    op.drop_column('users', 'last_sso_login')
    op.drop_column('users', 'sso_email')
    op.drop_column('users', 'external_id')
    op.drop_column('users', 'sso_provider_id')

    # Remover índices de sso_providers
    op.drop_index('idx_sso_providers_active', 'sso_providers')
    op.drop_index('idx_sso_providers_type', 'sso_providers')

    # Remover tabela sso_providers
    op.drop_table('sso_providers')
