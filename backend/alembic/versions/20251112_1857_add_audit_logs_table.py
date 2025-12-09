"""add_audit_logs_table

Revision ID: 68f59d5036f1
Revises: 20251112_1400
Create Date: 2025-11-12 18:57:18.612361+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON


# revision identifiers, used by Alembic.
revision: str = '68f59d5036f1'
down_revision: Union[str, None] = '20251112_1400'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('event_type', sa.String(50), nullable=False, comment='Tipo: sso_login, sso_login_failed, sso_provider_created, etc'),
        sa.Column('category', sa.String(20), nullable=False, comment='Categoria: authentication, configuration, user_management, sync'),
        sa.Column('severity', sa.String(20), nullable=False, server_default='info', comment='Severidade: info, warning, error, critical'),
        sa.Column('user_id', UUID(as_uuid=True), nullable=True, comment='Usuário que realizou a ação (NULL para eventos automáticos)'),
        sa.Column('target_user_id', UUID(as_uuid=True), nullable=True, comment='Usuário afetado pela ação'),
        sa.Column('sso_provider_id', UUID(as_uuid=True), nullable=True, comment='Provider SSO relacionado ao evento'),
        sa.Column('description', sa.Text(), nullable=False, comment='Descrição legível do evento'),
        sa.Column('event_metadata', JSON, nullable=True, comment='Dados adicionais: IP, user agent, detalhes do erro, etc'),
        sa.Column('ip_address', sa.String(45), nullable=True, comment='IP do cliente (IPv4 ou IPv6)'),
        sa.Column('user_agent', sa.String(500), nullable=True, comment='User Agent do browser'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()'), comment='Timestamp do evento'),

        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['sso_provider_id'], ['sso_providers.id'], ondelete='SET NULL'),
    )

    # Create indexes for performance
    op.create_index('idx_audit_event_type', 'audit_logs', ['event_type'])
    op.create_index('idx_audit_category', 'audit_logs', ['category'])
    op.create_index('idx_audit_user_id', 'audit_logs', ['user_id'])
    op.create_index('idx_audit_target_user_id', 'audit_logs', ['target_user_id'])
    op.create_index('idx_audit_sso_provider_id', 'audit_logs', ['sso_provider_id'])
    op.create_index('idx_audit_created_at', 'audit_logs', ['created_at'])
    op.create_index('idx_audit_severity', 'audit_logs', ['severity'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('idx_audit_severity', 'audit_logs')
    op.drop_index('idx_audit_created_at', 'audit_logs')
    op.drop_index('idx_audit_sso_provider_id', 'audit_logs')
    op.drop_index('idx_audit_target_user_id', 'audit_logs')
    op.drop_index('idx_audit_user_id', 'audit_logs')
    op.drop_index('idx_audit_category', 'audit_logs')
    op.drop_index('idx_audit_event_type', 'audit_logs')

    # Drop table
    op.drop_table('audit_logs')
