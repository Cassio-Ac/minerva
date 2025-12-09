"""add users and dashboard permissions tables

Revision ID: 20251110_0100
Revises: 004_knowledge_system
Create Date: 2025-11-10 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251110_0100'
down_revision = '004_knowledge_system'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema"""

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('username', sa.String(50), nullable=False, unique=True, index=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('role', postgresql.ENUM('admin', 'power', 'reader', name='userrole', create_type=True), nullable=False, server_default='reader'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('preferences', sa.String(), nullable=True),
    )

    # Create dashboard_permissions table
    op.create_table(
        'dashboard_permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('dashboard_id', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('visibility', postgresql.ENUM('private', 'public', 'shared', name='dashboardvisibility', create_type=True), nullable=False, server_default='private'),
        sa.Column('allow_edit_by_others', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('allow_copy', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    )

    # Create dashboard_shares table
    op.create_table(
        'dashboard_shares',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('can_edit', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.ForeignKeyConstraint(['permission_id'], ['dashboard_permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )

    # Indexes already created automatically via index=True in column definitions above

    # ==================== GROUPS TABLES ====================

    # Create groups table
    op.create_table(
        'groups',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True, index=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
    )

    # Create user_groups (many-to-many: users <-> groups)
    op.create_table(
        'user_groups',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('user_id', 'group_id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
    )

    # Create group_dashboard_permissions (many-to-many: groups <-> dashboards)
    op.create_table(
        'group_dashboard_permissions',
        sa.Column('group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('dashboard_id', sa.String(255), nullable=False),
        sa.Column('can_view', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('can_edit', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('can_delete', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('group_id', 'dashboard_id'),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
    )

    # Create indexes for groups
    op.create_index('ix_user_groups_user_id', 'user_groups', ['user_id'])
    op.create_index('ix_user_groups_group_id', 'user_groups', ['group_id'])
    op.create_index('ix_group_dashboard_permissions_group_id', 'group_dashboard_permissions', ['group_id'])
    op.create_index('ix_group_dashboard_permissions_dashboard_id', 'group_dashboard_permissions', ['dashboard_id'])

    # Insert default admin user
    # Password: admin123 (hashed with bcrypt)
    # bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    op.execute("""
        INSERT INTO users (id, username, email, hashed_password, full_name, role, is_active, is_superuser)
        VALUES (
            gen_random_uuid(),
            'admin',
            'admin@dashboard-ai.local',
            '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5lW7aW.WX2Kfi',
            'Administrator',
            'admin',
            true,
            true
        )
        ON CONFLICT (username) DO NOTHING;
    """)

    # Insert default system groups
    op.execute("""
        INSERT INTO groups (id, name, description, is_system, is_active)
        VALUES
            (gen_random_uuid(), 'Administradores', 'Grupo de administradores do sistema', true, true),
            (gen_random_uuid(), 'Analistas', 'Grupo de analistas com acesso ao LLM', true, true),
            (gen_random_uuid(), 'Leitores', 'Grupo de usuários com acesso somente leitura', true, true)
        ON CONFLICT (name) DO NOTHING;
    """)


def downgrade() -> None:
    """Downgrade database schema"""

    # Drop tables (reverse order of creation)
    op.drop_table('group_dashboard_permissions')
    op.drop_table('user_groups')
    op.drop_table('groups')
    op.drop_table('dashboard_shares')
    op.drop_table('dashboard_permissions')
    op.drop_table('users')

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS dashboardvisibility;")
    op.execute("DROP TYPE IF EXISTS userrole;")
