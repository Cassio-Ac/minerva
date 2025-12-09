-- Migration: Add users and permissions tables
-- Run with: docker exec dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai -f /migrate_users.sql

-- Create enum types
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
        CREATE TYPE userrole AS ENUM ('admin', 'power', 'reader');
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dashboardvisibility') THEN
        CREATE TYPE dashboardvisibility AS ENUM ('private', 'public', 'shared');
    END IF;
END $$;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role userrole NOT NULL DEFAULT 'reader',
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_superuser BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP,
    preferences TEXT
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

-- Create dashboard_permissions table
CREATE TABLE IF NOT EXISTS dashboard_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_id VARCHAR(255) NOT NULL UNIQUE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    visibility dashboardvisibility NOT NULL DEFAULT 'private',
    allow_edit_by_others BOOLEAN NOT NULL DEFAULT false,
    allow_copy BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_dashboard_permissions_dashboard_id ON dashboard_permissions(dashboard_id);
CREATE INDEX IF NOT EXISTS ix_dashboard_permissions_owner_id ON dashboard_permissions(owner_id);

-- Create dashboard_shares table
CREATE TABLE IF NOT EXISTS dashboard_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_id UUID NOT NULL REFERENCES dashboard_permissions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_edit BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_dashboard_shares_permission_id ON dashboard_shares(permission_id);
CREATE INDEX IF NOT EXISTS ix_dashboard_shares_user_id ON dashboard_shares(user_id);

-- Create groups table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by_id UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_groups_name ON groups(name);

-- Create user_groups table (many-to-many)
CREATE TABLE IF NOT EXISTS user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS ix_user_groups_user_id ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS ix_user_groups_group_id ON user_groups(group_id);

-- Create group_dashboard_permissions table (many-to-many)
CREATE TABLE IF NOT EXISTS group_dashboard_permissions (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    dashboard_id VARCHAR(255) NOT NULL,
    can_view BOOLEAN NOT NULL DEFAULT true,
    can_edit BOOLEAN NOT NULL DEFAULT false,
    can_delete BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, dashboard_id)
);

CREATE INDEX IF NOT EXISTS ix_group_dashboard_permissions_group_id ON group_dashboard_permissions(group_id);
CREATE INDEX IF NOT EXISTS ix_group_dashboard_permissions_dashboard_id ON group_dashboard_permissions(dashboard_id);

-- Insert default admin user (password: admin123)
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

-- Insert default system groups
INSERT INTO groups (id, name, description, is_system, is_active)
VALUES
    (gen_random_uuid(), 'Administradores', 'Grupo de administradores do sistema', true, true),
    (gen_random_uuid(), 'Analistas', 'Grupo de analistas com acesso ao LLM', true, true),
    (gen_random_uuid(), 'Leitores', 'Grupo de usuários com acesso somente leitura', true, true)
ON CONFLICT (name) DO NOTHING;

-- Update alembic_version
INSERT INTO alembic_version (version_num) VALUES ('20251110_0100')
ON CONFLICT (version_num) DO UPDATE SET version_num = '20251110_0100';

-- Show results
SELECT 'Migration completed successfully!' AS status;
SELECT COUNT(*) AS user_count FROM users;
SELECT COUNT(*) AS group_count FROM groups;
