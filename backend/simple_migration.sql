-- Simple migration
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(20) DEFAULT 'reader' NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    is_superuser BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW() NOT NULL,
    last_login TIMESTAMP,
    preferences TEXT
);

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW() NOT NULL,
    created_by_id UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE dashboard_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_id VARCHAR(255) UNIQUE NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    visibility VARCHAR(20) DEFAULT 'private' NOT NULL,
    allow_edit_by_others BOOLEAN DEFAULT false NOT NULL,
    allow_copy BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE TABLE dashboard_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_id UUID NOT NULL REFERENCES dashboard_permissions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_edit BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE TABLE user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE group_dashboard_permissions (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    dashboard_id VARCHAR(255) NOT NULL,
    can_view BOOLEAN DEFAULT true NOT NULL,
    can_edit BOOLEAN DEFAULT false NOT NULL,
    can_delete BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    PRIMARY KEY (group_id, dashboard_id)
);

INSERT INTO users (username, email, hashed_password, full_name, role, is_active, is_superuser)
VALUES ('admin', 'admin@dashboard-ai.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5lW7aW.WX2Kfi', 'Administrator', 'admin', true, true);

INSERT INTO groups (name, description, is_system, is_active) VALUES
('Administradores', 'Grupo de administradores do sistema', true, true),
('Analistas', 'Grupo de analistas com acesso ao LLM', true, true),
('Leitores', 'Grupo de usuários com acesso somente leitura', true, true);
