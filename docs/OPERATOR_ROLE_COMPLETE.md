# 👤 OPERATOR Role - Sistema Completo de Restrições

## 🎯 Visão Geral

Sistema completo de controle granular para usuários OPERATOR, permitindo que administradores restrinjam acesso a servidores Elasticsearch específicos e índices designados (com suporte a wildcards).

---

## 📋 Hierarquia de Roles

### 1. **ADMIN** 🔴
- ✅ Acesso total ao sistema
- ✅ Gerenciar todos os usuários
- ✅ Configurar servidores ES
- ✅ Acesso a todos os índices de todos os servidores
- ✅ Upload CSV sem restrições

### 2. **POWER** 🔵
- ✅ Acesso a todos os índices e servidores
- ✅ Pode usar LLM e criar dashboards
- ✅ Upload CSV sem restrições
- ❌ Não pode adicionar novos servidores
- ❌ Não pode gerenciar usuários

### 3. **OPERATOR** 🟠 (NOVO)
- ⚠️ Acesso **APENAS** ao servidor ES designado
- ⚠️ Acesso **APENAS** aos índices designados pelo admin
- ✅ Pode fazer upload CSV para índices permitidos
- ✅ Pode criar novos índices (se permissão `can_create`)
- ✅ Suporte a wildcards para múltiplos índices
- ❌ Sem acesso a LLM ou criar dashboards
- ❌ Sem acesso a configurações do sistema

### 4. **READER** 🟢
- ✅ Visualizar apenas dashboards públicos
- ❌ Sem upload CSV
- ❌ Sem criar dashboards

---

## 🏗️ Arquitetura

### Backend

#### Models

**`backend/app/models/user.py`**
```python
class User(Base):
    # ... campos existentes
    assigned_es_server_id = Column(UUID(as_uuid=True), nullable=True)
    # NULL = sem restrição (ADMIN/POWER)
    # UUID = servidor ES específico (OPERATOR)
```

**`backend/app/models/user_index_access.py`**
```python
class UserIndexAccess(Base):
    __tablename__ = "user_index_accesses"

    id = Column(UUID, primary_key=True)
    user_id = Column(UUID, ForeignKey("users.id"))
    es_server_id = Column(UUID)
    index_name = Column(String(255))  # Suporta wildcards

    # Permissões granulares
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)  # CSV upload
    can_create = Column(Boolean, default=False)  # Criar índices

    def matches_index(self, index_name: str) -> bool:
        """Verifica se índice match com wildcard"""
        import fnmatch
        return fnmatch.fnmatch(index_name, self.index_name)
```

#### Services

**`backend/app/services/index_authorization_service.py`**
- `can_access_index(user, index_name, es_server_id, action)`
- Valida ADMIN/POWER (acesso total)
- Valida OPERATOR (apenas índices designados)
- Suporte a wildcards com `fnmatch`

**`backend/app/services/csv_upload_service.py`**
- Usa `index_authorization_service` para validar upload
- Auto-cria acesso quando OPERATOR cria novo índice
- Valida permissões `can_create` e `can_write`

#### API Endpoints

**`backend/app/api/v1/users.py`**
- `POST /api/v1/users/` - Cria usuário (aceita `assigned_es_server_id`)
- `PATCH /api/v1/users/{id}` - Atualiza usuário (aceita `assigned_es_server_id`)
- `GET /api/v1/users/{id}` - Retorna user com `assigned_es_server_id`

**`backend/app/api/v1/index_access.py`**
- `POST /api/v1/index-access/` - Cria permissão de índice
- `GET /api/v1/index-access/user/{user_id}` - Lista permissões do usuário
- `PATCH /api/v1/index-access/{id}` - Atualiza permissões
- `DELETE /api/v1/index-access/{id}` - Remove permissão

**`backend/app/api/v1/csv_upload.py`**
- `POST /api/v1/csv-upload/` - Upload CSV com validação de acesso

#### Schemas

**`backend/app/schemas/user.py`**
```python
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole
    assigned_es_server_id: Optional[str] = None  # UUID do servidor ES
```

### Frontend

#### Components

**`frontend/src/components/UserManager.tsx`** (Gerenciar Usuários)
- Dropdown "Servidor Elasticsearch" (condicional para OPERATOR)
- Lista servidores ES disponíveis
- Campo obrigatório com hint explicativo
- Botão "Gerenciar Índices" (ícone pasta amber) para OPERATORs
- Badge amber/orange para role OPERATOR

**`frontend/src/components/IndexAccessManager.tsx`** (Gerenciar Índices)
- Modal full-screen para gerenciar permissões
- Info box com exemplos de wildcards
- Formulário inline para adicionar permissões
- Lista de permissões configuradas
- Toggle rápido de checkboxes (read/write/create)
- Confirmação antes de remover
- Loading states e feedback visual

#### Services

**`frontend/src/services/api.ts`**
```typescript
// Gerenciamento de acessos a índices
async listUserIndexAccess(userId: string): Promise<any[]>
async createIndexAccess(data: {...}): Promise<any>
async updateIndexAccess(accessId: string, data: {...}): Promise<any>
async deleteIndexAccess(accessId: string): Promise<void>

// Upload CSV
async uploadCSV(formData: FormData): Promise<any>

// Servidores ES
async getESServers(): Promise<any[]>
```

#### Stores

**`frontend/src/stores/authStore.ts`**
```typescript
interface User {
  // ... campos existentes
  role: 'admin' | 'power' | 'operator' | 'reader';
  can_upload_csv: boolean;
  has_index_restrictions: boolean;
  assigned_es_server_id: string | null;
}
```

---

## 🎨 Fluxo de Uso (Admin)

### 1. Criar Usuário OPERATOR

1. **Settings** → **Admin** → **Gerenciar Usuários**
2. Clicar em **"+ Novo Usuário"**
3. Preencher dados básicos:
   - Username: `operador1`
   - Email: `operador1@empresa.com`
   - Nome completo: `João Operador`
   - Senha: `********`
4. Selecionar **Perfil**: `Operator - Upload CSV com restrições de índices`
5. Aparece dropdown **"Servidor Elasticsearch *"**
6. Selecionar servidor: `Produção (https://es.prod.com:9200)`
7. Clicar **"Criar"**

**Resultado:**
- ✅ Usuário criado com `assigned_es_server_id`
- ⚠️ Usuário ainda **NÃO tem acesso a nenhum índice**
- 🟠 Badge amber "Operator" aparece no card do usuário

### 2. Designar Índices Permitidos

1. No card do usuário OPERATOR, clicar no **botão de pasta amber** (Gerenciar Índices)
2. Modal abre mostrando "Nenhuma permissão configurada ainda"
3. Clicar em **"+ Adicionar Permissão de Índice"**

#### Exemplo 1: Acesso a logs com wildcard
```
Índice: logs-*
✅ Leitura (Read)
✅ Escrita/Upload (Write)
❌ Criar Novos (Create)
```
→ Usuário pode ler e fazer upload em **todos** os índices `logs-*` (logs-2024, logs-prod, etc)

#### Exemplo 2: Criar índices de vulnerabilidades
```
Índice: gvuln*
✅ Leitura (Read)
✅ Escrita/Upload (Write)
✅ Criar Novos (Create)
```
→ Usuário pode criar novos índices `gvuln*` via upload CSV

#### Exemplo 3: Índice específico apenas leitura
```
Índice: dashboard-metrics
✅ Leitura (Read)
❌ Escrita/Upload (Write)
❌ Criar Novos (Create)
```
→ Usuário só pode visualizar, sem modificar

### 3. Gerenciar Permissões

**Editar Permissões:**
- Clicar nos checkboxes para toggle rápido
- Mudanças aplicadas imediatamente via API

**Remover Permissão:**
- Clicar em "Remover" ao lado da permissão
- Confirmação antes de deletar
- Usuário perde acesso ao índice imediatamente

---

## 🎯 Fluxo de Uso (Operator)

### Login e Home

1. **Login**: `operador1` / `********`
2. **Home Page**: Vê apenas:
   - 📤 Upload CSV (se tiver permissões write)
   - 📊 Dashboards (apenas públicos)
   - 📥 Downloads (próprios)

### Upload CSV

1. **Upload CSV** → Seleciona arquivo
2. **Servidor ES**: Já pré-selecionado (assigned_es_server_id)
3. **Nome do Índice**:
   - Se índice existe → valida se tem permissão
   - Se índice não existe → valida se tem `can_create` + wildcard match

#### Cenário 1: Upload para índice existente permitido ✅
```
Permissão: logs-* (can_write=true)
Índice: logs-2024-11
Resultado: ✅ Upload autorizado
```

#### Cenário 2: Upload para índice não permitido ❌
```
Permissão: logs-* (can_write=true)
Índice: metrics-2024
Resultado: ❌ Acesso negado (não match com logs-*)
```

#### Cenário 3: Criar novo índice com permissão ✅
```
Permissão: gvuln* (can_create=true, can_write=true)
Índice: gvuln-2024-new
Resultado: ✅ Índice criado + upload autorizado + acesso auto-concedido
```

#### Cenário 4: Tentar criar sem permissão ❌
```
Permissão: logs-* (can_write=true, can_create=false)
Índice: logs-new-index (não existe)
Resultado: ❌ Sem permissão para criar índices
```

---

## 💡 Wildcards Suportados

### Padrões Comuns

| Wildcard | Exemplo Match | Não Match |
|----------|---------------|-----------|
| `logs-*` | logs-2024, logs-prod, logs-app | metrics-logs, app-logs |
| `*-2024` | logs-2024, metrics-2024 | logs-2023, app |
| `gvuln*` | gvuln, gvuln-test, gvuln123 | app-gvuln |
| `app-*-prod` | app-api-prod, app-web-prod | app-dev, app-api-staging |
| `test*log*` | test-logs, testing-log-api | logs-test |

### Implementação

Backend usa `fnmatch` (Python):
```python
import fnmatch

def matches_index(self, index_name: str) -> bool:
    return fnmatch.fnmatch(index_name, self.index_name)
```

---

## 🔐 Matriz de Permissões

### Por Action

| Action | ADMIN | POWER | OPERATOR | READER |
|--------|-------|-------|----------|--------|
| **Ver todos os servidores ES** | ✅ | ✅ | ❌ | ❌ |
| **Ver servidor designado** | ✅ | ✅ | ✅ | ❌ |
| **Ler índice sem restrição** | ✅ | ✅ | ❌ | ❌ |
| **Ler índice designado** | ✅ | ✅ | ✅ | ❌ |
| **Upload CSV sem restrição** | ✅ | ✅ | ❌ | ❌ |
| **Upload CSV (índice permitido)** | ✅ | ✅ | ✅ | ❌ |
| **Criar índice sem restrição** | ✅ | ✅ | ❌ | ❌ |
| **Criar índice (can_create=true)** | ✅ | ✅ | ✅ | ❌ |
| **Usar LLM** | ✅ | ✅ | ❌ | ❌ |
| **Criar dashboards** | ✅ | ✅ | ❌ | ❌ |
| **Ver dashboards públicos** | ✅ | ✅ | ✅ | ✅ |
| **Gerenciar usuários** | ✅ | ❌ | ❌ | ❌ |
| **Configurar servidores ES** | ✅ | ❌ | ❌ | ❌ |

### Por Índice

| Permissão | Descrição | Permite |
|-----------|-----------|---------|
| **can_read** | Leitura | Queries, visualização, dashboards |
| **can_write** | Escrita | Upload CSV, bulk indexing, updates |
| **can_create** | Criar | Criar novos índices via upload CSV |

---

## 🗄️ Database Schema

### Tabela: `users`

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role userrole NOT NULL DEFAULT 'reader',
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_superuser BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP,
    preferences TEXT,
    assigned_es_server_id UUID  -- NULL = sem restrição
);

-- Enum UserRole
CREATE TYPE userrole AS ENUM ('admin', 'power', 'operator', 'reader');
```

### Tabela: `user_index_accesses`

```sql
CREATE TABLE user_index_accesses (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    es_server_id UUID NOT NULL,
    index_name VARCHAR(255) NOT NULL,  -- Suporta wildcards
    can_read BOOLEAN NOT NULL DEFAULT true,
    can_write BOOLEAN NOT NULL DEFAULT false,
    can_create BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by_id UUID REFERENCES users(id),

    -- Índices
    CONSTRAINT unique_user_server_index UNIQUE(user_id, es_server_id, index_name)
);

CREATE INDEX idx_user_index_accesses_user_id ON user_index_accesses(user_id);
CREATE INDEX idx_user_index_accesses_es_server_id ON user_index_accesses(es_server_id);
```

---

## 📊 Exemplos Práticos

### Caso de Uso 1: Operador de Logs

**Cenário:**
- Operador responsável por ingerir logs de aplicações

**Setup:**
1. Criar usuário `operador-logs`
2. Role: `operator`
3. Servidor: `ES Produção`
4. Permissões:
   ```
   logs-* (read=true, write=true, create=true)
   ```

**O que ele pode fazer:**
- ✅ Upload CSV para logs-2024, logs-prod, logs-app
- ✅ Criar novos índices logs-*
- ✅ Visualizar dashboards de logs

**O que ele NÃO pode fazer:**
- ❌ Acessar índices metrics-*
- ❌ Acessar índices de outros servidores
- ❌ Usar LLM ou criar dashboards

### Caso de Uso 2: Operador de Vulnerabilidades

**Cenário:**
- Analista de segurança que gerencia dados de vulnerabilidades

**Setup:**
1. Criar usuário `sec-analyst`
2. Role: `operator`
3. Servidor: `ES Segurança`
4. Permissões:
   ```
   gvuln* (read=true, write=true, create=true)
   cve-* (read=true, write=false, create=false)
   ```

**O que ele pode fazer:**
- ✅ Upload CSV para gvuln* (criar e atualizar)
- ✅ Visualizar dados de cve-*
- ❌ Modificar cve-* (apenas leitura)

### Caso de Uso 3: Operador Restrito

**Cenário:**
- Terceirizado que apenas ingere dados específicos

**Setup:**
1. Criar usuário `terceiro-fornecedor`
2. Role: `operator`
3. Servidor: `ES Dev`
4. Permissões:
   ```
   fornecedor-dados (read=false, write=true, create=false)
   ```

**O que ele pode fazer:**
- ✅ Apenas fazer upload para índice `fornecedor-dados`
- ❌ Não pode ler (blind upload)
- ❌ Não pode criar outros índices
- ❌ Não pode ver dashboards

---

## 🚀 Migration

**Arquivo:** `backend/alembic/versions/20251111_1000_add_operator_role_and_index_access.py`

### Aplicar Migration

```bash
cd backend
alembic upgrade head
```

### Rollback

```bash
alembic downgrade -1
```

---

## 🧪 Testing

### Testar Criação de OPERATOR

```bash
# 1. Login como admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Salvar token
TOKEN="eyJ..."

# 2. Listar servidores ES
curl http://localhost:8000/api/v1/es-servers/ \
  -H "Authorization: Bearer $TOKEN"

# Salvar ES_SERVER_ID
ES_SERVER_ID="745baee9-450f-4eb2-a68f-269ac6e8f4ab"

# 3. Criar usuário OPERATOR
curl -X POST http://localhost:8000/api/v1/users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operador_teste",
    "email": "op@test.com",
    "password": "senha123",
    "full_name": "Operador Teste",
    "role": "operator",
    "assigned_es_server_id": "'$ES_SERVER_ID'"
  }'

# Salvar USER_ID
USER_ID="..."
```

### Testar Permissões de Índice

```bash
# 1. Adicionar permissão wildcard
curl -X POST http://localhost:8000/api/v1/index-access/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "'$USER_ID'",
    "es_server_id": "'$ES_SERVER_ID'",
    "index_name": "logs-*",
    "can_read": true,
    "can_write": true,
    "can_create": true
  }'

# 2. Listar permissões do usuário
curl http://localhost:8000/api/v1/index-access/user/$USER_ID \
  -H "Authorization: Bearer $TOKEN"

# 3. Login como OPERATOR
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"operador_teste","password":"senha123"}'

OP_TOKEN="eyJ..."

# 4. Tentar upload CSV (deve funcionar para logs-*)
curl -X POST http://localhost:8000/api/v1/csv-upload/ \
  -H "Authorization: Bearer $OP_TOKEN" \
  -F "file=@dados.csv" \
  -F "index_name=logs-2024" \
  -F "es_server_id=$ES_SERVER_ID"
```

---

## 📝 Conclusão

Sistema completo de OPERATOR implementado e testado! 🎉

**Commits principais:**
1. `fix: add OPERATOR role to user creation dropdown` - UI para criar OPERATOR
2. `feat: add Elasticsearch server assignment for OPERATOR users` - Designar servidor
3. `feat: add IndexAccessManager component for OPERATOR index permissions` - Gerenciar índices

**Pronto para produção:**
- ✅ Backend completo com validações
- ✅ Frontend com UI intuitiva
- ✅ Documentação completa
- ✅ Suporte a wildcards
- ✅ Permissões granulares
- ✅ Auto-grant de acesso em criação de índices

🎯 **Admin pode agora criar operadores restritos e designar exatamente quais índices eles podem acessar!**
