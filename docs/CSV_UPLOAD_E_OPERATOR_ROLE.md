# CSV Upload e Role OPERATOR - Documentação Completa

## Sumário
- [Visão Geral](#visão-geral)
- [Novo Role: OPERATOR](#novo-role-operator)
- [Sistema de Upload de CSV](#sistema-de-upload-de-csv)
- [Sistema de Autorização de Índices](#sistema-de-autorização-de-índices)
- [Arquitetura e Implementação](#arquitetura-e-implementação)
- [API Endpoints](#api-endpoints)
- [Exemplos de Uso](#exemplos-de-uso)
- [Migração de Banco de Dados](#migração-de-banco-de-dados)

---

## Visão Geral

Esta feature adiciona:

1. **Novo role de usuário OPERATOR**: Usuários com acesso restrito a índices específicos
2. **Upload de CSV**: Permite envio de arquivos CSV para o Elasticsearch
3. **Autorização por índice**: Sistema granular de permissões por índice/servidor
4. **Smart mapping**: Validação automática de compatibilidade de CSV com índices existentes

### Roles do Sistema

| Role | Descrição | Permissões |
|------|-----------|------------|
| **ADMIN** | Administrador do sistema | Acesso total, gerenciar usuários, configurar sistema |
| **POWER** | Usuário avançado | LLM, dashboards, CSV upload (sem restrições) |
| **OPERATOR** | Operador restrito | LLM, dashboards, CSV upload (restrito a índices específicos) |
| **READER** | Leitor | Apenas visualizar dashboards compartilhados |

---

## Novo Role: OPERATOR

### Características

O role **OPERATOR** foi criado para usuários que precisam:
- Usar o chat/LLM para análise de dados
- Criar e visualizar dashboards
- **Fazer upload de arquivos CSV**
- Mas com **restrições de acesso** a índices específicos

### Restrições

Um usuário OPERATOR:
1. **Servidor Elasticsearch**: Pode ser restrito a um servidor específico (`assigned_es_server_id`)
2. **Índices**: Só pode acessar índices explicitamente permitidos
3. **Wildcards**: Suporta padrões com wildcard (`logs-*`, `gvuln*`)

### Modelo de Dados

```python
class User(Base):
    # ... campos existentes ...

    # Novo campo para OPERATOR
    assigned_es_server_id = Column(UUID, nullable=True)

    # Relationships
    index_accesses = relationship("UserIndexAccess", ...)
```

---

## Sistema de Upload de CSV

### Fluxo de Upload

```
┌──────────────┐
│ Upload CSV   │
└──────┬───────┘
       │
       ▼
┌────────────────────┐
│ 1. Verificar       │
│    Permissões      │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ 2. Parse CSV       │
│    (validar)       │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ 3. Índice existe?  │
└─────────┬──────────┘
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
┌────────┐   ┌──────────────┐
│  NÃO   │   │     SIM      │
└───┬────┘   └──────┬───────┘
    │               │
    ▼               ▼
┌────────────┐   ┌──────────────────┐
│ Criar      │   │ Smart Mapping    │
│ Índice     │   │ (validar schema) │
└─────┬──────┘   └──────┬───────────┘
      │                 │
      ▼                 ▼
┌────────────────────────┐
│ 4. Bulk Index          │
│    (Elasticsearch)     │
└────────────┬───────────┘
             │
             ▼
┌────────────────────────┐
│ 5. Auto-grant Access   │
│    (se OPERATOR)       │
└────────────────────────┘
```

### Smart Mapping

Quando um índice JÁ EXISTE, o sistema:

1. **Valida campos**: Verifica se todos os campos do CSV existem no índice
2. **Valida tipos**: Checa compatibilidade de tipos de dados
3. **Retorna erro detalhado**: Se incompatível, lista todos os problemas

```python
# Exemplo de erro de smart mapping
{
  "success": false,
  "message": "Formato do CSV não é compatível com o índice existente",
  "errors": [
    "Campo 'new_field' não existe no índice",
    "Campo 'age' deve ser numérico inteiro, mas encontrado 'str'"
  ]
}
```

### Criação de Índice (Primeira Vez)

Quando o índice NÃO EXISTE, o sistema:

1. **Infere tipos**: Analisa os dados para determinar tipos
2. **Cria mapping**: Define estrutura do índice
3. **Cria índice**: No Elasticsearch com o mapping inferido
4. **Indexa dados**: Faz bulk upload dos documentos

```python
# Exemplo de mapping inferido
{
  "properties": {
    "name": {
      "type": "text",
      "fields": {
        "keyword": {"type": "keyword", "ignore_above": 256}
      }
    },
    "age": {"type": "long"},
    "score": {"type": "float"},
    "active": {"type": "boolean"},
    "_upload_timestamp": {"type": "date"},
    "_uploaded_by": {"type": "keyword"}
  }
}
```

---

## Sistema de Autorização de Índices

### Modelo UserIndexAccess

```python
class UserIndexAccess(Base):
    user_id: UUID
    es_server_id: UUID
    index_name: str  # Suporta wildcards: logs-*, gvuln*

    # Permissões
    can_read: bool = True
    can_write: bool = False  # Para CSV upload
    can_create: bool = False  # Para criar novos índices
```

### Wildcards

Suporta padrões fnmatch:

| Padrão | Match | Não Match |
|--------|-------|-----------|
| `logs-*` | `logs-2024`, `logs-prod` | `gvuln`, `metrics-2024` |
| `gvuln*` | `gvuln_v1`, `gvuln-test` | `logs-gvuln` |
| `*-prod` | `logs-prod`, `metrics-prod` | `logs-dev` |
| `*` | Todos os índices | N/A |

### Verificação de Permissões

```python
# Exemplo de verificação
auth_service = get_index_authorization_service(db)

can_access = auth_service.can_access_index(
    user=current_user,
    index_name="logs-2024-01",
    es_server_id="server-123",
    action="write"  # read, write, create
)
```

---

## Arquitetura e Implementação

### Estrutura de Arquivos

```
backend/
├── app/
│   ├── models/
│   │   ├── user.py                        # ✨ Atualizado (OPERATOR role)
│   │   └── user_index_access.py           # ✨ Novo
│   ├── services/
│   │   ├── csv_upload_service.py          # ✨ Novo
│   │   ├── index_authorization_service.py # ✨ Novo
│   │   └── auth_service.py                # ✨ Atualizado
│   ├── api/v1/
│   │   ├── csv_upload.py                  # ✨ Novo
│   │   ├── index_access.py                # ✨ Novo
│   │   ├── chat.py                        # ✨ Atualizado (auth check)
│   │   ├── elasticsearch_api.py           # ✨ Atualizado (auth check)
│   │   └── users.py                       # ✨ Atualizado
│   └── schemas/
│       └── user.py                        # ✨ Atualizado
└── alembic/versions/
    └── 20251111_1000_add_operator_role_and_index_access.py  # ✨ Novo
```

### Services

#### CSVUploadService

Responsável por:
- Parse de arquivos CSV
- Validação de formato
- Inferência de tipos
- Criação de índices
- Smart mapping
- Bulk indexing

**Métodos principais:**
```python
async def process_and_upload_csv(
    file_content: bytes,
    index_name: str,
    es_server_id: str,
    user_id: str,
    force_create: bool = False
) -> Dict[str, Any]
```

#### IndexAuthorizationService

Responsável por:
- Verificação de permissões por índice
- Gerenciamento de acessos (CRUD)
- Suporte a wildcards
- Listagem de índices acessíveis

**Métodos principais:**
```python
def can_access_index(user, index_name, es_server_id, action) -> bool
def get_accessible_indices(user, es_server_id, action) -> List[str]
def grant_index_access(...) -> UserIndexAccess
def revoke_index_access(access_id) -> bool
```

---

## API Endpoints

### CSV Upload

#### `POST /api/v1/csv-upload/`

Upload de arquivo CSV para o Elasticsearch.

**Permissões:**
- ADMIN: Upload para qualquer índice
- POWER: Upload para qualquer índice
- OPERATOR: Apenas para índices com permissão

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/csv-upload/ \
  -H "Authorization: Bearer <token>" \
  -F "file=@data.csv" \
  -F "index_name=logs-2024-01" \
  -F "es_server_id=server-123" \
  -F "force_create=false"
```

**Response (Sucesso):**
```json
{
  "success": true,
  "message": "Successfully uploaded 1000 documents",
  "index_name": "logs-2024-01",
  "documents_processed": 1000,
  "documents_indexed": 1000,
  "created_index": false,
  "errors": [],
  "mapping": null
}
```

**Response (Erro - Smart Mapping):**
```json
{
  "success": false,
  "message": "Formato do CSV não é compatível com o índice existente",
  "index_name": "logs-2024-01",
  "documents_processed": 1000,
  "documents_indexed": 0,
  "errors": [
    "Campo 'timestamp' não existe no índice. Campos esperados: date, level, message",
    "Campo 'level' deve ser texto, mas encontrado 'int' no documento 1"
  ],
  "created_index": false
}
```

#### `GET /api/v1/csv-upload/my-upload-permissions`

Retorna permissões de upload do usuário atual.

**Response:**
```json
{
  "can_upload": true,
  "has_restrictions": true,
  "role": "operator",
  "accessible_servers": ["server-123"],
  "accessible_indices": [
    {
      "index_pattern": "logs-*",
      "es_server_id": "server-123",
      "can_read": true,
      "can_write": true,
      "can_create": false
    }
  ],
  "message": "Restricted to 1 index patterns"
}
```

### Gerenciamento de Acessos

#### `POST /api/v1/index-access/`

Concede acesso a um índice para um usuário OPERATOR.

**Permissões:** ADMIN only

**Request:**
```json
{
  "user_id": "user-uuid",
  "es_server_id": "server-uuid",
  "index_name": "logs-*",
  "can_read": true,
  "can_write": true,
  "can_create": false
}
```

#### `GET /api/v1/index-access/user/{user_id}`

Lista todos os acessos de um usuário.

**Permissões:** ADMIN ou o próprio usuário

#### `GET /api/v1/index-access/my-accesses`

Lista acessos do usuário atual.

#### `PATCH /api/v1/index-access/{access_id}`

Atualiza permissões de um acesso.

**Permissões:** ADMIN only

#### `DELETE /api/v1/index-access/{access_id}`

Remove um acesso.

**Permissões:** ADMIN only

#### `POST /api/v1/index-access/check-access`

Verifica se usuário tem acesso a um índice.

**Query Parameters:**
- `index_name`: Nome do índice
- `es_server_id`: ID do servidor
- `action`: Tipo de ação (read, write, create)

**Response:**
```json
{
  "has_access": true,
  "role": "operator",
  "action": "write",
  "index_name": "logs-2024-01",
  "es_server_id": "server-123",
  "reason": "User has explicit write permission for this index"
}
```

---

## Exemplos de Uso

### Exemplo 1: Criar usuário OPERATOR

```bash
# 1. Criar usuário
curl -X POST http://localhost:8000/api/v1/users/ \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator1",
    "email": "operator1@company.com",
    "password": "SecurePass123",
    "full_name": "Operator User",
    "role": "operator",
    "assigned_es_server_id": "server-123"
  }'
```

### Exemplo 2: Conceder acesso a índices

```bash
# 2. Conceder acesso a logs-*
curl -X POST http://localhost:8000/api/v1/index-access/ \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<operator-user-id>",
    "es_server_id": "server-123",
    "index_name": "logs-*",
    "can_read": true,
    "can_write": true,
    "can_create": true
  }'

# 3. Conceder acesso a gvuln*
curl -X POST http://localhost:8000/api/v1/index-access/ \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<operator-user-id>",
    "es_server_id": "server-123",
    "index_name": "gvuln*",
    "can_read": true,
    "can_write": false,
    "can_create": false
  }'
```

### Exemplo 3: Upload de CSV (OPERATOR)

```bash
# 4. Fazer upload de CSV
curl -X POST http://localhost:8000/api/v1/csv-upload/ \
  -H "Authorization: Bearer <operator-token>" \
  -F "file=@logs.csv" \
  -F "index_name=logs-2024-11" \
  -F "es_server_id=server-123"

# ✅ Sucesso: logs-2024-11 match com logs-*
# ❌ Erro: metrics-2024 não match com logs-* ou gvuln*
```

### Exemplo 4: Formato do CSV

```csv
timestamp,level,message,user_id
2024-11-11T10:00:00Z,INFO,User logged in,123
2024-11-11T10:01:00Z,ERROR,Connection failed,456
2024-11-11T10:02:00Z,WARN,Slow query detected,789
```

**Tipos inferidos:**
- `timestamp`: string (text + keyword)
- `level`: string (text + keyword)
- `message`: string (text + keyword)
- `user_id`: integer (long)

---

## Migração de Banco de Dados

### Migration: 20251111_1000_add_operator_role_and_index_access.py

**O que faz:**

1. Adiciona novo valor `operator` ao enum `UserRole`
2. Adiciona coluna `assigned_es_server_id` na tabela `users`
3. Cria tabela `user_index_accesses`
4. Cria índices para performance
5. Cria unique constraint para evitar duplicatas

**Executar migration:**

```bash
cd backend
alembic upgrade head
```

**Verificar:**

```bash
alembic current
# Deve mostrar: 20251111_1000
```

### Estrutura da tabela user_index_accesses

```sql
CREATE TABLE user_index_accesses (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    es_server_id UUID NOT NULL,
    index_name VARCHAR(255) NOT NULL,
    can_read BOOLEAN NOT NULL DEFAULT TRUE,
    can_write BOOLEAN NOT NULL DEFAULT FALSE,
    can_create BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by_id UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT uix_user_server_index UNIQUE (user_id, es_server_id, index_name)
);
```

---

## Segurança

### Validações Implementadas

1. **Autenticação**: Todos os endpoints requerem token JWT válido
2. **Autorização por role**: Verificação de permissões baseada em role
3. **Autorização por índice**: OPERATOR restrito a índices específicos
4. **Validação de CSV**: Parse seguro, limite de tamanho, validação de encoding
5. **SQL Injection**: Uso de ORM (SQLAlchemy) previne SQL injection
6. **XSS**: Dados sempre escapados no backend
7. **Metadados de auditoria**: `_uploaded_by` e `_upload_timestamp` em todos os documentos

### Boas Práticas

- **Não usar wildcards genéricos** (`*`) para OPERATOR
- **Revisar acessos periodicamente** via `/api/v1/index-access/user/{user_id}`
- **Monitorar uploads** via logs do sistema
- **Validar CSV antes de upload** (campos esperados, tipos corretos)

---

## Troubleshooting

### Erro: "User does not have permission to access index"

**Causa:** Usuário OPERATOR sem permissão explícita para o índice.

**Solução:**
```bash
# Verificar acessos do usuário
curl -X GET "http://localhost:8000/api/v1/index-access/user/<user-id>" \
  -H "Authorization: Bearer <admin-token>"

# Conceder acesso
curl -X POST http://localhost:8000/api/v1/index-access/ \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<user-id>",
    "es_server_id": "<server-id>",
    "index_name": "index-pattern",
    "can_read": true,
    "can_write": true
  }'
```

### Erro: "CSV não é compatível com o índice existente"

**Causa:** Campos ou tipos do CSV não match com o mapping do índice.

**Solução:**
1. Verificar mapping do índice no Elasticsearch
2. Ajustar CSV para match com os campos esperados
3. Ou criar novo índice com outro nome

### Erro: "Username already registered"

**Causa:** Username já existe no sistema.

**Solução:** Usar outro username ou atualizar usuário existente.

---

## Próximos Passos / Melhorias Futuras

### Backend
- [ ] Interface web para gerenciar acessos de índices (admin panel)
- [ ] Interface web para upload de CSV
- [ ] Validação de tamanho de arquivo CSV (limite)
- [ ] Suporte a outros formatos (JSON, Excel)
- [ ] Preview de dados antes do upload
- [ ] Histórico de uploads por usuário
- [ ] Rollback de uploads com erro

### Frontend
- [ ] Componente CSVUpload.tsx
- [ ] Página de gerenciamento de acessos (admin)
- [ ] Indicador de índices acessíveis no chat
- [ ] Filtro de índices baseado em permissões

---

## Referências

- **Modelo User**: `backend/app/models/user.py`
- **Modelo UserIndexAccess**: `backend/app/models/user_index_access.py`
- **CSV Upload Service**: `backend/app/services/csv_upload_service.py`
- **Auth Service**: `backend/app/services/index_authorization_service.py`
- **API Endpoints**: `backend/app/api/v1/csv_upload.py`, `backend/app/api/v1/index_access.py`
- **Migration**: `backend/alembic/versions/20251111_1000_add_operator_role_and_index_access.py`

---

**Versão:** 1.0
**Data:** 2025-11-11
**Autor:** Dashboard AI v2 Team
