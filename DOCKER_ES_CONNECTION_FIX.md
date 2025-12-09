# 🔧 Docker Elasticsearch Connection Fix

**Data**: 2025-11-20
**Problema**: Backend Docker não conseguia listar índices do Elasticsearch
**Status**: ✅ Resolvido

---

## 🐛 Problema Identificado

### Sintoma
- Página de Chat não mostrava índices no dropdown
- Console do navegador mostrava erro: `Error loading indices`
- Backend retornava lista vazia `[]` para endpoint `/api/v1/es-servers/{id}/indices`

### Causa Raiz
Quando o backend roda **dentro do Docker container**, tentar acessar `localhost:9200` falha porque:
- `localhost` dentro do container refere-se ao próprio container, não ao host
- O Elasticsearch está rodando no **host** (máquina local), não no container Docker

**Erro nos logs:**
```
Connection error caused by: ClientConnectorError(Cannot connect to host localhost:9200
ssl:default [Connect call failed ('127.0.0.1', 9200)])
```

---

## ✅ Solução Aplicada

### 1. Atualizar URL do ES Server no Banco de Dados

**Comando executado:**
```sql
UPDATE es_servers
SET url = 'http://host.docker.internal:9200'
WHERE name = 'Local_main';
```

**Explicação:**
- `host.docker.internal` é um DNS especial do Docker (macOS/Windows)
- Resolve para o IP do host, permitindo que containers acessem serviços do host
- No Linux, use `host.docker.internal` (Docker 20.10+) ou `172.17.0.1`

### 2. Correção no Service SQL

**Arquivo**: `backend/app/services/es_server_service_sql.py`

**Problema encontrado:**
O método `get_indices()` estava tentando acessar campos incorretos do objeto retornado pelo ORM.

**Código ANTES (linha 222-233):**
```python
# ❌ ERRADO - Tentava acessar campos diretos que não existem
es_client = AsyncElasticsearch(
    hosts=[server.url],  # ❌ server.url não existe
    basic_auth=(
        (server.username, password)  # ❌ server.username não existe
        if server.username and password
        else None
    ),
    verify_certs=server.verify_certs,  # ❌ server.verify_certs não existe
    request_timeout=30,
)
```

**Código DEPOIS (corrigido):**
```python
# ✅ CORRETO - Usa server.connection.* conforme o schema Pydantic
es_client = AsyncElasticsearch(
    hosts=[server.connection.url],  # ✅ Correto
    basic_auth=(
        (server.connection.username, server.connection.password)  # ✅ Correto
        if server.connection.username and server.connection.password
        else None
    ),
    verify_certs=server.connection.verify_ssl,  # ✅ Correto
    request_timeout=server.connection.timeout,  # ✅ Correto
)
```

**Razão da confusão:**
- O **ORM model** (`ESServerDB`) tem campos diretos: `url`, `username`, `password_encrypted`
- O **Pydantic model** (`ElasticsearchServer`) agrupa em nested object: `connection.url`, `connection.username`, etc
- O método `_to_pydantic()` faz a conversão ORM → Pydantic
- O método `get()` retorna o Pydantic model, não o ORM model

---

## 🏗️ Arquitetura do Fix

```
┌─────────────────────────────────────────────────────────┐
│                  Frontend (Browser)                     │
│                                                          │
│  IndexSelector.tsx                                      │
│    ↓ chama esServerApi.listIndices(serverId)           │
│    ↓                                                     │
└─────────────────────────────┬───────────────────────────┘
                              │ HTTP Request
                              │ GET /api/v1/es-servers/{id}/indices
                              ▼
┌─────────────────────────────────────────────────────────┐
│           Backend Docker Container (FastAPI)            │
│                                                          │
│  es_servers.py (API endpoint)                           │
│    ↓ chama service.get_indices(db, server_id)          │
│    ↓                                                     │
│  es_server_service_sql.py                               │
│    ↓ 1. Busca server no PostgreSQL                     │
│    ↓ 2. Converte para Pydantic (server.connection.*)   │
│    ↓ 3. Cria AsyncElasticsearch client                 │
│    ↓ 4. Conecta via host.docker.internal:9200         │
│    ↓                                                     │
└─────────────────────────────┬───────────────────────────┘
                              │ Elasticsearch Client
                              │ http://host.docker.internal:9200
                              ▼
┌─────────────────────────────────────────────────────────┐
│                Host Machine (macOS)                     │
│                                                          │
│  Elasticsearch :9200                                    │
│    ↓ Retorna 412 índices via cat.indices API           │
│    ↓                                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Resultados

### Antes do Fix
```bash
curl "http://localhost:8001/api/v1/es-servers/{id}/indices"
# Retorno: []  ❌ (lista vazia)
```

**Logs:**
```
ERROR - Connection error caused by: ClientConnectorError(Cannot connect to host localhost:9200)
INFO - 📚 Found 0 indices in server
```

### Depois do Fix
```bash
curl "http://localhost:8001/api/v1/es-servers/{id}/indices"
# Retorno: [{"name":"breachdetect","doc_count":954230,...}, ...]  ✅ (412 índices)
```

**Logs:**
```
INFO - Listing indices from ES server: bb39d2b3-33e7-4dd6-82fc-9b277630a264
INFO - 📚 Listed 412 indices from server Local_main
```

---

## 🧪 Como Testar

### 1. Verificar URL do ES Server no Banco

```bash
docker exec intelligence-platform-postgres psql -U intelligence_user \
  -d intelligence_platform \
  -c "SELECT name, url FROM es_servers;"
```

**Output esperado:**
```
    name    |               url
------------+----------------------------------
 Local_main | http://host.docker.internal:9200
```

### 2. Testar Endpoint Manualmente

```bash
# 1. Login
TOKEN=$(curl -s -X POST "http://localhost:8001/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  | jq -r '.access_token')

# 2. Buscar índices
curl -s "http://localhost:8001/api/v1/es-servers/bb39d2b3-33e7-4dd6-82fc-9b277630a264/indices" \
  -H "Authorization: Bearer $TOKEN" \
  | jq 'length'

# Output esperado: 412
```

### 3. Testar no Frontend

1. Acesse: http://localhost:5174/chat
2. Faça login com `admin` / `admin`
3. Clique no dropdown **"Índice:"** no header
4. Deve aparecer **412 índices** listados

---

## 🐧 Linux Docker

No Linux, `host.docker.internal` pode não funcionar em versões antigas do Docker.

**Alternativas:**

### Opção 1: Docker 20.10+ (Recomendado)
```sql
UPDATE es_servers SET url = 'http://host.docker.internal:9200';
```

### Opção 2: Docker < 20.10
```sql
-- Usar IP do host na bridge network (geralmente 172.17.0.1)
UPDATE es_servers SET url = 'http://172.17.0.1:9200';
```

### Opção 3: Adicionar extra_hosts no docker-compose.yml
```yaml
services:
  backend:
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

---

## 🔍 Troubleshooting

### Problema: Ainda retorna lista vazia

**Verificar:**
```bash
# 1. Backend consegue acessar ES?
docker exec intelligence-platform-backend curl http://host.docker.internal:9200
# Deve retornar: {"name":"...", "cluster_name":"..."}

# 2. URL está correta no banco?
docker exec intelligence-platform-postgres psql -U intelligence_user \
  -d intelligence_platform -c "SELECT url FROM es_servers WHERE is_default = true;"

# 3. Logs do backend mostram erro?
docker logs intelligence-platform-backend 2>&1 | grep -i "error listing"
```

### Problema: Frontend não mostra índices

**Verificar console do navegador (F12):**
- Erro de CORS? → Backend precisa permitir origem do frontend
- Erro 401? → Token expirado, faça novo login
- Erro 403? → Usuário sem permissão

**Verificar Network tab:**
- Request para `/api/v1/es-servers/{id}/indices` está sendo feito?
- Response está retornando `200 OK`?
- Response body tem os índices?

---

## 📚 Referências

- **Docker networking**: https://docs.docker.com/desktop/networking/
- **host.docker.internal**: https://docs.docker.com/desktop/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host
- **Elasticsearch Python client**: https://elasticsearch-py.readthedocs.io/

---

## ✅ Checklist de Validação

- [x] URL do ES server atualizada para `host.docker.internal:9200`
- [x] Código do service corrigido para usar `server.connection.*`
- [x] Backend reiniciado
- [x] Endpoint retorna 412 índices (testado via curl)
- [x] Frontend mostra índices no dropdown (testado no navegador)
- [x] Logs não mostram erros de conexão
- [x] Documentação criada

---

**Autor**: Angello Cassio + Claude Code
**Data**: 2025-11-20
**Versão**: 1.0
