# Guia de Desenvolvimento - Dashboard AI v2

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Arquitetura Docker](#arquitetura-docker)
- [Persistência de Dados](#persistência-de-dados)
- [Ambiente de Desenvolvimento](#ambiente-de-desenvolvimento)
- [Comandos Úteis](#comandos-úteis)
- [Troubleshooting](#troubleshooting)

## 🎯 Visão Geral

Este projeto utiliza **Docker** para isolar dependências e garantir ambiente reproduzível. A arquitetura permite **hot reload** no código (backend e frontend) sem necessidade de rebuild de containers.

### Stack Tecnológica

**Backend:**
- FastAPI (Python 3.11)
- SQLAlchemy + Alembic
- PostgreSQL 16
- Redis 7
- Socket.IO

**Frontend:**
- React 18 + TypeScript
- Vite
- Zustand
- TailwindCSS
- Plotly.js

**LLM Providers:**
- Anthropic Claude
- OpenAI GPT
- Databricks

## 🐳 Arquitetura Docker

### Containers Ativos

```
┌─────────────────────────────────────────────────────────────┐
│                    SEU MAC (macOS)                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  📁 Código Fonte (Bind Mounts)                             │
│     /Users/angellocassio/Downloads/dashboard-ai-v2/       │
│     ├── backend/          ←→ Container backend:/app        │
│     ├── frontend/         (roda FORA do Docker)            │
│     └── docker-compose.yml                                 │
│                                                             │
│  💾 Dados Persistentes (Docker Volume)                     │
│     /var/lib/docker/volumes/                               │
│     └── dashboard-ai-v2_postgres_data/ (~48MB)             │
│                                                             │
│  ┌───────────────────────────────────────────────────┐    │
│  │  🐳 dashboard-ai-postgres                         │    │
│  │  ─────────────────────────────                    │    │
│  │  Image: postgres:16-alpine                        │    │
│  │  Port: 5432                                       │    │
│  │  Volume: postgres_data                            │    │
│  │  Health: pg_isready check                         │    │
│  │                                                    │    │
│  │  Armazena:                                        │    │
│  │  • Dashboards                                     │    │
│  │  • Conversations                                  │    │
│  │  • ES Servers                                     │    │
│  │  • LLM Providers                                  │    │
│  └───────────────────────────────────────────────────┘    │
│                                                             │
│  ┌───────────────────────────────────────────────────┐    │
│  │  🐳 dashboard-ai-redis                            │    │
│  │  ─────────────────────────                        │    │
│  │  Image: redis:7-alpine                            │    │
│  │  Port: 6379                                       │    │
│  │  Health: redis-cli ping                           │    │
│  │  Status: Preparado (REDIS_ENABLED=False)          │    │
│  └───────────────────────────────────────────────────┘    │
│                                                             │
│  ┌───────────────────────────────────────────────────┐    │
│  │  🐳 dashboard-ai-backend                          │    │
│  │  ─────────────────────────                        │    │
│  │  Image: dashboard-ai-v2-backend (custom)          │    │
│  │  Port: 8000                                       │    │
│  │  Volume: ./backend ←→ /app (bind mount)           │    │
│  │  Command: uvicorn --reload (hot reload)           │    │
│  │                                                    │    │
│  │  Conecta:                                         │    │
│  │  • postgres:5432 (metadados)                      │    │
│  │  • redis:6379 (cache)                             │    │
│  │  • host.docker.internal:9200 (ES externo)         │    │
│  └───────────────────────────────────────────────────┘    │
│                                                             │
│  🌐 Elasticsearch & Kibana (Externos)                     │
│     Rodando fora do docker-compose:                       │
│     • elasticsearch:9200                                   │
│     • kibana:5601                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Docker Compose Services

```yaml
services:
  postgres:    # Banco de metadados
  redis:       # Cache (preparado para uso futuro)
  backend:     # API FastAPI com hot reload
```

**Removidos (otimização):**
- ❌ `frontend` - Roda direto com `npm run dev` (HMR mais rápido)
- ❌ `elasticsearch` - Usa instância externa já existente
- ❌ `kibana` - Usa instância externa já existente

**Resultado:**
- ~1.5GB RAM economizado
- Startup 3x mais rápido
- Apenas serviços essenciais rodando

## 💾 Persistência de Dados

### Como Funciona a Persistência

#### 1. Código Fonte (Bind Mount)

O código do backend é **montado** dentro do container usando bind mount:

```yaml
volumes:
  - ./backend:/app
```

**Fluxo:**
```
Você edita: ./backend/app/api/v1/chat.py
      ↓
Mudança reflete INSTANTANEAMENTE em: /app/app/api/v1/chat.py (container)
      ↓
uvicorn --reload detecta mudança
      ↓
Backend reinicia automaticamente
      ↓
Mudança aplicada SEM rebuild!
```

**Vantagens:**
- ✅ Edição instantânea
- ✅ Hot reload automático
- ✅ Sem rebuild necessário
- ✅ Logs em tempo real

#### 2. Dados PostgreSQL (Named Volume)

Dados do banco são armazenados em **volume gerenciado pelo Docker**:

```yaml
volumes:
  - postgres_data:/var/lib/postgresql/data
```

**Localização no Mac:**
```
/var/lib/docker/volumes/dashboard-ai-v2_postgres_data/_data/
```

**Fluxo de Dados:**
```
Backend grava dados
      ↓
PostgreSQL escreve em: /var/lib/postgresql/data/ (container)
      ↓
Docker monta volume em: /var/lib/docker/volumes/.../\_data/ (Mac)
      ↓
Dados PERSISTEM mesmo se container for deletado
```

**Dados armazenados:**
- Dashboards e widgets
- Conversas com IA
- Configurações de ES Servers
- LLM Providers (API keys criptografadas)

**Tamanho atual:** ~48.73MB

### Tabela Comparativa

| Item | Tipo | Localização | Persiste? | Hot Reload? |
|------|------|-------------|-----------|-------------|
| Código Backend | Bind Mount | `./backend` | ✅ Sim (no Git) | ✅ Sim |
| Código Frontend | Local | `./frontend` | ✅ Sim (no Git) | ✅ Sim |
| Dados PostgreSQL | Volume | Docker volume | ✅ Sim | N/A |
| Dados Redis | Container | Volátil | ❌ Não | N/A |
| Logs | Container | Volátil | ❌ Não | N/A |

## ⚙️ Ambiente de Desenvolvimento

### Configuração Inicial

#### 1. Clone do Repositório
```bash
git clone <repo-url>
cd dashboard-ai-v2
```

#### 2. Configurar Variáveis de Ambiente

**Backend (.env):**
```bash
cp backend/.env.example backend/.env
```

Edite `backend/.env`:
```bash
# PostgreSQL (container)
DATABASE_URL=postgresql+asyncpg://dashboard_user:dashboard_pass_secure_2024@postgres:5432/dashboard_ai

# Elasticsearch (externo)
ES_URL=http://host.docker.internal:9200

# Redis (container)
REDIS_URL=redis://redis:6379/0
REDIS_ENABLED=False

# Encryption (gere uma chave com: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
ENCRYPTION_KEY=<sua-chave-fernet>

# LLM Providers (configure via UI depois)
```

**Frontend (.env):**
```bash
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

#### 3. Iniciar Stack Docker
```bash
# Subir PostgreSQL, Redis e Backend
docker compose up -d

# Verificar status
docker compose ps

# Aguardar healthchecks
# ✅ postgres: healthy
# ✅ redis: healthy
# ✅ backend: up
```

#### 4. Iniciar Frontend
```bash
cd frontend
npm install
npm run dev

# Acesse: http://localhost:5173
```

### Fluxo de Desenvolvimento

```
┌────────────────────────────────────────────────────┐
│                                                    │
│  1. docker compose up -d                          │
│     ↓                                              │
│  2. Containers sobem (postgres, redis, backend)   │
│     ↓                                              │
│  3. Backend conecta PostgreSQL + Elasticsearch    │
│     ↓                                              │
│  4. cd frontend && npm run dev                    │
│     ↓                                              │
│  5. Desenvolvimento:                               │
│                                                    │
│     Backend:                                       │
│     • Edite código em ./backend/                  │
│     • uvicorn detecta mudança e recarrega         │
│     • Logs: docker compose logs -f backend        │
│                                                    │
│     Frontend:                                      │
│     • Edite código em ./frontend/                 │
│     • Vite HMR atualiza browser instantaneamente  │
│     • Logs no terminal npm run dev                │
│                                                    │
│  6. Testar:                                        │
│     • http://localhost:5173 (frontend)            │
│     • http://localhost:8000/docs (API docs)       │
│     • http://localhost:8000/health (health check) │
│                                                    │
└────────────────────────────────────────────────────┘
```

## 🔧 Comandos Úteis

### Docker Compose

```bash
# Subir stack
docker compose up -d

# Parar stack (mantém dados)
docker compose down

# Parar e APAGAR dados (cuidado!)
docker compose down -v

# Ver logs
docker compose logs -f
docker compose logs -f backend

# Status dos containers
docker compose ps

# Reiniciar serviço específico
docker compose restart backend

# Rebuild backend (após mudar Dockerfile)
docker compose build backend
docker compose up -d backend

# Remover containers órfãos
docker compose down --remove-orphans
```

### Acesso aos Containers

```bash
# Shell no backend
docker exec -it dashboard-ai-backend bash

# PostgreSQL CLI
docker exec -it dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai

# Redis CLI
docker exec -it dashboard-ai-redis redis-cli

# Ver variáveis de ambiente do backend
docker exec dashboard-ai-backend env

# Executar comando no backend
docker exec dashboard-ai-backend python -c "print('Hello')"
```

### Banco de Dados

```bash
# Backup PostgreSQL
docker exec dashboard-ai-postgres pg_dump -U dashboard_user dashboard_ai > backup.sql

# Restaurar backup
cat backup.sql | docker exec -i dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai

# Ver tabelas
docker exec -it dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai -c "\dt"

# Query SQL
docker exec -it dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai -c "SELECT * FROM dashboards;"
```

### Migrations

```bash
# Aplicar migrations
docker exec dashboard-ai-backend alembic upgrade head

# Criar nova migration
docker exec dashboard-ai-backend alembic revision --autogenerate -m "add new table"

# Ver histórico
docker exec dashboard-ai-backend alembic history

# Rollback
docker exec dashboard-ai-backend alembic downgrade -1
```

### Monitoramento

```bash
# Uso de recursos
docker stats

# Tamanho dos volumes
docker system df -v

# Inspecionar volume PostgreSQL
docker volume inspect dashboard-ai-v2_postgres_data

# Ver networks
docker network ls
docker network inspect dashboard-ai-v2_dashboard-network

# Logs do sistema Docker
docker system events
```

## 🐛 Troubleshooting

### Container não inicia

**Problema:** Backend não sobe após `docker compose up -d`

**Soluções:**
```bash
# 1. Ver logs de erro
docker compose logs backend

# 2. Verificar healthchecks
docker compose ps

# 3. Reconstruir imagem
docker compose build backend --no-cache
docker compose up -d backend

# 4. Verificar conflitos de porta
lsof -i :8000
```

### Dados não persistem

**Problema:** Dados do PostgreSQL desaparecem após reiniciar

**Verificar:**
```bash
# Volume existe?
docker volume ls | grep postgres_data

# Dados no volume?
docker volume inspect dashboard-ai-v2_postgres_data

# Se volume sumiu, restaurar backup
cat backup.sql | docker exec -i dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai
```

### Hot Reload não funciona

**Problema:** Edições no código não recarregam backend

**Soluções:**
```bash
# 1. Verificar bind mount
docker exec dashboard-ai-backend ls -la /app

# 2. Verificar comando uvicorn
docker compose ps backend
# Deve ter: uvicorn app.main:socket_app --host 0.0.0.0 --port 8000 --reload

# 3. Reiniciar container
docker compose restart backend
```

### Elasticsearch não conecta

**Problema:** Backend não consegue acessar Elasticsearch

**Verificar:**
```bash
# 1. ES está rodando?
curl http://localhost:9200

# 2. Container consegue acessar host.docker.internal?
docker exec dashboard-ai-backend ping -c 1 host.docker.internal

# 3. Verificar .env
docker exec dashboard-ai-backend env | grep ES_URL

# 4. Testar conexão do container
docker exec dashboard-ai-backend curl http://host.docker.internal:9200
```

### Erro de permissão no volume

**Problema:** Permission denied ao tentar escrever em volume

**Solução:**
```bash
# Verificar permissões
docker exec dashboard-ai-postgres ls -la /var/lib/postgresql/data

# Recriar volume
docker compose down -v
docker compose up -d
```

### Ports já em uso

**Problema:** `Bind for 0.0.0.0:8000 failed: port is already allocated`

**Solução:**
```bash
# Encontrar processo usando porta
lsof -i :8000

# Matar processo
kill -9 <PID>

# Ou mudar porta no docker-compose.yml
ports:
  - "8001:8000"  # Mac:8001 -> Container:8000
```

### Migrations falhando

**Problema:** `alembic upgrade head` retorna erro

**Soluções:**
```bash
# 1. Verificar conexão DB
docker exec dashboard-ai-backend python -c "from app.db.database import test_connection; import asyncio; asyncio.run(test_connection())"

# 2. Ver status migrations
docker exec dashboard-ai-backend alembic current

# 3. Forçar recreate das tabelas (cuidado!)
docker exec -it dashboard-ai-postgres psql -U dashboard_user -d dashboard_ai -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
docker exec dashboard-ai-backend alembic upgrade head
```

### Frontend não conecta no Backend

**Problema:** Erro CORS ou conexão recusada

**Verificar:**
```bash
# 1. Backend está rodando?
curl http://localhost:8000/health

# 2. CORS configurado?
# Verificar backend/.env: CORS_ORIGINS=["http://localhost:5173"]

# 3. Frontend .env correto?
# Verificar frontend/.env: VITE_API_URL=http://localhost:8000
```

## 📊 Métricas e Performance

### Uso de Recursos

```bash
# Ver consumo em tempo real
docker stats --no-stream

# Exemplo de saída:
CONTAINER ID   NAME                    CPU %     MEM USAGE / LIMIT
abc123         dashboard-ai-backend    2.50%     150MiB / 2GiB
def456         dashboard-ai-postgres   0.50%     45MiB / 2GiB
ghi789         dashboard-ai-redis      0.10%     10MiB / 2GiB
```

**Consumo típico:**
- Backend: ~150MB RAM, 2-5% CPU
- PostgreSQL: ~45MB RAM, 0.5% CPU
- Redis: ~10MB RAM, 0.1% CPU

**Total:** ~200MB RAM, ~3-6% CPU

### Otimizações Aplicadas

1. ✅ **Removido frontend do Docker** - HMR mais rápido
2. ✅ **Removido ES/Kibana duplicados** - ~1.5GB RAM economizado
3. ✅ **Imagens Alpine** - Imagens menores
4. ✅ **Multi-stage builds** - Dockerfile otimizado
5. ✅ **Healthchecks** - Dependências garantidas
6. ✅ **Restart policies** - Recuperação automática

## 🔐 Segurança

### Boas Práticas

1. **Nunca commitar .env**
   ```bash
   # Já está em .gitignore
   backend/.env
   frontend/.env
   ```

2. **Criptografia de senhas**
   - ES passwords: Fernet encryption
   - LLM API keys: Fernet + PBKDF2 (100k iterations)

3. **Secrets em variáveis de ambiente**
   ```bash
   # Gerar chave Fernet
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

   # Adicionar em .env
   ENCRYPTION_KEY=<chave-gerada>
   ```

4. **Network isolation**
   - Containers na mesma network privada
   - Apenas portas necessárias expostas

## 📚 Referências

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [PostgreSQL Docker](https://hub.docker.com/_/postgres)
- [Redis Docker](https://hub.docker.com/_/redis)
- [Vite](https://vitejs.dev/)

---

**Versão:** 2.0.0
**Última Atualização:** 07/11/2025
**Autores:** Dashboard AI Team + Claude Code
