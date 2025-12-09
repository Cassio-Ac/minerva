# Executando Intelligence Platform e Dashboard AI v2 Simultaneamente

Este guia explica como configurar e executar **Intelligence Platform** e **Dashboard AI v2** ao mesmo tempo, sem conflitos de portas ou recursos Docker.

---

## 🎯 Cenário

Você quer manter ambos os projetos rodando simultaneamente:
- **Dashboard AI v2**: `/Users/angellocassio/Downloads/dashboard-ai-v2` (agregador de KPIs)
- **Intelligence Platform**: `/Users/angellocassio/Documents/intelligence-platform` (análise de inteligência)

Ambos compartilham a mesma stack (FastAPI, React, PostgreSQL, Redis), então precisamos:
1. ✅ Portas diferentes
2. ✅ Nomes de containers diferentes
3. ✅ Networks Docker diferentes
4. ✅ Databases PostgreSQL separadas
5. ✅ Volumes Docker separados

---

## 📊 Mapeamento de Portas

### Dashboard AI v2 (projeto original)
| Serviço | Porta Host | Container |
|---------|------------|-----------|
| Backend FastAPI | `8000` | `dashboard-ai-backend:8000` |
| Frontend React | `5173` | (desenvolvimento local) |
| PostgreSQL | `5432` | `dashboard-ai-postgres:5432` |
| Redis | `6379` | `dashboard-ai-redis:6379` |
| Elasticsearch | `9200` | (externo - host) |

### Intelligence Platform (novo projeto)
| Serviço | Porta Host | Container |
|---------|------------|-----------|
| Backend FastAPI | `8001` | `intelligence-platform-backend:8000` |
| Frontend React | `5174` | (desenvolvimento local) |
| PostgreSQL | `5433` | `intelligence-platform-postgres:5432` |
| Redis | `6380` | `intelligence-platform-redis:6379` |
| Elasticsearch | `9200` | (externo - compartilhado com Dashboard AI) |

---

## ⚙️ Configuração do Intelligence Platform

### 1. Atualizar `docker-compose.yml`

O arquivo já está configurado com nomes únicos, mas precisamos ajustar as portas:

```yaml
services:
  # PostgreSQL (metadados do sistema)
  postgres:
    image: postgres:16-alpine
    container_name: intelligence-platform-postgres
    ports:
      - "5433:5432"  # ⬅️ Porta 5433 no host (evita conflito com Dashboard AI)
    environment:
      POSTGRES_USER: intelligence_user
      POSTGRES_PASSWORD: intelligence_pass_secure_2024
      POSTGRES_DB: intelligence_platform
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --lc-collate=C --lc-ctype=C"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - intelligence-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U intelligence_user -d intelligence_platform"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  # Redis (cache e pub/sub)
  redis:
    image: redis:7-alpine
    container_name: intelligence-platform-redis
    ports:
      - "6380:6379"  # ⬅️ Porta 6380 no host (evita conflito)
    networks:
      - intelligence-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  # Backend FastAPI
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: intelligence-platform-backend
    ports:
      - "8001:8000"  # ⬅️ Porta 8001 no host (evita conflito)
    env_file:
      - ./backend/.env
    environment:
      # Elasticsearch externo (compartilhado)
      - ES_URL=http://host.docker.internal:9200
      # Redis interno (container)
      - REDIS_URL=redis://redis:6379/0
      # PostgreSQL interno (container)
      - DATABASE_URL=postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@postgres:5432/intelligence_platform
      # MCP Configuration
      - MCP_DATA_DIR=/mcp-data
    volumes:
      - ./backend:/app
      - mcp_data:/mcp-data
      - /tmp:/tmp
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - intelligence-network
    extra_hosts:
      - "host.docker.internal:host-gateway"
    command: uvicorn app.main:socket_app --host 0.0.0.0 --port 8000 --reload
    restart: unless-stopped

volumes:
  postgres_data:
    driver: local
  mcp_data:
    driver: local

networks:
  intelligence-network:
    driver: bridge
```

### 2. Atualizar `backend/.env`

```bash
# Database (IMPORTANTE: porta 5433 no host, mas 5432 dentro do container)
DATABASE_URL=postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform

# Redis (porta 6380 no host)
REDIS_URL=redis://localhost:6380/0

# Elasticsearch (compartilhado entre os dois projetos)
ES_URL=http://localhost:9200

# API Keys (configurar suas próprias)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# Security
SECRET_KEY=your-secret-key-intelligence-platform
ENCRYPTION_KEY=your-encryption-key-base64
```

### 3. Atualizar `frontend/.env` (se necessário)

```bash
# Backend API URL - porta 8001
VITE_API_URL=http://localhost:8001
VITE_WS_URL=ws://localhost:8001/ws
```

### 4. Atualizar `start-dashboard.sh` (se existir)

```bash
#!/bin/bash

echo "🚀 Iniciando Intelligence Platform..."
echo ""

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verificar se Docker está rodando
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker não está rodando!${NC}"
    echo "Por favor, inicie o Docker Desktop e tente novamente."
    exit 1
fi

# Verificar se Dashboard AI v2 está rodando
if docker ps | grep -q "dashboard-ai"; then
    echo -e "${YELLOW}⚠️  Dashboard AI v2 está rodando em paralelo${NC}"
    echo "   - Dashboard AI: http://localhost:8000"
    echo "   - Intelligence Platform: http://localhost:8001"
    echo ""
fi

# Iniciar serviços
echo -e "${GREEN}📦 Iniciando containers...${NC}"
docker-compose up -d

# Aguardar serviços ficarem prontos
echo ""
echo -e "${GREEN}⏳ Aguardando serviços iniciarem...${NC}"
sleep 5

# Verificar status
echo ""
echo -e "${GREEN}📊 Status dos serviços:${NC}"
docker-compose ps

echo ""
echo -e "${GREEN}✅ Intelligence Platform iniciado!${NC}"
echo ""
echo "🔗 URLs de acesso:"
echo "   - Backend API: http://localhost:8001"
echo "   - API Docs: http://localhost:8001/docs"
echo "   - PostgreSQL: localhost:5433"
echo "   - Redis: localhost:6380"
echo ""
echo "📝 Logs:"
echo "   docker-compose logs -f backend"
echo ""
echo "🛑 Para parar:"
echo "   docker-compose down"
```

---

## 🚀 Como Executar os Dois Projetos

### Opção 1: Executar ambos com Docker Compose

**Terminal 1 - Dashboard AI v2:**
```bash
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose up
```

**Terminal 2 - Intelligence Platform:**
```bash
cd /Users/angellocassio/Documents/intelligence-platform
docker-compose up
```

### Opção 2: Usando scripts (recomendado)

**Dashboard AI v2:**
```bash
cd /Users/angellocassio/Downloads/dashboard-ai-v2
./start-dashboard.sh
```

**Intelligence Platform:**
```bash
cd /Users/angellocassio/Documents/intelligence-platform
./start-dashboard.sh
```

---

## 🌐 URLs de Acesso

### Dashboard AI v2
- Backend: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Frontend: http://localhost:5173 (se rodar npm run dev)

### Intelligence Platform
- Backend: http://localhost:8001
- API Docs: http://localhost:8001/docs
- Frontend: http://localhost:5174 (se rodar npm run dev)

### Recursos Compartilhados
- Elasticsearch: http://localhost:9200 (compartilhado entre os dois)

---

## 🗂️ Isolamento de Dados

### Databases PostgreSQL (SEPARADAS)
- **Dashboard AI v2**: `dashboard_ai` na porta 5432
- **Intelligence Platform**: `intelligence_platform` na porta 5433

### Redis (SEPARADAS)
- **Dashboard AI v2**: porta 6379
- **Intelligence Platform**: porta 6380

### Docker Networks (SEPARADAS)
- **Dashboard AI v2**: `dashboard-network`
- **Intelligence Platform**: `intelligence-network`

### Elasticsearch (COMPARTILHADO)
- Ambos projetos podem usar o mesmo Elasticsearch
- Índices diferentes evitam conflitos:
  - Dashboard AI: `dashboards`, `vazamentos`, etc
  - Intelligence Platform: `intelligence_reports`, `data_sources`, etc

---

## 🔧 Troubleshooting

### Erro: "Port already in use"

Se ainda houver conflito de portas:

1. **Verificar portas em uso:**
   ```bash
   # macOS
   lsof -i :8000
   lsof -i :8001
   lsof -i :5432
   lsof -i :5433
   ```

2. **Parar containers do Dashboard AI:**
   ```bash
   cd /Users/angellocassio/Downloads/dashboard-ai-v2
   docker-compose down
   ```

3. **Parar containers do Intelligence Platform:**
   ```bash
   cd /Users/angellocassio/Documents/intelligence-platform
   docker-compose down
   ```

### Erro: "Container name already exists"

```bash
# Listar todos os containers (incluindo parados)
docker ps -a | grep -E "dashboard-ai|intelligence-platform"

# Remover containers parados
docker rm intelligence-platform-postgres
docker rm intelligence-platform-redis
docker rm intelligence-platform-backend
```

### Erro: "Network already exists"

```bash
# Listar networks
docker network ls | grep -E "dashboard|intelligence"

# Remover network (se não estiver em uso)
docker network rm intelligence-network
```

### Limpar tudo e recomeçar

```bash
# Intelligence Platform
cd ~/Documents/intelligence-platform
docker-compose down -v  # Remove containers E volumes
docker-compose up --build  # Rebuild e reinicia

# Dashboard AI v2
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose down -v
docker-compose up --build
```

---

## 📊 Verificar o que está rodando

### Listar todos os containers

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Output esperado quando ambos estão rodando:

```
NAMES                               STATUS              PORTS
intelligence-platform-backend       Up 2 minutes        0.0.0.0:8001->8000/tcp
intelligence-platform-postgres      Up 2 minutes        0.0.0.0:5433->5432/tcp
intelligence-platform-redis         Up 2 minutes        0.0.0.0:6380->6379/tcp
dashboard-ai-backend                Up 10 minutes       0.0.0.0:8000->8000/tcp
dashboard-ai-postgres               Up 10 minutes       0.0.0.0:5432->5432/tcp
dashboard-ai-redis                  Up 10 minutes       0.0.0.0:6379->6379/tcp
```

### Verificar logs

**Dashboard AI:**
```bash
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose logs -f backend
```

**Intelligence Platform:**
```bash
cd ~/Documents/intelligence-platform
docker-compose logs -f backend
```

---

## 💡 Dicas

### 1. Elasticsearch compartilhado

Se ambos projetos usam Elasticsearch:
- Use **índices diferentes** para evitar conflitos
- Dashboard AI: `dashboards*`, `vazamentos*`
- Intelligence Platform: `intelligence_*`, `data_sources_*`

### 2. Desenvolvimento Frontend

Rode os frontends em portas diferentes:

**Dashboard AI:**
```bash
cd /Users/angellocassio/Downloads/dashboard-ai-v2/frontend
npm run dev  # Porta 5173 por padrão
```

**Intelligence Platform:**
```bash
cd ~/Documents/intelligence-platform/frontend
npm run dev -- --port 5174  # Força porta 5174
```

Ou edite `frontend/vite.config.ts`:

```typescript
export default defineConfig({
  server: {
    port: 5174,  // ⬅️ Porta diferente
    host: '0.0.0.0'
  },
  // ...
})
```

### 3. Scripts úteis

**Criar alias no shell** (`~/.zshrc` ou `~/.bashrc`):

```bash
# Dashboard AI v2
alias dash-ai-start="cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose up -d"
alias dash-ai-stop="cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose down"
alias dash-ai-logs="cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose logs -f"

# Intelligence Platform
alias intel-start="cd ~/Documents/intelligence-platform && docker-compose up -d"
alias intel-stop="cd ~/Documents/intelligence-platform && docker-compose down"
alias intel-logs="cd ~/Documents/intelligence-platform && docker-compose logs -f"

# Ambos
alias both-start="dash-ai-start && intel-start"
alias both-stop="dash-ai-stop && intel-stop"
```

Depois:
```bash
source ~/.zshrc  # ou ~/.bashrc

# Usar
both-start
both-stop
```

---

## 🎯 Checklist Rápido

Antes de iniciar os dois projetos, verifique:

- [ ] Docker Desktop está rodando
- [ ] Portas 8000, 8001, 5432, 5433, 6379, 6380 estão livres
- [ ] `docker-compose.yml` do Intelligence Platform usa portas corretas (8001, 5433, 6380)
- [ ] `backend/.env` do Intelligence Platform aponta para porta 5433 (PostgreSQL)
- [ ] Nomes de containers são diferentes (dashboard-ai-* vs intelligence-platform-*)
- [ ] Networks Docker são diferentes (dashboard-network vs intelligence-network)

Tudo ok? Execute:

```bash
# Terminal 1
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose up

# Terminal 2
cd ~/Documents/intelligence-platform
docker-compose up
```

---

**Última atualização**: 2025-01-14  
**Testado com**: Docker 24+, macOS (Apple Silicon)
