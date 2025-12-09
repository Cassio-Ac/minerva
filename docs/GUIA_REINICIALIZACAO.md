# 🔄 Guia de Reinicialização do Sistema

Este guia explica como garantir que todos os serviços do Dashboard AI v2 sejam iniciados automaticamente após reiniciar o computador.

---

## ✅ Status Atual: Configurado para Auto-Start!

**Boa notícia**: Seu `docker-compose.yml` já está configurado com `restart: unless-stopped` em todos os serviços! Isso significa que:

✅ Containers **reiniciam automaticamente** após reboot do computador
✅ Containers **reiniciam automaticamente** se travarem
✅ Containers **permanecem parados** apenas se você parar manualmente com `docker stop`

---

## 🚀 Como Funciona o Auto-Start

### Política de Restart: `unless-stopped`

```yaml
services:
  postgres:
    restart: unless-stopped  # ✅ Reinicia automaticamente

  redis:
    restart: unless-stopped  # ✅ Reinicia automaticamente

  backend:
    restart: unless-stopped  # ✅ Reinicia automaticamente
```

### Políticas Disponíveis:

| Política | Comportamento |
|----------|---------------|
| `no` | Nunca reinicia (padrão) |
| `always` | Sempre reinicia (mesmo se parado manualmente) |
| `on-failure` | Reinicia apenas se falhar |
| **`unless-stopped`** | **Reinicia sempre, exceto se parado manualmente** ✅ |

---

## 📝 Procedimento Após Reiniciar o Computador

### Opção 1: Deixar Docker Fazer Tudo Automaticamente ⭐ (Recomendado)

Se o **Docker Desktop** estiver configurado para iniciar automaticamente:

1. **Reinicie o computador** 🔄
2. **Aguarde ~30 segundos** ⏱️
3. **Pronto!** Todos os serviços já estão rodando 🎉

**Como verificar se Docker inicia automaticamente**:
```bash
# Mac
# Abra Docker Desktop → Settings → General
# ✅ Marque "Start Docker Desktop when you log in"
```

### Opção 2: Iniciar Manualmente Após Reboot

Se Docker Desktop não inicia automaticamente, você precisa:

```bash
# 1. Abra o Terminal
cd /Users/angellocassio/Downloads/dashboard-ai-v2

# 2. Inicie os containers
docker-compose up -d

# 3. Verifique status
docker-compose ps
```

**Explicação dos comandos**:
- `docker-compose up -d`: Inicia containers em background
- `-d` = "detached" (em background, não trava o terminal)

---

## 🔍 Verificar se Tudo Está Rodando

### Comando Rápido:
```bash
docker-compose ps
```

**Saída esperada** (todos com status `Up`):
```
NAME                      STATUS         PORTS
dashboard-ai-postgres     Up 2 minutes   0.0.0.0:5432->5432/tcp
dashboard-ai-redis        Up 2 minutes   0.0.0.0:6379->6379/tcp
dashboard-ai-backend      Up 2 minutes   0.0.0.0:8000->8000/tcp
```

### Verificar Logs:
```bash
# Ver logs de todos os serviços
docker-compose logs

# Ver logs de um serviço específico
docker-compose logs backend
docker-compose logs postgres
docker-compose logs redis

# Ver logs em tempo real (follow)
docker-compose logs -f backend
```

### Verificar Health:
```bash
# Ver health de todos os containers
docker ps --format "table {{.Names}}\t{{.Status}}"
```

**Saída esperada** (todos com "healthy"):
```
NAMES                     STATUS
dashboard-ai-backend      Up 5 minutes
dashboard-ai-postgres     Up 5 minutes (healthy)
dashboard-ai-redis        Up 5 minutes (healthy)
```

---

## 🖥️ Frontend (Vite)

**IMPORTANTE**: O frontend (Vite) **NÃO está no Docker** e **NÃO inicia automaticamente**.

### Iniciar Frontend Após Reboot:

```bash
# 1. Abrir novo terminal
cd /Users/angellocassio/Downloads/dashboard-ai-v2/frontend

# 2. Iniciar Vite dev server
npm run dev
```

**Saída esperada**:
```
  VITE v5.4.21  ready in 115 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.1.168:5173/
```

### Automatizar Frontend (Opcional)

**Opção 1: Script de Inicialização**

Crie um arquivo `start-dashboard.sh`:

```bash
#!/bin/bash

# Cores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Iniciando Dashboard AI v2...${NC}"

# 1. Iniciar Docker Compose (se não estiver rodando)
echo -e "${BLUE}📦 Verificando Docker containers...${NC}"
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose up -d

# 2. Aguardar backend ficar saudável
echo -e "${BLUE}⏱️  Aguardando backend...${NC}"
sleep 10

# 3. Iniciar frontend
echo -e "${BLUE}🎨 Iniciando frontend...${NC}"
cd frontend
npm run dev

echo -e "${GREEN}✅ Dashboard AI v2 iniciado!${NC}"
```

**Tornar executável**:
```bash
chmod +x start-dashboard.sh
```

**Usar**:
```bash
./start-dashboard.sh
```

**Opção 2: Alias no Shell**

Adicione ao seu `~/.zshrc` ou `~/.bashrc`:

```bash
# Dashboard AI v2
alias start-dashboard='cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose up -d && cd frontend && npm run dev'
alias stop-dashboard='cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose down'
alias status-dashboard='cd /Users/angellocassio/Downloads/dashboard-ai-v2 && docker-compose ps'
```

**Recarregar shell**:
```bash
source ~/.zshrc  # ou source ~/.bashrc
```

**Usar**:
```bash
start-dashboard   # Inicia tudo
stop-dashboard    # Para tudo
status-dashboard  # Verifica status
```

---

## 🗂️ Serviços Externos (Não-Docker)

Alguns serviços **não estão no Docker Compose** e precisam estar rodando separadamente:

### 1. Elasticsearch (Porta 9200)

```bash
# Verificar se está rodando
curl http://localhost:9200

# Se não estiver, iniciar (depende de como você instalou)
# Homebrew:
brew services start elasticsearch

# Manual:
elasticsearch
```

### 2. Kibana (Porta 5601) - Opcional

```bash
# Verificar
curl http://localhost:5601

# Iniciar
brew services start kibana
# ou
kibana
```

---

## 📋 Checklist Completo Após Reboot

Use este checklist para garantir que tudo está funcionando:

```
[ ] 1. Docker Desktop está rodando
[ ] 2. Containers Docker estão Up (docker-compose ps)
[ ] 3. PostgreSQL está healthy
[ ] 4. Redis está healthy
[ ] 5. Backend está respondendo (curl http://localhost:8000/health)
[ ] 6. Elasticsearch está rodando (curl http://localhost:9200)
[ ] 7. Frontend Vite está rodando (http://localhost:5173)
[ ] 8. Consegue fazer login no sistema
```

### Script de Verificação:

```bash
#!/bin/bash

echo "🔍 Verificando serviços..."

# Docker containers
echo -n "Docker containers: "
if docker-compose ps | grep -q "Up"; then
    echo "✅"
else
    echo "❌"
fi

# PostgreSQL
echo -n "PostgreSQL: "
if docker exec dashboard-ai-postgres pg_isready -U dashboard_user -q; then
    echo "✅"
else
    echo "❌"
fi

# Redis
echo -n "Redis: "
if docker exec dashboard-ai-redis redis-cli ping | grep -q "PONG"; then
    echo "✅"
else
    echo "❌"
fi

# Backend
echo -n "Backend: "
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅"
else
    echo "❌"
fi

# Elasticsearch
echo -n "Elasticsearch: "
if curl -s http://localhost:9200 > /dev/null; then
    echo "✅"
else
    echo "❌"
fi

# Frontend
echo -n "Frontend: "
if curl -s http://localhost:5173 > /dev/null; then
    echo "✅"
else
    echo "❌"
fi

echo ""
echo "✨ Verificação completa!"
```

Salve como `check-services.sh`, torne executável e use:

```bash
chmod +x check-services.sh
./check-services.sh
```

---

## ⚠️ Troubleshooting

### Problema: Containers não iniciam após reboot

**Solução 1**: Verificar se Docker Desktop está rodando
```bash
# Abrir Docker Desktop manualmente
open -a Docker
```

**Solução 2**: Iniciar containers manualmente
```bash
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker-compose up -d
```

**Solução 3**: Verificar logs de erro
```bash
docker-compose logs backend
```

### Problema: Porta já em uso

```bash
# Verificar qual processo está usando a porta
lsof -i :8000  # Backend
lsof -i :5432  # PostgreSQL
lsof -i :6379  # Redis
lsof -i :5173  # Frontend

# Matar processo (se necessário)
kill -9 <PID>
```

### Problema: Volume corrompido

```bash
# Parar containers
docker-compose down

# Remover volumes (⚠️ CUIDADO: deleta dados!)
docker-compose down -v

# Recriar tudo
docker-compose up -d

# Rodar migrations novamente
docker exec dashboard-ai-backend alembic upgrade head
```

### Problema: Elasticsearch não conecta

```bash
# Verificar se Elasticsearch está rodando no host
curl http://localhost:9200

# Se não estiver, iniciar
brew services start elasticsearch

# Verificar network
docker exec dashboard-ai-backend ping host.docker.internal
```

---

## 📊 Ordem de Inicialização (Automática)

O Docker Compose já cuida da ordem correta através de `depends_on`:

```
1. PostgreSQL (primeiro)
   ↓ (aguarda healthy)
2. Redis (primeiro)
   ↓ (aguarda healthy)
3. Backend (depende de PostgreSQL e Redis)
```

**HealthChecks garantem ordem**:
- PostgreSQL: `pg_isready` deve retornar sucesso
- Redis: `redis-cli ping` deve retornar PONG
- Backend: só inicia depois dos dois acima estarem healthy

---

## 🎯 Resumo Rápido

### O que você precisa fazer após reiniciar:

#### **Mínimo (se Docker Desktop inicia sozinho)**:
1. Abrir terminal
2. `cd /Users/angellocassio/Downloads/dashboard-ai-v2/frontend`
3. `npm run dev`

#### **Completo (se Docker não inicia sozinho)**:
1. Abrir Docker Desktop
2. Abrir terminal
3. `cd /Users/angellocassio/Downloads/dashboard-ai-v2`
4. `docker-compose up -d`
5. Abrir novo terminal
6. `cd /Users/angellocassio/Downloads/dashboard-ai-v2/frontend`
7. `npm run dev`

#### **Com script (recomendado)**:
1. `./start-dashboard.sh`

---

## 🔐 Dados Persistidos

Seus dados **estão seguros** em volumes Docker persistentes:

```yaml
volumes:
  postgres_data:  # Dados do PostgreSQL (conversas, usuários, etc.)
  mcp_data:       # Dados dos MCPs
```

**Localização física**:
```bash
# Ver onde volumes estão armazenados
docker volume inspect dashboard-ai-v2_postgres_data
docker volume inspect dashboard-ai-v2_mcp_data
```

**Backup de volumes** (opcional):
```bash
# Backup PostgreSQL
docker exec dashboard-ai-postgres pg_dump -U dashboard_user dashboard_ai > backup.sql

# Restaurar
docker exec -i dashboard-ai-postgres psql -U dashboard_user dashboard_ai < backup.sql
```

---

## 🎉 Conclusão

Com a configuração atual (`restart: unless-stopped`), você está protegido! Após reiniciar o computador:

✅ **PostgreSQL** reinicia automaticamente
✅ **Redis** reinicia automaticamente
✅ **Backend** reinicia automaticamente

Você só precisa:
1. Garantir que Docker Desktop esteja configurado para iniciar no login
2. Iniciar o frontend manualmente: `npm run dev`

**Dica**: Crie o script `start-dashboard.sh` para automatizar tudo com um único comando! 🚀
