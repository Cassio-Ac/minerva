#!/bin/bash
##
# START DEVELOPMENT - Intelligence Platform
# ==========================================
# Inicia toda a infraestrutura e serviços nativamente no Mac
#
# Autor: Angello Cassio
# Data: 2025-11-18
##

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIDS_FILE="$PROJECT_DIR/.pids"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================"
echo "🚀 INTELLIGENCE PLATFORM - STARTING DEVELOPMENT ENVIRONMENT"
echo -e "======================================================================${NC}"
echo ""

# Verificar se já está rodando
if [ -f "$PIDS_FILE" ]; then
    echo -e "${YELLOW}⚠️  Serviços já parecem estar rodando. Execute ./stop-dev.sh primeiro.${NC}"
    exit 1
fi

# Limpar arquivo de PIDs
> "$PIDS_FILE"

# ==================== 1. INFRAESTRUTURA (Docker) ====================
echo -e "${BLUE}1️⃣  Iniciando infraestrutura (PostgreSQL, Redis)...${NC}"
cd "$PROJECT_DIR"
docker compose -f docker-compose-infra.yml up -d

# Aguardar serviços ficarem prontos
echo -e "${YELLOW}   ⏳ Aguardando PostgreSQL...${NC}"
until docker compose -f docker-compose-infra.yml exec -T postgres pg_isready -U intelligence_user > /dev/null 2>&1; do
    sleep 1
done
echo -e "${GREEN}   ✅ PostgreSQL ready!${NC}"

echo -e "${YELLOW}   ⏳ Aguardando Redis...${NC}"
until docker compose -f docker-compose-infra.yml exec -T redis redis-cli ping > /dev/null 2>&1; do
    sleep 1
done
echo -e "${GREEN}   ✅ Redis ready!${NC}"

echo ""

# ==================== 2. BACKEND (FastAPI) ====================
echo -e "${BLUE}2️⃣  Iniciando Backend (FastAPI)...${NC}"
cd "$PROJECT_DIR/backend"

# Verificar se virtual environment existe
if [ ! -d "venv" ]; then
    echo -e "${RED}   ❌ Virtual environment não encontrado!${NC}"
    echo -e "${YELLOW}   Execute ./setup-native.sh primeiro para instalar dependências.${NC}"
    exit 1
fi

# Ativar virtual environment
source venv/bin/activate

# Verificar se .env.local existe
if [ ! -f ".env.local" ]; then
    echo -e "${RED}   ❌ Arquivo .env.local não encontrado!${NC}"
    echo -e "${YELLOW}   Copie o arquivo .env.local.example e configure.${NC}"
    exit 1
fi

# Carregar variáveis de ambiente
export $(cat .env.local | grep -v '^#' | xargs)

# Validar variáveis críticas
echo -e "${YELLOW}   🔍 Validando configurações...${NC}"

if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "your-super-secret-key-change-this-in-production-2024" ]; then
    echo -e "${RED}   ⚠️  WARNING: SECRET_KEY não está configurada! Use uma chave segura.${NC}"
fi

if [ -z "$ENCRYPTION_KEY" ] || [ "$ENCRYPTION_KEY" = "your-encryption-key-generate-with-fernet" ]; then
    echo -e "${RED}   ⚠️  WARNING: ENCRYPTION_KEY não está configurada! Gere uma chave Fernet.${NC}"
fi

# Verificar Elasticsearch
if [ ! -z "$ES_URL" ]; then
    echo -e "${YELLOW}   🔍 Verificando Elasticsearch...${NC}"
    if curl -s "$ES_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}   ✅ Elasticsearch acessível em $ES_URL${NC}"
    else
        echo -e "${YELLOW}   ⚠️  Elasticsearch não acessível em $ES_URL (continuando mesmo assim)${NC}"
    fi
fi

# Criar diretórios necessários
echo -e "${YELLOW}   📁 Verificando diretórios...${NC}"
mkdir -p telegram_sessions mcp-data logs
echo -e "${GREEN}   ✅ Diretórios criados/verificados${NC}"

# Executar migrations
echo -e "${YELLOW}   🔄 Executando migrations...${NC}"
export PYTHONPATH="$PROJECT_DIR/backend"
alembic upgrade head

# Verificar se migrations rodaram com sucesso
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ Migrations executadas com sucesso${NC}"
else
    echo -e "${RED}   ❌ ERRO ao executar migrations!${NC}"
    echo -e "${YELLOW}   Verifique se o PostgreSQL está acessível e as credenciais estão corretas.${NC}"
    exit 1
fi

# Verificar estrutura do banco de dados
echo -e "${YELLOW}   🔍 Verificando estrutura do banco...${NC}"
python check_database.py
if [ $? -ne 0 ]; then
    echo -e "${RED}   ❌ Problemas encontrados na estrutura do banco!${NC}"
    echo -e "${YELLOW}   Continuando mesmo assim, mas verifique os warnings acima.${NC}"
fi

# Iniciar backend em background
echo -e "${YELLOW}   🚀 Iniciando servidor FastAPI...${NC}"
uvicorn app.main:socket_app --host 0.0.0.0 --port 8001 --reload > logs/backend.log 2>&1 &
BACKEND_PID=$!
echo "backend:$BACKEND_PID" >> "$PIDS_FILE"
echo -e "${GREEN}   ✅ Backend started (PID: $BACKEND_PID)${NC}"
echo -e "${BLUE}      http://localhost:8001${NC}"

echo ""

# ==================== 3. CELERY WORKER ====================
echo -e "${BLUE}3️⃣  Iniciando Celery Worker...${NC}"
cd "$PROJECT_DIR/backend"
celery -A app.celery_app worker --loglevel=info > logs/celery-worker.log 2>&1 &
CELERY_WORKER_PID=$!
echo "celery-worker:$CELERY_WORKER_PID" >> "$PIDS_FILE"
echo -e "${GREEN}   ✅ Celery Worker started (PID: $CELERY_WORKER_PID)${NC}"

echo ""

# ==================== 4. CELERY BEAT ====================
echo -e "${BLUE}4️⃣  Iniciando Celery Beat (scheduler)...${NC}"
cd "$PROJECT_DIR/backend"
celery -A app.celery_app beat --loglevel=info > logs/celery-beat.log 2>&1 &
CELERY_BEAT_PID=$!
echo "celery-beat:$CELERY_BEAT_PID" >> "$PIDS_FILE"
echo -e "${GREEN}   ✅ Celery Beat started (PID: $CELERY_BEAT_PID)${NC}"

echo ""

# ==================== 5. FRONTEND (React/Vite) ====================
echo -e "${BLUE}5️⃣  Iniciando Frontend (React/Vite)...${NC}"
cd "$PROJECT_DIR/frontend"
npm run dev -- --host 0.0.0.0 --port 5180 > logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "frontend:$FRONTEND_PID" >> "$PIDS_FILE"
echo -e "${GREEN}   ✅ Frontend started (PID: $FRONTEND_PID)${NC}"
echo -e "${BLUE}      http://localhost:5180${NC}"

echo ""
echo -e "${GREEN}======================================================================"
echo "✅ TODOS OS SERVIÇOS INICIADOS COM SUCESSO!"
echo -e "======================================================================${NC}"
echo ""
echo -e "${YELLOW}📝 Logs disponíveis em:${NC}"
echo -e "   Backend:        tail -f backend/logs/backend.log"
echo -e "   Celery Worker:  tail -f backend/logs/celery-worker.log"
echo -e "   Celery Beat:    tail -f backend/logs/celery-beat.log"
echo -e "   Frontend:       tail -f frontend/logs/frontend.log"
echo ""
echo -e "${YELLOW}🛑 Para parar todos os serviços:${NC}"
echo -e "   ./stop-dev.sh"
echo ""
