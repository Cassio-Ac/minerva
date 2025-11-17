#!/bin/bash

# Script de Inicialização do Dashboard AI v2
# Inicia todos os serviços necessários

# Cores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🚀 Dashboard AI v2 - Inicialização${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Mudar para diretório do projeto
cd "$(dirname "$0")"

# 1. Verificar se Docker está rodando
echo -e "${BLUE}🐳 Verificando Docker...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker não está rodando!${NC}"
    echo -e "${YELLOW}   Abrindo Docker Desktop...${NC}"
    open -a Docker
    echo -e "${YELLOW}   Aguardando Docker iniciar (30s)...${NC}"
    sleep 30
fi
echo -e "${GREEN}✅ Docker está rodando${NC}"
echo ""

# 2. Iniciar containers Docker Compose
echo -e "${BLUE}📦 Iniciando containers (PostgreSQL, Redis, Backend)...${NC}"
docker compose up -d

# Aguardar containers ficarem healthy
echo -e "${YELLOW}⏱️  Aguardando serviços ficarem prontos...${NC}"
sleep 5

# 3. Verificar status dos containers
echo ""
echo -e "${BLUE}🔍 Status dos containers:${NC}"
docker compose ps
echo ""

# 4. Verificar saúde dos serviços
echo -e "${BLUE}🏥 Verificando saúde dos serviços...${NC}"

# PostgreSQL
if docker exec dashboard-ai-postgres pg_isready -U dashboard_user -q 2>/dev/null; then
    echo -e "${GREEN}✅ PostgreSQL: Pronto${NC}"
else
    echo -e "${RED}❌ PostgreSQL: Não está pronto${NC}"
fi

# Redis
if docker exec dashboard-ai-redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}✅ Redis: Pronto${NC}"
else
    echo -e "${RED}❌ Redis: Não está pronto${NC}"
fi

# Backend
echo -e "${YELLOW}   Aguardando backend iniciar (10s)...${NC}"
sleep 10

if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend: Pronto (http://localhost:8000)${NC}"
else
    echo -e "${YELLOW}⚠️  Backend: Ainda iniciando...${NC}"
fi

echo ""

# 5. Verificar Elasticsearch (externo)
echo -e "${BLUE}🔍 Verificando Elasticsearch (externo)...${NC}"
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Elasticsearch: Rodando (http://localhost:9200)${NC}"
else
    echo -e "${RED}❌ Elasticsearch: NÃO está rodando!${NC}"
    echo -e "${YELLOW}   Execute: brew services start elasticsearch${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✨ Backend iniciado com sucesso!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}🌐 URLs dos Serviços:${NC}"
echo -e "   Backend API:  ${GREEN}http://localhost:8000${NC}"
echo -e "   Docs API:     ${GREEN}http://localhost:8000/docs${NC}"
echo -e "   PostgreSQL:   ${GREEN}localhost:5432${NC}"
echo -e "   Redis:        ${GREEN}localhost:6379${NC}"
echo ""
echo -e "${BLUE}📱 Iniciando Frontend (Vite)...${NC}"
echo -e "${YELLOW}   Abrindo em nova janela do terminal...${NC}"
echo ""

# 6. Iniciar frontend
cd frontend

# Abrir nova janela do Terminal para o frontend
osascript -e 'tell application "Terminal" to do script "cd '"$(pwd)"' && npm run dev"'

# Ou, se preferir rodar no mesmo terminal (vai travar aqui):
# npm run dev

echo -e "${GREEN}✅ Frontend será iniciado em nova janela do terminal${NC}"
echo -e "   URL: ${GREEN}http://localhost:5173${NC}"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 Dashboard AI v2 iniciado com sucesso!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}💡 Comandos úteis:${NC}"
echo -e "   Parar tudo:         ${YELLOW}docker compose down${NC}"
echo -e "   Ver logs backend:   ${YELLOW}docker compose logs -f backend${NC}"
echo -e "   Status containers:  ${YELLOW}docker compose ps${NC}"
echo ""
