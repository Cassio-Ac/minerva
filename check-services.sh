#!/bin/bash

# Script de Verificação de Serviços do Dashboard AI v2

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔍 Dashboard AI v2 - Status dos Serviços${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cd "$(dirname "$0")"

# Docker
echo -n "🐳 Docker Desktop:          "
if docker info > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
    exit 1
fi

# PostgreSQL
echo -n "🗄️  PostgreSQL (5432):       "
if docker exec dashboard-ai-postgres pg_isready -U dashboard_user -q 2>/dev/null; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
fi

# Redis
echo -n "🔴 Redis (6379):            "
if docker exec dashboard-ai-redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
fi

# Backend
echo -n "🚀 Backend API (8000):      "
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
fi

# Elasticsearch
echo -n "🔍 Elasticsearch (9200):    "
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
fi

# Frontend
echo -n "🎨 Frontend Vite (5173):    "
if curl -s http://localhost:5173 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Rodando${NC}"
else
    echo -e "${RED}❌ Não está rodando${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📊 Status dos Containers Docker:${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
docker-compose ps
echo ""

echo -e "${BLUE}💾 Uso de Volumes:${NC}"
echo ""
docker volume ls | grep dashboard-ai
echo ""

echo -e "${BLUE}🌐 URLs dos Serviços:${NC}"
echo -e "   Backend API:  ${GREEN}http://localhost:8000${NC}"
echo -e "   API Docs:     ${GREEN}http://localhost:8000/docs${NC}"
echo -e "   Frontend:     ${GREEN}http://localhost:5173${NC}"
echo -e "   Elasticsearch:${GREEN}http://localhost:9200${NC}"
echo ""
