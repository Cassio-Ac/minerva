#!/bin/bash

# Script para Parar Dashboard AI v2

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🛑 Dashboard AI v2 - Parando Serviços${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cd "$(dirname "$0")"

# 1. Parar containers Docker
echo -e "${BLUE}📦 Parando containers Docker...${NC}"
docker-compose down

echo -e "${GREEN}✅ Containers parados${NC}"
echo ""

# 2. Verificar se frontend ainda está rodando
echo -e "${BLUE}🎨 Verificando frontend...${NC}"
if lsof -i :5173 > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Frontend ainda está rodando na porta 5173${NC}"
    echo -e "${YELLOW}   Para parar, pressione Ctrl+C no terminal do frontend${NC}"
    echo ""
    echo -e "${YELLOW}   Ou force a parada com:${NC}"
    echo -e "${YELLOW}   kill -9 \$(lsof -t -i:5173)${NC}"
else
    echo -e "${GREEN}✅ Frontend não está rodando${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✨ Serviços Docker parados com sucesso!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}💡 Nota:${NC}"
echo -e "   • Os dados estão salvos em volumes Docker"
echo -e "   • Para iniciar novamente: ${GREEN}./start-dashboard.sh${NC}"
echo -e "   • Para remover TUDO (incluindo dados): ${YELLOW}docker-compose down -v${NC}"
echo ""
