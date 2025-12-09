#!/bin/bash
##
# STOP DEVELOPMENT - Intelligence Platform
# =========================================
# Para todos os serviços da plataforma
#
# Autor: Angello Cassio
# Data: 2025-11-18
##

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIDS_FILE="$PROJECT_DIR/.pids"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================================"
echo "🛑 INTELLIGENCE PLATFORM - STOPPING ALL SERVICES"
echo -e "======================================================================${NC}"
echo ""

# Verificar se o arquivo de PIDs existe
if [ ! -f "$PIDS_FILE" ]; then
    echo -e "${YELLOW}⚠️  Nenhum serviço parece estar rodando (arquivo .pids não encontrado).${NC}"
    echo -e "${YELLOW}    Vou tentar parar a infraestrutura Docker de qualquer forma...${NC}"
    echo ""
else
    # Ler e matar os processos
    echo -e "${BLUE}📋 Parando serviços nativos...${NC}"
    while IFS=: read -r service pid; do
        if ps -p $pid > /dev/null 2>&1; then
            echo -e "${YELLOW}   🛑 Parando $service (PID: $pid)...${NC}"
            kill $pid 2>/dev/null || kill -9 $pid 2>/dev/null
            echo -e "${GREEN}   ✅ $service parado${NC}"
        else
            echo -e "${YELLOW}   ⚠️  $service (PID: $pid) já estava parado${NC}"
        fi
    done < "$PIDS_FILE"

    # Remover arquivo de PIDs
    rm "$PIDS_FILE"
    echo ""
fi

# Parar infraestrutura Docker
echo -e "${BLUE}🐳 Parando infraestrutura Docker...${NC}"
cd "$PROJECT_DIR"
docker compose -f docker-compose-infra.yml down

echo ""
echo -e "${GREEN}======================================================================"
echo "✅ TODOS OS SERVIÇOS FORAM PARADOS!"
echo -e "======================================================================${NC}"
echo ""
echo -e "${YELLOW}💡 Para iniciar novamente:${NC}"
echo -e "   ./start-dev.sh"
echo ""
