#!/bin/bash
##
# SETUP NATIVE - Intelligence Platform
# =====================================
# Instala dependências para execução nativa no Mac
#
# Autor: Angello Cassio
# Data: 2025-11-18
##

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================================"
echo "🔧 INTELLIGENCE PLATFORM - SETUP NATIVO"
echo -e "======================================================================${NC}"
echo ""

# ==================== 1. VERIFICAR PYTHON ====================
echo -e "${BLUE}1️⃣  Verificando Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}   ❌ Python 3 não encontrado!${NC}"
    echo -e "${YELLOW}   Instale Python 3.11+ antes de continuar.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}   ✅ Python $PYTHON_VERSION encontrado${NC}"
echo ""

# ==================== 2. CRIAR VIRTUAL ENVIRONMENT ====================
echo -e "${BLUE}2️⃣  Configurando Virtual Environment...${NC}"
cd "$PROJECT_DIR/backend"

if [ ! -d "venv" ]; then
    echo -e "${YELLOW}   📦 Criando virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}   ✅ Virtual environment criado${NC}"
else
    echo -e "${GREEN}   ✅ Virtual environment já existe${NC}"
fi
echo ""

# ==================== 3. INSTALAR DEPENDÊNCIAS BACKEND ====================
echo -e "${BLUE}3️⃣  Instalando dependências do Backend...${NC}"
source venv/bin/activate

echo -e "${YELLOW}   📦 Instalando requirements.txt...${NC}"
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

echo -e "${GREEN}   ✅ Dependências do backend instaladas${NC}"
echo ""

# ==================== 4. VERIFICAR FRONTEND ====================
echo -e "${BLUE}4️⃣  Verificando Frontend...${NC}"
cd "$PROJECT_DIR/frontend"

if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}   📦 Instalando dependências do frontend...${NC}"
    npm install
    echo -e "${GREEN}   ✅ Dependências do frontend instaladas${NC}"
else
    echo -e "${GREEN}   ✅ Dependências do frontend já instaladas${NC}"
fi
echo ""

# ==================== 5. VERIFICAR .env.local ====================
echo -e "${BLUE}5️⃣  Verificando configuração...${NC}"
cd "$PROJECT_DIR/backend"

if [ ! -f ".env.local" ]; then
    echo -e "${RED}   ❌ Arquivo .env.local não encontrado!${NC}"
    echo -e "${YELLOW}   Copie o arquivo .env.local.example e configure.${NC}"
    exit 1
fi

echo -e "${GREEN}   ✅ Arquivo .env.local encontrado${NC}"
echo ""

echo -e "${GREEN}======================================================================"
echo "✅ SETUP CONCLUÍDO!"
echo -e "======================================================================${NC}"
echo ""
echo -e "${YELLOW}📝 Próximos passos:${NC}"
echo -e "   1. Configure seu .env.local se necessário"
echo -e "   2. Execute: ./start-dev.sh"
echo ""
