# Intelligence Platform - Native Mac Setup

## Overview

A plataforma foi migrada de uma arquitetura totalmente Docker para uma **arquitetura híbrida** que executa serviços nativamente no Mac para melhor controle de rotinas diárias e scripts.

## Arquitetura

### Infraestrutura (Docker)
- **PostgreSQL** - porta 5433
- **Redis** - porta 6380

### Aplicação (Nativo Mac)
- **Backend (FastAPI)** - porta 8000
- **Celery Worker** - processamento de tarefas
- **Celery Beat** - agendamento de tarefas
- **Frontend (React/Vite)** - porta 5180

## Arquivos Criados

### 1. `docker-compose-infra.yml`
Docker Compose simplificado contendo apenas PostgreSQL e Redis.

### 2. `backend/.env.local`
Configuração de variáveis de ambiente para execução nativa com conexões localhost.

### 3. `setup-native.sh`
Script para instalar todas as dependências:
- Cria virtual environment Python
- Instala requirements.txt do backend
- Instala node_modules do frontend
- Valida configuração

###  4. `start-dev.sh`
Script mestre para iniciar todos os serviços:
1. Inicia infraestrutura Docker (PostgreSQL, Redis)
2. Aguarda serviços ficarem prontos
3. Executa migrations do banco
4. Inicia Backend (FastAPI com uvicorn)
5. Inicia Celery Worker
6. Inicia Celery Beat
7. Inicia Frontend (Vite dev server)

Todos os PIDs são salvos em `.pids` para controle.

### 5. `stop-dev.sh`
Script para parar todos os serviços:
- Lê PIDs do arquivo `.pids`
- Mata processos nativos
- Para infraestrutura Docker
- Remove arquivo `.pids`

## Dependências Atualizadas

### Removidas
- `psycopg2-binary==2.9.9` - Removido devido a incompatibilidade com Python 3.13, usando `asyncpg` exclusivamente

### Atualizadas
- `pillow==11.0.0` - Atualizado para suporte a Python 3.13 (era 10.1.0)

## Como Usar

### Primeira Vez (Setup)

```bash
# 1. Executar setup (instalar dependências)
./setup-native.sh
```

### Iniciar Plataforma

```bash
# 2. Iniciar todos os serviços
./start-dev.sh
```

Acesse:
- **Frontend**: http://localhost:5180
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### Parar Plataforma

```bash
# Parar todos os serviços
./stop-dev.sh
```

### Monitorar Logs

```bash
# Backend
tail -f backend/logs/backend.log

# Celery Worker
tail -f backend/logs/celery-worker.log

# Celery Beat
tail -f backend/logs/celery-beat.log

# Frontend
tail -f frontend/logs/frontend.log
```

## Estrutura de Logs

```
backend/logs/
├── backend.log         # FastAPI/Uvicorn
├── celery-worker.log   # Processamento de tarefas
└── celery-beat.log     # Agendamento de tarefas

frontend/logs/
└── frontend.log        # Vite dev server
```

## Vantagens da Arquitetura Nativa

1. **Controle Total**: Acesso direto aos processos e logs
2. **Desenvolvimento Rápido**: Hot reload nativo sem overhead de Docker
3. **Debugging Fácil**: Attach direto ao processo Python ou Node
4. **Scripts Diários**: Fácil integração com cron ou scripts customizados
5. **Performance**: Execução nativa sem virtualização
6. **Recursos**: Menor uso de memória e CPU

## Infraestrutura Isolada

PostgreSQL e Redis permanecem no Docker para:
- Isolamento de dados
- Portabilidade
- Facilidade de backup/restore
- Não poluir sistema com serviços de infraestrutura

## Próximos Passos

1. ✅ Infraestrutura Docker configurada
2. ✅ Scripts de gerenciamento criados
3. ✅ Dependências atualizadas para Python 3.13
4. ⏳ Finalizar instalação de dependências (`setup-native.sh`)
5. 🔜 Testar `start-dev.sh`
6. 🔜 Organizar scripts de coleta Telegram para rotinas diárias
7. 🔜 Configurar tarefas agendadas (cron/Celery Beat)

## Troubleshooting

### Erro ao iniciar: "Virtual environment não encontrado"
```bash
./setup-native.sh
```

### Porta já em uso
Verificar se há serviços rodando:
```bash
lsof -i :8000  # Backend
lsof -i :5180  # Frontend
lsof -i :5433  # PostgreSQL
lsof -i :6380  # Redis
```

### Containers Docker não param
```bash
docker ps  # Listar containers
docker stop <container_id>  # Parar manualmente
```

### Limpar tudo e recomeçar
```bash
./stop-dev.sh
rm -rf backend/venv backend/logs frontend/logs
docker compose -f docker-compose-infra.yml down -v
./setup-native.sh
./start-dev.sh
```

## Notas Importantes

- O setup usa **Python 3.11.14** (melhor compatibilidade com dependências)
- Virtual environment em `backend/venv`
- Logs rotacionam automaticamente
- PostgreSQL persiste dados em volume Docker
- Redis em modo append-only para durabilidade

### Por que Python 3.11?

Python 3.13 é muito recente e alguns pacotes críticos ainda não têm suporte completo:
- `pydantic-core` - Incompatibilidade ao compilar extensões Rust
- `asyncpg` - Problemas ao compilar extensões C
- `greenlet` - Problemas ao compilar extensões C

Python 3.11 tem suporte maduro para todas as dependências do projeto

---

**Autor**: Angello Cassio
**Data**: 2025-11-18
**Versão**: 1.0
