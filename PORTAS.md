# Configuração de Portas - Intelligence Platform

## ⚠️ PORTAS OCUPADAS - NÃO USAR

Estas portas são usadas pelo **Dashboard AI** (projeto separado) e **NÃO devem ser usadas** neste projeto:

- **5173** - Frontend Vite (Dashboard AI)
- **8000** - Backend FastAPI (Dashboard AI)
- **5432** - PostgreSQL (Dashboard AI)
- **6379** - Redis (Dashboard AI)

## ✅ Portas Usadas - Intelligence Platform

Este projeto usa as seguintes portas:

### Frontend
- **5180** - Vite Dev Server (React)
  - Configurado em: `frontend/vite.config.ts`
  - Variável: `VITE_API_URL=http://localhost:8002`

### Backend
- **8002** - FastAPI Server
  - Configurado em: `backend/app/core/config.py`
  - Comando: `uvicorn app.main:app --host 0.0.0.0 --port 8002`

### Infraestrutura (Docker)
- **5433** - PostgreSQL (mapeado de 5432 interno)
  - Container: `intelligence-platform-postgres`
  - Arquivo: `docker-compose-infra.yml`
  - Database: `intelligence_platform`
  - User: `intelligence_user`

- **6380** - Redis (mapeado de 6379 interno)
  - Container: `intelligence-platform-redis`
  - Arquivo: `docker-compose-infra.yml`

### Elasticsearch
- **9200** - Elasticsearch HTTP
- **9300** - Elasticsearch Transport

## Diferenças entre Projetos

### Intelligence Platform (este projeto)
- Backend: porta **8002**
- PostgreSQL: porta **5433**
- Redis: porta **6380**
- Frontend: porta **5180**
- **NÃO tem SSO**

### Dashboard AI (projeto separado)
- Backend: porta **8000**
- PostgreSQL: porta **5432**
- Redis: porta **6379**
- Frontend: porta **5173**
- **TEM SSO** (Entra ID/LDAP)

## Como Iniciar o Projeto

### 1. Infraestrutura (Docker)
```bash
docker compose -f docker-compose-infra.yml up -d
```

### 2. Backend
```bash
cd backend
PYTHONPATH=$PWD venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

### 3. Frontend
```bash
cd frontend
npm run dev
# Abre em http://localhost:5180
```

## Configuração de CORS

O backend está configurado para aceitar requisições de:
- `http://localhost:5174`
- `http://localhost:5180` ✅ (usado por este projeto)
- `http://localhost:3000`
