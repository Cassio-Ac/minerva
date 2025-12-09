# 🔌 Ports Reference - Intelligence Platform

**ATENÇÃO**: Este arquivo é a **ÚNICA FONTE DE VERDADE** para portas do projeto.
**NUNCA ALTERE ESTAS PORTAS SEM ATUALIZAR ESTE DOCUMENTO PRIMEIRO!**

---

## 📊 PostgreSQL Databases

### Intelligence Platform Database (PRINCIPAL)
- **Porta**: `5433`
- **Database**: `intelligence_platform`
- **User**: `intelligence_user`
- **Password**: `intelligence_pass_secure_2024`
- **Connection String**:
  ```
  postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform
  ```
- **Uso**:
  - Todos os dados da Intelligence Platform
  - IOCs (1.143 entries)
  - MISP Feeds
  - Galaxy Clusters (100 threat-actors)
  - Dashboards, Users, Conversations
  - SSO Configuration (Microsoft)

### Dashboard AI Database (LEGADO - NÃO USAR)
- **Porta**: `5432`
- **Database**: `dashboard_ai`
- **User**: `dashboard_user`
- **Password**: `dashboard_pass_secure_2024`
- **⚠️ ATENÇÃO**: Este database é de um projeto antigo. **NÃO USAR PARA INTELLIGENCE PLATFORM!**

---

## 🖥️ Application Servers

### Backend API
- **Porta**: `8001`
- **URL**: `http://localhost:8001`
- **Tipo**: FastAPI + Socket.IO
- **Docs**: `http://localhost:8001/docs`
- **Health**: `http://localhost:8001/health`

### Frontend
- **Porta**: `5180`
- **URL**: `http://localhost:5180`
- **Tipo**: React + Vite
- **Ambiente**: Development

---

## 🔍 Elasticsearch

### Elasticsearch Server
- **Porta**: `9200`
- **URL**: `http://localhost:9200`
- **Tipo**: Elasticsearch 8.x
- **Auth**: Opcional (configurável)

---

## 📝 Configuração Correta

### Backend .env
```bash
# PostgreSQL - Intelligence Platform
DATABASE_URL=postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform

# API Server
HOST=0.0.0.0
PORT=8001

# Elasticsearch
ES_URL=http://localhost:9200
```

### Frontend .env
```bash
VITE_API_URL=http://localhost:8001
```

---

## ⚠️ ERROS COMUNS A EVITAR

### ❌ ERRO #1: Usar porta 5432 (dashboard_ai)
**ERRADO**: postgresql+asyncpg://...@localhost:5432/dashboard_ai
**CORRETO**: postgresql+asyncpg://...@localhost:5433/intelligence_platform

### ❌ ERRO #2: Fallback incorreto em app/db/database.py
O fallback DEVE apontar para intelligence_platform:5433

### ❌ ERRO #3: Confundir databases
- dashboard_ai em 5432 = LEGADO, NÃO USAR
- intelligence_platform em 5433 = CORRETO, SEMPRE USAR

---

## 🎯 Checklist de Verificação

- [ ] A porta é 5433?
- [ ] O database é intelligence_platform?
- [ ] O user é intelligence_user?
- [ ] O password é intelligence_pass_secure_2024?
- [ ] O fallback em app/db/database.py está correto?

---

**ÚLTIMA ATUALIZAÇÃO**: 2025-01-21
**MANTIDO POR**: Claude Code
