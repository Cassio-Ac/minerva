# 🔧 Troubleshooting Guide - Intelligence Platform

## 📋 Índice

1. [Portas do Sistema](#portas-do-sistema)
2. [Problemas Comuns](#problemas-comuns)
3. [Erros Resolvidos](#erros-resolvidos)
4. [Validações Importantes](#validações-importantes)

---

## 🔌 Portas do Sistema

### ✅ Portas do Intelligence Platform (USAR SEMPRE)

| Serviço | Porta | URL | Descrição |
|---------|-------|-----|-----------|
| **Frontend** | `5180` | http://localhost:5180 | Interface React (Vite) |
| **Backend** | `8001` | http://localhost:8001 | API FastAPI |
| **PostgreSQL** | `5433` | localhost:5433 | Banco de metadados (isolado) |
| **Redis** | `6380` | localhost:6380 | Cache e pub/sub (isolado) |
| **Elasticsearch** | `9200` | http://localhost:9200 | Dados de negócio (COMPARTILHADO) |

### ❌ Portas do Dashboard AI (NUNCA USAR)

| Serviço | Porta | Conflito |
|---------|-------|----------|
| Frontend | `5173` | ⚠️ NÃO ACESSAR - É do projeto antigo! |
| Backend | `8000` | ⚠️ Pode rodar em Docker, ignorar |
| PostgreSQL | `5432` | ⚠️ Banco do projeto antigo |
| Redis | `6379` | ⚠️ Cache do projeto antigo |

### 🔍 Como Verificar Portas em Uso

```bash
# Verificar todas as portas do projeto
lsof -i :5180 -i :8001 -i :5433 -i :6380 -i :9200

# Verificar portas conflitantes (Dashboard AI)
lsof -i :5173 -i :8000 -i :5432 -i :6379
```

---

## 🐛 Problemas Comuns

### 1. WebSocket Connection Refused (403/NS_ERROR)

**Sintomas:**
```
❌ WebSocket connection error: websocket error
NS_ERROR_WEBSOCKET_CONNECTION_REFUSED
ws://localhost:8001/socket.io/?EIO=4&transport=websocket
```

**Status:** ⚠️ **NÃO AFETA FUNCIONALIDADE**

**Causa:**
- Socket.IO está configurado mas rejeitando conexões
- Pode ser problema de CORS ou ordem de inicialização

**Impacto:**
- WebSocket é usado apenas para **sincronização em tempo real** (colaboração)
- Sistema funciona 100% sem WebSocket
- Dashboards, CTI, Chat funcionam normalmente

**Solução Temporária:**
- Ignorar o erro por enquanto
- Sistema está funcional para todas as operações principais

**Solução Definitiva (TODO):**
- Investigar ordem de middleware no `app/main.py`
- Verificar se Socket.IO precisa de autenticação
- Testar com logging habilitado

---

### 2. Login Não Funciona / Erro de Import

**Sintomas:**
```python
ImportError: cannot import name 'MISPIOCModel' from 'app.cti.models.misp_feed'
```

**Causa:**
- Nome de classe errado em `app/cti/services/otx_bulk_enrichment_service.py`
- Arquivo estava importando `MISPIOCModel` mas o correto é `MISPIoC`

**Solução:**
```python
# ❌ ERRADO
from app.cti.models.misp_feed import MISPIOCModel

# ✅ CORRETO
from app.cti.models.misp_ioc import MISPIoC
```

**Arquivo Corrigido:** `app/cti/services/otx_bulk_enrichment_service.py:11`

---

### 3. Elasticsearch Configurado para Docker (Versão Errada)

**Sintomas:**
- Chat não mostra índices do Elasticsearch
- MISP Feeds aparecem vazios
- Frontend conectado mas sem dados

**Causa:**
- Configuração do Elasticsearch Server apontando para **versão Docker**
- Deveria apontar para **localhost nativo** (porta 9200)

**Como Verificar:**
1. Acessar: http://localhost:5180/settings (ou equivalente)
2. Verificar configuração de **Elasticsearch Servers**
3. Conferir se a URL é `http://localhost:9200` (nativo)

**Solução:**
1. No frontend, acessar configurações de **ES Servers**
2. Trocar de "Docker Elasticsearch" para "Local Elasticsearch"
3. Verificar URL: `http://localhost:9200`
4. Salvar e recarregar página

**Validação:**
```bash
# Verificar se Elasticsearch está acessível
curl http://localhost:9200

# Listar índices disponíveis
curl 'http://localhost:9200/_cat/indices?v' | head -20
```

---

### 4. Confusão Entre Projetos (Dashboard AI vs Intelligence Platform)

**Sintomas:**
- Ver dados do projeto antigo (6 dashboards de teste)
- Login funciona mas dados errados
- MISP Feeds vazios mesmo com backend funcionando

**Causa:**
- **Ambos os frontends rodando simultaneamente**
- Acidentalmente acessar porta errada

**Como Identificar:**

| Indicador | Intelligence Platform | Dashboard AI (ERRADO) |
|-----------|----------------------|----------------------|
| URL | http://localhost:5180 | http://localhost:5173 |
| Título | "Minerva - Intelligence Platform" | "Dashboard AI" |
| Dashboards | Novos (CTI, MISP) | 6 dashboards de teste |
| Backend | Port 8001 | Port 8000 |
| Database | Port 5433 | Port 5432 |

**Solução:**
1. **Sempre verificar a porta** antes de trabalhar: `http://localhost:5180`
2. Verificar título da página no navegador
3. Se necessário, parar o Dashboard AI:
   ```bash
   # Parar Docker do Dashboard AI
   cd ~/Downloads/dashboard-ai-v2
   docker-compose down
   ```

---

### 5. MISP Feed "Not Implemented Yet"

**Sintomas:**
```
POST http://localhost:8001/api/v1/cti/misp/feeds/test/botvrij
[HTTP/1.1 400 Bad Request]
API Error: { detail: "Feed type 'botvrij' not implemented yet" }
```

**Causa:**
- Feed `botvrij` ainda não implementado no backend
- Frontend tenta testar feed que não existe

**Feeds Disponíveis:**
```python
# Ver: backend/app/cti/services/misp_feed_sync_service.py
IMPLEMENTED_FEEDS = [
    'circl_osint',
    'feodotracker_browse',
    'feodotracker_ip_blocklist',
    'sslbl_abuse',
    'urlhaus',
    'threatfox',
    'blocklist_de',
    'malware_bazaar',
    'otx_pulses',
    'misp_warninglists',
    'abuse_ch_ransomware',
    'abuse_ch_urlhaus_urls',
    'abuse_ch_threatfox',
    'vxvault'
]
```

**Solução:**
- Ignorar feeds não implementados
- Usar apenas feeds da lista acima
- Se necessário, implementar novo feed seguindo padrão existente

---

## ✅ Erros Resolvidos

### 1. Import Error - MISPIOCModel

**Data:** 2025-11-22
**Arquivo:** `app/cti/services/otx_bulk_enrichment_service.py`
**Solução:** Corrigido import de `MISPIOCModel` para `MISPIoC`

### 2. WebSocket CORS Configuration

**Data:** 2025-11-22
**Arquivo:** `app/websocket/manager.py:13-25`
**Solução:** Adicionadas origens específicas ao `cors_allowed_origins`

```python
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=[
        'http://localhost:5174',
        'http://localhost:5180',
        'http://localhost:3000',
        'http://127.0.0.1:5174',
        'http://127.0.0.1:5180',
        'http://127.0.0.1:3000'
    ],
    logger=True,
    engineio_logger=True
)
```

**Status:** Configurado mas ainda com erro 403 (não afeta funcionalidade)

### 3. Elasticsearch Server Configuration

**Data:** 2025-11-22
**Problema:** Configurado para versão Docker ao invés de localhost nativo
**Solução:** Trocar para `http://localhost:9200` nas configurações do frontend

---

## ✔️ Validações Importantes

### Checklist de Inicialização

Antes de começar a trabalhar, sempre verificar:

```bash
# 1. Verificar se está no diretório correto
pwd
# Deve ser: /Users/angellocassio/Documents/intelligence-platform

# 2. Verificar portas em uso
lsof -i :5180 -i :8001 -i :5433 | grep LISTEN
# Deve mostrar: Frontend (5180) e Backend (8001)

# 3. Verificar backends rodando
curl -s http://localhost:8001/ | jq .app
# Deve retornar: "Minerva - Intelligence Platform"

curl -s http://localhost:8000/ 2>/dev/null | jq .app
# Se retornar "Dashboard AI", PARAR o Docker do projeto antigo!

# 4. Verificar database correto
grep DATABASE_URL backend/.env
# Deve mostrar: postgresql+asyncpg://intelligence_user:...@localhost:5433/intelligence_platform

# 5. Verificar Elasticsearch
curl -s http://localhost:9200 | jq .version.number
# Deve retornar versão do Elasticsearch (ex: "8.x.x")
```

### Checklist de Funcionalidades

Testar no navegador (http://localhost:5180):

- [ ] **Login:** Credenciais `admin/admin` funcionam
- [ ] **Dashboard:** Lista de dashboards carrega
- [ ] **Chat:** Elasticsearch Server selecionado (localhost:9200)
- [ ] **Chat:** Índices aparecem no dropdown
- [ ] **CTI → MISP Feeds:** Lista de 14 feeds aparece
- [ ] **CTI → Actors:** Lista de threat actors carrega
- [ ] **CTI → Families:** Malware families aparecem
- [ ] **CTI → Techniques:** MITRE ATT&CK techniques carregam

### Script de Teste Rápido

```bash
# Executar de: /Users/angellocassio/Documents/intelligence-platform/backend
PYTHONPATH=$PWD venv/bin/python3 test_backend_quick.py
```

**Saída esperada:**
```
✅ Backend está rodando!
✅ Login OK - Tempo: <1s
✅ 1+ chaves OTX cadastradas
✅ Total de chaves: 1+
✅ Overview obtido
```

---

## 🔐 Credenciais e Configurações

### Login Padrão

```
Username: admin
Password: admin
```

### Banco de Dados

```env
# Intelligence Platform (CORRETO)
DATABASE_URL=postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform

# Dashboard AI (NÃO USAR)
DATABASE_URL=postgresql+asyncpg://dashboard_user:dashboard_pass@localhost:5432/dashboard_ai
```

### Elasticsearch

```env
# SEMPRE usar localhost nativo
ES_URL=http://localhost:9200
ES_USERNAME=
ES_PASSWORD=
```

---

## 📞 Suporte

### Logs Importantes

```bash
# Backend logs
tail -f /Users/angellocassio/Documents/intelligence-platform/backend/logs/app.log

# Verificar processos rodando
ps aux | grep uvicorn
ps aux | grep node

# Docker do Dashboard AI (se necessário parar)
docker ps
docker-compose -f ~/Downloads/dashboard-ai-v2/docker-compose.yml down
```

### Comandos de Emergência

```bash
# Parar tudo e reiniciar limpo
cd /Users/angellocassio/Documents/intelligence-platform
./stop-dev.sh
sleep 3
./start-dev.sh

# Ou manual:
# 1. Parar backend
pkill -f "uvicorn app.main"

# 2. Parar frontend
pkill -f "vite.*5180"

# 3. Reiniciar
cd backend && PYTHONPATH=$PWD venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload &
cd frontend && npm run dev &
```

---

## 📝 Notas de Desenvolvimento

### Arquitetura de Portas

```
┌─────────────────────────────────────────────────────────┐
│         Intelligence Platform (Projeto Novo)            │
├─────────────────────────────────────────────────────────┤
│ Frontend (5180) → Backend (8001) → PostgreSQL (5433)   │
│                                  ↘ Redis (6380)         │
│                                  ↘ Elasticsearch (9200) │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│         Dashboard AI (Projeto Antigo - Evitar)          │
├─────────────────────────────────────────────────────────┤
│ Frontend (5173) → Backend (8000) → PostgreSQL (5432)   │
│                                  ↘ Redis (6379)         │
│                                  ↘ Elasticsearch (9200) │
└─────────────────────────────────────────────────────────┘

⚠️ ATENÇÃO: Elasticsearch (9200) é COMPARTILHADO!
```

### Isolamento de Dados

- **PostgreSQL:** Totalmente isolado (portas diferentes: 5432 vs 5433)
- **Redis:** Totalmente isolado (portas diferentes: 6379 vs 6380)
- **Elasticsearch:** **COMPARTILHADO** (mesma instância, mesmos índices)

**Implicação:** Os índices do Telegram são os mesmos em ambos os projetos!

---

## 📅 Histórico de Mudanças

| Data | Mudança | Arquivo |
|------|---------|---------|
| 2025-11-22 | Fix import MISPIOCModel → MISPIoC | `otx_bulk_enrichment_service.py` |
| 2025-11-22 | WebSocket CORS origins configurados | `app/websocket/manager.py` |
| 2025-11-22 | Elasticsearch config corrigido | Frontend Settings |

---

**Última atualização:** 2025-11-22
**Versão:** 1.0.0
**Autor:** Claude Code + Angello Cassio
