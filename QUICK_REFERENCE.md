# 🚀 Quick Reference - Intelligence Platform

## 📍 URLs Importantes

```
✅ USAR SEMPRE:
Frontend:  http://localhost:5180
Backend:   http://localhost:8001
API Docs:  http://localhost:8001/docs

❌ NUNCA USAR (Dashboard AI):
Frontend:  http://localhost:5173
Backend:   http://localhost:8000
```

## 🔐 Credenciais

```
Username: admin
Password: admin
```

## 🔌 Portas do Sistema

| Serviço | Intelligence Platform | Dashboard AI (Evitar) |
|---------|----------------------|----------------------|
| Frontend | **5180** ✅ | 5173 ❌ |
| Backend | **8001** ✅ | 8000 ❌ |
| PostgreSQL | **5433** ✅ | 5432 ❌ |
| Redis | **6380** ✅ | 6379 ❌ |
| Elasticsearch | **9200** (compartilhado) | 9200 (compartilhado) |

## ⚡ Comandos Rápidos

### Iniciar Sistema

```bash
cd /Users/angellocassio/Documents/intelligence-platform
./start-dev.sh
```

### Parar Sistema

```bash
./stop-dev.sh
```

### Verificar Status

```bash
# Verificar portas
lsof -i :5180 -i :8001 -i :5433

# Testar backend
curl http://localhost:8001/

# Testar login
cd backend
PYTHONPATH=$PWD venv/bin/python3 test_backend_quick.py
```

### Logs

```bash
# Backend logs (tempo real)
cd backend
PYTHONPATH=$PWD venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

# Elasticsearch
curl 'http://localhost:9200/_cat/indices?v'
```

## 🐛 Problemas Comuns

### WebSocket Error (IGNORAR)

```
❌ WebSocket connection error: websocket error
```

**Status:** ⚠️ Não afeta funcionalidade
**Ação:** Ignorar - sistema funciona normalmente

### Elasticsearch Não Aparece no Chat

**Causa:** Configurado para Docker ao invés de localhost
**Solução:** Settings → ES Servers → Trocar para `http://localhost:9200`

### MISP Feeds Vazios

**Verificar:**
1. Backend correto: `http://localhost:8001`
2. Login feito com `admin/admin`
3. Não está acessando Dashboard AI (porta 5173)

### Login Não Funciona

```bash
# Verificar se backend está rodando
curl http://localhost:8001/

# Deve retornar:
# {"app":"Minerva - Intelligence Platform","version":"1.0.0"}
```

## ✅ Checklist de Validação

Após iniciar o sistema, verificar:

- [ ] Frontend rodando em http://localhost:5180
- [ ] Backend rodando em http://localhost:8001
- [ ] Login com `admin/admin` funciona
- [ ] Dashboard carrega lista de dashboards
- [ ] Chat mostra índices do Elasticsearch
- [ ] CTI → MISP Feeds mostra 14 feeds
- [ ] WebSocket com erro (OK, ignorar)

## 📂 Estrutura de Arquivos

```
intelligence-platform/
├── backend/
│   ├── app/
│   │   ├── main.py              # Entry point
│   │   ├── cti/                 # CTI module
│   │   │   ├── api/             # API endpoints
│   │   │   ├── services/        # Business logic
│   │   │   └── models/          # Database models
│   │   └── websocket/           # WebSocket config
│   ├── .env                     # Environment vars
│   ├── requirements.txt         # Python deps
│   └── test_*.py                # Test scripts
├── frontend/
│   ├── src/
│   │   ├── pages/               # Pages
│   │   ├── services/            # API clients
│   │   └── stores/              # State management
│   └── .env                     # Frontend config
├── TROUBLESHOOTING.md           # Detailed guide
├── QUICK_REFERENCE.md           # This file
└── README.md                    # Project docs
```

## 🔧 Configurações Importantes

### Backend (.env)

```env
PORT=8002                        # Mas usa 8001 no uvicorn
DATABASE_URL=postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform
ES_URL=http://localhost:9200
REDIS_URL=redis://localhost:6380/0
```

### Frontend (.env)

```env
VITE_API_URL=http://localhost:8001
```

## 🆘 Emergência

### Sistema não responde

```bash
# Parar tudo
pkill -f uvicorn
pkill -f "vite.*5180"

# Reiniciar
cd /Users/angellocassio/Documents/intelligence-platform
./start-dev.sh
```

### Dashboard AI interferindo

```bash
# Parar Docker do Dashboard AI
cd ~/Downloads/dashboard-ai-v2
docker-compose down

# Verificar
docker ps  # Não deve mostrar containers
lsof -i :8000  # Não deve retornar nada
```

### Banco de dados errado

```bash
# Verificar connection string
grep DATABASE_URL backend/.env

# Deve ter: localhost:5433/intelligence_platform
# NÃO pode ter: localhost:5432/dashboard_ai
```

---

**Para mais detalhes, ver:** [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
