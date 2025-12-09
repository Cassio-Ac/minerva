# ⚡ Quick Start - Dashboard AI v2.0

**Teste o projeto em 2 minutos!**

---

## 🚀 Opção 1: Docker (Recomendado)

```bash
# 1. Entre no diretório
cd dashboard-ai-v2

# 2. Configure o ambiente
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# 3. Inicie tudo
docker-compose up

# ✅ Pronto! Acesse:
# - Frontend: http://localhost:5173
# - Backend: http://localhost:8000/docs
# - Elasticsearch: http://localhost:9200
```

---

## 💻 Opção 2: Local (Desenvolvimento)

### Terminal 1: Elasticsearch

```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0
```

### Terminal 2: Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

### Terminal 3: Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

---

## ✅ Verificação

**Backend funcionando:**
```bash
curl http://localhost:8000/health
```

Resposta esperada:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "services": {
    "elasticsearch": "checking...",
    "redis": "disabled"
  }
}
```

**Frontend funcionando:**

Acesse http://localhost:5173 e veja a tela de boas-vindas.

---

## 📖 Swagger API

Acesse http://localhost:8000/docs para explorar a API interativamente.

**Endpoints disponíveis:**
- `GET /health` - Health check
- `GET /api/v1/dashboards` - Listar dashboards
- `POST /api/v1/dashboards` - Criar dashboard
- `GET /api/v1/dashboards/{id}` - Obter dashboard
- `PATCH /api/v1/widgets/{id}/position` - Atualizar posição

---

## 🎯 Próximos Passos

1. Explore a API: http://localhost:8000/docs
2. Leia o status: [PROJECT_STATUS.md](PROJECT_STATUS.md)
3. Veja o guia completo: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
4. Desenvolva: Implemente os services do backend

---

**Pronto para começar!** 🚀
