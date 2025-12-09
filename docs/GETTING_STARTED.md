# 🚀 Getting Started - Dashboard AI v2.0

Guia rápido para começar a desenvolver com Dashboard AI v2.0

---

## 📋 Pré-requisitos

Antes de começar, certifique-se de ter instalado:

- **Node.js** 18+ ([Download](https://nodejs.org/))
- **Python** 3.11+ ([Download](https://www.python.org/))
- **Docker** & **Docker Compose** ([Download](https://www.docker.com/))
- **Git** ([Download](https://git-scm.com/))

---

## 🏁 Início Rápido (Docker)

A forma mais rápida de rodar o projeto é usando Docker Compose:

### 1. Clone o Projeto

```bash
cd dashboard-ai-v2
```

### 2. Configure Variáveis de Ambiente

```bash
# Backend
cp backend/.env.example backend/.env

# Frontend
cp frontend/.env.example frontend/.env
```

### 3. Inicie os Serviços

```bash
docker-compose up
```

Aguarde até todos os serviços estarem prontos:
- ✅ Elasticsearch: http://localhost:9200
- ✅ Backend FastAPI: http://localhost:8000
- ✅ Frontend React: http://localhost:5173

### 4. Acesse a Aplicação

Abra o navegador em: **http://localhost:5173**

---

## 💻 Desenvolvimento Local (sem Docker)

Para desenvolvimento local com hot-reload:

### 1. Elasticsearch

Inicie apenas o Elasticsearch via Docker:

```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0
```

Ou use um Elasticsearch existente.

### 2. Backend (Python/FastAPI)

```bash
cd backend

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt

# Configurar .env
cp .env.example .env
# Editar .env com suas configurações

# Executar servidor
uvicorn app.main:app --reload --port 8000
```

Backend estará em: **http://localhost:8000**

API Docs: **http://localhost:8000/docs** (Swagger)

### 3. Frontend (React/TypeScript)

```bash
cd frontend

# Instalar dependências
npm install

# Configurar .env
cp .env.example .env

# Executar servidor de desenvolvimento
npm run dev
```

Frontend estará em: **http://localhost:5173**

---

## 🧪 Testando a API

### Via Swagger UI

Acesse http://localhost:8000/docs e teste os endpoints interativamente.

### Via cURL

```bash
# Health check
curl http://localhost:8000/health

# Listar dashboards
curl http://localhost:8000/api/v1/dashboards

# Criar dashboard
curl -X POST http://localhost:8000/api/v1/dashboards \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Meu Dashboard",
    "index": "vazamentos",
    "description": "Dashboard de teste"
  }'
```

---

## 📁 Estrutura do Projeto

```
dashboard-ai-v2/
├── backend/              # FastAPI backend
│   ├── app/
│   │   ├── api/         # Endpoints REST
│   │   ├── models/      # Modelos Pydantic
│   │   ├── services/    # Lógica de negócio
│   │   └── main.py      # Entry point
│   └── requirements.txt
│
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/  # Componentes React
│   │   ├── pages/       # Páginas
│   │   ├── services/    # API client
│   │   ├── stores/      # Zustand stores
│   │   └── types/       # TypeScript types
│   └── package.json
│
└── docker-compose.yml    # Orquestração
```

---

## 🛠️ Comandos Úteis

### Backend

```bash
# Formatar código
black app/

# Lint
flake8 app/

# Type check
mypy app/

# Testes
pytest tests/
```

### Frontend

```bash
# Formatar código
npm run lint

# Type check
npm run type-check

# Build para produção
npm run build

# Preview build
npm run preview
```

### Docker

```bash
# Subir serviços
docker-compose up

# Subir em background
docker-compose up -d

# Parar serviços
docker-compose down

# Ver logs
docker-compose logs -f

# Rebuild containers
docker-compose up --build
```

---

## 🔧 Troubleshooting

### Backend não inicia

**Erro**: `ModuleNotFoundError`

**Solução**: Certifique-se de estar no ambiente virtual e ter instalado as dependências:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Frontend não inicia

**Erro**: `Cannot find module`

**Solução**: Reinstale as dependências:
```bash
rm -rf node_modules package-lock.json
npm install
```

### Elasticsearch não conecta

**Erro**: `Connection refused`

**Solução**: Verifique se o Elasticsearch está rodando:
```bash
curl http://localhost:9200
```

Se não estiver, inicie o container:
```bash
docker start elasticsearch
```

### Porta já em uso

**Erro**: `Address already in use`

**Solução**: Mude a porta no `.env` ou mate o processo:
```bash
# Ver processo usando a porta
lsof -i :8000

# Matar processo
kill -9 <PID>
```

---

## 📚 Próximos Passos

1. **Explore a API**: http://localhost:8000/docs
2. **Leia a documentação**: [ARCHITECTURE.md](ARCHITECTURE.md)
3. **Implemente features**: Veja [TODO.md](TODO.md)
4. **Contribua**: Veja [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🆘 Precisa de Ajuda?

- 📖 [Documentação Completa](README.md)
- 🏗️ [Arquitetura](ARCHITECTURE.md)
- 💬 [Issues](https://github.com/seu-repo/issues)

---

**Dashboard AI v2.0** | Desenvolvido com 💙
