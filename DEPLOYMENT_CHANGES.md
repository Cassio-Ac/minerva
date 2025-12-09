# Minerva Intelligence Platform - Modificações para Deploy em Produção

Este documento lista todas as modificações feitas no código para deploy em servidor de produção (sem Docker).

## Arquivos Modificados

### 1. Backend

#### `backend/alembic.ini`
**Linha 17** - Atualizar URL do banco de dados:
```ini
# DE:
sqlalchemy.url = postgresql+asyncpg://intelligence_user:intelligence_pass_secure_2024@localhost:5433/intelligence_platform

# PARA:
sqlalchemy.url = postgresql+asyncpg://minerva:MinervaDB2024@localhost:5432/minerva_db
```

#### `backend/app/credentials/services/telegram_bot_service.py`
**Linha 51** - Corrigir path hardcoded:
```python
# DE:
DOWNLOADS_DIR = Path("/Users/angellocassio/Documents/intelligence-platform/backend/downloads/credentials")

# PARA:
DOWNLOADS_DIR = BASE_DIR.parent.parent / "downloads" / "credentials"
```

#### `backend/app/credentials/services/cleanup_service.py`
**Linha 23** - Corrigir path hardcoded:
```python
# DE:
DOWNLOADS_DIR = Path("/Users/angellocassio/Documents/intelligence-platform/backend/downloads/credentials")

# PARA:
DOWNLOADS_DIR = Path(__file__).parent.parent.parent.parent / "downloads" / "credentials"
```

#### `backend/create_admin.py`
**Linhas 11-13** - Usar variável de ambiente para DATABASE_URL:
```python
# DE:
DB_URL = "postgresql://intelligence_user:intelligence_pass_secure_2024@postgres:5432/intelligence_platform"

# PARA:
import os
DB_URL = os.getenv("DATABASE_URL", "postgresql://minerva:MinervaDB2024@localhost:5432/minerva_db").replace("+asyncpg", "")
```

### 2. Frontend

#### `frontend/.env.production` (criar arquivo)
```env
# API Backend URL
VITE_API_URL=https://localhost
VITE_WS_URL=wss://localhost

# App Config
VITE_APP_NAME=Minerva - Intelligence Platform
VITE_APP_VERSION=2.0.0
```

## Arquivos de Configuração do Servidor

### Nginx (`/etc/nginx/sites-available/minerva`)
```nginx
# Minerva Intelligence Platform - SSL Configuration

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/minerva.crt;
    ssl_certificate_key /etc/nginx/ssl/minerva.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Frontend (React)
    location / {
        root /var/www/minerva/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # WebSocket
    location /socket.io/ {
        proxy_pass http://127.0.0.1:8002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Static files do backend
    location /static/ {
        alias /var/www/minerva/backend/static/;
    }

    # Docs do FastAPI
    location /docs {
        proxy_pass http://127.0.0.1:8002/docs;
    }

    location /redoc {
        proxy_pass http://127.0.0.1:8002/redoc;
    }

    location /openapi.json {
        proxy_pass http://127.0.0.1:8002/openapi.json;
    }
}
```

### Systemd Services

#### `/etc/systemd/system/minerva-backend.service`
```ini
[Unit]
Description=Minerva Backend API
After=network.target postgresql.service redis-server.service elasticsearch.service

[Service]
Type=simple
User=witcher
Group=witcher
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
Environment="APP_NAME=Minerva Intelligence Platform"
Environment="APP_VERSION=2.0.0"
Environment="DEBUG=False"
Environment="SECRET_KEY=<GERAR_NOVA_CHAVE>"
Environment="HOST=0.0.0.0"
Environment="PORT=8002"
Environment="CORS_ORIGINS=[\"https://localhost\",\"https://127.0.0.1\"]"
Environment="DATABASE_URL=postgresql+asyncpg://minerva:<SENHA>@localhost:5432/minerva_db"
Environment="ES_URL=https://localhost:9200"
Environment="ES_USERNAME=elastic"
Environment="ES_PASSWORD=<SENHA_ELASTIC>"
Environment="ES_TIMEOUT=30"
Environment="ES_MAX_RETRIES=3"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="REDIS_ENABLED=True"
Environment="JWT_SECRET_KEY=<GERAR_NOVA_CHAVE>"
Environment="JWT_ALGORITHM=HS256"
Environment="JWT_EXPIRATION_MINUTES=60"
Environment="LOG_LEVEL=INFO"
Environment="LOG_FORMAT=json"
ExecStart=/var/www/minerva/backend/venv/bin/uvicorn app.main:socket_app --host 0.0.0.0 --port 8002 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### `/etc/systemd/system/minerva-celery.service`
```ini
[Unit]
Description=Minerva Celery Worker
After=network.target redis-server.service

[Service]
Type=simple
User=witcher
Group=witcher
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
Environment="DATABASE_URL=postgresql+asyncpg://minerva:<SENHA>@localhost:5432/minerva_db"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="ES_URL=https://localhost:9200"
Environment="ES_USERNAME=elastic"
Environment="ES_PASSWORD=<SENHA_ELASTIC>"
ExecStart=/var/www/minerva/backend/venv/bin/celery -A app.celery_app worker --loglevel=info --concurrency=4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### `/etc/systemd/system/minerva-celery-beat.service`
```ini
[Unit]
Description=Minerva Celery Beat Scheduler
After=network.target redis-server.service

[Service]
Type=simple
User=witcher
Group=witcher
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
Environment="DATABASE_URL=postgresql+asyncpg://minerva:<SENHA>@localhost:5432/minerva_db"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="ES_URL=https://localhost:9200"
Environment="ES_USERNAME=elastic"
Environment="ES_PASSWORD=<SENHA_ELASTIC>"
ExecStart=/var/www/minerva/backend/venv/bin/celery -A app.celery_app beat --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Dependências Adicionais

Instalar no ambiente virtual do backend:
```bash
pip install telethon psycopg2-binary
```

## Diretórios a Criar

```bash
mkdir -p /var/www/minerva/backend/downloads/credentials
mkdir -p /var/www/minerva/backend/static/downloads
```

## Comandos de Deploy

```bash
# 1. Atualizar código
cd /var/www/minerva
git pull

# 2. Backend
cd backend
source venv/bin/activate
pip install -r requirements.txt
pip install telethon psycopg2-binary
PYTHONPATH=$PWD alembic upgrade head

# 3. Frontend
cd ../frontend
npm install
npm run build  # ou: npx vite build

# 4. Reiniciar serviços
sudo systemctl restart minerva-backend minerva-celery minerva-celery-beat nginx
```

## Credenciais Padrão

- **Usuário admin:** admin
- **Senha:** admin123

**IMPORTANTE:** Alterar a senha após o primeiro login!

## SSL

Para produção com domínio real, usar Let's Encrypt:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d seu_dominio.com
```

## Portas Utilizadas

| Serviço | Porta | Exposição |
|---------|-------|-----------|
| Nginx HTTP | 80 | Externa (redireciona para 443) |
| Nginx HTTPS | 443 | Externa |
| Backend | 8002 | Interna |
| PostgreSQL | 5432 | Interna |
| Redis | 6379 | Interna |
| Elasticsearch | 9200 | Interna |

## Correções Adicionais

### `backend/app/services/rss_elasticsearch.py`
**Linhas 363, 366, 463, 466, 469** - Corrigir agregações ES para usar `.keyword`:
```python
# DE:
"terms": {"field": "category", "size": 20}
"terms": {"field": "feed_name", "size": 50}

# PARA:
"terms": {"field": "category.keyword", "size": 20}
"terms": {"field": "feed_name.keyword", "size": 50}
```

Isso corrige o erro `Fielddata is disabled on [category]` ao fazer agregações em campos de texto.

### `backend/app/services/rss_elasticsearch.py`
**Linha 369** - Corrigir agregação de tags:
```python
# DE:
"terms": {"field": "tags", "size": 30}

# PARA:
"terms": {"field": "tags.keyword", "size": 30}
```

**Linhas 473, 478** - Timeline usar `collected_at` em vez de `published`:
```python
# DE:
"range": {"published": {"gte": days_30_ago.isoformat()}}
"field": "published",

# PARA:
"range": {"collected_at": {"gte": days_30_ago.isoformat()}}
"field": "collected_at",
```

### `frontend/src/pages/InfoPage.tsx`
**Linha 77** - Filtro de data padrão para "Todos":
```typescript
// DE:
const [dateRange, setDateRange] = useState('7d');

// PARA:
const [dateRange, setDateRange] = useState('all');
```

### `backend/app/tasks/rss_tasks.py`
**Linhas 20-27** - Helper para event loop no Celery:
```python
def _run_async(coro):
    """Helper to run async code in Celery worker with fresh event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
```

### `backend/app/celery_app.py`
**Linha 46** - RSS collection a cada 2 horas:
```python
# DE:
"schedule": crontab(minute=0, hour="8,20"),

# PARA:
"schedule": crontab(minute=0, hour="*/2"),
```
