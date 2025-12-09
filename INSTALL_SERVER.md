# Minerva Intelligence Platform - Guia de Instalação em Servidor

Este guia ensina como instalar a plataforma Minerva em um servidor Linux (Ubuntu/Debian) sem usar Docker.

## Requisitos do Sistema

- **OS**: Ubuntu 22.04 LTS ou Debian 12
- **RAM**: Mínimo 8GB (recomendado 16GB)
- **CPU**: 4 cores (recomendado 8 cores)
- **Disco**: 100GB SSD (recomendado 500GB para Elasticsearch)
- **Rede**: Acesso à internet para downloads

---

## 1. Preparação do Sistema

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependências básicas
sudo apt install -y \
    curl \
    wget \
    git \
    build-essential \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    unzip \
    htop \
    vim \
    ufw
```

---

## 2. PostgreSQL 15

### Instalação

```bash
# Adicionar repositório oficial do PostgreSQL
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

# Instalar PostgreSQL 15
sudo apt update
sudo apt install -y postgresql-15 postgresql-contrib-15

# Verificar status
sudo systemctl status postgresql
sudo systemctl enable postgresql
```

### Configuração

```bash
# Acessar como usuário postgres
sudo -u postgres psql

# Criar banco e usuário para a aplicação
CREATE USER minerva WITH PASSWORD 'sua_senha_segura_aqui';
CREATE DATABASE minerva_db OWNER minerva;
GRANT ALL PRIVILEGES ON DATABASE minerva_db TO minerva;

# Extensões úteis
\c minerva_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

\q
```

### Configurar acesso remoto (se necessário)

```bash
# Editar postgresql.conf
sudo nano /etc/postgresql/15/main/postgresql.conf

# Alterar:
listen_addresses = '*'

# Editar pg_hba.conf para permitir conexões
sudo nano /etc/postgresql/15/main/pg_hba.conf

# Adicionar linha (ajuste o IP conforme sua rede):
host    minerva_db    minerva    0.0.0.0/0    scram-sha-256

# Reiniciar PostgreSQL
sudo systemctl restart postgresql
```

### Testar conexão

```bash
psql -h localhost -U minerva -d minerva_db
# Digite a senha quando solicitado
```

---

## 3. Redis 7

### Instalação

```bash
# Adicionar repositório oficial do Redis
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

# Instalar Redis
sudo apt update
sudo apt install -y redis

# Verificar status
sudo systemctl status redis-server
sudo systemctl enable redis-server
```

### Configuração

```bash
# Editar configuração
sudo nano /etc/redis/redis.conf

# Configurações recomendadas:
bind 127.0.0.1          # Apenas localhost (mais seguro)
maxmemory 2gb           # Limite de memória
maxmemory-policy allkeys-lru
appendonly yes          # Persistência

# Se precisar de acesso remoto:
# bind 0.0.0.0
# requirepass sua_senha_redis

# Reiniciar Redis
sudo systemctl restart redis-server
```

### Testar conexão

```bash
redis-cli ping
# Deve retornar: PONG
```

---

## 4. Elasticsearch 8.x

### Instalação

```bash
# Importar chave GPG
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Adicionar repositório
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Instalar Elasticsearch
sudo apt update
sudo apt install -y elasticsearch

# NÃO iniciar ainda - precisamos configurar primeiro
```

### Configuração

```bash
# Editar configuração
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Conteúdo recomendado:

```yaml
# ======================== Elasticsearch Configuration =========================
cluster.name: minerva-cluster
node.name: minerva-node-1

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Network
network.host: 0.0.0.0
http.port: 9200

# Discovery (single node)
discovery.type: single-node

# Security (desabilitar para desenvolvimento, HABILITAR em produção!)
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

# Memory
bootstrap.memory_lock: true
```

### Configurar memória JVM

```bash
# Editar JVM options
sudo nano /etc/elasticsearch/jvm.options.d/heap.options
```

Conteúdo (ajuste conforme RAM disponível):

```
-Xms4g
-Xmx4g
```

### Configurar limites do sistema

```bash
# Editar limits
sudo nano /etc/security/limits.conf

# Adicionar:
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536

# Editar systemd override
sudo mkdir -p /etc/systemd/system/elasticsearch.service.d
sudo nano /etc/systemd/system/elasticsearch.service.d/override.conf
```

Conteúdo:

```ini
[Service]
LimitMEMLOCK=infinity
```

### Iniciar Elasticsearch

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verificar status
sudo systemctl status elasticsearch

# Aguardar inicialização (pode levar 30-60 segundos)
sleep 30

# Testar
curl -X GET "localhost:9200"
```

---

## 5. Python 3.11

### Instalação

```bash
# Adicionar repositório deadsnakes
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update

# Instalar Python 3.11
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3.11-distutils

# Instalar pip
curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11

# Verificar
python3.11 --version
pip3.11 --version
```

---

## 6. Node.js 20 LTS

### Instalação

```bash
# Instalar via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Verificar
node --version
npm --version
```

---

## 7. Nginx (Reverse Proxy)

### Instalação

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

### Configuração

```bash
# Criar configuração do site
sudo nano /etc/nginx/sites-available/minerva
```

Conteúdo:

```nginx
# Minerva Intelligence Platform
server {
    listen 80;
    server_name seu_dominio.com;  # Ou IP do servidor

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
}
```

### Ativar site

```bash
sudo ln -s /etc/nginx/sites-available/minerva /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remover default
sudo nginx -t  # Testar configuração
sudo systemctl reload nginx
```

---

## 8. Instalação da Aplicação

### Criar estrutura de diretórios

```bash
sudo mkdir -p /var/www/minerva
sudo chown -R $USER:$USER /var/www/minerva
cd /var/www/minerva
```

### Clonar repositório

```bash
git clone https://github.com/Cassio-Ac/minerva-intelligence.git .
```

### Backend

```bash
cd /var/www/minerva/backend

# Criar ambiente virtual
python3.11 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install --upgrade pip
pip install -r requirements.txt

# Criar arquivo .env
nano .env
```

Conteúdo do `.env`:

```env
# Database
DATABASE_URL=postgresql://minerva:sua_senha_segura_aqui@localhost:5432/minerva_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Elasticsearch
ES_URL=http://localhost:9200
ES_USERNAME=
ES_PASSWORD=

# App
APP_NAME=Minerva Intelligence Platform
APP_VERSION=2.0.0
DEBUG=false
LOG_LEVEL=INFO
HOST=0.0.0.0
PORT=8002

# Security
SECRET_KEY=gerar_uma_chave_secreta_forte_aqui_com_64_caracteres
JWT_SECRET_KEY=outra_chave_secreta_para_jwt_com_64_caracteres

# CORS (ajuste conforme seu domínio)
CORS_ORIGINS=["http://localhost", "http://seu_dominio.com"]
```

### Gerar chaves secretas

```bash
# Gerar SECRET_KEY
python3.11 -c "import secrets; print(secrets.token_hex(32))"

# Gerar JWT_SECRET_KEY
python3.11 -c "import secrets; print(secrets.token_hex(32))"
```

### Executar migrations

```bash
cd /var/www/minerva/backend
source venv/bin/activate

# Rodar migrations do Alembic
PYTHONPATH=$PWD alembic upgrade head
```

### Frontend

```bash
cd /var/www/minerva/frontend

# Instalar dependências
npm install

# Criar arquivo de configuração
nano .env.production
```

Conteúdo:

```env
VITE_API_URL=http://seu_dominio.com/api/v1
VITE_WS_URL=ws://seu_dominio.com
```

### Build do Frontend

```bash
npm run build

# Os arquivos estarão em /var/www/minerva/frontend/dist
```

---

## 9. Systemd Services

### Backend (Uvicorn)

```bash
sudo nano /etc/systemd/system/minerva-backend.service
```

Conteúdo:

```ini
[Unit]
Description=Minerva Backend API
After=network.target postgresql.service redis-server.service elasticsearch.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
ExecStart=/var/www/minerva/backend/venv/bin/uvicorn app.main:socket_app --host 0.0.0.0 --port 8002 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Celery Worker

```bash
sudo nano /etc/systemd/system/minerva-celery.service
```

Conteúdo:

```ini
[Unit]
Description=Minerva Celery Worker
After=network.target redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
ExecStart=/var/www/minerva/backend/venv/bin/celery -A app.celery_app worker --loglevel=info --concurrency=4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Celery Beat (Scheduler)

```bash
sudo nano /etc/systemd/system/minerva-celery-beat.service
```

Conteúdo:

```ini
[Unit]
Description=Minerva Celery Beat Scheduler
After=network.target redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/minerva/backend
Environment="PATH=/var/www/minerva/backend/venv/bin"
Environment="PYTHONPATH=/var/www/minerva/backend"
ExecStart=/var/www/minerva/backend/venv/bin/celery -A app.celery_app beat --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Ajustar permissões

```bash
sudo chown -R www-data:www-data /var/www/minerva
sudo chmod -R 755 /var/www/minerva
```

### Ativar e iniciar serviços

```bash
sudo systemctl daemon-reload

# Ativar serviços
sudo systemctl enable minerva-backend
sudo systemctl enable minerva-celery
sudo systemctl enable minerva-celery-beat

# Iniciar serviços
sudo systemctl start minerva-backend
sudo systemctl start minerva-celery
sudo systemctl start minerva-celery-beat

# Verificar status
sudo systemctl status minerva-backend
sudo systemctl status minerva-celery
sudo systemctl status minerva-celery-beat
```

---

## 10. Firewall (UFW)

```bash
# Habilitar UFW
sudo ufw enable

# Permitir SSH
sudo ufw allow ssh

# Permitir HTTP e HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Permitir Elasticsearch (apenas se precisar acesso externo)
# sudo ufw allow 9200/tcp

# Verificar regras
sudo ufw status
```

---

## 11. SSL com Let's Encrypt (Opcional, mas recomendado)

```bash
# Instalar Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obter certificado
sudo certbot --nginx -d seu_dominio.com

# Renovação automática já é configurada
# Testar renovação
sudo certbot renew --dry-run
```

---

## 12. Verificação Final

### Checklist de serviços

```bash
# PostgreSQL
sudo systemctl status postgresql

# Redis
sudo systemctl status redis-server

# Elasticsearch
sudo systemctl status elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"

# Backend
sudo systemctl status minerva-backend
curl http://localhost:8002/health

# Celery
sudo systemctl status minerva-celery

# Celery Beat
sudo systemctl status minerva-celery-beat

# Nginx
sudo systemctl status nginx
```

### Testar aplicação

```bash
# API
curl http://localhost:8002/

# Frontend (via Nginx)
curl http://localhost/
```

---

## 13. Comandos Úteis

### Logs

```bash
# Backend
sudo journalctl -u minerva-backend -f

# Celery
sudo journalctl -u minerva-celery -f

# Celery Beat
sudo journalctl -u minerva-celery-beat -f

# Nginx
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log

# Elasticsearch
sudo tail -f /var/log/elasticsearch/minerva-cluster.log
```

### Restart serviços

```bash
# Reiniciar tudo
sudo systemctl restart postgresql redis-server elasticsearch minerva-backend minerva-celery minerva-celery-beat nginx

# Apenas backend
sudo systemctl restart minerva-backend minerva-celery minerva-celery-beat
```

### Atualizar aplicação

```bash
cd /var/www/minerva

# Pull das mudanças
git pull

# Backend
cd backend
source venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=$PWD alembic upgrade head
sudo systemctl restart minerva-backend minerva-celery minerva-celery-beat

# Frontend
cd ../frontend
npm install
npm run build
```

---

## 14. Criar Usuário Admin Inicial

```bash
cd /var/www/minerva/backend
source venv/bin/activate

# Acessar shell do Python
PYTHONPATH=$PWD python3.11
```

```python
import asyncio
from app.db.database import get_db, init_db
from app.services.auth_service import AuthService

async def create_admin():
    async for db in get_db():
        auth_service = AuthService(db)
        user = await auth_service.create_user(
            username="admin",
            email="admin@seudominio.com",
            password="SenhaForte123!",
            role="admin"
        )
        print(f"Admin criado: {user.username}")

asyncio.run(create_admin())
```

---

## Resumo das Portas

| Serviço | Porta | Acesso |
|---------|-------|--------|
| PostgreSQL | 5432 | Interno |
| Redis | 6379 | Interno |
| Elasticsearch | 9200 | Interno |
| Backend (Uvicorn) | 8002 | Interno |
| Nginx HTTP | 80 | Externo |
| Nginx HTTPS | 443 | Externo |

---

## Troubleshooting

### Elasticsearch não inicia
```bash
# Verificar logs
sudo journalctl -u elasticsearch -f

# Verificar memória
free -h

# Comum: falta de memória - reduzir heap no jvm.options
```

### Backend não conecta ao PostgreSQL
```bash
# Verificar se PostgreSQL está rodando
sudo systemctl status postgresql

# Testar conexão manual
psql -h localhost -U minerva -d minerva_db
```

### Celery não processa tasks
```bash
# Verificar se Redis está rodando
redis-cli ping

# Verificar logs do Celery
sudo journalctl -u minerva-celery -f
```

---

## Suporte

- **GitHub**: https://github.com/Cassio-Ac/minerva-intelligence
- **Issues**: https://github.com/Cassio-Ac/minerva-intelligence/issues
