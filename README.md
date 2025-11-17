# MINERVA - Intelligence Platform

**MINERVA** é uma plataforma de inteligência de código aberto para coleta, análise e visualização de informações de segurança cibernética.

## Características Principais

- **RSS Feed Intelligence**: Sistema completo de coleta e análise de feeds RSS de fontes de segurança cibernética
- **Elasticsearch Integration**: Armazenamento e indexação eficiente de artigos com busca full-text
- **Multi-LLM Support**: Suporte a múltiplos provedores LLM (Anthropic, OpenAI, Databricks)
- **MCP (Model Context Protocol)**: Integração com servidores MCP para extensibilidade
- **Sistema de Conhecimento**: Knowledge base integrada para armazenar e consultar informações
- **Dashboards Interativos**: Visualizações personalizáveis com Apache ECharts
- **Sistema de Permissões**: Controle granular de acesso (Admin, Power, Operator, Reader)

## Funcionalidades RSS

### Coleta Automática
- Coleta periódica via Celery Beat (a cada 1 hora)
- Suporte a 38+ fontes RSS de segurança cibernética
- Deduplicação automática por hash de conteúdo
- Retry automático com backoff exponencial

### Fontes Incluídas
- **CVE/Vulnerabilities**: NVD, CISA, etc.
- **Security News**: Schneier, Krebs, Threatpost, Dark Reading
- **Tech Blogs**: Google Security, Microsoft Security, AWS Security
- **Threat Intelligence**: AlienVault, Recorded Future, Malpedia

### Busca e Análise
- Busca full-text em títulos, resumos e descrições
- Filtros por categoria, fonte, tags e data
- Agregações para faceted search
- Timeline de publicações
- Chat interativo com LLM sobre os artigos coletados

### API REST
- `GET /api/v1/rss/stats` - Estatísticas globais
- `POST /api/v1/rss/articles/search` - Busca de artigos
- `POST /api/v1/rss/collect` - Disparo manual de coleta (Sync Now)
- `GET /api/v1/rss/categories` - Gerenciar categorias
- `GET /api/v1/rss/sources` - Gerenciar fontes

## Tecnologias

### Backend
- **Python 3.11** com FastAPI
- **PostgreSQL** para dados relacionais
- **Elasticsearch 8.x** para busca full-text
- **Redis** para cache e Celery
- **Celery** para tarefas assíncronas
- **SQLAlchemy 2.0** com async support
- **Alembic** para migrações

### Frontend
- **React 18** com TypeScript
- **Vite** para build
- **Tailwind CSS** para estilos
- **Zustand** para state management
- **Apache ECharts** para visualizações
- **React Router** para navegação

## Instalação

### Pré-requisitos
- Docker e Docker Compose
- Node.js 20+ (para desenvolvimento frontend)
- Python 3.11+ (para desenvolvimento backend)

### Quick Start

```bash
# Clone o repositório
git clone <repo-url> minerva
cd minerva

# Configure as variáveis de ambiente
cp backend/.env.example backend/.env
# Edite backend/.env com suas credenciais

# Inicie os serviços
docker compose up -d

# Aguarde os serviços inicializarem (~30 segundos)
# Acesse: http://localhost:3000
```

### Primeiro Acesso

**Credenciais padrão:**
- **Username**: admin
- **Password**: admin123

**IMPORTANTE**: Altere a senha após o primeiro login!

## Desenvolvimento

### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Executar migrações
alembic upgrade head

# Criar usuário admin
python create_admin.py

# Iniciar servidor de desenvolvimento
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Celery (Coleta RSS)
```bash
cd backend
celery -A app.celery_app worker --loglevel=info
celery -A app.celery_app beat --loglevel=info
```

## Estrutura do Projeto

```
minerva/
├── backend/
│   ├── alembic/              # Migrações do banco de dados
│   ├── app/
│   │   ├── api/v1/           # Endpoints da API
│   │   ├── models/           # Modelos SQLAlchemy
│   │   ├── schemas/          # Schemas Pydantic
│   │   ├── services/         # Lógica de negócio
│   │   ├── tasks/            # Tarefas Celery
│   │   └── main.py           # Aplicação FastAPI
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── components/       # Componentes React
│   │   ├── pages/            # Páginas
│   │   ├── services/         # API clients
│   │   ├── stores/           # State management
│   │   └── App.tsx
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml
└── README.md
```

## Configuração de LLM Providers

O MINERVA suporta múltiplos provedores LLM. Configure através da interface web em **Settings > LLM Providers**.

### Provedores Suportados:
- **Anthropic Claude** (Sonnet, Opus, Haiku)
- **OpenAI** (GPT-4, GPT-3.5)
- **Databricks** (Custom models)

## RSS Feed Management

### Adicionar Nova Fonte

```python
# Via API ou interface web (Settings > RSS Manager)
POST /api/v1/rss/sources
{
  "name": "Nova Fonte",
  "url": "https://exemplo.com/feed.xml",
  "category_id": "<category-uuid>",
  "is_active": true
}
```

### Trigger Manual de Coleta

```bash
# Via API
curl -X POST http://localhost:8001/api/v1/rss/collect \
  -H "Content-Type: application/json" \
  -d '{}'

# Via interface web: Botão "Sync Now" na página de Feed de Notícias
```

## Elasticsearch Setup

O sistema cria automaticamente:
- **Index Template** com mappings otimizados
- **ILM Policy** para rotação automática (30 dias)
- **Alias** para operações de leitura/escrita

### Verificar Índice

```bash
# Contar documentos
curl http://localhost:9200/rss-articles/_count

# Buscar artigos
curl -X POST http://localhost:9200/rss-articles/_search \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'
```

## Logs e Monitoramento

```bash
# Backend logs
docker compose logs backend -f

# Celery worker logs
docker compose logs celery-worker -f

# Elasticsearch logs
docker compose logs elasticsearch -f

# Frontend logs (development)
cd frontend && npm run dev
```

## Troubleshooting

### RSS Collection Não Está Funcionando

1. Verificar Celery worker está rodando:
```bash
docker compose ps celery-worker
```

2. Verificar logs de erro:
```bash
docker compose logs celery-worker --tail 100 | grep ERROR
```

3. Trigger manual para debug:
```bash
cd backend
python test_rss_collection.py
```

### Elasticsearch Connection Error

1. Verificar se Elasticsearch está rodando:
```bash
docker compose ps elasticsearch
curl http://localhost:9200/_cluster/health
```

2. Recriar índice (CUIDADO: apaga dados):
```bash
curl -X DELETE http://localhost:9200/rss-articles-*
# Reiniciar backend para recriar índice
docker compose restart backend
```

## Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

MIT License - veja o arquivo LICENSE para detalhes.

## Suporte

Para reportar bugs ou solicitar features, abra uma issue no GitHub.

## Roadmap

- [ ] Análise de sentimento em artigos RSS
- [ ] Extração de entidades (NER)
- [ ] Geração de alertas customizados
- [ ] Integração com Telegram/Slack para notificações
- [ ] Dashboard público (sem autenticação)
- [ ] Export de relatórios em PDF
- [ ] API GraphQL
- [ ] Vector search com embeddings

---

**Desenvolvido com Claude Code**
