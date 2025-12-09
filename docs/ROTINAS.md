# Rotinas Automatizadas - Intelligence Platform (Minerva)

Este documento descreve **todas as rotinas automatizadas** da plataforma de inteligência de ameaças.

---

## 📋 Visão Geral

A plataforma possui **2 pipelines independentes** para coleta e processamento de dados:

| Pipeline | Frequência | Execução | Descrição |
|----------|-----------|----------|-----------|
| **RSS Feeds** | 2x por dia | Celery Beat | Coleta feeds RSS de fontes tradicionais |
| **Malpedia Library** | 1x por dia | Celery Beat | Enriquece biblioteca BibTeX com LLM |

---

## 🔄 ROTINA 1: Coleta de RSS Feeds

### Descrição
Coleta automática de feeds RSS configurados no banco de dados PostgreSQL.

### Características
- **Trigger**: Celery Beat schedule (2x por dia: 08:00 e 20:00)
- **Task**: `app.tasks.rss_tasks.collect_rss_feeds_periodic`
- **Elasticsearch**: Local (`elasticsearch:9200` dentro do Docker)
- **Índice**: `rss-articles`
- **Processamento**: Paralelo (até 10 feeds simultaneamente)

### Dados Coletados
- Título, autor, link, data de publicação
- Resumo (summary)
- Tags e categorias
- Feed source metadata

### Schedule
```python
# Executa 2x por dia
'collect-rss-feeds': {
    'task': 'app.tasks.rss_tasks.collect_rss_feeds_periodic',
    'schedule': crontab(hour='8,20', minute=0),  # 08:00 e 20:00
}
```

### Monitoramento
```bash
# Logs do Celery Worker
docker compose logs celery-worker -f

# Status da última coleta
curl -X GET http://localhost:8001/api/v1/rss/stats

# Total de artigos no ES
curl -s "http://elasticsearch:9200/rss-articles/_count" | jq
```

### Gerenciamento
- **Interface Web**: `http://localhost:5174/settings` (aba RSS)
- **API**: `http://localhost:8001/api/v1/rss/sources`
- **Adicionar feeds**: Via interface web ou bulk import (YAML)

### Configurações Individuais
Cada feed pode ter:
- `refresh_interval_hours`: Intervalo de atualização específico
- `is_active`: Ativar/desativar feed
- `max_articles`: Limite de artigos por coleta

---

## 🎯 ROTINA 2: Enriquecimento Malpedia Library

### Descrição
Processa biblioteca completa do Malpedia (BibTeX) com enriquecimento via LLM.

### Características
- **Trigger**: Celery Beat schedule (1x por dia: 02:00)
- **Task**: `app.tasks.malpedia_tasks.enrich_malpedia_library`
- **Elasticsearch**: EXTERNO (`localhost:9200` - projeto BHACK_2025)
- **Índices utilizados**:
  - `malpedia_actors` (864 docs) - Referência de atores
  - `malpedia_families` (3,578 docs) - Referência de famílias
  - `rss-articles` (17,595 docs) - Target para enriquecimento
- **LLM**: Databricks/Anthropic/OpenAI (configurável)

### Processamento
- **Batch size**: 50 artigos por vez
- **Checkpoint**: Salvo a cada batch (retoma de onde parou)
- **Tempo estimado**: 15-25 horas (completo)
- **Performance**: ~3-5 segundos por artigo (LLM call)

### Enriquecimento LLM
Para cada artigo, o LLM gera:
1. **Resumo**: 2-3 frases técnicas sobre o conteúdo
2. **Atores mencionados**: Lista de APTs/threat actors identificados
3. **Famílias mencionadas**: Lista de famílias de malware identificadas

### Schedule
```python
# Executa 1x por dia às 02:00
'enrich-malpedia': {
    'task': 'app.tasks.malpedia_tasks.enrich_malpedia_library',
    'schedule': crontab(hour=2, minute=0),  # 02:00
}
```

### Monitoramento
```bash
# Logs do Celery Worker
docker compose logs celery-worker -f | grep malpedia

# Checkpoint (progresso)
docker exec intelligence-platform-backend cat /app/malpedia_enrichment_checkpoint.json | jq

# Log detalhado
docker exec intelligence-platform-backend tail -f /app/malpedia_enrichment_log.jsonl

# Total de artigos enriquecidos
curl -s "http://localhost:9200/rss-articles/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"exists":{"field":"enriched_at"}}}' | jq
```

### Checkpoint e Retomada
O pipeline salva checkpoint automaticamente:
```json
{
  "last_processed_index": 5000,
  "total_processed": 5000,
  "total_enriched": 4950,
  "total_errors": 50,
  "started_at": "2025-01-17T08:00:00",
  "last_update": "2025-01-17T12:30:00"
}
```

Se interrompido, retoma automaticamente do último checkpoint.

---

## ⚙️ Configuração do Celery Beat

### Arquivo de Configuração
`app/core/celery_config.py`

### Beat Schedule Completo
```python
from celery.schedules import crontab

beat_schedule = {
    # RSS Feeds - 2x por dia
    'collect-rss-feeds': {
        'task': 'app.tasks.rss_tasks.collect_rss_feeds_periodic',
        'schedule': crontab(hour='8,20', minute=0),
    },

    # Malpedia Enrichment - 1x por dia
    'enrich-malpedia': {
        'task': 'app.tasks.malpedia_tasks.enrich_malpedia_library',
        'schedule': crontab(hour=2, minute=0),
    },
}
```

### Timezone
```python
timezone = 'America/Sao_Paulo'  # UTC-3
```

---

## 🐳 Serviços Docker

### Containers Envolvidos
```yaml
services:
  backend:          # FastAPI application
  celery-worker:    # Processa tasks
  celery-beat:      # Agenda tasks periódicas
  redis:            # Message broker
  postgres:         # Metadados (feeds config)
  elasticsearch:    # Armazenamento de artigos (local)
```

### Elasticsearch EXTERNO
- **URL**: `http://localhost:9200` (projeto BHACK_2025)
- **Acesso**: Do host, não do container
- **Índices**: malpedia_actors, malpedia_families, rss-articles

---

## 📊 Monitoramento Geral

### Status dos Workers
```bash
# Status dos containers
docker compose ps

# Logs do Celery Beat (scheduler)
docker compose logs celery-beat -f

# Logs do Celery Worker (executor)
docker compose logs celery-worker -f

# Tasks ativas
docker exec intelligence-platform-celery-worker celery -A app.core.celery_app inspect active

# Tasks agendadas
docker exec intelligence-platform-celery-worker celery -A app.core.celery_app inspect scheduled
```

### Estatísticas
```bash
# Total de artigos coletados (todos)
curl -s "http://elasticsearch:9200/rss-articles/_count" | jq

# Artigos RSS (normais)
curl -s "http://elasticsearch:9200/rss-articles/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"bool":{"must_not":{"term":{"feed_name":"Malpedia Library"}}}}}' | jq

# Artigos Malpedia enriquecidos
curl -s "http://localhost:9200/rss-articles/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"feed_name":"Malpedia Library"}}}' | jq
```

---

## 🔧 Troubleshooting

### RSS não está coletando

1. Verificar Celery Beat:
   ```bash
   docker compose logs celery-beat --tail 50
   ```

2. Verificar se há feeds ativos:
   ```bash
   curl http://localhost:8001/api/v1/rss/sources | jq '.[] | select(.is_active==true)'
   ```

3. Forçar coleta manual:
   ```bash
   curl -X POST http://localhost:8001/api/v1/rss/collect \
     -H "Authorization: Bearer $TOKEN"
   ```

### Malpedia não está enriquecendo

1. Verificar ES externo:
   ```bash
   curl http://localhost:9200
   ```

2. Verificar checkpoint:
   ```bash
   docker exec intelligence-platform-backend cat /app/malpedia_enrichment_checkpoint.json | jq
   ```

3. Verificar LLM configurado:
   ```bash
   docker exec intelligence-platform-backend env | grep -E "DATABRICKS|ANTHROPIC|OPENAI"
   ```

### Task travada

```bash
# Revoke task específica
docker exec intelligence-platform-celery-worker \
  celery -A app.core.celery_app control revoke <TASK_ID> --terminate

# Restart worker
docker compose restart celery-worker
```

---

## 🚀 Execução Manual

### Forçar coleta RSS (fora do schedule)
```bash
# Via API
curl -X POST http://localhost:8001/api/v1/rss/collect \
  -H "Authorization: Bearer $TOKEN"

# Via Celery
docker exec intelligence-platform-celery-worker \
  celery -A app.core.celery_app call app.tasks.rss_tasks.collect_rss_feeds_periodic
```

### Forçar enriquecimento Malpedia (fora do schedule)
```bash
# Via Celery
docker exec intelligence-platform-celery-worker \
  celery -A app.core.celery_app call app.tasks.malpedia_tasks.enrich_malpedia_library

# Via script direto (debugging)
./run_malpedia_pipeline.sh
```

---

## 📝 Logs e Auditoria

### Localização dos Logs

| Tipo | Localização |
|------|-------------|
| Celery Beat | `docker compose logs celery-beat` |
| Celery Worker | `docker compose logs celery-worker` |
| Backend API | `docker compose logs backend` |
| Malpedia Checkpoint | `/app/malpedia_enrichment_checkpoint.json` (dentro do container) |
| Malpedia Log | `/app/malpedia_enrichment_log.jsonl` (dentro do container) |

### Formato do Log Malpedia
```json
{
  "timestamp": "2025-01-17T10:30:45",
  "article_id": "abc123...",
  "status": "success",
  "data": {
    "enriched_summary": "Technical paper analyzing...",
    "actors_mentioned": ["APT28", "Fancy Bear"],
    "families_mentioned": ["XAgent", "Sofacy"]
  }
}
```

---

## 🎯 Métricas de Performance

### RSS Feeds
- **Frequência**: 2x por dia (08:00, 20:00)
- **Duração típica**: 2-5 minutos
- **Artigos por execução**: Varia (depende de novos artigos)
- **Taxa de sucesso esperada**: > 95%

### Malpedia Enrichment
- **Frequência**: 1x por dia (02:00)
- **Duração típica**: 15-25 horas (primeira execução completa)
- **Duração incremental**: 1-3 horas (apenas novos artigos)
- **Artigos processados**: ~50-60 por hora
- **Taxa de sucesso esperada**: > 90%

---

## 🔐 Segurança

### API Keys LLM
- Armazenadas criptografadas no banco (tabela `llm_providers`)
- Criptografia: Fernet + PBKDF2HMAC (100k iterations)
- Nunca expostas em logs ou responses HTTP

### Elasticsearch
- Local: Sem autenticação (network isolado)
- Externo: Configurável via `MALPEDIA_ES_USER` e `MALPEDIA_ES_PASS`

---

## 📚 Referências

- **Configuração Celery**: `app/core/celery_config.py`
- **Tasks RSS**: `app/tasks/rss_tasks.py`
- **Tasks Malpedia**: `app/tasks/malpedia_tasks.py`
- **Pipeline Malpedia**: `malpedia_pipeline.py`
- **Docker Compose**: `docker-compose.yml`
- **Documentação Pipelines**: `PIPELINES_README.md`
