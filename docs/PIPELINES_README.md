# Intelligence Platform - Pipelines de Coleta

Este documento descreve os **2 pipelines independentes** para coleta e processamento de inteligência de ameaças.

---

## 📊 PIPELINE 1: RSS Feeds (Normal)

**Objetivo**: Coletar feeds RSS de fontes de threat intelligence tradicionais

**Características**:
- Coleta RSS feeds configurados no banco de dados PostgreSQL
- Processa feeds normais com resumos, autores, tags
- Armazena em Elasticsearch local
- Executa automaticamente via Celery scheduler

### Como usar:

#### Via API (manual):
```bash
curl -X POST http://localhost:8001/api/v1/rss/collect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Via Celery (automático):
O Celery Beat executa automaticamente conforme configuração de `refresh_interval_hours` de cada feed.

### Monitorar execução:
```bash
# Logs do worker
docker compose logs celery-worker -f

# Stats de coleta
curl -X GET http://localhost:8001/api/v1/rss/stats
```

### Gerenciar feeds:
- Interface web: `http://localhost:5174/settings` (aba RSS)
- API: `/api/v1/rss/sources` (CRUD de feeds)

---

## 🎯 PIPELINE 2: Malpedia Library (BibTeX + Enrichment)

**Objetivo**: Processar biblioteca completa do Malpedia com enriquecimento LLM

**Características**:
- Baixa BibTeX completo do Malpedia (17.595 entries)
- Indexa artigos em Elasticsearch EXTERNO (projeto BHACK_2025)
- Enriquece com LLM:
  - Resumos gerados (2-3 frases técnicas)
  - Menções a atores de ameaça (APTs)
  - Menções a famílias de malware
- Processa em batches de 50 com checkpoint
- Pode retomar de onde parou em caso de interrupção

### Pré-requisitos:

1. **Elasticsearch EXTERNO** rodando em `localhost:9200` (projeto BHACK_2025):
   ```bash
   docker ps | grep elasticsearch
   # Deve mostrar container elasticsearch rodando na porta 9200
   ```

2. **Índices necessários**:
   - `malpedia_actors` (864 documentos)
   - `malpedia_families` (3,578 documentos)
   - `rss-articles` (target para armazenar)

3. **LLM configurado**:
   - Databricks, Anthropic ou OpenAI configurado no `.env`
   - Ou provider cadastrado na tabela `llm_providers`

### Como executar:

#### Opção 1: Usando script helper (recomendado):
```bash
cd /Users/angellocassio/Documents/intelligence-platform/backend
./run_malpedia_pipeline.sh
```

#### Opção 2: Executar diretamente no Docker:
```bash
# Copia o script para o container
docker cp malpedia_pipeline.py intelligence-platform-backend:/app/

# Executa
docker exec -it intelligence-platform-backend bash -c "
  cd /app && \
  export PYTHONPATH=/app && \
  python3 malpedia_pipeline.py
"
```

#### Opção 3: Background com nohup (dentro do Docker):
```bash
docker exec -d intelligence-platform-backend bash -c "
  cd /app && \
  nohup python3 malpedia_pipeline.py > /app/logs/malpedia_pipeline.log 2>&1
"

# Monitorar logs
docker exec intelligence-platform-backend tail -f /app/logs/malpedia_pipeline.log
```

### Configurar Elasticsearch externo (opcional):
```bash
# Via variáveis de ambiente
export MALPEDIA_ES_URL="http://localhost:9200"
export MALPEDIA_ES_USER="elastic"  # se autenticação habilitada
export MALPEDIA_ES_PASS="password"
```

### Monitorar progresso:

1. **Checkpoint file**: `malpedia_enrichment_checkpoint.json`
   ```bash
   cat malpedia_enrichment_checkpoint.json
   ```

2. **Log detalhado**: `malpedia_enrichment_log.jsonl`
   ```bash
   tail -f malpedia_enrichment_log.jsonl
   ```

3. **Query Elasticsearch**:
   ```bash
   # Total de artigos enriquecidos
   curl -s "http://localhost:9200/rss-articles/_count" \
     -H "Content-Type: application/json" \
     -d '{"query":{"exists":{"field":"enriched_at"}}}' | jq

   # Ver exemplo de artigo enriquecido
   curl -s "http://localhost:9200/rss-articles/_search" \
     -H "Content-Type: application/json" \
     -d '{"query":{"exists":{"field":"enriched_at"}},"size":1}' | jq
   ```

### Retomar processamento interrompido:

Se o script for interrompido, basta executá-lo novamente:
```bash
python3 malpedia_pipeline.py
```

O checkpoint será carregado automaticamente e continuará de onde parou.

### Performance estimada:

- **Batch size**: 50 artigos
- **Tempo estimado por artigo**: ~3-5 segundos (LLM call)
- **Total**: 17.595 artigos
- **Tempo total estimado**: 15-25 horas

---

## 🔧 Troubleshooting

### Pipeline RSS não está coletando

1. Verificar se Celery está rodando:
   ```bash
   docker compose ps celery-worker
   ```

2. Verificar logs:
   ```bash
   docker compose logs celery-worker --tail 50
   ```

3. Verificar se há feeds ativos:
   ```bash
   curl -X GET http://localhost:8001/api/v1/rss/sources | jq '.[] | select(.is_active==true)'
   ```

### Malpedia Pipeline com erro de conexão ES

1. Verificar se Elasticsearch externo está rodando:
   ```bash
   curl http://localhost:9200
   ```

2. Verificar índices:
   ```bash
   curl http://localhost:9200/_cat/indices | grep malpedia
   ```

3. Testar conexão manualmente:
   ```bash
   python3 -c "from elasticsearch import Elasticsearch; es = Elasticsearch(['http://localhost:9200']); print(es.info())"
   ```

### LLM não está configurado

1. Verificar variáveis de ambiente:
   ```bash
   env | grep -E "DATABRICKS|ANTHROPIC|OPENAI"
   ```

2. Ou verificar providers no banco:
   ```sql
   SELECT name, provider_type, model_name, is_active, is_default
   FROM llm_providers;
   ```

---

## 📝 Notas Importantes

### Separação de responsabilidades:

- **Pipeline RSS**: Gerenciado automaticamente pelo Celery
  - Adicione/remova feeds pela interface web
  - Coleta acontece automaticamente
  - Dados em Elasticsearch local do projeto

- **Pipeline Malpedia**: Executado manualmente (one-time ou periódico)
  - Conecta a Elasticsearch EXTERNO
  - Enriquecimento pesado com LLM
  - Execute quando quiser atualizar dados do Malpedia

### Não misturar:

❌ **NÃO** adicione Malpedia Library como feed RSS normal
✅ **USE** o pipeline dedicado `malpedia_pipeline.py`

O Malpedia usa formato BibTeX e precisa de enriquecimento especial com LLM.

---

## 🚀 Quick Start

### Para começar a coletar RSS feeds:
```bash
# 1. Configure feeds na interface web
http://localhost:5174/settings

# 2. Ou importe feeds via API
curl -X POST http://localhost:8001/api/v1/rss/sources/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@feeds.yaml"

# 3. Aguarde coleta automática ou force manualmente
curl -X POST http://localhost:8001/api/v1/rss/collect \
  -H "Authorization: Bearer $TOKEN"
```

### Para processar Malpedia:
```bash
# 1. Verificar pré-requisitos
curl http://localhost:9200 && echo "ES OK"

# 2. Executar pipeline
cd /Users/angellocassio/Documents/intelligence-platform/backend
./run_malpedia_pipeline.sh

# 3. Monitorar (em outro terminal)
docker exec intelligence-platform-backend cat /app/malpedia_enrichment_checkpoint.json | jq
```
