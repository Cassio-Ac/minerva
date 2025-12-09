# 🔄 Rotinas CTI - Guia Completo de Sincronização e Enriquecimento

**Data**: 2025-11-20
**Status**: ✅ Sistema 100% Operacional
**Cobertura**: 864/864 actors enriquecidos (100%)

---

## 📋 Sumário Executivo

Este documento descreve as **rotinas completas** para sincronização e enriquecimento de dados CTI (Cyber Threat Intelligence) da plataforma Minerva Intelligence Platform.

**Pipeline Completo:**
1. **Sincronização Malpedia** → Download incremental de actors/families
2. **Enriquecimento MITRE** → Mapping oficial de técnicas ATT&CK
3. **Enriquecimento LLM** → Inferência para actors sem mapping oficial
4. **Validação e Cache** → Persistência sem perda de dados

---

## 🎯 Objetivos das Rotinas

### ✅ Garantias do Sistema

1. **ZERO Perda de Dados**
   - Sincronização incremental (apenas novos/alterados)
   - Cache persistente separado dos dados brutos
   - Histórico de enriquecimento preservado

2. **Detecção Automática de Mudanças**
   - Content hash (MD5) para cada documento
   - Comparação automática com versão anterior
   - Update apenas quando necessário

3. **Enriquecimento Completo**
   - MITRE oficial (171 actors, 19.8%)
   - LLM inference (693 actors, 80.2%)
   - Cobertura total: 100%

4. **Performance Otimizada**
   - Primeira execução: ~45 minutos
   - Atualizações diárias: ~2-5 minutos
   - Speedup: até 22x

---

## 📁 Estrutura de Arquivos

```
backend/
├── app/
│   ├── cti/
│   │   ├── services/
│   │   │   ├── malpedia_service.py          # Acesso aos dados Malpedia
│   │   │   ├── attack_service.py            # MITRE ATT&CK framework
│   │   │   ├── enrichment_service.py        # Orquestração de enrichment
│   │   │   ├── enrichment_cache_service.py  # Cache persistente
│   │   │   ├── llm_enrichment_service.py    # Inferência LLM
│   │   │   └── misp_galaxy_service.py       # Dados geopolíticos
│   │   └── api/
│   │       ├── actors.py                     # Endpoints de actors
│   │       ├── families.py                   # Endpoints de families
│   │       ├── techniques.py                 # Endpoints MITRE
│   │       └── enrichment.py                 # Endpoints de enrichment
│   │
│   └── services/
│       └── malpedia_sync_service.py          # ✨ Sincronização Malpedia
│
├── sync_malpedia.py                          # 📥 ROTINA 1: Sync
├── populate_cti_cache.py                     # 🔨 ROTINA 2: MITRE Enrichment
├── populate_cti_cache_optimized.py           # 🚀 ROTINA 2 (otimizada)
├── enrich_missing_actors.py                  # 🤖 ROTINA 3: LLM Enrichment
├── populate_top_apt_cache.py                 # 🎯 Pre-populate top APTs
│
├── MALPEDIA_SYNC_README.md                   # Documentação de sync
├── CTI_BACKEND_PROCESS.md                    # Documentação do processo
└── ROTINAS_CTI_COMPLETAS.md                  # 👈 ESTE ARQUIVO
```

---

## 🔄 ROTINA COMPLETA - Execução Passo a Passo

### ✨ Cenário 1: Primeira Execução (Setup Inicial)

Execute esta rotina quando estiver configurando o sistema pela primeira vez.

#### PASSO 1: Sincronizar Dados do Malpedia

```bash
cd /Users/angellocassio/Documents/intelligence-platform/backend

# Sincronizar TODOS os actors do Malpedia (primeira vez)
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py

# Output esperado:
# 🚀 MALPEDIA ACTORS SYNC - Starting
# 📥 PHASE 1: Fetching actors list...
# ✅ Found 864 actors
# 🔄 PHASE 2: Processing actors...
# [1/864] APT28 ➕ NOVO
# [2/864] APT29 ➕ NOVO
# ...
# ✅ MALPEDIA ACTORS SYNC - Completed!
# 📊 Summary:
#    Total actors:    864
#    New:             864
#    Updated:         0
#    Unchanged:       0
# ⏱️  Time: ~45 minutes
```

**O que acontece:**
- Download de 864 páginas do Malpedia
- Parse de descrições, aliases, famílias, referências
- Cálculo de content_hash para cada actor
- Salvamento em `malpedia_actors` index
- **SEM PERDA**: Dados anteriores (se existirem) são preservados via upsert

#### PASSO 2: Enriquecer com MITRE ATT&CK (Oficial)

```bash
# Enriquecimento MITRE (versão otimizada com batching)
PYTHONPATH=$PWD venv/bin/python3 populate_cti_cache_optimized.py

# Output esperado:
# 🚀 Optimized CTI Cache Population - Starting
# 📥 Loading MITRE ATT&CK data...
# ✅ MITRE data loaded: 14 tactics, 216 techniques
#
# 🔄 Processing 864 actors...
# [171/864] ✅ APT28: 15 techniques mapped
# [342/864] ⏭️ DOPPEL SPIDER: No MITRE mapping
# ...
#
# ✅ Cache Population Complete!
# 📊 Summary:
#    Total processed:  864
#    MITRE mapped:     171 (19.8%)
#    No mapping:       693 (80.2%)
# ⏱️  Time: ~5 minutes
```

**O que acontece:**
- Carrega MITRE ATT&CK framework oficial
- Match de actors por nome exato, aliases, MITRE IDs
- Extrai técnicas associadas a cada actor
- Salva em `cti_enrichment_cache` com fonte "mitre_direct"
- **SEM PERDA**: Não sobrescreve dados, apenas adiciona novos

#### PASSO 3: Enriquecer com LLM (Inferência)

```bash
# Inferência LLM para actors sem MITRE mapping
# ATENÇÃO: Este processo pode demorar ~30-40 minutos e gera custo de API
PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py

# Opcional: Executar em background e monitorar logs
PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py > /tmp/llm_enrichment.log 2>&1 &

# Monitorar progresso:
tail -f /tmp/llm_enrichment.log

# Output esperado:
# 🤖 LLM Enrichment Service - Starting
# 📊 Found 693 actors without MITRE mapping
#
# [1/693] 🔄 Enriching: DOPPEL SPIDER
#         ✅ LLM inferred 10 techniques (confidence: medium)
# [2/693] 🔄 Enriching: DNSpionage
#         ✅ LLM inferred 9 techniques (confidence: medium)
# ...
# [693/693] ✅ All actors enriched!
#
# 📊 Final Summary:
#    Total processed:      693
#    Successfully enriched: 693 (100%)
#    Failed:               0
#    Average techniques:   9.2 per actor
#    Average confidence:   medium (99.4%)
# ⏱️  Time: ~35 minutes
# 💰 Cost: ~$0.02-0.03 USD (GPT-4o Mini)
```

**O que acontece:**
- Identifica actors sem MITRE mapping (693)
- Para cada actor:
  - Monta contexto (descrição + famílias + referências)
  - Envia prompt para GPT-4o Mini
  - Recebe técnicas inferidas + confiança + reasoning
  - Valida técnicas contra MITRE oficial
  - Salva em `cti_enrichment_cache` com fonte "llm_inference"
- **SEM PERDA**: Não sobrescreve enrichments MITRE existentes

#### PASSO 4: Validação

```bash
# Verificar contagem total de actors
curl -s http://localhost:9200/malpedia_actors/_count | jq '.count'
# Esperado: 864

# Verificar contagem de enrichments
curl -s http://localhost:9200/cti_enrichment_cache/_count | jq '.count'
# Esperado: 864 (100% de cobertura)

# Verificar distribuição de fontes
curl -s 'http://localhost:9200/cti_enrichment_cache/_search?size=0' -H 'Content-Type: application/json' -d '
{
  "aggs": {
    "by_source": {
      "terms": {"field": "enrichment_source.keyword"}
    }
  }
}' | jq '.aggregations.by_source.buckets'

# Esperado:
# [
#   {"key": "llm_inference", "doc_count": 693},
#   {"key": "mitre_direct", "doc_count": 171}
# ]
```

**✅ Primeira execução completa!** Agora você tem:
- 864 actors sincronizados
- 171 com MITRE oficial
- 693 com LLM inference
- 100% de cobertura
- Cache persistente

---

### 🔄 Cenário 2: Atualização Periódica (Semanal/Mensal)

Execute esta rotina periodicamente (recomendado: semanal).

#### PASSO 1: Sincronização Incremental

```bash
cd /Users/angellocassio/Documents/intelligence-platform/backend

# Sincronizar (detecta apenas mudanças)
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py

# Output esperado (update típico):
# 🚀 MALPEDIA ACTORS SYNC - Starting
# 📥 PHASE 1: Fetching actors list...
# ✅ Found 864 actors
# 🔄 PHASE 2: Processing actors...
# [1/864] APT28 ⏭️ sem mudanças
# [2/864] APT29 ⏭️ sem mudanças
# ...
# [156/864] BlueNoroff 🔄 ATUALIZADO (nova referência)
# [157/864] Lazarus ➕ NOVO
# ...
#
# ✅ MALPEDIA ACTORS SYNC - Completed!
# 📊 Summary:
#    Total actors:    864
#    New:             3      # 3 novos threat actors
#    Updated:         7      # 7 actors com novas informações
#    Unchanged:       854    # 854 sem mudanças
# ⏱️  Time: 2min 45s (22x mais rápido!)
#
# 💡 Next steps:
#    10 actors need enrichment (3 new + 7 updated)
#    Run: python3 populate_cti_cache_optimized.py
```

**Como funciona a detecção de mudanças:**

```python
# Exemplo de mudança detectada:
# Actor "BlueNoroff" ganhou nova referência

# ANTES (content_hash: a1b2c3...)
{
  "name": "BlueNoroff",
  "referencias": [
    {"desc": "Article 1", "url": "..."},
    {"desc": "Article 2", "url": "..."}
  ]
}

# DEPOIS (content_hash: d4e5f6... - DIFERENTE!)
{
  "name": "BlueNoroff",
  "referencias": [
    {"desc": "Article 1", "url": "..."},
    {"desc": "Article 2", "url": "..."},
    {"desc": "Article 3 - NEW!", "url": "..."}  # 👈 Nova referência
  ]
}

# Sistema detecta mudança automaticamente e marca como "ATUALIZADO"
```

#### PASSO 2: Re-enriquecimento (Apenas Necessário)

```bash
# Re-enriquecer APENAS os 10 actors novos/atualizados
# O script é inteligente: pula actors com cache válido
PYTHONPATH=$PWD venv/bin/python3 populate_cti_cache_optimized.py

# Output esperado:
# 🚀 Optimized CTI Cache Population - Starting
# 📊 Processing 864 actors...
#
# [1/10] 🔄 Lazarus (NEW)
#        ✅ 18 techniques mapped (MITRE direct)
# [2/10] 🔄 BlueNoroff (UPDATED)
#        ✅ Re-enriched: 12 techniques
# [3/10] ⏭️ APT28 (unchanged, cache valid)
# ...
#
# ✅ Cache Population Complete!
# 📊 Summary:
#    Processed:     10 (new/updated only)
#    Skipped:       854 (cache valid)
# ⏱️  Time: 30 seconds
```

#### PASSO 3: LLM Re-inference (Se Necessário)

```bash
# Apenas se houver novos actors SEM MITRE mapping
# O script pula actors já enriquecidos via LLM

PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py

# Output esperado (exemplo: 2 novos actors sem MITRE):
# 🤖 LLM Enrichment Service - Starting
# 📊 Found 2 actors without enrichment
#
# [1/2] 🔄 Enriching: New Ransomware Group XYZ
#       ✅ LLM inferred 11 techniques
# [2/2] 🔄 Enriching: Unknown APT-X
#       ✅ LLM inferred 8 techniques
#
# ✅ All actors enriched!
# ⏱️  Time: 15 seconds
# 💰 Cost: ~$0.0002 USD
```

**✅ Update completo!** Sistema atualizado com:
- Novos actors enriquecidos
- Actors existentes re-enriquecidos
- Cache preservado para actors sem mudanças
- ZERO perda de dados

---

## 🎯 Cenário 3: Rotina de Manutenção

### Verificar Integridade do Sistema

```bash
# 1. Verificar contagens
echo "=== ACTORS ==="
curl -s http://localhost:9200/malpedia_actors/_count | jq '.count'

echo "=== FAMILIES ==="
curl -s http://localhost:9200/malpedia_families/_count | jq '.count'

echo "=== ENRICHMENTS ==="
curl -s http://localhost:9200/cti_enrichment_cache/_count | jq '.count'

# 2. Verificar distribuição de fontes
curl -s 'http://localhost:9200/cti_enrichment_cache/_search?size=0' \
  -H 'Content-Type: application/json' -d '
{
  "aggs": {
    "sources": {"terms": {"field": "enrichment_source.keyword"}},
    "confidence": {"terms": {"field": "llm_inference.confidence.keyword"}}
  }
}' | jq '.aggregations'

# 3. Verificar actors sem enrichment
curl -s 'http://localhost:9200/malpedia_actors/_search' \
  -H 'Content-Type: application/json' -d '
{
  "query": {
    "bool": {
      "must_not": {
        "exists": {"field": "enrichment_cache_id"}
      }
    }
  },
  "size": 0
}' | jq '.hits.total.value'
# Esperado: 0 (todos devem estar enriquecidos)

# 4. Verificar últimas atualizações
curl -s 'http://localhost:9200/malpedia_actors/_search' \
  -H 'Content-Type: application/json' -d '
{
  "query": {"match_all": {}},
  "sort": [{"last_updated": "desc"}],
  "size": 5,
  "_source": ["name", "last_updated"]
}' | jq '.hits.hits[]._source'
```

### Re-processar Actor Específico

```bash
# Se precisar re-enriquecer um actor específico (força update)
curl -X POST "http://localhost:8001/api/v1/cti/enrich/APT28?force=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Limpar e Reconstruir Cache (CUIDADO!)

```bash
# ⚠️ ATENÇÃO: Isso deleta TODO o cache de enrichment!
# Use apenas se houver corrupção ou quiser reconstruir do zero

# 1. Backup do cache atual
curl -X POST "http://localhost:9200/cti_enrichment_cache/_search?scroll=1m" \
  -H 'Content-Type: application/json' -d '{"size": 1000}' \
  > /tmp/cti_cache_backup.json

# 2. Deletar índice
curl -X DELETE "http://localhost:9200/cti_enrichment_cache"

# 3. Recriar (será criado automaticamente no próximo enrichment)
# NADA A FAZER - o sistema cria automaticamente

# 4. Re-popular do zero
PYTHONPATH=$PWD venv/bin/python3 populate_cti_cache_optimized.py
PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py

# ⏱️ Tempo total: ~40-45 minutos
```

---

## 📊 Estrutura de Dados

### Índice: `malpedia_actors`

```json
{
  "_index": "malpedia_actors",
  "_id": "APT28",
  "_source": {
    "name": "APT28",
    "url": "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28",
    "aka": ["Fancy Bear", "Sofacy", "G0007", "STRONTIUM"],
    "explicacao": "APT28 is a threat group that has been attributed...",
    "familias_relacionadas": [
      "win.sedkit",
      "win.sofacy",
      "win.xagent"
    ],
    "referencias": [
      {
        "desc": "APT28: A Window Into Russia's Cyber Espionage Operations?",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf"
      }
    ],

    // 👇 Metadados para detecção de mudanças
    "content_hash": "a1b2c3d4e5f6789...",
    "last_updated": "2025-11-20T10:30:00Z",
    "created_at": "2025-11-15T08:00:00Z",
    "@timestamp": "2025-11-20T10:30:00Z"
  }
}
```

### Índice: `cti_enrichment_cache`

#### Exemplo 1: MITRE Direct Mapping

```json
{
  "_index": "cti_enrichment_cache",
  "_id": "APT28",
  "_source": {
    "actor_name": "APT28",
    "aliases": ["Fancy Bear", "Sofacy", "G0007"],

    // 👇 MITRE ATT&CK oficial
    "techniques": [
      "T1003.003",  // OS Credential Dumping: NTDS
      "T1566.001",  // Phishing: Spearphishing Attachment
      "T1059.001",  // Command and Scripting Interpreter: PowerShell
      "T1071.001",  // Application Layer Protocol: Web Protocols
      "T1055.001"   // Process Injection: Dynamic-link Library Injection
    ],
    "enrichment_source": "mitre_direct",
    "mitre_stix_id": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",

    // 👇 MISP Galaxy (geopolítico)
    "misp_galaxy": {
      "country": "RU",
      "description": "Russian cyber espionage group",
      "state_sponsor": "Russian Federation"
    },

    // 👇 Metadados
    "last_enriched": "2025-11-20T10:45:00Z",
    "@timestamp": "2025-11-20T10:45:00Z"
  }
}
```

#### Exemplo 2: LLM Inference

```json
{
  "_index": "cti_enrichment_cache",
  "_id": "DOPPEL_SPIDER",
  "_source": {
    "actor_name": "DOPPEL SPIDER",
    "aliases": ["Doppel Spider", "Doppelpaymer"],

    // 👇 Técnicas inferidas via LLM
    "techniques": [
      "T1566.001",  // Phishing: Spearphishing Attachment
      "T1486",      // Data Encrypted for Impact
      "T1561.002",  // Disk Wipe: Disk Structure Wipe
      "T1059.001",  // PowerShell
      "T1047",      // Windows Management Instrumentation
      "T1055.001",  // Process Injection
      "T1027",      // Obfuscated Files or Information
      "T1082",      // System Information Discovery
      "T1083",      // File and Directory Discovery
      "T1490"       // Inhibit System Recovery
    ],
    "enrichment_source": "llm_inference",

    // 👇 Metadados de inferência LLM
    "llm_inference": {
      "llm_used": "openai/gpt-4o-mini",
      "confidence": "medium",
      "reasoning": "As técnicas selecionadas refletem as práticas comuns de grupos de ransomware, como phishing para acesso inicial, uso de PowerShell para execução de scripts, descoberta de sistema para identificação de alvos valiosos, e criptografia de dados para extorsão.",
      "tokens_used": 135,
      "cost_usd": 0.0001
    },

    // 👇 MISP Galaxy (se disponível)
    "misp_galaxy": {
      "country": null,
      "description": null
    },

    // 👇 Metadados
    "last_enriched": "2025-11-20T11:57:35Z",
    "@timestamp": "2025-11-20T11:57:35Z"
  }
}
```

---

## ⚙️ Configuração e Otimização

### Variáveis de Ambiente (.env)

```bash
# LLM Provider para Inferência
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=4000

# Elasticsearch
ES_URL=http://localhost:9200
ES_USERNAME=
ES_PASSWORD=
```

### Rate Limiting

```python
# Em malpedia_sync_service.py
DELAY_BETWEEN_REQUESTS = 0.5  # 500ms (respeita o servidor Malpedia)

# Em llm_enrichment_service.py
# Automaticamente limitado pela API do OpenAI (3,500 RPM)
```

### Performance Tuning

```python
# populate_cti_cache_optimized.py
BATCH_SIZE = 100  # Processa 100 actors por vez

# enrich_missing_actors.py
CONCURRENT_REQUESTS = 1  # Não paralelizar (evita rate limit)
```

---

## 🔔 Monitoramento e Alertas

### Logs de Execução

```bash
# Formato dos logs
2025-11-20 10:30:00 - app.services.malpedia_sync_service - INFO - 🔄 Processing actors...
2025-11-20 10:30:01 - app.services.malpedia_sync_service - INFO - ➕ APT28: NOVO
2025-11-20 10:30:02 - app.services.malpedia_sync_service - INFO - 🔄 APT29: ATUALIZADO
2025-11-20 10:30:03 - app.services.malpedia_sync_service - DEBUG - ⏭️ Turla: sem mudanças
```

### Métricas Importantes

```bash
# Taxa de atualização semanal (média)
# - Novos actors: 0-5 por semana
# - Actors atualizados: 10-20 por semana
# - Taxa de mudança: ~2-3%

# Custo mensal de LLM (estimado)
# - Primeira execução: $0.02-0.03
# - Updates semanais: $0.001-0.002
# - Custo mensal: ~$0.05-0.10
```

### Health Check

```bash
# Script de health check (criar em: backend/health_check_cti.sh)
#!/bin/bash

echo "=== CTI HEALTH CHECK ==="
echo ""

# 1. Elasticsearch
echo "📊 Elasticsearch Status:"
curl -s http://localhost:9200/_cluster/health | jq '{status, number_of_nodes}'

# 2. Índices
echo ""
echo "📁 Index Counts:"
echo "  Actors: $(curl -s http://localhost:9200/malpedia_actors/_count | jq '.count')"
echo "  Families: $(curl -s http://localhost:9200/malpedia_families/_count | jq '.count')"
echo "  Cache: $(curl -s http://localhost:9200/cti_enrichment_cache/_count | jq '.count')"

# 3. Cobertura
TOTAL_ACTORS=$(curl -s http://localhost:9200/malpedia_actors/_count | jq '.count')
ENRICHED=$(curl -s http://localhost:9200/cti_enrichment_cache/_count | jq '.count')
COVERAGE=$((ENRICHED * 100 / TOTAL_ACTORS))
echo ""
echo "✅ Enrichment Coverage: ${COVERAGE}%"

# 4. Últimas atualizações
echo ""
echo "🕐 Latest Updates:"
curl -s 'http://localhost:9200/malpedia_actors/_search' -H 'Content-Type: application/json' -d '
{
  "query": {"match_all": {}},
  "sort": [{"last_updated": "desc"}],
  "size": 3,
  "_source": ["name", "last_updated"]
}' | jq -r '.hits.hits[]._source | "\(.name): \(.last_updated)"'

echo ""
echo "=== HEALTH CHECK COMPLETE ==="
```

Executar:
```bash
chmod +x backend/health_check_cti.sh
./backend/health_check_cti.sh
```

---

## 🐛 Troubleshooting

### Problema 1: Sync muito lento

**Sintoma**: Sincronização demora mais de 1 hora

**Causa**: Network throttling ou rate limiting do Malpedia

**Solução**:
```python
# Aumentar delay em malpedia_sync_service.py
DELAY_BETWEEN_REQUESTS = 1.0  # 1 segundo (mais conservador)
```

### Problema 2: LLM Enrichment falhando

**Sintoma**: Erro "API key invalid" ou "Rate limit exceeded"

**Causa**: Chave OpenAI inválida ou limite excedido

**Solução**:
```bash
# Verificar chave
grep OPENAI_API_KEY backend/.env

# Verificar quota
curl https://api.openai.com/v1/usage \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Usar provider alternativo (Databricks)
# Editar .env:
LLM_PROVIDER=databricks
```

### Problema 3: Todos os actors marcados como "NOVO" toda vez

**Sintoma**: Sync sempre mostra 864 novos, mesmo em updates

**Causa**: Campo `content_hash` não está sendo salvo

**Solução**:
```bash
# Re-criar índice com mapping correto
curl -X DELETE http://localhost:9200/malpedia_actors

# Re-sincronizar
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py
```

### Problema 4: Enrichment não encontra actors

**Sintoma**: "Actor not found" ao tentar enriquecer

**Causa**: Nome do actor com caracteres especiais ou case sensitivity

**Solução**:
```bash
# Verificar nome exato no Elasticsearch
curl -s 'http://localhost:9200/malpedia_actors/_search' \
  -H 'Content-Type: application/json' -d '
{
  "query": {"match": {"name": "apt28"}},
  "_source": ["name"]
}' | jq '.hits.hits[]._source.name'

# Usar nome exato retornado
```

---

## 📅 Rotina Recomendada de Manutenção

### Diário (Automático via Celery - Futuro)

```python
# TODO: Implementar Celery task
@shared_task(name="cti_daily_sync")
def cti_daily_sync():
    """
    Executa sincronização incremental diária
    Schedule: 2:00 AM UTC
    """
    # 1. Sync Malpedia
    stats = asyncio.run(sync_all_actors())

    # 2. Enrich novos/atualizados
    if stats['new'] + stats['updated'] > 0:
        enrich_stats = asyncio.run(enrich_new_actors())

    return stats
```

### Semanal (Manual)

```bash
# Toda segunda-feira, 9:00 AM
cd /Users/angellocassio/Documents/intelligence-platform/backend

# 1. Sync
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py

# 2. Re-enrichment (se houver updates)
PYTHONPATH=$PWD venv/bin/python3 populate_cti_cache_optimized.py

# 3. LLM inference (se houver novos sem MITRE)
PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py

# 4. Health check
./health_check_cti.sh
```

### Mensal (Manual)

```bash
# Primeiro dia útil do mês

# 1. Backup do cache
curl -X POST "http://localhost:9200/cti_enrichment_cache/_search?scroll=5m" \
  -H 'Content-Type: application/json' -d '{"size": 1000}' \
  > /tmp/cti_cache_backup_$(date +%Y%m%d).json

# 2. Sync completo
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py

# 3. Verificar integridade
./health_check_cti.sh

# 4. Relatório mensal
echo "=== CTI MONTHLY REPORT - $(date +%Y-%m) ===" > /tmp/cti_monthly_report.txt
curl -s 'http://localhost:9200/malpedia_actors/_search?size=0' \
  -H 'Content-Type: application/json' -d '
{
  "aggs": {
    "new_this_month": {
      "filter": {
        "range": {
          "created_at": {
            "gte": "now-1M/M"
          }
        }
      }
    },
    "updated_this_month": {
      "filter": {
        "range": {
          "last_updated": {
            "gte": "now-1M/M"
          }
        }
      }
    }
  }
}' | jq '.aggregations' >> /tmp/cti_monthly_report.txt

cat /tmp/cti_monthly_report.txt
```

---

## ✅ Checklist de Validação

Após cada execução completa, verificar:

- [ ] Contagem de actors: 864+ (pode aumentar com o tempo)
- [ ] Contagem de enrichments: igual à contagem de actors
- [ ] Cobertura: 100%
- [ ] Distribuição de fontes:
  - [ ] mitre_direct: ~19-20%
  - [ ] llm_inference: ~80-81%
- [ ] Todos os actors têm `content_hash`
- [ ] Todos os actors têm `last_updated`
- [ ] Cache tem timestamps recentes
- [ ] Nenhum erro nos logs
- [ ] Health check passou

---

## 📚 Referências

- **Malpedia**: https://malpedia.caad.fkie.fraunhofer.de/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **MISP Galaxy**: https://github.com/MISP/misp-galaxy
- **OpenAI API**: https://platform.openai.com/docs/

---

## 📝 Changelog de Rotinas

### v1.0 - 2025-11-20
- ✅ Sincronização incremental implementada
- ✅ Enrichment MITRE oficial
- ✅ Enrichment LLM (GPT-4o Mini)
- ✅ 100% de cobertura alcançada (864/864)
- ✅ Documentação completa

### v0.9 - 2025-11-19
- ✅ Sistema de content hash
- ✅ Detecção de mudanças
- ✅ Cache persistente

---

## 🎯 Conclusão

Este sistema de rotinas garante:

1. ✅ **ZERO perda de dados** - Sincronização incremental preserva histórico
2. ✅ **100% de cobertura** - Todos os actors enriquecidos (MITRE + LLM)
3. ✅ **Performance otimizada** - Updates 22x mais rápidos
4. ✅ **Custo controlado** - ~$0.05-0.10/mês de LLM
5. ✅ **Manutenibilidade** - Scripts simples e documentados

**Status atual**: ✅ Sistema 100% operacional e validado

---

**Autor**: Angello Cassio
**Data**: 2025-11-20
**Versão**: 1.0
