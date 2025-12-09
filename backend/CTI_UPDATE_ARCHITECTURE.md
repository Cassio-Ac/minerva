# Arquitetura de Atualização CTI - Incremental e Enriquecida

## 📋 Visão Geral

Sistema de atualização incremental para dados do Malpedia com enriquecimento MITRE ATT&CK e inferência via LLM.

## 🏗️ Arquitetura Atual vs. Proposta

### Atual (BHACK_2025/MALPEDIA)

```
┌─────────────────────────────────────────────────────────────┐
│                    PIPELINE ATUAL                            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Download Malpedia (families.py, actors.py)              │
│  2. Enriquecimento básico (enrich_*.py)                     │
│  3. Salvamento em arquivos JSON                             │
│  4. Envio para Elasticsearch (enviar_elk.py)                │
│                                                               │
│  ❌ Problema: SEMPRE reinsere TUDO (skip se ID existir)     │
│  ❌ Problema: Não detecta atualizações em docs existentes   │
│  ❌ Problema: Não tem cache de enriquecimento MITRE         │
└─────────────────────────────────────────────────────────────┘
```

### Proposta (Intelligence Platform)

```
┌───────────────────────────────────────────────────────────────────────┐
│                    ARQUITETURA PROPOSTA                                │
├───────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  ÍNDICES ELASTICSEARCH                                        │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                                │    │
│  │  1. malpedia_actors (dados brutos do Malpedia)               │    │
│  │     • name, aka, explicacao, familias_relacionadas            │    │
│  │     • referencias (array de artigos)                          │    │
│  │     • last_updated (timestamp da última atualização)          │    │
│  │     • content_hash (hash do conteúdo para detectar mudanças)  │    │
│  │                                                                │    │
│  │  2. malpedia_families (dados brutos do Malpedia)             │    │
│  │     • name, description, common_name, attack                  │    │
│  │     • last_updated, content_hash                              │    │
│  │                                                                │    │
│  │  3. cti_enrichment_cache (MITRE + MISP + LLM Inference)      │    │
│  │     • actor_name (chave)                                      │    │
│  │     • techniques (array de IDs MITRE)                         │    │
│  │     • mitre_stix_id, aliases                                  │    │
│  │     • MISP data (country, state_sponsor, etc.)                │    │
│  │     • llm_inferred_techniques (técnicas inferidas)            │    │
│  │     • inference_confidence (alta/média/baixa)                 │    │
│  │     • inference_reasoning (justificativa)                     │    │
│  │     • enrichment_version (v1, v2, etc.)                       │    │
│  │     • last_enriched (timestamp)                               │    │
│  │     • enrichment_source (mitre_api, llm_inference, manual)    │    │
│  │                                                                │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  PIPELINE DE ATUALIZAÇÃO (Celery Task)                       │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                                │    │
│  │  FASE 1: Sincronização Malpedia (Incremental)                │    │
│  │  ──────────────────────────────────────────────────────────   │    │
│  │  1. Download dados do Malpedia (API)                          │    │
│  │  2. Para cada documento:                                       │    │
│  │     a. Calcular content_hash (MD5 do JSON)                    │    │
│  │     b. Verificar se existe no ES                              │    │
│  │     c. Se não existe → INSERT                                 │    │
│  │     d. Se existe:                                              │    │
│  │        - Comparar content_hash                                 │    │
│  │        - Se diferente → UPDATE (dados novos/atualizados)      │    │
│  │        - Se igual → SKIP (nada mudou)                         │    │
│  │  3. Retorna lista de atores NOVOS ou ATUALIZADOS             │    │
│  │                                                                │    │
│  │  FASE 2: Enriquecimento MITRE (Incremental)                  │    │
│  │  ──────────────────────────────────────────────────────────   │    │
│  │  1. Para cada ator NOVO ou ATUALIZADO:                        │    │
│  │     a. Verificar se já tem cache de enriquecimento            │    │
│  │     b. Se tem cache válido (< 30 dias) → SKIP                 │    │
│  │     c. Se não tem ou expirado:                                │    │
│  │        - Tentar enriquecer via MITRE API                      │    │
│  │        - Se encontrou → salvar no cache                       │    │
│  │        - Se não encontrou → marcar para inferência LLM        │    │
│  │                                                                │    │
│  │  FASE 3: Inferência LLM (Somente atores sem MITRE)           │    │
│  │  ──────────────────────────────────────────────────────────   │    │
│  │  1. Para cada ator SEM mapping MITRE:                         │    │
│  │     a. Verificar se já tem inferência (enrichment_version)    │    │
│  │     b. Se tem inferência válida → SKIP                        │    │
│  │     c. Se não tem ou versão antiga:                           │    │
│  │        - Montar contexto (descrição + famílias + refs)        │    │
│  │        - Chamar LLM para inferir técnicas                     │    │
│  │        - Salvar técnicas inferidas com nível de confiança     │    │
│  │        - Salvar reasoning (explicação)                        │    │
│  │                                                                │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                         │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Fluxo de Atualização Incremental

### 1. Detecção de Mudanças

```python
def detect_changes(malpedia_doc, es_doc):
    """
    Detecta se um documento mudou

    Returns:
        - "new": Documento não existe no ES
        - "updated": Documento existe mas mudou
        - "unchanged": Documento igual
    """
    if not es_doc:
        return "new"

    # Calcula hash do conteúdo
    new_hash = hashlib.md5(json.dumps(malpedia_doc, sort_keys=True).encode()).hexdigest()
    old_hash = es_doc.get("content_hash")

    if new_hash != old_hash:
        return "updated"

    return "unchanged"
```

### 2. Atualização Inteligente

```python
def update_malpedia_data(actor_data):
    """
    Atualiza dados do Malpedia de forma incremental
    """
    es = get_es_client()

    # Verifica se existe
    existing = get_actor_from_es(actor_data["name"])

    # Detecta mudança
    change_type = detect_changes(actor_data, existing)

    if change_type == "unchanged":
        logger.info(f"⏭️ {actor_data['name']}: sem mudanças")
        return None

    # Adiciona metadados
    actor_data["content_hash"] = calculate_hash(actor_data)
    actor_data["last_updated"] = datetime.utcnow()

    if change_type == "new":
        logger.info(f"➕ {actor_data['name']}: NOVO")
        es.index(index="malpedia_actors", id=actor_data["name"], body=actor_data)
    else:
        logger.info(f"🔄 {actor_data['name']}: ATUALIZADO")
        es.update(index="malpedia_actors", id=actor_data["name"], body={"doc": actor_data})

    return change_type  # Retorna para enriquecer depois
```

### 3. Enriquecimento Condicional

```python
async def conditional_enrichment(actor_name, change_type):
    """
    Enriquece apenas se necessário
    """
    cache_service = get_enrichment_cache_service()

    # Verifica cache existente
    cached = await cache_service.get_cached_techniques(
        actor_name,
        max_age_hours=720  # 30 dias
    )

    # Decisão de enriquecer
    should_enrich = (
        change_type == "new" or  # Sempre enriquece novos
        change_type == "updated" or  # Sempre re-enriquece atualizados
        cached is None  # Enriquece se não tem cache
    )

    if not should_enrich:
        logger.info(f"⏭️ {actor_name}: cache válido, pulando enriquecimento")
        return

    # Enriquece
    logger.info(f"🔨 {actor_name}: enriquecendo...")
    techniques = await cache_service.enrich_and_cache_actor(actor_name)

    return techniques
```

---

## 📊 Estrutura do Cache Enriquecido

### Documento no `cti_enrichment_cache`

```json
{
  "actor_name": "APT28",
  "aliases": ["Fancy Bear", "Sofacy", "G0007"],

  // MITRE ATT&CK oficial (se existir)
  "mitre_stix_id": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",
  "techniques": ["T1003.003", "T1566.001", ...],
  "enrichment_source": "mitre_api",

  // MISP Galaxy geopolitical
  "misp_found": true,
  "country": "RU",
  "state_sponsor": "Russian Federation",
  "military_unit": "GRU Unit 26165",
  "targeted_countries": ["US", "UK", "FR", ...],
  "targeted_sectors": ["government", "military", "energy"],

  // LLM Inference (se não tiver MITRE oficial)
  "llm_inferred_techniques": [
    {
      "technique_id": "T1059.001",
      "confidence": "high",
      "reasoning": "Actor description mentions 'utilize PowerShell scripts for their attacks'",
      "evidence_type": "direct_mention"
    },
    {
      "technique_id": "T1486",
      "confidence": "high",
      "reasoning": "Confirmed ransomware group using multiple ransomware families",
      "evidence_type": "malware_family"
    }
  ],
  "inference_confidence": "high",  // high, medium, low
  "inference_reasoning": "Based on actor description, malware families, and 137 technical references",

  // Metadados de enriquecimento
  "enrichment_version": "v2",  // Incrementa quando o algoritmo melhora
  "last_enriched": "2025-11-19T21:45:00Z",
  "created_at": "2025-11-15T10:30:00Z"
}
```

---

## 🎯 Estratégia de Inferência LLM

### Quando Inferir

```python
def should_infer_techniques(actor_name):
    """
    Decide se deve inferir técnicas via LLM
    """
    cache = get_cached_enrichment(actor_name)

    # Critérios:
    # 1. Não tem MITRE oficial
    # 2. Não tem inferência ou versão antiga
    # 3. Ator tem dados suficientes (descrição ou famílias)

    has_mitre = cache and cache.get("mitre_stix_id")
    has_inference = cache and cache.get("llm_inferred_techniques")
    inference_version = cache.get("enrichment_version") if cache else None

    CURRENT_VERSION = "v2"

    if has_mitre:
        return False  # Já tem MITRE oficial, não precisa inferir

    if has_inference and inference_version == CURRENT_VERSION:
        return False  # Já tem inferência atualizada

    # Verifica se tem dados suficientes
    actor = get_actor_from_malpedia(actor_name)
    has_data = (
        actor.get("explicacao") or  # Tem descrição
        actor.get("familias_relacionadas") or  # Tem famílias
        len(actor.get("referencias", [])) > 5  # Tem referências
    )

    return has_data
```

### Prompt para LLM

```python
INFERENCE_PROMPT = """
You are a cybersecurity threat intelligence analyst specializing in mapping threat actor TTPs to MITRE ATT&CK framework.

Given the following information about a threat actor, infer the MITRE ATT&CK techniques they likely use.

**Threat Actor**: {actor_name}
**Aliases**: {aliases}
**Description**: {description}
**Malware Families**: {families}
**Number of Technical References**: {num_refs}

**Instructions**:
1. Analyze the actor description for direct mentions of techniques
2. Map known malware families to their typical techniques
3. Infer techniques based on actor type (APT, ransomware, cybercrime)
4. For each technique, provide:
   - Technique ID (e.g., T1059.001)
   - Confidence level (high, medium, low)
   - Reasoning (why you inferred this technique)
   - Evidence type (direct_mention, malware_family, behavioral_inference)

**Output Format** (JSON):
```json
{
  "techniques": [
    {
      "technique_id": "T1059.001",
      "confidence": "high",
      "reasoning": "Description explicitly mentions 'utilize PowerShell scripts'",
      "evidence_type": "direct_mention"
    },
    ...
  ],
  "overall_confidence": "high",
  "summary": "Brief summary of inference methodology"
}
```

Focus on techniques with HIGH confidence (direct evidence). Only include MEDIUM confidence if there's strong behavioral evidence.
"""
```

---

## 🔧 Implementação Prática

### Task Celery para Atualização Periódica

```python
# backend/app/tasks/update_malpedia.py

from celery import shared_task
import logging

logger = logging.getLogger(__name__)

@shared_task(name="update_malpedia_incremental")
def update_malpedia_incremental():
    """
    Task periódica para atualizar Malpedia incrementalmente

    Executar: diariamente às 2AM
    """
    logger.info("🚀 Starting incremental Malpedia update...")

    # FASE 1: Atualizar dados brutos do Malpedia
    new_actors, updated_actors = sync_malpedia_data()

    logger.info(f"📊 Sync complete: {len(new_actors)} new, {len(updated_actors)} updated")

    # FASE 2: Enriquecer com MITRE
    actors_to_enrich = new_actors + updated_actors
    enriched_count = 0

    for actor_name in actors_to_enrich:
        try:
            techniques = conditional_enrichment(actor_name, "new" if actor_name in new_actors else "updated")
            if techniques:
                enriched_count += 1
        except Exception as e:
            logger.error(f"Error enriching {actor_name}: {e}")

    logger.info(f"✅ Enriched {enriched_count}/{len(actors_to_enrich)} actors")

    # FASE 3: Inferir técnicas via LLM (para atores sem MITRE)
    inferred_count = infer_missing_techniques()

    logger.info(f"🤖 Inferred techniques for {inferred_count} actors")

    return {
        "new_actors": len(new_actors),
        "updated_actors": len(updated_actors),
        "enriched": enriched_count,
        "inferred": inferred_count
    }


def sync_malpedia_data():
    """
    Sincroniza dados do Malpedia de forma incremental
    """
    # Executar script externo (BHACK_2025/MALPEDIA/coletar_e_enviar.py)
    # MAS com lógica de hash para detectar mudanças

    # OU integrar diretamente a lógica aqui
    pass


def infer_missing_techniques():
    """
    Infere técnicas MITRE via LLM para atores sem mapping oficial
    """
    # Busca atores sem MITRE
    # Para cada um, chama LLM para inferir
    # Salva no cache com flag de inferência
    pass
```

### Configuração Celery Beat

```python
# backend/app/celery_app.py

from celery.schedules import crontab

app.conf.beat_schedule = {
    'update-malpedia-daily': {
        'task': 'update_malpedia_incremental',
        'schedule': crontab(hour=2, minute=0),  # Diariamente às 2AM
    },
}
```

---

## 📝 Próximos Passos

### 1. Adaptar Script de Coleta (Prioridade ALTA)

**Arquivo**: `/Users/angellocassio/Documents/BHACK_2025/APRESENTACAO/MALPEDIA/enviar_elk.py`

**Mudanças Necessárias**:
- ✅ Adicionar campo `content_hash` ao indexar documentos
- ✅ Adicionar campo `last_updated` (timestamp)
- ✅ Mudar lógica de "pular se existe" para "comparar hash e atualizar se diferente"
- ✅ Retornar lista de documentos NOVOS e ATUALIZADOS

### 2. Criar Serviço de Inferência LLM (Prioridade MÉDIA)

**Arquivo**: `backend/app/cti/services/llm_inference_service.py`

**Funcionalidades**:
- ✅ Montar contexto do ator (descrição + famílias + refs)
- ✅ Chamar LLM com prompt estruturado
- ✅ Parsear resposta JSON
- ✅ Validar técnicas retornadas (existem no MITRE?)
- ✅ Salvar no cache com metadados de inferência

### 3. Criar Task Celery (Prioridade MÉDIA)

**Arquivo**: `backend/app/tasks/update_malpedia.py`

**Funcionalidades**:
- ✅ Orquestrar pipeline completo
- ✅ Logging detalhado
- ✅ Retry logic
- ✅ Notificações de erro

### 4. Atualizar Frontend (Prioridade BAIXA)

**Funcionalidades**:
- ✅ Mostrar badge "Inferred" para técnicas inferidas
- ✅ Tooltip explicando a inferência
- ✅ Filtro para mostrar só técnicas oficiais ou incluir inferidas
- ✅ Nível de confiança visual (🟢 alta, 🟡 média, 🔴 baixa)

---

## ✅ Benefícios da Arquitetura

1. **Performance**: Atualização incremental (minutos vs horas)
2. **Cobertura**: De 19.8% → ~70%+ com inferência LLM
3. **Manutenibilidade**: Cache separado, fácil de invalidar/atualizar
4. **Rastreabilidade**: Metadados de enriquecimento (versão, fonte, timestamp)
5. **Escalabilidade**: Celery para processamento assíncrono
6. **Confiabilidade**: Diferenciação entre dados oficiais e inferidos

---

**Gerado em**: 2025-11-19
**Versão**: 1.0
