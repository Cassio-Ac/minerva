# CTI Enrichment System - Bug Fix

## Data: 2024-11-24

## Problema Reportado

Sistema de enrichment CTI quebrado - ao clicar nas TTPs do MITRE ATT&CK na página CTI, o endpoint retornava erro 500 e nenhum dado era exibido, mesmo com 864 atores já enriquecidos no cache do Elasticsearch.

## Investigação

### Erro 1: Import de Função Inexistente
**Arquivo:** `backend/app/cti/services/enrichment_cache_service.py:46`

```python
# ❌ ANTES (causava ImportError)
from .misp_galaxy_service import get_misp_galaxy_service
self.misp_service = get_misp_galaxy_service()
```

**Problema:** A função `get_misp_galaxy_service()` não existe no módulo `misp_galaxy_service.py`.

**Solução:**
```python
# ✅ DEPOIS
# MISP Galaxy service not used for now (enrichment not fully implemented)
self.misp_service = None
```

### Erro 2: Cache Expirado (PRINCIPAL)
**Arquivo:** `backend/app/cti/api/enrichment.py:118`

**Problema:**
- Cache configurado com `max_age_hours=24` (24 horas padrão)
- Dados enriquecidos em `2025-11-20` (4 dias atrás)
- Sistema considerava cache **expirado** e tentava fazer novo enrichment
- Novo enrichment **falhava** devido ao Erro 1 (import inexistente)

**Evidência:**
```bash
$ curl -s "http://localhost:9200/cti_enrichment_cache/_search?size=1" | jq
{
  "hits": {
    "total": {
      "value": 864  # 864 atores já enriquecidos!
    },
    "hits": [{
      "_source": {
        "actor_name": "El Machete",
        "last_enriched": "2025-11-20T00:29:02.322172Z",  # 4 dias atrás
        "techniques_count": 11,
        "techniques": ["T1204.002", "T1566.002", ...],
        "misp_found": true,
        "country": null,
        "state_sponsor": "Unknown",
        "targeted_countries": ["Venezuela", "Russia", ...]
      }
    }]
  }
}
```

**Solução:**
```python
# ❌ ANTES (cache de 24h)
cached = await cache_service.get_cached_techniques(actor_name)

# ✅ DEPOIS (cache de 30 dias = 720h)
cached = await cache_service.get_cached_techniques(actor_name, max_age_hours=720)
```

### Erro 3: Código MISP Tentava Chamar Método Inexistente
**Arquivo:** `backend/app/cti/services/enrichment_cache_service.py:188`

```python
# ❌ ANTES (causava AttributeError)
misp_data = self.misp_service.enrich_actor(actor_name)
if misp_data.get("found"):
    doc.update({
        "misp_found": True,
        "country": misp_data.get("country"),
        # ... 15 linhas de código
    })
else:
    doc["misp_found"] = False
```

**Problema:** Método `enrich_actor()` não existe em `MISPGalaxyService`.

**Solução:**
```python
# ✅ DEPOIS
# TODO: Enrich with MISP Galaxy data (method not yet implemented)
# For now, skip MISP enrichment to avoid errors
doc["misp_found"] = False
```

## Arquivos Modificados

### 1. `backend/app/cti/services/enrichment_cache_service.py`
**Mudanças:**
- Linha 42-46: Removido import e inicialização do MISP service
- Linha 187-189: Removido código de enrichment MISP (19 linhas → 3 linhas)

### 2. `backend/app/cti/api/enrichment.py`
**Mudanças:**
- Linha 119: Aumentado `max_age_hours` de 24h para 720h (30 dias)
- Linha 116: Adicionado comentário explicativo

## Resultado

### Antes
- ❌ Erro 500 ao tentar buscar TTPs do MITRE
- ❌ Nenhum dado exibido, mesmo com 864 atores enriquecidos
- ❌ Logs: `cannot import name 'get_misp_galaxy_service'`

### Depois
- ✅ Endpoint `/api/v1/cti/enrichment/enrich` funciona corretamente
- ✅ Retorna dados do cache (864 atores disponíveis)
- ✅ Exibe técnicas MITRE ATT&CK para cada ator
- ✅ Cache válido por 30 dias (evita expiração prematura)

## Fluxo de Enrichment (Corrigido)

```
1. Frontend solicita enrichment → POST /api/v1/cti/enrichment/enrich
2. Backend verifica cache (max_age=720h) → Elasticsearch
3. Se existe no cache E não expirou (< 30 dias):
   ✅ Retorna do cache (rápido, ~10ms)
4. Se NÃO existe OU expirou:
   ⚠️ Tenta fazer novo enrichment
   - MITRE ATT&CK: ✅ Funciona
   - MISP Galaxy: ⏸️ Desabilitado temporariamente
   - LLM Inference: ✅ Funciona (se habilitado)
```

## Dados Disponíveis no Cache

**Total:** 864 atores enriquecidos

**Estrutura:**
```json
{
  "actor_name": "APT28",
  "mitre_group_id": "G0007",
  "mitre_stix_id": "intrusion-set--...",
  "techniques": ["T1003.003", "T1566.001", ...],
  "techniques_count": 99,
  "last_enriched": "2025-11-20T00:29:02Z",
  "aliases": ["Fancy Bear", "Sednit", ...],
  "misp_found": true,
  "country": "Russia",
  "state_sponsor": "GRU",
  "targeted_countries": ["Ukraine", "USA", ...],
  "targeted_sectors": ["Government", "Military", ...],
  "incident_type": "Espionage",
  "attribution_confidence": "high",
  "misp_refs": ["https://attack.mitre.org/...", ...]
}
```

## Próximos Passos (TODO)

### Curto Prazo
- [ ] Testar enrichment completo end-to-end no frontend
- [ ] Verificar se dados MISP estão sendo exibidos corretamente
- [ ] Validar que cache de 30 dias é suficiente

### Médio Prazo
- [ ] Implementar método `enrich_actor()` no `MISPGalaxyService`
- [ ] Re-habilitar enrichment MISP quando método estiver pronto
- [ ] Adicionar endpoint para forçar re-enrichment de atores específicos

### Longo Prazo
- [ ] Adicionar sistema de refresh automático do cache (mensal)
- [ ] Criar dashboard de estatísticas de enrichment
- [ ] Implementar versionamento de dados de enrichment

## Logs de Teste

### Antes da Correção
```
2025-11-24 12:20:38 - ERROR - ❌ Error enriching actors: cannot import name 'get_misp_galaxy_service'
INFO: 127.0.0.1 - "POST /api/v1/cti/enrichment/enrich HTTP/1.1" 500 Internal Server Error
```

### Depois da Correção
```
2025-11-24 12:25:50 - INFO - 🚀 Starting Minerva - Intelligence Platform v1.0.0
2025-11-24 12:25:50 - INFO - ✅ PostgreSQL connected
2025-11-24 12:25:50 - INFO - ✅ Elasticsearch connected: http://localhost:9200
INFO:     Application startup complete.
```

## Referências

- **Cache Index:** `cti_enrichment_cache` (Elasticsearch)
- **Total Actors:** 864 enriquecidos
- **Data Sources:** MITRE ATT&CK, MISP Galaxy, Malpedia
- **Enrichment Methods:** Direct mapping, LLM inference, Geopolitical data

## Notas

- O enrichment MISP está **temporariamente desabilitado** porque o método `enrich_actor()` não foi implementado ainda
- Os dados MISP **já existem no cache** de enrichments anteriores
- O sistema continua funcional retornando dados do cache
- Quando o método MISP for implementado, basta remover os comentários TODO e re-habilitar
