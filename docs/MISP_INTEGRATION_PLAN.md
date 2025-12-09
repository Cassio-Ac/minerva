# 🔗 MISP Integration - Import-Only Implementation Plan

**Data**: 2025-11-20
**Status**: 🚀 Implementação
**Prioridade**: ⭐⭐⭐ Alta
**Modo**: 📥 Import-Only (Read-Only)

---

## 📋 Executive Summary

**O que é MISP?**
MISP (Malware Information Sharing Platform) é uma plataforma open-source para compartilhamento de threat intelligence, usada por 10,000+ organizações globalmente (governos, SOCs, CERTs, ISACs).

**Por que integrar (Import-Only)?**
- ✅ **Importar IOCs gratuitos** de feeds públicos (IPs, domains, hashes, URLs)
- ✅ **Enriquecer análises** com inteligência da comunidade global
- ✅ **Validar IOCs** em investigações com dados MISP
- ✅ **Zero-Cost Intelligence** - ~3,700 IOCs/dia de feeds públicos
- ✅ **Sem exposição** - Nada sai da plataforma, apenas consumimos

**⚠️ O que NÃO faremos nesta versão:**
- ❌ Exportar actors/families para MISP
- ❌ Compartilhar nossa inteligência
- ❌ Sync bidirecional
- ❌ Publicar eventos

---

## 🎯 Objetivos da Integração (Import-Only)

### 1. Consumir Feeds Públicos
Importar IOCs de feeds MISP públicos:
- **CIRCL OSINT Feed** (~500 IOCs/dia, gratuito)
- **Botvrij.eu** (~200 IOCs/dia, gratuito)
- **URLhaus** (~1000 IOCs/dia, gratuito)
- **AlienVault OTX** (~2000 IOCs/dia, gratuito com registro)

**Total potencial: ~3,700 IOCs/dia sem custo!**

### 2. Enriquecer Investigações
- Buscar se IP/domain/hash é malicioso
- Obter contexto: "WannaCry C2 server"
- Ver malware family relacionada
- Ver threat actor relacionado
- Timeline de primeira/última observação

### 3. Correlacionar com CTI Existente
- Correlacionar IOCs com nossos 864 actors
- Correlacionar IOCs com 3,591 families
- Exibir "MISP Intelligence" em páginas de actors
- Badge "🔴 Known MISP IOC" em resultados de busca

---

## 🏗️ Arquitetura Simplificada

### Estrutura de Código

```
backend/app/cti/
├── api/
│   ├── actors.py           ✅ Existente
│   ├── families.py         ✅ Existente
│   ├── techniques.py       ✅ Existente
│   ├── enrichment.py       ✅ Existente
│   └── misp_feeds.py      🆕 NOVO - Endpoints feeds
│
├── services/
│   ├── malpedia_service.py         ✅ Existente
│   ├── attack_service.py           ✅ Existente
│   ├── misp_feed_service.py       🆕 NOVO - Consumir feeds (CORE)
│   └── misp_correlation_service.py 🆕 NOVO - Correlacionar IOCs
│
├── schemas/
│   ├── actor.py            ✅ Existente
│   ├── family.py           ✅ Existente
│   ├── technique.py        ✅ Existente
│   └── misp_ioc.py        🆕 NOVO - Schema IOC
│
└── models/
    ├── misp_feed.py        🆕 NOVO - Config de feeds
    └── misp_ioc.py         🆕 NOVO - IOCs importados
```

### Frontend Components

```
frontend/src/components/cti/misp/
├── MISPBadge.tsx              🆕 Badge "Known IOC"
├── MISPIntelligenceSection.tsx 🆕 Seção MISP em actors
├── MISPFeedDashboard.tsx      🆕 Dashboard de feeds
├── MISPIOCSearch.tsx          🆕 Busca de IOCs
└── MISPFeedConfig.tsx         🆕 Configurar feeds
```

### Banco de Dados (PostgreSQL)

```sql
-- Feeds MISP configurados
CREATE TABLE misp_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR NOT NULL,
    url VARCHAR NOT NULL,
    feed_type VARCHAR DEFAULT 'misp',  -- 'misp', 'csv', 'freetext'
    is_active BOOLEAN DEFAULT true,
    is_public BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP,
    total_iocs_imported INT DEFAULT 0,
    sync_frequency VARCHAR DEFAULT 'daily',  -- 'hourly', 'daily', 'weekly'
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- IOCs importados do MISP
CREATE TABLE misp_iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id UUID REFERENCES misp_feeds(id) ON DELETE CASCADE,
    ioc_type VARCHAR NOT NULL,  -- 'ip', 'domain', 'hash', 'url', 'email'
    ioc_subtype VARCHAR,  -- 'md5', 'sha256', 'ip-dst', 'ip-src', etc
    ioc_value TEXT NOT NULL,
    context TEXT,  -- Ex: "WannaCry C2 server"
    malware_family VARCHAR,
    threat_actor VARCHAR,
    tags TEXT[],  -- Array de tags
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    tlp VARCHAR DEFAULT 'white',  -- 'white', 'green', 'amber', 'red'
    confidence VARCHAR DEFAULT 'medium',  -- 'low', 'medium', 'high'
    to_ids BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Índices para performance
CREATE INDEX idx_misp_iocs_value ON misp_iocs(ioc_value);
CREATE INDEX idx_misp_iocs_type ON misp_iocs(ioc_type);
CREATE INDEX idx_misp_iocs_feed ON misp_iocs(feed_id);
CREATE INDEX idx_misp_iocs_family ON misp_iocs(malware_family);
CREATE INDEX idx_misp_iocs_actor ON misp_iocs(threat_actor);
CREATE UNIQUE INDEX idx_misp_iocs_unique ON misp_iocs(ioc_value, feed_id);
```

### Elasticsearch Index

```json
// misp_iocs - Busca rápida de IOCs
{
  "mappings": {
    "properties": {
      "ioc_value": {"type": "keyword"},
      "ioc_type": {"type": "keyword"},
      "ioc_subtype": {"type": "keyword"},
      "context": {"type": "text"},
      "malware_family": {"type": "keyword"},
      "threat_actor": {"type": "keyword"},
      "tags": {"type": "keyword"},
      "first_seen": {"type": "date"},
      "last_seen": {"type": "date"},
      "tlp": {"type": "keyword"},
      "confidence": {"type": "keyword"},
      "to_ids": {"type": "boolean"},
      "feed_name": {"type": "keyword"}
    }
  }
}
```

---

## 📅 Roadmap de Implementação (3 Fases)

### 🚀 Phase 1: Foundation (2-3 dias) - PRIORIDADE ALTA

**Objetivo**: Importar IOCs de 1 feed público funcionando

**Tasks:**

1. **Instalar PyMISP**
   ```bash
   pip install pymisp
   echo "pymisp==2.4.180" >> requirements.txt
   ```

2. **Criar Models**
   - `backend/app/cti/models/misp_feed.py`
   - `backend/app/cti/models/misp_ioc.py`
   - Migração Alembic

3. **Criar Feed Service**
   - `backend/app/cti/services/misp_feed_service.py`
   - Implementar `fetch_circl_feed()` (feed público)
   - Implementar `import_iocs()` (salvar no PostgreSQL + ES)
   - Implementar `deduplicate_iocs()` (evitar duplicatas)

4. **Criar Endpoints**
   ```python
   POST /api/v1/cti/misp/feeds/sync           # Sync manual
   GET  /api/v1/cti/misp/feeds                # Listar feeds
   GET  /api/v1/cti/misp/iocs/search?value=X  # Buscar IOC
   GET  /api/v1/cti/misp/iocs/stats           # Estatísticas
   ```

5. **Criar Elasticsearch Index**
   ```bash
   curl -X PUT "localhost:9200/misp_iocs"
   ```

6. **Testing**
   - Importar IOCs do CIRCL (feed público)
   - Verificar salvamento no PostgreSQL
   - Verificar indexação no Elasticsearch
   - Testar busca de IOC específico

**Deliverables:**
- ✅ PyMISP instalado
- ✅ Models criados
- ✅ Migração rodada
- ✅ Feed service funcionando
- ✅ Endpoints criados
- ✅ 100+ IOCs importados de teste

**Estimativa**: 2-3 dias

---

### 🔍 Phase 2: Enrichment (2-3 dias) - PRIORIDADE ALTA

**Objetivo**: Exibir inteligência MISP na UI

**Tasks:**

1. **API de Busca**
   ```python
   GET /api/v1/cti/misp/iocs/search?value=185.176.43.94
   # Response:
   {
     "found": true,
     "ioc_type": "ip",
     "ioc_value": "185.176.43.94",
     "context": "WannaCry C2 server",
     "malware_family": "WannaCry",
     "threat_actor": "Lazarus Group",
     "first_seen": "2025-11-01T10:00:00Z",
     "tlp": "white",
     "confidence": "high"
   }
   ```

2. **Correlation Service**
   - `backend/app/cti/services/misp_correlation_service.py`
   - Correlacionar IOCs com actors (por malware_family, threat_actor)
   - Endpoint GET `/api/v1/cti/actors/{name}/misp-iocs`

3. **Frontend Components**
   - `MISPBadge.tsx` - Badge "🔴 Known MISP IOC" em resultados
   - `MISPIntelligenceSection.tsx` - Seção em páginas de actors
   - `MISPIOCSearch.tsx` - Busca de IOCs standalone

4. **Integração em Actors**
   - Adicionar seção "MISP Intelligence" em `ActorDetailPage`
   - Exibir IOCs relacionados ao actor
   - Mostrar estatísticas: total IOCs, tipos, última observação

5. **Testing**
   - Buscar IP conhecido no MISP
   - Verificar badge aparecendo
   - Verificar seção MISP em páginas de actors
   - Testar componente de busca standalone

**Deliverables:**
- ✅ API de busca funcionando
- ✅ Correlation service implementado
- ✅ Components React criados
- ✅ Seção MISP em actors
- ✅ Badges funcionando

**Estimativa**: 2-3 dias

---

### 🔄 Phase 3: Automation (1-2 dias) - PRIORIDADE MÉDIA

**Objetivo**: Sync automático de feeds via Celery

**Tasks:**

1. **Celery Tasks**
   ```python
   # backend/app/cti/tasks/misp_tasks.py

   @shared_task
   def sync_misp_feeds_daily():
       """Sincronizar todos os feeds ativos (roda diariamente às 3AM)"""
       service = MISPFeedService()
       feeds = db.query(MISPFeed).filter(MISPFeed.is_active == True).all()

       total_imported = 0
       for feed in feeds:
           iocs = service.fetch_feed(feed)
           service.import_iocs(iocs, feed.id)
           total_imported += len(iocs)

       logger.info(f"✅ MISP sync complete: {total_imported} IOCs imported")
       return total_imported

   @shared_task
   def cleanup_old_iocs():
       """Limpar IOCs antigos (>90 dias)"""
       cutoff = datetime.now() - timedelta(days=90)
       deleted = db.query(MISPIoC).filter(
           MISPIoC.last_seen < cutoff
       ).delete()
       logger.info(f"🗑️ Cleaned up {deleted} old IOCs")
   ```

2. **Celery Beat Schedule**
   ```python
   # backend/app/core/celery_config.py
   beat_schedule = {
       'sync-misp-feeds-daily': {
           'task': 'app.cti.tasks.misp_tasks.sync_misp_feeds_daily',
           'schedule': crontab(hour=3, minute=0),  # 3AM diário
       },
       'cleanup-old-iocs-weekly': {
           'task': 'app.cti.tasks.misp_tasks.cleanup_old_iocs',
           'schedule': crontab(day_of_week=0, hour=4, minute=0),  # Domingo 4AM
       }
   }
   ```

3. **Feed Configuration UI**
   - `MISPFeedDashboard.tsx` - Dashboard de feeds
   - Listar feeds configurados
   - Mostrar status: ativo/inativo, última sync, total IOCs
   - Botão "Sync Now" (manual)
   - Botão "Add Feed" (adicionar novo feed)

4. **Feed Manager**
   - `MISPFeedConfig.tsx` - Formulário de configuração
   - Campos: name, url, feed_type, sync_frequency
   - Toggle ativo/inativo
   - Testar conexão

5. **Adicionar Feeds Públicos Pré-configurados**
   ```python
   # Script para popular feeds públicos
   PUBLIC_FEEDS = [
       {
           "name": "CIRCL OSINT Feed",
           "url": "https://www.circl.lu/doc/misp/feed-osint/",
           "feed_type": "misp",
           "is_public": True
       },
       {
           "name": "Botvrij.eu",
           "url": "https://www.botvrij.eu/data/feed-osint/",
           "feed_type": "csv",
           "is_public": True
       },
       {
           "name": "URLhaus",
           "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
           "feed_type": "csv",
           "is_public": True
       }
   ]
   ```

6. **Testing**
   - Rodar task manualmente via Celery
   - Verificar logs de sync
   - Verificar dashboard mostrando status correto
   - Testar adicionar novo feed via UI

**Deliverables:**
- ✅ Celery tasks criados
- ✅ Beat schedule configurado
- ✅ Dashboard de feeds funcionando
- ✅ 3+ feeds públicos configurados
- ✅ Sync automático rodando

**Estimativa**: 1-2 dias

---

## 📊 Feeds Públicos Disponíveis

| Feed | URL | Tipo | IOCs/dia | Custo | TLP |
|------|-----|------|----------|-------|-----|
| **CIRCL OSINT** | circl.lu/doc/misp/feed-osint | MISP JSON | ~500 | Grátis | WHITE |
| **Botvrij.eu** | botvrij.eu/data/feed-osint | CSV | ~200 | Grátis | WHITE |
| **URLhaus** | urlhaus.abuse.ch/downloads | CSV | ~1000 | Grátis | WHITE |
| **AlienVault OTX** | otx.alienvault.com | API | ~2000 | Grátis* | WHITE |

**Total: ~3,700 IOCs/dia gratuitos!**

\* AlienVault OTX requer registro gratuito para obter API key

---

## 🎯 Casos de Uso

### Caso 1: Analista Investigando IP Suspeito

**Cenário**: Analista vê IP `185.176.43.94` em logs de firewall

**Fluxo:**
1. Analista busca IP no Minerva (Elasticsearch)
2. Sistema automaticamente consulta `misp_iocs` table
3. Encontra match: "WannaCry C2 server"
4. Exibe badge vermelho: **"🔴 Known Malicious IP"**
5. Mostra contexto completo:
   - Malware Family: WannaCry
   - Threat Actor: Lazarus Group
   - First Seen: 2025-11-01
   - TLP: WHITE
   - Confidence: HIGH

**Valor**: Validação imediata de IOC com contexto da comunidade MISP

---

### Caso 2: Enriquecimento de Actor

**Cenário**: Analista acessando página do actor "Lazarus Group"

**Fluxo:**
1. Sistema carrega página do actor
2. Chama endpoint `/api/v1/cti/actors/Lazarus%20Group/misp-iocs`
3. Retorna 234 IOCs relacionados ao Lazarus Group
4. Exibe seção **"MISP Intelligence"**:
   ```
   📊 234 IOCs conhecidos no MISP

   Por tipo:
   - 🌐 IPs: 87
   - 🔗 Domains: 65
   - 📄 Hashes: 82

   Última atividade: 2025-11-15 (há 5 dias)
   ```

**Valor**: Contexto adicional sobre atividade do threat actor

---

### Caso 3: Sync Automático Diário

**Cenário**: Task Celery roda automaticamente às 3AM

**Fluxo:**
1. Task `sync_misp_feeds_daily` inicia
2. Busca todos feeds ativos (3 feeds públicos)
3. Para cada feed:
   - Baixa manifest/índice
   - Extrai IOCs novos (últimas 24h)
   - Salva no PostgreSQL (deduplica)
   - Indexa no Elasticsearch
4. Completa com 1,234 IOCs importados
5. Admin recebe notificação (log):
   ```
   ✅ MISP sync complete: 1,234 IOCs imported
   - CIRCL OSINT: 498 IOCs
   - Botvrij.eu: 215 IOCs
   - URLhaus: 521 IOCs
   ```

**Valor**: Inteligência atualizada automaticamente, sem intervenção manual

---

### Caso 4: Busca Standalone de IOC

**Cenário**: Analista quer verificar se hash é malicioso

**Fluxo:**
1. Analista acessa página "MISP IOC Search"
2. Cola hash MD5: `db349b97c37d22f5ea1d1841e3c89eb4`
3. Sistema busca em `misp_iocs`
4. Retorna resultado:
   ```
   ✅ IOC Encontrado!

   Tipo: MD5 Hash
   Contexto: WannaCry ransomware sample
   Malware Family: WannaCry
   Threat Actor: Lazarus Group
   First Seen: 2025-10-20
   Confidence: HIGH
   TLP: WHITE
   ```

**Valor**: Verificação rápida de IOCs sem precisar acessar MISP externo

---

## ⚠️ Considerações de Segurança

### TLP (Traffic Light Protocol)

Apenas importamos IOCs com TLP:WHITE ou TLP:GREEN:
- **TLP:WHITE** - Pode ser compartilhado publicamente
- **TLP:GREEN** - Pode ser compartilhado dentro da comunidade

**Não importamos:**
- ❌ TLP:AMBER (restrito)
- ❌ TLP:RED (extremamente restrito)

### Validação de IOCs

Antes de usar IOCs em produção:
1. Verificar confidence level (preferir HIGH/MEDIUM)
2. Verificar data (evitar IOCs muito antigos)
3. Verificar contexto (entender origem)
4. Implementar whitelist (IPs legítimos como Google, Cloudflare)

### Rate Limiting

Respeitar limites dos feeds públicos:
- Delay de 1-2s entre requests
- Não fazer scraping agressivo
- Cachear resultados localmente
- Usar manifest para evitar downloads desnecessários

### Deduplicação

Evitar duplicatas:
- Índice único em `(ioc_value, feed_id)`
- UPDATE em vez de INSERT quando IOC já existe
- Atualizar `last_seen` timestamp

---

## 📈 Métricas de Sucesso

### KPIs Phase 1 (Foundation)

- ✅ **Feeds**: 1+ feed público configurado
- ✅ **IOCs**: 100+ IOCs importados de teste
- ✅ **Search**: API de busca funcionando
- ✅ **ES Index**: Índice criado e populado

### KPIs Phase 2 (Enrichment)

- ✅ **UI**: Badges exibindo em resultados
- ✅ **Actors**: Seção MISP em 100% das páginas de actors
- ✅ **Correlation**: IOCs correlacionados com actors
- ✅ **Search**: Componente standalone funcionando

### KPIs Phase 3 (Automation)

- ✅ **Automation**: Sync diário rodando automaticamente
- ✅ **Feeds**: 3+ feeds públicos ativos
- ✅ **Growth**: +500 IOCs/dia importados
- ✅ **Uptime**: 95%+ de tasks Celery com sucesso
- ✅ **Dashboard**: UI mostrando status de feeds

### Métricas de Longo Prazo

- 📊 **Total IOCs**: 50,000+ IOCs após 3 meses
- 📊 **Queries/dia**: 100+ buscas de IOCs/dia
- 📊 **Hit Rate**: 10%+ de buscas encontram match MISP
- 📊 **Freshness**: 95%+ IOCs com <7 dias

---

## ⏱️ Timeline Completo

| Fase | Duração | Entregável Principal |
|------|---------|---------------------|
| **Phase 1** | 2-3 dias | Import de 1 feed funcionando + API busca |
| **Phase 2** | 2-3 dias | UI com badges + seção MISP em actors |
| **Phase 3** | 1-2 dias | Sync automático + dashboard feeds |
| **TOTAL** | **5-8 dias** | Sistema completo import-only |

---

## 🚀 Quick Start (Meio Dia)

Quer validar **rápido**? MVP mínimo:

### Step 1: Instalar PyMISP (5 min)

```bash
cd backend
pip install pymisp
echo "pymisp==2.4.180" >> requirements.txt
```

### Step 2: Criar Service Básico (30 min)

```python
# backend/app/cti/services/misp_feed_service.py
import requests
from typing import List, Dict
from datetime import datetime

class MISPFeedService:
    """Consumir feeds públicos do MISP"""

    CIRCL_FEED = "https://www.circl.lu/doc/misp/feed-osint/"

    def fetch_circl_feed(self) -> List[Dict]:
        """Importa IOCs do feed CIRCL OSINT (público, sem auth)"""
        try:
            # 1. Baixar manifest
            response = requests.get(f"{self.CIRCL_FEED}/manifest.json", timeout=30)
            manifest = response.json()

            iocs = []
            # 2. Processar primeiros 10 eventos (teste)
            for event_uuid in list(manifest.keys())[:10]:
                event_url = f"{self.CIRCL_FEED}/{event_uuid}.json"
                event_resp = requests.get(event_url, timeout=30)
                event_data = event_resp.json()

                event = event_data.get("Event", {})

                # 3. Extrair IOCs
                for attr in event.get("Attribute", []):
                    attr_type = attr.get("type")
                    if attr_type in ["ip-dst", "ip-src", "domain", "hostname",
                                     "md5", "sha1", "sha256", "url"]:
                        iocs.append({
                            "type": attr_type,
                            "value": attr.get("value"),
                            "context": event.get("info", ""),
                            "tags": [t.get("name") for t in event.get("Tag", [])],
                            "first_seen": event.get("date")
                        })

            return iocs
        except Exception as e:
            print(f"❌ Error fetching CIRCL feed: {e}")
            return []

    def import_iocs(self, iocs: List[Dict]):
        """Salvar IOCs no log (teste simples)"""
        print(f"📥 Would import {len(iocs)} IOCs:")
        for ioc in iocs[:5]:  # Mostrar primeiros 5
            print(f"  - {ioc['type']}: {ioc['value']}")
```

### Step 3: Criar Endpoint Teste (20 min)

```python
# backend/app/cti/api/misp_feeds.py
from fastapi import APIRouter
from app.cti.services.misp_feed_service import MISPFeedService

router = APIRouter(prefix="/misp", tags=["CTI - MISP"])

@router.post("/feeds/test")
def test_circl_feed():
    """Testar import do feed CIRCL (primeiros 10 eventos)"""
    service = MISPFeedService()
    iocs = service.fetch_circl_feed()
    service.import_iocs(iocs)

    return {
        "status": "success",
        "feed": "CIRCL OSINT",
        "iocs_found": len(iocs),
        "sample": iocs[:5]
    }
```

### Step 4: Registrar Router (5 min)

```python
# backend/app/main.py
from app.cti.api import misp_feeds

app.include_router(misp_feeds.router, prefix="/api/v1/cti")
```

### Step 5: Testar (10 min)

```bash
# Restart backend
docker-compose restart backend

# Testar endpoint
curl -X POST "http://localhost:8001/api/v1/cti/misp/feeds/test"

# Output esperado:
# {
#   "status": "success",
#   "feed": "CIRCL OSINT",
#   "iocs_found": 234,
#   "sample": [
#     {"type": "ip-dst", "value": "185.176.43.94", ...},
#     ...
#   ]
# }
```

**Total: ~1 hora para validar conceito!**

---

## ✅ Benefícios para Minerva

### 1. Enriquecimento Zero-Cost
- 3,700+ IOCs/dia de feeds públicos gratuitos
- Validação de IOCs em investigações
- Contexto adicional (malware family, threat actor)

### 2. Credibilidade
- Dados validados pela comunidade MISP global (10,000+ orgs)
- Threat intelligence de fontes confiáveis
- TLP:WHITE (sem restrições)

### 3. Sem Exposição
- Nada sai da plataforma
- Apenas consumimos inteligência pública
- Zero risco de vazar dados sensíveis

### 4. Correlação Automática
- IOCs automaticamente correlacionados com 864 actors
- Seção "MISP Intelligence" em todas páginas de actors
- Badges visuais em resultados de busca

### 5. Automação
- Sync automático diário via Celery
- Cleanup automático de IOCs antigos (>90 dias)
- Zero manutenção manual

---

## 📚 Referências

### Documentação Oficial

- **MISP Project**: https://www.misp-project.org/
- **MISP Feeds**: https://www.misp-project.org/feeds/
- **PyMISP**: https://github.com/MISP/PyMISP
- **CIRCL OSINT Feed**: https://www.circl.lu/doc/misp/feed-osint/

### Feeds Públicos

- **CIRCL**: https://www.circl.lu/doc/misp/feed-osint/
- **Botvrij.eu**: https://www.botvrij.eu/data/feed-osint/
- **URLhaus**: https://urlhaus.abuse.ch/
- **AlienVault OTX**: https://otx.alienvault.com/

### Community

- **MISP Gitter**: https://gitter.im/MISP/MISP
- **MISP GitHub**: https://github.com/MISP/MISP

---

## 🚦 Próximos Passos

### Agora (Hoje)

1. ✅ **Aprovar plano** import-only
2. ⏳ **Implementar Phase 1** (Foundation) - começar agora!
3. ⏳ **Testar CIRCL feed** - validar conceito

### Esta Semana

1. ⏳ **Completar Phase 1** (2-3 dias)
2. ⏳ **Implementar Phase 2** (Enrichment) - começar sexta
3. ⏳ **Testar busca de IOCs** - validar UI

### Próxima Semana

1. ⏳ **Completar Phase 2** (2-3 dias)
2. ⏳ **Implementar Phase 3** (Automation)
3. ⏳ **Deploy em produção** - sistema completo funcionando

---

**Documentado com ❤️ para Minerva Intelligence Platform**

**Autor**: Angello Cassio + Claude Code
**Data**: 2025-11-20
**Versão**: 2.0 (Import-Only)
