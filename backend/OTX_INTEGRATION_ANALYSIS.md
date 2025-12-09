# 🔍 OTX Integration - Análise e Melhorias

**Data**: 2025-01-22
**Status Atual**: Integração básica implementada
**Proposta**: Expandir para integração completa com Pulses, Subscriptions e sync automático

---

## 📊 Análise da Implementação Atual

### ✅ O que já temos (`app/cti/services/otx_service.py`)

```python
class OTXService:
    def search_indicator(self, indicator: str, indicator_type: str = "general") -> Dict
    def _detect_indicator_type(self, indicator: str) -> str
```

**Features Implementadas**:
- ✅ Busca básica de indicadores (`/api/v1/indicators/{type}/{value}/general`)
- ✅ Auto-detecção de tipo de IOC (IPv4, domain, URL, hash)
- ✅ Extração de pulse count, tags, malware families
- ✅ Tratamento de erros e timeouts
- ✅ Logging detalhado

**Limitações**:
- ❌ Usa apenas endpoint `/general` (dados limitados)
- ❌ Não busca pulses completas
- ❌ Não sincroniza subscribed pulses
- ❌ Não persiste dados no database
- ❌ Não usa SDK oficial (OTXv2)
- ❌ Busca apenas sob demanda (sem sync automático)
- ❌ Não explora endpoints avançados (reputation, malware, geo, etc.)

---

## 🌟 OTX API - Funcionalidades Completas

### 📡 Endpoints Principais

#### 1. **Indicators API** (`/api/v1/indicators`)

**Tipos de Indicadores Suportados**:
- IPv4, IPv6, domain, hostname, email
- URL, URI, file hashes (MD5, SHA1, SHA256, PEHASH, IMPHASH)
- CVE, YARA rules, CIDR, mutex, JA3, SSL certs, Bitcoin addresses

**Seções de Dados por Indicador**:
```
/api/v1/indicators/{type}/{value}/general       # Info básica + pulse count
/api/v1/indicators/{type}/{value}/reputation    # Reputation score
/api/v1/indicators/{type}/{value}/geo           # Geographic data
/api/v1/indicators/{type}/{value}/malware       # Malware analysis
/api/v1/indicators/{type}/{value}/url_list      # URLs associadas
/api/v1/indicators/{type}/{value}/passive_dns   # Passive DNS records
/api/v1/indicators/{type}/{value}/whois         # WHOIS data
/api/v1/indicators/{type}/{value}/http_scans    # HTTP scanning results
```

**Exemplos**:
```bash
# Buscar reputação de IP
GET /api/v1/indicators/IPv4/8.8.8.8/reputation

# Buscar malware associado a domínio
GET /api/v1/indicators/domain/evil.com/malware

# Buscar passive DNS de IP
GET /api/v1/indicators/IPv4/1.2.3.4/passive_dns
```

#### 2. **Pulses API** (`/api/v1/pulses`)

**CRUD de Pulses**:
```
GET  /api/v1/pulses/subscribed           # Pulses subscritas
GET  /api/v1/pulses/{pulse_id}           # Detalhes de pulse
GET  /api/v1/pulses/{pulse_id}/indicators # Indicadores de uma pulse
GET  /api/v1/pulses/{pulse_id}/related   # Pulses relacionadas
POST /api/v1/pulses/create               # Criar nova pulse
POST /api/v1/pulses/{pulse_id}/subscribe # Subscrever
POST /api/v1/pulses/{pulse_id}/unsubscribe # Dessubscrever
```

**Campos de uma Pulse**:
- `name`, `description`, `tags`
- `adversary` (threat actor)
- `malware_families` (nomes de malware)
- `attack_ids` (MITRE ATT&CK techniques)
- `industries` (alvos)
- `targeted_countries`
- `references` (URLs de contexto)
- `indicators` (lista de IOCs)
- `TLP` (white, green, amber, red)

**Exemplo de Pulse**:
```json
{
  "id": "5f2d...",
  "name": "APT28 Campaign October 2024",
  "description": "Fancy Bear targeting government entities",
  "adversary": "APT28",
  "malware_families": ["Sofacy", "X-Agent"],
  "attack_ids": ["T1071.001", "T1566.001"],
  "industries": ["government", "defense"],
  "targeted_countries": ["US", "UK", "FR"],
  "TLP": "amber",
  "indicators": [
    {"indicator": "evil.com", "type": "domain", "role": "C2"},
    {"indicator": "1.2.3.4", "type": "IPv4", "role": "scanning_host"}
  ]
}
```

#### 3. **Subscriptions & Activity**

```
GET /api/v1/pulses/activity              # Activity feed de subscriptions
GET /api/v1/pulses/subscribed?limit=50   # Pulses subscritas
GET /api/v1/users/{username}/pulses      # Pulses de um autor
POST /api/v1/users/{username}/subscribe  # Seguir autor
```

#### 4. **Search API**

```
GET /api/v1/search/pulses?q=apt28&sort=-modified
GET /api/v1/search/users?q=malwarelab
```

#### 5. **Bulk Operations**

```
POST /api/v1/pulses/{pulse_id}/indicators/edit  # Editar múltiplos indicators
```

---

## 🎯 Melhorias Propostas

### **Fase 1: Expandir Enriquecimento de IOCs** 🟢 Prioridade Alta

**Objetivo**: Usar todos os endpoints de indicators para enriquecimento completo

**Implementação**:
```python
class OTXService:
    async def enrich_indicator_full(self, indicator: str, ioc_type: str) -> Dict:
        """Enriquecimento completo com todos os endpoints OTX"""
        sections = ["general", "reputation", "geo", "malware", "url_list", "passive_dns"]

        results = {}
        for section in sections:
            url = f"{self.BASE_URL}/indicators/{ioc_type}/{indicator}/{section}"
            data = await self._fetch_with_retry(url)
            results[section] = data

        return self._consolidate_results(results)
```

**Dados Adicionais Obtidos**:
- **Reputation**: Reputation score, activity dates
- **Geo**: Country, city, ASN, organization
- **Malware**: Malware families, hashes, samples
- **Passive DNS**: Historical DNS records
- **WHOIS**: Domain registration info
- **HTTP Scans**: HTTP headers, server info

**Benefícios**:
- Enriquecimento muito mais completo de IOCs
- Dados para correlação (ex: IPs do mesmo ASN, domínios do mesmo registrar)
- Contexto geográfico para análise de campanhas

---

### **Fase 2: Implementar Pulses Sync** 🟡 Prioridade Média

**Objetivo**: Sincronizar pulses subscritas automaticamente (igual MISP feeds)

**Arquitetura**:
```
1. User subscreve pulses relevantes no OTX (via web ou API)
2. Celery task roda 2x/dia (08:00, 20:00)
3. Task busca /api/v1/pulses/subscribed?modified_since={last_sync}
4. Para cada pulse nova/modificada:
   - Salva pulse em tabela otx_pulses
   - Extrai indicators e salva em misp_iocs (com source="OTX: {pulse_name}")
5. Atualiza last_sync timestamp
```

**Modelo de Database**:
```python
# app/cti/models/otx_pulse.py
class OTXPulse(Base):
    __tablename__ = "otx_pulses"

    id = Column(UUID, primary_key=True)
    otx_pulse_id = Column(String, unique=True, nullable=False)  # ID no OTX
    name = Column(String, nullable=False)
    description = Column(Text)
    author_name = Column(String)
    adversary = Column(String, index=True)
    malware_families = Column(JSON)  # ["Emotet", "TrickBot"]
    attack_ids = Column(JSON)  # ["T1071.001", "T1566.001"]
    industries = Column(JSON)
    targeted_countries = Column(JSON)
    tags = Column(JSON)
    references = Column(JSON)
    tlp = Column(String)  # white, green, amber, red
    indicator_count = Column(Integer)
    created_at_otx = Column(DateTime)
    modified_at_otx = Column(DateTime, index=True)
    synced_at = Column(DateTime)
```

**Celery Task**:
```python
# app/tasks/otx_tasks.py
@shared_task(name="app.tasks.otx_tasks.sync_otx_pulses")
def sync_otx_pulses():
    """
    Sincroniza pulses subscritas do OTX
    Agenda: 2x por dia (08:00, 20:00)
    """
    logger.info("🚀 Starting OTX pulses synchronization...")

    # Get last sync timestamp
    last_sync = get_last_otx_sync()

    # Fetch subscribed pulses modified since last sync
    url = f"/api/v1/pulses/subscribed?modified_since={last_sync.isoformat()}&limit=100"
    pulses = otx_api_call(url)

    for pulse in pulses['results']:
        # Save pulse
        save_otx_pulse(pulse)

        # Extract and save indicators
        for indicator in pulse['indicators']:
            save_ioc_from_otx(indicator, pulse['id'], pulse['name'])

    update_last_sync_timestamp()
```

**Celery Beat Config**:
```python
# app/celery_app.py
beat_schedule = {
    "sync-otx-pulses": {
        "task": "app.tasks.otx_tasks.sync_otx_pulses",
        "schedule": crontab(minute=0, hour="8,20"),  # 2x por dia
    }
}
```

**Benefícios**:
- IOCs automaticamente atualizados de fontes confiáveis
- Contexto de threat actor, malware family, MITRE ATT&CK
- Complementa MISP feeds com inteligência curada

---

### **Fase 3: Usar OTXv2 SDK Oficial** 🟢 Prioridade Alta

**Objetivo**: Substituir requests manuais pelo SDK oficial

**Instalação**:
```bash
pip install OTXv2
```

**Refatoração**:
```python
# app/cti/services/otx_service_v2.py
from OTXv2 import OTXv2, IndicatorTypes

class OTXServiceV2:
    def __init__(self, api_key: str = None):
        self.otx = OTXv2(api_key or os.getenv("OTX_API_KEY"))

    def get_indicator_details(self, indicator_type: str, indicator: str):
        """
        Busca detalhes completos de um indicador
        Usa método do SDK que faz múltiplas chamadas automaticamente
        """
        return self.otx.get_indicator_details_full(
            indicator_type=IndicatorTypes.IPv4,  # ou Domain, URL, FileHash
            indicator=indicator
        )

    def get_subscribed_pulses(self, modified_since: str = None):
        """Busca pulses subscritas"""
        return self.otx.getall_iter(modified_since=modified_since)

    def get_pulse_indicators(self, pulse_id: str):
        """Busca indicators de uma pulse"""
        return self.otx.get_pulse_indicators(pulse_id)
```

**Benefícios**:
- Menos código para manter
- Tratamento de erros já implementado
- Rate limiting automático
- Paginação automática

---

### **Fase 4: OTX Pulse Browser (Frontend)** 🟡 Prioridade Média

**Objetivo**: Interface para visualizar e gerenciar pulses OTX

**Páginas**:

#### 4.1. **OTX Pulses Dashboard** (`/cti/otx/pulses`)
```
┌─────────────────────────────────────────────────┐
│  🔍 OTX Pulses                        [Sync Now] │
├─────────────────────────────────────────────────┤
│  📊 Stats                                         │
│  - 127 pulses synced                             │
│  - Last sync: 2 hours ago                        │
│  - 1,834 indicators imported                     │
├─────────────────────────────────────────────────┤
│  Filters: [All] [APT] [Malware] [Ransomware]    │
├─────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────┐  │
│  │ APT28 Campaign October 2024               │  │
│  │ Author: FireEye | Modified: 2h ago        │  │
│  │ Adversary: APT28 | TLP: Amber             │  │
│  │ Techniques: T1071.001, T1566.001          │  │
│  │ 47 indicators | 12 malware families       │  │
│  │ [View Details] [View Indicators]          │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Emotet Banking Trojan Wave 42             │  │
│  │ ...                                        │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

#### 4.2. **OTX Pulse Details** (`/cti/otx/pulses/{id}`)
```
┌─────────────────────────────────────────────────┐
│  ⬅ Back | APT28 Campaign October 2024          │
├─────────────────────────────────────────────────┤
│  📋 Description                                  │
│  Russian threat actor APT28 (Fancy Bear)...     │
│                                                   │
│  🎯 Attribution                                  │
│  - Adversary: APT28                              │
│  - Malware: Sofacy, X-Agent, Zebrocy            │
│  - Industries: Government, Defense, Think Tanks │
│  - Countries: US, UK, FR, DE                     │
│                                                   │
│  🔧 MITRE ATT&CK                                 │
│  - T1071.001: Web Protocols (C2)                │
│  - T1566.001: Spearphishing Attachment          │
│  - T1027: Obfuscated Files                      │
│                                                   │
│  📊 Indicators (47)                              │
│  ┌─────────────────────────────────────────┐   │
│  │ Type   | Value            | Role        │   │
│  │ Domain | sofacy-c2.com    | C2          │   │
│  │ IPv4   | 1.2.3.4          | C2          │   │
│  │ MD5    | abc123...        | Malware     │   │
│  └─────────────────────────────────────────┘   │
│                                                   │
│  🔗 References                                   │
│  - https://fireeye.com/apt28-oct2024             │
│  - https://us-cert.gov/apt28-advisory            │
└─────────────────────────────────────────────────┘
```

**API Endpoints**:
```python
# app/cti/api/otx.py
@router.get("/pulses")
async def list_otx_pulses(
    adversary: Optional[str] = None,
    malware_family: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 50
):
    """Lista pulses OTX com filtros"""

@router.get("/pulses/{pulse_id}")
async def get_otx_pulse(pulse_id: UUID):
    """Detalhes de uma pulse"""

@router.get("/pulses/{pulse_id}/indicators")
async def get_pulse_indicators(pulse_id: UUID):
    """Indicators de uma pulse"""

@router.post("/pulses/sync")
async def trigger_sync():
    """Trigger manual sync de pulses"""
```

---

### **Fase 5: Correlação OTX + MISP** 🔵 Prioridade Baixa

**Objetivo**: Correlacionar dados OTX com MISP feeds e Galaxy

**Features**:

1. **IOC Cross-reference**:
   - IOC encontrado em OTX pulse + MISP feed → maior confiança
   - Mostrar em qual pulse OTX e qual feed MISP aparece

2. **Threat Actor Correlation**:
   - OTX Pulse adversary="APT28" → MISP Galaxy cluster APT28
   - Unificar informações de diferentes fontes

3. **Malware Family Mapping**:
   - OTX malware_families → MISP Galaxy malware
   - Cross-reference de hashes

**Exemplo**:
```
IOC: 1.2.3.4

Fontes:
- MISP Feed: URLhaus (Confidence: 90%)
- MISP Feed: ThreatFox (Confidence: 95%)
- OTX Pulse: "APT28 Campaign Oct 2024" (FireEye)
- OTX Pulse: "Sofacy Infrastructure Q4 2024" (Unit42)

Threat Actor:
- MISP Galaxy: APT28 (Fancy Bear)
- OTX Attribution: APT28

Confiança Final: 98% (múltiplas fontes confirmam)
```

---

## 🏗️ Roadmap de Implementação

### **Sprint 1: Enriquecimento Avançado** (2-3 dias)
- [ ] Instalar OTXv2 SDK (`pip install OTXv2`)
- [ ] Criar `OTXServiceV2` usando SDK
- [ ] Implementar `enrich_indicator_full()` com todos os endpoints
- [ ] Testar com 10 IOCs (IPs, domains, hashes)
- [ ] Atualizar API endpoint `/api/v1/cti/iocs/{id}/enrich` para usar novo service
- [ ] Documentar novos campos retornados

### **Sprint 2: Database & Models** (2 dias)
- [ ] Criar modelo `OTXPulse` em `app/cti/models/otx_pulse.py`
- [ ] Criar migration Alembic
- [ ] Implementar service `OTXPulseService` com CRUD
- [ ] Testar inserção manual de 5 pulses

### **Sprint 3: Sync Automático** (3 dias)
- [ ] Implementar `sync_otx_pulses()` em `app/tasks/otx_tasks.py`
- [ ] Adicionar ao Celery Beat (2x/dia)
- [ ] Implementar lógica de upsert (evitar duplicados)
- [ ] Logging detalhado de sync
- [ ] Testar sync manual via API
- [ ] Documentar em `OTX_SYNC_SCHEDULE.md`

### **Sprint 4: Frontend OTX Pulses** (3-4 dias)
- [ ] Página `/cti/otx/pulses` (lista de pulses)
- [ ] Página `/cti/otx/pulses/{id}` (detalhes)
- [ ] Componentes: PulseCard, PulseFilters, PulseStats
- [ ] Integração com API
- [ ] Testar navegação e filtros

### **Sprint 5: Correlação** (2-3 dias)
- [ ] Implementar `correlate_ioc_sources()` em IOC enrichment
- [ ] Mostrar fontes múltiplas no IOC Browser
- [ ] Link entre OTX Pulse adversary e MISP Galaxy
- [ ] Dashboard de cobertura (quantos IOCs têm múltiplas fontes)

**Tempo Total Estimado**: 12-15 dias (~3 semanas)

---

## 📊 Comparação: Antes vs Depois

| Feature | Antes | Depois |
|---------|-------|--------|
| **Enriquecimento de IOC** | Básico (pulse count + tags) | Completo (reputation, geo, malware, passive DNS, WHOIS) |
| **Pulses** | ❌ Não implementado | ✅ Sync automático 2x/dia |
| **Database** | Nada persistido | Pulses + indicators com contexto completo |
| **SDK** | Requests manual | OTXv2 SDK oficial |
| **Frontend** | ❌ Não tem | ✅ OTX Pulses Browser |
| **Correlação** | ❌ Isolado | ✅ Cross-reference com MISP |
| **MITRE ATT&CK** | ❌ Não | ✅ Via pulses (attack_ids) |
| **Threat Actor** | ❌ Não | ✅ Via pulses (adversary field) |
| **Automation** | Manual | Sync automático via Celery |

---

## 🎯 Benefícios Esperados

1. **Mais Dados**: 10x mais informações por IOC (geo, malware, DNS, WHOIS, etc.)
2. **Automação**: Sync de pulses igual MISP feeds → sempre atualizado
3. **Contexto**: Threat actors, MITRE ATT&CK, malware families
4. **Confiabilidade**: Múltiplas fontes (OTX + MISP) → maior confiança
5. **Curadoria**: Pulses são curadas por analistas → qualidade alta
6. **Manutenção**: SDK oficial → menos bugs, mais features

---

## 📚 Referências

- **OTX API Docs**: https://otx.alienvault.com/assets/static/external_api.html
- **OTX Python SDK**: https://github.com/AlienVault-OTX/OTX-Python-SDK
- **OTX Web**: https://otx.alienvault.com
- **Exemplos de Integração**: MISP Importer, OpenCTI Connector, The Hive

---

## 📝 Próximos Passos Recomendados

1. **Discutir Roadmap**: Revisar sprints propostos e priorizar
2. **Obter OTX API Key**: Criar conta em otx.alienvault.com e gerar API key
3. **Testar SDK**: Rodar exemplos do OTXv2 SDK para familiarização
4. **Iniciar Sprint 1**: Implementar enriquecimento avançado com SDK

---

**Última atualização**: 2025-01-22
**Autor**: Intelligence Platform Team
