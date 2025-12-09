# 🔍 OTX Integration - Exemplos Práticos de Código

**Data**: 2025-01-22
**Baseado em**: OTX API Docs + OTXv2 SDK + MISP Importers

---

## 📚 Índice

1. [Setup & Autenticação](#setup--autenticação)
2. [Buscar Indicadores](#buscar-indicadores)
3. [Buscar Pulses Subscritas](#buscar-pulses-subscritas)
4. [Enriquecimento Completo](#enriquecimento-completo)
5. [Sync Incremental](#sync-incremental)
6. [Mapping OTX → Database](#mapping-otx--database)
7. [Exemplos de Integrações Existentes](#exemplos-de-integrações-existentes)

---

## 1. Setup & Autenticação

### Instalação

```bash
pip install OTXv2
```

### Configuração Básica

```python
from OTXv2 import OTXv2, IndicatorTypes
import os

# Inicializar cliente OTX
otx = OTXv2(os.getenv("OTX_API_KEY"))

# Validar autenticação
try:
    user_info = otx.get('/api/v1/users/me')
    print(f"✅ Autenticado como: {user_info['username']}")
except Exception as e:
    print(f"❌ Erro de autenticação: {e}")
```

### Verificar Rate Limits

```python
# OTX API tem rate limits
# Recomendação: adicionar delays entre chamadas
import time

def rate_limited_call(func, *args, **kwargs):
    """Wrapper com delay de 0.2s entre chamadas"""
    time.sleep(0.2)
    return func(*args, **kwargs)
```

---

## 2. Buscar Indicadores

### 2.1. Busca Simples (General)

```python
def search_indicator_basic(indicator_value: str, indicator_type: str):
    """
    Busca básica de indicador

    indicator_type: IPv4, IPv6, domain, hostname, url, file
    """
    from OTXv2 import OTXv2, IndicatorTypes

    otx = OTXv2(os.getenv("OTX_API_KEY"))

    # Map string to IndicatorTypes
    type_map = {
        "IPv4": IndicatorTypes.IPv4,
        "IPv6": IndicatorTypes.IPv6,
        "domain": IndicatorTypes.DOMAIN,
        "hostname": IndicatorTypes.HOSTNAME,
        "url": IndicatorTypes.URL,
        "file": IndicatorTypes.FILE_HASH_MD5,  # ou SHA1, SHA256
    }

    ioc_type = type_map.get(indicator_type, IndicatorTypes.IPv4)

    # Buscar
    result = otx.get_indicator_details_by_section(ioc_type, indicator_value, 'general')

    pulse_count = result.get('pulse_info', {}).get('count', 0)

    print(f"Indicator: {indicator_value}")
    print(f"Found in {pulse_count} pulses")

    return result

# Exemplo de uso
result = search_indicator_basic("8.8.8.8", "IPv4")
```

### 2.2. Enriquecimento Completo (Todas as Seções)

```python
def enrich_indicator_full(indicator_value: str, indicator_type: IndicatorTypes):
    """
    Busca TODAS as seções disponíveis para um indicador

    Seções disponíveis:
    - general: Info básica + pulse count
    - reputation: Reputation score
    - geo: Geographic data (país, cidade, ASN)
    - malware: Malware families associados
    - url_list: URLs relacionadas
    - passive_dns: Historical DNS records
    - whois: Domain registration (apenas domains)
    - http_scans: HTTP scanning results
    """
    otx = OTXv2(os.getenv("OTX_API_KEY"))

    sections = ['general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns']

    # Para domains/hostnames, adicionar whois
    if indicator_type in [IndicatorTypes.DOMAIN, IndicatorTypes.HOSTNAME]:
        sections.append('whois')

    # Para IPs, adicionar http_scans
    if indicator_type in [IndicatorTypes.IPv4, IndicatorTypes.IPv6]:
        sections.append('http_scans')

    enriched_data = {}

    for section in sections:
        try:
            data = otx.get_indicator_details_by_section(
                indicator_type,
                indicator_value,
                section
            )
            enriched_data[section] = data
            time.sleep(0.2)  # Rate limiting
        except Exception as e:
            print(f"⚠️ Error fetching {section}: {e}")
            enriched_data[section] = None

    return enriched_data

# Exemplo de uso
from OTXv2 import IndicatorTypes

enriched = enrich_indicator_full("malware.com", IndicatorTypes.DOMAIN)

# Acessar dados específicos
print(f"Reputation: {enriched['reputation']}")
print(f"Country: {enriched['geo'].get('country_name')}")
print(f"ASN: {enriched['geo'].get('asn')}")
print(f"Malware: {enriched['malware']}")
```

### 2.3. Busca com get_indicator_details_full

```python
def get_full_details(indicator_value: str, indicator_type: IndicatorTypes):
    """
    Usa método do SDK que já busca todas as seções automaticamente
    """
    otx = OTXv2(os.getenv("OTX_API_KEY"))

    # Este método faz múltiplas chamadas internamente
    details = otx.get_indicator_details_full(indicator_type, indicator_value)

    return details

# Exemplo
details = get_full_details("8.8.8.8", IndicatorTypes.IPv4)
```

---

## 3. Buscar Pulses Subscritas

### 3.1. Listar Todas as Pulses Subscritas

```python
def get_subscribed_pulses(limit: int = 50):
    """
    Busca pulses que o usuário subscreveu

    Retorna pulses com:
    - id, name, description
    - author_name
    - adversary, malware_families
    - attack_ids (MITRE ATT&CK)
    - industries, targeted_countries
    - tags, references
    - indicators
    """
    otx = OTXv2(os.getenv("OTX_API_KEY"))

    # getall() retorna iterator de todas as pulses
    pulses = otx.getall()

    pulse_list = []
    for pulse in pulses[:limit]:
        pulse_list.append({
            "id": pulse['id'],
            "name": pulse['name'],
            "description": pulse.get('description', ''),
            "author": pulse.get('author_name', ''),
            "adversary": pulse.get('adversary', ''),
            "malware_families": pulse.get('malware_families', []),
            "attack_ids": pulse.get('attack_ids', []),
            "tags": pulse.get('tags', []),
            "indicator_count": pulse.get('indicator_count', 0),
            "modified": pulse.get('modified', ''),
        })

    return pulse_list

# Exemplo
pulses = get_subscribed_pulses(limit=10)
for p in pulses:
    print(f"Pulse: {p['name']} ({p['indicator_count']} IOCs)")
```

### 3.2. Sync Incremental (Apenas Pulses Modificadas)

```python
from datetime import datetime, timedelta

def sync_pulses_since(last_sync_timestamp: str = None):
    """
    Busca apenas pulses criadas/modificadas desde timestamp

    Args:
        last_sync_timestamp: ISO format (ex: "2025-01-20T10:00:00")

    Returns:
        Lista de pulses novas/modificadas
    """
    otx = OTXv2(os.getenv("OTX_API_KEY"))

    # Se não passou timestamp, pegar últimos 7 dias
    if not last_sync_timestamp:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        last_sync_timestamp = seven_days_ago.isoformat()

    # getsince() retorna pulses modificadas desde timestamp
    pulses = otx.getsince(last_sync_timestamp)

    print(f"📥 Fetched {len(pulses)} pulses modified since {last_sync_timestamp}")

    return pulses

# Exemplo: buscar pulses das últimas 24h
from datetime import datetime, timedelta

yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
new_pulses = sync_pulses_since(yesterday)

for pulse in new_pulses:
    print(f"Pulse: {pulse['name']}")
    print(f"  Modified: {pulse['modified']}")
    print(f"  Indicators: {pulse['indicator_count']}")
```

### 3.3. Buscar Indicadores de uma Pulse

```python
def get_pulse_indicators(pulse_id: str):
    """
    Busca todos os indicadores de uma pulse específica

    Cada indicador tem:
    - indicator: valor (IP, domain, hash, etc)
    - type: tipo (IPv4, domain, FileHash-SHA256, etc)
    - created: timestamp
    - title: descrição
    - role: C2, malware_download, scanning_host, etc
    - is_active: bool
    """
    otx = OTXv2(os.getenv("OTX_API_KEY"))

    indicators = otx.get_pulse_indicators(pulse_id)

    ioc_list = []
    for ioc in indicators:
        ioc_list.append({
            "value": ioc['indicator'],
            "type": ioc['type'],
            "role": ioc.get('role', ''),
            "description": ioc.get('description', ioc.get('title', '')),
            "is_active": ioc.get('is_active', True),
            "created": ioc.get('created', ''),
        })

    return ioc_list

# Exemplo
indicators = get_pulse_indicators("5f2d1e8c3b5a4d001f3e2b1a")
for ioc in indicators:
    print(f"{ioc['type']}: {ioc['value']} (role: {ioc['role']})")
```

---

## 4. Enriquecimento Completo (Exemplo Real)

```python
import asyncio
from OTXv2 import OTXv2, IndicatorTypes
import os

class OTXEnricher:
    """Service completo de enriquecimento OTX"""

    def __init__(self, api_key: str = None):
        self.otx = OTXv2(api_key or os.getenv("OTX_API_KEY"))

    def detect_indicator_type(self, indicator: str) -> IndicatorTypes:
        """Auto-detect indicator type"""
        import re

        if indicator.startswith("http"):
            return IndicatorTypes.URL

        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
            return IndicatorTypes.IPv4

        # IPv6
        if ":" in indicator and len(indicator) > 15:
            return IndicatorTypes.IPv6

        # File hash
        if len(indicator) == 32:  # MD5
            return IndicatorTypes.FILE_HASH_MD5
        if len(indicator) == 40:  # SHA1
            return IndicatorTypes.FILE_HASH_SHA1
        if len(indicator) == 64:  # SHA256
            return IndicatorTypes.FILE_HASH_SHA256

        # Domain/Hostname
        if "." in indicator:
            return IndicatorTypes.DOMAIN

        return IndicatorTypes.HOSTNAME

    def enrich_ioc(self, indicator: str):
        """Enriquecimento completo de um IOC"""

        ioc_type = self.detect_indicator_type(indicator)

        print(f"🔍 Enriching {ioc_type}: {indicator}")

        # 1. General info
        general = self.otx.get_indicator_details_by_section(ioc_type, indicator, 'general')
        pulse_count = general.get('pulse_info', {}).get('count', 0)

        if pulse_count == 0:
            return {"found": False, "message": "Not found in OTX"}

        # 2. Reputation
        reputation = self.otx.get_indicator_details_by_section(ioc_type, indicator, 'reputation')

        # 3. Geographic data (IPs/domains)
        geo = None
        if ioc_type in [IndicatorTypes.IPv4, IndicatorTypes.IPv6, IndicatorTypes.DOMAIN]:
            geo = self.otx.get_indicator_details_by_section(ioc_type, indicator, 'geo')

        # 4. Malware
        malware = self.otx.get_indicator_details_by_section(ioc_type, indicator, 'malware')

        # 5. Passive DNS (IPs/domains)
        passive_dns = None
        if ioc_type in [IndicatorTypes.IPv4, IndicatorTypes.IPv6, IndicatorTypes.DOMAIN]:
            passive_dns = self.otx.get_indicator_details_by_section(ioc_type, indicator, 'passive_dns')

        # Extract useful info from pulses
        pulses = general.get('pulse_info', {}).get('pulses', [])

        tags = set()
        malware_families = set()
        adversaries = set()
        attack_ids = set()

        for pulse in pulses[:20]:  # First 20 pulses
            tags.update(pulse.get('tags', []))
            malware_families.update(pulse.get('malware_families', []))
            if pulse.get('adversary'):
                adversaries.add(pulse['adversary'])
            attack_ids.update(pulse.get('attack_ids', []))

        # Consolidate results
        enriched = {
            "found": True,
            "indicator": indicator,
            "type": str(ioc_type),
            "pulse_count": pulse_count,
            "reputation": {
                "threat_score": reputation.get('threat_score', 0),
                "reputation": reputation.get('reputation', 0),
            },
            "geo": {
                "country": geo.get('country_name') if geo else None,
                "city": geo.get('city') if geo else None,
                "asn": geo.get('asn') if geo else None,
                "org": geo.get('organization') if geo else None,
            } if geo else None,
            "malware": {
                "families": list(malware_families) if malware_families else [],
                "samples": malware.get('data', [])[:5] if malware else []
            },
            "threat_intel": {
                "tags": list(tags)[:30],
                "adversaries": list(adversaries),
                "attack_ids": list(attack_ids),
            },
            "passive_dns": {
                "count": len(passive_dns.get('passive_dns', [])) if passive_dns else 0,
                "records": passive_dns.get('passive_dns', [])[:10] if passive_dns else []
            } if passive_dns else None,
            "pulse_names": [p['name'] for p in pulses[:5]]
        }

        print(f"✅ Found in {pulse_count} pulses")
        print(f"   Reputation: {enriched['reputation']['threat_score']}")
        print(f"   Malware families: {len(malware_families)}")
        print(f"   Adversaries: {list(adversaries)}")

        return enriched

# Exemplo de uso
enricher = OTXEnricher()

# Enriquecer IP
result = enricher.enrich_ioc("8.8.8.8")

# Enriquecer domain
result = enricher.enrich_ioc("malware.com")

# Enriquecer hash
result = enricher.enrich_ioc("abc123def456...")
```

---

## 5. Sync Incremental (Pattern MISP)

```python
from datetime import datetime, timedelta
import json
import os

class OTXPulseSync:
    """
    Sync automático de pulses OTX
    Baseado no pattern usado por integrações MISP
    """

    TIMESTAMP_FILE = "/tmp/otx_last_sync.json"

    def __init__(self, api_key: str = None):
        self.otx = OTXv2(api_key or os.getenv("OTX_API_KEY"))

    def get_last_sync_timestamp(self) -> str:
        """Carrega último timestamp de sync do arquivo"""
        if os.path.exists(self.TIMESTAMP_FILE):
            with open(self.TIMESTAMP_FILE, 'r') as f:
                data = json.load(f)
                return data.get('last_sync')

        # Se nunca sincronizou, pegar últimos 7 dias
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        return seven_days_ago.isoformat()

    def save_sync_timestamp(self, timestamp: str):
        """Salva timestamp do sync"""
        with open(self.TIMESTAMP_FILE, 'w') as f:
            json.dump({
                'last_sync': timestamp,
                'updated_at': datetime.utcnow().isoformat()
            }, f)

    def sync_pulses(self):
        """
        Sincroniza pulses modificadas desde último sync
        """
        last_sync = self.get_last_sync_timestamp()

        print(f"🔄 Syncing pulses modified since {last_sync}")

        # Buscar pulses modificadas
        pulses = self.otx.getsince(last_sync)

        print(f"📥 Found {len(pulses)} new/modified pulses")

        imported_pulses = 0
        imported_iocs = 0

        for pulse in pulses:
            try:
                # Salvar pulse no database
                pulse_id = self.save_pulse_to_db(pulse)

                # Buscar e salvar indicadores
                indicators = self.otx.get_pulse_indicators(pulse['id'])

                for indicator in indicators:
                    self.save_indicator_to_db(indicator, pulse_id, pulse['name'])
                    imported_iocs += 1

                imported_pulses += 1

                # Rate limiting
                time.sleep(0.2)

            except Exception as e:
                print(f"❌ Error processing pulse {pulse['name']}: {e}")

        # Atualizar timestamp
        current_time = datetime.utcnow().isoformat()
        self.save_sync_timestamp(current_time)

        print(f"✅ Sync completed:")
        print(f"   - {imported_pulses} pulses imported")
        print(f"   - {imported_iocs} indicators imported")

        return {
            "pulses_imported": imported_pulses,
            "iocs_imported": imported_iocs,
            "sync_timestamp": current_time
        }

    def save_pulse_to_db(self, pulse: dict):
        """
        Salva pulse no database

        Modelo: OTXPulse
        """
        # TODO: Implementar com SQLAlchemy
        # Campos importantes:
        pulse_data = {
            "otx_pulse_id": pulse['id'],
            "name": pulse['name'],
            "description": pulse.get('description', ''),
            "author_name": pulse.get('author_name', ''),
            "adversary": pulse.get('adversary'),
            "malware_families": pulse.get('malware_families', []),
            "attack_ids": pulse.get('attack_ids', []),
            "industries": pulse.get('industries', []),
            "targeted_countries": pulse.get('targeted_countries', []),
            "tags": pulse.get('tags', []),
            "references": pulse.get('references', []),
            "tlp": pulse.get('TLP', 'white'),
            "indicator_count": pulse.get('indicator_count', 0),
            "created_at_otx": pulse.get('created'),
            "modified_at_otx": pulse.get('modified'),
        }

        print(f"💾 Saving pulse: {pulse_data['name']}")

        # return saved pulse ID
        return pulse['id']

    def save_indicator_to_db(self, indicator: dict, pulse_id: str, pulse_name: str):
        """
        Salva indicador no database (misp_iocs table)

        Modelo: MISPIoC
        """
        # Map OTX type to our type
        type_mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "URI": "url",
            "FileHash-MD5": "hash-md5",
            "FileHash-SHA1": "hash-sha1",
            "FileHash-SHA256": "hash-sha256",
            "email": "email",
            "Mutex": "mutex",
        }

        ioc_type = type_mapping.get(indicator['type'], "other")

        ioc_data = {
            "value": indicator['indicator'],
            "ioc_type": ioc_type,
            "source": f"OTX: {pulse_name}",
            "tags": [indicator.get('role', 'unknown'), "otx"],
            "confidence": 85,  # OTX pulses são curadas
            "description": indicator.get('description', indicator.get('title', '')),
            "feed_id": pulse_id,  # Link to OTX pulse
        }

        print(f"  💾 Saving IOC: {ioc_type}={indicator['indicator']}")

        # TODO: Upsert to database

# Exemplo de uso (Celery task)
def sync_otx_pulses_task():
    """Celery task para sync automático"""
    syncer = OTXPulseSync()
    result = syncer.sync_pulses()
    return result
```

---

## 6. Mapping OTX → Database

### 6.1. Modelo OTXPulse

```python
# app/cti/models/otx_pulse.py
from sqlalchemy import Column, String, Text, Integer, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.db.database import Base
import uuid

class OTXPulse(Base):
    __tablename__ = "otx_pulses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    otx_pulse_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(500), nullable=False)
    description = Column(Text)
    author_name = Column(String(200))

    # Threat attribution
    adversary = Column(String(200), index=True)
    malware_families = Column(JSON)  # ["Emotet", "TrickBot"]
    attack_ids = Column(JSON)  # ["T1071.001", "T1566.001"]

    # Targeting
    industries = Column(JSON)  # ["government", "finance"]
    targeted_countries = Column(JSON)  # ["US", "UK", "FR"]

    # Metadata
    tags = Column(JSON)
    references = Column(JSON)  # URLs
    tlp = Column(String(20))  # white, green, amber, red

    # Stats
    indicator_count = Column(Integer)

    # Timestamps
    created_at_otx = Column(DateTime)
    modified_at_otx = Column(DateTime, index=True)
    synced_at = Column(DateTime)
```

### 6.2. Salvar Pulse com Upsert

```python
from sqlalchemy.dialects.postgresql import insert as pg_insert
from datetime import datetime

async def save_otx_pulse(pulse: dict, session):
    """
    Salva ou atualiza pulse no database
    Usa upsert para evitar duplicados
    """
    stmt = pg_insert(OTXPulse).values(
        id=uuid.uuid4(),
        otx_pulse_id=pulse['id'],
        name=pulse['name'],
        description=pulse.get('description', ''),
        author_name=pulse.get('author_name', ''),
        adversary=pulse.get('adversary'),
        malware_families=pulse.get('malware_families', []),
        attack_ids=pulse.get('attack_ids', []),
        industries=pulse.get('industries', []),
        targeted_countries=pulse.get('targeted_countries', []),
        tags=pulse.get('tags', []),
        references=pulse.get('references', []),
        tlp=pulse.get('TLP', 'white'),
        indicator_count=pulse.get('indicator_count', 0),
        created_at_otx=pulse.get('created'),
        modified_at_otx=pulse.get('modified'),
        synced_at=datetime.utcnow(),
    )

    # Upsert: atualiza se já existe (por otx_pulse_id)
    stmt = stmt.on_conflict_do_update(
        index_elements=['otx_pulse_id'],
        set_={
            'name': pulse['name'],
            'description': pulse.get('description', ''),
            'modified_at_otx': pulse.get('modified'),
            'synced_at': datetime.utcnow(),
            'indicator_count': pulse.get('indicator_count', 0),
        }
    )

    await session.execute(stmt)
    await session.commit()
```

---

## 7. Exemplos de Integrações Existentes

### 7.1. Pattern do MISP Importer (gitunique/cti-scripts)

```python
# Padrão usado por integrações MISP → OTX
from OTXv2 import OTXv2

otx = OTXv2(otx_api_key)

# 1. Buscar pulses desde timestamp
mtime = load_last_sync_timestamp()
pulses = otx.getsince(mtime)

# 2. Para cada pulse
for pulse in pulses:
    # Criar evento MISP
    event = create_misp_event(
        title=f"{pulse['author_name']} - {pulse['name']}",
        date=pulse['modified'].split('T')[0]
    )

    # Adicionar indicadores
    for indicator in otx.get_pulse_indicators(pulse['id']):
        # Map OTX type → MISP attribute
        if indicator['type'] in ['FileHash-SHA256', 'FileHash-SHA1', 'FileHash-MD5']:
            add_hash_to_misp(event, indicator['indicator'])
        elif indicator['type'] in ['URI', 'URL']:
            add_url_to_misp(event, indicator['indicator'])
        elif indicator['type'] == 'domain':
            add_domain_to_misp(event, indicator['indicator'])
        # ... etc

        time.sleep(0.2)  # Rate limiting

# 3. Salvar timestamp
save_last_sync_timestamp(datetime.utcnow().isoformat())
```

### 7.2. Pattern do OpenCTI Connector

```python
# OpenCTI usa abordagem similar mas com mais metadados
for pulse in pulses:
    # Criar observable
    observable = create_opencti_observable(
        value=indicator['indicator'],
        type=map_otx_type_to_opencti(indicator['type'])
    )

    # Adicionar relacionamentos
    if pulse.get('adversary'):
        link_to_threat_actor(observable, pulse['adversary'])

    if pulse.get('malware_families'):
        for malware in pulse['malware_families']:
            link_to_malware(observable, malware)

    if pulse.get('attack_ids'):
        for attack_id in pulse['attack_ids']:
            link_to_technique(observable, attack_id)
```

### 7.3. Pattern do Splunk Importer

```python
# Splunk: exportar para CSV
import csv

pulses = otx.getsince(last_sync)

with open('otx_indicators.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=['indicator', 'type', 'pulse_name', 'tags'])
    writer.writeheader()

    for pulse in pulses:
        indicators = otx.get_pulse_indicators(pulse['id'])

        for ioc in indicators:
            writer.writerow({
                'indicator': ioc['indicator'],
                'type': ioc['type'],
                'pulse_name': pulse['name'],
                'tags': ','.join(pulse.get('tags', []))
            })
```

---

## 🎯 Resumo: Melhores Práticas

1. **Use o SDK oficial** (`OTXv2`) ao invés de requests manuais
2. **Rate limiting**: Adicione `time.sleep(0.2)` entre chamadas
3. **Sync incremental**: Use `getsince()` com timestamp persistido
4. **Upsert**: Use `ON CONFLICT DO UPDATE` para evitar duplicados
5. **Enriquecimento completo**: Busque múltiplas seções (general, reputation, geo, malware)
6. **Mapping de tipos**: Crie dicionário OTX type → seu type interno
7. **Contexto**: Salve adversary, malware_families, attack_ids das pulses
8. **TLP**: Respeite Traffic Light Protocol das pulses
9. **Logging**: Log detalhado de sync (quantas pulses, quantos IOCs)
10. **Error handling**: Try/catch por pulse (não falhar todo sync por 1 erro)

---

**Próximo passo**: Implementar Sprint 1 do OTX_INTEGRATION_ANALYSIS.md
