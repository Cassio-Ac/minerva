# MISP Feeds - Fontes Adicionais Descobertas

Data: 2025-11-21

## Fonte 1: Cosive MISP Feeds Catalog

URL: https://www.cosive.com/misp-feeds

### Feeds Públicos de Alta Qualidade

#### 1. **Command & Control Servers**

##### DiamondFox C2 Panels (Unit42/Palo Alto Networks)
- **URL**: `https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt`
- **Tipo**: TXT (lista de URLs)
- **Foco**: Painéis C2 de malware DiamondFox
- **Provider**: Palo Alto Networks Unit42
- **Auth**: Não requerida
- **TLP**: Provavelmente White
- **Priority**: ⭐⭐⭐ (C2 intel é crítico)

#### 2. **SSL Certificates Maliciosos**

##### abuse.ch SSL IP Blacklist
- **URL**: `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`
- **Tipo**: CSV
- **Formato**: SHA1 fingerprints + datas + razões
- **Foco**: Certificados SSL associados a malware/C2
- **Provider**: abuse.ch (mesmo do URLhaus/ThreatFox)
- **Auth**: Não requerida
- **TLP**: White
- **Priority**: ⭐⭐⭐⭐ (SSL intel para detecção de C2)

#### 3. **Malicious IPs**

##### AlienVault Reputation Generic
- **URL**: `https://reputation.alienvault.com/reputation.generic`
- **Tipo**: Texto formatado
- **Foco**: IPs linkados a malware, phishing, C2 servers
- **Provider**: LevelBlue/AT&T Cybersecurity (antigo AlienVault)
- **Auth**: Não requerida
- **TLP**: White
- **Priority**: ⭐⭐⭐⭐⭐ (reputação de IPs critical)
- **Taxa estimada**: Milhares de IPs/dia

##### CyberCure IP Feed
- **URL**: `https://api.cybercure.ai/feed/get_ips?type=csv`
- **Tipo**: CSV (via API)
- **Provider**: cybercure.ai
- **Auth**: Provavelmente requerida (API)
- **TLP**: Unknown
- **Priority**: ⭐⭐⭐

##### CINS Score Bad Guys List
- **URL**: `https://cinsscore.com/list/ci-badguys.txt`
- **Tipo**: TXT
- **Provider**: The CINS Score
- **Auth**: Não requerida
- **Priority**: ⭐⭐⭐

#### 4. **Malicious Domains**

##### Bambenek DGA Feed (High Confidence)
- **URL**: `https://osint.bambenekconsulting.com/feeds/dga-feed-high.csv`
- **Tipo**: CSV
- **Foco**: Domains gerados por algoritmo (DGA) para C2 evasion
- **Provider**: Bambenek Consulting
- **Auth**: Não requerida
- **TLP**: White
- **Priority**: ⭐⭐⭐⭐⭐ (DGA detection é essencial)
- **Diferencial**: Alta confiança, foco em C2 evasion

##### blocklist.de All Lists
- **URL**: `https://lists.blocklist.de/lists/all.txt`
- **Tipo**: TXT
- **Provider**: blocklist.de (projeto alemão)
- **Auth**: Não requerida
- **Priority**: ⭐⭐⭐⭐

##### GreenSnow Blocklist
- **URL**: `https://blocklist.greensnow.co/greensnow.txt`
- **Tipo**: TXT
- **Provider**: greensnow.co
- **Auth**: Não requerida
- **Priority**: ⭐⭐⭐

#### 5. **Malicious URLs**

##### CyberCure Blocked URL Feed
- **URL**: `https://api.cybercure.ai/feed/get_url?type=csv`
- **Tipo**: CSV (via API)
- **Provider**: cybercure.ai
- **Auth**: Provavelmente requerida
- **Priority**: ⭐⭐⭐

#### 6. **Comprehensive OSINT Feeds**

##### DigitalSide Threat-Intel
- **URL**: `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/`
- **Tipo**: MISP JSON format
- **Provider**: DigitalSide
- **Auth**: Não requerida
- **Priority**: ⭐⭐⭐⭐
- **Diferencial**: Feed MISP nativo (fácil integração)

##### Cybercrime Tracker
- **URL**: `https://cybercrime-tracker.net/all.php`
- **Tipo**: HTML/Mixed
- **Provider**: cybercrime-tracker.net
- **Auth**: Não requerida
- **Priority**: ⭐⭐⭐

#### 7. **IDS Rules & Network Intel**

##### ProofPoint Emerging Threats Compromised IPs
- **URL**: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`
- **Tipo**: TXT
- **Provider**: ProofPoint (Emerging Threats)
- **Auth**: Não requerida
- **TLP**: White
- **Priority**: ⭐⭐⭐⭐⭐
- **Diferencial**: IPs comprometidos (bots, proxies, etc.)

#### 8. **File Hashes**

##### CyberCure Hash Feed
- **URL**: `https://api.cybercure.ai/feed/get_hash?type=csv`
- **Tipo**: CSV (via API)
- **Formatos**: MD5, SHA1, SHA256
- **Provider**: cybercure.ai
- **Auth**: Provavelmente requerida
- **Priority**: ⭐⭐⭐

---

## Fonte 2: Labs HowTo Scripts (GitHub)

URL: https://github.com/howtoonline/labs_howto

### Análise dos Scripts Python

#### Script 1: `alien_to_misp_lab.py` (AlienVault OTX → MISP)

**Funcionalidade**:
- Importa pulses do AlienVault OTX para MISP como eventos
- Processa até 50 páginas de pulses subscritos
- Cria eventos MISP completos com metadados ricos

**Arquitetura**:
```python
# Loop paginado
for page in range(1, 50):
    # Busca pulses via API OTX
    GET https://otx.alienvault.com/api/v1/pulses/subscribed?page={page}
    Headers: {'X-OTX-API-KEY': api_key}

    # Para cada pulse
    for pulse in pulses['results']:
        # Cria MISPEvent
        event = MISPEvent()
        event.info = pulse['name']
        event.distribution = 4  # Sharing group
        event.sharing_group_id = 1
        event.threat_level_id = 1  # HIGH
        event.add_tag('tlp:clear')

        # Adiciona adversary tag
        if pulse['adversary']:
            event.add_tag(f"Adversary:{adversary}")

        # Type mapping (muito útil!)
        type_mapping = {
            'FileHash-MD5': 'md5',
            'FileHash-SHA1': 'sha1',
            'FileHash-SHA256': 'sha256',
            'FileHash-SHA512': 'sha512',
            'BitcoinAddress': 'btc',
            'URL': 'url',
            'CVE': 'vulnerability',
            'IPv4': 'ip-src',
            'YARA': 'comment',
            'SSLCertFingerprint': 'comment'
        }

        # Enriquecimento automático
        - Tags de malware families
        - Tags de targeted countries
        - Tags de industries
        - ATT&CK IDs
        - References

        # Filtro especial: Brazil
        if 'Brazil' in targeted_countries:
            event.add_tag('Targeted_country:BRAZIL')
```

**Insights importantes**:
1. **Paginação**: OTX API retorna resultados paginados (precisa loop)
2. **Type normalization**: Mapping OTX types → MISP types
3. **Auto-tagging**: Extrai automaticamente tags de malware, indústrias, países
4. **ATT&CK integration**: Mapeia `attack_ids` para tags
5. **Filtros geográficos**: Lógica especial para país específico (Brasil)

**O que podemos melhorar na nossa implementação**:
- ✅ Já temos type normalization
- ❌ Não estamos extraindo `adversary`
- ❌ Não estamos processando `malware_families`
- ❌ Não estamos processando `industries`
- ❌ Não estamos processando `attack_ids` (ATT&CK!)
- ❌ Não estamos processando `references`
- ❌ Não temos paginação (limitamos a 5-50 pulses)

---

#### Script 2: `openphish_to_misp.py` (OpenPhish → MISP)

**Funcionalidade**:
- Importa URLs de phishing do OpenPhish feed
- Cria um único evento MISP com todas as URLs

**Arquitetura**:
```python
# Feed público do OpenPhish
url = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'

# Busca feed
r = requests.get(url)

# Cria evento único
event = MISPEvent()
event.info = "Openphish daily report"
event.threat_level_id = 1  # HIGH
event.distribution = 4

# Adiciona cada URL como atributo
for url in r.text.splitlines():
    event.add_attribute('url', url,
                       comment="Phishing URL",
                       to_ids=True)

# Tags
event.add_tag('tlp:amber+strict')
event.add_tag('openphish')
event.add_tag('enisa:nefarious-activity-abuse="phishing-attacks"')

misp.add_event(event)
```

**Insights importantes**:
1. **OpenPhish Feed**: Feed público gratuito de URLs de phishing
   - URL: `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`
   - Formato: TXT (uma URL por linha)
   - Update: Daily
   - TLP: Amber+strict

2. **Single Event Pattern**: Agrupa múltiplos IOCs em um evento (daily report)

3. **ENISA Taxonomy**: Usa tag `enisa:nefarious-activity-abuse="phishing-attacks"`

**Novo feed descoberto**: ⭐⭐⭐⭐⭐ OpenPhish (crítico para phishing detection!)

---

#### Script 3: `serpro_feed_to_misp.py` (SERPRO Blocklist → MISP)

**Funcionalidade**:
- Importa IPs maliciosos do feed governamental brasileiro (SERPRO)
- Cria evento de reputação de IPs

**Arquitetura**:
```python
# Feed público do SERPRO (Governo BR)
url = 'https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt'

# Busca feed
r = requests.get(url)

# Cria evento único
event = MISPEvent()
event.info = "Serpro Feed - IP Reputation"
event.threat_level_id = 1

# Adiciona cada IP como atributo
for ip in r.text.splitlines():
    event.add_attribute('ip-dst', ip,
                       comment="Malicious IP",
                       to_ids=True)

# Tags
event.add_tag('tlp:amber+strict')
event.add_tag('malicious_ip')

misp.add_event(event)
```

**Insights importantes**:
1. **SERPRO Feed**: Feed governamental brasileiro de IPs maliciosos
   - URL: `https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt`
   - Formato: TXT (um IP por linha)
   - Provider: SERPRO (Serviço Federal de Processamento de Dados - Governo BR)
   - Update: Regular
   - TLP: Amber+strict
   - **PRIORIDADE MÁXIMA PARA BRASIL** ⭐⭐⭐⭐⭐

2. **IP Reputation**: Foco em reputação de IPs

**Novo feed descoberto**: ⭐⭐⭐⭐⭐ SERPRO (crítico para contexto brasileiro!)

---

## Feeds Priorizados para Implementação

### Tier 1: CRÍTICOS (implementar AGORA)

1. **OpenPhish** ⭐⭐⭐⭐⭐
   - URL: `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`
   - Razão: Phishing detection crítico, feed gratuito e atualizado diariamente
   - Formato: TXT (simples de parsear)
   - Implementação: 15 minutos

2. **SERPRO Blocklist (Brasil)** ⭐⭐⭐⭐⭐
   - URL: `https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt`
   - Razão: Feed governamental BR, altamente relevante para contexto brasileiro
   - Formato: TXT (simples de parsear)
   - Implementação: 15 minutos

3. **Bambenek DGA Feed** ⭐⭐⭐⭐⭐
   - URL: `https://osint.bambenekconsulting.com/feeds/dga-feed-high.csv`
   - Razão: DGA detection essencial para C2 evasion
   - Formato: CSV
   - Implementação: 20 minutos

4. **ProofPoint Emerging Threats IPs** ⭐⭐⭐⭐⭐
   - URL: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`
   - Razão: IPs comprometidos (critical)
   - Formato: TXT
   - Implementação: 15 minutos

5. **AlienVault IP Reputation** ⭐⭐⭐⭐⭐
   - URL: `https://reputation.alienvault.com/reputation.generic`
   - Razão: Reputação de IPs de alta qualidade
   - Formato: Texto estruturado
   - Implementação: 30 minutos (parsing customizado)

### Tier 2: ALTA PRIORIDADE

6. **abuse.ch SSL Blacklist** ⭐⭐⭐⭐
   - URL: `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`
   - Razão: SSL cert intel para C2 detection
   - Formato: CSV

7. **DigitalSide Threat-Intel** ⭐⭐⭐⭐
   - URL: `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/`
   - Razão: MISP native format (easy integration)
   - Formato: MISP JSON

8. **blocklist.de** ⭐⭐⭐⭐
   - URL: `https://lists.blocklist.de/lists/all.txt`
   - Razão: Agregador de múltiplas fontes
   - Formato: TXT

9. **DiamondFox C2 Panels** ⭐⭐⭐
   - URL: `https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt`
   - Razão: C2 intel específico
   - Formato: TXT

### Tier 3: MÉDIA PRIORIDADE

10. **GreenSnow** ⭐⭐⭐
11. **CINS Score** ⭐⭐⭐
12. **CyberCure feeds** (requer API key)

---

## Melhorias para Nossa Implementação OTX

Com base no script `alien_to_misp_lab.py`, precisamos melhorar nosso `fetch_otx_feed()`:

### Features a adicionar:

```python
def fetch_otx_feed_enhanced(self, api_key: str, limit: int = 50) -> List[Dict]:
    """Versão melhorada baseada em alien_to_misp_lab.py"""

    iocs = []

    # ADICIONAR: Paginação (em vez de limit fixo)
    for page in range(1, limit // 10 + 1):
        pulses = otx.getall(page=page)

        for pulse in pulses:
            # ADICIONAR: Extrair adversary
            adversary = pulse.get("adversary", "")

            # ADICIONAR: Extrair malware families
            malware_families = pulse.get("malware_families", [])

            # ADICIONAR: Extrair industries
            industries = pulse.get("industries", [])

            # ADICIONAR: Extrair ATT&CK IDs
            attack_ids = pulse.get("attack_ids", [])

            # ADICIONAR: Extrair references
            references = pulse.get("references", [])

            # ADICIONAR: Extrair targeted countries
            targeted_countries = pulse.get("targeted_countries", [])

            # Para cada indicator
            for indicator in pulse.get("indicators", []):
                ioc = {
                    "type": self._normalize_otx_type(indicator["type"]),
                    "value": indicator["indicator"],
                    "context": f"OTX Pulse: {pulse['name']}",
                    "tags": pulse.get("tags", []),

                    # NOVOS CAMPOS:
                    "threat_actor": adversary if adversary else None,
                    "malware_families": malware_families,
                    "industries": industries,
                    "attack_ids": attack_ids,  # ATT&CK!
                    "references": references,
                    "targeted_countries": targeted_countries,

                    "tlp": pulse.get("TLP", "white").lower(),
                    "to_ids": True,
                }

                iocs.append(ioc)

    return iocs
```

---

## Plano de Ação

### Phase 2A: Implementar Feeds Tier 1 (4-6 horas)

1. **OpenPhish** (15min)
   - Método: `fetch_openphish_feed()`
   - Parser: TXT simples

2. **SERPRO** (15min)
   - Método: `fetch_serpro_feed()`
   - Parser: TXT simples

3. **Bambenek DGA** (20min)
   - Método: `fetch_bambenek_dga_feed()`
   - Parser: CSV

4. **ProofPoint ET** (15min)
   - Método: `fetch_emerging_threats_feed()`
   - Parser: TXT simples

5. **AlienVault IP Reputation** (30min)
   - Método: `fetch_alienvault_reputation_feed()`
   - Parser: Custom (formato estruturado)

6. **Melhorar OTX** (2h)
   - Adicionar paginação
   - Adicionar campos: adversary, malware_families, industries, attack_ids
   - Adicionar ATT&CK mapping

### Phase 2B: Implementar Feeds Tier 2 (3-4 horas)

7-9. Implementar feeds Tier 2

### Phase 2C: Testing & Documentation (2 horas)

10. Testar todos os novos feeds
11. Atualizar documentação
12. Criar dashboard de feeds

---

## Taxonomias & Tags Descobertas

### ENISA Taxonomy
- `enisa:nefarious-activity-abuse="phishing-attacks"`

### Custom Tags Pattern
- `Adversary:{threat_actor_name}`
- `industry:{industry_name}`
- `malware_family:{family_name}`
- `Targeted_country:{COUNTRY}`

### TLP Levels nos Scripts
- `tlp:clear` (público)
- `tlp:amber+strict` (restrito)

---

## Conclusão

**Descobertos**: 12+ novos feeds públicos de alta qualidade
**Tier 1 (críticos)**: 5 feeds (OpenPhish, SERPRO, Bambenek, ET, AlienVault)
**Scripts analisados**: 3 scripts Python do labs_howto

**Próximo passo**: Implementar feeds Tier 1 (estimativa: 4-6 horas)
