# 📋 OTX Integration - Resumo Executivo

**Data**: 2025-01-22
**Análise Completa**: 3 documentos criados

---

## 🎯 TL;DR

**Problema**: Nossa integração OTX atual usa apenas 1 de 8+ endpoints disponíveis. Estamos deixando 87% dos dados OTX na mesa.

**Solução**: Expandir para integração completa com:
- ✅ SDK oficial (OTXv2)
- ✅ Enriquecimento 8x mais detalhado
- ✅ Sync automático de pulses (igual MISP feeds)
- ✅ Contexto de threat actor, malware, MITRE ATT&CK

**ROI**: Economia de 61 min/IOC (~97% do tempo de investigação)

**Esforço**: 12-15 dias (~3 semanas)

**Payback**: < 1 mês

---

## 📚 Documentos Criados

### 1. **OTX_INTEGRATION_ANALYSIS.md** (Análise Técnica Completa)

**Conteúdo**:
- ✅ Análise da implementação atual (165 linhas)
- ✅ OTX API completa (todos os endpoints)
- ✅ 5 fases de melhorias propostas
- ✅ Roadmap de implementação (5 sprints)
- ✅ Comparação Before vs After
- ✅ Benefícios esperados

**Principais Seções**:
- Fase 1: Enriquecimento Avançado (prioridade alta)
- Fase 2: Implementar Pulses Sync (prioridade média)
- Fase 3: Usar OTXv2 SDK (prioridade alta)
- Fase 4: Frontend OTX Pulses (prioridade média)
- Fase 5: Correlação OTX + MISP (prioridade baixa)

---

### 2. **OTX_INTEGRATION_EXAMPLES.md** (Código Prático)

**Conteúdo**:
- ✅ Setup & autenticação com OTXv2
- ✅ Buscar indicadores (basic + full enrichment)
- ✅ Buscar pulses subscritas
- ✅ Sync incremental (pattern MISP)
- ✅ Mapping OTX → Database
- ✅ Exemplos de integrações existentes (MISP, OpenCTI, Splunk)

**Exemplos Práticos**:
```python
# Enriquecimento completo
enricher = OTXEnricher()
result = enricher.enrich_ioc("malware.com")

# Sync incremental
syncer = OTXPulseSync()
result = syncer.sync_pulses()

# Modelo de database
class OTXPulse(Base):
    adversary = Column(String)
    malware_families = Column(JSON)
    attack_ids = Column(JSON)
```

---

### 3. **OTX_INTEGRATION_COMPARISON.md** (Comparação Detalhada)

**Conteúdo**:
- ✅ Tabela comparativa lado a lado (12 aspectos)
- ✅ Exemplo real: enriquecimento de IOC malicioso
- ✅ Comparação de sync de pulses
- ✅ Correlação multi-source
- ✅ Frontend comparison
- ✅ **Estimativa de valor** (economia de tempo)
- ✅ **ROI estimado**

**Principais Insights**:
- Enriquecimento atual: 5 campos
- Enriquecimento proposto: 40+ campos
- Economia: 61 min/IOC (97% do tempo)
- 10 IOCs/dia = 223 horas economizadas/mês

---

## 🚀 Roadmap de Implementação

### **Sprint 1: Enriquecimento Avançado** (2-3 dias) 🟢 COMEÇAR AQUI

**Objetivos**:
- [x] Instalar `OTXv2` SDK
- [ ] Criar `OTXServiceV2` usando SDK
- [ ] Implementar `enrich_indicator_full()` (8 endpoints)
- [ ] Testar com 10 IOCs
- [ ] Atualizar API endpoint `/api/v1/cti/iocs/{id}/enrich`

**Deliverables**:
- Service completo com SDK
- Enriquecimento retornando reputation, geo, malware, passive DNS, WHOIS
- Testes com IPs, domains, hashes

---

### **Sprint 2: Database & Models** (2 dias)

**Objetivos**:
- [ ] Criar modelo `OTXPulse`
- [ ] Criar migration Alembic
- [ ] Implementar service `OTXPulseService`
- [ ] Testar CRUD

**Deliverables**:
- Tabela `otx_pulses` criada
- Service com métodos save, get, list

---

### **Sprint 3: Sync Automático** (3 dias)

**Objetivos**:
- [ ] Implementar `sync_otx_pulses()` task
- [ ] Adicionar ao Celery Beat (2x/dia)
- [ ] Logging detalhado
- [ ] Documentar em `OTX_SYNC_SCHEDULE.md`

**Deliverables**:
- Task rodando 2x/dia
- Pulses sendo sincronizadas
- IOCs sendo importados com source="OTX"

---

### **Sprint 4: Frontend OTX Pulses** (3-4 dias)

**Objetivos**:
- [ ] Página `/cti/otx/pulses`
- [ ] Página `/cti/otx/pulses/{id}`
- [ ] Componentes: PulseCard, PulseFilters, PulseStats
- [ ] Integração com API

**Deliverables**:
- Interface completa para navegar pulses
- Filtros por adversary, malware, técnica
- Link para IOC Browser

---

### **Sprint 5: Correlação** (2-3 dias)

**Objetivos**:
- [ ] Implementar `correlate_ioc_sources()`
- [ ] Mostrar múltiplas fontes no IOC Browser
- [ ] Link OTX Pulse ↔ MISP Galaxy
- [ ] Dashboard de cobertura

**Deliverables**:
- IOC Browser mostrando fontes múltiplas
- Maior confiança quando múltiplas fontes confirmam
- Visualização de cross-reference

---

## 📊 Dados: Atual vs Proposta

### Enriquecimento de IOC

| Dados | ❌ Atual | ✅ Proposta |
|-------|---------|------------|
| Pulse count | ✅ | ✅ |
| Tags | ✅ | ✅ |
| Pulse names | ✅ | ✅ |
| **Reputation score** | ❌ | ✅ |
| **Geographic data** | ❌ | ✅ (país, cidade, ASN, org) |
| **Malware families** | ❌ | ✅ |
| **Malware samples** | ❌ | ✅ (hashes + dates) |
| **Passive DNS** | ❌ | ✅ (IPs relacionados) |
| **WHOIS** | ❌ | ✅ (domains) |
| **HTTP scans** | ❌ | ✅ (IPs) |
| **Threat actor** | ❌ | ✅ (via pulses) |
| **MITRE ATT&CK** | ❌ | ✅ (via pulses) |

**Total**: 5 campos → 40+ campos (**8x mais dados**)

---

### Pulses

| Feature | ❌ Atual | ✅ Proposta |
|---------|---------|------------|
| Database | ❌ | ✅ `otx_pulses` table |
| Sync | ❌ | ✅ Automático 2x/dia |
| Adversary | ❌ | ✅ APT28, Wizard Spider, etc |
| Malware families | ❌ | ✅ Emotet, TrickBot, etc |
| MITRE ATT&CK | ❌ | ✅ T1071.001, T1566.001, etc |
| Industries | ❌ | ✅ government, finance, etc |
| Countries | ❌ | ✅ US, UK, FR, etc |
| TLP | ❌ | ✅ white, green, amber, red |
| Frontend | ❌ | ✅ OTX Pulses Browser |

---

## 💡 Principais Integrações como Referência

**Projetos que já integram OTX**:

1. **MISP Importer** (`gcrahay/otx_misp`)
   - Sync de pulses → MISP events
   - Mapping de indicators → MISP attributes
   - 53 stars, usado em produção

2. **OpenCTI Connector**
   - Sync de pulses → OpenCTI observables
   - Link com threat actors, malware, techniques
   - Oficial do OpenCTI

3. **Splunk Importer**
   - Export de IOCs para CSV
   - Importação no Splunk para SIEM
   - Tutorial oficial

4. **The Hive**
   - Incident Response Platform
   - Usa OTX para enriquecimento

**Pattern Comum** (todos usam):
- ✅ OTXv2 SDK
- ✅ `getsince()` para sync incremental
- ✅ `get_pulse_indicators()` para IOCs
- ✅ Rate limiting (0.2s entre chamadas)
- ✅ Upsert para evitar duplicados
- ✅ Timestamp persistido

---

## 🎯 Recomendações

### Prioridade 1 (Fazer AGORA): 🔴

**Sprint 1: Enriquecimento Avançado**
- Motivo: ROI imediato (61 min economizados/IOC)
- Esforço: 2-3 dias
- Benefício: 8x mais dados de IOCs

**Ação**:
```bash
# Instalar SDK
pip install OTXv2

# Adicionar ao requirements.txt
echo "OTXv2==1.5.12" >> backend/requirements.txt

# Criar OTXServiceV2
# Seguir exemplos de OTX_INTEGRATION_EXAMPLES.md
```

---

### Prioridade 2 (Próximas 2 semanas): 🟡

**Sprints 2-3: Database + Sync Automático**
- Motivo: Automação completa, igual MISP feeds
- Esforço: 5 dias
- Benefício: Pulses sempre atualizadas, contexto de threat actor

---

### Prioridade 3 (Médio prazo): 🟢

**Sprints 4-5: Frontend + Correlação**
- Motivo: UX e correlação multi-source
- Esforço: 5-7 dias
- Benefício: Interface completa, maior confiança

---

## 📈 Métricas de Sucesso

### Sprint 1 (Enriquecimento)
- [ ] 100% dos IOCs enriquecidos têm reputation score
- [ ] 100% dos IOCs (IPs/domains) têm geo data
- [ ] 80% dos IOCs maliciosos têm malware families

### Sprint 2-3 (Sync)
- [ ] 100+ pulses sincronizadas no primeiro sync
- [ ] 1,000+ IOCs importados de pulses
- [ ] Sync rodando 2x/dia sem falhas

### Sprint 4 (Frontend)
- [ ] Tempo de navegação < 2s por pulse
- [ ] Filtros funcionando (adversary, malware, tag)
- [ ] Link para IOC Browser funcionando

### Sprint 5 (Correlação)
- [ ] 50% dos IOCs têm múltiplas fontes
- [ ] Cross-reference automático funcionando
- [ ] Dashboard de cobertura implementado

---

## 📝 Próximos Passos Imediatos

1. **Obter OTX API Key**:
   - Criar conta em https://otx.alienvault.com
   - Gerar API key
   - Adicionar ao `.env`: `OTX_API_KEY=...`

2. **Instalar SDK**:
   ```bash
   cd backend
   source venv/bin/activate
   pip install OTXv2
   ```

3. **Testar SDK**:
   ```python
   from OTXv2 import OTXv2
   otx = OTXv2(os.getenv("OTX_API_KEY"))
   user = otx.get('/api/v1/users/me')
   print(f"Autenticado: {user['username']}")
   ```

4. **Implementar Sprint 1**:
   - Criar `app/cti/services/otx_service_v2.py`
   - Seguir exemplos de `OTX_INTEGRATION_EXAMPLES.md`
   - Testar com 10 IOCs

---

## 🔗 Documentação Relacionada

- **OTX API Docs**: https://otx.alienvault.com/assets/static/external_api.html
- **OTX Python SDK**: https://github.com/AlienVault-OTX/OTX-Python-SDK
- **MISP Importer Reference**: https://github.com/gcrahay/otx_misp
- **Nossa Análise**: `OTX_INTEGRATION_ANALYSIS.md`
- **Exemplos Código**: `OTX_INTEGRATION_EXAMPLES.md`
- **Comparação**: `OTX_INTEGRATION_COMPARISON.md`

---

**Pronto para começar?** 🚀

Começar pelo **Sprint 1: Enriquecimento Avançado** garante ROI imediato e valida a abordagem antes de investir em sync e frontend.

---

**Última atualização**: 2025-01-22
**Autor**: Intelligence Platform Team
