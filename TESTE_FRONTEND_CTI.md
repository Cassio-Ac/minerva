# 🧪 Guia de Teste - Frontend CTI UI

**Data**: 2025-11-21
**Status**: ✅ Frontend rodando sem erros
**URL Base**: http://localhost:5181

---

## ✅ Status Atual

### Backend
- ✅ Rodando em http://localhost:8002
- ✅ 15 MISP feeds disponíveis
- ✅ IOC Enrichment service funcionando
- ✅ LLM usando OpenAI GPT-4o-mini

### Frontend
- ✅ Rodando em http://localhost:5181
- ✅ Compilado sem erros de Material-UI
- ✅ Usando Tailwind CSS + lucide-react
- ✅ 2 páginas CTI criadas

---

## 🎯 Páginas Disponíveis

### 1. MISP Feeds Page
**URL**: http://localhost:5181/cti/feeds

**O que faz**:
- Lista 15 feeds MISP disponíveis
- Testa feeds em tempo real
- Exibe samples de IOCs
- Mostra estatísticas

**Feeds disponíveis**:
1. DiamondFox C2 Panels (Unit42)
2. abuse.ch SSL Blacklist
3. OpenPhish
4. SERPRO (BR Gov)
5. URLhaus
6. ThreatFox
7. Emerging Threats
8. AlienVault Reputation
9. blocklist.de
10. GreenSnow
11. CINS Score Bad Guys

### 2. IOC Enrichment Page
**URL**: http://localhost:5181/cti/enrichment

**O que faz**:
- Busca IOCs de um feed
- Enriquece com LLM (OpenAI)
- Mostra MITRE ATT&CK techniques
- Exibe detection methods
- Calcula severity e confidence

---

## 🧪 Teste 1: MISP Feeds (2 min)

### Passo a Passo:

1. **Acesse**: http://localhost:5181/cti/feeds

2. **Selecione o feed**: "DiamondFox C2 Panels (Unit42)"

3. **Configure limite**: 5 IOCs

4. **Clique em**: "Testar Feed"

5. **Aguarde**: ~2 segundos

### ✅ Resultado Esperado:

```
┌─────────────────────────────────────────┐
│ Resultado do Teste                      │
├─────────────────────────────────────────┤
│ Feed: DiamondFox C2 Panels (Unit42)    │
│ Itens Processados: 5                    │
│ IOCs Encontrados: 5                     │
│ Status: success ✓                       │
├─────────────────────────────────────────┤
│ Samples de IOCs:                        │
│                                          │
│ [🌐] hxxp://185.234.218.xxx/xxx/xxx    │
│ [url] Malware: DiamondFox               │
│ Context: C2 panel URL                   │
│ Tags: [c2] [diamondfox] [unit42]       │
│                                          │
│ [🌐] hxxp://192.168.1.xxx/panel/login  │
│ [url] Malware: DiamondFox               │
│ Context: C2 panel URL                   │
│ Tags: [c2] [malware]                    │
└─────────────────────────────────────────┘
```

**O que observar**:
- ✅ Cards de estatísticas aparecem
- ✅ IOCs estão listados com URLs defanged (hxxp)
- ✅ Badges coloridos para tipo de IOC
- ✅ Tags visuais (c2, diamondfox, unit42)
- ✅ Malware family identificado
- ✅ Sem erros no console

---

## 🧪 Teste 2: SSL Blacklist (2 min)

### Passo a Passo:

1. **Selecione o feed**: "abuse.ch SSL Blacklist"

2. **Configure limite**: 10 IOCs

3. **Clique em**: "Testar Feed"

### ✅ Resultado Esperado:

```
┌─────────────────────────────────────────┐
│ Feed: abuse.ch SSL Blacklist           │
│ IOCs Encontrados: 10                    │
├─────────────────────────────────────────┤
│ [#] 2c4064d26a6ee3f1e80ca4d1b7c49c91...│
│ [hash] Malware: ConnectWise             │
│ Context: SSL certificate fingerprint    │
│ Tags: [c2] [ssl] [certificate]         │
└─────────────────────────────────────────┘
```

**O que observar**:
- ✅ Type: hash (com ícone #)
- ✅ SHA1 fingerprints exibidos
- ✅ Malware families detectados
- ✅ Context correto (SSL certificate)

---

## 🧪 Teste 3: IOC Enrichment (1 min de setup + 10 seg processing)

### Passo a Passo:

1. **Acesse**: http://localhost:5181/cti/enrichment

2. **Selecione o feed**: "DiamondFox C2 Panels"

3. **Configure limite**: 3 IOCs

4. **Clique em**: "Enriquecer"

5. **Aguarde**: ~8-10 segundos (LLM processing)

### ✅ Resultado Esperado:

```
┌─────────────────────────────────────────────────────────┐
│ Resultado do Enrichment                                 │
├─────────────────────────────────────────────────────────┤
│ Feed: DiamondFox C2 Panels (Unit42)                    │
│ IOCs Fetched: 3                                         │
│ IOCs Enriquecidos: 3                                    │
│ Status: success ✓                                       │
├─────────────────────────────────────────────────────────┤
│ IOCs Enriquecidos:                                      │
│                                                          │
│ ┌───────────────────────────────────────────────────┐  │
│ │ [🎯] hxxp://185.234.218.xxx/xxx/xxx     [url]    │  │
│ ├───────────────────────────────────────────────────┤  │
│ │ Threat Type: [c2] 🔴                              │  │
│ │ Severity: [HIGH] 🔴                               │  │
│ │                                                    │  │
│ │ Summary:                                           │  │
│ │ This URL is a C2 panel for DiamondFox malware.   │  │
│ │ Attackers use this panel to control infected     │  │
│ │ systems and exfiltrate data.                      │  │
│ │                                                    │  │
│ │ 🎯 MITRE ATT&CK Techniques:                       │  │
│ │ [T1071.001] [T1587.001] [T1202]                   │  │
│ │                                                    │  │
│ │ Tactics:                                           │  │
│ │ [command-and-control] [initial-access]            │  │
│ │                                                    │  │
│ │ Detection Methods:                                 │  │
│ │ 1. Monitor outbound HTTP connections to this URL │  │
│ │ 2. Block domain at firewall level                │  │
│ │ 3. Analyze network traffic for C2 patterns       │  │
│ │ 4. Check DNS logs for suspicious queries         │  │
│ │                                                    │  │
│ │ Confidence: high | 🧠 LLM: openai/gpt-4o-mini    │  │
│ └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**O que observar**:
- ✅ Threat Type: c2 (badge vermelho)
- ✅ Severity: HIGH (badge vermelho)
- ✅ Summary contextual gerado por LLM
- ✅ MITRE ATT&CK Techniques: T1071.001, T1587.001, T1202
- ✅ Tactics: command-and-control, initial-access
- ✅ Detection Methods: 3-5 sugestões práticas
- ✅ Confidence: high
- ✅ LLM usado: openai/gpt-4o-mini

---

## 🧪 Teste 4: Phishing Enrichment (10 seg processing)

### Passo a Passo:

1. **Selecione o feed**: "OpenPhish"

2. **Configure limite**: 3 IOCs

3. **Clique em**: "Enriquecer"

### ✅ Resultado Esperado:

```
┌─────────────────────────────────────────┐
│ Threat Type: [phishing] 🟠             │
│ Severity: [MEDIUM] 🟠                  │
│                                          │
│ MITRE ATT&CK:                           │
│ [T1566.002] Spearphishing Link         │
│ [T1204] User Execution                  │
│                                          │
│ Detection Methods:                       │
│ 1. URL reputation services              │
│ 2. Email filtering (SPF, DKIM, DMARC)  │
│ 3. User security awareness training     │
└─────────────────────────────────────────┘
```

**O que observar**:
- ✅ Threat Type: phishing (badge laranja)
- ✅ Severity: MEDIUM (badge laranja)
- ✅ Techniques específicos de phishing (T1566.002)
- ✅ Detection methods contextuais para phishing

---

## 🎨 Elementos Visuais para Verificar

### Color Coding

**Severity**:
- 🔴 Critical/High: vermelho (#dc2626)
- 🟠 Medium: laranja (#f59e0b)
- 🔵 Low: azul (#3b82f6)
- ⚪ Unknown: cinza (#6b7280)

**Threat Type**:
- 🔴 C2 / Malware Delivery: vermelho
- 🟠 Phishing: laranja
- 🔵 Reconnaissance: azul
- ⚪ Other: cinza

**IOC Type**:
- 🔵 IP: azul (#3b82f6)
- 🟣 URL: roxo (#8b5cf6)
- 🔷 Hash: ciano (#06b6d4)
- 🟢 Domain: verde (#10b981)

### Icons

- 🛡️ Shield - Security/CTI
- 🧠 Brain - LLM enrichment
- ☁️ CloudDownload - Fetch data
- 🎯 Target - IOC
- 📊 TrendingUp - MITRE ATT&CK
- 🌐 Globe - Network IOCs
- # Hash - File-based IOCs
- ✓ Check - Success
- ⚠️ AlertCircle - Error
- ⏳ Loader2 - Loading

---

## 🐛 Troubleshooting

### Frontend não compilou?
```bash
cd frontend
npm install
npm run dev
```

### Backend não está respondendo?
```bash
curl http://localhost:8002/api/v1/cti/misp/feeds/available
```

Se retornar `{"detail":"Not authenticated"}`, está funcionando!

### Erro de CORS?
Verifique se backend está em http://localhost:8002 (não 8000)

### IOC Enrichment retornando erro?
Verifique se tem OPENAI_API_KEY no .env:
```bash
grep OPENAI_API_KEY backend/.env
```

---

## 📊 Checklist de Sucesso

### MISP Feeds Page (/cti/feeds)
- [ ] Página carrega sem erros
- [ ] Dropdown mostra 15 feeds
- [ ] Botão "Testar Feed" funciona
- [ ] Stats cards aparecem após teste
- [ ] IOCs são exibidos com formatação correta
- [ ] Tags visuais aparecem
- [ ] Color coding funciona (badges coloridos)
- [ ] Icons corretos para cada tipo (Globe, Hash)

### IOC Enrichment Page (/cti/enrichment)
- [ ] Página carrega sem erros
- [ ] Dropdown mostra feeds disponíveis
- [ ] Seletor de limite (1, 3, 5, 10) funciona
- [ ] Botão "Enriquecer" funciona
- [ ] Loading state aparece (~10 seg)
- [ ] Stats cards aparecem após enrichment
- [ ] IOCs enriquecidos são exibidos
- [ ] Threat Type badges coloridos aparecem
- [ ] Severity indicators coloridos aparecem
- [ ] MITRE ATT&CK techniques aparecem
- [ ] Tactics são listados
- [ ] Detection methods são listados
- [ ] Confidence e LLM usado aparecem

### Console do Browser
- [ ] Sem erros de Material-UI
- [ ] Sem erros de import
- [ ] Sem erros de API (exceto 401 se não logado)

---

## 🎉 Próximos Passos

Se todos os testes passaram:

### Phase 4A: Dashboard de Estatísticas
1. Criar página de stats (`/cti/stats`)
2. Gráficos de distribuição por tipo
3. Timeline de enrichments
4. Top malware families
5. MITRE ATT&CK heatmap

### Phase 4B: Search & Filter
1. Buscar IOCs por valor
2. Filtrar por tipo, severity, confidence
3. Export to CSV/JSON
4. Paginação

### Phase 4C: Visualization
1. Graph de relationships entre IOCs
2. Geographic distribution (IPs)
3. Timeline de descoberta
4. Network topology

---

## 📝 Notas

- Frontend usa **Tailwind CSS** (não Material-UI)
- Icons são **lucide-react**
- Theme é gerenciado por **useSettingsStore**
- Backend API: `/api/v1/cti/`
- LLM: OpenAI GPT-4o-mini (env fallback)

---

**Gerado por**: Claude Code
**Data**: 2025-11-21
**Versão**: 1.0
