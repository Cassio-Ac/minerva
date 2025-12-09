# 📊 Dashboards GVULN

Dashboards HTML interativos gerados pelo sistema GVULN.

## 📁 Arquivos Disponíveis

### 1. **dashboard_completo.html** (4.6 MB)
- **Período:** Todo o histórico
- **Total de Tickets:** 233.142
- **Timeline:** 64 pontos de dados
- **Gerado em:** 2025-10-30 11:08:22

### 2. **dashboard_ultimos_30_dias.html** (4.6 MB)
- **Período:** 2025-09-30 até 2025-10-30
- **Total de Tickets:** 80.302
- **Timeline:** 14 pontos de dados
- **Gerado em:** 2025-10-30 11:08:09

## 🎨 Visualizações Incluídas

Cada dashboard contém:

1. **📊 Total de Tickets** - Indicador principal
2. **🍕 Tickets por Severidade** - Gráfico de pizza
3. **📈 Tickets por Prioridade** - Gráfico de barras
4. **👥 Top 10 Squads** - Ranking de equipes
5. **🔧 Top 10 Remediações** - Ações mais comuns
6. **💻 Top 10 Hosts** - Hosts mais afetados
7. **📊 Distribuição CVSS** - Histograma de scores
8. **⚠️ Distribuição EPSS** - Probabilidade de exploração
9. **🎯 CISA KEV** - Vulnerabilidades exploradas ativamente
10. **🔥 Severidade por Squad** - Matriz de calor
11. **📅 Timeline** - Evolução temporal

## 🚀 Como Usar

### Abrir no Navegador

```bash
# Dashboard completo
open dashboards/dashboard_completo.html

# Últimos 30 dias
open dashboards/dashboard_ultimos_30_dias.html
```

### Gerar Novos Dashboards

```bash
# Todo o período
python3 dashboard_agent.py

# Últimos N dias
python3 dashboard_agent.py --last-days 30

# Período específico
python3 dashboard_agent.py --start-date 2025-01-01 --end-date 2025-01-31
```

## 📊 Características

- ✅ **100% dos dados** - Usa Scroll API para buscar todos os documentos
- ✅ **Interativo** - Hover, zoom, pan em todos os gráficos
- ✅ **Responsivo** - Layout adaptável
- ✅ **Offline** - Funciona sem conexão com internet
- ✅ **Leve** - ~4.6 MB por dashboard

## 🔧 Correções Implementadas

### Problema 1: Limite de 10.000 Documentos ✅
- **Antes:** Apenas 10.000 tickets (4% dos dados)
- **Depois:** 233.142 tickets (100% dos dados)
- **Solução:** `track_total_hits: True` + Scroll API

### Problema 2: Timeline Não Aparecia ✅
- **Antes:** Gráfico vazio
- **Depois:** Timeline completa com 64 pontos
- **Solução:** Campo correto `created_date` (era `created_timestamp`)

### Problema 3: CISA KEV Retornava Zero ✅
- **Antes:** Sempre zero (nested query errado)
- **Depois:** Valor real
- **Solução:** Campo direto `is_cisa_kev` (não `cves.is_cisa_kev`)

## 📈 Estatísticas

| Métrica | Valor |
|---------|-------|
| **Total de Tickets** | 233.142 |
| **Últimos 30 dias** | 80.302 |
| **Pontos na Timeline (completo)** | 64 |
| **Pontos na Timeline (30 dias)** | 14 |
| **Tamanho do Arquivo** | 4.6 MB |
| **Tempo de Geração** | ~5 segundos |

## 🎯 Próximos Passos

- [ ] Adicionar filtros interativos
- [ ] Exportar para PDF
- [ ] Adicionar comparação entre períodos
- [ ] Dashboard em tempo real
- [ ] Alertas automáticos

---

**Gerado por:** Dashboard Agent GVULN  
**Data:** 2025-10-30  
**Versão:** 1.0
