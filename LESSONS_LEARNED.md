# Lições Aprendidas - Dashboard AI v2

## Data: 2025-11-06

---

## 1. Problema: Widgets Não Atualizavam com Mudança de Período Temporal

### Sintoma
- Usuário mudava período (30d → 7d → 90d)
- Logs mostravam query sendo atualizada
- Resultado da API retornava dados diferentes
- **MAS** o gráfico na tela não mudava

### Causa Raiz
O sistema tinha **dois lugares** onde dados eram armazenados:
1. `widget.data.results` - Resultado bruto da API (atualizado ✅)
2. `widget.data.config` - Dados processados para Plotly (NÃO atualizado ❌)

O componente `PlotlyChart` lia de `widget.data.config.data`, então mesmo com novos resultados, o gráfico não mudava.

### Solução
**Arquivo:** `frontend/src/stores/dashboardStore.ts:358-363`

```typescript
// ANTES - Só atualizava results
updateWidgetData(widget.id, {
  query: updatedQuery,
  results: result,
  last_updated: new Date().toISOString(),
});

// DEPOIS - Atualiza results E config
updateWidgetData(widget.id, {
  query: updatedQuery,
  results: result,
  config: { data: result.data },  // ← CRÍTICO: Atualizar config!
  last_updated: new Date().toISOString(),
});
```

### Lição Aprendida
**Sempre atualizar TODOS os lugares onde dados são armazenados.** Se há cache/transformação de dados em múltiplos campos, TODOS devem ser sincronizados.

---

## 2. Problema: Widget Consultava Índice Errado

### Sintoma
- Widget criado no índice "vazamentos"
- Logs mostravam consulta no índice "dashboard_servers"
- Resultados vinham vazios ou incorretos

### Causa Raiz
Widget **não salvava** o índice usado na criação. Ao atualizar, usava o índice **globalmente selecionado** no momento do refresh, não o índice original do widget.

### Solução Implementada

#### Backend (`backend/app/models/widget.py:42`)
```python
class Widget(BaseModel):
    id: str
    title: str
    type: Literal['pie', 'bar', 'line', 'metric', 'table', 'area', 'scatter']
    position: WidgetPosition
    data: WidgetData
    index: Optional[str] = Field(None, description="Elasticsearch index used by this widget")  # ← NOVO
    metadata: WidgetMetadata
```

#### Frontend (`frontend/src/types/widget.ts:34`)
```typescript
export interface Widget {
  id: string;
  title: string;
  type: VisualizationType;
  position: WidgetPosition;
  data: WidgetData;
  index?: string;  // ← NOVO: Elasticsearch index for this widget
  metadata: WidgetMetadata;
}
```

#### Salvar na Criação (`frontend/src/components/ChatPanel.tsx:87`)
```typescript
const newWidget: Widget = {
  id: `widget-${Date.now()}`,
  title: response.widget.title || 'Novo Widget',
  type: response.widget.type || 'pie',
  position: calculateNextPosition(),
  data: response.widget.data,
  index: selectedIndex,  // ← Salvar índice usado na criação
  metadata: { ... },
};
```

#### Usar na Execução (`frontend/src/components/WidgetCard.tsx:40`)
```typescript
// Usar índice do widget (prioritário) ou índice global
const indexToUse = widget.index || selectedIndex;

const result = await api.executeQuery(
  indexToUse,  // ← Usa índice do widget, não global
  widget.data.query,
  selectedServerId || undefined,
  timeRange
);
```

#### Usar no Refresh (`frontend/src/stores/dashboardStore.ts:306`)
```typescript
// Usar índice do widget (prioritário) ou índice global
const indexToUse = widget.index || selectedIndex;

if (!indexToUse) {
  console.warn(`⚠️ Widget ${widget.id} has no index, skipping`);
  continue;
}

const result = await api.executeQuery(
  indexToUse,  // ← Cada widget consulta SEU índice
  updatedQuery,
  selectedServerId || undefined,
  timeRange
);
```

### Lição Aprendida
**Widgets devem ser auto-contidos.** Cada widget deve armazenar TODAS as informações necessárias para se auto-atualizar, incluindo:
- Query Elasticsearch
- Índice de origem
- Configuração de visualização

Não depender de estado global que pode mudar.

---

## 3. Problema: Query vs Results - Persistência Incorreta

### Sintoma Inicial
- Widgets salvos no Elasticsearch continham `results` enormes
- Ao carregar dashboard, widgets não re-executavam query
- Mudança de período não fazia nada (não tinha query para re-executar)

### Arquitetura Correta Implementada

#### Separação Clara
```
┌─────────────────────────────────────┐
│ PERSISTIDO (Elasticsearch)          │
├─────────────────────────────────────┤
│ - query: { size: 0, aggs: {...} }   │  ← Salvar
│ - config: { colors: [...] }         │  ← Salvar
│ - results: <NÃO PERSISTIR>          │  ← Remover antes de salvar
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ RUNTIME (Zustand store)              │
├─────────────────────────────────────┤
│ - query: {...}                       │  ← Carregado do ES
│ - config: {...}                      │  ← Carregado do ES
│ - results: {...}                     │  ← Cache temporário (executar query)
│ - last_updated: "2025-11-06..."     │  ← Timestamp
└─────────────────────────────────────┘
```

#### Implementação (`backend/app/services/dashboard_service.py`)
```python
# Preparar para salvamento (remover results dos widgets)
dashboard_dict = current.model_dump(mode='json')
if 'widgets' in dashboard_dict:
    for widget in dashboard_dict['widgets']:
        if 'data' in widget and 'results' in widget['data']:
            # Remover results - não persistir cache
            del widget['data']['results']

# Salvar no Elasticsearch
await self.es.index(
    index=self.index_name,
    id=dashboard_id,
    document=dashboard_dict
)
```

### Lição Aprendida
**Separar persistência de cache.**
- **Persistir:** Queries, configurações, metadados
- **Cache runtime:** Resultados de execução, timestamps
- **Nunca:** Persistir dados que podem ser recalculados

---

## 4. Problema: Campo de Data Dinâmico por Índice

### Sintoma
- LLM criava queries com `@timestamp`
- Índice "vazamentos" não tem `@timestamp`
- Índice tem `breach_date`, `scan_date`, `ultima_senha`
- Queries retornavam 0 resultados

### Solução
LLM agora recebe **mapping do índice** e escolhe campo DATE dinamicamente.

#### Prompt LLM (`backend/app/services/llm_service.py`)
```python
**⚠️ CRÍTICO - FILTRO TEMPORAL OBRIGATÓRIO:**
- TODA query DEVE incluir filtro temporal em um campo DATE
- Escolha o campo DATE mais apropriado da base de conhecimento acima
- Use EXATAMENTE estes valores:
  - gte: {time_range_dict.get('from') or 'now-30d'}
  - lte: {time_range_dict.get('to', 'now')}

**Como escolher o campo de data:**
- Procure na base de conhecimento por campos tipo DATE
- Use o campo mais relevante (ex: @timestamp, data_criacao, scan_date, etc)
- Se o índice não tiver campo de data, NÃO adicione o filtro temporal
```

#### Backend Smart Filter (`backend/app/api/v1/chat.py:136-228`)
Função `_inject_time_filter()`:
1. Procura filtro `range` existente em qualquer campo DATE
2. Se encontrou, **atualiza** valores `gte` e `lte`
3. Se não encontrou, injeta novo filtro com `@timestamp`

```python
# Procurar por filtro range existente
for i, filter_item in enumerate(filters):
    if isinstance(filter_item, dict) and "range" in filter_item:
        date_field = list(filter_item["range"].keys())[0]
        date_field_found = date_field
        filter_index = i
        break

# Se encontrou, atualizar valores
if date_field_found and filter_index is not None:
    filters[filter_index]["range"][date_field_found] = {
        "gte": time_from,
        "lte": time_to
    }
```

### Lição Aprendida
**Sistemas devem ser agnósticos ao schema.** Não assumir nomes de campos fixos. Usar metadados do índice (mapping) para descobrir campos dinamicamente.

---

## 5. Estado Atual do Sistema

### ✅ Funcionalidades Implementadas

#### 1. **Dashboard Multi-Índice**
- Widgets podem ser de índices diferentes no mesmo dashboard
- Ex: Widget de "vazamentos" + Widget de "logs" + Widget de "metrics"
- Cada widget **sempre** consulta seu índice original

#### 2. **Filtro Temporal Global**
- Time Range Picker com 10 presets (1h até 1 ano)
- Range customizado com datetime pickers
- Ao mudar período, **TODOS** widgets atualizam
- Cada widget mantém seu índice, mas filtra pelo período global

#### 3. **Atualização Inteligente de Queries**
- Frontend detecta campo DATE na query
- Atualiza valores `gte` e `lte` localmente
- Backend recebe query já atualizada
- Backend valida e ajusta se necessário

#### 4. **Chat com IA**
- LLM recebe mapping do índice
- Escolhe campo DATE apropriado dinamicamente
- Cria queries com filtro temporal correto
- Gera visualizações (pie, bar, line, metric, table, area, scatter)

#### 5. **Persistência Otimizada**
- Salva apenas queries e configs
- Remove results antes de persistir
- Widgets re-executam query ao carregar
- Cache runtime mantém última execução

### 📊 Arquitetura de Dados

```
┌──────────────────────────────────────────────────────────────┐
│                         DASHBOARD                             │
├──────────────────────────────────────────────────────────────┤
│  Time Range: [now-30d] to [now]  ← GLOBAL                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────────────┐  ┌───────────────────┐               │
│  │ Widget 1          │  │ Widget 2          │               │
│  │ index: vazamentos │  │ index: logs       │               │
│  │ query: {...}      │  │ query: {...}      │               │
│  │ config: {...}     │  │ config: {...}     │               │
│  │ results: CACHE    │  │ results: CACHE    │               │
│  └───────────────────┘  └───────────────────┘               │
│           ↓                       ↓                           │
│    ES: vazamentos          ES: logs                          │
│    filtered by             filtered by                       │
│    now-30d to now          now-30d to now                    │
└──────────────────────────────────────────────────────────────┘
```

### 🔄 Fluxo de Atualização

```
1. Usuário muda Time Range (30d → 7d)
   ↓
2. Store trigger: setTimeRange()
   ↓
3. setTimeout 100ms → refreshAllWidgets()
   ↓
4. Para CADA widget:
   a) Lê widget.index (ex: "vazamentos")
   b) Atualiza query local: breach_date.gte = "now-7d"
   c) Executa: api.executeQuery(widget.index, updatedQuery, timeRange)
   d) Recebe: { total: 10, data: [...] }
   e) Atualiza store:
      - widget.data.query = updatedQuery
      - widget.data.results = result
      - widget.data.config = { data: result.data }  ← CRÍTICO!
      - widget.data.last_updated = now()
   ↓
5. React detecta mudança em widget.data
   ↓
6. WidgetCard re-renderiza com key={widget.id}-${last_updated}
   ↓
7. PlotlyChart recebe config.data atualizado
   ↓
8. Gráfico renderiza com novos dados
```

### 🐛 Debug Logs Implementados

Para facilitar troubleshooting futuro:

```typescript
// dashboardStore.ts
console.log('🕒 Time range updated:', timeRange);
console.log('📊 Will refresh X widgets in 100ms');
console.log('🔄 refreshAllWidgets called!');
console.log('🔍 Processing widget X:');
console.log('  - Title:', widget.title);
console.log('  - Index to use:', indexToUse, '(from widget)');
console.log('  - Original Query:', query);
console.log('  🔧 Updating date_field filter: from to');
console.log('  - Updated Query:', updatedQuery);
console.log('  - Result:', result);
console.log('📝 updateWidgetData called for X:', data);
console.log('✅ Widget X data updated in store');

// WidgetCard.tsx
console.log('🔄 WidgetCard X render:', {
  hasResults, hasConfig, configData, lastUpdated
});
```

---

## 6. Próximos Passos Sugeridos

### 🎨 UX Enhancements
1. **Badge de Índice no Widget**
   - Mostrar qual índice o widget consulta
   - Útil quando há múltiplos índices no dashboard

2. **Loading State no Refresh**
   - Spinner/overlay durante atualização de período
   - Feedback visual de que dados estão sendo atualizados

3. **Error Handling**
   - Mostrar erro se query falhar
   - Retry button
   - Mensagem específica (ex: "Índice não encontrado")

### 🔧 Funcionalidades
1. **Widget Settings**
   - Permitir trocar índice do widget manualmente
   - Re-executar query após troca

2. **Query Editor**
   - Modo avançado para editar query manualmente
   - Syntax highlighting
   - Validação

3. **Export/Import**
   - Exportar dashboard como JSON
   - Importar dashboard salvo
   - Templates de dashboards

### 🚀 Performance
1. **Debounce Time Range**
   - Evitar múltiplas chamadas durante seleção de range customizado

2. **Parallel Query Execution**
   - Executar queries de múltiplos widgets em paralelo
   - Usar Promise.all()

3. **WebSocket para Updates**
   - Corrigir conexão WebSocket (atualmente falhando)
   - Sync em tempo real entre usuários

---

## 7. Comandos Úteis

### Docker
```bash
# Restart serviços
cd /Users/angellocassio/Downloads/dashboard-ai-v2
docker compose restart backend frontend

# Ver logs
docker compose logs -f backend
docker compose logs -f frontend

# Rebuild completo
docker compose down
docker compose up --build -d
```

### Debug Frontend
```bash
# Console do navegador
# Filtrar por emoji:
🕒  # Time range updates
🔄  # Widget refresh
📝  # Store updates
✅  # Success
❌  # Errors
```

---

## 8. Arquivos Críticos Modificados

### Backend
- `backend/app/models/widget.py` - Adicionado campo `index`
- `backend/app/api/v1/chat.py` - Smart filter `_inject_time_filter()`
- `backend/app/services/llm_service.py` - Prompt dinâmico para campo DATE
- `backend/app/services/dashboard_service.py` - Remove results antes de salvar

### Frontend
- `frontend/src/types/widget.ts` - Interface Widget com `index?: string`
- `frontend/src/stores/dashboardStore.ts` - TimeRange, refreshAllWidgets, updateWidgetData
- `frontend/src/components/ChatPanel.tsx` - Salva index na criação
- `frontend/src/components/WidgetCard.tsx` - Usa widget.index, key dinâmica
- `frontend/src/components/TimeRangePicker.tsx` - **NOVO** componente
- `frontend/src/components/PlotlyChart.tsx` - Renderiza visualizações
- `frontend/src/pages/DashboardEditor.tsx` - Integra TimeRangePicker

---

## 9. Referências

### Tecnologias
- **Frontend:** React 18, TypeScript, Vite, Zustand, Plotly.js, TailwindCSS
- **Backend:** FastAPI, Python 3.11, Pydantic, Elasticsearch
- **LLM:** Claude (Databricks), LangChain
- **Infra:** Docker Compose

### Links Úteis
- React Plotly: https://plotly.com/javascript/react/
- Zustand: https://github.com/pmndrs/zustand
- FastAPI: https://fastapi.tiangolo.com/
- Elasticsearch Query DSL: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html

---

**Documento criado em:** 2025-11-06
**Última atualização:** 2025-11-06
**Versão do sistema:** v2.0 - Multi-Index Support
