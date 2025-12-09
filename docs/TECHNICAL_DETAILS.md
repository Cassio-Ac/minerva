# Dashboard AI v2 - Detalhes Técnicos

## 📋 Índice

- [Estrutura de Dados](#estrutura-de-dados)
- [Fluxo de Criação de Widgets](#fluxo-de-criação-de-widgets)
- [Persistência e Salvamento](#persistência-e-salvamento)
- [Time Range e Queries](#time-range-e-queries)
- [Sistema de Temas](#sistema-de-temas)
- [WebSocket Real-Time](#websocket-real-time)
- [Otimizações e Performance](#otimizações-e-performance)

---

## 🗂️ Estrutura de Dados

### **Widget Object**

Estrutura completa de um widget no frontend:

```typescript
interface Widget {
  id: string;                    // UUID gerado: `widget-${Date.now()}`
  title: string;                 // Ex: "Timeline de Vazamentos"
  type: VisualizationType;       // pie | bar | line | area | scatter | metric | table
  position: WidgetPosition;      // { x, y, w, h } para grid layout
  index: string;                 // Índice ES associado (próprio do widget!)

  data: {
    query: object;               // Query Elasticsearch original
    results?: {                  // Resultados da query (runtime)
      total: number;
      took: number;
      data: Array<{label: any, value: number}>;
    };
    config?: {                   // Configuração Plotly (persistido)
      colors?: string[];
      layout?: object;
      plotly?: object;
      data: Array<{label: any, value: number}>;  // Dados formatados
    };
    last_updated?: string;       // ISO timestamp da última execução
  };

  metadata: {
    created_at: string;          // ISO timestamp
    updated_at: string;          // ISO timestamp
    version: number;             // Versão do widget
  };
}
```

### **Dashboard Object**

Estrutura de um dashboard no PostgreSQL:

```typescript
interface Dashboard {
  id: string;                    // UUID
  title: string;                 // Nome do dashboard
  description?: string;          // Descrição opcional
  index: string;                 // Índice ES principal (legacy)
  server_id?: string;            // FK para es_servers

  layout: {
    cols: number;                // Colunas do grid (default: 12)
    row_height: number;          // Altura da linha em px (default: 60)
    width: number;               // Largura total (default: 1600)
  };

  widgets: Widget[];             // Array de widgets (JSON no PG)

  metadata: {
    is_public: boolean;          // Dashboard público?
    tags: string[];              // Tags para busca
    version: string;             // Versão (ex: "1.0.0")
    created_by?: string;         // User ID (futuro)
    created_at: string;          // ISO timestamp
    updated_at: string;          // ISO timestamp
  };
}
```

### **Conversation Object**

Estrutura de uma conversa no PostgreSQL:

```typescript
interface Conversation {
  id: string;                    // UUID
  title: string;                 // Título da conversa
  index: string;                 // Índice ES associado
  server_id?: string;            // FK para es_servers

  messages: ConversationMessage[]; // Array de mensagens (JSON no PG)

  created_by?: string;           // User ID (futuro)
  created_at: string;            // ISO timestamp
  updated_at: string;            // ISO timestamp
}

interface ConversationMessage {
  id: string;                    // UUID da mensagem
  role: 'user' | 'assistant';    // Quem enviou
  content: string;               // Texto da mensagem
  timestamp: string;             // ISO timestamp

  widget?: {                     // Widget anexado (se houver)
    title: string;
    type: string;
    query: object;               // Query ES usada
    data: object;                // Dados + config completo
    config?: object;
  };
}
```

---

## 🔨 Fluxo de Criação de Widgets

### **Passo 1: Usuário Envia Mensagem**

```typescript
// ChatPanel.tsx - handleSendMessage()

const userMessage: Message = {
  role: 'user',
  content: 'Mostre uma timeline dos vazamentos',
  timestamp: new Date().toISOString(),
};

setMessages(prev => [...prev, userMessage]);
```

### **Passo 2: Backend Processa com LLM**

```python
# backend/app/api/v1/chat.py

@router.post("/", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    # 1. Buscar campos do índice ES
    fields = await es_client.get_index_fields(request.index)

    # 2. Montar system prompt
    system_prompt = f"""
    Você é um assistente especializado em Elasticsearch.
    Índice: {request.index}
    Campos disponíveis: {fields}

    Crie uma query ES e retorne os dados formatados.
    """

    # 3. Chamar LLM (Claude/OpenAI/Databricks)
    response = await llm_service.generate_widget(
        user_message=request.message,
        system_prompt=system_prompt,
        index_fields=fields
    )

    # 4. Executar query gerada no ES
    es_results = await es_client.search(
        index=request.index,
        query=response.query
    )

    # 5. Formatar dados para Plotly
    plotly_data = format_data_for_plotly(
        es_results,
        chart_type=response.widget_type
    )

    # 6. Retornar widget completo
    return ChatResponse(
        explanation="Criei um gráfico...",
        widget=Widget(
            title=response.title,
            type=response.widget_type,
            data={
                "query": response.query,
                "results": es_results,
                "config": {
                    "data": plotly_data,
                    "colors": [...],
                    "layout": {...}
                }
            }
        )
    )
```

### **Passo 3: Frontend Adiciona Widget**

```typescript
// ChatPanel.tsx

if (response.widget) {
  const newWidget: Widget = {
    id: `widget-${Date.now()}`,           // ← ID único baseado em timestamp
    title: response.widget.title,
    type: response.widget.type,
    position: calculateNextPosition(),     // ← Calcula posição no grid

    data: {
      ...response.widget.data,
      last_updated: new Date().toISOString(), // ← Marca como recém-criado
    },

    index: selectedIndex,                  // ← Salva índice usado!

    metadata: {
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      version: 1,
    },
  };

  // Adiciona ao store Zustand
  addWidget(newWidget);

  // Store automaticamente salva após 500ms (debounce)
  // Ver: useDashboardStore.addWidget()
}
```

### **Passo 4: Widget é Renderizado**

```typescript
// WidgetCard.tsx

export const WidgetCard: React.FC<WidgetCardProps> = ({ widget }) => {
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const executeQuery = async () => {
      // Verifica se já tem dados recentes
      const hasRecentData =
        widget.data.results &&
        widget.data.last_updated &&
        (Date.now() - new Date(widget.data.last_updated).getTime()) < 5000;

      if (hasRecentData) {
        console.log('Widget tem dados recentes, pulando query');
        return; // ← Widget recém-criado não re-executa!
      }

      // Se não tem dados, executa query
      setIsLoading(true);
      const result = await api.executeQuery(
        widget.index,      // ← Usa índice do widget
        widget.data.query,
        selectedServerId,
        undefined          // ← NÃO envia timeRange (query já tem)
      );

      updateWidgetData(widget.id, {
        results: result,
        config: {
          ...widget.data.config,
          data: result.data
        },
        last_updated: new Date().toISOString(),
      });
      setIsLoading(false);
    };

    executeQuery();
  }, [widget.id, widget.index, timeRange]); // ← NÃO depende de selectedIndex!

  return (
    <div>
      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <PlotlyChart
          type={widget.type}
          data={widget.data.results}  // ← Dados runtime
          config={widget.data.config} // ← Config persistido
        />
      )}
    </div>
  );
};
```

---

## 💾 Persistência e Salvamento

### **Auto-Save com Debounce**

O sistema salva automaticamente com debounce para evitar muitas requisições:

```typescript
// useDashboardStore.ts

addWidget: (widget, skipBroadcast = false) => {
  set((state) => ({
    widgets: [...state.widgets, widget],
  }));

  // Auto-save após 500ms
  if (!skipBroadcast) {
    setTimeout(() => {
      get().saveDashboard();
    }, 500);
  }
},

updateWidgetPosition: (widgetId, position, skipBroadcast = false) => {
  set((state) => ({
    widgets: state.widgets.map((w) =>
      w.id === widgetId
        ? { ...w, position, metadata: { ...w.metadata, updated_at: new Date().toISOString() } }
        : w
    ),
  }));

  // Auto-save após 1000ms (drag & drop)
  if (!skipBroadcast) {
    setTimeout(() => {
      get().saveDashboard();
    }, 1000);
  }
},
```

### **Método saveDashboard**

```typescript
saveDashboard: async () => {
  const { currentDashboard, widgets } = get();

  if (!currentDashboard) return;

  try {
    // Envia apenas widgets atualizados (PATCH semântico)
    await api.updateDashboard(currentDashboard.id, {
      widgets,
    });

    console.log('✅ Dashboard saved');
  } catch (error) {
    console.error('❌ Error saving:', error);
  }
}
```

### **Backend Service SQL**

```python
# backend/app/services/dashboard_service_sql.py

async def update(
    self,
    db: AsyncSession,
    dashboard_id: str,
    updates: DashboardUpdate
) -> Dashboard:
    """Atualiza dashboard no PostgreSQL"""

    # Buscar dashboard existente
    result = await db.execute(
        select(DashboardModel).where(DashboardModel.id == dashboard_id)
    )
    dashboard = result.scalar_one_or_none()

    if not dashboard:
        return None

    # Aplicar updates (apenas campos fornecidos)
    if updates.title:
        dashboard.title = updates.title
    if updates.description is not None:
        dashboard.description = updates.description
    if updates.widgets is not None:
        dashboard.widgets = updates.widgets  # ← Salva JSON completo

    # Atualizar timestamp
    dashboard.updated_at = datetime.utcnow()

    # Commit no PostgreSQL
    await db.commit()
    await db.refresh(dashboard)

    return dashboard
```

### **Estrutura no PostgreSQL**

```sql
-- Tabela dashboards
CREATE TABLE dashboards (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    index VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) REFERENCES es_servers(id),

    -- JSON columns
    layout JSON NOT NULL DEFAULT '{}',
    widgets JSON NOT NULL DEFAULT '[]',  -- ← Array de widgets completo!
    tags JSON NOT NULL DEFAULT '[]',

    -- Metadata
    is_public BOOLEAN DEFAULT false,
    version VARCHAR(20) DEFAULT '1.0.0',
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Exemplo de widget no JSON:
/*
{
  "id": "widget-1762547653774",
  "title": "Timeline Vazamentos",
  "type": "line",
  "position": {"x": 0, "y": 0, "w": 6, "h": 4},
  "index": "vazamentos",
  "data": {
    "query": {
      "size": 0,
      "query": {
        "bool": {
          "must": [
            {"range": {"breach_date": {"gte": "now-6M", "lte": "now"}}}
          ]
        }
      },
      "aggs": {...}
    },
    "config": {
      "colors": ["#6366f1"],
      "layout": {},
      "data": [
        {"label": "2025-05-05", "value": 99},
        {"label": "2025-05-12", "value": 6901}
      ]
    }
  },
  "metadata": {
    "created_at": "2025-11-07T20:05:11Z",
    "updated_at": "2025-11-07T20:05:11Z",
    "version": 1
  }
}
*/
```

---

## ⏱️ Time Range e Queries

### **Estrutura TimeRange**

```typescript
interface TimeRange {
  type: 'preset' | 'custom';
  preset?: string;        // Ex: "now-30d", "now-6M"
  from?: string;          // Ex: "now-30d", "2025-01-01"
  to?: string;            // Ex: "now", "2025-12-31"
  label: string;          // Ex: "Últimos 30 dias"
}
```

### **Fluxo de Mudança de Time Range**

#### **1. Usuário Seleciona Novo Período**

```typescript
// TimeRangePicker.tsx

const handlePresetChange = (preset: string) => {
  const newTimeRange: TimeRange = {
    type: 'preset',
    preset,
    from: preset,  // Ex: "now-6M"
    to: 'now',
    label: getPresetLabel(preset),  // "Últimos 6 meses"
  };

  onChange(newTimeRange);  // ← Chama setTimeRange do store
};
```

#### **2. Store Atualiza e Dispara Refresh**

```typescript
// useDashboardStore.ts

setTimeRange: (timeRange) => {
  set({ timeRange });

  console.log('🕒 Time range updated:', timeRange);
  console.log('📊 Will refresh', get().widgets.length, 'widgets in 100ms');

  // Aguarda 100ms para batch updates
  setTimeout(() => {
    get().refreshAllWidgets();
  }, 100);
},
```

#### **3. refreshAllWidgets Atualiza Todas as Queries**

```typescript
refreshAllWidgets: async () => {
  const { widgets, selectedIndex, selectedServerId, timeRange } = get();

  console.log('🔄 Starting refresh of', widgets.length, 'widgets');

  for (const widget of widgets) {
    if (!widget.data?.query) continue;

    // Usar índice do widget (prioritário) ou global
    const indexToUse = widget.index || selectedIndex;

    if (!indexToUse) {
      console.warn('Widget has no index, skipping');
      continue;
    }

    try {
      // 1. Clonar query original
      const updatedQuery = JSON.parse(JSON.stringify(widget.data.query));

      // 2. Atualizar filtros temporais
      const updateRangeInArray = (arr: any[]) => {
        for (const item of arr) {
          if (item.range) {
            const dateField = Object.keys(item.range)[0];
            if (dateField) {
              console.log(`🔧 Updating ${dateField}: ${timeRange.from} to ${timeRange.to}`);
              item.range[dateField].gte = timeRange.from;
              item.range[dateField].lte = timeRange.to;
            }
          }
        }
      };

      // Atualizar em filter (se existir)
      if (updatedQuery.query?.bool?.filter) {
        const filters = Array.isArray(updatedQuery.query.bool.filter)
          ? updatedQuery.query.bool.filter
          : [updatedQuery.query.bool.filter];
        updateRangeInArray(filters);
      }

      // Atualizar em must (se existir)
      if (updatedQuery.query?.bool?.must) {
        const musts = Array.isArray(updatedQuery.query.bool.must)
          ? updatedQuery.query.bool.must
          : [updatedQuery.query.bool.must];
        updateRangeInArray(musts);
      }

      console.log('Updated Query:', updatedQuery);

      // 3. Executar query atualizada
      const result = await api.executeQuery(
        indexToUse,
        updatedQuery,
        selectedServerId || undefined,
        undefined  // ← NÃO envia timeRange - query já atualizada!
      );

      // 4. Atualizar dados do widget
      get().updateWidgetData(widget.id, {
        query: updatedQuery,  // ← Salva query atualizada
        results: result,
        config: {
          ...widget.data.config,
          data: result.data
        },
        last_updated: new Date().toISOString(),
      });

      console.log(`✅ Widget ${widget.id} refreshed`);
    } catch (error) {
      console.error(`❌ Error refreshing widget ${widget.id}:`, error);
    }
  }

  console.log('✅ All widgets refresh completed');
},
```

### **Por Que NÃO Enviamos timeRange na API?**

**Problema:** Backend aplicaria timeRange sobre query que JÁ tem range atualizado, causando conflito.

**Solução:** Atualizar range DENTRO da query e enviar `undefined` para timeRange:

```typescript
// ❌ ERRADO (causa conflito):
api.executeQuery(index, query, serverId, timeRange);

// ✅ CORRETO (query já atualizada):
api.executeQuery(index, updatedQuery, serverId, undefined);
```

---

## 🎨 Sistema de Temas

### **Definição de Temas**

```typescript
// settingsStore.ts

const themes = {
  light: {
    bg: {
      primary: '#ffffff',
      secondary: '#f9fafb',
      tertiary: '#f3f4f6',
      hover: '#e5e7eb',
    },
    text: {
      primary: '#111827',
      secondary: '#374151',
      muted: '#6b7280',
      inverse: '#ffffff',
    },
    border: {
      default: '#e5e7eb',
      hover: '#d1d5db',
    },
    accent: {
      primary: '#6366f1',
      primaryHover: '#4f46e5',
    },
  },

  dark: {
    bg: {
      primary: '#1e1e1e',
      secondary: '#2d2d2d',
      tertiary: '#3e3e3e',
      hover: '#4a4a4a',
    },
    text: {
      primary: '#e0e0e0',
      secondary: '#b0b0b0',
      muted: '#808080',
      inverse: '#ffffff',
    },
    border: {
      default: '#404040',
      hover: '#505050',
    },
    accent: {
      primary: '#6366f1',
      primaryHover: '#818cf8',
    },
  },

  // ... monokai, dracula, nord, solarized
};
```

### **Settings Store**

```typescript
interface SettingsStore {
  currentTheme: string;
  currentColors: ColorPalette;

  setTheme: (theme: string) => void;
  getThemeStyles: () => object;
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  // Carregar tema do localStorage
  currentTheme: typeof window !== 'undefined'
    ? localStorage.getItem('theme') || 'dark'
    : 'dark',

  // Paleta ativa baseada no tema
  currentColors: themes[currentTheme] || themes.dark,

  // Trocar tema
  setTheme: (theme: string) => {
    if (!themes[theme]) return;

    set({
      currentTheme: theme,
      currentColors: themes[theme],
    });

    // Persistir
    if (typeof window !== 'undefined') {
      localStorage.setItem('theme', theme);
    }

    console.log('✅ Theme changed to:', theme);
  },

  // Utilitário para estilos comuns
  getThemeStyles: () => {
    const colors = get().currentColors;
    return {
      card: {
        backgroundColor: colors.bg.primary,
        borderColor: colors.border.default,
        color: colors.text.primary,
      },
      button: {
        backgroundColor: colors.accent.primary,
        color: colors.text.inverse,
      },
      // ... mais estilos
    };
  },
}));
```

### **Aplicação em Componentes**

```typescript
// Exemplo: WidgetCard.tsx

export const WidgetCard: React.FC = ({ widget }) => {
  const { currentColors } = useSettingsStore();

  return (
    <div
      className="rounded-lg shadow-md"
      style={{
        backgroundColor: currentColors.bg.primary,  // ← Cor dinâmica
      }}
    >
      {/* Header */}
      <div
        className="px-4 py-3"
        style={{
          background: `linear-gradient(to right, ${currentColors.accent.primary}, ${currentColors.accent.primaryHover})`,
          color: currentColors.text.inverse,
        }}
      >
        <h3 style={{ color: currentColors.text.inverse }}>
          {widget.title}
        </h3>
      </div>

      {/* Content */}
      <div style={{ color: currentColors.text.primary }}>
        <PlotlyChart
          type={widget.type}
          data={widget.data.results}
        />
      </div>

      {/* Footer */}
      <div
        style={{
          borderColor: currentColors.border.default,
          backgroundColor: currentColors.bg.tertiary,
          color: currentColors.text.muted,
        }}
      >
        <span>{widget.type}</span>
      </div>
    </div>
  );
};
```

### **Tematização de Gráficos Plotly**

```typescript
// PlotlyChart.tsx

export const PlotlyChart: React.FC = ({ type, data, config }) => {
  const { currentColors } = useSettingsStore();

  const layout = {
    title: '',
    autosize: true,

    // Fundo transparente (usa cor do container)
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',

    // Cores do tema
    font: {
      color: currentColors.text.primary,
      size: 12,
    },

    xaxis: {
      gridcolor: currentColors.border.default,
      tickfont: {
        color: currentColors.text.secondary,
      },
    },

    yaxis: {
      gridcolor: currentColors.border.default,
      tickfont: {
        color: currentColors.text.secondary,
      },
    },
  };

  return (
    <Plot
      data={getPlotlyData()}
      layout={layout}
      config={{ responsive: true, displayModeBar: false }}
    />
  );
};
```

---

## 🔌 WebSocket Real-Time

### **Inicialização (Frontend)**

```typescript
// useDashboardStore.ts

initializeWebSocket: () => {
  websocketService.connect();

  // Registrar callbacks
  websocketService.onWidgetAdded((widget) => {
    console.log('📥 Widget added via WebSocket:', widget.id);
    get().addWidget(widget, true);  // skipBroadcast = true (evita loop)
  });

  websocketService.onWidgetUpdated((widget) => {
    console.log('📥 Widget updated via WebSocket');
    set((state) => ({
      widgets: state.widgets.map((w) =>
        w.id === widget.id ? widget : w
      ),
    }));
  });

  websocketService.onWidgetDeleted((widgetId) => {
    console.log('📥 Widget deleted via WebSocket');
    get().removeWidget(widgetId, true);  // skipBroadcast = true
  });

  websocketService.onPositionsUpdated((positions) => {
    console.log('📥 Positions updated via WebSocket');
    get().updateMultiplePositions(positions);
  });

  websocketService.onConnectionChange((connected) => {
    console.log('WebSocket status:', connected);
    set({ isConnected: connected });

    // Rejoin dashboard se reconectou
    if (connected && get().currentDashboard) {
      websocketService.joinDashboard(get().currentDashboard!.id);
    }
  });
},
```

### **Join Dashboard**

```typescript
// websocketService.ts

class WebSocketService {
  private currentDashboard: string | null = null;

  joinDashboard(dashboardId: string) {
    if (this.currentDashboard === dashboardId) {
      console.log('Already in dashboard:', dashboardId);
      return;
    }

    // Leave dashboard anterior
    if (this.currentDashboard) {
      this.leaveDashboard(this.currentDashboard);
    }

    console.log('📥 Joining dashboard:', dashboardId);
    this.socket.emit('join_dashboard', { dashboard_id: dashboardId });
    this.currentDashboard = dashboardId;
  }

  leaveDashboard(dashboardId: string) {
    console.log('📤 Leaving dashboard:', dashboardId);
    this.socket.emit('leave_dashboard', { dashboard_id: dashboardId });
    this.currentDashboard = null;
  }
}
```

### **Backend Socket.IO**

```python
# backend/app/websocket.py

@sio.event
async def join_dashboard(sid: str, data: dict):
    """Cliente entra em um dashboard (room)"""
    dashboard_id = data.get("dashboard_id")

    if not dashboard_id:
        return {"error": "dashboard_id required"}

    # Entrar na room
    sio.enter_room(sid, dashboard_id)

    logger.info(f"Client {sid} joined dashboard {dashboard_id}")

    # Confirmar join
    await sio.emit(
        "dashboard_joined",
        {"dashboard_id": dashboard_id},
        room=sid
    )

    return {"status": "joined", "dashboard_id": dashboard_id}


@sio.event
async def widget_added(sid: str, data: dict):
    """Broadcast widget added para outros clientes"""
    dashboard_id = data.get("dashboard_id")
    widget = data.get("widget")

    if not dashboard_id or not widget:
        return {"error": "dashboard_id and widget required"}

    # Broadcast para TODOS na room EXCETO sender
    await sio.emit(
        "widget_added",
        {"widget": widget},
        room=dashboard_id,
        skip_sid=sid  # ← Não envia para quem criou
    )

    logger.info(f"Widget {widget['id']} broadcast to dashboard {dashboard_id}")

    return {"status": "broadcast"}
```

### **Broadcast ao Salvar Dashboard**

```typescript
// useDashboardStore.ts

saveDashboard: async () => {
  const { currentDashboard, widgets } = get();

  if (!currentDashboard) return;

  try {
    await api.updateDashboard(currentDashboard.id, { widgets });

    console.log('✅ Dashboard saved');

    // Broadcast via WebSocket
    if (websocketService.isConnected()) {
      websocketService.emit('dashboard_updated', {
        dashboard_id: currentDashboard.id,
        widgets: widgets,
      });
    }
  } catch (error) {
    console.error('❌ Error saving:', error);
  }
},
```

---

## ⚡ Otimizações e Performance

### **1. Prevenção de Queries Duplicadas**

```typescript
// WidgetCard.tsx

const hasRecentData =
  widget.data.results &&
  widget.data.last_updated &&
  (Date.now() - new Date(widget.data.last_updated).getTime()) < 5000;

if (hasRecentData) {
  console.log('Widget tem dados recentes (<5s), pulando query');
  return;  // ← Não executa query!
}
```

**Cenários Prevenidos:**
- Widget recém-criado pelo chat
- Widget atualizado por outro usuário via WebSocket
- Múltiplos re-renders do React

### **2. Debouncing de Auto-Save**

```typescript
// useDashboardStore.ts

addWidget: (widget) => {
  set((state) => ({ widgets: [...state.widgets, widget] }));

  // Aguarda 500ms antes de salvar
  setTimeout(() => {
    get().saveDashboard();
  }, 500);
},

updateWidgetPosition: (widgetId, position) => {
  set((state) => ({
    widgets: state.widgets.map((w) =>
      w.id === widgetId ? { ...w, position } : w
    ),
  }));

  // Aguarda 1000ms (drag & drop pode ter múltiplos updates)
  setTimeout(() => {
    get().saveDashboard();
  }, 1000);
},
```

**Benefício:** Reduz requisições de ~100 por minuto para ~1 por minuto durante drag & drop intenso.

### **3. Prevenção de Loop Infinito**

```typescript
// DashboardEditor.tsx

const [isInitialized, setIsInitialized] = useState(false);

useEffect(() => {
  const initializeDashboard = async () => {
    if (!currentDashboard && !isInitialized) {
      setIsInitialized(true);  // ← Marca ANTES de carregar

      const dashboard = await api.getDashboard('example-dashboard');
      setCurrentDashboard(dashboard);
    }
  };

  initializeDashboard();
}, []);  // ← deps vazias - roda apenas no mount
```

**Problema Evitado:** useEffect com `currentDashboard` na deps causava:
```
mount → load → setDashboard → deps change → load again → loop!
```

### **4. Widgets Independentes (Multi-Índice)**

Cada widget mantém seu próprio índice:

```typescript
widget1.index = "vazamentos";
widget2.index = "tickets_jira";
widget3.index = "logs_aplicacao";
```

**Benefícios:**
- ✅ Dashboard com dados de múltiplas fontes
- ✅ Queries sempre no índice correto
- ✅ Não re-executa quando índice global muda
- ✅ Isolamento de contexto

### **5. Batch Updates de Time Range**

```typescript
setTimeRange: (timeRange) => {
  set({ timeRange });

  // Aguarda 100ms para batch múltiplos updates
  setTimeout(() => {
    get().refreshAllWidgets();
  }, 100);
},
```

**Benefício:** Se usuário trocar rapidamente entre períodos, apenas o último é aplicado.

### **6. WebSocket Reconnection**

```typescript
// websocketService.ts

connect() {
  this.socket = io(this.url, {
    transports: ['websocket'],
    reconnection: true,           // ← Auto-reconnect
    reconnectionDelay: 1000,      // Aguarda 1s
    reconnectionAttempts: 5,      // Tenta 5 vezes
  });

  this.socket.on('connect', () => {
    console.log('✅ WebSocket connected');
    this.isConnected = true;

    // Re-join dashboard
    if (this.currentDashboard) {
      this.joinDashboard(this.currentDashboard);
    }
  });
}
```

**Benefício:** Mantém sincronização mesmo com quedas temporárias de conexão.

### **7. Lazy Loading de Índices**

```typescript
// IndexSelector.tsx

useEffect(() => {
  const loadIndices = async () => {
    if (!serverId) return;  // ← Não carrega se não tem servidor

    setLoading(true);
    const indices = await api.getIndices(serverId);
    setIndices(indices);
    setLoading(false);
  };

  loadIndices();
}, [serverId]);  // ← Carrega apenas quando servidor muda
```

**Benefício:** Não lista todos os índices de todos os servidores ao iniciar.

---

## 🐛 Problemas Resolvidos Durante Desenvolvimento

### **Problema 1: Widgets Vazios Após Reload**

**Sintoma:** Widgets carregavam do PostgreSQL mas ficavam sem dados.

**Causa:** Query retornando 0 resultados porque:
1. Widget não tinha `last_updated`
2. Query executava com timeRange incorreto

**Solução:**
- Adicionar `last_updated` ao criar widget
- Não enviar `timeRange` na API (query já tem range)

### **Problema 2: Loop Infinito de Reloads**

**Sintoma:** Dashboard carregava 4x, widgets re-executavam múltiplas vezes.

**Causa:** useEffect com `currentDashboard` nas deps:
```typescript
useEffect(() => {
  load(); → setDashboard → deps change → load again!
}, [currentDashboard]);
```

**Solução:**
- Flag `isInitialized`
- Deps vazias: `[]`
- Guard duplo: `if (!dashboard && !isInitialized)`

### **Problema 3: Widgets Perdiam Dados ao Salvar**

**Sintoma:** Após clicar "Salvar", widgets ficavam vazios.

**Causa:** Dashboard salvo no PostgreSQL não tinha `results`, só `config`.

**Solução:**
- `refreshAllWidgets()` após salvar
- Re-executa queries e recarrega dados

### **Problema 4: Gráficos Ilegíveis em Temas Escuros**

**Sintoma:** Texto preto em fundo preto.

**Causa:** PlotlyChart usava cores hardcoded.

**Solução:**
- Integrar `useSettingsStore` no PlotlyChart
- Aplicar `currentColors` em todos elementos
- Grid, texto, labels com cores do tema

### **Problema 5: Timestamps Como Números no Eixo X**

**Sintoma:** Eixo X mostrava `1730937600000` em vez de datas.

**Causa:** Backend retornava timestamps em ms.

**Solução:**
- Função `formatLabel()` detecta timestamps
- Converte para data legível: `"07/11/2025"`
- Aplica em todos tipos de gráfico

---

## 📚 Referências Técnicas

### **Frontend**
- React 18 (Hooks, Suspense)
- TypeScript 5
- Zustand (state management)
- React Router v6
- Plotly.js + react-plotly.js
- Socket.IO Client
- Tailwind CSS
- Vite (build tool)

### **Backend**
- FastAPI 0.104+
- SQLAlchemy 2.0 (async)
- Alembic (migrations)
- Socket.IO (WebSocket)
- Elasticsearch Python Client
- Anthropic SDK
- OpenAI SDK
- Cryptography (Fernet)

### **Database**
- PostgreSQL 14+ (JSONB support)
- Elasticsearch 8+

### **Padrões Arquiteturais**
- Service Layer Pattern
- Repository Pattern
- Factory Pattern (LLM)
- Observer Pattern (WebSocket)
- Strategy Pattern (Themes)

---

**Versão**: 2.0.0
**Última Atualização**: 2025-11-07
**Autores**: Dashboard AI Team + Claude Code
