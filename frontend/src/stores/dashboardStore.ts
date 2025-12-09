/**
 * Dashboard Store (Zustand)
 * Gerencia estado global do dashboard
 */

import { create } from 'zustand';
import type { Dashboard, Widget, WidgetPosition } from '@types/index';
import { api } from '@services/api';
import { websocketService } from '@services/websocket';

export interface TimeRange {
  type: 'preset' | 'custom';
  preset?: string;
  from?: string;
  to?: string;
  label: string;
}

interface DashboardStore {
  // Estado
  currentDashboard: Dashboard | null;
  widgets: Widget[];
  isLoading: boolean;
  error: string | null;
  isConnected: boolean;
  selectedServerId: string | null;
  selectedIndex: string | null;
  isChatOpen: boolean;
  timeRange: TimeRange;

  // Actions
  setCurrentDashboard: (dashboard: Dashboard) => void;
  addWidget: (widget: Widget, skipBroadcast?: boolean) => void;
  updateWidget: (widgetId: string, updates: Partial<Widget>) => void;
  updateWidgetPosition: (widgetId: string, position: WidgetPosition, skipBroadcast?: boolean) => void;
  updateMultiplePositions: (positions: Record<string, WidgetPosition>) => void;
  removeWidget: (widgetId: string, skipBroadcast?: boolean) => void;
  loadDashboard: (dashboardId: string) => Promise<void>;
  saveDashboard: () => Promise<void>;
  clearError: () => void;
  initializeWebSocket: () => void;
  disconnectWebSocket: () => void;
  setConnectionStatus: (connected: boolean) => void;
  setSelectedServer: (serverId: string) => void;
  setSelectedIndex: (index: string) => void;
  toggleChat: () => void;
  setTimeRange: (timeRange: TimeRange) => void;
  updateWidgetData: (widgetId: string, data: any) => void;
  refreshAllWidgets: () => Promise<void>;
}

export const useDashboardStore = create<DashboardStore>((set, get) => ({
  // Estado inicial
  currentDashboard: null,
  widgets: [],
  isLoading: false,
  error: null,
  isConnected: false,
  selectedServerId: null,
  selectedIndex: null,
  isChatOpen: typeof window !== 'undefined' ? localStorage.getItem('chatOpen') !== 'false' : true,
  timeRange: {
    type: 'preset',
    preset: 'now-30d',
    from: 'now-30d',
    to: 'now',
    label: 'Últimos 30 dias',
  },

  // Setar dashboard atual
  setCurrentDashboard: (dashboard) => {
    set({
      currentDashboard: dashboard,
      widgets: dashboard.widgets || [],
    });

    // Join dashboard via WebSocket
    if (websocketService.isConnected()) {
      websocketService.joinDashboard(dashboard.id);
    }
  },

  // Adicionar widget
  addWidget: (widget, skipBroadcast = false) => {
    set((state) => ({
      widgets: [...state.widgets, widget],
    }));

    // Auto-save após adicionar (que fará broadcast automaticamente)
    if (!skipBroadcast) {
      setTimeout(() => {
        get().saveDashboard();
      }, 500);
    }
  },

  // Atualizar widget (título, configurações, etc)
  updateWidget: (widgetId, updates) => {
    set((state) => ({
      widgets: state.widgets.map((w) =>
        w.id === widgetId
          ? { ...w, ...updates, metadata: { ...w.metadata, updated_at: new Date().toISOString() } }
          : w
      ),
    }));

    // Auto-save após atualizar (que fará broadcast automaticamente)
    setTimeout(() => {
      get().saveDashboard();
    }, 500);
  },

  // Atualizar posição do widget (drag-and-drop)
  updateWidgetPosition: (widgetId, position, skipBroadcast = false) => {
    set((state) => ({
      widgets: state.widgets.map((w) =>
        w.id === widgetId
          ? { ...w, position, metadata: { ...w.metadata, updated_at: new Date().toISOString() } }
          : w
      ),
    }));

    // Auto-save com debounce (que fará broadcast automaticamente)
    if (!skipBroadcast) {
      setTimeout(() => {
        get().saveDashboard();
      }, 1000);
    }
  },

  // Atualizar múltiplas posições de uma vez (recebido via WebSocket)
  updateMultiplePositions: (positions) => {
    set((state) => ({
      widgets: state.widgets.map((w) =>
        positions[w.id]
          ? { ...w, position: positions[w.id], metadata: { ...w.metadata, updated_at: new Date().toISOString() } }
          : w
      ),
    }));
  },

  // Remover widget
  removeWidget: (widgetId, skipBroadcast = false) => {
    set((state) => ({
      widgets: state.widgets.filter((w) => w.id !== widgetId),
    }));

    // Auto-save após remover (que fará broadcast automaticamente)
    if (!skipBroadcast) {
      setTimeout(() => {
        get().saveDashboard();
      }, 500);
    }
  },

  // Carregar dashboard
  loadDashboard: async (dashboardId) => {
    set({ isLoading: true, error: null });

    try {
      const dashboard = await api.getDashboard(dashboardId);
      set({
        currentDashboard: dashboard,
        widgets: dashboard.widgets || [],
        isLoading: false,
      });
    } catch (error: any) {
      set({
        error: error.message || 'Erro ao carregar dashboard',
        isLoading: false,
      });
    }
  },

  // Salvar dashboard
  saveDashboard: async () => {
    const { currentDashboard, widgets } = get();

    if (!currentDashboard) {
      console.warn('No dashboard to save');
      return;
    }

    try {
      await api.updateDashboard(currentDashboard.id, {
        widgets,
      });
      console.log('Dashboard saved successfully');
    } catch (error: any) {
      console.error('Error saving dashboard:', error);
      set({ error: error.message || 'Erro ao salvar dashboard' });
    }
  },

  // Limpar erro
  clearError: () => set({ error: null }),

  // Inicializar WebSocket e registrar callbacks
  initializeWebSocket: () => {
    websocketService.connect();

    // Registrar callbacks
    websocketService.onWidgetAdded((widget) => {
      console.log('📥 Received widget added via WebSocket:', widget.id);
      get().addWidget(widget, true); // skipBroadcast = true para evitar loop
    });

    websocketService.onWidgetUpdated((widget) => {
      console.log('📥 Received widget updated via WebSocket:', widget.id);
      // Atualizar widget no estado
      set((state) => ({
        widgets: state.widgets.map((w) => (w.id === widget.id ? widget : w)),
      }));
    });

    websocketService.onWidgetDeleted((widgetId) => {
      console.log('📥 Received widget deleted via WebSocket:', widgetId);
      get().removeWidget(widgetId, true); // skipBroadcast = true para evitar loop
    });

    websocketService.onPositionsUpdated((positions) => {
      console.log('📥 Received positions updated via WebSocket');
      get().updateMultiplePositions(positions);
    });

    websocketService.onConnectionChange((connected) => {
      console.log('WebSocket connection status:', connected);
      set({ isConnected: connected });

      // Se reconectou, rejoin dashboard
      if (connected && get().currentDashboard) {
        websocketService.joinDashboard(get().currentDashboard!.id);
      }
    });
  },

  // Desconectar WebSocket
  disconnectWebSocket: () => {
    websocketService.disconnect();
    set({ isConnected: false });
  },

  // Atualizar status de conexão
  setConnectionStatus: (connected) => {
    set({ isConnected: connected });
  },

  // Definir servidor selecionado
  setSelectedServer: (serverId) => {
    set({ selectedServerId: serverId });
    console.log('Selected ES Server:', serverId);
  },

  // Definir índice selecionado
  setSelectedIndex: (index) => {
    set({ selectedIndex: index });
    console.log('Selected Index:', index);
  },

  // Toggle chat visibility
  toggleChat: () => {
    const newState = !get().isChatOpen;
    set({ isChatOpen: newState });
    if (typeof window !== 'undefined') {
      localStorage.setItem('chatOpen', String(newState));
    }
    console.log('Chat toggled:', newState);
  },

  // Definir time range
  setTimeRange: (timeRange) => {
    set({ timeRange });
    console.log('🕒 Time range updated:', timeRange);
    console.log('📊 Will refresh', get().widgets.length, 'widgets in 100ms');

    // Atualizar todos os widgets com o novo período
    setTimeout(() => {
      console.log('⏰ Timeout triggered, calling refreshAllWidgets...');
      get().refreshAllWidgets();
    }, 100);
  },

  // Atualizar dados de um widget específico
  updateWidgetData: (widgetId, data) => {
    console.log(`📝 updateWidgetData called for ${widgetId}:`, data);
    set((state) => ({
      widgets: state.widgets.map((w) =>
        w.id === widgetId
          ? {
              ...w,
              data: { ...w.data, ...data },
              metadata: { ...w.metadata, updated_at: new Date().toISOString() }
            }
          : w
      ),
    }));
    console.log(`✅ Widget ${widgetId} data updated in store`);
  },

  // Refresh todos os widgets re-executando suas queries
  refreshAllWidgets: async () => {
    const { widgets, selectedIndex, selectedServerId, timeRange } = get();

    console.log('🔄 refreshAllWidgets called!');
    console.log('  - Widgets count:', widgets.length);
    console.log('  - Selected index:', selectedIndex);
    console.log('  - Time range:', timeRange);

    if (!selectedIndex) {
      console.warn('⚠️ No index selected, skipping widget refresh');
      return;
    }

    console.log(`🔄 Starting refresh of ${widgets.length} widgets with new time range:`, timeRange);

    // Re-executar query de cada widget
    for (const widget of widgets) {
      console.log(`\n🔍 Processing widget ${widget.id}:`);
      console.log('  - Title:', widget.title);
      console.log('  - Has query?', !!widget.data?.query);

      if (widget.data?.query) {
        try {
          // Usar índice do widget (prioritário) ou índice global
          const indexToUse = widget.index || selectedIndex;

          if (!indexToUse) {
            console.warn(`  ⚠️ Widget ${widget.id} has no index, skipping`);
            continue;
          }

          console.log(`  ✨ Refreshing widget ${widget.id} (${widget.title})...`);
          console.log('  - Original Query:', JSON.stringify(widget.data.query, null, 2));
          console.log('  - Index to use:', indexToUse, widget.index ? '(from widget)' : '(global)');
          console.log('  - Server:', selectedServerId);
          console.log('  - Time range:', timeRange);

          // Criar cópia da query para atualizar localmente
          const updatedQuery = JSON.parse(JSON.stringify(widget.data.query));

          // Atualizar filtro temporal na query local antes de enviar
          // Procurar em filter E must (queries podem ter range em qualquer um)
          const updateRangeInArray = (arr: any[]) => {
            for (const item of arr) {
              if (item.range) {
                const dateField = Object.keys(item.range)[0];
                if (dateField) {
                  console.log(`  🔧 Updating ${dateField} filter: ${timeRange.from} to ${timeRange.to}`);
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

          console.log('  - Updated Query:', JSON.stringify(updatedQuery, null, 2));

          // Executar query atualizada com novo time range no índice correto
          // NÃO enviar timeRange porque a query já foi atualizada com os valores corretos
          const result = await api.executeQuery(
            indexToUse,
            updatedQuery,
            selectedServerId || undefined,
            undefined  // Não enviar timeRange - a query já tem os valores corretos
          );

          console.log('  - Result:', result);
          console.log('  - Result data type:', typeof result.data, Array.isArray(result.data));
          console.log('  - Result data sample:', result.data?.slice(0, 2));

          // Atualizar dados do widget com query atualizada E config
          // Preservar estrutura do config original, atualizando apenas os dados
          const currentConfig = widget.data.config || {};
          console.log('  🔍 Current config before update:', currentConfig);
          console.log('  🔍 Result.data:', result.data);
          console.log('  🔍 Result.data length:', result.data?.length);
          console.log('  🔍 Result.data sample:', result.data?.slice(0, 2));

          const newConfig = {
            ...currentConfig,  // Preservar colors, layout, plotly
            data: result.data  // Atualizar apenas os dados formatados {label, value}
          };
          console.log('  🔍 New config:', newConfig);

          get().updateWidgetData(widget.id, {
            query: updatedQuery,  // Salvar query atualizada
            results: result,
            config: newConfig,
            last_updated: new Date().toISOString(),
          });

          console.log(`  ✅ Widget ${widget.id} refreshed successfully on index: ${indexToUse}`);
        } catch (error) {
          console.error(`  ❌ Error refreshing widget ${widget.id}:`, error);
        }
      } else {
        console.log(`  ⏭️ Widget ${widget.id} has no query, skipping`);
      }
    }

    console.log('\n✅ All widgets refresh completed');
  },
}));
