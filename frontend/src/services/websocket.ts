/**
 * WebSocket Service
 * Gerencia conexão Socket.IO para sincronização real-time
 */

import { io, Socket } from 'socket.io-client';
import { Widget, WidgetPosition } from '../types/widget';

const SOCKET_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';

class WebSocketService {
  private socket: Socket | null = null;
  private currentDashboard: string | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  // Callbacks
  private onWidgetAddedCallback?: (widget: Widget) => void;
  private onWidgetUpdatedCallback?: (widget: Widget) => void;
  private onWidgetDeletedCallback?: (widgetId: string) => void;
  private onPositionsUpdatedCallback?: (positions: Record<string, WidgetPosition>) => void;
  private onConnectionChangeCallback?: (connected: boolean) => void;

  /**
   * Conecta ao WebSocket server
   */
  connect() {
    if (this.socket?.connected) {
      console.log('WebSocket already connected');
      return;
    }

    console.log('🔌 Connecting to WebSocket:', SOCKET_URL);

    this.socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: this.maxReconnectAttempts,
    });

    this.setupEventListeners();
  }

  /**
   * Desconecta do WebSocket server
   */
  disconnect() {
    if (this.socket) {
      console.log('🔌 Disconnecting from WebSocket');
      this.socket.disconnect();
      this.socket = null;
      this.currentDashboard = null;
    }
  }

  /**
   * Entra em um dashboard específico
   */
  joinDashboard(dashboardId: string) {
    if (!this.socket?.connected) {
      console.warn('WebSocket not connected, cannot join dashboard');
      return;
    }

    if (this.currentDashboard === dashboardId) {
      console.log('Already in dashboard:', dashboardId);
      return;
    }

    // Sair do dashboard anterior se houver
    if (this.currentDashboard) {
      this.leaveDashboard();
    }

    console.log('📥 Joining dashboard:', dashboardId);
    this.socket.emit('join_dashboard', { dashboard_id: dashboardId });
    this.currentDashboard = dashboardId;
  }

  /**
   * Sai do dashboard atual
   */
  leaveDashboard() {
    if (!this.socket?.connected || !this.currentDashboard) {
      return;
    }

    console.log('📤 Leaving dashboard:', this.currentDashboard);
    this.socket.emit('leave_dashboard', { dashboard_id: this.currentDashboard });
    this.currentDashboard = null;
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners() {
    if (!this.socket) return;

    // Conexão estabelecida
    this.socket.on('connect', () => {
      console.log('✅ WebSocket connected:', this.socket?.id);
      this.reconnectAttempts = 0;
      this.onConnectionChangeCallback?.(true);

      // Re-join dashboard se estava em um
      if (this.currentDashboard) {
        const dashboardId = this.currentDashboard;
        this.currentDashboard = null; // Reset para forçar rejoin
        this.joinDashboard(dashboardId);
      }
    });

    // Desconectado
    this.socket.on('disconnect', (reason) => {
      console.log('❌ WebSocket disconnected:', reason);
      this.onConnectionChangeCallback?.(false);
    });

    // Erro de conexão
    this.socket.on('connect_error', (error) => {
      this.reconnectAttempts++;
      console.error('❌ WebSocket connection error:', error.message);

      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error('Max reconnection attempts reached');
        this.onConnectionChangeCallback?.(false);
      }
    });

    // Confirmação de entrada no dashboard
    this.socket.on('joined', (data: { dashboard_id: string }) => {
      console.log('✅ Joined dashboard:', data.dashboard_id);
    });

    // Widget adicionado
    this.socket.on('widget:added', (data: { widget: Widget }) => {
      console.log('🆕 Widget added:', data.widget.id);
      this.onWidgetAddedCallback?.(data.widget);
    });

    // Widget atualizado
    this.socket.on('widget:updated', (data: { widget: Widget }) => {
      console.log('✏️ Widget updated:', data.widget.id);
      this.onWidgetUpdatedCallback?.(data.widget);
    });

    // Widget deletado
    this.socket.on('widget:deleted', (data: { widget_id: string }) => {
      console.log('🗑️ Widget deleted:', data.widget_id);
      this.onWidgetDeletedCallback?.(data.widget_id);
    });

    // Posições atualizadas
    this.socket.on('positions:updated', (data: { positions: Record<string, WidgetPosition> }) => {
      console.log('📐 Positions updated:', Object.keys(data.positions).length, 'widgets');
      this.onPositionsUpdatedCallback?.(data.positions);
    });
  }

  /**
   * Registra callback para widget adicionado
   */
  onWidgetAdded(callback: (widget: Widget) => void) {
    this.onWidgetAddedCallback = callback;
  }

  /**
   * Registra callback para widget atualizado
   */
  onWidgetUpdated(callback: (widget: Widget) => void) {
    this.onWidgetUpdatedCallback = callback;
  }

  /**
   * Registra callback para widget deletado
   */
  onWidgetDeleted(callback: (widgetId: string) => void) {
    this.onWidgetDeletedCallback = callback;
  }

  /**
   * Registra callback para posições atualizadas
   */
  onPositionsUpdated(callback: (positions: Record<string, WidgetPosition>) => void) {
    this.onPositionsUpdatedCallback = callback;
  }

  /**
   * Registra callback para mudança de status de conexão
   */
  onConnectionChange(callback: (connected: boolean) => void) {
    this.onConnectionChangeCallback = callback;
  }

  /**
   * Verifica se está conectado
   */
  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }

  /**
   * Retorna o ID do dashboard atual
   */
  getCurrentDashboard(): string | null {
    return this.currentDashboard;
  }
}

// Singleton instance
export const websocketService = new WebSocketService();
