/**
 * ChatPage - Página dedicada para chat com IA
 * Permite conversas contextuais com visualizações inline
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '@services/api';
import { useDashboardStore } from '@stores/dashboardStore';
import { useSettingsStore } from '@stores/settingsStore';
import { useUserStore } from '@stores/userStore';
import { PlotlyChart } from '@components/PlotlyChart';
import { ESServerSelector } from '@components/ESServerSelector';
import { IndexSelector } from '@components/IndexSelector';
import { IndexFieldsViewer } from '@components/IndexFieldsViewer';
import { TimeRangePicker } from '@components/TimeRangePicker';
import { LLMProviderIndicator } from '@components/LLMProviderIndicator';
import { KnowledgeService } from '@services/knowledgeService';
import type { VisualizationType } from '@types/widget';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  widget?: {
    title: string;
    type: VisualizationType;
    data: any;
  };
}

interface Conversation {
  id: string;
  title: string;
  index: string;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
}

export const ChatPage: React.FC = () => {
  const {
    selectedServerId,
    setSelectedServer,
    selectedIndex,
    setSelectedIndex,
    timeRange,
    setTimeRange,
    addWidget,
    currentDashboard,
    loadDashboard,
  } = useDashboardStore();
  const { currentColors } = useSettingsStore();
  const { userId } = useUserStore();

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const navigate = useNavigate();
  const [currentConversation, setCurrentConversation] = useState<Conversation | null>(null);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Dashboard selector state
  const [availableDashboards, setAvailableDashboards] = useState<any[]>([]);
  const [selectedDashboardId, setSelectedDashboardId] = useState<string>('');

  // Carregar dashboards disponíveis ao montar componente
  useEffect(() => {
    const fetchDashboards = async () => {
      try {
        const dashboards = await api.listDashboards();
        console.log('📊 Available dashboards:', dashboards);
        setAvailableDashboards(dashboards);
        // Auto-select first dashboard
        if (dashboards.length > 0 && !selectedDashboardId) {
          setSelectedDashboardId(dashboards[0].id);
          console.log('📌 Auto-selected dashboard:', dashboards[0].title);
        }
      } catch (error) {
        console.error('❌ Error fetching dashboards:', error);
      }
    };

    fetchDashboards();
  }, []);

  // Carregar conversas ao montar componente ou quando índice mudar
  useEffect(() => {
    if (selectedIndex) {
      loadConversations();
    }
  }, [selectedIndex]);

  // Auto-scroll para última mensagem
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [currentConversation?.messages]);

  // Carregar conversas do backend
  const loadConversations = async () => {
    try {
      const data = await api.listConversations({
        created_by: userId,  // Filtrar por usuário
        limit: 50,
      });

      // Mapear para o formato local
      const mappedConversations: Conversation[] = data.map((conv: any) => ({
        id: conv.id,
        title: conv.title,
        index: conv.index,
        createdAt: conv.created_at,
        updatedAt: conv.updated_at,
        messages: [], // Mensagens serão carregadas ao abrir conversa
      }));

      setConversations(mappedConversations);
    } catch (error: any) {
      console.error('Erro ao carregar conversas:', error);
    }
  };

  // Carregar conversa completa (com mensagens)
  const loadConversation = async (conversationId: string) => {
    try {
      setIsLoading(true);
      const data = await api.getConversation(conversationId);

      // Mapear para formato local
      const conversation: Conversation = {
        id: data.id,
        title: data.title,
        index: data.index,
        createdAt: data.created_at,
        updatedAt: data.updated_at,
        messages: data.messages.map((msg: any) => ({
          id: msg.id,
          role: msg.role,
          content: msg.content,
          timestamp: msg.timestamp,
          widget: msg.widget,
        })),
      };

      setCurrentConversation(conversation);
    } catch (error: any) {
      alert(`Erro ao carregar conversa: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Criar nova conversa
  const createNewConversation = async () => {
    if (!selectedIndex) {
      alert('Por favor, selecione um índice primeiro');
      return;
    }

    try {
      setIsLoading(true);

      // Criar conversa no backend (já vem com mensagem inicial)
      const data = await api.createConversation({
        title: `Conversa sobre ${selectedIndex}`,
        index: selectedIndex,
        server_id: selectedServerId || undefined,
        created_by: userId,  // Associar ao usuário
      });

      // Mapear para formato local
      const newConversation: Conversation = {
        id: data.id,
        title: data.title,
        index: data.index,
        createdAt: data.created_at,
        updatedAt: data.updated_at,
        messages: data.messages.map((msg: any) => ({
          id: msg.id,
          role: msg.role,
          content: msg.content,
          timestamp: msg.timestamp,
          widget: msg.widget,
        })),
      };

      setConversations([newConversation, ...conversations]);
      setCurrentConversation(newConversation);
    } catch (error: any) {
      alert(`Erro ao criar conversa: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Deletar conversa
  const handleDeleteConversation = async (conversationId: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Evita que o clique dispare o loadConversation

    if (!confirm('Tem certeza que deseja excluir esta conversa?')) {
      return;
    }

    try {
      await api.deleteConversation(conversationId);

      // Remover da lista
      setConversations((prev) => prev.filter((conv) => conv.id !== conversationId));

      // Se era a conversa atual, limpar
      if (currentConversation?.id === conversationId) {
        setCurrentConversation(null);
      }
    } catch (error: any) {
      alert(`Erro ao excluir conversa: ${error.message}`);
    }
  };

  // Enviar mensagem
  const handleSendMessage = async () => {
    if (!input.trim() || isLoading || !currentConversation || !selectedIndex) return;

    const userMessageContent = input;

    // Adicionar mensagem do usuário localmente (otimistic update)
    const tempUserMessage: ChatMessage = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content: userMessageContent,
      timestamp: new Date().toISOString(),
    };

    const updatedConversation = {
      ...currentConversation,
      messages: [...currentConversation.messages, tempUserMessage],
      updatedAt: new Date().toISOString(),
    };
    setCurrentConversation(updatedConversation);
    setInput('');
    setIsLoading(true);

    try {
      // 1. Salvar mensagem do usuário no backend
      const userSaved = await api.addMessageToConversation(currentConversation.id, {
        role: 'user',
        content: userMessageContent,
      });

      // 2. Buscar contexto do Knowledge Base
      const knowledgeContext = await KnowledgeService.buildContext(
        userMessageContent,
        selectedIndex
      );

      // 3. Montar mensagem completa com contexto
      const enrichedMessage = knowledgeContext
        ? `${knowledgeContext}\n\n---\n\nUser Question: ${userMessageContent}`
        : userMessageContent;

      // 4. Chamar API do chat com contexto enriquecido
      const response = await api.chat({
        message: enrichedMessage,
        index: selectedIndex,
        server_id: selectedServerId || undefined,
        time_range: timeRange,
        context: currentConversation.messages.slice(-10), // Últimas 10 mensagens
      });

      // 5. Salvar resposta do assistente no backend com widget completo
      const assistantWidget = response.widget
        ? {
            title: response.widget.title,
            type: response.widget.type,
            query: response.query || {}, // Salvar query completa!
            data: response.widget.data, // Salvar dados completos!
            config: response.widget.data?.config || {},
          }
        : undefined;

      const assistantSaved = await api.addMessageToConversation(currentConversation.id, {
        role: 'assistant',
        content: response.explanation,
        widget: assistantWidget,
      });

      // 6. Atualizar estado local com dados salvos
      const finalMessages = assistantSaved.messages.map((msg: any) => {
        return {
          id: msg.id,
          role: msg.role,
          content: msg.content,
          timestamp: msg.timestamp,
          widget: msg.widget,
        };
      });

      const finalConversation: Conversation = {
        ...currentConversation,
        messages: finalMessages,
        updatedAt: assistantSaved.updated_at,
      };

      setCurrentConversation(finalConversation);

      // Atualizar na lista de conversas
      setConversations((prev) =>
        prev.map((conv) => (conv.id === finalConversation.id ? finalConversation : conv))
      );
    } catch (error: any) {
      const errorMessage: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: `❌ Erro: ${error.message || 'Não foi possível processar sua mensagem'}`,
        timestamp: new Date().toISOString(),
      };

      const errorConversation = {
        ...updatedConversation,
        messages: [...updatedConversation.messages, errorMessage],
      };
      setCurrentConversation(errorConversation);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Adicionar widget do chat ao dashboard
  const handleAddToDashboard = useCallback(async (widget: any, fixTimeRange: boolean = false) => {
    try {
      // Verificar se tem dashboard selecionado
      if (!selectedDashboardId || selectedDashboardId === '') {
        alert('⚠️ Por favor, selecione um dashboard de destino antes de adicionar widgets.');
        return;
      }

      console.log('🎯 Adding widget to dashboard:', selectedDashboardId);
      console.log('🔒 Fix time range:', fixTimeRange);

      // Buscar dashboard atual para pegar os widgets existentes
      const dashboard = await api.getDashboard(selectedDashboardId);
      console.log('📋 Dashboard fetched:', dashboard.title, 'with', dashboard.widgets?.length || 0, 'widgets');

      // Calcular próxima posição livre
      const existingWidgets = dashboard.widgets || [];
      const cols = 12;
      const widgetWidth = 6;
      const widgetHeight = 4;

      let x = 0;
      let y = 0;

      if (existingWidgets.length > 0) {
        const lastWidget = existingWidgets[existingWidgets.length - 1];
        x = (lastWidget.position.x + lastWidget.position.w) % cols;
        y = lastWidget.position.y + Math.floor((lastWidget.position.x + lastWidget.position.w) / cols) * widgetHeight;
      }

      // Criar novo widget
      const newWidget = {
        id: `widget-${Date.now()}`,
        title: widget.title,
        type: widget.type,
        position: { x, y, w: widgetWidth, h: widgetHeight },
        data: {
          query: widget.query || {},
          config: widget.data?.config || widget.config || {},
          results: widget.data || {},
          last_updated: new Date().toISOString(),
        },
        index: currentConversation?.index || selectedIndex || '',
        ...(fixTimeRange && { fixedTimeRange: timeRange }),  // Adicionar fixedTimeRange se solicitado
        metadata: {
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          version: 1,
        },
      };

      console.log('✅ Widget created:', newWidget.title);

      // Atualizar dashboard com novo widget
      await api.updateDashboard(selectedDashboardId, {
        widgets: [...existingWidgets, newWidget],
      });

      console.log('💾 Dashboard updated successfully');

      const fixMessage = fixTimeRange ? ` (com time range fixado: ${timeRange.label})` : '';
      alert(`✅ Widget "${widget.title}" adicionado ao dashboard "${dashboard.title}"!${fixMessage}`);
    } catch (error: any) {
      console.error('❌ Error adding widget:', error);
      alert(`❌ Erro ao adicionar widget: ${error.message}`);
    }
  }, [selectedDashboardId, currentConversation?.index, selectedIndex, timeRange]);

  return (
    <div className="h-full flex flex-col overflow-x-hidden" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <header className="border-b flex-shrink-0" style={{
        backgroundColor: currentColors.bg.primary,
        borderColor: currentColors.border.default
      }}>
        <div className="px-6 py-4">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-4">
              {/* Botão Voltar */}
              <button
                onClick={() => navigate('/')}
                className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
                style={{
                  color: currentColors.text.secondary,
                  backgroundColor: 'transparent'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                  e.currentTarget.style.color = currentColors.text.primary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = currentColors.text.secondary;
                }}
                title="Voltar ao menu"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
                <span className="font-medium">Menu</span>
              </button>

              <div className="h-8 w-px" style={{ backgroundColor: currentColors.border.default }}></div>

              <h1 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>Chat com IA</h1>
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              {/* Elasticsearch Server */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>Servidor:</label>
                <ESServerSelector
                  selectedServerId={selectedServerId}
                  onServerChange={setSelectedServer}
                />
              </div>

              {/* Index Selector */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>Índice:</label>
                <IndexSelector
                  serverId={selectedServerId}
                  selectedIndex={selectedIndex}
                  onIndexChange={setSelectedIndex}
                />
              </div>

              {/* Index Fields */}
              {selectedIndex && (
                <IndexFieldsViewer serverId={selectedServerId} indexName={selectedIndex} />
              )}

              {/* Time Range */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>Período:</label>
                <TimeRangePicker value={timeRange} onChange={setTimeRange} />
              </div>

              {/* Dashboard Selector */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>📊 Dashboard:</label>
                <select
                  value={selectedDashboardId}
                  onChange={(e) => setSelectedDashboardId(e.target.value)}
                  className="px-3 py-1.5 rounded-lg border text-sm transition-colors"
                  style={{
                    backgroundColor: currentColors.bg.primary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <option value="">Selecione...</option>
                  {availableDashboards.map((dash) => (
                    <option key={dash.id} value={dash.id}>
                      {dash.title}
                    </option>
                  ))}
                </select>
              </div>

              {/* Separador */}
              <div className="h-8 w-px" style={{ backgroundColor: currentColors.border.default }}></div>

              {/* LLM Provider Indicator */}
              <LLMProviderIndicator compact />

              <div className="h-8 w-px" style={{ backgroundColor: currentColors.border.default }}></div>

              {/* Nova Conversa */}
              <button
                onClick={createNewConversation}
                disabled={!selectedIndex}
                className="px-4 py-2 rounded-lg transition-colors disabled:cursor-not-allowed flex items-center gap-2"
                style={{
                  backgroundColor: !selectedIndex ? currentColors.bg.hover : currentColors.accent.primary,
                  color: currentColors.text.inverse
                }}
                onMouseEnter={(e) => {
                  if (selectedIndex) {
                    e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                  }
                }}
                onMouseLeave={(e) => {
                  if (selectedIndex) {
                    e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                  }
                }}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 4v16m8-8H4"
                  />
                </svg>
                Nova Conversa
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar - Histórico de Conversas */}
        <aside
          className={`border-r flex-shrink-0 transition-all duration-300 ${
            isSidebarOpen ? 'w-80' : 'w-0'
          } overflow-hidden`}
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default
          }}
        >
          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold uppercase" style={{ color: currentColors.text.secondary }}>Conversas</h2>
              <button
                onClick={() => setIsSidebarOpen(false)}
                style={{
                  color: currentColors.text.muted,
                  backgroundColor: 'transparent'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = currentColors.text.secondary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = currentColors.text.muted;
                }}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>

            {/* Lista de Conversas */}
            <div className="space-y-2">
              {conversations.length === 0 ? (
                <div className="text-center py-8 text-sm" style={{ color: currentColors.text.muted }}>
                  <p>Nenhuma conversa ainda</p>
                  <p className="mt-2">Clique em "Nova Conversa" para começar</p>
                </div>
              ) : (
                conversations.map((conv) => (
                  <div
                    key={conv.id}
                    className="relative group rounded-lg transition-colors border-2"
                    style={{
                      backgroundColor: currentConversation?.id === conv.id ? currentColors.bg.tertiary : currentColors.bg.secondary,
                      borderColor: currentConversation?.id === conv.id ? currentColors.accent.primary : 'transparent'
                    }}
                    onMouseEnter={(e) => {
                      if (currentConversation?.id !== conv.id) {
                        e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (currentConversation?.id !== conv.id) {
                        e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
                      }
                    }}
                  >
                    <button
                      onClick={() => loadConversation(conv.id)}
                      className="w-full text-left p-3"
                    >
                      <div className="font-medium text-sm truncate pr-8" style={{ color: currentColors.text.primary }}>
                        {conv.title}
                      </div>
                      <div className="text-xs mt-1" style={{ color: currentColors.text.secondary }}>
                        {conv.messages.length} mensagens
                      </div>
                      <div className="text-xs mt-1" style={{ color: currentColors.text.muted }}>
                        {new Date(conv.updatedAt).toLocaleString('pt-BR', {
                          day: '2-digit',
                          month: 'short',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </button>
                    {/* Botão de Excluir */}
                    <button
                      onClick={(e) => handleDeleteConversation(conv.id, e)}
                      className="absolute top-2 right-2 p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                      style={{
                        color: currentColors.text.muted,
                        backgroundColor: 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                        e.currentTarget.style.color = currentColors.accent.error;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'transparent';
                        e.currentTarget.style.color = currentColors.text.muted;
                      }}
                      title="Excluir conversa"
                    >
                      <svg
                        className="w-4 h-4"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                        />
                      </svg>
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </aside>

        {/* Toggle Sidebar Button */}
        {!isSidebarOpen && (
          <button
            onClick={() => setIsSidebarOpen(true)}
            className="absolute left-0 top-1/2 -translate-y-1/2 rounded-r-lg p-2 shadow-lg transition-colors"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderWidth: '1px',
              borderStyle: 'solid',
              borderColor: currentColors.border.default,
              color: currentColors.text.secondary
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              e.currentTarget.style.color = currentColors.text.primary;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.bg.primary;
              e.currentTarget.style.color = currentColors.text.secondary;
            }}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 5l7 7-7 7"
              />
            </svg>
          </button>
        )}

        {/* Chat Area */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {!currentConversation ? (
            // Empty State
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center max-w-md">
                <svg
                  className="w-24 h-24 mx-auto mb-6"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  style={{ color: currentColors.text.muted }}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.5}
                    d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                  />
                </svg>
                <h2 className="text-2xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Bem-vindo ao Chat com IA!
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.secondary }}>
                  Selecione um índice e clique em "Nova Conversa" para começar a explorar seus
                  dados usando linguagem natural.
                </p>
                <button
                  onClick={createNewConversation}
                  disabled={!selectedIndex}
                  className="px-6 py-3 rounded-lg transition-colors disabled:cursor-not-allowed"
                  style={{
                    backgroundColor: !selectedIndex ? currentColors.bg.hover : currentColors.accent.primary,
                    color: currentColors.text.inverse
                  }}
                  onMouseEnter={(e) => {
                    if (selectedIndex) {
                      e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (selectedIndex) {
                      e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                    }
                  }}
                >
                  {selectedIndex ? 'Criar Nova Conversa' : 'Selecione um índice primeiro'}
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
                <div className="max-w-5xl mx-auto space-y-6">
                  {currentConversation.messages.map((message) => (
                    <div
                      key={message.id}
                      className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className="max-w-3xl rounded-lg shadow-sm p-4"
                        style={{
                          backgroundColor: message.role === 'user' ? currentColors.accent.primary : currentColors.bg.primary,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: currentColors.border.default
                        }}
                      >
                      {/* Message Content */}
                      <div className="prose prose-sm max-w-none markdown-content">
                        <ReactMarkdown
                          remarkPlugins={[remarkGfm]}
                          components={{
                            // Customize all elements with proper styling
                            h1: ({node, ...props}) => <h1 style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }} {...props} />,
                            h2: ({node, ...props}) => <h2 style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '0.5rem' }} {...props} />,
                            h3: ({node, ...props}) => <h3 style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontSize: '1.1rem', fontWeight: 'bold', marginBottom: '0.5rem' }} {...props} />,
                            p: ({node, ...props}) => <p style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontSize: '0.875rem', marginBottom: '0.5rem' }} {...props} />,
                            li: ({node, ...props}) => <li style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontSize: '0.875rem' }} {...props} />,
                            strong: ({node, ...props}) => <strong style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, fontWeight: 'bold' }} {...props} />,
                            ul: ({node, ...props}) => <ul style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, paddingLeft: '1.5rem', marginBottom: '0.5rem' }} {...props} />,
                            ol: ({node, ...props}) => <ol style={{ color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary, paddingLeft: '1.5rem', marginBottom: '0.5rem' }} {...props} />,
                            code: ({node, inline, ...props}) =>
                              inline
                                ? <code style={{ backgroundColor: message.role === 'user' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.05)', padding: '2px 4px', borderRadius: '3px', fontSize: '0.85rem' }} {...props} />
                                : <code style={{ display: 'block', backgroundColor: message.role === 'user' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.05)', padding: '0.5rem', borderRadius: '0.25rem', fontSize: '0.85rem', overflowX: 'auto' }} {...props} />,
                            table: ({node, ...props}) => <table style={{ borderCollapse: 'collapse', width: '100%', marginBottom: '0.5rem' }} {...props} />,
                            th: ({node, ...props}) => <th style={{ border: '1px solid ' + currentColors.border.default, padding: '0.5rem', backgroundColor: message.role === 'user' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.05)' }} {...props} />,
                            td: ({node, ...props}) => <td style={{ border: '1px solid ' + currentColors.border.default, padding: '0.5rem' }} {...props} />,
                          }}
                        >
                          {message.content}
                        </ReactMarkdown>
                      </div>

                      {/* Widget Visualization */}
                      {message.widget && (
                        <div className="mt-4 pt-4" style={{ borderTopWidth: '1px', borderTopStyle: 'solid', borderTopColor: currentColors.border.default }}>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                              {message.widget.title}
                            </h4>
                            <div className="flex gap-2">
                              <button
                                onClick={() => handleAddToDashboard(message.widget, false)}
                                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors"
                                style={{
                                  backgroundColor: currentColors.accent.primary,
                                  color: currentColors.text.inverse
                                }}
                                onMouseEnter={(e) => {
                                  e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                                }}
                                onMouseLeave={(e) => {
                                  e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                                }}
                                title="Adicionar ao dashboard (time range global)"
                              >
                                <svg
                                  className="w-4 h-4"
                                  fill="none"
                                  stroke="currentColor"
                                  viewBox="0 0 24 24"
                                >
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M12 4v16m8-8H4"
                                  />
                                </svg>
                                Adicionar
                              </button>
                              <button
                                onClick={() => handleAddToDashboard(message.widget, true)}
                                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors border"
                                style={{
                                  backgroundColor: 'transparent',
                                  color: currentColors.accent.primary,
                                  borderColor: currentColors.accent.primary
                                }}
                                onMouseEnter={(e) => {
                                  e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                                  e.currentTarget.style.color = currentColors.text.inverse;
                                }}
                                onMouseLeave={(e) => {
                                  e.currentTarget.style.backgroundColor = 'transparent';
                                  e.currentTarget.style.color = currentColors.accent.primary;
                                }}
                                title={`Adicionar com time range fixado (${timeRange.label})`}
                              >
                                <svg
                                  className="w-4 h-4"
                                  fill="none"
                                  stroke="currentColor"
                                  viewBox="0 0 24 24"
                                >
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                                  />
                                </svg>
                                Fixar {timeRange.label}
                              </button>
                            </div>
                          </div>
                          <div className="rounded-lg p-4" style={{ backgroundColor: currentColors.bg.secondary, height: '400px' }}>
                            <PlotlyChart
                              type={message.widget.type}
                              data={message.widget.data.config}
                              title=""
                              config={message.widget.data.config}
                            />
                          </div>
                        </div>
                      )}

                      {/* Timestamp */}
                      <div
                        className="text-xs mt-2"
                        style={{
                          color: message.role === 'user'
                            ? currentColors.text.inverse
                            : currentColors.text.muted,
                          opacity: message.role === 'user' ? 0.8 : 1
                        }}
                      >
                        {new Date(message.timestamp).toLocaleTimeString('pt-BR', {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </div>
                  </div>
                ))}

                  {/* Loading Indicator */}
                  {isLoading && (
                    <div className="flex justify-start">
                      <div className="rounded-lg shadow-sm p-4" style={{
                        backgroundColor: currentColors.bg.primary,
                        borderWidth: '1px',
                        borderStyle: 'solid',
                        borderColor: currentColors.border.default
                      }}>
                        <div className="flex space-x-2">
                          <div className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: currentColors.text.muted }}></div>
                          <div
                            className="w-2 h-2 rounded-full animate-bounce"
                            style={{ backgroundColor: currentColors.text.muted, animationDelay: '0.2s' }}
                          ></div>
                          <div
                            className="w-2 h-2 rounded-full animate-bounce"
                            style={{ backgroundColor: currentColors.text.muted, animationDelay: '0.4s' }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div ref={messagesEndRef} />
                </div>
              </div>

              {/* Input Area */}
              <div className="p-4" style={{
                borderTopWidth: '1px',
                borderTopStyle: 'solid',
                borderTopColor: currentColors.border.default,
                backgroundColor: currentColors.bg.primary
              }}>
                <div className="max-w-5xl mx-auto flex gap-2">
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Digite sua pergunta... (Shift+Enter para nova linha)"
                    rows={3}
                    className="flex-1 px-4 py-3 rounded-lg resize-none transition-colors placeholder-opacity-50"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: currentColors.border.default
                    }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = currentColors.border.focus;
                    }}
                    onBlur={(e) => {
                      e.currentTarget.style.borderColor = currentColors.border.default;
                    }}
                    disabled={isLoading}
                  />
                  <button
                    onClick={handleSendMessage}
                    disabled={isLoading || !input.trim()}
                    className="px-6 py-3 rounded-lg transition-colors self-end disabled:cursor-not-allowed"
                    style={{
                      backgroundColor: (isLoading || !input.trim()) ? currentColors.bg.hover : currentColors.accent.primary,
                      color: currentColors.text.inverse
                    }}
                    onMouseEnter={(e) => {
                      if (!isLoading && input.trim()) {
                        e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isLoading && input.trim()) {
                        e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                      }
                    }}
                  >
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                      />
                    </svg>
                  </button>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
};
