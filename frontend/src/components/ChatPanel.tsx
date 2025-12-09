/**
 * ChatPanel Component
 * Chat com IA para criar widgets
 */

import React, { useState, useRef, useEffect } from 'react';
import { api } from '@services/api';
import { useDashboardStore } from '@stores/dashboardStore';
import { useSettingsStore } from '@stores/settingsStore';
import { LLMProviderIndicator } from '@components/LLMProviderIndicator';
import { KnowledgeService } from '@services/knowledgeService';
import type { Widget, WidgetPosition } from '@types/widget';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export const ChatPanel: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: 'Olá! Primeiro selecione um servidor e índice acima, depois diga o que você quer visualizar e eu crio um widget para você.\n\nExemplos:\n- "Mostre um gráfico de pizza com categorias"\n- "Quero ver o total em uma métrica"\n- "Crie um gráfico de barras"',
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { currentDashboard, widgets, addWidget, selectedServerId, selectedIndex, timeRange } = useDashboardStore();

  // Auto-scroll para última mensagem
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: input,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      // Verificar se tem índice selecionado
      if (!selectedIndex) {
        const errorMessage: Message = {
          role: 'assistant',
          content: '⚠️ Por favor, selecione um servidor e um índice primeiro.',
          timestamp: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, errorMessage]);
        setIsLoading(false);
        return;
      }

      // Buscar contexto do Knowledge Base
      const knowledgeContext = await KnowledgeService.buildContext(
        input,
        selectedIndex
      );

      // Montar mensagem completa com contexto
      const enrichedMessage = knowledgeContext
        ? `${knowledgeContext}\n\n---\n\nUser Question: ${input}`
        : input;

      // Chamar API do chat com contexto enriquecido
      const response = await api.chat({
        message: enrichedMessage,
        index: selectedIndex,
        server_id: selectedServerId || undefined,
        time_range: timeRange,
        context: messages.slice(-5), // Últimas 5 mensagens como contexto
      });

      // DEBUG: Log response to see what we're getting
      console.log('🐛 Chat API Response:', {
        fullResponse: response,
        explanationType: typeof response.explanation,
        explanationValue: response.explanation,
        explanationPreview: response.explanation?.substring(0, 100)
      });

      // Adicionar resposta do assistente
      const assistantMessage: Message = {
        role: 'assistant',
        content: response.explanation,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMessage]);

      // Se retornou widget, adicionar ao dashboard
      if (response.widget) {
        const newWidget: Widget = {
          id: `widget-${Date.now()}`,
          title: response.widget.title || 'Novo Widget',
          type: response.widget.type || 'pie',
          position: calculateNextPosition(),
          data: {
            ...response.widget.data,
            last_updated: new Date().toISOString(),  // Adicionar timestamp para evitar re-execução imediata
          },
          index: selectedIndex,  // Salvar índice usado na criação
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
          },
        };

        console.log(`✅ Widget created with index: ${selectedIndex}`);
        addWidget(newWidget);

        // Mensagem de confirmação
        const confirmMessage: Message = {
          role: 'assistant',
          content: '✅ Widget adicionado ao dashboard!',
          timestamp: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, confirmMessage]);
      }
    } catch (error: any) {
      const errorMessage: Message = {
        role: 'assistant',
        content: `❌ Erro ao processar mensagem: ${error.message}`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const calculateNextPosition = (): WidgetPosition => {
    // Calcular próxima posição livre no grid
    const cols = 12;
    const widgetWidth = 4;
    const widgetHeight = 4;

    const usedPositions = widgets.map((w) => w.position);

    // Tentar encontrar espaço vazio
    let x = 0;
    let y = 0;

    if (usedPositions.length > 0) {
      // Posicionar ao lado do último widget
      const lastWidget = usedPositions[usedPositions.length - 1];
      x = (lastWidget.x + lastWidget.w) % cols;
      y = lastWidget.y + Math.floor((lastWidget.x + lastWidget.w) / cols) * widgetHeight;
    }

    return { x, y, w: widgetWidth, h: widgetHeight };
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className="flex flex-col h-full rounded-lg shadow-lg" style={{ backgroundColor: currentColors.bg.primary }}>
      {/* Header */}
      <div className="px-4 py-3 rounded-t-lg" style={{
        background: `linear-gradient(to right, ${currentColors.accent.primary}, ${currentColors.accent.primaryHover})`,
        color: currentColors.text.inverse
      }}>
        <div className="flex items-start justify-between">
          <div>
            <h3 className="font-semibold flex items-center gap-2">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                />
              </svg>
              Chat com IA
            </h3>
            <p className="text-xs mt-1" style={{ color: currentColors.text.inverse, opacity: 0.9 }}>
              Crie widgets usando linguagem natural
            </p>
          </div>
          <div className="ml-3 flex-shrink-0">
            <LLMProviderIndicator compact />
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message, index) => (
          <div
            key={index}
            className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className="max-w-xs lg:max-w-md px-4 py-2 rounded-lg"
              style={{
                backgroundColor: message.role === 'user' ? currentColors.accent.primary : currentColors.bg.tertiary,
                color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.primary
              }}
            >
              <p className="text-sm whitespace-pre-wrap">{message.content}</p>
              <p
                className="text-xs mt-1"
                style={{
                  color: message.role === 'user' ? currentColors.text.inverse : currentColors.text.muted,
                  opacity: message.role === 'user' ? 0.8 : 1
                }}
              >
                {new Date(message.timestamp).toLocaleTimeString('pt-BR', {
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </p>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="px-4 py-2 rounded-lg" style={{ backgroundColor: currentColors.bg.tertiary }}>
              <div className="flex space-x-2">
                <div className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: currentColors.accent.primary }}></div>
                <div
                  className="w-2 h-2 rounded-full animate-bounce"
                  style={{ backgroundColor: currentColors.accent.primary, animationDelay: '0.2s' }}
                ></div>
                <div
                  className="w-2 h-2 rounded-full animate-bounce"
                  style={{ backgroundColor: currentColors.accent.primary, animationDelay: '0.4s' }}
                ></div>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-gray-200 p-4">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Digite sua mensagem..."
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={isLoading}
          />
          <button
            onClick={handleSendMessage}
            disabled={isLoading || !input.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
    </div>
  );
};
