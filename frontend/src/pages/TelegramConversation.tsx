/**
 * TelegramConversation - Context Viewer for Telegram Messages
 *
 * Shows N messages before and after a selected message
 * Allows navigation through the conversation
 */

import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';

interface TelegramMessage {
  id: number;
  date: string;
  message?: string;
  sender_info?: {
    user_id?: number;
    username?: string;
    full_name?: string;
  };
  group_info?: {
    group_username?: string;
    group_title?: string;
  };
}

interface ConversationContext {
  total: number;
  messages: TelegramMessage[];
  selected_message_id: number;
  selected_index?: number;
}

const TelegramConversation: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const location = useLocation();
  const navigate = useNavigate();

  const { message_id, index_name, group_username } = location.state as {
    message_id: number;
    index_name: string;
    group_username?: string;
  };

  const [context, setContext] = useState<ConversationContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [contextSize, setContextSize] = useState({  before: 10, after: 10 });

  // Fetch conversation context
  useEffect(() => {
    const fetchContext = async () => {
      setLoading(true);
      try {
        const response = await api.get<ConversationContext>('/telegram/messages/context', {
          params: {
            index_name,
            msg_id: message_id,
            before: contextSize.before,
            after: contextSize.after
          }
        });
        setContext(response.data);
      } catch (error) {
        console.error('Error fetching context:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchContext();
  }, [message_id, index_name, contextSize]);

  const handleChangeContext = (before: number, after: number) => {
    setContextSize({ before, after });
  };

  return (
    <div className="h-full flex flex-col" style={{ backgroundColor: currentColors.bg.secondary }}>
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="container mx-auto px-4 py-6 flex-shrink-0">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <button
                onClick={() => navigate(-1)}
                className="text-blue-600 hover:text-blue-700 mb-2"
              >
                ← Voltar para busca
              </button>
              <h1 className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
                Contexto da Conversa
              </h1>
              {group_username && (
                <p className="text-lg" style={{ color: currentColors.text.secondary }}>
                  Grupo: @{group_username}
                </p>
              )}
            </div>

            {/* Context Size Controls */}
            <div className="flex gap-4 items-center">
              <div className="flex gap-2 items-center">
                <label style={{ color: currentColors.text.secondary }}>Antes:</label>
                <select
                  value={contextSize.before}
                  onChange={(e) => handleChangeContext(Number(e.target.value), contextSize.after)}
                  className="px-3 py-2 rounded-lg"
                  style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary, border: `1px solid ${currentColors.border.default}` }}
                >
                  <option value={5}>5</option>
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                </select>
              </div>
              <div className="flex gap-2 items-center">
                <label style={{ color: currentColors.text.secondary }}>Depois:</label>
                <select
                  value={contextSize.after}
                  onChange={(e) => handleChangeContext(contextSize.before, Number(e.target.value))}
                  className="px-3 py-2 rounded-lg"
                  style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary, border: `1px solid ${currentColors.border.default}` }}
                >
                  <option value={5}>5</option>
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* Messages - Scrollable Area */}
        <div className="flex-1 overflow-y-auto">
          <div className="container mx-auto px-4 pb-6">
            {loading ? (
              <div className="flex justify-center items-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
              </div>
            ) : context ? (
              <div className="space-y-3">
                {context.messages.map((msg, idx) => {
                  const isSelected = msg.id === context.selected_message_id;

                  return (
                    <div
                      key={idx}
                      className={`rounded-lg shadow p-4 ${isSelected ? 'ring-4 ring-yellow-400' : ''}`}
                      style={{
                        backgroundColor: isSelected ? currentColors.accent.warning + '20' : currentColors.bg.primary
                      }}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <div className="font-semibold" style={{ color: currentColors.text.primary }}>
                            {msg.sender_info?.full_name || msg.sender_info?.username || `User ${msg.sender_info?.user_id || 'Unknown'}`}
                            {msg.sender_info?.username && (
                              <span className="ml-2 text-sm font-normal" style={{ color: currentColors.text.secondary }}>
                                @{msg.sender_info.username}
                              </span>
                            )}
                          </div>
                          <div className="text-sm" style={{ color: currentColors.text.secondary }}>
                            {msg.group_info?.group_title || msg.group_info?.group_username}
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          <div className="text-sm" style={{ color: currentColors.text.secondary }}>
                            {new Date(msg.date).toLocaleString('pt-BR')}
                          </div>
                          {isSelected && (
                            <div className="px-2 py-1 rounded text-xs font-bold bg-yellow-400 text-gray-900">
                              MENSAGEM SELECIONADA
                            </div>
                          )}
                        </div>
                      </div>
                      <div style={{ color: currentColors.text.primary }} className="whitespace-pre-wrap">
                        {msg.message || '[Mensagem sem texto]'}
                      </div>
                      <div className="text-xs mt-2" style={{ color: currentColors.text.secondary }}>
                        ID: {msg.id}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-12" style={{ color: currentColors.text.secondary }}>
                Erro ao carregar contexto
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TelegramConversation;
