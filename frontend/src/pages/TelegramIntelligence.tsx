/**
 * TelegramIntelligence - Telegram Messages Intelligence Platform
 *
 * Layout:
 * - Top: Timeline with message volume (last 30 days)
 * - Left Sidebar: Groups list with search
 * - Center: Message and user search
 * - Right Sidebar: Statistics
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import TelegramBlacklistManager from '@components/TelegramBlacklistManager';

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
  _actualGroupUsername?: string;  // Set by frontend when viewing group messages
  _actual_group_username?: string;  // Set by backend when searching (comes from ES _index)
}

interface TelegramGroup {
  title: string;
  username: string;
  id: number;
}

interface TelegramStats {
  total_mensagens: number;
  total_grupos: number;
  total_usuarios: number;
  grupos: Array<{
    key: string;
    doc_count: number;
    titulo?: { buckets: Array<{ key: string }> };
  }>;
  usuarios: Array<{
    key: number;
    doc_count: number;
    username?: { buckets: Array<{ key: string }> };
    full_name?: { buckets: Array<{ key: string }> };
  }>;
}

interface TimelineDataPoint {
  date: string;
  count: number;
}

interface TelegramTimeline {
  total_days: number;
  days: number;
  timeline: TimelineDataPoint[];
}

interface ConversationContext {
  total: number;
  messages: TelegramMessage[];
  selected_message_id: number;
  selected_index?: number;
  group_title?: string;
  group_username?: string;
}

const TelegramIntelligence: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Data state
  const [messages, setMessages] = useState<TelegramMessage[]>([]);
  const [groups, setGroups] = useState<TelegramGroup[]>([]);
  const [stats, setStats] = useState<TelegramStats | null>(null);
  const [timeline, setTimeline] = useState<TelegramTimeline | null>(null);
  const [loading, setLoading] = useState(false);
  const [isPageMounted, setIsPageMounted] = useState(false);

  // Search state
  const [searchType, setSearchType] = useState<'message' | 'user'>('message');
  const [searchQuery, setSearchQuery] = useState('');
  const [isExactSearch, setIsExactSearch] = useState(false);
  const [periodDays, setPeriodDays] = useState<number | null>(null);
  const [groupSearchQuery, setGroupSearchQuery] = useState('');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(50);
  const [totalResults, setTotalResults] = useState(0);
  const [hasMore, setHasMore] = useState(false);

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalContext, setModalContext] = useState<ConversationContext | null>(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [contextSize, setContextSize] = useState({ before: 10, after: 10 });
  const [selectedMessage, setSelectedMessage] = useState<{ message_id: number; index_name: string; group_username?: string } | null>(null);

  // Blacklist manager state
  const [showBlacklistManager, setShowBlacklistManager] = useState(false);

  // Timeline visibility state
  const [showTimeline, setShowTimeline] = useState(true);

  // Fetch groups
  const fetchGroups = useCallback(async () => {
    try {
      const response = await api.get<{ total: number; groups: TelegramGroup[] }>('/telegram/groups');
      setGroups(response.data.groups);
    } catch (error) {
      console.error('Error fetching groups:', error);
    }
  }, []);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get<TelegramStats>('/telegram/statistics', {
        params: { period_days: periodDays }
      });
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, [periodDays]);

  // Fetch timeline
  const fetchTimeline = useCallback(async () => {
    try {
      const response = await api.get<TelegramTimeline>('/telegram/timeline', {
        params: { days: 30 }
      });
      setTimeline(response.data);
    } catch (error) {
      console.error('Error fetching timeline:', error);
    }
  }, []);

  useEffect(() => {
    // Mark page as mounted after a brief delay to ensure DOM is ready
    const timer = setTimeout(() => setIsPageMounted(true), 100);

    fetchGroups();
    fetchStats();
    fetchTimeline();

    return () => clearTimeout(timer);
  }, [fetchGroups, fetchStats, fetchTimeline]);

  // Search messages with pagination
  const handleSearch = async (page: number = 1) => {
    if (!searchQuery.trim()) return;

    setLoading(true);
    try {
      if (searchType === 'message') {
        const response = await api.post<{
          total: number;
          messages: TelegramMessage[];
          page: number;
          page_size: number;
          has_more: boolean;
        }>('/telegram/search/messages', {
          text: searchQuery,
          is_exact_search: isExactSearch,
          page: page,
          page_size: pageSize
        });
        setMessages(response.data.messages);
        setTotalResults(response.data.total);
        setHasMore(response.data.has_more);
        setCurrentPage(page);
      } else {
        const response = await api.post<{
          total: number;
          messages: TelegramMessage[];
          page: number;
          page_size: number;
          has_more: boolean;
        }>('/telegram/search/users', {
          search_term: searchQuery,
          page: page,
          page_size: pageSize
        });
        setMessages(response.data.messages);
        setTotalResults(response.data.total);
        setHasMore(response.data.has_more);
        setCurrentPage(page);
      }
    } catch (error) {
      console.error('Error searching:', error);
    } finally {
      setLoading(false);
    }
  };

  // Handle page change
  const handlePageChange = (newPage: number) => {
    handleSearch(newPage);
  };

  // Reset pagination when search query changes
  const handleNewSearch = () => {
    setCurrentPage(1);
    handleSearch(1);
  };

  // Handle message click to show context
  const handleMessageClick = async (message: TelegramMessage) => {
    console.log('Message clicked:', message);
    console.log('group_info:', message.group_info);
    console.log('_index:', (message as any)._index);
    console.log('_actual_group_username:', message._actual_group_username);
    console.log('_actualGroupUsername:', message._actualGroupUsername);

    // Use the FULL index name from ES hit (like telegram_messages_puxadasgratis)
    // This is the source of truth from Python script: index_name = msg_selecionada['_index']
    const indexName = (message as any)._index ||
                     `telegram_messages_${(message._actual_group_username || message._actualGroupUsername || 'unknown').toLowerCase()}`;
    const messageId = message.id;
    console.log('Using index:', indexName);

    setSelectedMessage({
      message_id: messageId,
      index_name: indexName,
      group_username: message.group_info?.group_username
    });

    setModalLoading(true);
    setShowModal(true);

    try {
      const groupId = message.group_info?.group_id;
      console.log('Fetching context for message:', messageId, 'in index:', indexName, 'group_id:', groupId);
      const response = await api.get<ConversationContext>('/telegram/messages/context', {
        params: {
          index_name: indexName,
          msg_id: messageId,
          group_id: groupId,  // Add group_id to filter correctly
          before: contextSize.before,
          after: contextSize.after
        }
      });
      console.log('Context response:', response.data);
      console.log('📊 CONTEXT DETAILS:');
      console.log('  Total messages:', response.data.total);
      console.log('  Selected message ID:', response.data.selected_message_id);
      console.log('  Selected index in window:', response.data.selected_index);
      console.log('  Group title:', response.data.group_title);
      console.log('  Group username:', response.data.group_username);

      // Log all messages in context
      console.log('📝 MESSAGES IN CONTEXT:');
      response.data.messages.forEach((msg: any, idx: number) => {
        const isSelected = msg.id === response.data.selected_message_id;
        const prefix = isSelected ? '🎯 SELECTED' : `   [${idx}]`;
        console.log(`${prefix} ID: ${msg.id} | Date: ${msg.date} | Message: ${msg.message?.substring(0, 50)}...`);
      });

      // Override group_title with the one from clicked message, but keep index-based username
      // The index name (groupUsername) is the source of truth for WHERE the message is stored
      // The group_title from message metadata shows the display name
      const contextWithTitle = {
        ...response.data,
        group_title: response.data.group_title || message.group_info?.group_title || null,
        group_username: response.data.group_username  // Always use index-based username (v2, etc)
      };

      console.log('✅ Context with title override:', contextWithTitle);
      setModalContext(contextWithTitle);
    } catch (error) {
      console.error('Error fetching context:', error);
    } finally {
      setModalLoading(false);
    }
  };

  // Handle group click to show recent messages
  const handleGroupClick = async (group: TelegramGroup) => {
    console.log('Group clicked:', group);
    setModalLoading(true);
    setShowModal(true);

    try {
      console.log('Fetching messages for group:', group.username);
      const response = await api.get<{
        mensagens: TelegramMessage[];
        total: number;
        titulo: string;
        username: string;
      }>(`/telegram/groups/${group.username}/messages`, {
        params: {
          page: 1,
          page_size: 100  // Max allowed by backend
        }
      });

      console.log('Group messages response:', response.data);

      // Add _actualGroupUsername to each message to track the real group index
      const messagesWithActualGroup = response.data.mensagens.map(msg => ({
        ...msg,
        _actualGroupUsername: group.username
      }));

      setModalContext({
        total: response.data.total,
        messages: messagesWithActualGroup,
        selected_message_id: messagesWithActualGroup[0]?.id || 0,
        selected_index: 0
      });
    } catch (error) {
      console.error('Error fetching group messages:', error);
    } finally {
      setModalLoading(false);
    }
  };

  // Filter groups by search
  const filteredGroups = React.useMemo(() => {
    if (!groupSearchQuery.trim()) {
      return groups;
    }
    const query = groupSearchQuery.toLowerCase();
    return groups.filter(group =>
      (group.title && group.title.toLowerCase().includes(query)) ||
      (group.username && group.username.toLowerCase().includes(query))
    );
  }, [groups, groupSearchQuery]);

  // Prepare timeline chart data for recharts with unique IDs
  const timelineChartData = timeline
    ? timeline.timeline.map((point, idx) => ({
        ...point,
        id: `${point.date}-${idx}` // Add unique ID to prevent key warnings
      }))
    : [];

  return (
    <div style={{
      height: '100%',
      backgroundColor: currentColors.bg.primary,
      color: currentColors.text.primary,
      padding: '12px',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      boxSizing: 'border-box'
    }}>
      {/* Timeline Chart - Top (Collapsible) */}
      <div style={{
        backgroundColor: currentColors.bg.secondary,
        borderRadius: '8px',
        padding: showTimeline ? '12px' : '8px 12px',
        marginBottom: '12px',
        border: `1px solid ${currentColors.border.default}`,
        flexShrink: 0
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: showTimeline ? '8px' : '0'
        }}>
          <h3 style={{ margin: '0', color: currentColors.text.primary, fontSize: '14px' }}>
            Volume de Mensagens (30 Dias)
          </h3>
          <button
            onClick={() => setShowTimeline(!showTimeline)}
            style={{
              padding: '6px 12px',
              backgroundColor: currentColors.bg.tertiary,
              border: `1px solid ${currentColors.border.default}`,
              borderRadius: '6px',
              color: currentColors.text.secondary,
              cursor: 'pointer',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}
          >
            {showTimeline ? '▲ Ocultar' : '▼ Mostrar'}
          </button>
        </div>
        {showTimeline && (
          <>
            {isPageMounted && timeline && timelineChartData.length > 0 ? (
              <div style={{ height: '150px', minHeight: '150px', width: '100%', minWidth: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={currentColors.border.default} />
                    <XAxis
                      dataKey="date"
                      stroke={currentColors.text.secondary}
                      tick={{ fill: currentColors.text.secondary, fontSize: 12 }}
                      angle={-45}
                      textAnchor="end"
                      height={80}
                    />
                    <YAxis
                      stroke={currentColors.text.secondary}
                      tick={{ fill: currentColors.text.secondary, fontSize: 12 }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: currentColors.bg.secondary,
                        border: `1px solid ${currentColors.border.default}`,
                        borderRadius: '8px',
                        color: currentColors.text.primary
                      }}
                      labelStyle={{ color: currentColors.text.primary }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke={currentColors.accent.primary}
                      strokeWidth={2}
                      fill={`${currentColors.accent.primary}33`}
                      fillOpacity={1}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div style={{
                height: '150px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: currentColors.text.secondary
              }}>
                {!timeline ? 'Carregando timeline...' : 'Sem dados para exibir'}
              </div>
            )}
          </>
        )}
      </div>

      {/* Main Layout - 3 Columns */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '250px 1fr 280px',
        gap: '12px',
        flex: 1,
        minHeight: 0,
        maxHeight: '100%',
        overflow: 'hidden'
      }}>
        {/* Left Sidebar - Groups */}
        <div style={{
          backgroundColor: currentColors.bg.secondary,
          borderRadius: '8px',
          padding: '12px',
          border: `1px solid ${currentColors.border.default}`,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          maxHeight: '100%'
        }}>
          <h3 style={{ margin: '0 0 10px 0', color: currentColors.text.primary, fontSize: '14px' }}>
            Grupos ({filteredGroups.length}/{groups.length})
          </h3>

          {/* Group Search */}
          <input
            type="text"
            placeholder="Buscar grupos..."
            value={groupSearchQuery}
            onChange={(e) => setGroupSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '8px',
              marginBottom: '10px',
              backgroundColor: currentColors.bg.tertiary,
              border: `1px solid ${currentColors.border.default}`,
              borderRadius: '6px',
              color: currentColors.text.primary,
              fontSize: '13px',
              boxSizing: 'border-box'
            }}
          />

          {/* Groups List */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {filteredGroups.length === 0 && groupSearchQuery && (
              <div style={{
                padding: '20px',
                textAlign: 'center',
                color: currentColors.text.secondary
              }}>
                Nenhum grupo encontrado para "{groupSearchQuery}"
              </div>
            )}
            {filteredGroups.map((group, idx) => (
              <div
                key={`${group.username}-${group.id}-${idx}`}
                onClick={() => handleGroupClick(group)}
                style={{
                  padding: '12px',
                  backgroundColor: currentColors.bg.tertiary,
                  borderRadius: '8px',
                  cursor: 'pointer',
                  border: `1px solid ${currentColors.border.default}`,
                  transition: 'all 0.2s'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                  e.currentTarget.style.borderColor = currentColors.accent.primary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
                  e.currentTarget.style.borderColor = currentColors.border.default;
                }}
              >
                <div style={{
                  fontSize: '14px',
                  fontWeight: '500',
                  color: currentColors.text.primary,
                  marginBottom: '4px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  {group.title}
                </div>
                <div style={{
                  fontSize: '12px',
                  color: currentColors.text.secondary,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  @{group.username}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Center - Search and Results */}
        <div style={{
          backgroundColor: currentColors.bg.secondary,
          borderRadius: '8px',
          border: `1px solid ${currentColors.border.default}`,
          display: 'grid',
          gridTemplateRows: 'auto 1fr auto',
          overflow: 'hidden',
          maxHeight: '100%'
        }}>
          {/* Header - Fixed */}
          <div style={{
            padding: '15px 15px 10px 15px',
            borderBottom: `1px solid ${currentColors.border.default}`
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '10px'
            }}>
              <h3 style={{ margin: '0', color: currentColors.text.primary, fontSize: '15px' }}>
                Buscar Mensagens e Usuários
              </h3>
              <button
                onClick={() => setShowBlacklistManager(true)}
                style={{
                  padding: '8px 16px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '8px',
                  color: currentColors.text.primary,
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: 500,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
                title="Manage message filters"
              >
                <span>🚫</span>
                <span>Filtros</span>
              </button>
            </div>

            {/* Search Controls */}
            <div style={{
              display: 'flex',
              gap: '8px',
              marginBottom: '10px',
              flexWrap: 'wrap'
            }}>
              <select
                value={searchType}
                onChange={(e) => setSearchType(e.target.value as 'message' | 'user')}
                style={{
                  padding: '10px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '8px',
                  color: currentColors.text.primary
                }}
              >
                <option value="message">Por Mensagem</option>
                <option value="user">Por Usuário</option>
              </select>

              {searchType === 'message' && (
                <label style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '8px',
                  cursor: 'pointer'
                }}>
                  <input
                    type="checkbox"
                    checked={isExactSearch}
                    onChange={(e) => setIsExactSearch(e.target.checked)}
                  />
                  <span style={{ fontSize: '14px', color: currentColors.text.primary }}>
                    Busca Exata
                  </span>
                </label>
              )}
            </div>

            {/* Search Input */}
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                placeholder={searchType === 'message' ? 'Digite o texto da mensagem...' : 'Digite user_id, username ou nome...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleNewSearch()}
                style={{
                  flex: 1,
                  padding: '10px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '8px',
                  color: currentColors.text.primary,
                  fontSize: '14px'
                }}
              />
              <button
                onClick={handleNewSearch}
                disabled={loading}
                style={{
                  padding: '10px 20px',
                  backgroundColor: currentColors.accent.primary,
                  color: '#fff',
                  border: 'none',
                  borderRadius: '8px',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontWeight: '500',
                  opacity: loading ? 0.6 : 1
                }}
              >
                {loading ? 'Buscando...' : 'Buscar'}
              </button>
            </div>
          </div>

          {/* Results - Scrollable */}
          <div style={{
            overflowY: 'auto',
            padding: '10px 15px',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}>
            {messages.length === 0 && !loading && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Digite algo para buscar mensagens ou usuários
              </div>
            )}

            {messages.map((msg, idx) => (
              <div
                key={`msg-${msg.id}-${new Date(msg.date).getTime()}-${idx}`}
                onClick={() => handleMessageClick(msg)}
                style={{
                  padding: '15px',
                  backgroundColor: currentColors.bg.tertiary,
                  borderRadius: '8px',
                  cursor: 'pointer',
                  border: `1px solid ${currentColors.border.default}`,
                  transition: 'all 0.2s',
                  flexShrink: 0
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                  e.currentTarget.style.borderColor = currentColors.accent.primary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
                  e.currentTarget.style.borderColor = currentColors.border.default;
                }}
              >
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                  fontSize: '12px',
                  color: currentColors.text.secondary
                }}>
                  <span>
                    {msg.sender_info?.username ? `@${msg.sender_info.username}` : msg.sender_info?.full_name || 'Unknown'}
                  </span>
                  <span>{new Date(msg.date).toLocaleString('pt-BR')}</span>
                </div>
                <div style={{
                  fontSize: '14px',
                  color: currentColors.text.primary,
                  marginBottom: '8px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 3,
                  WebkitBoxOrient: 'vertical'
                }}>
                  {msg.message || '<sem conteúdo>'}
                </div>
                {msg.group_info && (
                  <div style={{
                    fontSize: '12px',
                    color: currentColors.accent.primary
                  }}>
                    {msg.group_info.group_title}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Pagination Controls - Fixed at bottom */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '12px 15px',
            borderTop: `1px solid ${currentColors.border.default}`,
            backgroundColor: currentColors.bg.tertiary,
            minHeight: '50px'
          }}>
            {messages.length > 0 ? (
              <>
                <span style={{
                  fontSize: '13px',
                  color: currentColors.text.secondary
                }}>
                  {messages.length} de ~{totalResults.toLocaleString('pt-BR')} (Página {currentPage})
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage <= 1 || loading}
                    style={{
                      padding: '8px 16px',
                      backgroundColor: currentPage <= 1 ? currentColors.bg.secondary : currentColors.accent.primary,
                      color: currentPage <= 1 ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: currentPage <= 1 || loading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '13px',
                      opacity: currentPage <= 1 ? 0.5 : 1
                    }}
                  >
                    ← Anterior
                  </button>
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={!hasMore || loading}
                    style={{
                      padding: '8px 16px',
                      backgroundColor: !hasMore ? currentColors.bg.secondary : currentColors.accent.primary,
                      color: !hasMore ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: !hasMore || loading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '13px',
                      opacity: !hasMore ? 0.5 : 1
                    }}
                  >
                    Próxima →
                  </button>
                </div>
              </>
            ) : (
              <span style={{ fontSize: '13px', color: currentColors.text.secondary }}>
                Faça uma busca para ver resultados
              </span>
            )}
          </div>
        </div>

        {/* Right Sidebar - Statistics */}
        <div style={{
          backgroundColor: currentColors.bg.secondary,
          borderRadius: '8px',
          padding: '12px',
          border: `1px solid ${currentColors.border.default}`,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          maxHeight: '100%'
        }}>
          <h3 style={{ margin: '0 0 10px 0', color: currentColors.text.primary, fontSize: '14px' }}>
            Estatísticas
          </h3>

          {/* Stats Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Total de Mensagens
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.primary }}>
                {stats?.total_mensagens.toLocaleString('pt-BR') || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Grupos Monitorados
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.success }}>
                {stats?.total_grupos.toLocaleString('pt-BR') || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Usuários Pesquisáveis
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.warning }}>
                {stats?.total_usuarios.toLocaleString('pt-BR') || '0'}
              </div>
            </div>
          </div>

          {/* Period Filter */}
          <div style={{ marginBottom: '15px' }}>
            <label style={{
              fontSize: '12px',
              color: currentColors.text.secondary,
              marginBottom: '8px',
              display: 'block'
            }}>
              Período de Estatísticas
            </label>
            <select
              value={periodDays || ''}
              onChange={(e) => setPeriodDays(e.target.value ? parseInt(e.target.value) : null)}
              style={{
                width: '100%',
                padding: '10px',
                backgroundColor: currentColors.bg.tertiary,
                border: `1px solid ${currentColors.border.default}`,
                borderRadius: '8px',
                color: currentColors.text.primary,
                fontSize: '14px'
              }}
            >
              <option value="">Todos os tempos</option>
              <option value="1">Últimas 24 horas</option>
              <option value="7">Últimos 7 dias</option>
              <option value="15">Últimos 15 dias</option>
              <option value="30">Últimos 30 dias</option>
            </select>
          </div>
        </div>
      </div>

      {/* Modal - Message Context */}
      {showModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}
          onClick={() => setShowModal(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              backgroundColor: currentColors.bg.secondary,
              borderRadius: '12px',
              padding: '30px',
              maxWidth: '900px',
              width: '100%',
              maxHeight: '80vh',
              overflow: 'auto',
              border: `1px solid ${currentColors.border.default}`
            }}
          >
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px'
            }}>
              <div>
                <h3 style={{ margin: 0, marginBottom: '4px', color: currentColors.text.primary }}>
                  Contexto da Conversa
                </h3>
                {modalContext?.group_username && (
                  <p style={{ margin: 0, fontSize: '14px', color: currentColors.text.secondary }}>
                    Grupo: {modalContext.group_title || modalContext.group_username}
                    {modalContext.group_title && ` (@${modalContext.group_username})`}
                  </p>
                )}
              </div>
              <button
                onClick={() => setShowModal(false)}
                style={{
                  padding: '8px 16px',
                  backgroundColor: currentColors.accent.error,
                  color: '#fff',
                  border: 'none',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                Fechar
              </button>
            </div>

            {modalLoading ? (
              <div style={{ textAlign: 'center', padding: '40px', color: currentColors.text.secondary }}>
                Carregando contexto...
              </div>
            ) : modalContext ? (
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                {modalContext.messages.map((msg, idx) => {
                  const isSelected = msg.id === modalContext.selected_message_id;
                  return (
                    <div
                      key={`modal-msg-${msg.id}-${new Date(msg.date).getTime()}-${idx}`}
                      style={{
                        padding: '15px',
                        backgroundColor: isSelected ? `${currentColors.accent.primary}22` : currentColors.bg.tertiary,
                        borderRadius: '8px',
                        border: `2px solid ${isSelected ? currentColors.accent.primary : currentColors.border.default}`
                      }}
                    >
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        marginBottom: '8px',
                        fontSize: '12px',
                        color: currentColors.text.secondary
                      }}>
                        <span style={{ fontWeight: isSelected ? '600' : '400' }}>
                          {msg.sender_info?.username ? `@${msg.sender_info.username}` : msg.sender_info?.full_name || 'Unknown'}
                        </span>
                        <span>{new Date(msg.date).toLocaleString('pt-BR')}</span>
                      </div>
                      <div style={{
                        fontSize: '14px',
                        color: currentColors.text.primary,
                        whiteSpace: 'pre-wrap'
                      }}>
                        {msg.message || '<sem conteúdo>'}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px', color: currentColors.text.secondary }}>
                Nenhuma mensagem encontrada
              </div>
            )}
          </div>
        </div>
      )}

      {/* Blacklist Manager Modal */}
      {showBlacklistManager && (
        <TelegramBlacklistManager onClose={() => setShowBlacklistManager(false)} />
      )}
    </div>
  );
};

export default TelegramIntelligence;
