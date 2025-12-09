/**
 * DataLeaksPage - Data Breaches & Leaks with Responsive Layout
 *
 * Features:
 * - Collapsible timeline chart
 * - Two-column layout (Breaches list + Statistics)
 * - Pagination support
 * - Full-width responsive design
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import FloatingChat from '../components/rss/FloatingChat';

interface BreachEntry {
  id: number;
  date: string;
  breach_source: string;
  breach_content: string;
  breach_author: string;
  breach_type: string;
}

interface BreachStats {
  total_breaches: number;
  breaches_today: number;
  breaches_this_week: number;
  breaches_this_month: number;
  breaches_by_type: Record<string, number>;
  top_sources: Array<{ name: string; count: number }>;
  top_authors: Array<{ name: string; count: number }>;
  timeline: Array<{ date: string; count: number }>;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

const DataLeaksPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Data state
  const [breaches, setBreaches] = useState<BreachEntry[]>([]);
  const [stats, setStats] = useState<BreachStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [totalResults, setTotalResults] = useState(0);

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('');
  const [dateRange, setDateRange] = useState('7d');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(20);
  const [hasMore, setHasMore] = useState(false);

  // UI state
  const [showTimeline, setShowTimeline] = useState(true);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get<BreachStats>('/breaches/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  // Fetch breaches with pagination
  const fetchBreaches = useCallback(async (page: number = 1) => {
    setLoading(true);
    try {
      // Build date filter
      let dateFrom: Date | undefined;
      const now = new Date();
      if (dateRange === '24h') {
        dateFrom = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      } else if (dateRange === '7d') {
        dateFrom = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      } else if (dateRange === '30d') {
        dateFrom = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      }

      const offset = (page - 1) * pageSize;

      const response = await api.post<{
        total: number;
        breaches: BreachEntry[];
        facets?: any;
        took_ms: number;
      }>('/breaches/search', {
        query: searchQuery || undefined,
        types: selectedType ? [selectedType] : undefined,
        date_from: dateFrom?.toISOString(),
        limit: pageSize,
        offset,
        sort_by: 'date',
        sort_order: 'desc',
      });

      setBreaches(response.data.breaches);
      setTotalResults(response.data.total);
      setHasMore(offset + response.data.breaches.length < response.data.total);
      setCurrentPage(page);
    } catch (error) {
      console.error('Error fetching breaches:', error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, selectedType, dateRange, pageSize]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    fetchBreaches(1);
  }, [searchQuery, selectedType, dateRange]);

  // Handle search
  const handleSearch = () => {
    setCurrentPage(1);
    fetchBreaches(1);
  };

  // Handle page change
  const handlePageChange = (newPage: number) => {
    fetchBreaches(newPage);
  };

  // Chat handler
  const handleSendMessage = async (message: string, context: Message[]): Promise<string> => {
    try {
      const response = await api.post<{ answer: string; context_used: number }>('/breaches/chat', {
        query: message,
        breach_type: selectedType || undefined,
        days: dateRange === '24h' ? 1 : dateRange === '7d' ? 7 : dateRange === '30d' ? 30 : 365,
        max_context: 10,
      });
      return response.data.answer;
    } catch (error) {
      console.error('Error sending chat message:', error);
      throw error;
    }
  };

  // Get type color
  const getTypeColor = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'database': return '#dc2626';
      case 'credentials': return '#f97316';
      case 'documents': return '#eab308';
      case 'pii': return '#22c55e';
      case 'financial': return '#3b82f6';
      default: return currentColors.text.secondary;
    }
  };

  // Timeline data
  const timelineData = stats?.timeline || [];

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
            Timeline de Data Leaks (7 Dias)
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
          timelineData.length > 0 ? (
            <div style={{ height: '150px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={currentColors.border.default} />
                  <XAxis
                    dataKey="date"
                    stroke={currentColors.text.secondary}
                    tick={{ fill: currentColors.text.secondary, fontSize: 11 }}
                    angle={-45}
                    textAnchor="end"
                    height={60}
                  />
                  <YAxis
                    stroke={currentColors.text.secondary}
                    tick={{ fill: currentColors.text.secondary, fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: currentColors.bg.secondary,
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '8px',
                      color: currentColors.text.primary
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#dc2626"
                    strokeWidth={2}
                    fill="#dc262633"
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
              Carregando timeline...
            </div>
          )
        )}
      </div>

      {/* Main Layout - 2 Columns */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 300px',
        gap: '12px',
        flex: 1,
        minHeight: 0,
        maxHeight: '100%',
        overflow: 'hidden'
      }}>
        {/* Left - Breaches List */}
        <div style={{
          backgroundColor: currentColors.bg.secondary,
          borderRadius: '8px',
          border: `1px solid ${currentColors.border.default}`,
          display: 'grid',
          gridTemplateRows: 'auto 1fr auto',
          overflow: 'hidden',
          maxHeight: '100%'
        }}>
          {/* Header with Search */}
          <div style={{
            padding: '12px',
            borderBottom: `1px solid ${currentColors.border.default}`
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '10px'
            }}>
              <h3 style={{ margin: '0', color: currentColors.text.primary, fontSize: '15px' }}>
                Data Leaks & Breaches
              </h3>
            </div>

            {/* Search and Filters */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Buscar vazamentos..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                style={{
                  flex: 1,
                  minWidth: '200px',
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              />
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                style={{
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              >
                <option value="">Todos os Tipos</option>
                {stats?.breaches_by_type && Object.keys(stats.breaches_by_type).map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
              <select
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value)}
                style={{
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              >
                <option value="24h">Últimas 24h</option>
                <option value="7d">Últimos 7 dias</option>
                <option value="30d">Últimos 30 dias</option>
                <option value="all">Todos</option>
              </select>
              <button
                onClick={handleSearch}
                disabled={loading}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#dc2626',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontWeight: '500',
                  fontSize: '13px',
                  opacity: loading ? 0.6 : 1
                }}
              >
                {loading ? 'Buscando...' : 'Buscar'}
              </button>
            </div>
          </div>

          {/* Breaches List - Scrollable */}
          <div style={{
            overflowY: 'auto',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {loading && breaches.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Carregando vazamentos...
              </div>
            ) : breaches.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Nenhum vazamento encontrado
              </div>
            ) : (
              breaches.map((breach, idx) => (
                <div
                  key={`${breach.id}-${idx}`}
                  style={{
                    padding: '12px',
                    backgroundColor: currentColors.bg.tertiary,
                    borderRadius: '6px',
                    border: `1px solid ${currentColors.border.default}`,
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#dc2626';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = currentColors.border.default;
                  }}
                >
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    marginBottom: '6px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        backgroundColor: getTypeColor(breach.breach_type),
                        color: '#fff'
                      }}>
                        {breach.breach_type || 'Unknown'}
                      </span>
                      <span style={{
                        fontSize: '11px',
                        color: currentColors.text.secondary
                      }}>
                        {breach.breach_source}
                      </span>
                    </div>
                    <span style={{
                      fontSize: '11px',
                      color: currentColors.text.secondary
                    }}>
                      {new Date(breach.date).toLocaleDateString('pt-BR')}
                    </span>
                  </div>
                  {breach.breach_author && (
                    <div style={{
                      fontSize: '12px',
                      color: currentColors.accent.primary,
                      marginBottom: '4px'
                    }}>
                      @{breach.breach_author}
                    </div>
                  )}
                  <div style={{
                    fontSize: '12px',
                    color: currentColors.text.secondary,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    display: '-webkit-box',
                    WebkitLineClamp: 3,
                    WebkitBoxOrient: 'vertical'
                  }}>
                    {breach.breach_content}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Pagination Controls */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '10px 12px',
            borderTop: `1px solid ${currentColors.border.default}`,
            backgroundColor: currentColors.bg.tertiary,
            minHeight: '44px'
          }}>
            {breaches.length > 0 ? (
              <>
                <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                  {breaches.length} de {totalResults.toLocaleString('pt-BR')} (Página {currentPage})
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage <= 1 || loading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: currentPage <= 1 ? currentColors.bg.secondary : '#dc2626',
                      color: currentPage <= 1 ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: currentPage <= 1 || loading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '12px',
                      opacity: currentPage <= 1 ? 0.5 : 1
                    }}
                  >
                    ← Anterior
                  </button>
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={!hasMore || loading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: !hasMore ? currentColors.bg.secondary : '#dc2626',
                      color: !hasMore ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: !hasMore || loading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '12px',
                      opacity: !hasMore ? 0.5 : 1
                    }}
                  >
                    Próxima →
                  </button>
                </div>
              </>
            ) : (
              <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                Faça uma busca para ver resultados
              </span>
            )}
          </div>
        </div>

        {/* Right - Statistics */}
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
          <h3 style={{ margin: '0 0 12px 0', color: currentColors.text.primary, fontSize: '14px' }}>
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
                Total de Vazamentos
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#dc2626' }}>
                {stats?.total_breaches.toLocaleString('pt-BR') || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Hoje
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.success }}>
                {stats?.breaches_today || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Esta Semana
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.warning }}>
                {stats?.breaches_this_week || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Este Mês
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#a855f7' }}>
                {stats?.breaches_this_month.toLocaleString('pt-BR') || '0'}
              </div>
            </div>
          </div>

          {/* Type Breakdown */}
          {stats?.breaches_by_type && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Tipo
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(stats.breaches_by_type)
                  .sort((a, b) => b[1] - a[1])
                  .map(([type, count]) => (
                    <div
                      key={type}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '6px 8px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedType(type === selectedType ? '' : type)}
                    >
                      <span style={{
                        fontSize: '12px',
                        color: getTypeColor(type),
                        fontWeight: type === selectedType ? '600' : '400'
                      }}>
                        {type || 'Unknown'}
                      </span>
                      <span style={{
                        fontSize: '12px',
                        color: currentColors.text.secondary
                      }}>
                        {count.toLocaleString('pt-BR')}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Top Sources */}
          {stats?.top_sources && stats.top_sources.length > 0 && (
            <div style={{ marginTop: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Top Fontes
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {stats.top_sources.slice(0, 5).map((source, idx) => (
                  <div
                    key={source.name}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '11px',
                      color: currentColors.text.secondary
                    }}
                  >
                    <span>{source.name}</span>
                    <span>{source.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Floating Chat */}
      <FloatingChat onSendMessage={handleSendMessage} />
    </div>
  );
};

export default DataLeaksPage;
