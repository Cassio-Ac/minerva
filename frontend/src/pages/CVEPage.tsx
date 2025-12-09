/**
 * CVEPage - CVE Vulnerabilities with Responsive Layout
 *
 * Features:
 * - Collapsible timeline chart
 * - Two-column layout (CVE list + Statistics)
 * - Pagination support
 * - Full-width responsive design
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import FloatingChat from '../components/rss/FloatingChat';

interface CVEEntry {
  id: number;
  date: string;
  cve_id: string;
  cve_title: string;
  cve_content: string;
  cve_severity_level: string;
  cve_severity_score: number;
}

interface CVEStats {
  total_cves: number;
  cves_today: number;
  cves_this_week: number;
  cves_this_month: number;
  cves_by_severity: Record<string, number>;
  top_sources: Array<{ name: string; count: number }>;
  timeline: Array<{ date: string; count: number }>;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

const CVEPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Data state
  const [cves, setCVEs] = useState<CVEEntry[]>([]);
  const [stats, setStats] = useState<CVEStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [totalResults, setTotalResults] = useState(0);

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
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
      const response = await api.get<CVEStats>('/cves/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  // Fetch CVEs with pagination
  const fetchCVEs = useCallback(async (page: number = 1) => {
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
        cves: CVEEntry[];
        facets?: any;
        took_ms: number;
      }>('/cves/search', {
        query: searchQuery || undefined,
        severity_levels: selectedSeverity ? [selectedSeverity] : undefined,
        date_from: dateFrom?.toISOString(),
        limit: pageSize,
        offset,
        sort_by: 'date',
        sort_order: 'desc',
      });

      setCVEs(response.data.cves);
      setTotalResults(response.data.total);
      setHasMore(offset + response.data.cves.length < response.data.total);
      setCurrentPage(page);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, selectedSeverity, dateRange, pageSize]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    fetchCVEs(1);
  }, [searchQuery, selectedSeverity, dateRange]);

  // Handle search
  const handleSearch = () => {
    setCurrentPage(1);
    fetchCVEs(1);
  };

  // Handle page change
  const handlePageChange = (newPage: number) => {
    fetchCVEs(newPage);
  };

  // Chat handler
  const handleSendMessage = async (message: string, context: Message[]): Promise<string> => {
    try {
      const response = await api.post<{ answer: string; context_used: number }>('/cves/chat', {
        query: message,
        severity_level: selectedSeverity || undefined,
        days: dateRange === '24h' ? 1 : dateRange === '7d' ? 7 : dateRange === '30d' ? 30 : 365,
        max_context: 10,
      });
      return response.data.answer;
    } catch (error) {
      console.error('Error sending chat message:', error);
      throw error;
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#eab308';
      case 'LOW': return '#22c55e';
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
            Timeline de CVEs (7 Dias)
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
                    stroke={currentColors.accent.primary}
                    strokeWidth={2}
                    fill={`${currentColors.accent.primary}33`}
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
        {/* Left - CVE List */}
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
                CVE Vulnerabilities
              </h3>
            </div>

            {/* Search and Filters */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Buscar CVEs..."
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
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                style={{
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              >
                <option value="">Todas Severidades</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
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
                  backgroundColor: currentColors.accent.primary,
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

          {/* CVE List - Scrollable */}
          <div style={{
            overflowY: 'auto',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {loading && cves.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Carregando CVEs...
              </div>
            ) : cves.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Nenhum CVE encontrado
              </div>
            ) : (
              cves.map((cve, idx) => (
                <div
                  key={`${cve.cve_id}-${idx}`}
                  style={{
                    padding: '12px',
                    backgroundColor: currentColors.bg.tertiary,
                    borderRadius: '6px',
                    border: `1px solid ${currentColors.border.default}`,
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = currentColors.accent.primary;
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
                        backgroundColor: getSeverityColor(cve.cve_severity_level),
                        color: '#fff'
                      }}>
                        {cve.cve_severity_level || 'N/A'}
                      </span>
                      {cve.cve_severity_score > 0 && (
                        <span style={{
                          fontSize: '11px',
                          color: currentColors.text.secondary
                        }}>
                          Score: {cve.cve_severity_score}
                        </span>
                      )}
                    </div>
                    <span style={{
                      fontSize: '11px',
                      color: currentColors.text.secondary
                    }}>
                      {new Date(cve.date).toLocaleDateString('pt-BR')}
                    </span>
                  </div>
                  <div style={{
                    fontSize: '13px',
                    fontWeight: '500',
                    color: currentColors.accent.primary,
                    marginBottom: '4px'
                  }}>
                    {cve.cve_id}
                  </div>
                  <div style={{
                    fontSize: '13px',
                    color: currentColors.text.primary,
                    marginBottom: '4px',
                    fontWeight: '500'
                  }}>
                    {cve.cve_title}
                  </div>
                  <div style={{
                    fontSize: '12px',
                    color: currentColors.text.secondary,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical'
                  }}>
                    {cve.cve_content}
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
            {cves.length > 0 ? (
              <>
                <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                  {cves.length} de {totalResults.toLocaleString('pt-BR')} (Página {currentPage})
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage <= 1 || loading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: currentPage <= 1 ? currentColors.bg.secondary : currentColors.accent.primary,
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
                      backgroundColor: !hasMore ? currentColors.bg.secondary : currentColors.accent.primary,
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
                Total de CVEs
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.primary }}>
                {stats?.total_cves.toLocaleString('pt-BR') || '0'}
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
                {stats?.cves_today || '0'}
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
                {stats?.cves_this_week || '0'}
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
                {stats?.cves_this_month.toLocaleString('pt-BR') || '0'}
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          {stats?.cves_by_severity && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Severidade
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(stats.cves_by_severity)
                  .sort((a, b) => b[1] - a[1])
                  .map(([severity, count]) => (
                    <div
                      key={severity}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '6px 8px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedSeverity(severity === selectedSeverity ? '' : severity)}
                    >
                      <span style={{
                        fontSize: '12px',
                        color: getSeverityColor(severity),
                        fontWeight: severity === selectedSeverity ? '600' : '400'
                      }}>
                        {severity || 'N/A'}
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
        </div>
      </div>

      {/* Floating Chat */}
      <FloatingChat onSendMessage={handleSendMessage} />
    </div>
  );
};

export default CVEPage;
