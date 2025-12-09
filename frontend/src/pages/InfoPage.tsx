/**
 * InfoPage - RSS News Feed with Responsive Layout
 *
 * Features:
 * - Collapsible timeline chart
 * - Two-column layout (News list + Statistics)
 * - Pagination support
 * - Full-width responsive design
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import FloatingChat from '../components/rss/FloatingChat';

interface RSSArticle {
  content_hash: string;
  title: string;
  link: string;
  published: string;
  summary: string;
  author?: string;
  tags: string[];
  category: string;
  feed_name: string;
  feed_title?: string;
  feed_description?: string;
  feed_link?: string;
  feed_updated?: string;
  collected_at: string;
  source_type?: string;
  '@timestamp'?: string;
  sentiment?: string;
  entities?: string[];
  keywords?: string[];
  enriched_summary?: string;
  actors_mentioned?: string[];
  families_mentioned?: string[];
  enriched_at?: string;
  enrichment_version?: string;
}

interface RSSStats {
  total_articles: number;
  total_sources: number;
  active_sources: number;
  total_categories: number;
  articles_today: number;
  articles_this_week: number;
  articles_this_month: number;
  last_collection_at?: string;
  top_sources: Array<{ name: string; count: number }>;
  articles_by_category: Record<string, number>;
  timeline: Array<{ date: string; count: number }>;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

const InfoPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Data state
  const [articles, setArticles] = useState<RSSArticle[]>([]);
  const [stats, setStats] = useState<RSSStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [totalResults, setTotalResults] = useState(0);

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedSource, setSelectedSource] = useState<string>('');
  const [dateRange, setDateRange] = useState('all');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(20);
  const [hasMore, setHasMore] = useState(false);

  // UI state
  const [showTimeline, setShowTimeline] = useState(true);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get<RSSStats>('/rss/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  // Fetch articles with pagination
  const fetchArticles = useCallback(async (page: number = 1) => {
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
        articles: RSSArticle[];
      }>('/rss/articles/search', {
        query: searchQuery || undefined,
        categories: selectedCategory ? [selectedCategory] : undefined,
        feed_names: selectedSource ? [selectedSource] : undefined,
        date_from: dateFrom?.toISOString(),
        limit: pageSize,
        offset,
        sort_by: 'published',
        sort_order: 'desc',
      });

      setArticles(response.data.articles);
      setTotalResults(response.data.total);
      setHasMore(offset + response.data.articles.length < response.data.total);
      setCurrentPage(page);
    } catch (error) {
      console.error('Error fetching articles:', error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, selectedCategory, selectedSource, dateRange, pageSize]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    fetchArticles(1);
  }, [searchQuery, selectedCategory, selectedSource, dateRange]);

  // Handle search
  const handleSearch = () => {
    setCurrentPage(1);
    fetchArticles(1);
  };

  // Handle page change
  const handlePageChange = (newPage: number) => {
    fetchArticles(newPage);
  };

  // Sync Now handler
  const handleSyncNow = async () => {
    setSyncing(true);
    try {
      await api.post('/rss/collect', {});
      setTimeout(() => {
        fetchStats();
        fetchArticles(currentPage);
        setSyncing(false);
      }, 60000);
    } catch (error) {
      console.error('Error triggering RSS sync:', error);
      setSyncing(false);
    }
  };

  // Chat handler
  const handleSendMessage = async (message: string, context: Message[]): Promise<string> => {
    try {
      const response = await api.post<{ answer: string }>('/rss/chat', {
        query: message,
        categories: selectedCategory ? [selectedCategory] : undefined,
        sources: selectedSource ? [selectedSource] : undefined,
        max_context_articles: 10,
        context: context.map(msg => ({ role: msg.role, content: msg.content })),
      });
      return response.data.answer;
    } catch (error) {
      console.error('Error sending chat message:', error);
      throw error;
    }
  };

  // Get category color
  const getCategoryColor = (category: string) => {
    switch (category?.toLowerCase()) {
      case 'security': return '#dc2626';
      case 'malware': return '#f97316';
      case 'vulnerability': return '#eab308';
      case 'threat': return '#22c55e';
      case 'news': return '#3b82f6';
      default: return currentColors.text.secondary;
    }
  };

  // Timeline data
  const timelineData = stats?.timeline || [];

  // Available categories and sources
  const availableCategories = stats
    ? Object.keys(stats.articles_by_category).filter(cat => stats.articles_by_category[cat] > 0)
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
            Timeline de Notícias (7 Dias)
          </h3>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              onClick={handleSyncNow}
              disabled={syncing}
              style={{
                padding: '6px 12px',
                backgroundColor: syncing ? currentColors.bg.tertiary : '#22c55e',
                border: 'none',
                borderRadius: '6px',
                color: '#fff',
                cursor: syncing ? 'not-allowed' : 'pointer',
                fontSize: '12px',
                fontWeight: '500',
                opacity: syncing ? 0.6 : 1
              }}
            >
              {syncing ? 'Sincronizando...' : 'Sync Agora'}
            </button>
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
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fill="#3b82f633"
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
        {/* Left - News List */}
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
                Feed de Notícias
              </h3>
            </div>

            {/* Search and Filters */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Buscar notícias..."
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
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                style={{
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              >
                <option value="">Todas Categorias</option>
                {availableCategories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
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
                  backgroundColor: '#3b82f6',
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

          {/* News List - Scrollable */}
          <div style={{
            overflowY: 'auto',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {loading && articles.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Carregando notícias...
              </div>
            ) : articles.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Nenhuma notícia encontrada
              </div>
            ) : (
              articles.map((article, idx) => (
                <a
                  key={`${article.content_hash}-${idx}`}
                  href={article.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    padding: '12px',
                    backgroundColor: currentColors.bg.tertiary,
                    borderRadius: '6px',
                    border: `1px solid ${currentColors.border.default}`,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    textDecoration: 'none',
                    display: 'block'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#3b82f6';
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        backgroundColor: getCategoryColor(article.category),
                        color: '#fff'
                      }}>
                        {article.category || 'News'}
                      </span>
                      <span style={{
                        fontSize: '11px',
                        color: currentColors.text.secondary
                      }}>
                        {article.feed_name}
                      </span>
                    </div>
                    <span style={{
                      fontSize: '11px',
                      color: currentColors.text.secondary,
                      flexShrink: 0
                    }}>
                      {new Date(article.published).toLocaleDateString('pt-BR')}
                    </span>
                  </div>
                  <div style={{
                    fontSize: '13px',
                    fontWeight: '500',
                    color: currentColors.text.primary,
                    marginBottom: '4px'
                  }}>
                    {article.title}
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
                    {article.summary || article.enriched_summary}
                  </div>
                  {article.tags && article.tags.length > 0 && (
                    <div style={{
                      display: 'flex',
                      gap: '4px',
                      flexWrap: 'wrap',
                      marginTop: '6px'
                    }}>
                      {article.tags.slice(0, 3).map((tag, tagIdx) => (
                        <span
                          key={tagIdx}
                          style={{
                            padding: '2px 6px',
                            backgroundColor: currentColors.bg.secondary,
                            borderRadius: '4px',
                            fontSize: '10px',
                            color: currentColors.text.secondary
                          }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </a>
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
            {articles.length > 0 ? (
              <>
                <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                  {articles.length} de {totalResults.toLocaleString('pt-BR')} (Página {currentPage})
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage <= 1 || loading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: currentPage <= 1 ? currentColors.bg.secondary : '#3b82f6',
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
                      backgroundColor: !hasMore ? currentColors.bg.secondary : '#3b82f6',
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
                Total de Artigos
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#3b82f6' }}>
                {stats?.total_articles.toLocaleString('pt-BR') || '0'}
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
                {stats?.articles_today || '0'}
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
                {stats?.articles_this_week || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Fontes Ativas
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#a855f7' }}>
                {stats?.active_sources || '0'}
              </div>
            </div>
          </div>

          {/* Category Breakdown */}
          {stats?.articles_by_category && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Categoria
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(stats.articles_by_category)
                  .filter(([_, count]) => count > 0)
                  .sort((a, b) => b[1] - a[1])
                  .map(([category, count]) => (
                    <div
                      key={category}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '6px 8px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedCategory(category === selectedCategory ? '' : category)}
                    >
                      <span style={{
                        fontSize: '12px',
                        color: getCategoryColor(category),
                        fontWeight: category === selectedCategory ? '600' : '400'
                      }}>
                        {category || 'Other'}
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
                {stats.top_sources.slice(0, 5).map((source) => (
                  <div
                    key={source.name}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '11px',
                      color: currentColors.text.secondary,
                      cursor: 'pointer',
                      padding: '4px',
                      borderRadius: '4px'
                    }}
                    onClick={() => setSelectedSource(source.name === selectedSource ? '' : source.name)}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }}
                  >
                    <span style={{
                      fontWeight: source.name === selectedSource ? '600' : '400',
                      color: source.name === selectedSource ? '#3b82f6' : currentColors.text.secondary
                    }}>
                      {source.name}
                    </span>
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

export default InfoPage;
