/**
 * CredentialsPage - Consulta Externa de Credenciais
 *
 * Features:
 * - Query form for searching leaked credentials
 * - HTML result viewer with iframe rendering
 * - Query history with pagination
 * - Statistics panel
 * - Download support
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';

interface QueryResult {
  id: string;
  query_type: string;
  query_type_display: string | null;
  query_value: string;
  bot_name: string;
  found: boolean;
  result_count: number;
  result_preview: string | null;
  html_url: string | null;
  download_url: string | null;
  status: string;
  error_message: string | null;
  created_at: string;
}

interface QueryHistoryItem {
  id: string;
  query_type: string;
  query_value: string;
  bot_name: string | null;
  found: boolean;
  result_count: number;
  status: string;
  created_at: string;
  created_by: string | null;
  html_available: boolean;
  days_remaining: number;
}

interface CredentialsStats {
  total_queries: number;
  queries_today: number;
  queries_with_results: number;
  success_rate: number;
  top_query_types: Record<string, number>;
  recent_queries: QueryHistoryItem[];
}

interface BotInfo {
  key: string;
  id: number;
  name: string;
  description: string;
  supported_types: string[];
}

const CredentialsPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Query state
  const [queryValue, setQueryValue] = useState<string>('');
  const [autoDownload, setAutoDownload] = useState<boolean>(true);
  const [isQuerying, setIsQuerying] = useState<boolean>(false);
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);

  // History state
  const [history, setHistory] = useState<QueryHistoryItem[]>([]);
  const [historyTotal, setHistoryTotal] = useState<number>(0);
  const [historyPage, setHistoryPage] = useState<number>(1);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);

  // Stats & UI state
  const [stats, setStats] = useState<CredentialsStats | null>(null);
  const [bots, setBots] = useState<BotInfo[]>([]);
  const [selectedView, setSelectedView] = useState<'query' | 'history'>('query');
  const [htmlContent, setHtmlContent] = useState<string | null>(null);
  const [loadingHtml, setLoadingHtml] = useState<boolean>(false);

  // Fetch available bots
  const fetchBots = useCallback(async () => {
    try {
      const response = await api.get<{ bots: BotInfo[] }>('/credentials/bots');
      setBots(response.data.bots);
    } catch (error) {
      console.error('Error fetching bots:', error);
    }
  }, []);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get<CredentialsStats>('/credentials/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  // Fetch history
  const fetchHistory = useCallback(async (page: number = 1) => {
    setHistoryLoading(true);
    try {
      const offset = (page - 1) * 20;
      const response = await api.get<{ total: number; queries: QueryHistoryItem[] }>(
        `/credentials/history?limit=20&offset=${offset}`
      );
      setHistory(response.data.queries);
      setHistoryTotal(response.data.total);
      setHistoryPage(page);
    } catch (error) {
      console.error('Error fetching history:', error);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  // Execute query
  const executeQuery = useCallback(async () => {
    if (!queryValue.trim()) {
      setQueryError('Digite um valor para consultar');
      return;
    }

    setIsQuerying(true);
    setQueryError(null);
    setQueryResult(null);
    setHtmlContent(null);

    try {
      const response = await api.post<QueryResult>('/credentials/query', {
        query_value: queryValue.trim(),
        auto_download: autoDownload
      });

      setQueryResult(response.data);

      // Refresh stats and history
      fetchStats();
      fetchHistory(1);

      // If has HTML, load it
      if (response.data.html_url) {
        loadHtmlContent(response.data.id);
      }
    } catch (error: any) {
      console.error('Error executing query:', error);
      setQueryError(error.response?.data?.detail || 'Erro ao executar consulta');
    } finally {
      setIsQuerying(false);
    }
  }, [queryValue, autoDownload, fetchStats, fetchHistory]);

  // Load HTML content
  const loadHtmlContent = useCallback(async (queryId: string) => {
    setLoadingHtml(true);
    try {
      const response = await api.get(`/credentials/query/${queryId}/html`, {
        responseType: 'text'
      });
      setHtmlContent(response.data);
    } catch (error) {
      console.error('Error loading HTML:', error);
    } finally {
      setLoadingHtml(false);
    }
  }, []);

  // Load result from history
  const loadHistoryItem = useCallback(async (item: QueryHistoryItem) => {
    try {
      const response = await api.get<QueryResult>(`/credentials/query/${item.id}`);
      setQueryResult(response.data);
      setSelectedView('query');

      if (response.data.html_url) {
        loadHtmlContent(item.id);
      } else {
        setHtmlContent(null);
      }
    } catch (error) {
      console.error('Error loading history item:', error);
    }
  }, [loadHtmlContent]);

  // Initial load
  useEffect(() => {
    fetchBots();
    fetchStats();
    fetchHistory(1);
  }, [fetchBots, fetchStats, fetchHistory]);

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
      {/* Header */}
      <div style={{
        backgroundColor: currentColors.bg.secondary,
        borderRadius: '8px',
        padding: '12px',
        marginBottom: '12px',
        border: `1px solid ${currentColors.border.default}`,
        flexShrink: 0
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <h2 style={{ margin: '0 0 4px 0', fontSize: '18px', color: currentColors.text.primary }}>
              Consulta Externa de Credenciais
            </h2>
            <p style={{ margin: 0, fontSize: '12px', color: currentColors.text.secondary }}>
              Consulte credenciais vazadas em bases de dados externas via Telegram
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setSelectedView('query')}
              style={{
                padding: '8px 16px',
                backgroundColor: selectedView === 'query' ? '#f97316' : currentColors.bg.tertiary,
                color: selectedView === 'query' ? '#fff' : currentColors.text.secondary,
                border: `1px solid ${currentColors.border.default}`,
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '500',
                fontSize: '13px'
              }}
            >
              Nova Consulta
            </button>
            <button
              onClick={() => setSelectedView('history')}
              style={{
                padding: '8px 16px',
                backgroundColor: selectedView === 'history' ? '#f97316' : currentColors.bg.tertiary,
                color: selectedView === 'history' ? '#fff' : currentColors.text.secondary,
                border: `1px solid ${currentColors.border.default}`,
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '500',
                fontSize: '13px'
              }}
            >
              Historico ({historyTotal})
            </button>
          </div>
        </div>
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
        {/* Left - Query Form or History */}
        <div style={{
          backgroundColor: currentColors.bg.secondary,
          borderRadius: '8px',
          border: `1px solid ${currentColors.border.default}`,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          maxHeight: '100%'
        }}>
          {selectedView === 'query' ? (
            <>
              {/* Query Form */}
              <div style={{
                padding: '12px',
                borderBottom: `1px solid ${currentColors.border.default}`
              }}>
                <h3 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '15px' }}>
                  Executar Consulta
                </h3>
                <p style={{ margin: '0 0 12px 0', fontSize: '12px', color: currentColors.text.secondary }}>
                  Digite email, CPF, CNPJ, telefone, dominio, IP ou username - o tipo sera detectado automaticamente
                </p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    placeholder="Digite o valor para consultar..."
                    value={queryValue}
                    onChange={(e) => setQueryValue(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && executeQuery()}
                    style={{
                      flex: 1,
                      minWidth: '300px',
                      padding: '12px 16px',
                      backgroundColor: currentColors.bg.tertiary,
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      color: currentColors.text.primary,
                      fontSize: '14px'
                    }}
                  />
                  <label style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '0 12px',
                    fontSize: '12px',
                    color: currentColors.text.secondary
                  }}>
                    <input
                      type="checkbox"
                      checked={autoDownload}
                      onChange={(e) => setAutoDownload(e.target.checked)}
                    />
                    Auto-download
                  </label>
                  <button
                    onClick={executeQuery}
                    disabled={isQuerying || !queryValue.trim()}
                    style={{
                      padding: '12px 24px',
                      backgroundColor: '#f97316',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: (isQuerying || !queryValue.trim()) ? 'not-allowed' : 'pointer',
                      fontWeight: '600',
                      fontSize: '14px',
                      opacity: (isQuerying || !queryValue.trim()) ? 0.6 : 1,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    {isQuerying ? 'Consultando...' : 'Consultar'}
                  </button>
                </div>
                {queryError && (
                  <div style={{
                    marginTop: '8px',
                    padding: '8px 12px',
                    backgroundColor: '#dc262633',
                    border: '1px solid #dc2626',
                    borderRadius: '6px',
                    color: '#dc2626',
                    fontSize: '12px'
                  }}>
                    {queryError}
                  </div>
                )}
              </div>

              {/* Result Area */}
              <div style={{
                flex: 1,
                overflow: 'auto',
                padding: '12px'
              }}>
                {queryResult ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', height: '100%' }}>
                    {/* Result Summary */}
                    <div style={{
                      padding: '12px',
                      backgroundColor: currentColors.bg.tertiary,
                      borderRadius: '6px',
                      border: `1px solid ${queryResult.found ? '#22c55e' : currentColors.border.default}`
                    }}>
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '8px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '4px',
                            fontSize: '12px',
                            fontWeight: '600',
                            backgroundColor: queryResult.found ? '#22c55e' : '#6b7280',
                            color: '#fff'
                          }}>
                            {queryResult.found ? 'ENCONTRADO' : 'NAO ENCONTRADO'}
                          </span>
                          <span style={{
                            fontSize: '13px',
                            color: currentColors.text.secondary
                          }}>
                            {queryResult.bot_name}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          {queryResult.download_url && (
                            <a
                              href={`http://localhost:8001/api/v1${queryResult.download_url}`}
                              download
                              style={{
                                padding: '6px 12px',
                                backgroundColor: '#3b82f6',
                                color: '#fff',
                                borderRadius: '4px',
                                fontSize: '11px',
                                textDecoration: 'none',
                                fontWeight: '500'
                              }}
                            >
                              Download
                            </a>
                          )}
                        </div>
                      </div>
                      <div style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                        <strong>Consulta:</strong>{' '}
                        <span style={{
                          padding: '2px 6px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          backgroundColor: '#3b82f633',
                          color: '#3b82f6',
                          marginRight: '6px'
                        }}>
                          {queryResult.query_type_display || queryResult.query_type}
                        </span>
                        {queryResult.query_value}
                      </div>
                      {queryResult.result_count > 0 && (
                        <div style={{ fontSize: '12px', color: currentColors.text.secondary, marginTop: '4px' }}>
                          <strong>Resultados:</strong> {queryResult.result_count} registro(s)
                        </div>
                      )}
                    </div>

                    {/* Preview Text */}
                    {queryResult.result_preview && !htmlContent && (
                      <div style={{
                        padding: '12px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        color: currentColors.text.secondary,
                        maxHeight: '200px',
                        overflow: 'auto'
                      }}>
                        {queryResult.result_preview}
                      </div>
                    )}

                    {/* HTML Viewer */}
                    {loadingHtml ? (
                      <div style={{
                        flex: 1,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: currentColors.text.secondary
                      }}>
                        Carregando resultado HTML...
                      </div>
                    ) : htmlContent ? (
                      <div style={{
                        flex: 1,
                        borderRadius: '6px',
                        overflow: 'hidden',
                        border: `1px solid ${currentColors.border.default}`
                      }}>
                        <iframe
                          srcDoc={htmlContent}
                          style={{
                            width: '100%',
                            height: '100%',
                            border: 'none',
                            backgroundColor: '#fff',
                            minHeight: '400px'
                          }}
                          sandbox="allow-same-origin"
                          title="Query Result"
                        />
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <div style={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: currentColors.text.secondary
                  }}>
                    <div style={{ fontSize: '48px', marginBottom: '12px' }}>🔍</div>
                    <div style={{ fontSize: '14px', marginBottom: '4px' }}>
                      Nenhuma consulta realizada
                    </div>
                    <div style={{ fontSize: '12px' }}>
                      Use o formulario acima para buscar credenciais vazadas
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <>
              {/* History View */}
              <div style={{
                padding: '12px',
                borderBottom: `1px solid ${currentColors.border.default}`
              }}>
                <h3 style={{ margin: '0', color: currentColors.text.primary, fontSize: '15px' }}>
                  Historico de Consultas
                </h3>
              </div>

              {/* History List */}
              <div style={{
                flex: 1,
                overflow: 'auto',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}>
                {historyLoading ? (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: '100%',
                    color: currentColors.text.secondary
                  }}>
                    Carregando historico...
                  </div>
                ) : history.length === 0 ? (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: '100%',
                    color: currentColors.text.secondary
                  }}>
                    Nenhuma consulta no historico
                  </div>
                ) : (
                  history.map((item) => (
                    <div
                      key={item.id}
                      onClick={() => loadHistoryItem(item)}
                      style={{
                        padding: '12px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '6px',
                        border: `1px solid ${currentColors.border.default}`,
                        cursor: 'pointer',
                        transition: 'all 0.2s'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = '#f97316';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = currentColors.border.default;
                      }}
                    >
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '6px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: '600',
                            backgroundColor: item.found ? '#22c55e' : '#6b7280',
                            color: '#fff'
                          }}>
                            {item.found ? 'FOUND' : 'NOT FOUND'}
                          </span>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            backgroundColor: '#f9731633',
                            color: '#f97316'
                          }}>
                            {item.query_type}
                          </span>
                        </div>
                        <span style={{
                          fontSize: '11px',
                          color: currentColors.text.secondary
                        }}>
                          {new Date(item.created_at).toLocaleString('pt-BR')}
                        </span>
                      </div>
                      <div style={{
                        fontSize: '13px',
                        color: currentColors.text.primary,
                        fontFamily: 'monospace',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        {item.query_value}
                      </div>
                      {/* Footer com resultados e disponibilidade */}
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginTop: '6px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {item.result_count > 0 && (
                            <span style={{
                              fontSize: '11px',
                              color: currentColors.text.secondary
                            }}>
                              {item.result_count} resultado(s)
                            </span>
                          )}
                        </div>
                        {/* Indicador de disponibilidade do HTML */}
                        {item.found && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {item.html_available ? (
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: '4px',
                                fontSize: '10px',
                                backgroundColor: '#22c55e33',
                                color: '#22c55e',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px'
                              }}>
                                HTML disponivel ({item.days_remaining}d)
                              </span>
                            ) : (
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: '4px',
                                fontSize: '10px',
                                backgroundColor: '#6b728033',
                                color: '#6b7280'
                              }}>
                                HTML expirado
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Pagination */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '10px 12px',
                borderTop: `1px solid ${currentColors.border.default}`,
                backgroundColor: currentColors.bg.tertiary
              }}>
                <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                  Pagina {historyPage} de {Math.ceil(historyTotal / 20)}
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => fetchHistory(historyPage - 1)}
                    disabled={historyPage <= 1 || historyLoading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: historyPage <= 1 ? currentColors.bg.secondary : '#f97316',
                      color: historyPage <= 1 ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: historyPage <= 1 || historyLoading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '12px',
                      opacity: historyPage <= 1 ? 0.5 : 1
                    }}
                  >
                    Anterior
                  </button>
                  <button
                    onClick={() => fetchHistory(historyPage + 1)}
                    disabled={historyPage >= Math.ceil(historyTotal / 20) || historyLoading}
                    style={{
                      padding: '6px 12px',
                      backgroundColor: historyPage >= Math.ceil(historyTotal / 20) ? currentColors.bg.secondary : '#f97316',
                      color: historyPage >= Math.ceil(historyTotal / 20) ? currentColors.text.secondary : '#fff',
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '6px',
                      cursor: historyPage >= Math.ceil(historyTotal / 20) || historyLoading ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '12px',
                      opacity: historyPage >= Math.ceil(historyTotal / 20) ? 0.5 : 1
                    }}
                  >
                    Proxima
                  </button>
                </div>
              </div>
            </>
          )}
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
            Estatisticas
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
                Total de Consultas
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#f97316' }}>
                {stats?.total_queries.toLocaleString('pt-BR') || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Consultas Hoje
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.success }}>
                {stats?.queries_today || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Com Resultados
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#22c55e' }}>
                {stats?.queries_with_results || '0'}
              </div>
            </div>

            <div style={{
              padding: '10px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.border.default}`
            }}>
              <div style={{ fontSize: '11px', color: currentColors.text.secondary, marginBottom: '3px' }}>
                Taxa de Sucesso
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: '#3b82f6' }}>
                {stats?.success_rate || '0'}%
              </div>
            </div>
          </div>

          {/* Query Types Breakdown */}
          {stats?.top_query_types && Object.keys(stats.top_query_types).length > 0 && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Tipo de Consulta
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(stats.top_query_types)
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
                        borderRadius: '4px'
                      }}
                    >
                      <span style={{
                        fontSize: '12px',
                        color: '#f97316',
                        textTransform: 'uppercase'
                      }}>
                        {type}
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

          {/* Bots Info */}
          {bots.length > 0 && (
            <div style={{ marginTop: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Bots Disponiveis
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {bots.map((bot) => (
                  <div
                    key={bot.key}
                    style={{
                      padding: '6px 8px',
                      backgroundColor: currentColors.bg.tertiary,
                      borderRadius: '4px'
                    }}
                  >
                    <div style={{
                      fontSize: '12px',
                      color: currentColors.text.primary,
                      fontWeight: '500'
                    }}>
                      {bot.name}
                    </div>
                    <div style={{
                      fontSize: '10px',
                      color: currentColors.text.secondary
                    }}>
                      {bot.description}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CredentialsPage;
