/**
 * CPFPage - CPF Lookup with Responsive Layout
 *
 * Features:
 * - Collapsible timeline chart (birth years distribution)
 * - Two-column layout (Results list + Statistics)
 * - Pagination support
 * - Search by CPF, Name, Date of Birth, Age
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@services/api';
import { useSettingsStore } from '@stores/settingsStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

interface CPFEntry {
  cpf: string;
  nome: string;
  sexo: string;
  nasc: string | null;
}

interface CPFStats {
  total_records: number;
  by_sexo: Record<string, number>;
  by_decade: Array<{ year: string; count: number }>;
  by_age_range: Array<{ range: string; count: number }>;
  timeline: Array<{ date: string; count: number }>;
}

const CPFPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Data state
  const [results, setResults] = useState<CPFEntry[]>([]);
  const [stats, setStats] = useState<CPFStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [totalResults, setTotalResults] = useState(0);
  const [statsLoading, setStatsLoading] = useState(true);

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSexo, setSelectedSexo] = useState<string>('');
  const [idadeMin, setIdadeMin] = useState<string>('');
  const [idadeMax, setIdadeMax] = useState<string>('');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(20);
  const [hasMore, setHasMore] = useState(false);

  // UI state
  const [showTimeline, setShowTimeline] = useState(true);
  const [selectedResult, setSelectedResult] = useState<CPFEntry | null>(null);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const response = await api.get<CPFStats>('/cpf/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Fetch CPF records with pagination
  const fetchCPF = useCallback(async (page: number = 1) => {
    if (!searchQuery.trim() && !selectedSexo && !idadeMin && !idadeMax) {
      // Don't search without any filter
      return;
    }

    setLoading(true);
    try {
      const offset = (page - 1) * pageSize;

      const response = await api.post<{
        total: number;
        results: CPFEntry[];
        facets?: any;
        took_ms: number;
      }>('/cpf/search', {
        query: searchQuery || undefined,
        sexo: selectedSexo || undefined,
        idade_min: idadeMin ? parseInt(idadeMin) : undefined,
        idade_max: idadeMax ? parseInt(idadeMax) : undefined,
        limit: pageSize,
        offset,
        sort_by: 'nome.keyword',
        sort_order: 'asc',
      });

      setResults(response.data.results);
      setTotalResults(response.data.total);
      setHasMore(offset + response.data.results.length < response.data.total);
      setCurrentPage(page);
    } catch (error) {
      console.error('Error fetching CPF:', error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, selectedSexo, idadeMin, idadeMax, pageSize]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  // Handle search
  const handleSearch = () => {
    setCurrentPage(1);
    fetchCPF(1);
  };

  // Handle page change
  const handlePageChange = (newPage: number) => {
    fetchCPF(newPage);
  };

  // Format CPF with mask
  const formatCPF = (cpf: string) => {
    if (!cpf || cpf.length !== 11) return cpf;
    return `${cpf.slice(0, 3)}.${cpf.slice(3, 6)}.${cpf.slice(6, 9)}-${cpf.slice(9)}`;
  };

  // Format date
  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    try {
      const date = new Date(dateStr);
      return date.toLocaleDateString('pt-BR');
    } catch {
      return dateStr;
    }
  };

  // Calculate age from birth date
  const calculateAge = (dateStr: string | null) => {
    if (!dateStr) return null;
    try {
      const birth = new Date(dateStr);
      const today = new Date();
      let age = today.getFullYear() - birth.getFullYear();
      const m = today.getMonth() - birth.getMonth();
      if (m < 0 || (m === 0 && today.getDate() < birth.getDate())) {
        age--;
      }
      return age;
    } catch {
      return null;
    }
  };

  // Get sexo label
  const getSexoLabel = (sexo: string) => {
    switch (sexo?.toUpperCase()) {
      case 'M': return 'Masculino';
      case 'F': return 'Feminino';
      case 'I': return 'Intersexo';
      default: return 'Não informado';
    }
  };

  // Get sexo color
  const getSexoColor = (sexo: string) => {
    switch (sexo?.toUpperCase()) {
      case 'M': return '#3b82f6';
      case 'F': return '#ec4899';
      case 'I': return '#8b5cf6';
      default: return currentColors.text.secondary;
    }
  };

  // Timeline data (birth years)
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
            Distribuicao por Ano de Nascimento
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
          statsLoading ? (
            <div style={{
              height: '150px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: currentColors.text.secondary
            }}>
              Carregando timeline...
            </div>
          ) : timelineData.length > 0 ? (
            <div style={{ height: '150px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={currentColors.border.default} />
                  <XAxis
                    dataKey="date"
                    stroke={currentColors.text.secondary}
                    tick={{ fill: currentColors.text.secondary, fontSize: 10 }}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    stroke={currentColors.text.secondary}
                    tick={{ fill: currentColors.text.secondary, fontSize: 11 }}
                    tickFormatter={(value) => value >= 1000000 ? `${(value / 1000000).toFixed(1)}M` : value >= 1000 ? `${(value / 1000).toFixed(0)}K` : value}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: currentColors.bg.secondary,
                      border: `1px solid ${currentColors.border.default}`,
                      borderRadius: '8px',
                      color: currentColors.text.primary
                    }}
                    formatter={(value: number) => [value.toLocaleString('pt-BR'), 'Registros']}
                    labelFormatter={(label) => `Ano: ${label}`}
                  />
                  <Bar
                    dataKey="count"
                    fill={currentColors.accent.primary}
                    radius={[2, 2, 0, 0]}
                  />
                </BarChart>
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
              Sem dados de timeline
            </div>
          )
        )}
      </div>

      {/* Main Layout - 2 Columns */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 320px',
        gap: '12px',
        flex: 1,
        minHeight: 0,
        maxHeight: '100%',
        overflow: 'hidden'
      }}>
        {/* Left - Results List */}
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
                Consulta CPF
              </h3>
            </div>

            {/* Search and Filters */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="CPF ou Nome..."
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
                value={selectedSexo}
                onChange={(e) => setSelectedSexo(e.target.value)}
                style={{
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              >
                <option value="">Todos Sexos</option>
                <option value="M">Masculino</option>
                <option value="F">Feminino</option>
                <option value="I">Intersexo</option>
              </select>
              <input
                type="number"
                placeholder="Idade Min"
                value={idadeMin}
                onChange={(e) => setIdadeMin(e.target.value)}
                style={{
                  width: '90px',
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              />
              <input
                type="number"
                placeholder="Idade Max"
                value={idadeMax}
                onChange={(e) => setIdadeMax(e.target.value)}
                style={{
                  width: '90px',
                  padding: '8px 12px',
                  backgroundColor: currentColors.bg.tertiary,
                  border: `1px solid ${currentColors.border.default}`,
                  borderRadius: '6px',
                  color: currentColors.text.primary,
                  fontSize: '13px'
                }}
              />
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

          {/* Results List - Scrollable */}
          <div style={{
            overflowY: 'auto',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}>
            {loading && results.length === 0 ? (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary
              }}>
                Buscando registros...
              </div>
            ) : results.length === 0 ? (
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: currentColors.text.secondary,
                gap: '8px'
              }}>
                <span style={{ fontSize: '32px' }}>🔍</span>
                <span>Digite um CPF ou nome para buscar</span>
              </div>
            ) : (
              results.map((record, idx) => {
                const age = calculateAge(record.nasc);
                return (
                  <div
                    key={`${record.cpf}-${idx}`}
                    style={{
                      padding: '12px',
                      backgroundColor: selectedResult?.cpf === record.cpf ? `${currentColors.accent.primary}22` : currentColors.bg.tertiary,
                      borderRadius: '6px',
                      border: `1px solid ${selectedResult?.cpf === record.cpf ? currentColors.accent.primary : currentColors.border.default}`,
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                    onClick={() => setSelectedResult(record)}
                    onMouseEnter={(e) => {
                      if (selectedResult?.cpf !== record.cpf) {
                        e.currentTarget.style.borderColor = currentColors.accent.primary;
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (selectedResult?.cpf !== record.cpf) {
                        e.currentTarget.style.borderColor = currentColors.border.default;
                      }
                    }}
                  >
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'flex-start',
                      marginBottom: '6px'
                    }}>
                      <div style={{
                        fontSize: '14px',
                        fontWeight: '600',
                        color: currentColors.text.primary
                      }}>
                        {record.nome}
                      </div>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '500',
                        backgroundColor: `${getSexoColor(record.sexo)}22`,
                        color: getSexoColor(record.sexo),
                        border: `1px solid ${getSexoColor(record.sexo)}44`
                      }}>
                        {getSexoLabel(record.sexo)}
                      </span>
                    </div>
                    <div style={{
                      display: 'flex',
                      gap: '16px',
                      fontSize: '13px'
                    }}>
                      <div>
                        <span style={{ color: currentColors.text.secondary }}>CPF: </span>
                        <span style={{ color: currentColors.accent.primary, fontFamily: 'monospace' }}>
                          {formatCPF(record.cpf)}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: currentColors.text.secondary }}>Nascimento: </span>
                        <span style={{ color: currentColors.text.primary }}>
                          {formatDate(record.nasc)}
                        </span>
                      </div>
                      {age !== null && (
                        <div>
                          <span style={{ color: currentColors.text.secondary }}>Idade: </span>
                          <span style={{ color: currentColors.text.primary }}>
                            {age} anos
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
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
            {results.length > 0 ? (
              <>
                <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                  {results.length} de {totalResults.toLocaleString('pt-BR')} (Pagina {currentPage})
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
                    Proxima →
                  </button>
                </div>
              </>
            ) : (
              <span style={{ fontSize: '12px', color: currentColors.text.secondary }}>
                Faca uma busca para ver resultados
              </span>
            )}
          </div>
        </div>

        {/* Right - Statistics & Details */}
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
                Total de Registros
              </div>
              <div style={{ fontSize: '18px', fontWeight: '600', color: currentColors.accent.primary }}>
                {statsLoading ? '...' : stats?.total_records.toLocaleString('pt-BR') || '0'}
              </div>
            </div>
          </div>

          {/* Gender Distribution */}
          {stats?.by_sexo && (
            <div style={{ marginBottom: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Sexo
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(stats.by_sexo)
                  .sort((a, b) => b[1] - a[1])
                  .map(([sexo, count]) => (
                    <div
                      key={sexo}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '6px 8px',
                        backgroundColor: currentColors.bg.tertiary,
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedSexo(sexo === selectedSexo ? '' : sexo)}
                    >
                      <span style={{
                        fontSize: '12px',
                        color: getSexoColor(sexo),
                        fontWeight: sexo === selectedSexo ? '600' : '400'
                      }}>
                        {getSexoLabel(sexo)}
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

          {/* Age Range Distribution */}
          {stats?.by_age_range && stats.by_age_range.length > 0 && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.text.primary, fontSize: '13px' }}>
                Por Faixa Etaria
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {stats.by_age_range
                  .filter(item => item.count > 0)
                  .map((item) => (
                    <div
                      key={item.range}
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
                        color: currentColors.text.primary
                      }}>
                        {item.range} anos
                      </span>
                      <span style={{
                        fontSize: '12px',
                        color: currentColors.text.secondary
                      }}>
                        {item.count.toLocaleString('pt-BR')}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Selected Record Details */}
          {selectedResult && (
            <div style={{
              marginTop: '12px',
              padding: '12px',
              backgroundColor: currentColors.bg.tertiary,
              borderRadius: '6px',
              border: `1px solid ${currentColors.accent.primary}`
            }}>
              <h4 style={{ margin: '0 0 8px 0', color: currentColors.accent.primary, fontSize: '13px' }}>
                Detalhes do Registro
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px' }}>
                <div>
                  <span style={{ color: currentColors.text.secondary }}>Nome: </span>
                  <span style={{ color: currentColors.text.primary, fontWeight: '500' }}>{selectedResult.nome}</span>
                </div>
                <div>
                  <span style={{ color: currentColors.text.secondary }}>CPF: </span>
                  <span style={{ color: currentColors.accent.primary, fontFamily: 'monospace' }}>{formatCPF(selectedResult.cpf)}</span>
                </div>
                <div>
                  <span style={{ color: currentColors.text.secondary }}>Sexo: </span>
                  <span style={{ color: getSexoColor(selectedResult.sexo) }}>{getSexoLabel(selectedResult.sexo)}</span>
                </div>
                <div>
                  <span style={{ color: currentColors.text.secondary }}>Nascimento: </span>
                  <span style={{ color: currentColors.text.primary }}>{formatDate(selectedResult.nasc)}</span>
                </div>
                {calculateAge(selectedResult.nasc) !== null && (
                  <div>
                    <span style={{ color: currentColors.text.secondary }}>Idade: </span>
                    <span style={{ color: currentColors.text.primary }}>{calculateAge(selectedResult.nasc)} anos</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CPFPage;
