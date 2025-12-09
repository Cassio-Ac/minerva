/**
 * IOC Browser Page - Dashboard com Widgets
 * Visualize distribuição de IOCs por tipo, feed, TLP e confidence
 * Clique nos widgets para navegar e filtrar IOCs
 */

import React, { useState, useEffect } from 'react';
import {
  Database,
  Globe,
  Hash,
  Mail,
  Link as LinkIcon,
  Shield,
  AlertCircle,
  Loader2,
  TrendingUp,
  Filter,
  X,
  Calendar,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import mispFeedsService, { IOCStats, MISPIoC } from '../../services/cti/mispFeedsService';

const IOCBrowserPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Stats
  const [stats, setStats] = useState<IOCStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filtered IOCs
  const [filteredIOCs, setFilteredIOCs] = useState<MISPIoC[]>([]);
  const [loadingIOCs, setLoadingIOCs] = useState(false);
  const [currentFilter, setCurrentFilter] = useState<{
    type: string;
    value: string;
  } | null>(null);

  // Pagination for filtered IOCs
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const limit = 20;

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await mispFeedsService.getStats();
      setStats(data);
    } catch (err: any) {
      setError(`Erro ao carregar estatísticas: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleWidgetClick = async (filterType: string, filterValue: string) => {
    setCurrentFilter({ type: filterType, value: filterValue });
    setPage(0);
    await loadFilteredIOCs(filterType, filterValue, 0);
  };

  const loadFilteredIOCs = async (filterType: string, filterValue: string, pageNum: number) => {
    setLoadingIOCs(true);
    try {
      const params: any = {
        limit,
        offset: pageNum * limit,
      };

      if (filterType === 'type') {
        params.ioc_type = filterValue;
      } else if (filterType === 'feed') {
        // Buscar feed_id pelo nome
        const feeds = await mispFeedsService.listFeeds();
        const feed = feeds.find((f: any) => f.name === filterValue);
        if (feed) {
          params.feed_id = feed.id;
        }
      }

      const response = await mispFeedsService.listIOCs(params);
      setFilteredIOCs(response.iocs);
      setTotal(response.total);
    } catch (err) {
      console.error('Error loading filtered IOCs:', err);
    } finally {
      setLoadingIOCs(false);
    }
  };

  const clearFilter = () => {
    setCurrentFilter(null);
    setFilteredIOCs([]);
    setTotal(0);
    setPage(0);
  };

  const getTypeIcon = (type: string, size: number = 20) => {
    switch (type) {
      case 'ip':
        return <Globe size={size} />;
      case 'domain':
        return <Globe size={size} />;
      case 'url':
        return <LinkIcon size={size} />;
      case 'hash':
        return <Hash size={size} />;
      case 'email':
        return <Mail size={size} />;
      default:
        return <Database size={size} />;
    }
  };

  const getTypeColor = (type: string): string => {
    switch (type) {
      case 'ip':
        return '#3b82f6'; // blue
      case 'url':
        return '#8b5cf6'; // purple
      case 'hash':
        return '#06b6d4'; // cyan
      case 'domain':
        return '#10b981'; // green
      case 'email':
        return '#f59e0b'; // orange
      default:
        return '#6b7280'; // gray
    }
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center" style={{ backgroundColor: currentColors.bg.secondary }}>
        <Loader2 className="animate-spin" size={48} style={{ color: currentColors.accent.primary }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
        <div className="p-4 rounded-lg flex items-start gap-3" style={{ backgroundColor: '#fee2e2' }}>
          <AlertCircle size={20} color="#dc2626" />
          <div className="flex-1">
            <p className="text-sm" style={{ color: '#991b1b' }}>{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="h-full p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
        <div className="p-6 rounded-lg text-center" style={{ backgroundColor: currentColors.bg.primary }}>
          <Database size={48} className="mx-auto mb-4" style={{ color: currentColors.text.secondary }} />
          <p style={{ color: currentColors.text.secondary }}>Nenhum IOC encontrado. Sincronize feeds primeiro.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Database size={32} style={{ color: currentColors.text.primary }} />
          <h1 className="text-3xl font-semibold" style={{ color: currentColors.text.primary }}>
            IOC Browser
          </h1>
        </div>
        <p className="text-sm" style={{ color: currentColors.text.secondary }}>
          Navegue pelos {stats.total_iocs.toLocaleString()} IOCs salvos. Clique nos widgets para filtrar e visualizar.
        </p>
      </div>

      {/* Overall Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <div className="flex items-center gap-3 mb-2">
            <Database size={20} style={{ color: currentColors.accent.primary }} />
            <p className="text-xs font-semibold" style={{ color: currentColors.text.secondary }}>Total IOCs</p>
          </div>
          <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
            {stats.total_iocs.toLocaleString()}
          </p>
        </div>

        <div className="p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <div className="flex items-center gap-3 mb-2">
            <Shield size={20} style={{ color: currentColors.accent.secondary }} />
            <p className="text-xs font-semibold" style={{ color: currentColors.text.secondary }}>Feeds Ativos</p>
          </div>
          <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
            {stats.feeds_count}
          </p>
        </div>

        <div className="p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp size={20} style={{ color: '#10b981' }} />
            <p className="text-xs font-semibold" style={{ color: currentColors.text.secondary }}>Tipos de IOC</p>
          </div>
          <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
            {Object.keys(stats.by_type).length}
          </p>
        </div>

        <div className="p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <div className="flex items-center gap-3 mb-2">
            <Calendar size={20} style={{ color: '#f59e0b' }} />
            <p className="text-xs font-semibold" style={{ color: currentColors.text.secondary }}>Última Sync</p>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.primary }}>
            {stats.last_sync ? new Date(stats.last_sync).toLocaleDateString('pt-BR') : 'N/A'}
          </p>
        </div>
      </div>

      {/* IOCs by Type - Clickable Widgets */}
      <div className="mb-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: currentColors.text.primary }}>
          <Filter size={20} />
          IOCs por Tipo (clique para filtrar)
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {Object.entries(stats.by_type)
            .sort(([, a], [, b]) => (b as number) - (a as number))
            .map(([type, count]) => (
              <button
                key={type}
                onClick={() => handleWidgetClick('type', type)}
                className="p-4 rounded-lg border-2 hover:shadow-lg transition-all text-left"
                style={{
                  backgroundColor: currentColors.bg.primary,
                  borderColor: currentFilter?.type === 'type' && currentFilter?.value === type
                    ? getTypeColor(type)
                    : currentColors.border.default,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = getTypeColor(type);
                  e.currentTarget.style.transform = 'translateY(-2px)';
                }}
                onMouseLeave={(e) => {
                  if (!(currentFilter?.type === 'type' && currentFilter?.value === type)) {
                    e.currentTarget.style.borderColor = currentColors.border.default;
                  }
                  e.currentTarget.style.transform = 'translateY(0)';
                }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div style={{ color: getTypeColor(type) }}>
                    {getTypeIcon(type, 24)}
                  </div>
                  <p className="text-xs font-semibold uppercase" style={{ color: currentColors.text.secondary }}>
                    {type}
                  </p>
                </div>
                <p className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                  {(count as number).toLocaleString()}
                </p>
                <p className="text-xs mt-1" style={{ color: currentColors.text.secondary }}>
                  {((count as number / stats.total_iocs) * 100).toFixed(1)}%
                </p>
              </button>
            ))}
        </div>
      </div>

      {/* IOCs by Feed - Clickable Widgets */}
      {Object.keys(stats.by_feed).length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: currentColors.text.primary }}>
            <Shield size={20} />
            IOCs por Feed (clique para filtrar)
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(stats.by_feed)
              .sort(([, a], [, b]) => (b as number) - (a as number))
              .slice(0, 9)
              .map(([feed, count]) => (
                <button
                  key={feed}
                  onClick={() => handleWidgetClick('feed', feed)}
                  className="p-4 rounded-lg border-2 hover:shadow-lg transition-all text-left"
                  style={{
                    backgroundColor: currentColors.bg.primary,
                    borderColor: currentFilter?.type === 'feed' && currentFilter?.value === feed
                      ? currentColors.accent.primary
                      : currentColors.border.default,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = currentColors.accent.primary;
                    e.currentTarget.style.transform = 'translateY(-2px)';
                  }}
                  onMouseLeave={(e) => {
                    if (!(currentFilter?.type === 'feed' && currentFilter?.value === feed)) {
                      e.currentTarget.style.borderColor = currentColors.border.default;
                    }
                    e.currentTarget.style.transform = 'translateY(0)';
                  }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <Shield size={20} style={{ color: currentColors.accent.primary }} />
                    <p className="text-sm font-semibold truncate" style={{ color: currentColors.text.primary }}>
                      {feed}
                    </p>
                  </div>
                  <p className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                    {(count as number).toLocaleString()}
                  </p>
                  <p className="text-xs mt-1" style={{ color: currentColors.text.secondary }}>
                    {((count as number / stats.total_iocs) * 100).toFixed(1)}% do total
                  </p>
                </button>
              ))}
          </div>
        </div>
      )}

      {/* Filtered IOCs Section */}
      {currentFilter && (
        <div className="mt-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: currentColors.text.primary }}>
              <Database size={20} />
              IOCs Filtrados: {currentFilter.value}
              <span className="text-sm font-normal" style={{ color: currentColors.text.secondary }}>
                ({total} total)
              </span>
            </h2>
            <button
              onClick={clearFilter}
              className="px-3 py-1 rounded flex items-center gap-2 hover:opacity-80"
              style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary }}
            >
              <X size={16} />
              Limpar Filtro
            </button>
          </div>

          {loadingIOCs ? (
            <div className="p-12 text-center" style={{ backgroundColor: currentColors.bg.primary }}>
              <Loader2 className="animate-spin mx-auto mb-4" size={32} style={{ color: currentColors.accent.primary }} />
              <p style={{ color: currentColors.text.secondary }}>Carregando IOCs...</p>
            </div>
          ) : filteredIOCs.length === 0 ? (
            <div className="p-12 text-center rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
              <Database size={48} className="mx-auto mb-4" style={{ color: currentColors.text.secondary }} />
              <p style={{ color: currentColors.text.secondary }}>Nenhum IOC encontrado.</p>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-3">
                {filteredIOCs.map((ioc, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg border"
                    style={{
                      backgroundColor: currentColors.bg.primary,
                      borderColor: currentColors.border.default,
                    }}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span
                            className="px-2 py-1 rounded text-xs font-semibold"
                            style={{ backgroundColor: getTypeColor(ioc.type), color: '#fff' }}
                          >
                            {getTypeIcon(ioc.type, 14)}
                            <span className="ml-1">{ioc.type.toUpperCase()}</span>
                          </span>
                          {ioc.tlp && (
                            <span
                              className="px-2 py-1 rounded text-xs"
                              style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.secondary }}
                            >
                              TLP:{ioc.tlp}
                            </span>
                          )}
                        </div>
                        <p className="font-mono text-sm mb-2" style={{ color: currentColors.text.primary }}>
                          {ioc.value}
                        </p>
                        {ioc.context && (
                          <p className="text-xs" style={{ color: currentColors.text.secondary }}>
                            {ioc.context}
                          </p>
                        )}
                        {ioc.tags && ioc.tags.length > 0 && (
                          <div className="flex gap-2 flex-wrap mt-2">
                            {ioc.tags.slice(0, 5).map((tag, i) => (
                              <span
                                key={i}
                                className="px-2 py-1 rounded text-xs border"
                                style={{
                                  borderColor: currentColors.border.primary,
                                  color: currentColors.text.secondary,
                                }}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {total > limit && (
                <div className="flex items-center justify-between mt-4">
                  <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                    Mostrando {page * limit + 1}-{Math.min((page + 1) * limit, total)} de {total}
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        const newPage = page - 1;
                        setPage(newPage);
                        loadFilteredIOCs(currentFilter.type, currentFilter.value, newPage);
                      }}
                      disabled={page === 0}
                      className="px-4 py-2 rounded disabled:opacity-50 hover:opacity-80"
                      style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary }}
                    >
                      Anterior
                    </button>
                    <button
                      onClick={() => {
                        const newPage = page + 1;
                        setPage(newPage);
                        loadFilteredIOCs(currentFilter.type, currentFilter.value, newPage);
                      }}
                      disabled={(page + 1) * limit >= total}
                      className="px-4 py-2 rounded disabled:opacity-80"
                      style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary }}
                    >
                      Próxima
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default IOCBrowserPage;
