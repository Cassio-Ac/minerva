import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useSettingsStore } from '../stores/settingsStore';
import { getThemeColors } from '../utils/themeStyles';
import { API_URL, API_BASE_URL } from '../config/api';

interface Dashboard {
  id: string;
  title: string;
  description: string;
  index: string;
  widget_count: number;
  created_at: string;
  updated_at: string;
  tags: string[];
}

export default function DashboardList() {
  const { theme, currentColors } = useSettingsStore();
  const colors = currentColors;
  const navigate = useNavigate();
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboards();
  }, []);

  const fetchDashboards = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/dashboards/`);
      if (!response.ok) {
        throw new Error('Failed to fetch dashboards');
      }
      const data = await response.json();
      setDashboards(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNew = () => {
    navigate('/dashboard');
  };

  const handleOpenDashboard = (dashboardId: string) => {
    navigate(`/dashboard?id=${dashboardId}`);
  };

  const handleDeleteDashboard = async (dashboardId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Tem certeza que deseja excluir este dashboard?')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/dashboards/${dashboardId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error('Failed to delete dashboard');
      }
      // Refresh list
      fetchDashboards();
    } catch (err) {
      alert('Erro ao excluir dashboard: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="min-h-screen w-full overflow-x-hidden" style={{ backgroundColor: colors.bg.primary }}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold mb-2" style={{ color: colors.text.primary }}>
              Meus Dashboards
            </h1>
            <p style={{ color: colors.text.secondary }}>
              Gerencie seus dashboards salvos
            </p>
          </div>
          <div className="flex gap-4">
            <Link
              to="/"
              className="px-4 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: colors.bg.tertiary,
                color: colors.text.primary,
                border: `1px solid ${colors.border.default}`,
              }}
            >
              ← Voltar
            </Link>
            <button
              onClick={handleCreateNew}
              className="px-6 py-2 rounded-lg font-medium transition-colors"
              style={{
                backgroundColor: colors.accent.primary,
                color: colors.text.inverse,
              }}
            >
              + Novo Dashboard
            </button>
          </div>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4" style={{
              borderColor: colors.border.default,
              borderTopColor: colors.accent.primary,
            }}></div>
            <p className="mt-4" style={{ color: colors.text.secondary }}>
              Carregando dashboards...
            </p>
          </div>
        )}

        {/* Error State */}
        {error && !loading && (
          <div className="p-4 rounded-lg" style={{
            backgroundColor: '#fee2e2',
            border: '1px solid #ef4444',
          }}>
            <p style={{ color: '#ef4444' }}>
              Erro ao carregar dashboards: {error}
            </p>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && dashboards.length === 0 && (
          <div className="text-center py-12 rounded-lg" style={{
            backgroundColor: colors.bg.secondary,
            border: `1px solid ${colors.border.default}`,
          }}>
            <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: colors.text.muted }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <h3 className="text-xl font-semibold mb-2" style={{ color: colors.text.primary }}>
              Nenhum dashboard encontrado
            </h3>
            <p className="mb-6" style={{ color: colors.text.muted }}>
              Crie seu primeiro dashboard para começar
            </p>
            <button
              onClick={handleCreateNew}
              className="px-6 py-3 rounded-lg font-medium transition-colors"
              style={{
                backgroundColor: colors.accent.primary,
                color: colors.text.inverse,
              }}
            >
              Criar Primeiro Dashboard
            </button>
          </div>
        )}

        {/* Dashboards Grid */}
        {!loading && !error && dashboards.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {dashboards.map((dashboard) => (
              <div
                key={dashboard.id}
                onClick={() => handleOpenDashboard(dashboard.id)}
                className="rounded-lg p-6 cursor-pointer transition-all hover:shadow-lg"
                style={{
                  backgroundColor: colors.bg.secondary,
                  border: `1px solid ${colors.border.default}`,
                }}
              >
                {/* Dashboard Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold mb-1" style={{ color: colors.text.primary }}>
                      {dashboard.title}
                    </h3>
                    {dashboard.description && (
                      <p className="text-sm line-clamp-2" style={{ color: colors.text.secondary }}>
                        {dashboard.description}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={(e) => handleDeleteDashboard(dashboard.id, e)}
                    className="p-2 rounded-lg transition-colors hover:bg-red-500/20"
                    style={{ color: '#ef4444' }}
                    title="Excluir dashboard"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>

                {/* Dashboard Info */}
                <div className="space-y-2">
                  <div className="flex items-center text-sm" style={{ color: colors.text.muted }}>
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                    </svg>
                    {dashboard.widget_count} widget{dashboard.widget_count !== 1 ? 's' : ''}
                  </div>
                  <div className="flex items-center text-sm" style={{ color: colors.text.muted }}>
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                    </svg>
                    Índice: {dashboard.index}
                  </div>
                  <div className="flex items-center text-sm" style={{ color: colors.text.muted }}>
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Atualizado: {formatDate(dashboard.updated_at)}
                  </div>
                </div>

                {/* Tags */}
                {dashboard.tags && dashboard.tags.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {dashboard.tags.map((tag, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 text-xs rounded"
                        style={{
                          backgroundColor: colors.accent.primary + '20',
                          color: colors.accent.primary,
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
