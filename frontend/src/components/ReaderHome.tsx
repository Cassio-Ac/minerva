/**
 * ReaderHome Component
 * Home page para usuários leitores (reader) com lista de dashboards disponíveis
 */

import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useSettingsStore } from '@stores/settingsStore';
import { useAuthStore } from '@stores/authStore';
import { API_URL, API_BASE_URL } from '../config/api';

interface Dashboard {
  id: string;
  title: string;
  description: string;
  created_at: string;
  updated_at: string;
  widgets_count: number;
  owner_name?: string;
}

export const ReaderHome: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const { token, user } = useAuthStore();
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboards = async () => {
      try {
        const response = await fetch(`${API_URL}/dashboards`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const data = await response.json();
          setDashboards(data);
        }
      } catch (error) {
        console.error('Error fetching dashboards:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboards();
  }, [token]);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
              Dashboards Disponíveis
            </h1>
            <p className="text-lg" style={{ color: currentColors.text.secondary }}>
              Olá, {user?.full_name || user?.username} 👋
            </p>
          </div>
          <div className="text-6xl">
            📊
          </div>
        </div>
      </div>

      {/* Dashboards Grid */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <h2 className="text-2xl font-bold mb-6" style={{ color: currentColors.text.primary }}>
          📈 Visualizações
        </h2>

        {loading ? (
          <div className="text-center py-12" style={{ color: currentColors.text.muted }}>
            <div className="text-5xl mb-4">⏳</div>
            <p>Carregando dashboards...</p>
          </div>
        ) : dashboards.length === 0 ? (
          <div className="text-center py-12" style={{ color: currentColors.text.muted }}>
            <div className="text-5xl mb-4">📊</div>
            <h3 className="text-xl font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Nenhum dashboard disponível
            </h3>
            <p>Nenhum dashboard foi criado ainda.</p>
            <p className="text-sm mt-2">
              Entre em contato com um administrador para criar dashboards.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {dashboards.map((dash) => (
              <Link
                key={dash.id}
                to={`/dashboard?id=${dash.id}`}
                className="rounded-xl p-6 border hover:shadow-xl transition-all group"
                style={{
                  backgroundColor: currentColors.bg.tertiary,
                  borderColor: currentColors.border.default
                }}
              >
                {/* Dashboard Icon */}
                <div className="flex items-center justify-between mb-4">
                  <div className="text-4xl group-hover:scale-110 transition-transform">
                    📊
                  </div>
                  <div className="text-xs px-2 py-1 rounded" style={{
                    backgroundColor: currentColors.accent.primary + '20',
                    color: currentColors.accent.primary
                  }}>
                    {dash.widgets_count || 0} widgets
                  </div>
                </div>

                {/* Dashboard Title */}
                <h3 className="text-lg font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  {dash.title}
                </h3>

                {/* Dashboard Description */}
                <p className="text-sm mb-4 line-clamp-2" style={{ color: currentColors.text.muted }}>
                  {dash.description || 'Sem descrição'}
                </p>

                {/* Dashboard Meta */}
                <div className="flex items-center justify-between text-xs pt-4 border-t" style={{
                  borderColor: currentColors.border.default,
                  color: currentColors.text.muted
                }}>
                  <span>Atualizado em {formatDate(dash.updated_at)}</span>
                  <svg className="w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: currentColors.accent.primary }}>
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>

      {/* Info Section */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl p-6 border" style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}>
          <div className="text-3xl mb-3">👁️</div>
          <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
            Visualização
          </h3>
          <p className="text-sm" style={{ color: currentColors.text.muted }}>
            Você pode visualizar todos os dashboards disponíveis
          </p>
        </div>

        <div className="rounded-xl p-6 border" style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}>
          <div className="text-3xl mb-3">🔄</div>
          <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
            Tempo Real
          </h3>
          <p className="text-sm" style={{ color: currentColors.text.muted }}>
            Dashboards são atualizados em tempo real
          </p>
        </div>

        <div className="rounded-xl p-6 border" style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}>
          <div className="text-3xl mb-3">📥</div>
          <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
            Downloads
          </h3>
          <p className="text-sm" style={{ color: currentColors.text.muted }}>
            Acesse <Link to="/downloads" className="underline" style={{ color: currentColors.accent.primary }}>downloads</Link> para ver seus arquivos
          </p>
        </div>
      </div>
    </div>
  );
};
