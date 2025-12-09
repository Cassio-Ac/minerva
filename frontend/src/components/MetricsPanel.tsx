/**
 * MetricsPanel Component
 * Dashboard de métricas do sistema
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '../services/api';

interface MetricsSummary {
  period_hours: number;
  total_requests: number;
  avg_response_time_ms: number;
  total_errors: number;
  error_rate_percent: number;
  avg_cache_hit_rate_percent: number;
  active_users: number;
  timestamp: string;
}

export const MetricsPanel: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [period, setPeriod] = useState(24); // horas

  useEffect(() => {
    loadMetrics();
    // Atualizar a cada 30 segundos
    const interval = setInterval(loadMetrics, 30000);
    return () => clearInterval(interval);
  }, [period]);

  const loadMetrics = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await api['client'].get(`/metrics/summary?hours=${period}`);
      setMetrics(response.data);
    } catch (err: any) {
      console.error('Error loading metrics:', err);
      setError(err.response?.data?.detail || 'Erro ao carregar métricas');
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading && !metrics) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-lg" style={{ color: currentColors.text.secondary }}>
          Carregando métricas...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div
          className="rounded-lg p-4 border"
          style={{
            backgroundColor: currentColors.accent.error + '20',
            borderColor: currentColors.accent.error,
            color: currentColors.accent.error,
          }}
        >
          ⚠️ {error}
        </div>
      </div>
    );
  }

  if (!metrics) return null;

  // Calcular últimas N horas em texto
  const periodText = period === 24 ? 'últimas 24h' :
                     period === 168 ? 'últimos 7 dias' :
                     `últimas ${period}h`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
            📊 Métricas do Sistema
          </h2>
          <p className="text-sm mt-1" style={{ color: currentColors.text.muted }}>
            Monitoramento de performance e uso ({periodText})
          </p>
        </div>

        {/* Period Selector */}
        <div className="flex items-center gap-2">
          <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
            Período:
          </label>
          <select
            value={period}
            onChange={(e) => setPeriod(Number(e.target.value))}
            className="px-3 py-2 rounded-lg border"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              borderColor: currentColors.border.default,
            }}
          >
            <option value={1}>Última hora</option>
            <option value={6}>Últimas 6h</option>
            <option value={24}>Últimas 24h</option>
            <option value={168}>Últimos 7 dias</option>
          </select>
          <button
            onClick={loadMetrics}
            className="px-3 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
            title="Atualizar"
          >
            🔄
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Requests */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <div className="text-3xl">📈</div>
            <div
              className="px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: currentColors.accent.primary + '20',
                color: currentColors.accent.primary,
              }}
            >
              Uso
            </div>
          </div>
          <div className="text-3xl font-bold mb-1" style={{ color: currentColors.text.primary }}>
            {metrics.total_requests.toLocaleString()}
          </div>
          <div className="text-sm" style={{ color: currentColors.text.muted }}>
            Total de Requisições
          </div>
        </div>

        {/* Response Time */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <div className="text-3xl">⚡</div>
            <div
              className="px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: '#10b981' + '20',
                color: '#10b981',
              }}
            >
              Performance
            </div>
          </div>
          <div className="text-3xl font-bold mb-1" style={{ color: currentColors.text.primary }}>
            {metrics.avg_response_time_ms.toFixed(0)}ms
          </div>
          <div className="text-sm" style={{ color: currentColors.text.muted }}>
            Tempo Médio de Resposta
          </div>
        </div>

        {/* Error Rate */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <div className="text-3xl">⚠️</div>
            <div
              className="px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: metrics.error_rate_percent > 5
                  ? currentColors.accent.error + '20'
                  : '#10b981' + '20',
                color: metrics.error_rate_percent > 5
                  ? currentColors.accent.error
                  : '#10b981',
              }}
            >
              Erros
            </div>
          </div>
          <div className="text-3xl font-bold mb-1" style={{ color: currentColors.text.primary }}>
            {metrics.error_rate_percent.toFixed(2)}%
          </div>
          <div className="text-sm" style={{ color: currentColors.text.muted }}>
            Taxa de Erro ({metrics.total_errors} erros)
          </div>
        </div>

        {/* Cache Hit Rate */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <div className="text-3xl">💾</div>
            <div
              className="px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: '#8b5cf6' + '20',
                color: '#8b5cf6',
              }}
            >
              Cache
            </div>
          </div>
          <div className="text-3xl font-bold mb-1" style={{ color: currentColors.text.primary }}>
            {metrics.avg_cache_hit_rate_percent.toFixed(1)}%
          </div>
          <div className="text-sm" style={{ color: currentColors.text.muted }}>
            Taxa de Acerto do Cache
          </div>
        </div>
      </div>

      {/* Additional Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Active Users */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center gap-4">
            <div className="text-4xl">👥</div>
            <div className="flex-1">
              <div className="text-2xl font-bold mb-1" style={{ color: currentColors.text.primary }}>
                {metrics.active_users}
              </div>
              <div className="text-sm" style={{ color: currentColors.text.muted }}>
                Usuários Ativos
              </div>
            </div>
          </div>
        </div>

        {/* Last Update */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center gap-4">
            <div className="text-4xl">🕐</div>
            <div className="flex-1">
              <div className="text-lg font-bold mb-1" style={{ color: currentColors.text.primary }}>
                {new Date(metrics.timestamp).toLocaleTimeString('pt-BR')}
              </div>
              <div className="text-sm" style={{ color: currentColors.text.muted }}>
                Última Atualização
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Info Banner */}
      <div
        className="rounded-lg p-4 border"
        style={{
          backgroundColor: currentColors.accent.primary + '10',
          borderColor: currentColors.accent.primary + '30',
        }}
      >
        <div className="flex items-start gap-3">
          <div className="text-xl">ℹ️</div>
          <div>
            <div className="font-medium mb-1" style={{ color: currentColors.text.primary }}>
              Sobre as Métricas
            </div>
            <div className="text-sm" style={{ color: currentColors.text.secondary }}>
              As métricas são coletadas automaticamente e atualizadas a cada 30 segundos.
              Dados históricos são mantidos por 30 dias.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
