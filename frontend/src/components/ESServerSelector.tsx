/**
 * Elasticsearch Server Selector
 * Dropdown para selecionar servidor ES
 */

import { useState, useEffect } from 'react';
import { ElasticsearchServer } from '../types/elasticsearch';
import { esServerApi } from '../services/esServerApi';
import { useSettingsStore } from '@stores/settingsStore';

interface ESServerSelectorProps {
  selectedServerId?: string | null;
  onServerChange: (serverId: string) => void;
}

export function ESServerSelector({ selectedServerId, onServerChange }: ESServerSelectorProps) {
  const { currentColors } = useSettingsStore();
  const [servers, setServers] = useState<ElasticsearchServer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadServers();
  }, []);

  const loadServers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Buscar apenas servidores ativos
      const data = await esServerApi.list(true, false);
      setServers(data);

      // Se não tem servidor selecionado, usar o default
      if (!selectedServerId && data.length > 0) {
        const defaultServer = data.find((s) => s.is_default) || data[0];
        onServerChange(defaultServer.id);
      }
    } catch (err: any) {
      console.error('Error loading servers:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const selectedServer = servers.find((s) => s.id === selectedServerId);

  const getHealthColor = (health?: 'green' | 'yellow' | 'red' | null) => {
    switch (health) {
      case 'green':
        return 'bg-green-500';
      case 'yellow':
        return 'bg-yellow-500';
      case 'red':
        return 'bg-red-500';
      default:
        return 'bg-gray-400';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border" style={{
        backgroundColor: currentColors.bg.secondary,
        borderColor: currentColors.border.default
      }}>
        <div className="animate-spin h-4 w-4 border-2 border-t-transparent rounded-full" style={{
          borderColor: currentColors.accent.primary
        }}></div>
        <span className="text-sm" style={{ color: currentColors.text.secondary }}>Carregando servidores...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-red-50 rounded-lg border border-red-300">
        <svg className="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span className="text-sm text-red-800">Erro ao carregar servidores</span>
      </div>
    );
  }

  if (servers.length === 0) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-yellow-50 rounded-lg border border-yellow-300">
        <svg className="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        <span className="text-sm text-yellow-800">Nenhum servidor ativo</span>
      </div>
    );
  }

  return (
    <div className="relative">
      <select
        value={selectedServerId || ''}
        onChange={(e) => onServerChange(e.target.value)}
        className="appearance-none px-4 py-2 pr-10 border rounded-lg text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent cursor-pointer"
        style={{
          backgroundColor: currentColors.bg.secondary,
          borderColor: currentColors.border.default,
          color: currentColors.text.primary
        }}
      >
        {servers.map((server) => (
          <option key={server.id} value={server.id}>
            {server.name}
            {server.is_default && ' (Padrão)'}
            {server.stats.cluster_health && ` • ${server.stats.cluster_health.toUpperCase()}`}
          </option>
        ))}
      </select>

      {/* Ícone de dropdown */}
      <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: currentColors.text.muted }}>
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {/* Info do servidor selecionado */}
      {selectedServer && (
        <div className="absolute top-full mt-2 left-0 z-10 bg-white rounded-lg shadow-lg border border-gray-200 p-3 min-w-[280px] hidden group-hover:block">
          <div className="flex items-center gap-2 mb-2">
            <div className={`w-2 h-2 rounded-full ${getHealthColor(selectedServer.stats.cluster_health)}`}></div>
            <span className="font-semibold text-gray-900">{selectedServer.name}</span>
          </div>

          {selectedServer.description && (
            <p className="text-xs text-gray-600 mb-2">{selectedServer.description}</p>
          )}

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-gray-500">Cluster:</span>
              <p className="font-medium text-gray-900">{selectedServer.stats.cluster_name || 'N/A'}</p>
            </div>
            <div>
              <span className="text-gray-500">Versão:</span>
              <p className="font-medium text-gray-900">{selectedServer.metadata.version || 'N/A'}</p>
            </div>
            <div>
              <span className="text-gray-500">Índices:</span>
              <p className="font-medium text-gray-900">{selectedServer.stats.total_indices.toLocaleString()}</p>
            </div>
            <div>
              <span className="text-gray-500">Documentos:</span>
              <p className="font-medium text-gray-900">{selectedServer.stats.total_documents.toLocaleString()}</p>
            </div>
          </div>

          <div className="mt-2 pt-2 border-t border-gray-200">
            <p className="text-xs text-gray-500 font-mono truncate">{selectedServer.connection.url}</p>
          </div>
        </div>
      )}
    </div>
  );
}
