/**
 * IndexMCPConfigManager Component
 * Gerencia configuração de MCPs por índice do Elasticsearch
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '../services/api';
import { IndexSelector } from './IndexSelector';

interface IndexMCPConfig {
  id: string;
  es_server_id: string;
  index_name: string;
  mcp_server_id: string;
  priority: number;
  is_enabled: boolean;
  auto_inject_context: boolean;
  config: Record<string, any> | null;
  created_at: string;
  updated_at: string;
}

interface ESServer {
  id: string;
  name: string;
  url: string;
}

interface MCPServer {
  id: string;
  name: string;
  description?: string;
}

export const IndexMCPConfigManager: React.FC = () => {
  const { currentColors } = useSettingsStore();

  const [configs, setConfigs] = useState<IndexMCPConfig[]>([]);
  const [esServers, setEsServers] = useState<ESServer[]>([]);
  const [mcpServers, setMcpServers] = useState<MCPServer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    es_server_id: '',
    index_name: '',
    mcp_server_id: '',
    priority: 10,
    is_enabled: true,
    auto_inject_context: true,
  });

  // Carregar dados iniciais
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);

    try {
      console.log('🔍 [IndexMCPConfig] Loading data...');

      // Carregar ES servers, MCP servers e configs em paralelo
      const [configsRes, esRes, mcpRes] = await Promise.all([
        api.get('/index-mcp-config/'),
        api.get('/es-servers/'),
        api.get('/mcp-servers/'),
      ]);

      console.log('✅ [IndexMCPConfig] Configs:', configsRes.data);
      console.log('✅ [IndexMCPConfig] ES Servers:', esRes.data);
      console.log('✅ [IndexMCPConfig] MCP Servers:', mcpRes.data);

      setConfigs(configsRes.data);
      setEsServers(esRes.data);
      setMcpServers(mcpRes.data);
    } catch (err: any) {
      console.error('❌ [IndexMCPConfig] Error loading data:', err);
      console.error('❌ [IndexMCPConfig] Error response:', err.response);
      console.error('❌ [IndexMCPConfig] Error status:', err.response?.status);
      console.error('❌ [IndexMCPConfig] Error detail:', err.response?.data?.detail);
      setError(err.response?.data?.detail || err.message || 'Erro ao carregar dados');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAdd = async () => {
    try {
      await api.post('/index-mcp-config/', formData);
      setShowAddModal(false);
      setFormData({
        es_server_id: '',
        index_name: '',
        mcp_server_id: '',
        priority: 10,
        is_enabled: true,
        auto_inject_context: true,
      });
      loadData();
    } catch (err: any) {
      alert('Erro ao adicionar configuração: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleToggleEnabled = async (config: IndexMCPConfig) => {
    try {
      await api.patch(`/index-mcp-config/${config.id}`, {
        is_enabled: !config.is_enabled,
      });
      loadData();
    } catch (err: any) {
      alert('Erro ao atualizar: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleDelete = async (configId: string) => {
    if (!confirm('Deseja realmente deletar esta configuração?')) return;

    try {
      await api.delete(`/index-mcp-config/${configId}`);
      loadData();
    } catch (err: any) {
      alert('Erro ao deletar: ' + (err.response?.data?.detail || err.message));
    }
  };

  const getServerName = (serverId: string) => {
    return esServers.find((s) => s.id === serverId)?.name || serverId;
  };

  const getMCPName = (mcpId: string) => {
    return mcpServers.find((m) => m.id === mcpId)?.name || mcpId;
  };

  // Agrupar configs por índice
  const groupedConfigs = configs.reduce((acc, config) => {
    const key = `${config.es_server_id}::${config.index_name}`;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(config);
    return acc;
  }, {} as Record<string, IndexMCPConfig[]>);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-lg" style={{ color: currentColors.text.secondary }}>
          Carregando...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
            🔧 Configuração de MCPs por Índice
          </h2>
          <p className="text-sm mt-1" style={{ color: currentColors.text.muted }}>
            Configure quais MCP servers usar para cada índice do Elasticsearch
          </p>
          <div
            className="text-xs mt-2 px-3 py-2 rounded-lg border inline-block"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default,
              color: currentColors.text.muted
            }}
          >
            🔒 <strong>Modo Restritivo:</strong> MCPs só são usados se configurados. Suporta wildcards (<code>logs-*</code>).
          </div>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 rounded-lg font-medium transition-colors"
          style={{
            backgroundColor: currentColors.accent.primary,
            color: currentColors.text.inverse,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = currentColors.accent.primary;
          }}
        >
          ➕ Adicionar Configuração
        </button>
      </div>

      {error && (
        <div
          className="rounded-lg p-4 border"
          style={{
            backgroundColor: currentColors.accent.error + '20',
            borderColor: currentColors.accent.error,
            color: currentColors.accent.error,
          }}
        >
          {error}
        </div>
      )}

      {/* Lista de Configurações Agrupadas */}
      {Object.keys(groupedConfigs).length === 0 ? (
        <div
          className="text-center p-8 rounded-lg border"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <p className="text-lg" style={{ color: currentColors.text.muted }}>
            Nenhuma configuração cadastrada
          </p>
          <p className="text-sm mt-2" style={{ color: currentColors.text.muted }}>
            Adicione configurações para conectar MCPs a índices específicos
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(groupedConfigs).map(([key, indexConfigs]) => {
            const [esServerId, indexName] = key.split('::');
            const serverName = getServerName(esServerId);

            return (
              <div
                key={key}
                className="rounded-lg border p-4"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                      📊 {indexName}
                    </h3>
                    <p className="text-sm" style={{ color: currentColors.text.muted }}>
                      Servidor: {serverName}
                    </p>
                  </div>
                </div>

                {/* Lista de MCPs para este índice */}
                <div className="space-y-2">
                  {indexConfigs
                    .sort((a, b) => a.priority - b.priority)
                    .map((config) => (
                      <div
                        key={config.id}
                        className="flex items-center justify-between p-3 rounded-lg border"
                        style={{
                          backgroundColor: currentColors.bg.tertiary,
                          borderColor: currentColors.border.default,
                          opacity: config.is_enabled ? 1 : 0.6,
                        }}
                      >
                        <div className="flex items-center gap-4">
                          {/* Priority Badge */}
                          <div
                            className="w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm"
                            style={{
                              backgroundColor: currentColors.accent.primary + '30',
                              color: currentColors.accent.primary,
                            }}
                          >
                            {config.priority}
                          </div>

                          {/* MCP Info */}
                          <div>
                            <div className="font-medium" style={{ color: currentColors.text.primary }}>
                              {getMCPName(config.mcp_server_id)}
                            </div>
                            <div className="text-xs space-x-3" style={{ color: currentColors.text.muted }}>
                              <span>{config.is_enabled ? '✅ Ativo' : '❌ Inativo'}</span>
                              <span>{config.auto_inject_context ? '🤖 Auto-inject' : '🔧 Manual'}</span>
                            </div>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleToggleEnabled(config)}
                            className="p-2 rounded-lg transition-colors"
                            style={{ color: currentColors.text.secondary }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.backgroundColor = 'transparent';
                            }}
                            title={config.is_enabled ? 'Desativar' : 'Ativar'}
                          >
                            {config.is_enabled ? '⏸️' : '▶️'}
                          </button>
                          <button
                            onClick={() => handleDelete(config.id)}
                            className="p-2 rounded-lg transition-colors"
                            style={{ color: currentColors.accent.error }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.backgroundColor = currentColors.accent.error + '20';
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.backgroundColor = 'transparent';
                            }}
                            title="Deletar"
                          >
                            🗑️
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Modal de Adicionar */}
      {showAddModal && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black bg-opacity-50 z-50"
            onClick={() => setShowAddModal(false)}
          />

          {/* Modal */}
          <div
            className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md rounded-xl shadow-2xl p-6"
            style={{
              backgroundColor: currentColors.bg.primary,
              border: `1px solid ${currentColors.border.default}`,
            }}
          >
            <h3 className="text-xl font-bold mb-4" style={{ color: currentColors.text.primary }}>
              ➕ Adicionar Configuração
            </h3>

            <div className="space-y-4">
              {/* ES Server */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Servidor Elasticsearch
                </label>
                <select
                  value={formData.es_server_id}
                  onChange={(e) => setFormData({ ...formData, es_server_id: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <option value="">Selecione...</option>
                  {esServers.map((server) => (
                    <option key={server.id} value={server.id}>
                      {server.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Index Name */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Nome do Índice ou Padrão
                </label>
                <IndexSelector
                  serverId={formData.es_server_id}
                  selectedIndex={formData.index_name}
                  onIndexChange={(index) => setFormData({ ...formData, index_name: index })}
                />
                <p className="text-xs mt-2" style={{ color: currentColors.text.muted }}>
                  ✨ Suporta wildcards: <code style={{
                    backgroundColor: currentColors.bg.tertiary,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontFamily: 'monospace'
                  }}>logs-*</code> para todos os índices que começam com "logs-"
                </p>
              </div>

              {/* MCP Server */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  MCP Server
                </label>
                <select
                  value={formData.mcp_server_id}
                  onChange={(e) => setFormData({ ...formData, mcp_server_id: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <option value="">Selecione...</option>
                  {mcpServers.map((mcp) => (
                    <option key={mcp.id} value={mcp.id}>
                      {mcp.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Priority */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Prioridade (menor = maior prioridade)
                </label>
                <input
                  type="number"
                  value={formData.priority}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                  min={1}
                  max={100}
                />
              </div>

              {/* Checkboxes */}
              <div className="space-y-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.is_enabled}
                    onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                    className="w-4 h-4 rounded"
                    style={{ accentColor: currentColors.accent.primary }}
                  />
                  <span className="text-sm" style={{ color: currentColors.text.primary }}>
                    Ativo
                  </span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.auto_inject_context}
                    onChange={(e) => setFormData({ ...formData, auto_inject_context: e.target.checked })}
                    className="w-4 h-4 rounded"
                    style={{ accentColor: currentColors.accent.primary }}
                  />
                  <span className="text-sm" style={{ color: currentColors.text.primary }}>
                    Auto-inject no contexto do LLM
                  </span>
                </label>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="flex-1 px-4 py-2 rounded-lg transition-colors"
                style={{
                  backgroundColor: currentColors.bg.tertiary,
                  color: currentColors.text.primary,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
                }}
              >
                Cancelar
              </button>
              <button
                onClick={handleAdd}
                disabled={!formData.es_server_id || !formData.index_name || !formData.mcp_server_id}
                className="flex-1 px-4 py-2 rounded-lg font-medium transition-colors"
                style={{
                  backgroundColor: currentColors.accent.primary,
                  color: currentColors.text.inverse,
                  opacity: (!formData.es_server_id || !formData.index_name || !formData.mcp_server_id) ? 0.5 : 1,
                }}
                onMouseEnter={(e) => {
                  if (formData.es_server_id && formData.index_name && formData.mcp_server_id) {
                    e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                  }
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                }}
              >
                💾 Salvar
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
