/**
 * Elasticsearch Servers Manager
 * Página para gerenciar servidores Elasticsearch
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ElasticsearchServer, ESServerCreate } from '../types/elasticsearch';
import { esServerApi } from '../services/esServerApi';
import { useSettingsStore } from '@stores/settingsStore';

export function ESServersManager() {
  const navigate = useNavigate();
  const { currentColors } = useSettingsStore();
  const [servers, setServers] = useState<ElasticsearchServer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [testingServer, setTestingServer] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Carregar servidores
  useEffect(() => {
    loadServers();
  }, []);

  const loadServers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Carregar servidores sem stats primeiro (rápido)
      const data = await esServerApi.list(false, false);
      setServers(data);
      setIsLoading(false);

      // Depois, atualizar stats em background para servidores que já foram testados
      for (const server of data) {
        if (server.metadata.last_test_status === 'success') {
          try {
            const updated = await esServerApi.get(server.id);
            setServers((prev) =>
              prev.map((s) => (s.id === updated.id ? updated : s))
            );
          } catch (err) {
            console.warn(`Failed to update stats for ${server.name}:`, err);
          }
        }
      }
    } catch (err: any) {
      console.error('Error loading servers:', err);
      const errorMsg = err.response?.data?.detail || err.message || 'Erro ao carregar servidores';
      setError(errorMsg);
      setIsLoading(false);
    }
  };

  const handleTestConnection = async (serverId: string) => {
    setTestingServer(serverId);
    try {
      const result = await esServerApi.testConnection(serverId);

      if (result.success) {
        alert(`✅ Conexão bem-sucedida!\n\nVersão: ${result.version}\nCluster: ${result.cluster_name}\nHealth: ${result.cluster_health}`);
      } else {
        alert(`❌ Falha na conexão\n\n${result.error}`);
      }

      // Recarregar para atualizar metadata
      await loadServers();
    } catch (err: any) {
      alert(`❌ Erro ao testar conexão: ${err.message}`);
    } finally {
      setTestingServer(null);
    }
  };

  const handleDelete = async (serverId: string, serverName: string) => {
    if (!confirm(`Tem certeza que deseja deletar o servidor "${serverName}"?`)) {
      return;
    }

    try {
      await esServerApi.delete(serverId);
      await loadServers();
    } catch (err: any) {
      alert(`Erro ao deletar servidor: ${err.message}`);
    }
  };

  const handleSetDefault = async (serverId: string) => {
    try {
      await esServerApi.update(serverId, { is_default: true });
      await loadServers();
    } catch (err: any) {
      alert(`Erro ao definir servidor padrão: ${err.message}`);
    }
  };

  const getHealthColor = (health?: 'green' | 'yellow' | 'red' | null) => {
    switch (health) {
      case 'green': return 'text-green-600 bg-green-100';
      case 'yellow': return 'text-yellow-600 bg-yellow-100';
      case 'red': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: currentColors.bg.secondary }}>
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 mx-auto mb-4" style={{ borderColor: currentColors.accent.primary }}></div>
          <p style={{ color: currentColors.text.secondary }}>Carregando servidores...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <div className="shadow" style={{ backgroundColor: currentColors.bg.primary }}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-4">
              {/* Botão Voltar */}
              <button
                onClick={() => navigate('/')}
                className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
                style={{ color: currentColors.text.secondary }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                  e.currentTarget.style.color = currentColors.text.primary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = currentColors.text.secondary;
                }}
                title="Voltar ao menu"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
                <span className="font-medium">Menu</span>
              </button>

              <div className="h-8 w-px" style={{ backgroundColor: currentColors.border.default }}></div>

              <div>
                <h1 className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
                  Servidores Elasticsearch
                </h1>
                <p className="mt-1 text-sm" style={{ color: currentColors.text.muted }}>
                  Gerencie conexões com clusters Elasticsearch
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowAddForm(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Adicionar Servidor
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
            <p className="text-red-800">{error}</p>
          </div>
        )}

        {servers.length === 0 ? (
          <div className="rounded-lg shadow p-12 text-center" style={{ backgroundColor: currentColors.bg.primary }}>
            <svg className="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: currentColors.text.muted }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
            <h3 className="text-lg font-medium mb-2" style={{ color: currentColors.text.primary }}>
              Nenhum servidor cadastrado
            </h3>
            <p className="mb-6" style={{ color: currentColors.text.muted }}>
              Adicione seu primeiro servidor Elasticsearch para começar
            </p>
            <button
              onClick={() => setShowAddForm(true)}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Adicionar Servidor
            </button>
          </div>
        ) : (
          <div className="grid gap-6">
            {servers.map((server) => (
              <div
                key={server.id}
                className="rounded-lg shadow hover:shadow-md transition-shadow"
                style={{ backgroundColor: currentColors.bg.primary }}
              >
                <div className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                          {server.name}
                        </h3>
                        {server.is_default && (
                          <span className="px-2 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded">
                            Padrão
                          </span>
                        )}
                        {!server.is_active && (
                          <span className="px-2 py-1 bg-gray-100 text-gray-800 text-xs font-medium rounded">
                            Inativo
                          </span>
                        )}
                        {server.stats.cluster_health && (
                          <span className={`px-2 py-1 text-xs font-medium rounded ${getHealthColor(server.stats.cluster_health)}`}>
                            {server.stats.cluster_health.toUpperCase()}
                          </span>
                        )}
                      </div>

                      {server.description && (
                        <p className="mb-3" style={{ color: currentColors.text.secondary }}>{server.description}</p>
                      )}

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <p style={{ color: currentColors.text.muted }}>URL</p>
                          <p className="font-mono" style={{ color: currentColors.text.primary }}>{server.connection.url}</p>
                        </div>
                        <div>
                          <p style={{ color: currentColors.text.muted }}>Versão</p>
                          <p style={{ color: currentColors.text.primary }}>{server.metadata.version || 'N/A'}</p>
                        </div>
                        <div>
                          <p style={{ color: currentColors.text.muted }}>Índices</p>
                          <p style={{ color: currentColors.text.primary }}>{server.stats.total_indices.toLocaleString()}</p>
                        </div>
                        <div>
                          <p style={{ color: currentColors.text.muted }}>Documentos</p>
                          <p style={{ color: currentColors.text.primary }}>{server.stats.total_documents.toLocaleString()}</p>
                        </div>
                      </div>

                      {server.metadata.last_test && (
                        <div className="mt-3 text-xs" style={{ color: currentColors.text.muted }}>
                          Último teste: {new Date(server.metadata.last_test).toLocaleString()} -
                          <span className={server.metadata.last_test_status === 'success' ? 'text-green-600' : 'text-red-600'}>
                            {' '}{server.metadata.last_test_status === 'success' ? 'Sucesso' : 'Falha'}
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="flex gap-2 ml-4">
                      <button
                        onClick={() => handleTestConnection(server.id)}
                        disabled={testingServer === server.id}
                        className="px-3 py-2 text-sm bg-green-50 text-green-700 hover:bg-green-100 rounded-lg transition-colors disabled:opacity-50"
                        title="Testar Conexão"
                      >
                        {testingServer === server.id ? (
                          <div className="animate-spin h-4 w-4 border-2 border-green-700 border-t-transparent rounded-full"></div>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </button>

                      {!server.is_default && (
                        <button
                          onClick={() => handleSetDefault(server.id)}
                          className="px-3 py-2 text-sm bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg transition-colors"
                          title="Definir como Padrão"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                          </svg>
                        </button>
                      )}

                      <button
                        onClick={() => handleDelete(server.id, server.name)}
                        className="px-3 py-2 text-sm bg-red-50 text-red-700 hover:bg-red-100 rounded-lg transition-colors"
                        title="Deletar"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Server Modal */}
      {showAddForm && (
        <AddServerModal
          onClose={() => setShowAddForm(false)}
          onSuccess={() => {
            setShowAddForm(false);
            loadServers();
          }}
          currentColors={currentColors}
        />
      )}
    </div>
  );
}

// Modal para adicionar servidor
function AddServerModal({ onClose, onSuccess, currentColors }: { onClose: () => void; onSuccess: () => void; currentColors: any }) {
  const [formData, setFormData] = useState<ESServerCreate>({
    name: '',
    description: '',
    connection: {
      url: '',
      username: '',
      password: '',
      verify_ssl: true,
      timeout: 30,
    },
    is_default: false,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      await esServerApi.create(formData);
      onSuccess();
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Erro ao criar servidor');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto" style={{ backgroundColor: currentColors.bg.primary }}>
        <div className="p-6 border-b" style={{ borderColor: currentColors.border.default }}>
          <h2 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>Adicionar Servidor</h2>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <p className="text-red-800">{error}</p>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
              Nome *
            </label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary
              }}
              placeholder="Ex: Production Cluster"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
              Descrição
            </label>
            <textarea
              value={formData.description || ''}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary
              }}
              rows={2}
              placeholder="Descrição opcional do servidor"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
              URL *
            </label>
            <input
              type="text"
              required
              value={formData.connection.url}
              onChange={(e) => setFormData({
                ...formData,
                connection: { ...formData.connection, url: e.target.value }
              })}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary
              }}
              placeholder="https://elasticsearch.example.com:9200"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                Username
              </label>
              <input
                type="text"
                value={formData.connection.username || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  connection: { ...formData.connection, username: e.target.value }
                })}
                className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary
                }}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                Password
              </label>
              <input
                type="password"
                value={formData.connection.password || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  connection: { ...formData.connection, password: e.target.value }
                })}
                className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary
                }}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                Timeout (segundos)
              </label>
              <input
                type="number"
                min="5"
                max="300"
                value={formData.connection.timeout}
                onChange={(e) => setFormData({
                  ...formData,
                  connection: { ...formData.connection, timeout: parseInt(e.target.value) }
                })}
                className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary
                }}
              />
            </div>

            <div className="flex items-end">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.connection.verify_ssl}
                  onChange={(e) => setFormData({
                    ...formData,
                    connection: { ...formData.connection, verify_ssl: e.target.checked }
                  })}
                  className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
                  style={{ borderColor: currentColors.border.default }}
                />
                <span className="text-sm" style={{ color: currentColors.text.secondary }}>Verificar SSL</span>
              </label>
            </div>
          </div>

          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.is_default}
                onChange={(e) => setFormData({ ...formData, is_default: e.target.checked })}
                className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
                style={{ borderColor: currentColors.border.default }}
              />
              <span className="text-sm" style={{ color: currentColors.text.secondary }}>Definir como servidor padrão</span>
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t" style={{ borderColor: currentColors.border.default }}>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg transition-colors"
              style={{ color: currentColors.text.secondary }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Criando...' : 'Criar Servidor'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
