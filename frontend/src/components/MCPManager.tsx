/**
 * MCP Manager Component
 * Gerenciamento de servidores MCP (Model Context Protocol)
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { API_URL, API_BASE_URL } from '../config/api';

interface MCPServer {
  id: string;
  name: string;
  type: 'stdio' | 'sse' | 'http';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export const MCPManager: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    type: 'stdio' as 'stdio' | 'sse' | 'http',
    command: '',
    args: '',
    env: '',
    url: '',
    description: '',
  });

  // Carregar MCPs do backend
  useEffect(() => {
    loadServers();
  }, []);

  const loadServers = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(`${API_URL}/mcp-servers`);

      if (response.ok) {
        const data = await response.json();
        setServers(data);
      } else {
        setError('Erro ao carregar servidores MCP');
      }
    } catch (err) {
      setError('Erro de conexão com o servidor');
      console.error('Error loading MCP servers:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAddServer = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const payload: any = {
        name: formData.name,
        type: formData.type,
        description: formData.description || undefined,
      };

      // Configuração específica por tipo
      if (formData.type === 'stdio') {
        payload.command = formData.command;
        payload.args = formData.args ? formData.args.split(',').map(s => s.trim()) : [];
        payload.env = formData.env ? JSON.parse(formData.env) : undefined;
      } else if (formData.type === 'http' || formData.type === 'sse') {
        payload.url = formData.url;
      }

      const response = await fetch(`${API_URL}/mcp-servers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        await loadServers();
        setShowAddForm(false);
        resetForm();
      } else {
        const error = await response.json();
        setError(error.detail || 'Erro ao adicionar servidor MCP');
      }
    } catch (err) {
      setError('Erro ao adicionar servidor MCP');
      console.error('Error adding MCP server:', err);
    }
  };

  const handleToggleActive = async (serverId: string, isActive: boolean) => {
    try {
      const response = await fetch(`${API_URL}/mcp-servers/${serverId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: !isActive }),
      });

      if (response.ok) {
        await loadServers();
      } else {
        setError('Erro ao atualizar servidor MCP');
      }
    } catch (err) {
      setError('Erro ao atualizar servidor MCP');
      console.error('Error toggling MCP server:', err);
    }
  };

  const handleDeleteServer = async (serverId: string) => {
    if (!confirm('Tem certeza que deseja remover este servidor MCP?')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/mcp-servers/${serverId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        await loadServers();
      } else {
        setError('Erro ao remover servidor MCP');
      }
    } catch (err) {
      setError('Erro ao remover servidor MCP');
      console.error('Error deleting MCP server:', err);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      type: 'stdio',
      command: '',
      args: '',
      env: '',
      url: '',
      description: '',
    });
  };

  const getMCPTypeIcon = (type: string) => {
    switch (type) {
      case 'stdio':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        );
      case 'http':
      case 'sse':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
        );
      default:
        return null;
    }
  };

  return (
    <div>
      {/* Error Alert */}
      {error && (
        <div className="mb-4 p-4 rounded-lg border-l-4" style={{
          backgroundColor: currentColors.bg.secondary,
          borderColor: '#ef4444',
        }}>
          <div className="flex items-center justify-between">
            <p style={{ color: '#ef4444' }}>{error}</p>
            <button
              onClick={() => setError(null)}
              style={{ color: '#ef4444' }}
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>
      )}

      {/* Add Button */}
      <div className="mb-6">
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
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
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {showAddForm ? 'Cancelar' : 'Adicionar Servidor MCP'}
        </button>
      </div>

      {/* Add Form */}
      {showAddForm && (
        <div
          className="mb-6 p-6 rounded-lg border"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
            Novo Servidor MCP
          </h3>

          <form onSubmit={handleAddServer} className="space-y-4">
            {/* Nome */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                Nome *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
                placeholder="Ex: filesystem, github, postgres"
                required
              />
            </div>

            {/* Tipo */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                Tipo de Conexão *
              </label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value as any })}
                className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
              >
                <option value="stdio">STDIO (Processo local)</option>
                <option value="http">HTTP (API REST)</option>
                <option value="sse">SSE (Server-Sent Events)</option>
              </select>
            </div>

            {/* Configuração STDIO */}
            {formData.type === 'stdio' && (
              <>
                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                    Comando *
                  </label>
                  <input
                    type="text"
                    value={formData.command}
                    onChange={(e) => setFormData({ ...formData, command: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      borderColor: currentColors.border.default,
                      color: currentColors.text.primary,
                    }}
                    placeholder="npx, python, node"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                    Argumentos (separados por vírgula)
                  </label>
                  <input
                    type="text"
                    value={formData.args}
                    onChange={(e) => setFormData({ ...formData, args: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      borderColor: currentColors.border.default,
                      color: currentColors.text.primary,
                    }}
                    placeholder="-m, mcp_server_filesystem, /path/to/dir"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                    Variáveis de Ambiente (JSON)
                  </label>
                  <textarea
                    value={formData.env}
                    onChange={(e) => setFormData({ ...formData, env: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2 font-mono text-sm"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      borderColor: currentColors.border.default,
                      color: currentColors.text.primary,
                    }}
                    placeholder='{"API_KEY": "xxx", "DEBUG": "true"}'
                    rows={3}
                  />
                </div>
              </>
            )}

            {/* Configuração HTTP/SSE */}
            {(formData.type === 'http' || formData.type === 'sse') && (
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                  URL *
                </label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary,
                  }}
                  placeholder="http://localhost:3000/mcp"
                  required
                />
              </div>
            )}

            {/* Descrição */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                Descrição
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
                placeholder="Descrição do servidor MCP..."
                rows={2}
              />
            </div>

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                type="submit"
                className="px-4 py-2 rounded-lg transition-colors"
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
                Adicionar
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowAddForm(false);
                  resetForm();
                }}
                className="px-4 py-2 rounded-lg transition-colors"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  color: currentColors.text.primary,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
                }}
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Servers List */}
      {isLoading ? (
        <div className="text-center py-8">
          <div
            className="animate-spin h-8 w-8 border-4 border-t-transparent rounded-full mx-auto"
            style={{
              borderColor: currentColors.accent.primary,
              borderTopColor: 'transparent',
            }}
          ></div>
          <p className="mt-2" style={{ color: currentColors.text.muted }}>
            Carregando servidores MCP...
          </p>
        </div>
      ) : servers.length === 0 ? (
        <div
          className="text-center py-12 rounded-lg border"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <svg
            className="w-12 h-12 mx-auto mb-4 opacity-50"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            style={{ color: currentColors.text.muted }}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
            />
          </svg>
          <p style={{ color: currentColors.text.secondary }}>
            Nenhum servidor MCP configurado
          </p>
          <p className="text-sm mt-1" style={{ color: currentColors.text.muted }}>
            Adicione um servidor MCP para expandir as capacidades da IA
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {servers.map((server) => (
            <div
              key={server.id}
              className="p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.primary,
                borderColor: currentColors.border.default,
              }}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3 flex-1">
                  <div
                    className="p-2 rounded-lg"
                    style={{
                      backgroundColor: currentColors.bg.tertiary,
                      color: currentColors.accent.primary,
                    }}
                  >
                    {getMCPTypeIcon(server.type)}
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold" style={{ color: currentColors.text.primary }}>
                        {server.name}
                      </h4>
                      <span
                        className="px-2 py-0.5 rounded text-xs font-medium"
                        style={{
                          backgroundColor: currentColors.bg.tertiary,
                          color: currentColors.text.secondary,
                        }}
                      >
                        {server.type.toUpperCase()}
                      </span>
                      {server.is_active && (
                        <span
                          className="px-2 py-0.5 rounded text-xs font-medium"
                          style={{
                            backgroundColor: '#10b98120',
                            color: '#10b981',
                          }}
                        >
                          Ativo
                        </span>
                      )}
                    </div>

                    {server.description && (
                      <p className="text-sm mb-2" style={{ color: currentColors.text.muted }}>
                        {server.description}
                      </p>
                    )}

                    <div className="text-xs space-y-1" style={{ color: currentColors.text.muted }}>
                      {server.command && (
                        <div className="font-mono">
                          <span className="font-semibold">Comando:</span> {server.command} {server.args?.join(' ')}
                        </div>
                      )}
                      {server.url && (
                        <div>
                          <span className="font-semibold">URL:</span> {server.url}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => handleToggleActive(server.id, server.is_active)}
                    className="px-3 py-1.5 rounded-lg text-sm transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
                    }}
                  >
                    {server.is_active ? 'Desativar' : 'Ativar'}
                  </button>

                  <button
                    onClick={() => handleDeleteServer(server.id)}
                    className="p-1.5 rounded-lg transition-colors"
                    style={{
                      color: '#ef4444',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }}
                    title="Remover servidor"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
