/**
 * Index Access Manager Component
 * Gerencia permissões de acesso a índices para usuários OPERATOR
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '@services/api';

interface IndexAccess {
  id: string;
  user_id: string;
  es_server_id: string;
  index_name: string;
  can_read: boolean;
  can_write: boolean;
  can_create: boolean;
  created_at: string;
}

interface IndexAccessManagerProps {
  userId: string;
  username: string;
  assignedServerId: string | null;
  onClose: () => void;
}

export const IndexAccessManager: React.FC<IndexAccessManagerProps> = ({
  userId,
  username,
  assignedServerId,
  onClose,
}) => {
  const { currentColors } = useSettingsStore();
  const [indexAccesses, setIndexAccesses] = useState<IndexAccess[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newIndexName, setNewIndexName] = useState('');
  const [canRead, setCanRead] = useState(true);
  const [canWrite, setCanWrite] = useState(true);
  const [canCreate, setCanCreate] = useState(false);

  useEffect(() => {
    loadIndexAccesses();
  }, [userId]);

  const loadIndexAccesses = async () => {
    try {
      setIsLoading(true);
      const data = await api.listUserIndexAccess(userId);
      setIndexAccesses(data);
    } catch (error: any) {
      console.error('Erro ao carregar acessos:', error);
      alert(`Erro ao carregar permissões de índices: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAddAccess = async () => {
    if (!newIndexName.trim()) {
      alert('Digite o nome do índice ou padrão wildcard');
      return;
    }

    if (!assignedServerId) {
      alert('Usuário não possui servidor ES atribuído');
      return;
    }

    try {
      setIsLoading(true);
      await api.createIndexAccess({
        user_id: userId,
        es_server_id: assignedServerId,
        index_name: newIndexName.trim(),
        can_read: canRead,
        can_write: canWrite,
        can_create: canCreate,
      });

      // Reset form
      setNewIndexName('');
      setCanRead(true);
      setCanWrite(true);
      setCanCreate(false);
      setShowAddForm(false);

      // Reload list
      await loadIndexAccesses();

      alert('✅ Permissão de acesso adicionada com sucesso!');
    } catch (error: any) {
      console.error('Erro ao adicionar acesso:', error);
      alert(`Erro ao adicionar permissão: ${error.response?.data?.detail || error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteAccess = async (accessId: string, indexName: string) => {
    if (!confirm(`Remover acesso ao índice "${indexName}"?`)) {
      return;
    }

    try {
      setIsLoading(true);
      await api.deleteIndexAccess(accessId);
      await loadIndexAccesses();
      alert('✅ Permissão removida com sucesso!');
    } catch (error: any) {
      console.error('Erro ao remover acesso:', error);
      alert(`Erro ao remover permissão: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleTogglePermission = async (
    accessId: string,
    field: 'can_read' | 'can_write' | 'can_create',
    currentValue: boolean
  ) => {
    try {
      setIsLoading(true);
      await api.updateIndexAccess(accessId, {
        [field]: !currentValue,
      });
      await loadIndexAccesses();
    } catch (error: any) {
      console.error('Erro ao atualizar permissão:', error);
      alert(`Erro ao atualizar permissão: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden"
        style={{ backgroundColor: currentColors.bg.primary }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          className="px-6 py-4 border-b"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold" style={{ color: currentColors.text.primary }}>
                🔐 Gerenciar Permissões de Índices
              </h2>
              <p className="text-sm mt-1" style={{ color: currentColors.text.secondary }}>
                Usuário: <span className="font-semibold">{username}</span>
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-opacity-80 transition-colors"
              style={{ backgroundColor: currentColors.bg.tertiary }}
            >
              <span style={{ color: currentColors.text.primary }}>✕</span>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 max-h-[70vh] overflow-y-auto">
          {/* Info Box */}
          <div
            className="mb-6 p-4 rounded-lg border"
            style={{
              backgroundColor: currentColors.bg.secondary,
              borderColor: currentColors.border.default,
            }}
          >
            <p className="text-sm" style={{ color: currentColors.text.secondary }}>
              💡 <strong>Dica:</strong> Você pode usar wildcards para permitir acesso a múltiplos índices:
            </p>
            <ul className="text-sm mt-2 ml-6 list-disc" style={{ color: currentColors.text.secondary }}>
              <li><code>logs-*</code> - Todos os índices que começam com "logs-"</li>
              <li><code>*-2024</code> - Todos os índices que terminam com "-2024"</li>
              <li><code>gvuln*</code> - Todos os índices que começam com "gvuln"</li>
              <li><code>meu-indice</code> - Índice específico sem wildcard</li>
            </ul>
          </div>

          {/* Add Access Form */}
          {!showAddForm ? (
            <button
              onClick={() => setShowAddForm(true)}
              disabled={isLoading || !assignedServerId}
              className="w-full mb-4 px-4 py-3 rounded-lg border-2 border-dashed transition-colors hover:border-solid"
              style={{
                borderColor: currentColors.border.default,
                color: currentColors.text.secondary,
              }}
            >
              + Adicionar Permissão de Índice
            </button>
          ) : (
            <div
              className="mb-4 p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
              }}
            >
              <h3 className="text-sm font-semibold mb-3" style={{ color: currentColors.text.primary }}>
                Nova Permissão de Índice
              </h3>

              <div className="space-y-3">
                {/* Index Name */}
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                    Nome do Índice (ou padrão wildcard) *
                  </label>
                  <input
                    type="text"
                    value={newIndexName}
                    onChange={(e) => setNewIndexName(e.target.value)}
                    placeholder="Ex: logs-*, gvuln*, meu-indice"
                    className="w-full px-3 py-2 rounded-lg border"
                    style={{
                      backgroundColor: currentColors.bg.primary,
                      color: currentColors.text.primary,
                      borderColor: currentColors.border.default,
                    }}
                  />
                </div>

                {/* Permissions */}
                <div className="flex gap-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={canRead}
                      onChange={(e) => setCanRead(e.target.checked)}
                      className="w-4 h-4"
                    />
                    <span className="text-sm" style={{ color: currentColors.text.primary }}>
                      Leitura (Read)
                    </span>
                  </label>

                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={canWrite}
                      onChange={(e) => setCanWrite(e.target.checked)}
                      className="w-4 h-4"
                    />
                    <span className="text-sm" style={{ color: currentColors.text.primary }}>
                      Escrita/Upload (Write)
                    </span>
                  </label>

                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={canCreate}
                      onChange={(e) => setCanCreate(e.target.checked)}
                      className="w-4 h-4"
                    />
                    <span className="text-sm" style={{ color: currentColors.text.primary }}>
                      Criar Novos (Create)
                    </span>
                  </label>
                </div>

                {/* Buttons */}
                <div className="flex gap-2 mt-4">
                  <button
                    onClick={handleAddAccess}
                    disabled={isLoading}
                    className="flex-1 px-4 py-2 rounded-lg transition-colors"
                    style={{
                      backgroundColor: currentColors.accent.primary,
                      color: '#ffffff',
                    }}
                  >
                    {isLoading ? 'Adicionando...' : 'Adicionar'}
                  </button>
                  <button
                    onClick={() => {
                      setShowAddForm(false);
                      setNewIndexName('');
                      setCanRead(true);
                      setCanWrite(true);
                      setCanCreate(false);
                    }}
                    disabled={isLoading}
                    className="px-4 py-2 rounded-lg transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.tertiary,
                      color: currentColors.text.primary,
                    }}
                  >
                    Cancelar
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Index Access List */}
          {isLoading && indexAccesses.length === 0 ? (
            <div className="text-center py-8" style={{ color: currentColors.text.secondary }}>
              Carregando permissões...
            </div>
          ) : indexAccesses.length === 0 ? (
            <div
              className="text-center py-8 rounded-lg"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.secondary,
              }}
            >
              <p className="text-sm">
                Nenhuma permissão configurada ainda.
              </p>
              <p className="text-xs mt-2">
                Este usuário não terá acesso a nenhum índice até que você adicione permissões.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.primary }}>
                Permissões Configuradas ({indexAccesses.length})
              </h3>
              {indexAccesses.map((access) => (
                <div
                  key={access.id}
                  className="p-4 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <code
                          className="text-sm font-semibold px-2 py-1 rounded"
                          style={{
                            backgroundColor: currentColors.bg.tertiary,
                            color: currentColors.text.primary,
                          }}
                        >
                          {access.index_name}
                        </code>
                      </div>

                      <div className="flex gap-3 mt-2">
                        <label className="flex items-center gap-1 text-xs">
                          <input
                            type="checkbox"
                            checked={access.can_read}
                            onChange={() => handleTogglePermission(access.id, 'can_read', access.can_read)}
                            disabled={isLoading}
                            className="w-3 h-3"
                          />
                          <span style={{ color: currentColors.text.secondary }}>Leitura</span>
                        </label>

                        <label className="flex items-center gap-1 text-xs">
                          <input
                            type="checkbox"
                            checked={access.can_write}
                            onChange={() => handleTogglePermission(access.id, 'can_write', access.can_write)}
                            disabled={isLoading}
                            className="w-3 h-3"
                          />
                          <span style={{ color: currentColors.text.secondary }}>Escrita</span>
                        </label>

                        <label className="flex items-center gap-1 text-xs">
                          <input
                            type="checkbox"
                            checked={access.can_create}
                            onChange={() => handleTogglePermission(access.id, 'can_create', access.can_create)}
                            disabled={isLoading}
                            className="w-3 h-3"
                          />
                          <span style={{ color: currentColors.text.secondary }}>Criar</span>
                        </label>
                      </div>
                    </div>

                    <button
                      onClick={() => handleDeleteAccess(access.id, access.index_name)}
                      disabled={isLoading}
                      className="ml-4 px-3 py-1 rounded-lg transition-colors text-sm"
                      style={{
                        backgroundColor: currentColors.bg.tertiary,
                        color: '#ef4444',
                      }}
                    >
                      Remover
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          className="px-6 py-4 border-t"
          style={{
            backgroundColor: currentColors.bg.secondary,
            borderColor: currentColors.border.default,
          }}
        >
          <button
            onClick={onClose}
            className="w-full px-4 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: '#ffffff',
            }}
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
