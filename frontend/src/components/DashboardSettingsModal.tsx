/**
 * DashboardSettingsModal
 * Modal para editar configurações do dashboard (nome, descrição, permissões, etc)
 */

import React, { useState, useEffect } from 'react';
import { useAuthStore } from '@stores/authStore';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '../services/api';
import { API_URL, API_BASE_URL } from '../config/api';

interface DashboardSettingsModalProps {
  dashboardId: string;
  currentTitle: string;
  currentDescription: string;
  onClose: () => void;
  onSave: (updates: {
    title: string;
    description: string;
    visibility: string;
    allowEditByOthers: boolean;
    allowCopy: boolean;
  }) => void;
}

export const DashboardSettingsModal: React.FC<DashboardSettingsModalProps> = ({
  dashboardId,
  currentTitle,
  currentDescription,
  onClose,
  onSave,
}) => {
  const { user } = useAuthStore();
  const { currentColors } = useSettingsStore();

  const [title, setTitle] = useState(currentTitle);
  const [description, setDescription] = useState(currentDescription);
  const [visibility, setVisibility] = useState<'private' | 'public' | 'shared'>('private');
  const [allowEditByOthers, setAllowEditByOthers] = useState(false);
  const [allowCopy, setAllowCopy] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Carregar permissões atuais
  useEffect(() => {
    const loadPermissions = async () => {
      try {
        const response = await fetch(
          `${API_URL}/dashboard-permissions/${dashboardId}`,
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('dashboard-auth-storage')
                ? JSON.parse(localStorage.getItem('dashboard-auth-storage')!).state.token
                : ''}`,
            },
          }
        );

        if (response.ok) {
          const permission = await response.json();
          setVisibility(permission.visibility);
          setAllowEditByOthers(permission.allow_edit_by_others);
          setAllowCopy(permission.allow_copy);
        }
      } catch (error) {
        console.error('Error loading permissions:', error);
        // Não mostrar erro se permissão não existe (pode ser dashboard novo)
      }
    };

    loadPermissions();
  }, [dashboardId]);

  const handleSave = async () => {
    setIsLoading(true);
    setError(null);

    try {
      onSave({
        title,
        description,
        visibility,
        allowEditByOthers,
        allowCopy,
      });
      onClose();
    } catch (err: any) {
      setError(err.message || 'Erro ao salvar configurações');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50 z-50"
        onClick={onClose}
      />

      {/* Modal */}
      <div
        className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl shadow-2xl"
        style={{
          backgroundColor: currentColors.bg.primary,
          border: `1px solid ${currentColors.border.default}`,
        }}
      >
        {/* Header */}
        <div
          className="sticky top-0 px-6 py-4 border-b flex items-center justify-between"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <h2 className="text-xl font-bold" style={{ color: currentColors.text.primary }}>
            ⚙️ Configurações do Dashboard
          </h2>
          <button
            onClick={onClose}
            className="p-2 rounded-lg transition-colors"
            style={{ color: currentColors.text.secondary }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.bg.hover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
            }}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
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

          {/* Informações Básicas */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              📝 Informações Básicas
            </h3>

            {/* Título */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Título
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full px-4 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  color: currentColors.text.primary,
                  borderColor: currentColors.border.default,
                }}
                placeholder="Nome do dashboard"
              />
            </div>

            {/* Descrição */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Descrição
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full px-4 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  color: currentColors.text.primary,
                  borderColor: currentColors.border.default,
                }}
                placeholder="Descrição do dashboard"
              />
            </div>
          </div>

          {/* Permissões */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              🔐 Permissões e Visibilidade
            </h3>

            {/* Visibilidade */}
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Visibilidade
              </label>
              <select
                value={visibility}
                onChange={(e) => setVisibility(e.target.value as any)}
                className="w-full px-4 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  color: currentColors.text.primary,
                  borderColor: currentColors.border.default,
                }}
              >
                <option value="private">🔒 Privado - Apenas você</option>
                <option value="public">🌐 Público - Todos podem ver</option>
                <option value="shared">👥 Compartilhado - Usuários específicos</option>
              </select>
              <p className="text-xs mt-1" style={{ color: currentColors.text.muted }}>
                {visibility === 'private' && 'Apenas você pode visualizar e editar'}
                {visibility === 'public' && 'Todos os usuários podem visualizar'}
                {visibility === 'shared' && 'Apenas usuários com quem você compartilhar podem ver'}
              </p>
            </div>

            {/* Permitir edição por outros */}
            {(visibility === 'public' || visibility === 'shared') && (
              <div>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={allowEditByOthers}
                    onChange={(e) => setAllowEditByOthers(e.target.checked)}
                    className="w-5 h-5 rounded"
                    style={{ accentColor: currentColors.accent.primary }}
                  />
                  <div>
                    <div className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                      ✏️ Permitir edição por outros usuários
                    </div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>
                      Usuários com acesso poderão editar widgets e configurações
                    </div>
                  </div>
                </label>
              </div>
            )}

            {/* Permitir cópia */}
            <div>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={allowCopy}
                  onChange={(e) => setAllowCopy(e.target.checked)}
                  className="w-5 h-5 rounded"
                  style={{ accentColor: currentColors.accent.primary }}
                />
                <div>
                  <div className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                    📋 Permitir cópia do dashboard
                  </div>
                  <div className="text-xs" style={{ color: currentColors.text.muted }}>
                    Usuários poderão duplicar este dashboard para uso próprio
                  </div>
                </div>
              </label>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          className="sticky bottom-0 px-6 py-4 border-t flex items-center justify-end gap-3"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-6 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              color: currentColors.text.primary,
            }}
            onMouseEnter={(e) => {
              if (!isLoading) {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
            }}
          >
            Cancelar
          </button>
          <button
            onClick={handleSave}
            disabled={isLoading}
            className="px-6 py-2 rounded-lg transition-colors font-medium"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
              opacity: isLoading ? 0.6 : 1,
            }}
            onMouseEnter={(e) => {
              if (!isLoading) {
                e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.accent.primary;
            }}
          >
            {isLoading ? 'Salvando...' : '💾 Salvar Configurações'}
          </button>
        </div>
      </div>
    </>
  );
};
