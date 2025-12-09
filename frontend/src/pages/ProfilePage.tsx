/**
 * ProfilePage - Configurações do próprio usuário
 * Permite que o usuário edite seus próprios dados (exceto perfil)
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@stores/authStore';
import { useSettingsStore, type Theme } from '@stores/settingsStore';
import { API_URL, API_BASE_URL } from '../config/api';

const API_BASE = `${API_URL}`;

export const ProfilePage: React.FC = () => {
  const navigate = useNavigate();
  const { user, token, loadUser } = useAuthStore();
  const { currentColors, theme, setTheme } = useSettingsStore();

  const [formData, setFormData] = useState({
    email: user?.email || '',
    full_name: user?.full_name || '',
    current_password: '',
    new_password: '',
    confirm_password: '',
  });

  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'info' | 'password' | 'preferences'>('info');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleUpdateInfo = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);

    try {
      setIsLoading(true);

      const response = await fetch(`${API_BASE}/users/${user?.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          email: formData.email,
          full_name: formData.full_name || null,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Erro ao atualizar informações');
      }

      // Recarregar dados do usuário
      await loadUser();

      setMessage({ type: 'success', text: 'Informações atualizadas com sucesso!' });
    } catch (error: any) {
      setMessage({ type: 'error', text: error.message });
    } finally {
      setIsLoading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);

    // Validações
    if (!formData.current_password) {
      setMessage({ type: 'error', text: 'Digite sua senha atual' });
      return;
    }

    if (!formData.new_password) {
      setMessage({ type: 'error', text: 'Digite a nova senha' });
      return;
    }

    if (formData.new_password.length < 8) {
      setMessage({ type: 'error', text: 'A nova senha deve ter pelo menos 8 caracteres' });
      return;
    }

    if (formData.new_password !== formData.confirm_password) {
      setMessage({ type: 'error', text: 'As senhas não conferem' });
      return;
    }

    try {
      setIsLoading(true);

      // Usar endpoint correto: POST /auth/change-password
      const response = await fetch(`${API_BASE}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          current_password: formData.current_password,
          new_password: formData.new_password,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Erro ao alterar senha');
      }

      // Limpar campos de senha
      setFormData({
        ...formData,
        current_password: '',
        new_password: '',
        confirm_password: '',
      });

      setMessage({ type: 'success', text: 'Senha alterada com sucesso!' });
    } catch (error: any) {
      setMessage({ type: 'error', text: error.message });
    } finally {
      setIsLoading(false);
    }
  };

  const getRoleBadgeColor = () => {
    switch (user?.role) {
      case 'admin':
        return '#ef4444';
      case 'power':
        return '#3b82f6';
      case 'reader':
        return '#10b981';
      default:
        return '#6b7280';
    }
  };

  const getRoleLabel = () => {
    switch (user?.role) {
      case 'admin':
        return 'Admin';
      case 'power':
        return 'Power';
      case 'reader':
        return 'Reader';
      default:
        return 'Unknown';
    }
  };

  if (!user) return null;

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{
        backgroundColor: currentColors.bg.secondary,
        color: currentColors.text.primary,
      }}
    >
      {/* Header */}
      <header
        className="border-b"
        style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default,
        }}
      >
        <div className="max-w-4xl mx-auto px-6 py-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                color: currentColors.text.secondary,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              <span className="font-medium">Menu</span>
            </button>

            <div
              className="h-8 w-px"
              style={{ backgroundColor: currentColors.border.default }}
            ></div>

            <div>
              <h1 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                Meu Perfil
              </h1>
              <p className="text-sm" style={{ color: currentColors.text.muted }}>
                Gerencie suas informações pessoais
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 max-w-4xl w-full mx-auto px-6 py-8">
        {/* User Info Card */}
        <div
          className="rounded-lg p-6 border mb-8"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center gap-4">
            {/* Avatar */}
            {user.profile_photo_url ? (
              <img
                src={`${API_BASE_URL}${user.profile_photo_url}`}
                alt={user.username}
                className="w-16 h-16 rounded-full"
                style={{ objectFit: 'cover' }}
              />
            ) : (
              <div
                className="w-16 h-16 rounded-full flex items-center justify-center text-2xl font-bold"
                style={{
                  backgroundColor: currentColors.accent.primary,
                  color: '#ffffff',
                }}
              >
                {user.username.charAt(0).toUpperCase()}
              </div>
            )}

            {/* User Info */}
            <div className="flex-1">
              <h2 className="text-xl font-bold" style={{ color: currentColors.text.primary }}>
                {user.full_name || user.username}
              </h2>
              <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                @{user.username}
              </p>
              <div className="flex items-center gap-2 mt-2">
                <span
                  className="px-2 py-1 rounded text-xs font-semibold text-white"
                  style={{ backgroundColor: getRoleBadgeColor() }}
                >
                  {getRoleLabel()}
                </span>
                <span className="text-xs" style={{ color: currentColors.text.muted }}>
                  • Membro desde {new Date(user.created_at).toLocaleDateString('pt-BR')}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => setActiveTab('info')}
            className="px-4 py-2 rounded-lg transition-colors font-medium"
            style={{
              backgroundColor: activeTab === 'info' ? currentColors.accent.primary : currentColors.bg.primary,
              color: activeTab === 'info' ? currentColors.text.inverse : currentColors.text.primary,
            }}
          >
            Informações Pessoais
          </button>
          <button
            onClick={() => setActiveTab('password')}
            className="px-4 py-2 rounded-lg transition-colors font-medium"
            style={{
              backgroundColor: activeTab === 'password' ? currentColors.accent.primary : currentColors.bg.primary,
              color: activeTab === 'password' ? currentColors.text.inverse : currentColors.text.primary,
            }}
          >
            Alterar Senha
          </button>
          <button
            onClick={() => setActiveTab('preferences')}
            className="px-4 py-2 rounded-lg transition-colors font-medium"
            style={{
              backgroundColor: activeTab === 'preferences' ? currentColors.accent.primary : currentColors.bg.primary,
              color: activeTab === 'preferences' ? currentColors.text.inverse : currentColors.text.primary,
            }}
          >
            Preferências
          </button>
        </div>

        {/* Message */}
        {message && (
          <div
            className="rounded-lg p-4 mb-6 border"
            style={{
              backgroundColor: message.type === 'success' ? currentColors.accent.success + '20' : currentColors.accent.error + '20',
              borderColor: message.type === 'success' ? currentColors.accent.success : currentColors.accent.error,
              color: message.type === 'success' ? currentColors.accent.success : currentColors.accent.error,
            }}
          >
            {message.text}
          </div>
        )}

        {/* Info Tab */}
        {activeTab === 'info' && (
          <div
            className="rounded-lg p-6 border"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border.default,
            }}
          >
            <form onSubmit={handleUpdateInfo} className="space-y-6">
              {/* Email */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  disabled={isLoading}
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Full Name */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Nome Completo
                </label>
                <input
                  type="text"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  disabled={isLoading}
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Username (read-only) */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Usuário
                </label>
                <input
                  type="text"
                  value={user.username}
                  disabled
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.hover,
                    color: currentColors.text.muted,
                    borderColor: currentColors.border.default,
                  }}
                />
                <p className="text-xs mt-1" style={{ color: currentColors.text.muted }}>
                  O nome de usuário não pode ser alterado
                </p>
              </div>

              {/* Role (read-only) */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Perfil
                </label>
                <div className="flex items-center gap-2">
                  <span
                    className="px-3 py-2 rounded-lg text-sm font-semibold text-white"
                    style={{ backgroundColor: getRoleBadgeColor() }}
                  >
                    {getRoleLabel()}
                  </span>
                  <p className="text-xs" style={{ color: currentColors.text.muted }}>
                    Apenas administradores podem alterar perfis
                  </p>
                </div>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="px-6 py-2 rounded-lg transition-colors font-medium"
                style={{
                  backgroundColor: currentColors.accent.primary,
                  color: currentColors.text.inverse,
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
                {isLoading ? 'Salvando...' : 'Salvar Alterações'}
              </button>
            </form>
          </div>
        )}

        {/* Password Tab */}
        {activeTab === 'password' && (
          <div
            className="rounded-lg p-6 border"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border.default,
            }}
          >
            <form onSubmit={handleChangePassword} className="space-y-6">
              {/* Current Password */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Senha Atual
                </label>
                <input
                  type="password"
                  value={formData.current_password}
                  onChange={(e) => setFormData({ ...formData, current_password: e.target.value })}
                  disabled={isLoading}
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                  placeholder="Digite sua senha atual"
                />
              </div>

              {/* New Password */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Nova Senha
                </label>
                <input
                  type="password"
                  value={formData.new_password}
                  onChange={(e) => setFormData({ ...formData, new_password: e.target.value })}
                  disabled={isLoading}
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                  placeholder="Digite a nova senha (mínimo 6 caracteres)"
                />
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Confirmar Nova Senha
                </label>
                <input
                  type="password"
                  value={formData.confirm_password}
                  onChange={(e) => setFormData({ ...formData, confirm_password: e.target.value })}
                  disabled={isLoading}
                  className="w-full px-4 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                  placeholder="Digite a nova senha novamente"
                />
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="px-6 py-2 rounded-lg transition-colors font-medium"
                style={{
                  backgroundColor: currentColors.accent.primary,
                  color: currentColors.text.inverse,
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
                {isLoading ? 'Alterando...' : 'Alterar Senha'}
              </button>
            </form>
          </div>
        )}

        {/* Preferences Tab */}
        {activeTab === 'preferences' && (
          <div
            className="rounded-lg p-6 border"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border.default,
            }}
          >
            <div className="space-y-6">
              {/* Theme Selector */}
              <div>
                <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
                  🎨 Tema da Interface
                </h3>
                <p className="text-sm mb-4" style={{ color: currentColors.text.muted }}>
                  Escolha o tema que mais combina com você
                </p>

                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {/* Light Theme */}
                  <button
                    onClick={() => {
                      setTheme('light');
                      setMessage({ type: 'success', text: 'Tema alterado para Light' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'light' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'light' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">☀️</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Light</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Tema claro</div>
                  </button>

                  {/* Dark Theme */}
                  <button
                    onClick={() => {
                      setTheme('dark');
                      setMessage({ type: 'success', text: 'Tema alterado para Dark' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'dark' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'dark' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">🌙</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Dark</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Tema escuro</div>
                  </button>

                  {/* Monokai Theme */}
                  <button
                    onClick={() => {
                      setTheme('monokai');
                      setMessage({ type: 'success', text: 'Tema alterado para Monokai' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'monokai' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'monokai' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">🎮</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Monokai</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Developer style</div>
                  </button>

                  {/* Dracula Theme */}
                  <button
                    onClick={() => {
                      setTheme('dracula');
                      setMessage({ type: 'success', text: 'Tema alterado para Dracula' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'dracula' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'dracula' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">🧛</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Dracula</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Vampire dark</div>
                  </button>

                  {/* Nord Theme */}
                  <button
                    onClick={() => {
                      setTheme('nord');
                      setMessage({ type: 'success', text: 'Tema alterado para Nord' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'nord' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'nord' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">❄️</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Nord</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Arctic aurora</div>
                  </button>

                  {/* Solarized Theme */}
                  <button
                    onClick={() => {
                      setTheme('solarized');
                      setMessage({ type: 'success', text: 'Tema alterado para Solarized' });
                    }}
                    className="p-4 rounded-lg border-2 transition-all"
                    style={{
                      backgroundColor: theme === 'solarized' ? currentColors.accent.primary + '20' : currentColors.bg.secondary,
                      borderColor: theme === 'solarized' ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="text-2xl mb-2">🌅</div>
                    <div className="font-semibold mb-1" style={{ color: currentColors.text.primary }}>Solarized</div>
                    <div className="text-xs" style={{ color: currentColors.text.muted }}>Eye comfort</div>
                  </button>
                </div>

                <div className="mt-4 p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.secondary }}>
                  <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                    ✨ <strong>Tema atual:</strong> {theme.charAt(0).toUpperCase() + theme.slice(1)}
                  </p>
                  <p className="text-xs mt-2" style={{ color: currentColors.text.muted }}>
                    O tema é salvo automaticamente no navegador e aplicado em todas as páginas.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
