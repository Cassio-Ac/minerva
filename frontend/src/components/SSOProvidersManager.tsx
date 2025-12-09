/**
 * SSOProvidersManager Component
 * Gerenciamento de SSO Providers (CRUD + Sync AD)
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { useAuthStore } from '@stores/authStore';
import { API_URL, API_BASE_URL } from '../config/api';

interface SSOProvider {
  id: string;
  name: string;
  provider_type: 'entra_id' | 'google' | 'okta';
  client_id: string;
  tenant_id: string | null;
  authority_url: string | null;
  redirect_uri: string;
  scopes: string[];
  default_role: string;
  auto_provision: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  user_count: number;
}

interface SSOProviderFormData {
  name: string;
  provider_type: 'entra_id' | 'google' | 'okta';
  client_id: string;
  client_secret: string;
  tenant_id: string;
  authority_url: string;
  redirect_uri: string;
  scopes: string[];
  default_role: string;
  auto_provision: boolean;
  is_active: boolean;
}

const API_BASE = `${API_URL}`;

export const SSOProvidersManager: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const { token } = useAuthStore();
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<SSOProvider | null>(null);
  const [syncingProvider, setSyncingProvider] = useState<string | null>(null);
  const [formData, setFormData] = useState<SSOProviderFormData>({
    name: '',
    provider_type: 'entra_id',
    client_id: '',
    client_secret: '',
    tenant_id: '',
    authority_url: '',
    redirect_uri: `${API_URL}/auth/sso/callback/entra_id`,
    scopes: ['openid', 'profile', 'email', 'User.Read'],
    default_role: 'reader',
    auto_provision: true,
    is_active: true,
  });

  useEffect(() => {
    loadProviders();
  }, []);

  const loadProviders = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE}/sso-providers/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) throw new Error('Failed to load SSO providers');

      const data = await response.json();
      setProviders(data);
    } catch (error: any) {
      alert(`Erro ao carregar SSO providers: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      if (editingProvider) {
        // Update existing provider
        const updateData: any = {
          name: formData.name,
          client_id: formData.client_id,
          tenant_id: formData.tenant_id || null,
          authority_url: formData.authority_url || null,
          redirect_uri: formData.redirect_uri,
          scopes: formData.scopes,
          default_role: formData.default_role,
          auto_provision: formData.auto_provision,
          is_active: formData.is_active,
        };

        // Only include client_secret if provided
        if (formData.client_secret) {
          updateData.client_secret = formData.client_secret;
        }

        const response = await fetch(`${API_BASE}/sso-providers/${editingProvider.id}`, {
          method: 'PATCH',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(updateData),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to update provider');
        }

        alert('Provider atualizado com sucesso!');
      } else {
        // Create new provider
        const response = await fetch(`${API_BASE}/sso-providers/`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(formData),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to create provider');
        }

        alert('Provider criado com sucesso!');
      }

      setShowForm(false);
      setEditingProvider(null);
      resetForm();
      loadProviders();
    } catch (error: any) {
      alert(`Erro: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleEdit = (provider: SSOProvider) => {
    setEditingProvider(provider);
    setFormData({
      name: provider.name,
      provider_type: provider.provider_type,
      client_id: provider.client_id,
      client_secret: '', // Don't show existing secret
      tenant_id: provider.tenant_id || '',
      authority_url: provider.authority_url || '',
      redirect_uri: provider.redirect_uri,
      scopes: provider.scopes,
      default_role: provider.default_role,
      auto_provision: provider.auto_provision,
      is_active: provider.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (provider: SSOProvider) => {
    if (!confirm(`Tem certeza que deseja deletar o provider "${provider.name}"?\n\nIsso afetará ${provider.user_count} usuário(s) vinculado(s).`)) {
      return;
    }

    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE}/sso-providers/${provider.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to delete provider');
      }

      alert('Provider deletado com sucesso!');
      loadProviders();
    } catch (error: any) {
      alert(`Erro ao deletar provider: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSyncAD = async (provider: SSOProvider) => {
    if (provider.provider_type !== 'entra_id') {
      alert('Sincronização manual só está disponível para Microsoft Entra ID');
      return;
    }

    if (!confirm(`Iniciar sincronização manual com AD para "${provider.name}"?\n\nIsso verificará o status de ${provider.user_count} usuário(s).`)) {
      return;
    }

    try {
      setSyncingProvider(provider.id);
      const response = await fetch(`${API_BASE}/sso-providers/${provider.id}/sync`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to sync');
      }

      const result = await response.json();
      alert(
        `✅ Sincronização concluída!\n\n` +
        `Total verificado: ${result.total_checked}\n` +
        `Desativados: ${result.deactivated}\n` +
        `Ativados: ${result.activated || 0}\n` +
        `Erros: ${result.errors}`
      );
      loadProviders();
    } catch (error: any) {
      alert(`Erro na sincronização: ${error.message}`);
    } finally {
      setSyncingProvider(null);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      provider_type: 'entra_id',
      client_id: '',
      client_secret: '',
      tenant_id: '',
      authority_url: '',
      redirect_uri: `${API_URL}/auth/sso/callback/entra_id`,
      scopes: ['openid', 'profile', 'email', 'User.Read'],
      default_role: 'reader',
      auto_provision: true,
      is_active: true,
    });
  };

  const getProviderTypeLabel = (type: string) => {
    switch (type) {
      case 'entra_id': return 'Microsoft Entra ID';
      case 'google': return 'Google';
      case 'okta': return 'Okta';
      default: return type;
    }
  };

  const getProviderTypeColor = (type: string) => {
    switch (type) {
      case 'entra_id': return '#0078d4';
      case 'google': return '#4285f4';
      case 'okta': return '#007dc1';
      default: return currentColors.text.secondary;
    }
  };

  const getRoleLabel = (role: string) => {
    switch (role) {
      case 'admin': return 'Admin';
      case 'power': return 'Power User';
      case 'operator': return 'Operator';
      case 'reader': return 'Reader';
      default: return role;
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ margin: 0, color: currentColors.text.primary, fontSize: '24px', fontWeight: '600' }}>
            SSO Providers
          </h2>
          <p style={{ margin: '8px 0 0 0', color: currentColors.text.secondary, fontSize: '14px' }}>
            Gerenciar provedores de autenticação SSO (Microsoft Entra ID, Google, Okta)
          </p>
        </div>
        <button
          onClick={() => {
            setEditingProvider(null);
            resetForm();
            setShowForm(true);
          }}
          style={{
            padding: '10px 20px',
            backgroundColor: currentColors.primary,
            color: '#ffffff',
            border: 'none',
            borderRadius: '8px',
            fontSize: '14px',
            fontWeight: '500',
            cursor: 'pointer',
          }}
        >
          + Novo Provider
        </button>
      </div>

      {/* Form Modal */}
      {showForm && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
        }}>
          <div style={{
            backgroundColor: currentColors.bg.primary,
            borderRadius: '12px',
            padding: '32px',
            maxWidth: '600px',
            width: '90%',
            maxHeight: '90vh',
            overflow: 'auto',
          }}>
            <h3 style={{ margin: '0 0 24px 0', color: currentColors.text.primary, fontSize: '20px', fontWeight: '600' }}>
              {editingProvider ? 'Editar Provider' : 'Novo Provider'}
            </h3>

            <form onSubmit={handleSubmit}>
              {/* Name */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Nome *
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="Ex: Microsoft Entra ID - Empresa X"
                  required
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                  }}
                />
              </div>

              {/* Provider Type */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Tipo de Provider *
                </label>
                <select
                  value={formData.provider_type}
                  onChange={(e) => setFormData({ ...formData, provider_type: e.target.value as any })}
                  disabled={!!editingProvider} // Can't change type
                  required
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: editingProvider ? currentColors.bg.hover : currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                  }}
                >
                  <option value="entra_id">Microsoft Entra ID (Azure AD)</option>
                  <option value="google">Google</option>
                  <option value="okta">Okta</option>
                </select>
              </div>

              {/* Client ID */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Client ID *
                </label>
                <input
                  type="text"
                  value={formData.client_id}
                  onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
                  placeholder="Application (client) ID"
                  required
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Client Secret */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Client Secret {editingProvider ? '(deixe vazio para manter)' : '*'}
                </label>
                <input
                  type="password"
                  value={formData.client_secret}
                  onChange={(e) => setFormData({ ...formData, client_secret: e.target.value })}
                  placeholder={editingProvider ? 'Deixe vazio para não alterar' : 'Client Secret Value'}
                  required={!editingProvider}
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Tenant ID (Entra ID only) */}
              {formData.provider_type === 'entra_id' && (
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                    Tenant ID *
                  </label>
                  <input
                    type="text"
                    value={formData.tenant_id}
                    onChange={(e) => setFormData({ ...formData, tenant_id: e.target.value })}
                    placeholder="Directory (tenant) ID"
                    required={formData.provider_type === 'entra_id'}
                    style={{
                      width: '100%',
                      padding: '10px',
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                      border: `1px solid ${currentColors.border}`,
                      borderRadius: '6px',
                      fontSize: '14px',
                      fontFamily: 'monospace',
                    }}
                  />
                </div>
              )}

              {/* Redirect URI */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Redirect URI *
                </label>
                <input
                  type="url"
                  value={formData.redirect_uri}
                  onChange={(e) => setFormData({ ...formData, redirect_uri: e.target.value })}
                  placeholder={`${API_URL}/auth/sso/callback/entra_id`}
                  required
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Default Role */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  Role Padrão (novos usuários) *
                </label>
                <select
                  value={formData.default_role}
                  onChange={(e) => setFormData({ ...formData, default_role: e.target.value })}
                  required
                  style={{
                    width: '100%',
                    padding: '10px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                  }}
                >
                  <option value="reader">Reader (Visualização)</option>
                  <option value="operator">Operator (Operação)</option>
                  <option value="power">Power User (Gerenciamento)</option>
                  <option value="admin">Admin (Administração)</option>
                </select>
              </div>

              {/* Checkboxes */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', marginBottom: '12px' }}>
                  <input
                    type="checkbox"
                    checked={formData.auto_provision}
                    onChange={(e) => setFormData({ ...formData, auto_provision: e.target.checked })}
                    style={{ marginRight: '8px' }}
                  />
                  <span style={{ color: currentColors.text.primary, fontSize: '14px' }}>
                    Auto-provisionar novos usuários
                  </span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={formData.is_active}
                    onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                    style={{ marginRight: '8px' }}
                  />
                  <span style={{ color: currentColors.text.primary, fontSize: '14px' }}>
                    Provider ativo
                  </span>
                </label>
              </div>

              {/* Buttons */}
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => {
                    setShowForm(false);
                    setEditingProvider(null);
                    resetForm();
                  }}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontWeight: '500',
                    cursor: 'pointer',
                  }}
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: currentColors.primary,
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontWeight: '500',
                    cursor: isLoading ? 'not-allowed' : 'pointer',
                    opacity: isLoading ? 0.6 : 1,
                  }}
                >
                  {isLoading ? 'Salvando...' : editingProvider ? 'Atualizar' : 'Criar'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Providers List */}
      <div style={{
        backgroundColor: currentColors.bg.secondary,
        borderRadius: '12px',
        border: `1px solid ${currentColors.border}`,
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: currentColors.bg.hover }}>
              <th style={{ padding: '16px', textAlign: 'left', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Provider
              </th>
              <th style={{ padding: '16px', textAlign: 'left', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Tipo
              </th>
              <th style={{ padding: '16px', textAlign: 'left', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Role Padrão
              </th>
              <th style={{ padding: '16px', textAlign: 'center', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Usuários
              </th>
              <th style={{ padding: '16px', textAlign: 'center', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Status
              </th>
              <th style={{ padding: '16px', textAlign: 'right', color: currentColors.text.secondary, fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                Ações
              </th>
            </tr>
          </thead>
          <tbody>
            {providers.map((provider) => (
              <tr key={provider.id} style={{ borderTop: `1px solid ${currentColors.border}` }}>
                <td style={{ padding: '16px' }}>
                  <div>
                    <div style={{ color: currentColors.text.primary, fontSize: '14px', fontWeight: '500', marginBottom: '4px' }}>
                      {provider.name}
                    </div>
                    <div style={{ color: currentColors.text.secondary, fontSize: '12px', fontFamily: 'monospace' }}>
                      {provider.client_id.substring(0, 20)}...
                    </div>
                  </div>
                </td>
                <td style={{ padding: '16px' }}>
                  <span style={{
                    padding: '4px 12px',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontWeight: '500',
                    backgroundColor: `${getProviderTypeColor(provider.provider_type)}20`,
                    color: getProviderTypeColor(provider.provider_type),
                  }}>
                    {getProviderTypeLabel(provider.provider_type)}
                  </span>
                </td>
                <td style={{ padding: '16px', color: currentColors.text.primary, fontSize: '14px' }}>
                  {getRoleLabel(provider.default_role)}
                </td>
                <td style={{ padding: '16px', textAlign: 'center', color: currentColors.text.primary, fontSize: '14px', fontWeight: '500' }}>
                  {provider.user_count}
                </td>
                <td style={{ padding: '16px', textAlign: 'center' }}>
                  <span style={{
                    padding: '4px 12px',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontWeight: '500',
                    backgroundColor: provider.is_active ? '#10b98120' : '#ef444420',
                    color: provider.is_active ? '#10b981' : '#ef4444',
                  }}>
                    {provider.is_active ? 'Ativo' : 'Inativo'}
                  </span>
                </td>
                <td style={{ padding: '16px', textAlign: 'right' }}>
                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                    {provider.provider_type === 'entra_id' && (
                      <button
                        onClick={() => handleSyncAD(provider)}
                        disabled={syncingProvider === provider.id}
                        title="Sincronizar com AD"
                        style={{
                          padding: '8px 12px',
                          backgroundColor: currentColors.bg.hover,
                          color: currentColors.text.primary,
                          border: `1px solid ${currentColors.border}`,
                          borderRadius: '6px',
                          fontSize: '12px',
                          cursor: syncingProvider === provider.id ? 'not-allowed' : 'pointer',
                          opacity: syncingProvider === provider.id ? 0.6 : 1,
                        }}
                      >
                        {syncingProvider === provider.id ? '🔄 Sincronizando...' : '🔄 Sync AD'}
                      </button>
                    )}
                    <button
                      onClick={() => handleEdit(provider)}
                      style={{
                        padding: '8px 12px',
                        backgroundColor: currentColors.bg.hover,
                        color: currentColors.text.primary,
                        border: `1px solid ${currentColors.border}`,
                        borderRadius: '6px',
                        fontSize: '12px',
                        cursor: 'pointer',
                      }}
                    >
                      Editar
                    </button>
                    <button
                      onClick={() => handleDelete(provider)}
                      style={{
                        padding: '8px 12px',
                        backgroundColor: '#ef444420',
                        color: '#ef4444',
                        border: '1px solid #ef4444',
                        borderRadius: '6px',
                        fontSize: '12px',
                        cursor: 'pointer',
                      }}
                    >
                      Deletar
                    </button>
                  </div>
                </td>
              </tr>
            ))}

            {providers.length === 0 && !isLoading && (
              <tr>
                <td colSpan={6} style={{ padding: '48px', textAlign: 'center', color: currentColors.text.secondary }}>
                  <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔐</div>
                  <div style={{ fontSize: '16px', fontWeight: '500', marginBottom: '8px' }}>
                    Nenhum SSO provider configurado
                  </div>
                  <div style={{ fontSize: '14px' }}>
                    Clique em "Novo Provider" para adicionar Microsoft Entra ID, Google ou Okta
                  </div>
                </td>
              </tr>
            )}

            {isLoading && providers.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '48px', textAlign: 'center', color: currentColors.text.secondary }}>
                  Carregando...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
