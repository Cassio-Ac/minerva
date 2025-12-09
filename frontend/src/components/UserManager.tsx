/**
 * UserManager Component
 * Gerenciamento de usuários (CRUD)
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { useAuthStore } from '@stores/authStore';
import { IndexAccessManager } from './IndexAccessManager';
import { API_URL } from '../config/api';

interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: 'admin' | 'power' | 'operator' | 'reader';
  is_active: boolean;
  created_at: string;
  can_manage_users: boolean;
  can_use_llm: boolean;
  can_create_dashboards: boolean;
  can_configure_system: boolean;
  assigned_es_server_id: string | null;
}

interface UserFormData {
  username: string;
  email: string;
  full_name: string;
  password: string;
  role: 'admin' | 'power' | 'operator' | 'reader';
  is_active: boolean;
  assigned_es_server_id: string | null;
}

interface ESServer {
  id: string;
  name: string;
  url: string;
}

const API_BASE = `${API_URL}`;

export const UserManager: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const { token } = useAuthStore();
  const [users, setUsers] = useState<User[]>([]);
  const [esServers, setEsServers] = useState<ESServer[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [managingIndexesUser, setManagingIndexesUser] = useState<User | null>(null);
  const [formData, setFormData] = useState<UserFormData>({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role: 'reader',
    is_active: true,
    assigned_es_server_id: null,
  });

  useEffect(() => {
    loadUsers();
    loadESServers();
  }, []);

  const loadUsers = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE}/users/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) throw new Error('Failed to load users');

      const data = await response.json();
      setUsers(data);
    } catch (error: any) {
      alert(`Erro ao carregar usuários: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const loadESServers = async () => {
    try {
      const response = await fetch(`${API_BASE}/es-servers/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) throw new Error('Failed to load ES servers');

      const data = await response.json();
      setEsServers(data);
    } catch (error: any) {
      console.error('Erro ao carregar servidores ES:', error.message);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setIsLoading(true);

      if (editingUser) {
        // Update user
        const updateData: any = {
          email: formData.email,
          full_name: formData.full_name || null,
          role: formData.role,
          is_active: formData.is_active,
          assigned_es_server_id: formData.assigned_es_server_id,
        };

        // Only include password if provided
        if (formData.password) {
          updateData.password = formData.password;
        }

        const response = await fetch(`${API_BASE}/users/${editingUser.id}`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(updateData),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to update user');
        }
      } else {
        // Create user
        const response = await fetch(`${API_BASE}/users/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(formData),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to create user');
        }
      }

      // Reset form and reload users
      setFormData({
        username: '',
        email: '',
        full_name: '',
        password: '',
        role: 'reader',
        is_active: true,
        assigned_es_server_id: null,
      });
      setEditingUser(null);
      setShowForm(false);
      await loadUsers();
    } catch (error: any) {
      alert(`Erro: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleEdit = (user: User) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      email: user.email,
      full_name: user.full_name || '',
      password: '', // Don't pre-fill password
      role: user.role,
      is_active: user.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (userId: string) => {
    if (!confirm('Tem certeza que deseja excluir este usuário?')) return;

    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE}/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) throw new Error('Failed to delete user');

      await loadUsers();
    } catch (error: any) {
      alert(`Erro ao excluir usuário: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin':
        return '#ef4444'; // red
      case 'power':
        return '#3b82f6'; // blue
      case 'operator':
        return '#f59e0b'; // amber/orange
      case 'reader':
        return '#10b981'; // green
      default:
        return '#6b7280'; // gray
    }
  };

  const getRoleLabel = (role: string) => {
    switch (role) {
      case 'admin':
        return 'Admin';
      case 'power':
        return 'Power';
      case 'operator':
        return 'Operator';
      case 'reader':
        return 'Reader';
      default:
        return role;
    }
  };

  return (
    <div>
      {/* Header with Add Button */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <p style={{ color: currentColors.text.muted }}>
            {users.length} usuário{users.length !== 1 ? 's' : ''} cadastrado{users.length !== 1 ? 's' : ''}
          </p>
        </div>
        <button
          onClick={() => {
            setEditingUser(null);
            setFormData({
              username: '',
              email: '',
              full_name: '',
              password: '',
              role: 'reader',
              is_active: true,
            });
            setShowForm(true);
          }}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
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
          Novo Usuário
        </button>
      </div>

      {/* User Form Modal */}
      {showForm && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setShowForm(false)}
        >
          <div
            className="rounded-lg p-6 max-w-md w-full"
            style={{
              backgroundColor: currentColors.bg.primary,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-bold mb-4" style={{ color: currentColors.text.primary }}>
              {editingUser ? 'Editar Usuário' : 'Novo Usuário'}
            </h3>

            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Username */}
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Usuário *
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  disabled={!!editingUser} // Can't change username
                  required={!editingUser}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: editingUser ? currentColors.bg.hover : currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Email */}
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Email *
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Full Name */}
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Nome Completo
                </label>
                <input
                  type="text"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Password */}
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Senha {editingUser ? '(deixe vazio para manter)' : '*'}
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required={!editingUser}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                />
              </div>

              {/* Role */}
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Perfil *
                </label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as any })}
                  required
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <option value="reader">Reader - Apenas visualização</option>
                  <option value="operator">Operator - Upload CSV com restrições de índices</option>
                  <option value="power">Power - Pode usar LLM e criar dashboards</option>
                  <option value="admin">Admin - Acesso total</option>
                </select>
              </div>

              {/* Elasticsearch Server (only for OPERATOR) */}
              {formData.role === 'operator' && (
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                    Servidor Elasticsearch *
                  </label>
                  <select
                    value={formData.assigned_es_server_id || ''}
                    onChange={(e) => setFormData({ ...formData, assigned_es_server_id: e.target.value || null })}
                    required
                    className="w-full px-3 py-2 rounded-lg border"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                      borderColor: currentColors.border.default,
                    }}
                  >
                    <option value="">Selecione um servidor...</option>
                    {esServers.map((server) => (
                      <option key={server.id} value={server.id}>
                        {server.name} ({server.url})
                      </option>
                    ))}
                  </select>
                  <p className="text-xs mt-1" style={{ color: currentColors.text.secondary }}>
                    O usuário OPERATOR terá acesso apenas aos índices deste servidor que você designar.
                  </p>
                </div>
              )}

              {/* Active */}
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_active"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  className="w-4 h-4"
                />
                <label htmlFor="is_active" className="text-sm" style={{ color: currentColors.text.primary }}>
                  Usuário ativo
                </label>
              </div>

              {/* Buttons */}
              <div className="flex gap-2 mt-6">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 px-4 py-2 rounded-lg transition-colors"
                  style={{
                    backgroundColor: currentColors.accent.primary,
                    color: currentColors.text.inverse,
                  }}
                >
                  {isLoading ? 'Salvando...' : editingUser ? 'Atualizar' : 'Criar'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
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
            </form>
          </div>
        </div>
      )}

      {/* Users List */}
      {isLoading && users.length === 0 ? (
        <div className="text-center py-12" style={{ color: currentColors.text.muted }}>
          Carregando usuários...
        </div>
      ) : users.length === 0 ? (
        <div className="text-center py-12" style={{ color: currentColors.text.muted }}>
          Nenhum usuário encontrado
        </div>
      ) : (
        <div className="grid gap-4">
          {users.map((user) => (
            <div
              key={user.id}
              className="rounded-lg p-4 border"
              style={{
                backgroundColor: currentColors.bg.primary,
                borderColor: currentColors.border.default,
              }}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                      {user.full_name || user.username}
                    </h3>
                    <span
                      className="px-2 py-1 rounded text-xs font-semibold text-white"
                      style={{ backgroundColor: getRoleBadgeColor(user.role) }}
                    >
                      {getRoleLabel(user.role)}
                    </span>
                    {!user.is_active && (
                      <span
                        className="px-2 py-1 rounded text-xs font-semibold"
                        style={{
                          backgroundColor: currentColors.accent.error + '20',
                          color: currentColors.accent.error,
                        }}
                      >
                        Inativo
                      </span>
                    )}
                  </div>

                  <p className="text-sm mb-1" style={{ color: currentColors.text.secondary }}>
                    @{user.username} · {user.email}
                  </p>

                  <div className="flex flex-wrap gap-2 mt-2">
                    {user.can_manage_users && (
                      <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: currentColors.bg.tertiary, color: currentColors.text.muted }}>
                        👥 Gerenciar usuários
                      </span>
                    )}
                    {user.can_use_llm && (
                      <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: currentColors.bg.tertiary, color: currentColors.text.muted }}>
                        🤖 Usar LLM
                      </span>
                    )}
                    {user.can_create_dashboards && (
                      <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: currentColors.bg.tertiary, color: currentColors.text.muted }}>
                        📊 Criar dashboards
                      </span>
                    )}
                    {user.can_configure_system && (
                      <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: currentColors.bg.tertiary, color: currentColors.text.muted }}>
                        ⚙️ Configurar sistema
                      </span>
                    )}
                  </div>

                  <p className="text-xs mt-2" style={{ color: currentColors.text.muted }}>
                    Criado em {new Date(user.created_at).toLocaleDateString('pt-BR')}
                  </p>
                </div>

                <div className="flex gap-2 ml-4">
                  {/* Manage Indexes button (only for OPERATOR) */}
                  {user.role === 'operator' && (
                    <button
                      onClick={() => setManagingIndexesUser(user)}
                      disabled={isLoading}
                      className="p-2 rounded-lg transition-colors"
                      style={{
                        backgroundColor: currentColors.bg.hover,
                        color: '#f59e0b',
                      }}
                      title="Gerenciar Índices"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                      </svg>
                    </button>
                  )}

                  <button
                    onClick={() => handleEdit(user)}
                    disabled={isLoading}
                    className="p-2 rounded-lg transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.hover,
                      color: currentColors.accent.primary,
                    }}
                    title="Editar"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleDelete(user.id)}
                    disabled={isLoading}
                    className="p-2 rounded-lg transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.hover,
                      color: currentColors.accent.error,
                    }}
                    title="Excluir"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Index Access Manager Modal */}
      {managingIndexesUser && (
        <IndexAccessManager
          userId={managingIndexesUser.id}
          username={managingIndexesUser.username}
          assignedServerId={managingIndexesUser.assigned_es_server_id}
          onClose={() => setManagingIndexesUser(null)}
        />
      )}
    </div>
  );
};
