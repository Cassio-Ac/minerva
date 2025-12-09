/**
 * LLM Providers Manager Component
 * Interface for managing LLM provider configurations
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import axios from 'axios';
import { API_URL } from '../config/api';

interface LLMProvider {
  id: string;
  name: string;
  provider_type: 'anthropic' | 'openai' | 'databricks';
  model_name: string;
  api_base_url?: string;
  temperature: number;
  max_tokens: number;
  is_active: boolean;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

interface ModelSuggestions {
  anthropic: string[];
  openai: string[];
  databricks: string[];
}

export const LLMProvidersManager: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<LLMProvider | null>(null);
  const [modelSuggestions, setModelSuggestions] = useState<ModelSuggestions | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    provider_type: 'anthropic' as 'anthropic' | 'openai' | 'databricks',
    model_name: '',
    api_key: '',
    api_base_url: '',
    temperature: 0.1,
    max_tokens: 4000,
    is_default: false,
  });

  useEffect(() => {
    loadProviders();
    loadModelSuggestions();
  }, []);

  const loadProviders = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_URL}/llm-providers`);
      setProviders(response.data);
    } catch (error) {
      console.error('Error loading providers:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadModelSuggestions = async () => {
    try {
      const response = await axios.get(`${API_URL}/llm-providers/models/suggestions`);
      setModelSuggestions(response.data);
    } catch (error) {
      console.error('Error loading model suggestions:', error);
    }
  };

  const handleEdit = (provider: LLMProvider) => {
    setEditingProvider(provider);
    setFormData({
      name: provider.name,
      provider_type: provider.provider_type,
      model_name: provider.model_name,
      api_key: '', // Don't show existing key
      api_base_url: provider.api_base_url || '',
      temperature: provider.temperature,
      max_tokens: provider.max_tokens,
      is_default: provider.is_default,
    });
    setShowAddForm(false);
  };

  const handleCancelEdit = () => {
    setEditingProvider(null);
    setFormData({
      name: '',
      provider_type: 'anthropic',
      model_name: '',
      api_key: '',
      api_base_url: '',
      temperature: 0.1,
      max_tokens: 4000,
      is_default: false,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      if (editingProvider) {
        // Update existing provider
        const updateData: any = {
          name: formData.name,
          model_name: formData.model_name,
          temperature: formData.temperature,
          max_tokens: formData.max_tokens,
          is_default: formData.is_default,
        };

        // Only include API key if it was changed
        if (formData.api_key) {
          updateData.api_key = formData.api_key;
        }

        // Only include base URL for Databricks
        if (formData.provider_type === 'databricks') {
          updateData.api_base_url = formData.api_base_url;
        }

        await axios.put(`${API_URL}/llm-providers/${editingProvider.id}`, updateData);
        setEditingProvider(null);
      } else {
        // Create new provider
        await axios.post(`${API_URL}/llm-providers`, formData);
        setShowAddForm(false);
      }

      await loadProviders();

      // Reset form
      setFormData({
        name: '',
        provider_type: 'anthropic',
        model_name: '',
        api_key: '',
        api_base_url: '',
        temperature: 0.1,
        max_tokens: 4000,
        is_default: false,
      });
    } catch (error) {
      console.error('Error saving provider:', error);
      alert('Erro ao salvar provider. Verifique os dados e tente novamente.');
    }
  };

  const handleSetDefault = async (providerId: string) => {
    try {
      await axios.post(`${API_URL}/llm-providers/${providerId}/set-default`);
      await loadProviders();
    } catch (error) {
      console.error('Error setting default provider:', error);
    }
  };

  const handleDelete = async (providerId: string) => {
    if (!confirm('Tem certeza que deseja excluir este provider?')) {
      return;
    }

    try {
      await axios.delete(`${API_URL}/llm-providers/${providerId}`);
      await loadProviders();
    } catch (error) {
      console.error('Error deleting provider:', error);
    }
  };

  const getProviderIcon = (type: string) => {
    switch (type) {
      case 'anthropic':
        return '🤖';
      case 'openai':
        return '🔥';
      case 'databricks':
        return '📊';
      default:
        return '💡';
    }
  };

  const getProviderName = (type: string) => {
    switch (type) {
      case 'anthropic':
        return 'Anthropic';
      case 'openai':
        return 'OpenAI';
      case 'databricks':
        return 'Databricks';
      default:
        return type;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: currentColors.accent.primary }}></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Add Provider Button */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
            LLM Providers
          </h3>
          <p className="text-sm" style={{ color: currentColors.text.muted }}>
            Configure os provedores de LLM (Anthropic, OpenAI, Databricks)
          </p>
        </div>

        <button
          onClick={() => {
            setShowAddForm(!showAddForm);
            if (editingProvider) {
              handleCancelEdit();
            }
          }}
          className="px-4 py-2 rounded-lg font-medium transition-colors"
          style={{
            backgroundColor: showAddForm ? currentColors.bg.tertiary : currentColors.accent.primary,
            color: showAddForm ? currentColors.text.primary : currentColors.text.inverse,
          }}
        >
          {showAddForm ? 'Cancelar' : '+ Adicionar Provider'}
        </button>
      </div>

      {/* Add/Edit Form */}
      {(showAddForm || editingProvider) && (
        <form
          onSubmit={handleSubmit}
          className="rounded-lg p-6 border space-y-4"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              {editingProvider ? 'Editar Provider' : 'Adicionar Provider'}
            </h3>
            {editingProvider && (
              <button
                type="button"
                onClick={handleCancelEdit}
                className="text-sm px-3 py-1 rounded"
                style={{
                  backgroundColor: currentColors.bg.tertiary,
                  color: currentColors.text.secondary,
                }}
              >
                Cancelar
              </button>
            )}
          </div>
          <div className="grid grid-cols-2 gap-4">
            {/* Name */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                Nome
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
                className="w-full px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
                placeholder="ex: Claude Produção"
              />
            </div>

            {/* Provider Type */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                Provedor
              </label>
              <select
                value={formData.provider_type}
                onChange={(e) => setFormData({ ...formData, provider_type: e.target.value as any, model_name: '' })}
                disabled={!!editingProvider}
                className="w-full px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: editingProvider ? currentColors.bg.tertiary : currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                  opacity: editingProvider ? 0.6 : 1,
                  cursor: editingProvider ? 'not-allowed' : 'pointer',
                }}
              >
                <option value="anthropic">Anthropic</option>
                <option value="openai">OpenAI</option>
                <option value="databricks">Databricks</option>
              </select>
            </div>

            {/* Model Name */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                Modelo
              </label>
              <select
                value={formData.model_name}
                onChange={(e) => setFormData({ ...formData, model_name: e.target.value })}
                required
                className="w-full px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
              >
                <option value="">Selecione um modelo</option>
                {modelSuggestions?.[formData.provider_type]?.map((model) => (
                  <option key={model} value={model}>
                    {model}
                  </option>
                ))}
              </select>
            </div>

            {/* API Key */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                API Key {editingProvider && <span className="text-xs" style={{ color: currentColors.text.muted }}>(deixe em branco para manter a atual)</span>}
              </label>
              <input
                type="password"
                value={formData.api_key}
                onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
                required={!editingProvider}
                className="w-full px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
                placeholder={editingProvider ? "••••••••" : "sk-..."}
              />
            </div>

            {/* API Base URL (for Databricks) */}
            {formData.provider_type === 'databricks' && (
              <div className="col-span-2">
                <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                  Base URL
                </label>
                <input
                  type="text"
                  value={formData.api_base_url}
                  onChange={(e) => setFormData({ ...formData, api_base_url: e.target.value })}
                  required={formData.provider_type === 'databricks'}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary,
                  }}
                  placeholder="https://..."
                />
              </div>
            )}

            {/* Temperature */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                Temperature: {formData.temperature}
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={formData.temperature}
                onChange={(e) => setFormData({ ...formData, temperature: parseFloat(e.target.value) })}
                className="w-full"
              />
            </div>

            {/* Max Tokens */}
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: currentColors.text.primary }}>
                Max Tokens
              </label>
              <input
                type="number"
                value={formData.max_tokens}
                onChange={(e) => setFormData({ ...formData, max_tokens: parseInt(e.target.value) })}
                min="100"
                max="100000"
                className="w-full px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default,
                  color: currentColors.text.primary,
                }}
              />
            </div>

            {/* Is Default */}
            <div className="col-span-2 flex items-center gap-2">
              <input
                type="checkbox"
                id="is_default"
                checked={formData.is_default}
                onChange={(e) => setFormData({ ...formData, is_default: e.target.checked })}
                className="w-4 h-4"
              />
              <label htmlFor="is_default" className="text-sm" style={{ color: currentColors.text.primary }}>
                Definir como provider padrão
              </label>
            </div>
          </div>

          <button
            type="submit"
            className="w-full px-4 py-2 rounded-lg font-medium"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
          >
            {editingProvider ? 'Salvar Alterações' : 'Criar Provider'}
          </button>
        </form>
      )}

      {/* Providers List */}
      <div className="space-y-3">
        {providers.length === 0 ? (
          <div
            className="text-center p-8 rounded-lg border"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border.default,
              color: currentColors.text.muted,
            }}
          >
            Nenhum provider configurado. Adicione seu primeiro provider acima.
          </div>
        ) : (
          providers.map((provider) => (
            <div
              key={provider.id}
              className="rounded-lg p-4 border flex items-center justify-between"
              style={{
                backgroundColor: currentColors.bg.primary,
                borderColor: provider.is_default ? currentColors.accent.primary : currentColors.border.default,
              }}
            >
              <div className="flex items-center gap-4">
                <div className="text-3xl">{getProviderIcon(provider.provider_type)}</div>
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="font-semibold" style={{ color: currentColors.text.primary }}>
                      {provider.name}
                    </h4>
                    {provider.is_default && (
                      <span
                        className="text-xs px-2 py-1 rounded"
                        style={{
                          backgroundColor: currentColors.accent.primary,
                          color: currentColors.text.inverse,
                        }}
                      >
                        Padrão
                      </span>
                    )}
                    {!provider.is_active && (
                      <span
                        className="text-xs px-2 py-1 rounded"
                        style={{
                          backgroundColor: currentColors.bg.tertiary,
                          color: currentColors.text.muted,
                        }}
                      >
                        Inativo
                      </span>
                    )}
                  </div>
                  <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                    {getProviderName(provider.provider_type)} • {provider.model_name}
                  </p>
                  <p className="text-xs" style={{ color: currentColors.text.muted }}>
                    Temperature: {provider.temperature} • Max Tokens: {provider.max_tokens}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleEdit(provider)}
                  className="px-3 py-1 rounded text-sm transition-colors"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    color: currentColors.text.primary,
                  }}
                >
                  Editar
                </button>
                {!provider.is_default && (
                  <button
                    onClick={() => handleSetDefault(provider.id)}
                    className="px-3 py-1 rounded text-sm transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.tertiary,
                      color: currentColors.text.primary,
                    }}
                  >
                    Definir como padrão
                  </button>
                )}
                <button
                  onClick={() => handleDelete(provider.id)}
                  className="px-3 py-1 rounded text-sm transition-colors"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    color: currentColors.accent.error,
                  }}
                >
                  Excluir
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
