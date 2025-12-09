/**
 * RSS Manager Component
 * Manage RSS feeds, categories, sources, and collection settings
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '@services/api';
import {
  Plus, Trash2, Edit2, Play, RefreshCw, Settings as SettingsIcon,
  Folder, Rss, Clock, CheckCircle, XCircle, Loader2, Upload
} from 'lucide-react';

interface RSSCategory {
  id: string;
  name: string;
  description?: string;
  sources_count?: number;
}

interface RSSSource {
  id: string;
  name: string;
  url: string;
  category_id: string;
  is_active: boolean;
  refresh_interval_hours: number;
  last_collected_at?: string;
  total_articles_collected: number;
}

interface RSSSettings {
  id: string;
  scheduler_enabled: boolean;
  scheduler_interval_hours: number;
  max_articles_per_feed: number;
  es_index_alias: string;
}

export const RSSManager: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // State
  const [categories, setCategories] = useState<RSSCategory[]>([]);
  const [sources, setSources] = useState<RSSSource[]>([]);
  const [settings, setSettings] = useState<RSSSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'categories' | 'sources' | 'settings'>('sources');

  // Modals
  const [showCategoryModal, setShowCategoryModal] = useState(false);
  const [showSourceModal, setShowSourceModal] = useState(false);
  const [editingCategory, setEditingCategory] = useState<RSSCategory | null>(null);
  const [editingSource, setEditingSource] = useState<RSSSource | null>(null);

  // Form data
  const [categoryForm, setCategoryForm] = useState({ name: '', description: '' });
  const [sourceForm, setSourceForm] = useState({
    name: '',
    url: '',
    category_id: '',
    is_active: true,
    refresh_interval_hours: 6
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [categoriesRes, sourcesRes, settingsRes] = await Promise.all([
        api.get('/rss/categories'),
        api.get('/rss/sources'),
        api.get('/rss/settings')
      ]);

      setCategories(categoriesRes.data);
      setSources(sourcesRes.data);
      setSettings(settingsRes.data);
    } catch (error) {
      console.error('Failed to fetch RSS data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCategory = async () => {
    try {
      await api.post('/rss/categories', categoryForm);
      setCategoryForm({ name: '', description: '' });
      setShowCategoryModal(false);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao criar categoria: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleUpdateCategory = async () => {
    if (!editingCategory) return;
    try {
      await api.put(`/rss/categories/${editingCategory.id}`, categoryForm);
      setEditingCategory(null);
      setCategoryForm({ name: '', description: '' });
      setShowCategoryModal(false);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao atualizar categoria: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleDeleteCategory = async (id: string) => {
    if (!confirm('Tem certeza que deseja excluir esta categoria?')) return;
    try {
      await api.delete(`/rss/categories/${id}`);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao excluir categoria: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleCreateSource = async () => {
    try {
      await api.post('/rss/sources', sourceForm);
      setSourceForm({ name: '', url: '', category_id: '', is_active: true, refresh_interval_hours: 6 });
      setShowSourceModal(false);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao criar fonte: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleUpdateSource = async () => {
    if (!editingSource) return;
    try {
      await api.put(`/rss/sources/${editingSource.id}`, sourceForm);
      setEditingSource(null);
      setSourceForm({ name: '', url: '', category_id: '', is_active: true, refresh_interval_hours: 6 });
      setShowSourceModal(false);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao atualizar fonte: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleDeleteSource = async (id: string) => {
    if (!confirm('Tem certeza que deseja excluir esta fonte?')) return;
    try {
      await api.delete(`/rss/sources/${id}`);
      fetchData();
    } catch (error: any) {
      alert(`Erro ao excluir fonte: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleCollect = async (sourceIds?: string[]) => {
    try {
      const payload = sourceIds ? { source_ids: sourceIds } : {};
      const response = await api.post('/rss/collect', payload);
      alert(`Coleta iniciada! Task ID: ${response.data.task_id}`);
    } catch (error: any) {
      alert(`Erro ao iniciar coleta: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleUpdateSettings = async () => {
    if (!settings) return;
    try {
      await api.put('/rss/settings', {
        scheduler_enabled: settings.scheduler_enabled,
        scheduler_interval_hours: settings.scheduler_interval_hours,
        max_articles_per_feed: settings.max_articles_per_feed,
        es_index_alias: settings.es_index_alias
      });
      alert('Configurações atualizadas!');
      fetchData();
    } catch (error: any) {
      alert(`Erro ao atualizar configurações: ${error.response?.data?.detail || error.message}`);
    }
  };

  const openCategoryModal = (category?: RSSCategory) => {
    if (category) {
      setEditingCategory(category);
      setCategoryForm({ name: category.name, description: category.description || '' });
    } else {
      setEditingCategory(null);
      setCategoryForm({ name: '', description: '' });
    }
    setShowCategoryModal(true);
  };

  const openSourceModal = (source?: RSSSource) => {
    if (source) {
      setEditingSource(source);
      setSourceForm({
        name: source.name,
        url: source.url,
        category_id: source.category_id,
        is_active: source.is_active,
        refresh_interval_hours: source.refresh_interval_hours
      });
    } else {
      setEditingSource(null);
      setSourceForm({ name: '', url: '', category_id: '', is_active: true, refresh_interval_hours: 6 });
    }
    setShowSourceModal(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="animate-spin" size={32} style={{ color: currentColors.primary }} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
            RSS Feeds
          </h2>
          <p className="text-sm mt-1" style={{ color: currentColors.text.muted }}>
            Gerencie fontes de notícias e configurações de coleta
          </p>
        </div>

        <button
          onClick={() => handleCollect()}
          className="px-4 py-2 rounded-lg font-semibold flex items-center gap-2"
          style={{
            backgroundColor: currentColors.success,
            color: currentColors.bg.primary
          }}
        >
          <Play size={16} />
          Coletar Agora
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b" style={{ borderColor: currentColors.border.default }}>
        {[
          { id: 'sources', label: 'Fontes', icon: <Rss size={16} /> },
          { id: 'categories', label: 'Categorias', icon: <Folder size={16} /> },
          { id: 'settings', label: 'Configurações', icon: <SettingsIcon size={16} /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className="px-4 py-2 font-medium flex items-center gap-2 border-b-2 transition-colors"
            style={{
              color: activeTab === tab.id ? currentColors.primary : currentColors.text.muted,
              borderColor: activeTab === tab.id ? currentColors.primary : 'transparent'
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'sources' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <p className="text-sm" style={{ color: currentColors.text.secondary }}>
              {sources.length} fontes • {sources.filter(s => s.is_active).length} ativas
            </p>
            <button
              onClick={() => openSourceModal()}
              className="px-4 py-2 rounded-lg font-semibold flex items-center gap-2"
              style={{
                backgroundColor: currentColors.primary,
                color: currentColors.bg.primary
              }}
            >
              <Plus size={16} />
              Nova Fonte
            </button>
          </div>

          <div className="grid gap-4">
            {sources.map(source => {
              const category = categories.find(c => c.id === source.category_id);
              return (
                <div
                  key={source.id}
                  className="p-4 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.primary,
                    borderColor: currentColors.border.default
                  }}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <h3 className="font-semibold" style={{ color: currentColors.text.primary }}>
                          {source.name}
                        </h3>
                        {source.is_active ? (
                          <CheckCircle size={16} style={{ color: currentColors.success }} />
                        ) : (
                          <XCircle size={16} style={{ color: currentColors.error }} />
                        )}
                      </div>

                      <p className="text-sm mb-2" style={{ color: currentColors.text.secondary }}>
                        {source.url}
                      </p>

                      <div className="flex items-center gap-4 text-xs" style={{ color: currentColors.text.muted }}>
                        <span className="px-2 py-1 rounded" style={{ backgroundColor: currentColors.bg.tertiary }}>
                          {category?.name || 'Sem categoria'}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock size={12} />
                          Atualiza a cada {source.refresh_interval_hours}h
                        </span>
                        <span>{source.total_articles_collected} artigos coletados</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleCollect([source.id])}
                        className="p-2 rounded-lg"
                        style={{ backgroundColor: currentColors.bg.tertiary }}
                      >
                        <RefreshCw size={16} style={{ color: currentColors.text.secondary }} />
                      </button>
                      <button
                        onClick={() => openSourceModal(source)}
                        className="p-2 rounded-lg"
                        style={{ backgroundColor: currentColors.bg.tertiary }}
                      >
                        <Edit2 size={16} style={{ color: currentColors.text.secondary }} />
                      </button>
                      <button
                        onClick={() => handleDeleteSource(source.id)}
                        className="p-2 rounded-lg"
                        style={{ backgroundColor: currentColors.bg.tertiary }}
                      >
                        <Trash2 size={16} style={{ color: currentColors.error }} />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {activeTab === 'categories' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <p className="text-sm" style={{ color: currentColors.text.secondary }}>
              {categories.length} categorias
            </p>
            <button
              onClick={() => openCategoryModal()}
              className="px-4 py-2 rounded-lg font-semibold flex items-center gap-2"
              style={{
                backgroundColor: currentColors.primary,
                color: currentColors.bg.primary
              }}
            >
              <Plus size={16} />
              Nova Categoria
            </button>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {categories.map(category => (
              <div
                key={category.id}
                className="p-4 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.primary,
                  borderColor: currentColors.border.default
                }}
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-semibold" style={{ color: currentColors.text.primary }}>
                    {category.name}
                  </h3>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => openCategoryModal(category)}
                      className="p-1 rounded"
                      style={{ backgroundColor: currentColors.bg.tertiary }}
                    >
                      <Edit2 size={14} style={{ color: currentColors.text.secondary }} />
                    </button>
                    <button
                      onClick={() => handleDeleteCategory(category.id)}
                      className="p-1 rounded"
                      style={{ backgroundColor: currentColors.bg.tertiary }}
                    >
                      <Trash2 size={14} style={{ color: currentColors.error }} />
                    </button>
                  </div>
                </div>

                {category.description && (
                  <p className="text-sm mb-2" style={{ color: currentColors.text.secondary }}>
                    {category.description}
                  </p>
                )}

                <p className="text-xs" style={{ color: currentColors.text.muted }}>
                  {category.sources_count || 0} fontes
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'settings' && settings && (
        <div className="max-w-2xl space-y-6">
          <div className="p-6 rounded-lg border" style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default
          }}>
            <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
              Agendamento
            </h3>

            <div className="space-y-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.scheduler_enabled}
                  onChange={(e) => setSettings({ ...settings, scheduler_enabled: e.target.checked })}
                  className="rounded"
                />
                <span style={{ color: currentColors.text.primary }}>
                  Habilitar coleta automática
                </span>
              </label>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Intervalo (horas)
                </label>
                <input
                  type="number"
                  min="1"
                  max="168"
                  value={settings.scheduler_interval_hours}
                  onChange={(e) => setSettings({ ...settings, scheduler_interval_hours: parseInt(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Máximo de artigos por feed
                </label>
                <input
                  type="number"
                  min="10"
                  max="1000"
                  value={settings.max_articles_per_feed}
                  onChange={(e) => setSettings({ ...settings, max_articles_per_feed: parseInt(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Índice Elasticsearch
                </label>
                <input
                  type="text"
                  value={settings.es_index_alias}
                  onChange={(e) => setSettings({ ...settings, es_index_alias: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <button
                onClick={handleUpdateSettings}
                className="w-full px-4 py-2 rounded-lg font-semibold"
                style={{
                  backgroundColor: currentColors.primary,
                  color: currentColors.bg.primary
                }}
              >
                Salvar Configurações
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Category Modal */}
      {showCategoryModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="p-6 rounded-lg max-w-md w-full" style={{ backgroundColor: currentColors.bg.primary }}>
            <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
              {editingCategory ? 'Editar Categoria' : 'Nova Categoria'}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Nome
                </label>
                <input
                  type="text"
                  value={categoryForm.name}
                  onChange={(e) => setCategoryForm({ ...categoryForm, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Descrição
                </label>
                <textarea
                  value={categoryForm.description}
                  onChange={(e) => setCategoryForm({ ...categoryForm, description: e.target.value })}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setShowCategoryModal(false);
                    setEditingCategory(null);
                  }}
                  className="flex-1 px-4 py-2 rounded-lg"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    color: currentColors.text.primary
                  }}
                >
                  Cancelar
                </button>
                <button
                  onClick={editingCategory ? handleUpdateCategory : handleCreateCategory}
                  className="flex-1 px-4 py-2 rounded-lg font-semibold"
                  style={{
                    backgroundColor: currentColors.primary,
                    color: currentColors.bg.primary
                  }}
                >
                  {editingCategory ? 'Atualizar' : 'Criar'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Source Modal */}
      {showSourceModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="p-6 rounded-lg max-w-md w-full" style={{ backgroundColor: currentColors.bg.primary }}>
            <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
              {editingSource ? 'Editar Fonte' : 'Nova Fonte'}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Nome
                </label>
                <input
                  type="text"
                  value={sourceForm.name}
                  onChange={(e) => setSourceForm({ ...sourceForm, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  URL do Feed
                </label>
                <input
                  type="url"
                  value={sourceForm.url}
                  onChange={(e) => setSourceForm({ ...sourceForm, url: e.target.value })}
                  placeholder="https://example.com/feed.xml"
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Categoria
                </label>
                <select
                  value={sourceForm.category_id}
                  onChange={(e) => setSourceForm({ ...sourceForm, category_id: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                >
                  <option value="">Selecione uma categoria</option>
                  {categories.map(cat => (
                    <option key={cat.id} value={cat.id}>{cat.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                  Intervalo de atualização (horas)
                </label>
                <input
                  type="number"
                  min="1"
                  max="168"
                  value={sourceForm.refresh_interval_hours}
                  onChange={(e) => setSourceForm({ ...sourceForm, refresh_interval_hours: parseInt(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary
                  }}
                />
              </div>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sourceForm.is_active}
                  onChange={(e) => setSourceForm({ ...sourceForm, is_active: e.target.checked })}
                  className="rounded"
                />
                <span style={{ color: currentColors.text.primary }}>
                  Fonte ativa
                </span>
              </label>

              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setShowSourceModal(false);
                    setEditingSource(null);
                  }}
                  className="flex-1 px-4 py-2 rounded-lg"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    color: currentColors.text.primary
                  }}
                >
                  Cancelar
                </button>
                <button
                  onClick={editingSource ? handleUpdateSource : handleCreateSource}
                  className="flex-1 px-4 py-2 rounded-lg font-semibold"
                  style={{
                    backgroundColor: currentColors.primary,
                    color: currentColors.bg.primary
                  }}
                >
                  {editingSource ? 'Atualizar' : 'Criar'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
