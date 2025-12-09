/**
 * DashboardEditor Page
 * Página principal de edição de dashboard
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { DashboardGrid } from '@components/DashboardGrid';
import { ChatPanel } from '@components/ChatPanel';
import { ESServerSelector } from '@components/ESServerSelector';
import { IndexSelector } from '@components/IndexSelector';
import { IndexFieldsViewer } from '@components/IndexFieldsViewer';
import { TimeRangePicker } from '@components/TimeRangePicker';
import { LLMProviderIndicator } from '@components/LLMProviderIndicator';
import { DashboardSettingsModal } from '@components/DashboardSettingsModal';
import { useDashboardStore } from '@stores/dashboardStore';
import { useSettingsStore } from '@stores/settingsStore';
import type { Widget } from '@types/widget';
import { API_URL, API_BASE_URL } from '../config/api';

export const DashboardEditor: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { currentColors } = useSettingsStore();
  const {
    currentDashboard,
    widgets,
    addWidget,
    setCurrentDashboard,
    error,
    clearError,
    selectedServerId,
    setSelectedServer,
    selectedIndex,
    setSelectedIndex,
    isChatOpen,
    toggleChat,
    timeRange,
    setTimeRange,
    refreshAllWidgets,
    loadDashboard,
  } = useDashboardStore();
  const [showAddWidgetModal, setShowAddWidgetModal] = useState(false);
  const [showStats, setShowStats] = useState(true);
  const [isEditingTitle, setIsEditingTitle] = useState(false);
  const [editedTitle, setEditedTitle] = useState('');
  const [editedDescription, setEditedDescription] = useState('');
  const [isInitialized, setIsInitialized] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);

  // Inicializar dashboard (carregar do URL ou criar novo)
  useEffect(() => {
    const initializeDashboard = async () => {
      if (!currentDashboard && !isInitialized) {
        setIsInitialized(true); // Marcar como inicializado ANTES de carregar

        // Verificar se há ID na URL
        const dashboardId = searchParams.get('id');

        try {
          if (dashboardId) {
            // Carregar dashboard específico da URL
            console.log('Loading dashboard from URL:', dashboardId);
            await loadDashboard(dashboardId);
            return;
          }

          // Sem ID na URL: tentar carregar dashboard example
          const response = await fetch(`${API_URL}/dashboards/example-dashboard`);

          if (response.ok) {
            const dashboard = await response.json();
            setCurrentDashboard(dashboard);
            console.log('Dashboard loaded from Elasticsearch');
          } else {
            // Dashboard não existe, criar um novo
            const newDashboard = {
              title: 'Meu Dashboard',
              description: 'Dashboard de exemplo para demonstração',
              index: 'vazamentos',
              widgets: [],
            };

            const createResponse = await fetch(`${API_URL}/dashboards`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(newDashboard),
            });

            if (createResponse.ok) {
              const createdDashboard = await createResponse.json();
              // Forçar ID para example-dashboard para compatibilidade
              createdDashboard.id = 'example-dashboard';
              setCurrentDashboard(createdDashboard);
              console.log('Dashboard created in Elasticsearch');
            }
          }
        } catch (error) {
          console.error('Error initializing dashboard:', error);
          // Fallback: criar dashboard local
          const fallbackDashboard = {
            id: 'example-dashboard',
            title: 'Meu Dashboard',
            description: 'Dashboard de exemplo para demonstração',
            layout: {
              cols: 12,
              row_height: 30,
              width: 1600,
            },
            widgets: [],
            index: 'vazamentos',
            metadata: {
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              is_public: false,
              tags: [],
              version: 1,
            },
          };
          setCurrentDashboard(fallbackDashboard);
        }
      }
    };

    initializeDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Executar apenas uma vez no mount

  // Função para adicionar widget de exemplo
  const handleAddExampleWidget = () => {
    const newWidget: Widget = {
      id: `widget-${Date.now()}`,
      title: `Widget ${widgets.length + 1}`,
      type: 'pie',
      position: {
        x: (widgets.length * 4) % 12,
        y: Math.floor((widgets.length * 4) / 12) * 4,
        w: 4,
        h: 4,
      },
      data: {
        query: {},
        results: {},
        config: {
          data: [
            { label: 'Categoria A', value: 30 },
            { label: 'Categoria B', value: 20 },
            { label: 'Categoria C', value: 50 },
          ],
        },
      },
      metadata: {
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        version: 1,
      },
    };

    addWidget(newWidget);
    setShowAddWidgetModal(false);
  };

  // Função para abrir modal de edição
  const handleEditTitle = () => {
    if (currentDashboard) {
      setEditedTitle(currentDashboard.title);
      setEditedDescription(currentDashboard.description || '');
      setIsEditingTitle(true);
    }
  };

  // Função para salvar título e descrição
  const handleSaveTitle = async () => {
    if (!currentDashboard) return;

    // Enviar apenas os campos que mudaram (PATCH semântico)
    const updates = {
      title: editedTitle,
      description: editedDescription,
    };

    try {
      const response = await fetch(`${API_URL}/dashboards/${currentDashboard.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });

      if (response.ok) {
        const saved = await response.json();
        setCurrentDashboard(saved);
        setIsEditingTitle(false);
        console.log('✅ Dashboard title updated');
      } else {
        const error = await response.json();
        console.error('❌ Error updating title:', error);
        alert('Erro ao atualizar título: ' + (error.detail || 'Erro desconhecido'));
      }
    } catch (error) {
      console.error('❌ Error updating title:', error);
      alert('Erro ao atualizar título: ' + error);
    }
  };

  // Função para salvar dashboard (widgets)
  const handleSaveDashboard = async () => {
    if (!currentDashboard) {
      console.error('No dashboard to save');
      return;
    }

    try {
      // Enviar apenas widgets (PATCH semântico)
      const updates = {
        widgets: widgets,
      };

      const response = await fetch(`${API_URL}/dashboards/${currentDashboard.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });

      if (response.ok) {
        const updatedDashboard = await response.json();
        setCurrentDashboard(updatedDashboard);
        console.log('✅ Dashboard saved successfully');

        // Refresh widgets para recarregar dados
        console.log('🔄 Refreshing widgets after save...');
        await refreshAllWidgets();

        alert('Dashboard salvo com sucesso!');
      } else {
        const error = await response.json();
        console.error('❌ Error saving dashboard:', error);
        alert('Erro ao salvar dashboard: ' + (error.detail || 'Erro desconhecido'));
      }
    } catch (error) {
      console.error('❌ Error saving dashboard:', error);
      alert('Erro ao salvar dashboard: ' + error);
    }
  };

  // Função para exportar dashboard em PDF
  const handleExportPDF = async () => {
    if (!currentDashboard?.id) {
      alert('Nenhum dashboard para exportar');
      return;
    }

    try {
      // Primeiro salvar para garantir que está atualizado
      console.log('💾 Salvando dashboard antes de exportar...');
      await handleSaveDashboard();

      // Exportar para PDF
      console.log('📄 Exportando dashboard para PDF...');
      const authStorage = localStorage.getItem('dashboard-auth-storage');
      let token = '';
      if (authStorage) {
        const { state } = JSON.parse(authStorage);
        token = state?.token || '';
      }

      const response = await fetch(`${API_URL}/export/dashboards/${currentDashboard.id}/export/pdf`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const result = await response.json();
        console.log('✅ PDF exportado com sucesso:', result);

        // Fazer download do arquivo
        const downloadResponse = await fetch(`${API_URL}/downloads/${result.download_id}/download`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (downloadResponse.ok) {
          const blob = await downloadResponse.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = result.filename;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);

          alert('Dashboard exportado com sucesso!');
        } else {
          throw new Error('Erro ao fazer download do PDF');
        }
      } else {
        const error = await response.json();
        console.error('❌ Error exporting PDF:', error);
        alert('Erro ao exportar PDF: ' + (error.detail || 'Erro desconhecido'));
      }
    } catch (error) {
      console.error('❌ Error exporting PDF:', error);
      alert('Erro ao exportar PDF: ' + error);
    }
  };

  // Handler para salvar configurações do modal
  const handleSaveSettings = async (updates: {
    title: string;
    description: string;
    visibility: string;
    allowEditByOthers: boolean;
    allowCopy: boolean;
  }) => {
    if (!currentDashboard) return;

    try {
      // 1. Atualizar dashboard (título e descrição)
      const dashboardResponse = await fetch(
        `${API_URL}/dashboards/${currentDashboard.id}`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${
              localStorage.getItem('dashboard-auth-storage')
                ? JSON.parse(localStorage.getItem('dashboard-auth-storage')!).state.token
                : ''
            }`,
          },
          body: JSON.stringify({
            title: updates.title,
            description: updates.description,
          }),
        }
      );

      if (!dashboardResponse.ok) {
        throw new Error('Erro ao atualizar dashboard');
      }

      // 2. Criar ou atualizar permissões
      const permissionData = {
        dashboard_id: currentDashboard.id,
        visibility: updates.visibility,
        allow_edit_by_others: updates.allowEditByOthers,
        allow_copy: updates.allowCopy,
      };

      // Tentar criar permissão (se já existe, atualizar)
      const permissionResponse = await fetch(
        `${API_URL}/dashboard-permissions/`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${
              localStorage.getItem('dashboard-auth-storage')
                ? JSON.parse(localStorage.getItem('dashboard-auth-storage')!).state.token
                : ''
            }`,
          },
          body: JSON.stringify(permissionData),
        }
      );

      // Se criação falhar (409 = já existe), fazer update
      if (permissionResponse.status === 409 || permissionResponse.status === 400) {
        await fetch(`${API_URL}/dashboard-permissions/${currentDashboard.id}`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${
              localStorage.getItem('dashboard-auth-storage')
                ? JSON.parse(localStorage.getItem('dashboard-auth-storage')!).state.token
                : ''
            }`,
          },
          body: JSON.stringify({
            visibility: updates.visibility,
            allow_edit_by_others: updates.allowEditByOthers,
            allow_copy: updates.allowCopy,
          }),
        });
      }

      // Atualizar dashboard local
      setCurrentDashboard({
        ...currentDashboard,
        title: updates.title,
        description: updates.description,
      });

      alert('✅ Configurações salvas com sucesso!');
    } catch (error) {
      console.error('Error saving settings:', error);
      alert('❌ Erro ao salvar configurações');
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <header className="shadow-sm border-b flex-shrink-0 overflow-visible" style={{
        backgroundColor: currentColors.bg.primary,
        borderColor: currentColors.border.default
      }}>
        <div className="w-full px-6 py-4">
          {/* Primeira Linha - Título e Ações */}
          <div className="flex justify-between items-center mb-3">
            <div className="flex items-center gap-4">
              {/* Botão Voltar */}
              <button
                onClick={() => navigate('/')}
                className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors flex-shrink-0"
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

              <div className="flex items-start gap-3">
                <div>
                  <h1 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                    {currentDashboard?.title || 'Dashboard'}
                  </h1>
                  {currentDashboard?.description && (
                    <p className="text-sm mt-1" style={{ color: currentColors.text.muted }}>
                      {currentDashboard.description}
                    </p>
                  )}
                </div>
                <button
                  onClick={handleEditTitle}
                  className="p-2 rounded-lg transition-colors flex-shrink-0"
                  style={{ color: currentColors.text.secondary }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                    e.currentTarget.style.color = currentColors.text.primary;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                    e.currentTarget.style.color = currentColors.text.secondary;
                  }}
                  title="Editar nome e descrição"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-3 flex-shrink-0">
              <button
                onClick={toggleChat}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
                title={isChatOpen ? 'Ocultar Chat' : 'Mostrar Chat'}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                </svg>
                {isChatOpen ? 'Ocultar' : 'Chat'}
              </button>
              <button
                onClick={handleAddExampleWidget}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Adicionar Widget
              </button>
              <button
                onClick={handleSaveDashboard}
                className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                </svg>
                Salvar
              </button>
              <button
                onClick={handleExportPDF}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
                title="Exportar dashboard em PDF"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                </svg>
                Exportar PDF
              </button>
              <button
                onClick={() => setShowSettingsModal(true)}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                Editar
              </button>
            </div>
          </div>

          {/* Segunda Linha - Controles */}
          <div className="flex items-center gap-3 flex-wrap">
              {/* Elasticsearch Server Selector */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
                  Servidor:
                </label>
                <ESServerSelector
                  selectedServerId={selectedServerId}
                  onServerChange={setSelectedServer}
                />
              </div>

              {/* Index Selector */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
                  Índice:
                </label>
                <IndexSelector
                  serverId={selectedServerId}
                  selectedIndex={selectedIndex}
                  onIndexChange={setSelectedIndex}
                />
              </div>

              {/* Index Fields Viewer (inline) */}
              {selectedIndex && (
                <IndexFieldsViewer
                  serverId={selectedServerId}
                  indexName={selectedIndex}
                />
              )}

              {/* Time Range Picker */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
                  Período:
                </label>
                <TimeRangePicker
                  value={timeRange}
                  onChange={setTimeRange}
                />
              </div>

              {/* Separador */}
              <div className="h-8 w-px" style={{ backgroundColor: currentColors.border.default }}></div>

              {/* LLM Provider Indicator */}
              <LLMProviderIndicator compact />
            </div>
          </div>
        </header>

      {/* Error Alert */}
      {error && (
        <div className="w-full px-6 py-4">
          <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded">
            <div className="flex justify-between items-center">
              <div className="flex items-center">
                <svg
                  className="w-5 h-5 text-red-500 mr-3"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                    clipRule="evenodd"
                  />
                </svg>
                <p className="text-red-700">{error}</p>
              </div>
              <button
                onClick={clearError}
                className="text-red-500 hover:text-red-700"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fillRule="evenodd"
                    d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                    clipRule="evenodd"
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dashboard Stats - Collapsible */}
      <div className="w-full px-6 py-2">
        <div className="rounded-lg shadow-sm border" style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}>
          {/* Stats Header com Toggle */}
          <div className="flex items-center justify-between px-4 py-3 border-b" style={{
            borderColor: currentColors.border.default
          }}>
            <div className="flex items-center gap-2">
              <svg
                className="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                style={{ color: currentColors.text.secondary }}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                />
              </svg>
              <h3 className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>Estatísticas do Dashboard</h3>
            </div>
            <button
              onClick={() => setShowStats(!showStats)}
              className="flex items-center gap-2 px-3 py-1.5 text-sm rounded transition-colors"
              style={{ color: currentColors.text.secondary }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                e.currentTarget.style.color = currentColors.text.primary;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = currentColors.text.secondary;
              }}
            >
              {showStats ? 'Recolher' : 'Expandir'}
              <svg
                className={`w-4 h-4 transition-transform duration-200 ${showStats ? 'rotate-180' : ''}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M19 9l-7 7-7-7"
                />
              </svg>
            </button>
          </div>

          {/* Stats Content - Collapsible */}
          {showStats && (
            <div className="p-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
                <div className="rounded-lg p-4 border transition-colors" style={{
                  backgroundColor: currentColors.bg.tertiary,
                  borderColor: currentColors.border.default
                }}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-xs mb-1" style={{ color: currentColors.text.muted }}>Total de Widgets</p>
                      <p className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>{widgets.length}</p>
                    </div>
                    <div className="rounded-full p-2.5" style={{ backgroundColor: currentColors.accent.primary + '20' }}>
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        style={{ color: currentColors.accent.primary }}
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg p-4 border transition-colors" style={{
                  backgroundColor: currentColors.bg.tertiary,
                  borderColor: currentColors.border.default
                }}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-xs mb-1" style={{ color: currentColors.text.muted }}>Servidor ES</p>
                      <p className="text-sm font-semibold truncate" style={{ color: currentColors.text.primary }}>
                        {selectedServerId ? selectedServerId.slice(0, 12) + '...' : 'Nenhum'}
                      </p>
                    </div>
                    <div className="rounded-full p-2.5" style={{ backgroundColor: currentColors.accent.primary + '20' }}>
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        style={{ color: currentColors.accent.primary }}
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg p-4 border transition-colors" style={{ backgroundColor: currentColors.bg.tertiary, borderColor: currentColors.border.default }}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs mb-1" style={{ color: currentColors.text.muted }}>Índice Selecionado</p>
                      <p className="text-sm font-semibold truncate" style={{ color: currentColors.text.primary }}>
                        {selectedIndex || 'Nenhum'}
                      </p>
                    </div>
                    <div className="rounded-full p-2.5 flex-shrink-0" style={{ backgroundColor: currentColors.accent.primary + '20' }}>
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        style={{ color: currentColors.accent.primary }}
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg p-4 border transition-colors" style={{ backgroundColor: currentColors.bg.tertiary, borderColor: currentColors.border.default }}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-xs mb-1" style={{ color: currentColors.text.muted }}>Status</p>
                      <p className="text-lg font-semibold" style={{ color: '#10b981' }}>Online</p>
                    </div>
                    <div className="rounded-full p-2.5 flex items-center justify-center" style={{ backgroundColor: currentColors.accent.primary + '20' }}>
                      <div className="w-3 h-3 rounded-full animate-pulse" style={{ backgroundColor: '#10b981' }}></div>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg p-4 border transition-colors" style={{ backgroundColor: currentColors.bg.tertiary, borderColor: currentColors.border.default }}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-xs mb-1" style={{ color: currentColors.text.muted }}>Última Atualização</p>
                      <p className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                        {new Date().toLocaleTimeString('pt-BR', {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </p>
                    </div>
                    <div className="rounded-full p-2.5" style={{ backgroundColor: currentColors.accent.primary + '20' }}>
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        style={{ color: currentColors.accent.primary }}
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Main Content - Dashboard Grid + Chat Panel */}
      <div className="flex gap-0 flex-1 overflow-hidden">
        {/* Dashboard Grid - Ocupa todo espaço disponível */}
        <main className="flex-1 min-w-0 transition-all duration-300 overflow-auto">
          <DashboardGrid
            cols={currentDashboard?.layout.cols || 12}
            rowHeight={currentDashboard?.layout.row_height || 60}
          />
        </main>

        {/* Chat Panel - Fixed */}
        {isChatOpen && (
          <aside className="w-96 flex-shrink-0 transition-all duration-300 h-full overflow-hidden" style={{ paddingRight: '24px' }}>
            <ChatPanel />
          </aside>
        )}
      </div>

      {/* Modal de Edição de Título */}
      {isEditingTitle && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="rounded-lg shadow-xl max-w-md w-full mx-4" style={{ backgroundColor: currentColors.bg.primary }}>
            {/* Header */}
            <div className="px-6 py-4 border-b" style={{ borderColor: currentColors.border.default }}>
              <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                Editar Dashboard
              </h3>
            </div>

            {/* Body */}
            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                  Nome do Dashboard
                </label>
                <input
                  type="text"
                  value={editedTitle}
                  onChange={(e) => setEditedTitle(e.target.value)}
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary,
                  }}
                  placeholder="Digite o nome do dashboard"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                  Descrição (opcional)
                </label>
                <textarea
                  value={editedDescription}
                  onChange={(e) => setEditedDescription(e.target.value)}
                  rows={3}
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 resize-none"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary,
                  }}
                  placeholder="Digite uma descrição para o dashboard"
                />
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-4 border-t flex justify-end gap-3" style={{ borderColor: currentColors.border.default }}>
              <button
                onClick={() => setIsEditingTitle(false)}
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
              <button
                onClick={handleSaveTitle}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Salvar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de Configurações */}
      {showSettingsModal && currentDashboard && (
        <DashboardSettingsModal
          dashboardId={currentDashboard.id}
          currentTitle={currentDashboard.title}
          currentDescription={currentDashboard.description || ''}
          onClose={() => setShowSettingsModal(false)}
          onSave={handleSaveSettings}
        />
      )}
    </div>
  );
};
