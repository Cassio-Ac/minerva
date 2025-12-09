/**
 * WidgetCard Component
 * Card individual de widget com visualização
 */

import React, { useEffect, useState, useCallback, useRef } from 'react';
import type { Widget } from '@types/widget';
import { PlotlyChart } from './PlotlyChart';
import { WidgetEditModal } from './WidgetEditModal';
import { useDashboardStore } from '@stores/dashboardStore';
import { useSettingsStore } from '@stores/settingsStore';
import { api } from '@services/api';

interface WidgetCardProps {
  widget: Widget;
  onRemove?: (widgetId: string) => void;
}

export const WidgetCard: React.FC<WidgetCardProps> = ({ widget, onRemove }) => {
  const { currentColors } = useSettingsStore();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const { selectedServerId, timeRange, updateWidgetData, updateWidget } = useDashboardStore();
  const isExecutingRef = useRef(false);
  const lastExecutionKey = useRef<string>('');

  // Log para debug - ver quando dados mudam (comentado para produção)
  // useEffect(() => {
  //   console.log(`🔄 WidgetCard ${widget.id} render:`, {
  //     hasResults: !!widget.data.results,
  //     hasConfig: !!widget.data.config,
  //     configData: widget.data.config?.data?.length || 0,
  //     lastUpdated: widget.data.last_updated,
  //   });
  // }, [widget.data.results, widget.data.config, widget.data.last_updated]);

  // Função para executar query com retry automático
  const executeQueryWithRetry = useCallback(async (attempt = 1, maxAttempts = 3) => {
    // Determinar qual time range usar: fixedTimeRange se existir, senão timeRange global
    const effectiveTimeRange = widget.fixedTimeRange || timeRange;

    // Criar chave única para esta execução
    const executionKey = `${widget.id}-${widget.index}-${JSON.stringify(effectiveTimeRange)}`;

    // Se já está executando a mesma query, não executar novamente
    if (isExecutingRef.current && lastExecutionKey.current === executionKey) {
      console.log(`⏭️ Widget ${widget.id}: Already executing this exact query, skipping...`);
      return;
    }

    // Se não tem query, não executar
    if (!widget.data.query) {
      return;
    }

    // SEMPRE usar o índice do widget, nunca o global
    if (!widget.index) {
      console.warn(`Widget ${widget.id}: Widget must have its own index property`);
      setError('Widget sem índice configurado');
      return;
    }

    const indexToUse = widget.index;

    // Se já tem resultados válidos E last_updated recente (< 5 segundos), não re-executar
    const hasDataInResults = widget.data.results && widget.data.results.data && widget.data.results.data.length > 0;
    const hasLastUpdated = widget.data.last_updated;
    const timeSinceUpdate = hasLastUpdated ? (Date.now() - new Date(widget.data.last_updated).getTime()) : Infinity;

    const hasRecentData = hasDataInResults && hasLastUpdated && timeSinceUpdate < 5000;

    if (hasRecentData && attempt === 1) {
      console.log(`✅ Widget ${widget.id} tem dados recentes (< 5s), pulando execução de query`);
      setError(null);
      return;
    }

    // Marcar como executando
    isExecutingRef.current = true;
    lastExecutionKey.current = executionKey;
    setIsLoading(true);
    setError(null);

    try {
      console.log(`⏳ [${attempt}/${maxAttempts}] Executing query for widget ${widget.id} (${widget.title}) on index: ${indexToUse}`);
      console.log(`   Time range: ${widget.fixedTimeRange ? '🔒 FIXED' : '🌐 GLOBAL'} - ${effectiveTimeRange.label}`);

      const result = await api.executeQuery(
        indexToUse,
        widget.data.query,
        selectedServerId || undefined,
        effectiveTimeRange  // Usar time range efetivo (fixado ou global)
      );

      // Sucesso! Atualizar dados
      const currentConfig = widget.data.config || {};
      updateWidgetData(widget.id, {
        results: result,
        config: {
          ...currentConfig,
          data: result.data
        },
        last_updated: new Date().toISOString(),
      });

      console.log(`✅ Widget ${widget.id} data loaded from index: ${indexToUse}`);
      setError(null);
      setRetryCount(0);
      isExecutingRef.current = false;

    } catch (error: any) {
      console.error(`❌ [${attempt}/${maxAttempts}] Error loading widget ${widget.id} data:`, error);

      // Se ainda tem tentativas restantes, fazer retry com backoff exponencial
      if (attempt < maxAttempts) {
        const delayMs = Math.min(1000 * Math.pow(2, attempt - 1), 5000); // 1s, 2s, 4s (max 5s)
        console.log(`🔄 Retrying widget ${widget.id} in ${delayMs}ms...`);
        setRetryCount(attempt);

        setTimeout(() => {
          isExecutingRef.current = false; // Liberar para retry
          executeQueryWithRetry(attempt + 1, maxAttempts);
        }, delayMs);
      } else {
        // Todas as tentativas falharam
        const errorMessage = error?.response?.data?.detail || error?.message || 'Erro ao carregar dados';
        setError(errorMessage);
        setRetryCount(0);
        isExecutingRef.current = false;
        console.error(`💥 Widget ${widget.id} failed after ${maxAttempts} attempts`);
      }
    } finally {
      // Só desativar loading se não vai retry
      if (attempt >= maxAttempts || error === null) {
        setIsLoading(false);
      }
    }
  }, [widget.id, widget.index, widget.data.query, widget.data.results, widget.data.last_updated, widget.fixedTimeRange, selectedServerId, timeRange, updateWidgetData]);

  // Executar query quando widget monta ou quando index/timeRange mudam
  // Se widget tem fixedTimeRange, não re-executar quando timeRange global mudar
  useEffect(() => {
    executeQueryWithRetry(1, 3);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    widget.id,
    widget.index,
    // Se tem fixedTimeRange, usar ele; senão usar o global
    widget.fixedTimeRange ? JSON.stringify(widget.fixedTimeRange) : JSON.stringify(timeRange)
  ]);

  // Handler para salvar mudanças do modal
  const handleSaveFromModal = (updates: Partial<Widget>) => {
    updateWidget(widget.id, updates);

    // Se a query foi alterada, forçar re-execução
    if (updates.data?.query) {
      executeQueryWithRetry(1, 3);
    }
  };

  return (
    <>
      <WidgetEditModal
        widget={widget}
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
        onSave={handleSaveFromModal}
      />

      <div className="rounded-lg shadow-md overflow-hidden h-full flex flex-col" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        {/* Header - Drag handle */}
        <div className="widget-header px-4 py-3 cursor-move flex justify-between items-center" style={{
          background: `linear-gradient(to right, ${currentColors.accent.primary}, ${currentColors.accent.primaryHover})`,
          color: currentColors.text.inverse
        }}>
          <div className="flex-1 flex items-center gap-2">
            <h3 className="font-semibold text-sm truncate">{widget.title}</h3>
            {widget.fixedTimeRange && (
              <span
                className="text-xs px-2 py-0.5 rounded-full flex items-center gap-1"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  color: currentColors.text.inverse,
                }}
                title={`Time range fixado: ${widget.fixedTimeRange.label}`}
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                {widget.fixedTimeRange.label}
              </span>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsEditModalOpen(true);
              }}
              className="transition-colors"
              style={{
                color: currentColors.text.inverse,
                opacity: 0.8
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.opacity = '1';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.opacity = '0.8';
              }}
              title="Editar widget"
            >
              <svg
                className="w-4 h-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                />
              </svg>
            </button>
            {onRemove && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onRemove(widget.id);
                }}
                className="transition-colors"
                style={{
                  color: currentColors.text.inverse,
                  opacity: 0.8
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.opacity = '1';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.opacity = '0.8';
                }}
                title="Remover widget"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            )}
          </div>
        </div>

      {/* Content - Visualização */}
      <div className="flex-1 p-4 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="animate-spin h-8 w-8 border-4 border-t-transparent rounded-full mx-auto mb-2" style={{
                borderColor: currentColors.accent.primary,
                borderTopColor: 'transparent'
              }}></div>
              <p className="text-sm" style={{ color: currentColors.text.muted }}>
                Carregando dados...
              </p>
              {retryCount > 0 && (
                <p className="text-xs mt-1" style={{ color: currentColors.text.muted, opacity: 0.7 }}>
                  Tentativa {retryCount} de 3
                </p>
              )}
            </div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center max-w-md">
              <svg
                className="w-12 h-12 mx-auto mb-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                style={{ color: '#ef4444' }}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <p className="text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Erro ao carregar dados
              </p>
              <p className="text-xs mb-4" style={{ color: currentColors.text.muted }}>
                {error}
              </p>
              <button
                onClick={() => executeQueryWithRetry(1, 3)}
                className="px-4 py-2 rounded-lg text-sm font-medium transition-colors"
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
                <div className="flex items-center gap-2">
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                    />
                  </svg>
                  Tentar novamente
                </div>
              </button>
            </div>
          </div>
        ) : widget.data.results ? (
          <PlotlyChart
            key={`${widget.id}-${widget.data.last_updated || Date.now()}`}
            type={widget.type}
            data={widget.data.results}
            title=""
            config={widget.data.config}
          />
        ) : (
          <div className="flex items-center justify-center h-full" style={{ color: currentColors.text.muted }}>
            <div className="text-center">
              <svg
                className="w-12 h-12 mx-auto mb-2 opacity-50"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                />
              </svg>
              <p className="text-sm">Sem dados</p>
            </div>
          </div>
        )}
      </div>

      {/* Footer - Metadata */}
      <div className="border-t px-4 py-2" style={{
        borderColor: currentColors.border.default,
        backgroundColor: currentColors.bg.tertiary
      }}>
        <div className="flex justify-between items-center text-xs" style={{ color: currentColors.text.muted }}>
          <span className="capitalize">{widget.type}</span>
          <span>
            {new Date(widget.metadata.updated_at).toLocaleTimeString('pt-BR', {
              hour: '2-digit',
              minute: '2-digit',
            })}
          </span>
        </div>
      </div>
      </div>
    </>
  );
};
