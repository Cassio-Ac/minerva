/**
 * WidgetEditModal - Modal para editar configurações do widget
 * Permite editar título, time range fixado e query (modo avançado)
 */

import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { useDashboardStore } from '@stores/dashboardStore';
import { TimeRangePicker } from '@components/TimeRangePicker';
import type { Widget } from '@types/widget';
import type { TimeRange } from '@types/chat';

interface WidgetEditModalProps {
  widget: Widget;
  isOpen: boolean;
  onClose: () => void;
  onSave: (updates: Partial<Widget>) => void;
}

export const WidgetEditModal: React.FC<WidgetEditModalProps> = ({
  widget,
  isOpen,
  onClose,
  onSave,
}) => {
  const { currentColors } = useSettingsStore();
  const { timeRange: globalTimeRange } = useDashboardStore();

  const [activeTab, setActiveTab] = useState<'basic' | 'advanced'>('basic');
  const [editedTitle, setEditedTitle] = useState(widget.title);
  const [useFixedTimeRange, setUseFixedTimeRange] = useState(!!widget.fixedTimeRange);
  const [fixedTimeRange, setFixedTimeRange] = useState<TimeRange>(
    widget.fixedTimeRange || globalTimeRange
  );
  const [editedQuery, setEditedQuery] = useState(
    JSON.stringify(widget.data.query, null, 2)
  );
  const [queryError, setQueryError] = useState<string | null>(null);

  // Reset state when widget changes or modal opens
  useEffect(() => {
    if (isOpen) {
      setEditedTitle(widget.title);
      setUseFixedTimeRange(!!widget.fixedTimeRange);
      setFixedTimeRange(widget.fixedTimeRange || globalTimeRange);
      setEditedQuery(JSON.stringify(widget.data.query, null, 2));
      setQueryError(null);
      setActiveTab('basic');
    }
  }, [widget, isOpen, globalTimeRange]);

  const handleSave = () => {
    // Validar query JSON se estiver na aba avançada
    if (activeTab === 'advanced') {
      try {
        JSON.parse(editedQuery);
        setQueryError(null);
      } catch (e) {
        setQueryError('Query JSON inválida');
        return;
      }
    }

    const updates: Partial<Widget> = {
      title: editedTitle.trim() || widget.title,
    };

    // Time range
    if (useFixedTimeRange) {
      updates.fixedTimeRange = fixedTimeRange;
    } else {
      updates.fixedTimeRange = undefined;
    }

    // Query (se foi editada)
    if (activeTab === 'advanced') {
      try {
        const parsedQuery = JSON.parse(editedQuery);
        updates.data = {
          ...widget.data,
          query: parsedQuery,
        };
      } catch (e) {
        // Já validado acima
      }
    }

    onSave(updates);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50"
        style={{ zIndex: 9998 }}
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-0 flex items-center justify-center p-4" style={{ zIndex: 9999 }}>
        <div
          className="rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
            borderWidth: '1px',
          }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div
            className="px-6 py-4 border-b flex items-center justify-between"
            style={{ borderColor: currentColors.border.default }}
          >
            <h2
              className="text-xl font-bold"
              style={{ color: currentColors.text.primary }}
            >
              Editar Widget
            </h2>
            <button
              onClick={onClose}
              className="p-2 rounded-lg transition-colors"
              style={{
                color: currentColors.text.secondary,
                backgroundColor: 'transparent',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>

          {/* Tabs */}
          <div
            className="flex border-b"
            style={{ borderColor: currentColors.border.default }}
          >
            <button
              onClick={() => setActiveTab('basic')}
              className="px-6 py-3 font-medium transition-colors"
              style={{
                color: activeTab === 'basic' ? currentColors.accent.primary : currentColors.text.secondary,
                borderBottomWidth: '2px',
                borderBottomColor: activeTab === 'basic' ? currentColors.accent.primary : 'transparent',
                backgroundColor: activeTab === 'basic' ? currentColors.bg.secondary : 'transparent',
              }}
            >
              Básico
            </button>
            <button
              onClick={() => setActiveTab('advanced')}
              className="px-6 py-3 font-medium transition-colors"
              style={{
                color: activeTab === 'advanced' ? currentColors.accent.primary : currentColors.text.secondary,
                borderBottomWidth: '2px',
                borderBottomColor: activeTab === 'advanced' ? currentColors.accent.primary : 'transparent',
                backgroundColor: activeTab === 'advanced' ? currentColors.bg.secondary : 'transparent',
              }}
            >
              Avançado
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-6">
            {activeTab === 'basic' ? (
              <div className="space-y-6">
                {/* Título */}
                <div>
                  <label
                    className="block text-sm font-medium mb-2"
                    style={{ color: currentColors.text.primary }}
                  >
                    Título do Widget
                  </label>
                  <input
                    type="text"
                    value={editedTitle}
                    onChange={(e) => setEditedTitle(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg border transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                      borderColor: currentColors.border.default,
                    }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = currentColors.border.focus;
                    }}
                    onBlur={(e) => {
                      e.currentTarget.style.borderColor = currentColors.border.default;
                    }}
                    placeholder="Nome do widget"
                    maxLength={100}
                  />
                </div>

                {/* Time Range */}
                <div>
                  <label
                    className="block text-sm font-medium mb-2"
                    style={{ color: currentColors.text.primary }}
                  >
                    Período Temporal
                  </label>

                  {/* Toggle: Usar global ou fixar */}
                  <div className="flex items-center gap-3 mb-3">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        checked={!useFixedTimeRange}
                        onChange={() => setUseFixedTimeRange(false)}
                        className="w-4 h-4"
                        style={{ accentColor: currentColors.accent.primary }}
                      />
                      <span
                        className="text-sm"
                        style={{ color: currentColors.text.primary }}
                      >
                        Usar período global do dashboard
                      </span>
                    </label>
                  </div>

                  <div className="flex items-center gap-3 mb-3">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        checked={useFixedTimeRange}
                        onChange={() => setUseFixedTimeRange(true)}
                        className="w-4 h-4"
                        style={{ accentColor: currentColors.accent.primary }}
                      />
                      <span
                        className="text-sm"
                        style={{ color: currentColors.text.primary }}
                      >
                        Fixar período específico
                      </span>
                    </label>
                  </div>

                  {/* Time Range Picker (só mostra se fixedTimeRange estiver ativo) */}
                  {useFixedTimeRange && (
                    <div className="mt-3 pl-6">
                      <TimeRangePicker
                        value={fixedTimeRange}
                        onChange={setFixedTimeRange}
                      />
                      <p
                        className="text-xs mt-2"
                        style={{ color: currentColors.text.muted }}
                      >
                        Este widget sempre usará o período: <strong>{fixedTimeRange.label}</strong>
                      </p>
                    </div>
                  )}
                </div>

                {/* Info sobre índice */}
                <div
                  className="p-4 rounded-lg"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    borderColor: currentColors.border.default,
                    borderWidth: '1px',
                  }}
                >
                  <div className="flex items-start gap-2">
                    <svg
                      className="w-5 h-5 mt-0.5 flex-shrink-0"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      style={{ color: currentColors.accent.primary }}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <div>
                      <p
                        className="text-sm font-medium"
                        style={{ color: currentColors.text.primary }}
                      >
                        Informações do Widget
                      </p>
                      <p
                        className="text-xs mt-1"
                        style={{ color: currentColors.text.secondary }}
                      >
                        <strong>Tipo:</strong> {widget.type} | <strong>Índice:</strong> {widget.index || 'Não definido'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label
                    className="block text-sm font-medium mb-2"
                    style={{ color: currentColors.text.primary }}
                  >
                    Query Elasticsearch (JSON)
                  </label>
                  <textarea
                    value={editedQuery}
                    onChange={(e) => {
                      setEditedQuery(e.target.value);
                      setQueryError(null);
                    }}
                    className="w-full px-4 py-3 rounded-lg border font-mono text-sm transition-colors"
                    style={{
                      backgroundColor: currentColors.bg.secondary,
                      color: currentColors.text.primary,
                      borderColor: queryError ? currentColors.accent.error : currentColors.border.default,
                      minHeight: '400px',
                    }}
                    onFocus={(e) => {
                      if (!queryError) {
                        e.currentTarget.style.borderColor = currentColors.border.focus;
                      }
                    }}
                    onBlur={(e) => {
                      if (!queryError) {
                        e.currentTarget.style.borderColor = currentColors.border.default;
                      }
                    }}
                    placeholder='{"query": {...}, "aggs": {...}}'
                  />
                  {queryError && (
                    <p
                      className="text-sm mt-2"
                      style={{ color: currentColors.accent.error }}
                    >
                      ⚠️ {queryError}
                    </p>
                  )}
                </div>

                <div
                  className="p-4 rounded-lg"
                  style={{
                    backgroundColor: currentColors.bg.tertiary,
                    borderColor: currentColors.accent.warning,
                    borderWidth: '1px',
                  }}
                >
                  <div className="flex items-start gap-2">
                    <svg
                      className="w-5 h-5 mt-0.5 flex-shrink-0"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      style={{ color: currentColors.accent.warning }}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                      />
                    </svg>
                    <div>
                      <p
                        className="text-sm font-medium"
                        style={{ color: currentColors.text.primary }}
                      >
                        ⚠️ Modo Avançado
                      </p>
                      <p
                        className="text-xs mt-1"
                        style={{ color: currentColors.text.secondary }}
                      >
                        Editar a query manualmente pode quebrar a visualização. Tenha certeza do que está fazendo.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div
            className="px-6 py-4 border-t flex items-center justify-end gap-3"
            style={{ borderColor: currentColors.border.default }}
          >
            <button
              onClick={onClose}
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
              onClick={handleSave}
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
              Salvar Alterações
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
