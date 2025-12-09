/**
 * TimeRangePicker Component
 * Seletor de período temporal com presets e custom range
 */

import { useState } from 'react';
import { useSettingsStore } from '@stores/settingsStore';

export interface TimeRange {
  type: 'preset' | 'custom';
  preset?: string;
  from?: string;
  to?: string;
  label: string;
}

interface TimeRangePickerProps {
  value?: TimeRange;
  onChange: (timeRange: TimeRange) => void;
}

const PRESETS = [
  { value: 'now-1h', label: 'Última hora', from: 'now-1h', to: 'now' },
  { value: 'now-3h', label: 'Últimas 3 horas', from: 'now-3h', to: 'now' },
  { value: 'now-6h', label: 'Últimas 6 horas', from: 'now-6h', to: 'now' },
  { value: 'now-12h', label: 'Últimas 12 horas', from: 'now-12h', to: 'now' },
  { value: 'now-24h', label: 'Últimas 24 horas', from: 'now-24h', to: 'now' },
  { value: 'now-7d', label: 'Últimos 7 dias', from: 'now-7d', to: 'now' },
  { value: 'now-30d', label: 'Últimos 30 dias', from: 'now-30d', to: 'now' },
  { value: 'now-90d', label: 'Últimos 90 dias', from: 'now-90d', to: 'now' },
  { value: 'now-6M', label: 'Últimos 6 meses', from: 'now-6M', to: 'now' },
  { value: 'now-1y', label: 'Último ano', from: 'now-1y', to: 'now' },
  { value: 'now-2y', label: 'Últimos 2 anos', from: 'now-2y', to: 'now' },
  { value: 'now-5y', label: 'Últimos 5 anos', from: 'now-5y', to: 'now' },
  { value: 'all', label: 'Todos os dados (fulltime)', from: '*', to: 'now' },
];

export function TimeRangePicker({ value, onChange }: TimeRangePickerProps) {
  const { currentColors } = useSettingsStore();
  const [isOpen, setIsOpen] = useState(false);
  const [showCustom, setShowCustom] = useState(false);
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');

  const currentLabel = value?.label || 'Últimos 30 dias';

  const handlePresetClick = (preset: typeof PRESETS[0]) => {
    onChange({
      type: 'preset',
      preset: preset.value,
      from: preset.from,
      to: preset.to,
      label: preset.label,
    });
    setIsOpen(false);
    setShowCustom(false);
  };

  const handleCustomSubmit = () => {
    if (!customFrom || !customTo) {
      alert('Por favor, preencha ambas as datas');
      return;
    }

    const fromDate = new Date(customFrom);
    const toDate = new Date(customTo);

    if (fromDate > toDate) {
      alert('Data inicial deve ser anterior à data final');
      return;
    }

    onChange({
      type: 'custom',
      from: customFrom,
      to: customTo,
      label: `${fromDate.toLocaleDateString('pt-BR')} - ${toDate.toLocaleDateString('pt-BR')}`,
    });
    setIsOpen(false);
    setShowCustom(false);
    setCustomFrom('');
    setCustomTo('');
  };

  return (
    <div className="relative">
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 border rounded-lg text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
        style={{
          backgroundColor: currentColors.bg.secondary,
          borderColor: currentColors.border.default,
          color: currentColors.text.primary
        }}
      >
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
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span>{currentLabel}</span>
        <svg
          className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          style={{ color: currentColors.text.muted }}
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown */}
      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => {
              setIsOpen(false);
              setShowCustom(false);
            }}
          />

          {/* Dropdown Content */}
          <div className="absolute top-full right-0 mt-2 w-72 rounded-lg shadow-lg border z-20" style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default
          }}>
            {!showCustom ? (
              <>
                {/* Presets */}
                <div className="p-2">
                  <div className="text-xs font-semibold uppercase px-2 py-1 mb-1" style={{
                    color: currentColors.text.muted
                  }}>
                    Período
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {PRESETS.map((preset) => (
                      <button
                        key={preset.value}
                        onClick={() => handlePresetClick(preset)}
                        className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                          value?.preset === preset.value
                            ? 'bg-blue-50 text-blue-700 font-medium'
                            : ''
                        }`}
                        style={value?.preset !== preset.value ? {
                          color: currentColors.text.secondary,
                          backgroundColor: 'transparent'
                        } : {}}
                        onMouseEnter={(e) => {
                          if (value?.preset !== preset.value) {
                            e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (value?.preset !== preset.value) {
                            e.currentTarget.style.backgroundColor = 'transparent';
                          }
                        }}
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Divider */}
                <div className="border-t" style={{ borderColor: currentColors.border.default }} />

                {/* Custom Range Button */}
                <div className="p-2">
                  <button
                    onClick={() => setShowCustom(true)}
                    className="w-full text-left px-3 py-2 rounded text-sm text-blue-600 hover:bg-blue-50 transition-colors flex items-center gap-2"
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
                        d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                      />
                    </svg>
                    Período customizado
                  </button>
                </div>
              </>
            ) : (
              <>
                {/* Custom Range Form */}
                <div className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>Período Customizado</h3>
                    <button
                      onClick={() => setShowCustom(false)}
                      style={{ color: currentColors.text.muted }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.color = currentColors.text.secondary;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.color = currentColors.text.muted;
                      }}
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

                  <div className="space-y-4">
                    <div>
                      <label className="block text-xs font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                        Data e hora inicial
                      </label>
                      <input
                        type="datetime-local"
                        value={customFrom}
                        onChange={(e) => setCustomFrom(e.target.value)}
                        className="w-full px-3 py-2.5 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                        style={{
                          backgroundColor: currentColors.bg.secondary,
                          borderColor: currentColors.border.default,
                          color: currentColors.text.primary,
                          colorScheme: 'dark'
                        }}
                        placeholder="Selecione data e hora"
                      />
                      <p className="mt-1 text-xs" style={{ color: currentColors.text.muted }}>
                        Clique para abrir o calendário
                      </p>
                    </div>

                    <div>
                      <label className="block text-xs font-medium mb-2" style={{ color: currentColors.text.secondary }}>
                        Data e hora final
                      </label>
                      <input
                        type="datetime-local"
                        value={customTo}
                        onChange={(e) => setCustomTo(e.target.value)}
                        className="w-full px-3 py-2.5 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                        style={{
                          backgroundColor: currentColors.bg.secondary,
                          borderColor: currentColors.border.default,
                          color: currentColors.text.primary,
                          colorScheme: 'dark'
                        }}
                        placeholder="Selecione data e hora"
                      />
                      <p className="mt-1 text-xs" style={{ color: currentColors.text.muted }}>
                        Clique para abrir o calendário
                      </p>
                    </div>

                    <button
                      onClick={handleCustomSubmit}
                      className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
                    >
                      Aplicar
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
