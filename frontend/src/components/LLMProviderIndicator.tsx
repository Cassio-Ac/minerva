/**
 * LLM Provider Indicator Component
 * Exibe e permite selecionar o provedor LLM ativo
 */

import React, { useState, useEffect, useRef } from 'react';
import { useSettingsStore } from '@stores/settingsStore';
import { useLLMProvider } from '@hooks/useLLMProvider';
import axios from 'axios';
import { API_URL } from '../config/api';

interface LLMProviderIndicatorProps {
  compact?: boolean; // Modo compacto para header
}

interface LLMProvider {
  id: string;
  name: string;
  provider_type: 'anthropic' | 'openai' | 'databricks';
  model_name: string;
  is_default: boolean;
}

export const LLMProviderIndicator: React.FC<LLMProviderIndicatorProps> = ({ compact = false }) => {
  const { currentColors } = useSettingsStore();
  const { provider, loading, refresh } = useLLMProvider();
  const [isOpen, setIsOpen] = useState(false);
  const [allProviders, setAllProviders] = useState<LLMProvider[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Fechar dropdown ao clicar fora
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Carregar todos os provedores quando abrir o dropdown
  const loadAllProviders = async () => {
    if (allProviders.length > 0) {
      setIsOpen(true);
      return;
    }

    setLoadingProviders(true);
    try {
      const response = await axios.get(`${API_URL}/llm-providers`);
      setAllProviders(response.data);
      setIsOpen(true);
    } catch (error) {
      console.error('Error loading providers:', error);
    } finally {
      setLoadingProviders(false);
    }
  };

  // Definir provedor como padrão
  const handleSetDefault = async (providerId: string) => {
    try {
      await axios.post(`${API_URL}/llm-providers/${providerId}/set-default`);
      await refresh(); // Recarregar provider atual
      setIsOpen(false);

      // Atualizar lista local
      setAllProviders(prev =>
        prev.map(p => ({ ...p, is_default: p.id === providerId }))
      );
    } catch (error) {
      console.error('Error setting default provider:', error);
      alert('Erro ao definir provedor padrão');
    }
  };

  if (loading) {
    return null; // Não mostrar nada enquanto carrega
  }

  if (!provider) {
    return (
      <div
        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${compact ? 'text-xs' : 'text-sm'}`}
        style={{
          backgroundColor: currentColors.bg.tertiary,
          color: currentColors.text.muted,
          border: `1px solid ${currentColors.border.default}`,
        }}
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        {!compact && <span>Nenhum LLM configurado</span>}
      </div>
    );
  }

  // Ícone baseado no provider type
  const getProviderIcon = (providerType: 'anthropic' | 'openai' | 'databricks') => {
    switch (providerType) {
      case 'anthropic':
        return (
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z" />
          </svg>
        );
      case 'openai':
        return (
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10" />
          </svg>
        );
      case 'databricks':
        return (
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
          </svg>
        );
      default:
        return null;
    }
  };

  // Cor baseada no provider type
  const getProviderColor = (providerType: 'anthropic' | 'openai' | 'databricks') => {
    switch (providerType) {
      case 'anthropic':
        return '#D4745C'; // Coral/laranja
      case 'openai':
        return '#10A37F'; // Verde OpenAI
      case 'databricks':
        return '#FF3621'; // Vermelho Databricks
      default:
        return currentColors.accent.primary;
    }
  };

  const providerColor = getProviderColor(provider.provider_type);

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Botão/Indicador */}
      <button
        onClick={loadAllProviders}
        disabled={loadingProviders}
        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${compact ? 'text-xs' : 'text-sm'} font-medium transition-colors cursor-pointer`}
        style={{
          backgroundColor: currentColors.bg.tertiary,
          color: currentColors.text.primary,
          border: `1px solid ${currentColors.border.default}`,
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.backgroundColor = currentColors.bg.hover;
          e.currentTarget.style.borderColor = currentColors.accent.primary;
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.backgroundColor = currentColors.bg.tertiary;
          e.currentTarget.style.borderColor = currentColors.border.default;
        }}
        title={`Provedor LLM: ${provider.name}\nModelo: ${provider.model_name}\nClique para trocar`}
      >
        <div style={{ color: providerColor }}>{getProviderIcon(provider.provider_type)}</div>
        {compact ? (
          <span className="truncate max-w-[120px]">{provider.provider_type}</span>
        ) : (
          <div className="flex flex-col">
            <span className="font-semibold truncate max-w-[200px]">{provider.name}</span>
            <span className="text-xs opacity-70 truncate max-w-[200px]" style={{ color: currentColors.text.muted }}>
              {provider.model_name}
            </span>
          </div>
        )}
        {/* Ícone dropdown */}
        <svg
          className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown Menu */}
      {isOpen && allProviders.length > 0 && (
        <div
          className="absolute top-full mt-2 rounded-lg shadow-lg border z-50 min-w-[280px]"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
            right: compact ? 0 : 'auto',
            left: compact ? 'auto' : 0,
          }}
        >
          <div className="p-2 border-b" style={{ borderColor: currentColors.border.default }}>
            <p className="text-xs font-semibold" style={{ color: currentColors.text.muted }}>
              Selecionar Provedor LLM
            </p>
          </div>

          <div className="max-h-[300px] overflow-y-auto">
            {allProviders.map((p) => {
              const isActive = p.is_default;
              const color = getProviderColor(p.provider_type);

              return (
                <button
                  key={p.id}
                  onClick={() => handleSetDefault(p.id)}
                  disabled={isActive}
                  className="w-full flex items-center gap-3 px-4 py-3 transition-colors text-left"
                  style={{
                    backgroundColor: isActive ? currentColors.bg.tertiary : 'transparent',
                    color: currentColors.text.primary,
                    cursor: isActive ? 'default' : 'pointer',
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <div style={{ color }}>{getProviderIcon(p.provider_type)}</div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{p.name}</span>
                      {isActive && (
                        <span
                          className="text-xs px-2 py-0.5 rounded-full font-medium"
                          style={{
                            backgroundColor: currentColors.accent.primary,
                            color: currentColors.text.inverse,
                          }}
                        >
                          Ativo
                        </span>
                      )}
                    </div>
                    <div className="text-xs mt-0.5" style={{ color: currentColors.text.muted }}>
                      {p.model_name}
                    </div>
                  </div>
                  {isActive && (
                    <svg
                      className="w-5 h-5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      style={{ color: currentColors.accent.primary }}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </button>
              );
            })}
          </div>

          {allProviders.length === 0 && (
            <div className="p-4 text-center text-sm" style={{ color: currentColors.text.muted }}>
              Nenhum provedor configurado
            </div>
          )}
        </div>
      )}
    </div>
  );
};
