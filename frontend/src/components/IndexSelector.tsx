/**
 * Index Selector Component
 * Dropdown para selecionar índice Elasticsearch com suporte a wildcards
 */

import { useState, useEffect, useRef } from 'react';
import { esServerApi } from '../services/esServerApi';
import { useSettingsStore } from '@stores/settingsStore';

interface IndexSelectorProps {
  serverId: string | null;
  selectedIndex?: string | null;
  onIndexChange: (index: string) => void;
}

export function IndexSelector({
  serverId,
  selectedIndex,
  onIndexChange,
}: IndexSelectorProps) {
  const { currentColors } = useSettingsStore();
  const [indices, setIndices] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [inputValue, setInputValue] = useState(selectedIndex || '');
  const [filteredIndices, setFilteredIndices] = useState<string[]>([]);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (serverId) {
      loadIndices(serverId);
    } else {
      setIndices([]);
      setError('Selecione um servidor primeiro');
    }
  }, [serverId]);

  useEffect(() => {
    setInputValue(selectedIndex || '');
  }, [selectedIndex]);

  useEffect(() => {
    if (!inputValue) {
      setFilteredIndices(indices);
    } else {
      const filtered = indices.filter((index) =>
        index.toLowerCase().includes(inputValue.toLowerCase())
      );
      setFilteredIndices(filtered);
    }
  }, [inputValue, indices]);

  // Fechar dropdown ao clicar fora
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const loadIndices = async (sId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await esServerApi.listIndices(sId);
      const indexNames = data.map((idx) => idx.name).sort();
      setIndices(indexNames);
      setFilteredIndices(indexNames);

      // Se não tem índice selecionado e há índices disponíveis, selecionar o primeiro
      if (!selectedIndex && indexNames.length > 0) {
        onIndexChange(indexNames[0]);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Erro ao carregar índices');
      setIndices([]);
      setFilteredIndices([]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setInputValue(newValue);
    setIsOpen(true);
  };

  const handleSelectIndex = (index: string) => {
    setInputValue(index);
    onIndexChange(index);
    setIsOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      setIsOpen(false);
      inputRef.current?.blur();
    } else if (e.key === 'Enter') {
      if (filteredIndices.length > 0) {
        handleSelectIndex(filteredIndices[0]);
      } else if (inputValue) {
        // Permite usar valor digitado mesmo que não exista (wildcard)
        handleSelectIndex(inputValue);
      }
    }
  };

  const hasWildcard = inputValue.includes('*');
  const isExactMatch = indices.includes(inputValue);

  if (!serverId) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border" style={{
        backgroundColor: currentColors.accent.warning + '20',
        borderColor: currentColors.accent.warning
      }}>
        <span className="text-sm" style={{ color: currentColors.accent.warning }}>⚠️ Selecione um servidor</span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border" style={{
        backgroundColor: currentColors.bg.secondary,
        borderColor: currentColors.border.default
      }}>
        <div className="animate-spin h-4 w-4 border-2 border-t-transparent rounded-full" style={{
          borderColor: currentColors.accent.primary
        }}></div>
        <span className="text-sm" style={{ color: currentColors.text.secondary }}>Carregando índices...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border" style={{
        backgroundColor: currentColors.accent.error + '20',
        borderColor: currentColors.accent.error
      }}>
        <span className="text-sm" style={{ color: currentColors.accent.error }}>❌ Erro ao carregar</span>
      </div>
    );
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <div className="relative">
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          onFocus={() => setIsOpen(true)}
          onKeyDown={handleKeyDown}
          placeholder="Selecione ou digite um padrão..."
          className="w-64 px-3 py-1.5 pr-20 rounded-lg border text-sm transition-colors"
          style={{
            backgroundColor: currentColors.bg.secondary,
            color: currentColors.text.primary,
            borderColor: isOpen ? currentColors.accent.primary : currentColors.border.default,
          }}
        />

        {/* Indicators */}
        <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
          {hasWildcard && (
            <span
              className="text-xs px-1.5 py-0.5 rounded"
              style={{
                backgroundColor: currentColors.accent.warning + '20',
                color: currentColors.accent.warning,
              }}
              title="Padrão com wildcard"
            >
              ✨
            </span>
          )}
          {isExactMatch && !hasWildcard && (
            <span className="text-xs" style={{ color: currentColors.accent.success }} title="Índice válido">
              ✓
            </span>
          )}
          <svg
            className="w-4 h-4 transition-transform"
            style={{
              color: currentColors.text.muted,
              transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            }}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {/* Dropdown */}
      {isOpen && (
        <div
          className="absolute z-50 w-full mt-1 rounded-lg border shadow-xl max-h-64 overflow-y-auto"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          {filteredIndices.length === 0 && indices.length > 0 ? (
            <div className="p-3 text-center" style={{ color: currentColors.text.muted }}>
              {inputValue ? (
                <div>
                  <div className="text-sm mb-1">Nenhum índice encontrado</div>
                  <button
                    onClick={() => handleSelectIndex(inputValue)}
                    className="text-xs mt-2 px-3 py-1.5 rounded-lg transition-colors"
                    style={{
                      backgroundColor: currentColors.accent.primary,
                      color: currentColors.text.inverse
                    }}
                  >
                    {inputValue.includes('*') ? '✨ Usar wildcard' : '➕ Usar digitado'}: <strong>{inputValue}</strong>
                  </button>
                </div>
              ) : (
                'Digite para filtrar índices...'
              )}
            </div>
          ) : (
            <>
              {/* Suggestion para usar input atual se não for match exato */}
              {inputValue && !isExactMatch && inputValue !== '' && (
                <button
                  onClick={() => handleSelectIndex(inputValue)}
                  className="w-full px-3 py-2 text-left border-b transition-colors"
                  style={{
                    backgroundColor: currentColors.bg.hover,
                    borderColor: currentColors.border.default,
                    color: currentColors.text.primary,
                  }}
                >
                  <div className="flex items-center gap-2">
                    {inputValue.includes('*') ? '✨' : '➕'}
                    <span className="font-medium">{inputValue}</span>
                    <span className="text-xs" style={{ color: currentColors.text.muted }}>
                      {inputValue.includes('*') ? '(wildcard)' : '(manual)'}
                    </span>
                  </div>
                </button>
              )}

              {/* Lista de índices */}
              {filteredIndices.map((index) => (
                <button
                  key={index}
                  onClick={() => handleSelectIndex(index)}
                  className="w-full px-3 py-2 text-left text-sm transition-colors"
                  style={{
                    backgroundColor: index === inputValue ? currentColors.bg.tertiary : 'transparent',
                    color: currentColors.text.primary,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                  }}
                  onMouseLeave={(e) => {
                    if (index !== inputValue) {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span>{index}</span>
                    {index === inputValue && (
                      <span style={{ color: currentColors.accent.primary }}>✓</span>
                    )}
                  </div>
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}
