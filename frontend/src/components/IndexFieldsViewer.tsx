/**
 * Index Fields Viewer Component
 * Exibe campos e tipos do índice selecionado
 */

import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useSettingsStore } from '@stores/settingsStore';

interface IndexField {
  name: string;
  type: string;
  aggregatable?: boolean;
  searchable?: boolean;
}

interface IndexFieldsViewerProps {
  serverId: string | null;
  indexName: string | null;
}

export function IndexFieldsViewer({ serverId, indexName }: IndexFieldsViewerProps) {
  const { currentColors } = useSettingsStore();
  const [fields, setFields] = useState<IndexField[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (serverId && indexName && isOpen) {
      loadFields();
    }
  }, [serverId, indexName, isOpen]);

  const loadFields = async () => {
    if (!indexName) return;

    setIsLoading(true);
    setError(null);
    try {
      console.log('Loading fields for index:', indexName);
      const fieldsData = await api.getFields(indexName);
      setFields(fieldsData || []);
    } catch (err: any) {
      console.error('Error loading fields:', err);
      setError(err.response?.data?.detail || err.message || 'Erro ao carregar campos');
    } finally {
      setIsLoading(false);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'text':
      case 'keyword':
        return '📝';
      case 'long':
      case 'integer':
      case 'short':
      case 'byte':
      case 'double':
      case 'float':
        return '🔢';
      case 'date':
        return '📅';
      case 'boolean':
        return '✓';
      case 'ip':
        return '🌐';
      case 'geo_point':
        return '📍';
      default:
        return '📄';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'text':
      case 'keyword':
        return 'text-blue-600 bg-blue-50';
      case 'long':
      case 'integer':
      case 'short':
      case 'byte':
      case 'double':
      case 'float':
        return 'text-green-600 bg-green-50';
      case 'date':
        return 'text-purple-600 bg-purple-50';
      case 'boolean':
        return 'text-yellow-600 bg-yellow-50';
      case 'ip':
        return 'text-orange-600 bg-orange-50';
      default:
        return 'text-gray-600 bg-gray-50';
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    console.log('Copied to clipboard:', text);
    // TODO: Adicionar toast notification
  };

  const filteredFields = fields.filter((field) =>
    field.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (!serverId || !indexName) {
    return null;
  }

  return (
    <div className="relative">
      {/* Compact Header Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="px-3 py-2 border rounded-lg transition-colors flex items-center gap-2 text-sm"
        style={{
          backgroundColor: currentColors.bg.secondary,
          borderColor: currentColors.border.default
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.backgroundColor = currentColors.bg.hover;
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
        }}
        title="Ver campos do índice"
      >
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          style={{ color: currentColors.text.secondary }}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span className="font-medium" style={{ color: currentColors.text.primary }}>Campos do Índice</span>
        {!isOpen && fields.length > 0 && (
          <span className="text-xs px-2 py-0.5 rounded-full" style={{
            color: currentColors.text.muted,
            backgroundColor: currentColors.bg.tertiary
          }}>
            {fields.length}
          </span>
        )}
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

      {/* Dropdown Content (Absolute positioned) */}
      {isOpen && (
        <div className="absolute top-full mt-2 left-0 z-50 w-[600px] rounded-lg shadow-xl border" style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}>
          {/* Search */}
          <div className="p-3 border-b" style={{ borderColor: currentColors.border.default }}>
            <input
              type="text"
              placeholder="Buscar campos..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary
              }}
            />
          </div>

          {/* Loading */}
          {isLoading && (
            <div className="p-4 text-center" style={{ color: currentColors.text.muted }}>
              <div className="animate-spin h-6 w-6 border-2 border-t-transparent rounded-full mx-auto mb-2" style={{
                borderColor: currentColors.accent.primary
              }}></div>
              Carregando campos...
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="p-4 text-center text-red-600">
              <p className="text-sm">{error}</p>
              <button onClick={loadFields} className="mt-2 text-sm text-blue-600 hover:underline">
                Tentar novamente
              </button>
            </div>
          )}

          {/* Fields List */}
          {!isLoading && !error && filteredFields.length > 0 && (
            <div className="max-h-96 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0" style={{ backgroundColor: currentColors.bg.tertiary }}>
                  <tr>
                    <th className="px-3 py-2 text-left text-xs font-medium uppercase" style={{ color: currentColors.text.secondary }}>
                      Campo
                    </th>
                    <th className="px-3 py-2 text-left text-xs font-medium uppercase" style={{ color: currentColors.text.secondary }}>
                      Tipo
                    </th>
                    <th className="px-3 py-2 text-center text-xs font-medium uppercase" style={{ color: currentColors.text.secondary }}>
                      Agregável
                    </th>
                    <th className="px-3 py-2 text-center text-xs font-medium uppercase" style={{ color: currentColors.text.secondary }}>
                      Ações
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: currentColors.border.default }}>
                  {filteredFields.map((field, index) => (
                    <tr key={index} className="transition-colors" style={{ backgroundColor: 'transparent' }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      <td className="px-3 py-2 font-mono text-xs" style={{ color: currentColors.text.primary }}>
                        {field.name}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${getTypeColor(
                            field.type
                          )}`}
                        >
                          <span>{getTypeIcon(field.type)}</span>
                          <span>{field.type}</span>
                        </span>
                      </td>
                      <td className="px-3 py-2 text-center">
                        {field.aggregatable ? (
                          <span className="text-green-600">✓</span>
                        ) : (
                          <span className="text-gray-300">−</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <button
                          onClick={() => copyToClipboard(field.name)}
                          className="text-blue-600 hover:text-blue-700"
                          title="Copiar nome do campo"
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
                              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                            />
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Empty State */}
          {!isLoading && !error && filteredFields.length === 0 && fields.length === 0 && (
            <div className="p-4 text-center" style={{ color: currentColors.text.muted }}>
              <p className="text-sm">Nenhum campo encontrado</p>
            </div>
          )}

          {/* No Results */}
          {!isLoading && !error && filteredFields.length === 0 && fields.length > 0 && (
            <div className="p-4 text-center" style={{ color: currentColors.text.muted }}>
              <p className="text-sm">Nenhum campo corresponde à busca</p>
            </div>
          )}

          {/* Footer */}
          <div className="px-3 py-2 border-t text-xs" style={{
            backgroundColor: currentColors.bg.tertiary,
            borderColor: currentColors.border.default,
            color: currentColors.text.secondary
          }}>
            {filteredFields.length} de {fields.length} campos
          </div>
        </div>
      )}
    </div>
  );
}
