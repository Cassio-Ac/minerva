import React from 'react';
import { Search, Filter, Calendar } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';

interface BreachFilterBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedTypes: string[];
  onTypeChange: (types: string[]) => void;
  selectedSources: string[];
  onSourceChange: (sources: string[]) => void;
  dateRange: string;
  onDateRangeChange: (range: string) => void;
  types: string[];
  sources: string[];
}

const BreachFilterBar: React.FC<BreachFilterBarProps> = ({
  searchQuery,
  onSearchChange,
  selectedTypes,
  onTypeChange,
  selectedSources,
  onSourceChange,
  dateRange,
  onDateRangeChange,
  types,
  sources,
}) => {
  const { currentColors } = useSettingsStore();

  const handleTypeToggle = (type: string) => {
    if (selectedTypes.includes(type)) {
      onTypeChange(selectedTypes.filter(t => t !== type));
    } else {
      onTypeChange([...selectedTypes, type]);
    }
  };

  const handleSourceToggle = (source: string) => {
    if (selectedSources.includes(source)) {
      onSourceChange(selectedSources.filter(s => s !== source));
    } else {
      onSourceChange([...selectedSources, source]);
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Bar */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search
            className="absolute left-3 top-1/2 transform -translate-y-1/2"
            size={18}
            style={{ color: currentColors.text.secondary }}
          />
          <input
            type="text"
            placeholder="Buscar vazamentos..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg border outline-none focus:ring-2 focus:ring-red-500"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border,
              color: currentColors.text.primary,
            }}
          />
        </div>

        {/* Date Range */}
        <select
          value={dateRange}
          onChange={(e) => onDateRangeChange(e.target.value)}
          className="px-4 py-2 rounded-lg border outline-none focus:ring-2 focus:ring-red-500"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border,
            color: currentColors.text.primary,
          }}
        >
          <option value="24h">Últimas 24h</option>
          <option value="7d">Últimos 7 dias</option>
          <option value="30d">Últimos 30 dias</option>
          <option value="all">Todos</option>
        </select>
      </div>

      {/* Type & Source Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Type Filter */}
        <div className="flex items-center gap-2">
          <Filter size={16} style={{ color: currentColors.text.secondary }} />
          <span className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
            Tipo:
          </span>
          <div className="flex gap-2 flex-wrap">
            {types.map((type) => (
              <button
                key={type}
                onClick={() => handleTypeToggle(type)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  selectedTypes.includes(type)
                    ? 'bg-red-600 text-white'
                    : ''
                }`}
                style={
                  !selectedTypes.includes(type)
                    ? {
                        backgroundColor: currentColors.bg.primary,
                        color: currentColors.text.secondary,
                        border: `1px solid ${currentColors.border}`,
                      }
                    : undefined
                }
              >
                {type}
              </button>
            ))}
          </div>
        </div>

        {/* Source Filter */}
        {sources.length > 0 && (
          <div className="flex items-center gap-2">
            <Calendar size={16} style={{ color: currentColors.text.secondary }} />
            <span className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
              Fonte:
            </span>
            <select
              value={selectedSources[0] || ''}
              onChange={(e) =>
                onSourceChange(e.target.value ? [e.target.value] : [])
              }
              className="px-3 py-1 rounded-lg border text-xs outline-none focus:ring-2 focus:ring-red-500"
              style={{
                backgroundColor: currentColors.bg.primary,
                borderColor: currentColors.border,
                color: currentColors.text.primary,
              }}
            >
              <option value="">Todas as fontes</option>
              {sources.slice(0, 20).map((source) => (
                <option key={source} value={source}>
                  {source}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Active Filters Summary */}
      {(selectedTypes.length > 0 || selectedSources.length > 0 || searchQuery) && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs" style={{ color: currentColors.text.secondary }}>
            Filtros ativos:
          </span>
          {selectedTypes.map((type) => (
            <span
              key={type}
              className="px-2 py-1 bg-red-600 text-white rounded text-xs flex items-center gap-1"
            >
              {type}
              <button onClick={() => handleTypeToggle(type)} className="hover:text-red-200">
                ×
              </button>
            </span>
          ))}
          {selectedSources.map((source) => (
            <span
              key={source}
              className="px-2 py-1 bg-orange-600 text-white rounded text-xs flex items-center gap-1"
            >
              {source.length > 30 ? source.substring(0, 30) + '...' : source}
              <button onClick={() => handleSourceToggle(source)} className="hover:text-orange-200">
                ×
              </button>
            </span>
          ))}
          {searchQuery && (
            <span className="px-2 py-1 bg-blue-600 text-white rounded text-xs flex items-center gap-1">
              Busca: {searchQuery}
              <button onClick={() => onSearchChange('')} className="hover:text-blue-200">
                ×
              </button>
            </span>
          )}
        </div>
      )}
    </div>
  );
};

export default BreachFilterBar;
