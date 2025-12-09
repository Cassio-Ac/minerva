import React, { useState } from 'react';
import { Calendar, Filter, Search, X, RefreshCw, Rss } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import { getThemeStyles } from '../../utils/themeStyles';

interface FilterBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedCategories: string[];
  onCategoryChange: (categories: string[]) => void;
  selectedSources: string[];
  onSourceChange: (sources: string[]) => void;
  dateRange: string;
  onDateRangeChange: (range: string) => void;
  categories: string[];
  sources: string[];
  onSyncNow?: () => void;
}

const FilterBar: React.FC<FilterBarProps> = ({
  searchQuery,
  onSearchChange,
  selectedCategories,
  onCategoryChange,
  selectedSources,
  onSourceChange,
  dateRange,
  onDateRangeChange,
  categories,
  sources,
  onSyncNow,
}) => {
  const { currentColors } = useSettingsStore();
  const themeStyles = getThemeStyles(currentColors);
  const [syncing, setSyncing] = useState(false);

  const dateRanges = [
    { value: '24h', label: 'Últimas 24h' },
    { value: '7d', label: 'Última semana' },
    { value: '30d', label: 'Último mês' },
    { value: 'all', label: 'Tudo' },
  ];

  const toggleCategory = (category: string) => {
    if (selectedCategories.includes(category)) {
      onCategoryChange(selectedCategories.filter(c => c !== category));
    } else {
      onCategoryChange([...selectedCategories, category]);
    }
  };

  const toggleSource = (source: string) => {
    if (selectedSources.includes(source)) {
      onSourceChange(selectedSources.filter(s => s !== source));
    } else {
      onSourceChange([...selectedSources, source]);
    }
  };

  const clearFilters = () => {
    onSearchChange('');
    onCategoryChange([]);
    onSourceChange([]);
    onDateRangeChange('7d');
  };

  const handleSyncNow = async () => {
    if (!onSyncNow || syncing) return;

    setSyncing(true);
    try {
      await onSyncNow();
    } finally {
      // Keep spinning for a bit to show feedback
      setTimeout(() => setSyncing(false), 2000);
    }
  };

  const hasActiveFilters = searchQuery || selectedCategories.length > 0 || selectedSources.length > 0 || dateRange !== '7d';

  return (
    <div
      className="rounded-lg shadow-md p-4 mb-6"
      style={{
        backgroundColor: currentColors.bg.primary,
        borderWidth: '1px',
        borderStyle: 'solid',
        borderColor: currentColors.border.default,
      }}
    >
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Search */}
        <div className="flex-1">
          <div className="relative">
            <Search
              className="absolute left-3 top-1/2 transform -translate-y-1/2"
              size={18}
              style={{ color: currentColors.text.secondary }}
            />
            <input
              type="text"
              placeholder="Buscar notícias..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary,
              }}
            />
          </div>
        </div>

        {/* Source Dropdown */}
        <div className="flex items-center gap-2">
          <Rss size={18} style={{ color: currentColors.text.secondary }} />
          <select
            value={selectedSources.length === 1 ? selectedSources[0] : ''}
            onChange={(e) => {
              const value = e.target.value;
              if (value === '') {
                onSourceChange([]);
              } else {
                onSourceChange([value]);
              }
            }}
            className="px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{
              backgroundColor: currentColors.bg.secondary,
              borderColor: currentColors.border.default,
              color: currentColors.text.primary,
            }}
          >
            <option value="">Todas as fontes</option>
            {sources.map(source => (
              <option key={source} value={source}>
                {source}
              </option>
            ))}
          </select>
        </div>

        {/* Date Range */}
        <div className="flex items-center gap-2">
          <Calendar size={18} style={{ color: currentColors.text.secondary }} />
          <select
            value={dateRange}
            onChange={(e) => onDateRangeChange(e.target.value)}
            className="px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{
              backgroundColor: currentColors.bg.secondary,
              borderColor: currentColors.border.default,
              color: currentColors.text.primary,
            }}
          >
            {dateRanges.map(range => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>
        </div>

        {/* Sync Now Button */}
        {onSyncNow && (
          <button
            onClick={handleSyncNow}
            disabled={syncing}
            className="px-4 py-2 text-sm flex items-center gap-2 rounded-lg border transition-colors hover:opacity-70 disabled:opacity-50"
            style={{
              backgroundColor: currentColors.accent.primary,
              borderColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
            title="Sincronizar RSS agora"
          >
            <RefreshCw size={16} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Sincronizando...' : 'Sync Now'}
          </button>
        )}

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="px-4 py-2 text-sm flex items-center gap-2 transition-colors hover:opacity-70"
            style={{ color: currentColors.text.secondary }}
          >
            <X size={16} />
            Limpar
          </button>
        )}
      </div>

      {/* Category Filters */}
      {categories.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          <div
            className="flex items-center gap-2 text-sm font-medium"
            style={{ color: currentColors.text.primary }}
          >
            <Filter size={16} />
            Categorias:
          </div>
          {categories.map(category => {
            const isSelected = selectedCategories.includes(category);
            return (
              <button
                key={category}
                onClick={() => toggleCategory(category)}
                className="px-3 py-1 text-sm rounded-full transition-all"
                style={
                  isSelected
                    ? {
                        backgroundColor: currentColors.accent.primary,
                        color: currentColors.text.inverse,
                      }
                    : {
                        backgroundColor: currentColors.bg.secondary,
                        color: currentColors.text.secondary,
                      }
                }
              >
                {category}
              </button>
            );
          })}
        </div>
      )}

      {/* Active Filters Summary */}
      {hasActiveFilters && (
        <div className="mt-3 text-xs" style={{ color: currentColors.text.secondary }}>
          Filtros ativos:
          {searchQuery && <span className="ml-2">Busca: "{searchQuery}"</span>}
          {selectedCategories.length > 0 && (
            <span className="ml-2">Categorias: {selectedCategories.length}</span>
          )}
          {selectedSources.length > 0 && (
            <span className="ml-2">Fontes: {selectedSources.length}</span>
          )}
          {dateRange !== '7d' && (
            <span className="ml-2">Período: {dateRanges.find(r => r.value === dateRange)?.label}</span>
          )}
        </div>
      )}
    </div>
  );
};

export default FilterBar;
