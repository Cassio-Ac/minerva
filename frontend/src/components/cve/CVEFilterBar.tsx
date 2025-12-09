import React from 'react';
import { Search, Filter, Shield } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';

interface CVEFilterBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedSeverityLevels: string[];
  onSeverityLevelChange: (levels: string[]) => void;
  selectedSources: string[];
  onSourceChange: (sources: string[]) => void;
  dateRange: string;
  onDateRangeChange: (range: string) => void;
  severityLevels: string[];
  sources: string[];
}

const CVEFilterBar: React.FC<CVEFilterBarProps> = ({
  searchQuery,
  onSearchChange,
  selectedSeverityLevels,
  onSeverityLevelChange,
  selectedSources,
  onSourceChange,
  dateRange,
  onDateRangeChange,
  severityLevels,
  sources,
}) => {
  const { currentColors } = useSettingsStore();

  const handleSeverityToggle = (level: string) => {
    if (selectedSeverityLevels.includes(level)) {
      onSeverityLevelChange(selectedSeverityLevels.filter(l => l !== level));
    } else {
      onSeverityLevelChange([...selectedSeverityLevels, level]);
    }
  };

  const handleSourceToggle = (source: string) => {
    if (selectedSources.includes(source)) {
      onSourceChange(selectedSources.filter(s => s !== source));
    } else {
      onSourceChange([...selectedSources, source]);
    }
  };

  const getSeverityColor = (level: string) => {
    const colors: Record<string, string> = {
      'CRITICAL': 'bg-red-600 text-white',
      'HIGH': 'bg-orange-600 text-white',
      'MEDIUM': 'bg-yellow-600 text-white',
      'LOW': 'bg-blue-600 text-white',
      'NA': 'bg-gray-600 text-white',
    };
    return colors[level] || 'bg-gray-600 text-white';
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
            placeholder="Buscar CVEs..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg border outline-none focus:ring-2 focus:ring-blue-500"
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
          className="px-4 py-2 rounded-lg border outline-none focus:ring-2 focus:ring-blue-500"
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

      {/* Severity & Source Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <Filter size={16} style={{ color: currentColors.text.secondary }} />
          <span className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
            Severidade:
          </span>
          <div className="flex gap-2 flex-wrap">
            {severityLevels.map((level) => (
              <button
                key={level}
                onClick={() => handleSeverityToggle(level)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  selectedSeverityLevels.includes(level)
                    ? getSeverityColor(level)
                    : ''
                }`}
                style={
                  !selectedSeverityLevels.includes(level)
                    ? {
                        backgroundColor: currentColors.bg.primary,
                        color: currentColors.text.secondary,
                        border: `1px solid ${currentColors.border}`,
                      }
                    : undefined
                }
              >
                {level}
              </button>
            ))}
          </div>
        </div>

        {/* Source Filter */}
        {sources.length > 0 && (
          <div className="flex items-center gap-2">
            <Shield size={16} style={{ color: currentColors.text.secondary }} />
            <span className="text-sm font-medium" style={{ color: currentColors.text.secondary }}>
              Fonte:
            </span>
            <select
              value={selectedSources[0] || ''}
              onChange={(e) =>
                onSourceChange(e.target.value ? [e.target.value] : [])
              }
              className="px-3 py-1 rounded-lg border text-xs outline-none focus:ring-2 focus:ring-blue-500"
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
      {(selectedSeverityLevels.length > 0 || selectedSources.length > 0 || searchQuery) && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs" style={{ color: currentColors.text.secondary }}>
            Filtros ativos:
          </span>
          {selectedSeverityLevels.map((level) => (
            <span
              key={level}
              className={`px-2 py-1 rounded text-xs flex items-center gap-1 ${getSeverityColor(level)}`}
            >
              {level}
              <button onClick={() => handleSeverityToggle(level)} className="hover:opacity-70">
                ×
              </button>
            </span>
          ))}
          {selectedSources.map((source) => (
            <span
              key={source}
              className="px-2 py-1 bg-purple-600 text-white rounded text-xs flex items-center gap-1"
            >
              {source.length > 30 ? source.substring(0, 30) + '...' : source}
              <button onClick={() => handleSourceToggle(source)} className="hover:text-purple-200">
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

export default CVEFilterBar;
