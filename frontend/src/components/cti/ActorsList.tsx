/**
 * ActorsList Component - Threat Actors Selection
 *
 * Displays list of threat actors from Malpedia with:
 * - Search functionality
 * - Country filter
 * - Multi-selection with checkboxes
 * - Pagination
 */

import React, { useState, useEffect } from 'react';
import { Search, Loader2, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import { ctiService, Actor } from '../../services/cti/ctiService';

interface ActorsListProps {
  selectedActors: string[];
  onActorSelect: (actorName: string, selected: boolean) => void;
  onActorClick?: (actorName: string) => void;
}

const ActorsList: React.FC<ActorsListProps> = ({ selectedActors, onActorSelect, onActorClick }) => {
  const { currentColors } = useSettingsStore();

  // State
  const [actors, setActors] = useState<Actor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [countryFilter, setCountryFilter] = useState('');
  const [countries, setCountries] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const pageSize = 20;

  // Load countries on mount
  useEffect(() => {
    loadCountries();
  }, []);

  // Load actors when filters change
  useEffect(() => {
    loadActors();
  }, [searchQuery, countryFilter, page]);

  const loadCountries = async () => {
    try {
      const data = await ctiService.actors.getActorCountries();
      setCountries(data.sort());
    } catch (error) {
      console.error('Error loading countries:', error);
    }
  };

  const loadActors = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await ctiService.actors.listActors({
        search: searchQuery || undefined,
        country: countryFilter || undefined,
        page,
        page_size: pageSize
      });

      setActors(response.actors);
      setTotalPages(Math.ceil(response.total / pageSize));
    } catch (error: any) {
      console.error('Error loading actors:', error);
      setError(error.response?.data?.detail || 'Failed to load threat actors');
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = (actorName: string) => {
    console.log('🔘 ActorsList handleToggle called:', actorName);
    const isSelected = selectedActors.includes(actorName);
    console.log('🔘 isSelected:', isSelected, '-> will be:', !isSelected);
    console.log('🔘 Calling onActorSelect...');
    onActorSelect(actorName, !isSelected);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="relative mb-3">
        <Search size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2" style={{ color: currentColors.text.secondary }} />
        <input
          type="text"
          placeholder="Search actors..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setPage(1);
          }}
          className="w-full pl-10 pr-3 py-2 rounded text-sm focus:outline-none focus:ring-2"
          style={{
            backgroundColor: currentColors.bg.secondary,
            color: currentColors.text.primary,
            border: `1px solid ${currentColors.border.default}`
          }}
        />
      </div>

      {/* Country Filter */}
      <select
        value={countryFilter}
        onChange={(e) => {
          setCountryFilter(e.target.value);
          setPage(1);
        }}
        className="mb-3 px-3 py-2 rounded text-sm focus:outline-none focus:ring-2"
        style={{
          backgroundColor: currentColors.bg.secondary,
          color: currentColors.text.primary,
          border: `1px solid ${currentColors.border.default}`
        }}
      >
        <option value="">All Countries</option>
        {countries.map((country, idx) => (
          <option key={`country-${idx}-${country}`} value={country}>{country}</option>
        ))}
      </select>

      {/* Selection Count */}
      {selectedActors.length > 0 && (
        <div className="mb-3 px-3 py-1 rounded text-xs font-medium text-white" style={{ backgroundColor: currentColors.accent.primary }}>
          {selectedActors.length} selected
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mb-3 p-3 rounded text-sm" style={{ backgroundColor: '#fee2e2', color: '#991b1b' }}>
          {String(error)}
        </div>
      )}

      {/* List */}
      <div className="flex-1 overflow-auto mb-3">
        {loading ? (
          <div className="flex justify-center p-6">
            <Loader2 size={24} className="animate-spin" style={{ color: currentColors.accent.primary }} />
          </div>
        ) : actors.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-6" style={{ color: currentColors.text.secondary }}>
            <AlertTriangle size={32} className="mb-2 opacity-50" />
            <p className="text-sm">No actors found</p>
          </div>
        ) : (
          <div>
            {actors.map(actor => {
              const isSelected = selectedActors.includes(actor.name);

              return (
                <div
                  key={actor.name}
                  className="p-3 border-b cursor-pointer transition-colors hover:bg-opacity-80"
                  style={{
                    borderColor: currentColors.border.default,
                    backgroundColor: 'transparent'
                  }}
                  onClick={() => onActorClick?.(actor.name)}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                >
                  <div className="flex-1 min-w-0">
                    {/* Actor Name */}
                    <div className="flex items-center gap-2">
                      <p
                        className="text-sm font-medium truncate"
                        style={{ color: currentColors.text.primary }}
                      >
                        {actor.name}
                      </p>
                    </div>

                    {/* Badges */}
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {actor.country && (
                        <span className="px-2 py-0.5 rounded text-xs" style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.secondary }}>
                          {actor.country}
                        </span>
                      )}
                      {actor.familias_relacionadas && actor.familias_relacionadas.length > 0 && (
                        <span className="px-2 py-0.5 rounded text-xs" style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.secondary }}>
                          {actor.familias_relacionadas.length} families
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-1 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-opacity-80"
            style={{ backgroundColor: currentColors.bg.secondary }}
          >
            <ChevronLeft size={16} style={{ color: currentColors.text.primary }} />
          </button>
          <span className="text-sm" style={{ color: currentColors.text.primary }}>
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="p-1 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-opacity-80"
            style={{ backgroundColor: currentColors.bg.secondary }}
          >
            <ChevronRight size={16} style={{ color: currentColors.text.primary }} />
          </button>
        </div>
      )}
    </div>
  );
};

export default ActorsList;
