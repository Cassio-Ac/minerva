/**
 * FamiliesList Component - Malware Families Selection
 *
 * Displays list of malware families from Malpedia with:
 * - Search functionality
 * - Multi-selection with checkboxes
 * - Pagination
 */

import React, { useState, useEffect } from 'react';
import { Search, Loader2, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import { ctiService, Family } from '../../services/cti/ctiService';

interface FamiliesListProps {
  selectedFamilies: string[];
  onFamilySelect: (familyName: string, selected: boolean) => void;
}

const FamiliesList: React.FC<FamiliesListProps> = ({ selectedFamilies, onFamilySelect }) => {
  const { currentColors } = useSettingsStore();

  // State
  const [families, setFamilies] = useState<Family[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const pageSize = 20;

  // Load families when filters change
  useEffect(() => {
    loadFamilies();
  }, [searchQuery, page]);

  const loadFamilies = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await ctiService.families.listFamilies({
        search: searchQuery || undefined,
        page,
        page_size: pageSize
      });

      setFamilies(response.families);
      setTotalPages(Math.ceil(response.total / pageSize));
    } catch (error: any) {
      console.error('Error loading families:', error);
      setError(error.response?.data?.detail || 'Failed to load malware families');
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = (familyName: string) => {
    const isSelected = selectedFamilies.includes(familyName);
    onFamilySelect(familyName, !isSelected);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="relative mb-3">
        <Search size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2" style={{ color: currentColors.text.secondary }} />
        <input
          type="text"
          placeholder="Search families..."
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

      {/* Selection Count */}
      {selectedFamilies.length > 0 && (
        <div className="mb-3 px-3 py-1 rounded text-xs font-medium text-white" style={{ backgroundColor: currentColors.accent.primary }}>
          {selectedFamilies.length} selected
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
        ) : families.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-6" style={{ color: currentColors.text.secondary }}>
            <AlertTriangle size={32} className="mb-2 opacity-50" />
            <p className="text-sm">No families found</p>
          </div>
        ) : (
          <div>
            {families.map(family => {
              const isSelected = selectedFamilies.includes(family.name);

              return (
                <div
                  key={family.name}
                  className="p-3 cursor-pointer border-b transition-colors"
                  style={{
                    borderColor: currentColors.border.default,
                    backgroundColor: isSelected ? currentColors.bg.secondary : 'transparent'
                  }}
                  onClick={() => handleToggle(family.name)}
                  onMouseEnter={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.backgroundColor = currentColors.bg.secondary;
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <div className="flex items-start gap-2">
                    {/* Checkbox */}
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => {}}
                      className="mt-1"
                      style={{ accentColor: currentColors.accent.primary }}
                    />

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate" style={{ color: currentColors.text.primary }}>
                        {family.name}
                      </p>
                      {family.os && (
                        <p className="text-xs truncate mt-0.5" style={{ color: currentColors.text.secondary }}>
                          {family.os}
                        </p>
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

export default FamiliesList;
