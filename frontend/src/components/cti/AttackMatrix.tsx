/**
 * AttackMatrix Component - MITRE ATT&CK Matrix Visualization
 *
 * Displays the ATT&CK matrix (tactics × techniques) with:
 * - 14 tactics (columns)
 * - ~200 techniques (rows per tactic)
 * - Highlighting based on selected actors/families
 * - Click to view technique details
 */

import React, { useState, useEffect } from 'react';
import { Loader2, ExternalLink, X } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import { ctiService, Tactic, Technique, TechniqueDetail } from '../../services/cti/ctiService';

interface AttackMatrixProps {
  highlightedTechniques: string[];
}

const AttackMatrix: React.FC<AttackMatrixProps> = ({ highlightedTechniques }) => {
  const { currentColors } = useSettingsStore();

  // State
  const [tactics, setTactics] = useState<Tactic[]>([]);
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [matrix, setMatrix] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueDetail | null>(null);

  // Load matrix on mount
  useEffect(() => {
    loadMatrix();
  }, []);

  // Debug: Log when highlightedTechniques changes
  useEffect(() => {
    console.log('🎨 AttackMatrix received highlightedTechniques:', highlightedTechniques);
    console.log('🎨 Count:', highlightedTechniques.length);
  }, [highlightedTechniques]);

  const loadMatrix = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await ctiService.techniques.getMatrix();
      setTactics(response.tactics);
      setTechniques(response.techniques);
      setMatrix(response.matrix);
    } catch (error: any) {
      console.error('Error loading matrix:', error);
      setError(error.response?.data?.detail || 'Failed to load ATT&CK matrix');
    } finally {
      setLoading(false);
    }
  };

  const handleTechniqueClick = async (techniqueId: string) => {
    try {
      const details = await ctiService.techniques.getTechniqueDetail(techniqueId);
      setSelectedTechnique(details);
    } catch (error) {
      console.error('Error loading technique details:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full">
        <Loader2 size={32} className="animate-spin" style={{ color: currentColors.accent.primary }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 rounded" style={{ backgroundColor: '#fee2e2', color: '#991b1b' }}>
        {error}
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      {/* Matrix Grid */}
      <div
        className="grid gap-2 pb-4"
        style={{
          gridTemplateColumns: `repeat(${tactics.length}, minmax(120px, 1fr))`
        }}
      >
        {tactics.map(tactic => {
          const tacticTechniques = matrix[tactic.tactic_id] || [];
          const techniqueObjects = tacticTechniques
            .map(tid => techniques.find(t => t.technique_id === tid))
            .filter(Boolean) as Technique[];

          return (
            <div key={tactic.tactic_id} className="flex flex-col">
              {/* Tactic Header */}
              <div
                className="p-2 rounded mb-2 text-center cursor-help text-white"
                style={{ backgroundColor: currentColors.accent.primary }}
                title={tactic.description || ''}
              >
                <p className="text-xs font-semibold leading-tight">
                  {tactic.name}
                </p>
                <p className="text-[10px] opacity-90 mt-0.5">
                  {tactic.tactic_id}
                </p>
              </div>

              {/* Techniques */}
              <div className="flex flex-col gap-1">
                {techniqueObjects.length > 0 ? (
                  techniqueObjects.map(technique => {
                    const isHighlighted = highlightedTechniques.includes(technique.technique_id);

                    return (
                      <div
                        key={technique.technique_id}
                        className="p-2 rounded cursor-pointer transition-all hover:shadow-md"
                        style={{
                          backgroundColor: isHighlighted ? '#ff9800' : currentColors.bg.secondary,
                          border: isHighlighted ? '2px solid #ff9800' : `1px solid ${currentColors.border.default}`,
                          color: isHighlighted ? '#fff' : currentColors.text.primary
                        }}
                        onClick={() => handleTechniqueClick(technique.technique_id)}
                        title={technique.description?.substring(0, 200) + '...' || ''}
                      >
                        <p className="text-[10px] font-semibold leading-tight">
                          {technique.technique_id}
                        </p>
                        <p className="text-[9px] leading-tight mt-0.5 line-clamp-2">
                          {technique.name}
                        </p>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-[10px] p-2" style={{ color: currentColors.text.secondary }}>
                    No techniques
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique Details Modal */}
      {selectedTechnique && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedTechnique(null)}
        >
          <div
            className="rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] flex flex-col"
            style={{ backgroundColor: currentColors.bg.primary }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="p-4 border-b flex items-start justify-between" style={{ borderColor: currentColors.border.default }}>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    {selectedTechnique.technique_id}: {selectedTechnique.technique_name}
                  </h3>
                  {selectedTechnique.url && (
                    <a
                      href={selectedTechnique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:opacity-80"
                    >
                      <ExternalLink size={16} style={{ color: currentColors.accent.primary }} />
                    </a>
                  )}
                </div>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="p-1 rounded hover:bg-opacity-80"
                style={{ backgroundColor: currentColors.bg.secondary }}
              >
                <X size={20} style={{ color: currentColors.text.primary }} />
              </button>
            </div>

            {/* Content */}
            <div className="p-4 overflow-auto flex-1">
              {/* Description */}
              <p className="text-sm mb-4" style={{ color: currentColors.text.primary }}>
                {selectedTechnique.description}
              </p>

              {/* Tactics */}
              {selectedTechnique.tactics && selectedTechnique.tactics.length > 0 && (
                <div className="mb-4">
                  <p className="text-sm font-semibold mb-2" style={{ color: currentColors.text.primary }}>
                    Tactics:
                  </p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedTechnique.tactics.map((tactic: any) => (
                      <span
                        key={tactic.name}
                        className="px-2 py-1 rounded text-xs font-medium text-white"
                        style={{ backgroundColor: currentColors.accent.primary }}
                      >
                        {tactic.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Mitigations */}
              {selectedTechnique.mitigations && selectedTechnique.mitigations.length > 0 && (
                <div>
                  <p className="text-sm font-semibold mb-2" style={{ color: currentColors.text.primary }}>
                    Mitigations:
                  </p>
                  <div className="flex flex-col gap-3">
                    {selectedTechnique.mitigations.map(mitigation => (
                      <div key={mitigation.mitigation_id}>
                        <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                          {mitigation.mitigation_id}: {mitigation.name}
                        </p>
                        {mitigation.description && (
                          <p className="text-xs mt-1" style={{ color: currentColors.text.secondary }}>
                            {mitigation.description.substring(0, 150)}...
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t" style={{ borderColor: currentColors.border.default }}>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-2 rounded hover:opacity-80"
                style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackMatrix;
