/**
 * APT Dashboard - Advanced Persistent Threats
 *
 * Focused view for APT/threat actor analysis with:
 * - Interactive world map with heatmap (main focus)
 * - Stats panel on the right side
 * - Actor details and MITRE ATT&CK techniques
 */

import React, { useState, useEffect } from 'react';
import { Users, Search, Globe, LayoutGrid, X, Target, Shield, Crosshair } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import ActorsList from '../../components/cti/ActorsList';
import AttackMatrix from '../../components/cti/AttackMatrix';
import ActorDetailsPanel from '../../components/cti/ActorDetailsPanel';
import WorldMap from '../../components/cti/WorldMap';
import { ctiService } from '../../services/cti/ctiService';

const APTDashboard: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // View state
  const [rightPanelView, setRightPanelView] = useState<'none' | 'details' | 'matrix'>('none');
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [highlightedTechniques, setHighlightedTechniques] = useState<string[]>([]);

  // View mode: 'map' | 'list'
  const [viewMode, setViewMode] = useState<'map' | 'list'>('map');

  // Search query for highlighting on map
  const [searchQuery, setSearchQuery] = useState('');

  // Stats
  const [stats, setStats] = useState<any>(null);
  const [actorStats, setActorStats] = useState<{ totalActors: number; totalCountries: number } | null>(null);

  // Load initial stats
  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const [techniqueStats, actorsResponse] = await Promise.all([
        ctiService.techniques.getStats(),
        ctiService.actors.getActorsByCountry()
      ]);
      setStats(techniqueStats);

      // Calculate actor stats from country data
      const totalActors = actorsResponse.countries.reduce((sum: number, c: any) => sum + c.count, 0);
      const totalCountries = actorsResponse.countries.length;
      setActorStats({ totalActors, totalCountries });
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const handleActorClick = (actorName: string) => {
    setSelectedActor(actorName);
    setRightPanelView('details');
  };

  const handleTechniquesLoaded = (techniques: string[]) => {
    setHighlightedTechniques(techniques);
  };

  const handleViewMatrix = () => {
    setRightPanelView('matrix');
  };

  const handleClosePanel = () => {
    setRightPanelView('none');
    setSelectedActor(null);
    setHighlightedTechniques([]);
  };

  return (
    <div
      className="h-full overflow-hidden flex flex-col"
      style={{ backgroundColor: currentColors.bg.secondary }}
    >
      {/* Compact Header */}
      <div className="px-4 py-3 flex items-center justify-between flex-shrink-0" style={{ borderBottom: `1px solid ${currentColors.border.default}` }}>
        <div className="flex items-center gap-3">
          <Target size={28} style={{ color: currentColors.accent.error }} />
          <div>
            <h1 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
              APT - Advanced Persistent Threats
            </h1>
            <p className="text-xs" style={{ color: currentColors.text.secondary }}>
              Click on a country or marker to view threat actors
            </p>
          </div>
        </div>

        {/* View Mode Toggle and Search */}
        <div className="flex items-center gap-3">
          {/* Search for highlighting on map */}
          {viewMode === 'map' && (
            <div className="w-64">
              <div className="relative">
                <Search
                  size={14}
                  className="absolute left-3 top-1/2 transform -translate-y-1/2"
                  style={{ color: currentColors.text.secondary }}
                />
                <input
                  type="text"
                  placeholder="Search actor..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-8 py-1.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: currentColors.bg.primary,
                    color: currentColors.text.primary,
                    border: `1px solid ${currentColors.border.default}`,
                  }}
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 p-0.5 rounded hover:bg-opacity-80"
                    style={{ color: currentColors.text.muted }}
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
            </div>
          )}

          {/* View Mode Toggle */}
          <div
            className="flex rounded-lg overflow-hidden"
            style={{ border: `1px solid ${currentColors.border.default}` }}
          >
            <button
              onClick={() => setViewMode('map')}
              className="px-3 py-1.5 flex items-center gap-1.5 text-sm font-medium transition-colors"
              style={{
                backgroundColor: viewMode === 'map' ? currentColors.accent.primary : currentColors.bg.primary,
                color: viewMode === 'map' ? currentColors.text.inverse : currentColors.text.primary
              }}
            >
              <Globe size={14} />
              Map
            </button>
            <button
              onClick={() => setViewMode('list')}
              className="px-3 py-1.5 flex items-center gap-1.5 text-sm font-medium transition-colors"
              style={{
                backgroundColor: viewMode === 'list' ? currentColors.accent.primary : currentColors.bg.primary,
                color: viewMode === 'list' ? currentColors.text.inverse : currentColors.text.primary
              }}
            >
              <LayoutGrid size={14} />
              List
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Map View */}
        {viewMode === 'map' && (
          <>
            {/* Map - Main Area */}
            <div className="flex-1 p-2">
              <WorldMap
                onActorClick={handleActorClick}
                highlightedActor={searchQuery || null}
                className="h-full"
              />
            </div>

            {/* Stats Sidebar - Right */}
            <div
              className="w-48 flex-shrink-0 p-3 flex flex-col gap-3 overflow-y-auto"
              style={{
                backgroundColor: currentColors.bg.primary,
                borderLeft: `1px solid ${currentColors.border.default}`
              }}
            >
              <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: currentColors.text.muted }}>
                Statistics
              </h3>

              {/* Threat Actors */}
              {actorStats && (
                <>
                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Users size={16} style={{ color: currentColors.accent.error }} />
                      <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                        Threat Actors
                      </span>
                    </div>
                    <p className="text-2xl font-bold" style={{ color: currentColors.accent.error }}>
                      {actorStats.totalActors}
                    </p>
                  </div>

                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Globe size={16} style={{ color: currentColors.accent.warning }} />
                      <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                        Countries
                      </span>
                    </div>
                    <p className="text-2xl font-bold" style={{ color: currentColors.accent.warning }}>
                      {actorStats.totalCountries}
                    </p>
                  </div>
                </>
              )}

              {/* MITRE Stats */}
              {stats && (
                <>
                  <div className="mt-2 pt-3" style={{ borderTop: `1px solid ${currentColors.border.default}` }}>
                    <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: currentColors.text.muted }}>
                      MITRE ATT&CK
                    </h3>
                  </div>

                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Crosshair size={16} style={{ color: currentColors.accent.primary }} />
                      <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                        Tactics
                      </span>
                    </div>
                    <p className="text-2xl font-bold" style={{ color: currentColors.accent.primary }}>
                      {stats.total_tactics}
                    </p>
                  </div>

                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Shield size={16} style={{ color: currentColors.accent.secondary }} />
                      <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                        Techniques
                      </span>
                    </div>
                    <p className="text-2xl font-bold" style={{ color: currentColors.accent.secondary }}>
                      {stats.total_techniques}
                    </p>
                  </div>

                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      Sub-techniques
                    </span>
                    <p className="text-xl font-bold" style={{ color: currentColors.text.primary }}>
                      {stats.total_subtechniques}
                    </p>
                  </div>

                  <div
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: currentColors.bg.secondary }}
                  >
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      Mitigations
                    </span>
                    <p className="text-xl font-bold" style={{ color: currentColors.text.primary }}>
                      {stats.total_mitigations}
                    </p>
                  </div>
                </>
              )}
            </div>
          </>
        )}

        {/* List View: Two-Column Layout */}
        {viewMode === 'list' && (
          <div
            className={`flex-1 p-4 ${rightPanelView !== 'none' ? "grid grid-cols-[400px_1fr] gap-4" : "flex"}`}
          >
            {/* Column 1: Threat Actors */}
            <div
              className="rounded-lg p-4 flex flex-col overflow-hidden"
              style={{
                backgroundColor: currentColors.bg.primary,
                width: rightPanelView !== 'none' ? 'auto' : '400px',
                height: '100%'
              }}
            >
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{ color: currentColors.text.primary }}>
                <Users size={20} style={{ color: currentColors.accent.error }} />
                Threat Actors
              </h2>
              <div className="flex-1 overflow-hidden">
                <ActorsList
                  selectedActors={[]}
                  onActorSelect={() => {}}
                  onActorClick={handleActorClick}
                />
              </div>
            </div>

            {/* Column 2: Actor Details Panel */}
            {rightPanelView === 'details' && selectedActor && (
              <ActorDetailsPanel
                actorName={selectedActor}
                onClose={handleClosePanel}
                onTechniquesLoaded={handleTechniquesLoaded}
                onViewMatrix={handleViewMatrix}
              />
            )}

            {/* Column 2: MITRE ATT&CK Matrix */}
            {rightPanelView === 'matrix' && highlightedTechniques.length > 0 && (
              <div
                className="rounded-lg p-4 flex flex-col"
                style={{ backgroundColor: currentColors.bg.primary, minWidth: 0 }}
              >
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    MITRE ATT&CK Matrix - {highlightedTechniques.length} Techniques
                  </h2>
                  <button
                    onClick={() => setRightPanelView('details')}
                    className="px-3 py-1 rounded text-sm hover:opacity-80"
                    style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
                  >
                    Back to Details
                  </button>
                </div>
                <div className="flex-1 overflow-auto">
                  <AttackMatrix highlightedTechniques={highlightedTechniques} />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Actor Details Modal for Map View */}
      {viewMode === 'map' && selectedActor && rightPanelView !== 'matrix' && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50"
          onClick={(e) => {
            if (e.target === e.currentTarget) handleClosePanel();
          }}
        >
          <div
            className="w-full max-w-4xl h-[85vh] flex flex-col rounded-lg shadow-2xl"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <ActorDetailsPanel
              actorName={selectedActor}
              onClose={handleClosePanel}
              onTechniquesLoaded={handleTechniquesLoaded}
              onViewMatrix={handleViewMatrix}
            />
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Matrix Modal for Map View */}
      {viewMode === 'map' && rightPanelView === 'matrix' && highlightedTechniques.length > 0 && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50"
          onClick={(e) => {
            if (e.target === e.currentTarget) handleClosePanel();
          }}
        >
          <div
            className="w-[95vw] h-[90vh] flex flex-col rounded-lg shadow-2xl overflow-hidden"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            {/* Matrix Header */}
            <div
              className="flex items-center justify-between px-6 py-4 border-b flex-shrink-0"
              style={{ borderColor: currentColors.border.default }}
            >
              <div className="flex items-center gap-3">
                <Shield size={24} style={{ color: currentColors.accent.primary }} />
                <div>
                  <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                    MITRE ATT&CK Matrix
                  </h2>
                  <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                    {selectedActor} - {highlightedTechniques.length} techniques highlighted
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setRightPanelView('details')}
                  className="px-4 py-2 rounded text-sm hover:opacity-80 transition-opacity"
                  style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
                >
                  ← Back to Actor
                </button>
                <button
                  onClick={handleClosePanel}
                  className="p-2 rounded hover:bg-opacity-80 transition-colors"
                  style={{ backgroundColor: currentColors.bg.secondary }}
                >
                  <X size={20} style={{ color: currentColors.text.primary }} />
                </button>
              </div>
            </div>

            {/* Matrix Content */}
            <div className="flex-1 overflow-auto p-4">
              <AttackMatrix highlightedTechniques={highlightedTechniques} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APTDashboard;
