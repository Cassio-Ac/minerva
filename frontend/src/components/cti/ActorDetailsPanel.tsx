/**
 * ActorDetailsPanel Component (Non-Modal Version)
 *
 * Displays comprehensive information about a threat actor in a side panel including:
 * - Basic information (name, aliases)
 * - Geopolitical data from MISP Galaxy (country, state sponsor, etc.)
 * - Associated malware families from Malpedia
 * - Targeted countries and sectors
 * - MITRE ATT&CK techniques with "View in Matrix" button
 */

import React, { useState, useEffect } from 'react';
import { X, Loader2, Globe, Flag, Target, Shield, Users, AlertTriangle, ExternalLink, Activity, Database, FileCode, Radio } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useSettingsStore } from '@stores/settingsStore';
import { ctiService, Actor, ActorGeopoliticalData, ActorTechniquesResponse } from '../../services/cti/ctiService';
import mispFeedsService, { MISPIoC } from '../../services/cti/mispFeedsService';
import yaraService, { YaraRule } from '../../services/cti/yaraService';
import otxService, { OTXPulse } from '../../services/cti/otxService';

interface ActorDetailsPanelProps {
  actorName: string;
  onClose: () => void;
  onTechniquesLoaded?: (techniques: string[]) => void;
  onViewMatrix?: () => void;
}

const ActorDetailsPanel: React.FC<ActorDetailsPanelProps> = ({ actorName, onClose, onTechniquesLoaded, onViewMatrix }) => {
  const { currentColors } = useSettingsStore();
  const navigate = useNavigate();

  // State
  const [actor, setActor] = useState<Actor | null>(null);
  const [geopoliticalData, setGeopoliticalData] = useState<ActorGeopoliticalData | null>(null);
  const [techniques, setTechniques] = useState<ActorTechniquesResponse | null>(null);
  const [iocs, setIOCs] = useState<MISPIoC[]>([]);
  const [yaraRules, setYaraRules] = useState<YaraRule[]>([]);
  const [otxPulses, setOtxPulses] = useState<OTXPulse[]>([]);
  const [loadingTechniques, setLoadingTechniques] = useState(false);
  const [loadingIOCs, setLoadingIOCs] = useState(false);
  const [loadingYara, setLoadingYara] = useState(false);
  const [loadingOtx, setLoadingOtx] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load data on mount
  useEffect(() => {
    loadActorData();
  }, [actorName]);

  const loadActorData = async () => {
    setLoading(true);
    setError(null);

    try {
      // Load actor details (includes families)
      const actorData = await ctiService.actors.getActorDetail(actorName, {
        include_families: true
      });
      setActor(actorData);

      // Load geopolitical data from MISP Galaxy
      try {
        const geoData = await ctiService.enrichment.getActorGeopoliticalData(actorName);
        setGeopoliticalData(geoData);
      } catch (geoError) {
        console.warn('Geopolitical data not available:', geoError);
        // Non-critical error - continue with actor data only
      }

    } catch (error: any) {
      console.error('Error loading actor data:', error);
      setError(error.response?.data?.detail || 'Failed to load actor details');
    } finally {
      setLoading(false);
    }
  };

  const loadTechniques = async () => {
    setLoadingTechniques(true);
    try {
      const techniqueData = await ctiService.enrichment.getActorTechniques(actorName);
      setTechniques(techniqueData);
      // Notify parent dashboard to highlight techniques in matrix
      onTechniquesLoaded?.(techniqueData.techniques);
    } catch (error) {
      console.warn('MITRE ATT&CK techniques not available:', error);
      // Non-critical error - actor may not have enrichment yet
    } finally {
      setLoadingTechniques(false);
    }
  };

  const loadIOCs = async () => {
    setLoadingIOCs(true);
    try {
      // Try by threat_actor first
      let response = await mispFeedsService.listIOCs({
        threat_actor: actorName,
        limit: 20
      });

      // If no results, try search
      if (response.iocs.length === 0) {
        response = await mispFeedsService.listIOCs({
          search: actorName,
          limit: 20
        });
      }

      // Try aliases if available
      if (response.iocs.length === 0 && actor?.aka && actor.aka.length > 0) {
        for (const alias of actor.aka.slice(0, 3)) {
          const aliasResponse = await mispFeedsService.listIOCs({
            search: alias,
            limit: 10
          });
          if (aliasResponse.iocs.length > 0) {
            response = aliasResponse;
            break;
          }
        }
      }

      setIOCs(response.iocs);
    } catch (error) {
      console.warn('IOCs not available for actor:', error);
      // Non-critical error
    } finally {
      setLoadingIOCs(false);
    }
  };

  const loadYaraRules = async () => {
    setLoadingYara(true);
    try {
      // Try multiple search strategies to find related rules
      // 1. Search by threat_actor
      let response = await yaraService.listRules({
        threat_actor: actorName,
        page_size: 10
      });

      // 2. If no results, try search (name, description, threat_name)
      if (response.rules.length === 0) {
        response = await yaraService.listRules({
          search: actorName,
          page_size: 10
        });
      }

      // 3. If still no results and actor has aliases, search those too
      if (response.rules.length === 0 && actor?.aka && actor.aka.length > 0) {
        for (const alias of actor.aka.slice(0, 3)) {
          const aliasResponse = await yaraService.listRules({
            search: alias,
            page_size: 5
          });
          if (aliasResponse.rules.length > 0) {
            response = aliasResponse;
            break;
          }
        }
      }

      setYaraRules(response.rules);
    } catch (error) {
      console.warn('YARA rules not available for actor:', error);
    } finally {
      setLoadingYara(false);
    }
  };

  const loadOtxPulses = async () => {
    setLoadingOtx(true);
    try {
      // Try multiple search strategies
      // 1. Search by adversary
      let response = await otxService.listPulses({
        adversary: actorName,
        page_size: 10
      });

      // 2. If no results, try general search
      if (response.pulses.length === 0) {
        response = await otxService.listPulses({
          search: actorName,
          page_size: 10
        });
      }

      // 3. If still no results and actor has aliases, search those
      if (response.pulses.length === 0 && actor?.aka && actor.aka.length > 0) {
        for (const alias of actor.aka.slice(0, 3)) {
          const aliasResponse = await otxService.listPulses({
            search: alias,
            page_size: 5
          });
          if (aliasResponse.pulses.length > 0) {
            response = aliasResponse;
            break;
          }
        }
      }

      setOtxPulses(response.pulses);
    } catch (error) {
      console.warn('OTX pulses not available for actor:', error);
    } finally {
      setLoadingOtx(false);
    }
  };

  return (
    <div
      className="h-full rounded-lg shadow-xl flex flex-col overflow-hidden"
      style={{ backgroundColor: currentColors.bg.primary }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between p-6 border-b"
        style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default
        }}
      >
        <div className="flex items-center gap-3">
          <Shield size={24} style={{ color: currentColors.accent.primary }} />
          <h2 className="text-2xl font-semibold" style={{ color: currentColors.text.primary }}>
            {actorName}
          </h2>
        </div>
        <button
          onClick={onClose}
          className="p-2 rounded hover:bg-opacity-80 transition-colors"
          style={{ backgroundColor: currentColors.bg.secondary }}
        >
          <X size={20} style={{ color: currentColors.text.primary }} />
        </button>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* Loading State */}
        {loading && (
          <div className="flex justify-center items-center p-12">
            <Loader2 size={32} className="animate-spin" style={{ color: currentColors.accent.primary }} />
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="p-4 rounded" style={{ backgroundColor: '#fee2e2', color: '#991b1b' }}>
            <AlertTriangle size={20} className="inline mr-2" />
            {error}
          </div>
        )}

        {/* Content */}
        {!loading && !error && actor && (
          <>
            {/* Aliases */}
            {actor.aka && actor.aka.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                  ALIASES
                </h3>
                <div className="flex flex-wrap gap-2">
                  {actor.aka.map((alias, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1 rounded-full text-sm"
                      style={{
                        backgroundColor: currentColors.bg.secondary,
                        color: currentColors.text.primary
                      }}
                    >
                      {alias}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Geopolitical Data from MISP Galaxy */}
            {geopoliticalData?.found && (
              <div
                className="p-4 rounded-lg border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.default
                }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <Globe size={20} style={{ color: currentColors.accent.primary }} />
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    Geopolitical Intelligence
                  </h3>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  {/* Country */}
                  {geopoliticalData.country && (
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Flag size={16} style={{ color: currentColors.text.secondary }} />
                        <p className="text-xs font-medium" style={{ color: currentColors.text.secondary }}>
                          Country of Origin
                        </p>
                      </div>
                      <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                        {geopoliticalData.country}
                      </p>
                    </div>
                  )}

                  {/* State Sponsor */}
                  {geopoliticalData.state_sponsor && (
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Shield size={16} style={{ color: currentColors.text.secondary }} />
                        <p className="text-xs font-medium" style={{ color: currentColors.text.secondary }}>
                          State Sponsor
                        </p>
                      </div>
                      <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                        {geopoliticalData.state_sponsor}
                      </p>
                    </div>
                  )}

                  {/* Military Unit */}
                  {geopoliticalData.military_unit && (
                    <div className="col-span-2">
                      <div className="flex items-center gap-2 mb-1">
                        <Users size={16} style={{ color: currentColors.text.secondary }} />
                        <p className="text-xs font-medium" style={{ color: currentColors.text.secondary }}>
                          Military Unit
                        </p>
                      </div>
                      <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                        {geopoliticalData.military_unit}
                      </p>
                    </div>
                  )}

                  {/* Attribution Confidence */}
                  {geopoliticalData.attribution_confidence && (
                    <div>
                      <p className="text-xs font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                        Attribution Confidence
                      </p>
                      <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                        {geopoliticalData.attribution_confidence}
                      </p>
                    </div>
                  )}

                  {/* Incident Type */}
                  {geopoliticalData.incident_type && (
                    <div>
                      <p className="text-xs font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                        Incident Type
                      </p>
                      <p className="text-sm font-semibold" style={{ color: currentColors.text.primary }}>
                        {geopoliticalData.incident_type}
                      </p>
                    </div>
                  )}
                </div>

                {/* Targeted Countries */}
                {geopoliticalData.targeted_countries.length > 0 && (
                  <div className="mt-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Target size={16} style={{ color: currentColors.text.secondary }} />
                      <p className="text-xs font-medium" style={{ color: currentColors.text.secondary }}>
                        Targeted Countries
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {geopoliticalData.targeted_countries.map((country, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 rounded text-xs"
                          style={{
                            backgroundColor: currentColors.bg.primary,
                            color: currentColors.text.primary
                          }}
                        >
                          {country}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Targeted Sectors */}
                {geopoliticalData.targeted_sectors.length > 0 && (
                  <div className="mt-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Target size={16} style={{ color: currentColors.text.secondary }} />
                      <p className="text-xs font-medium" style={{ color: currentColors.text.secondary }}>
                        Targeted Sectors
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {geopoliticalData.targeted_sectors.map((sector, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 rounded text-xs"
                          style={{
                            backgroundColor: currentColors.bg.primary,
                            color: currentColors.text.primary
                          }}
                        >
                          {sector}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Description */}
                {geopoliticalData.description && (
                  <div className="mt-4">
                    <p className="text-xs font-medium mb-1" style={{ color: currentColors.text.secondary }}>
                      Description
                    </p>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>
                      {geopoliticalData.description}
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Associated Malware Families */}
            {actor.familias_relacionadas && actor.familias_relacionadas.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-3" style={{ color: currentColors.text.secondary }}>
                  ASSOCIATED MALWARE FAMILIES ({actor.familias_relacionadas.length})
                </h3>
                <div className="grid grid-cols-2 gap-2">
                  {actor.familias_relacionadas.map((family, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded border"
                      style={{
                        backgroundColor: currentColors.bg.secondary,
                        borderColor: currentColors.border.default
                      }}
                    >
                      <p className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                        {family}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Description */}
            {actor.explicacao && (
              <div>
                <h3 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                  DESCRIPTION
                </h3>
                <p className="text-sm leading-relaxed" style={{ color: currentColors.text.primary }}>
                  {actor.explicacao}
                </p>
              </div>
            )}

            {/* MITRE ATT&CK Techniques - Dynamic Load */}
            <div
              className="p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Activity size={20} style={{ color: currentColors.accent.primary }} />
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    MITRE ATT&CK Techniques
                  </h3>
                </div>
                {!techniques && !loadingTechniques && (
                  <button
                    onClick={loadTechniques}
                    className="px-3 py-1 rounded text-sm hover:opacity-80 transition-opacity"
                    style={{
                      backgroundColor: currentColors.accent.primary,
                      color: '#fff'
                    }}
                  >
                    Load Techniques
                  </button>
                )}
              </div>

              {loadingTechniques && (
                <div className="flex justify-center p-4">
                  <Loader2 size={20} className="animate-spin" style={{ color: currentColors.accent.primary }} />
                </div>
              )}

              {techniques && (
                <div>
                  <div className="mb-3 flex items-center justify-between">
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      {techniques.techniques_count} techniques identified
                      {techniques.from_cache && <span className="ml-2">(cached)</span>}
                    </span>
                    {techniques.techniques_count > 0 && onViewMatrix && (
                      <button
                        onClick={() => {
                          onViewMatrix();
                        }}
                        className="px-3 py-1 rounded text-xs hover:opacity-80 transition-opacity flex items-center gap-1"
                        style={{
                          backgroundColor: currentColors.accent.primary,
                          color: '#fff'
                        }}
                      >
                        <ExternalLink size={12} />
                        View in Matrix
                      </button>
                    )}
                  </div>

                  {techniques.techniques_count > 0 ? (
                    <div className="grid grid-cols-3 gap-2">
                      {techniques.techniques.map((techId) => (
                        <div
                          key={techId}
                          className="px-2 py-1.5 rounded text-center text-xs font-mono"
                          style={{
                            backgroundColor: currentColors.bg.primary,
                            color: currentColors.accent.primary,
                            border: `1px solid ${currentColors.accent.primary}`
                          }}
                        >
                          {techId}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-center py-4" style={{ color: currentColors.text.secondary }}>
                      No MITRE ATT&CK mapping available for this actor
                    </p>
                  )}
                </div>
              )}

              {!techniques && !loadingTechniques && (
                <p className="text-sm text-center py-4" style={{ color: currentColors.text.secondary }}>
                  Click "Load Techniques" to view MITRE ATT&CK mapping
                </p>
              )}
            </div>

            {/* References */}
            {actor.referencias && actor.referencias.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2" style={{ color: currentColors.text.secondary }}>
                  REFERENCES
                </h3>
                <div className="space-y-2">
                  {actor.referencias.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm hover:underline"
                      style={{ color: currentColors.accent.primary }}
                    >
                      <ExternalLink size={14} />
                      {ref.desc || ref.url}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* MISP IOCs - Related Indicators */}
            <div
              className="p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Database size={20} style={{ color: '#f59e0b' }} />
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    MISP IOCs
                  </h3>
                </div>
                {iocs.length === 0 && !loadingIOCs && (
                  <button
                    onClick={loadIOCs}
                    className="px-3 py-1 rounded text-sm hover:opacity-80 transition-opacity"
                    style={{
                      backgroundColor: '#f59e0b',
                      color: '#fff'
                    }}
                  >
                    Load IOCs
                  </button>
                )}
              </div>

              {loadingIOCs && (
                <div className="flex justify-center p-4">
                  <Loader2 size={20} className="animate-spin" style={{ color: '#f59e0b' }} />
                </div>
              )}

              {iocs.length > 0 && (
                <div>
                  <div className="mb-3">
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      {iocs.length} IOCs found in MISP feeds
                    </span>
                  </div>

                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {iocs.map((ioc) => (
                      <div
                        key={ioc.id}
                        className="p-3 rounded border"
                        style={{
                          backgroundColor: currentColors.bg.primary,
                          borderColor: currentColors.border.default
                        }}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <p className="font-mono text-xs mb-1 break-all" style={{ color: currentColors.text.primary }}>
                              {ioc.value}
                            </p>
                            <div className="flex gap-1 flex-wrap">
                              <span
                                className="px-2 py-0.5 rounded text-xs"
                                style={{
                                  backgroundColor: ioc.type === 'ip' ? '#3b82f6' : ioc.type === 'domain' ? '#10b981' : ioc.type === 'url' ? '#8b5cf6' : '#06b6d4',
                                  color: '#fff'
                                }}
                              >
                                {ioc.type}
                              </span>
                              {ioc.malware_family && (
                                <span
                                  className="px-2 py-0.5 rounded text-xs"
                                  style={{ backgroundColor: '#dc2626', color: '#fff' }}
                                >
                                  {ioc.malware_family}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {iocs.length === 0 && !loadingIOCs && (
                <p className="text-sm text-center py-4" style={{ color: currentColors.text.secondary }}>
                  Click "Load IOCs" to view indicators from MISP feeds
                </p>
              )}
            </div>

            {/* YARA Rules - Correlation */}
            <div
              className="p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileCode size={20} style={{ color: '#8b5cf6' }} />
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    YARA Rules
                  </h3>
                </div>
                {yaraRules.length === 0 && !loadingYara && (
                  <button
                    onClick={loadYaraRules}
                    className="px-3 py-1 rounded text-sm hover:opacity-80 transition-opacity"
                    style={{
                      backgroundColor: '#8b5cf6',
                      color: '#fff'
                    }}
                  >
                    Find Rules
                  </button>
                )}
              </div>

              {loadingYara && (
                <div className="flex justify-center p-4">
                  <Loader2 size={20} className="animate-spin" style={{ color: '#8b5cf6' }} />
                </div>
              )}

              {yaraRules.length > 0 && (
                <div>
                  <div className="mb-3 flex items-center justify-between">
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      {yaraRules.length} detection rules found
                    </span>
                    <button
                      onClick={() => navigate(`/cti/yara?threat_actor=${encodeURIComponent(actorName)}`)}
                      className="px-2 py-1 rounded text-xs hover:opacity-80 flex items-center gap-1"
                      style={{ backgroundColor: '#8b5cf620', color: '#8b5cf6' }}
                    >
                      View All
                      <ExternalLink size={10} />
                    </button>
                  </div>

                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {yaraRules.slice(0, 5).map((rule) => (
                      <div
                        key={rule.id}
                        className="p-2 rounded border"
                        style={{
                          backgroundColor: currentColors.bg.primary,
                          borderColor: currentColors.border.default
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="px-1.5 py-0.5 rounded text-xs"
                            style={{ backgroundColor: '#8b5cf6', color: '#fff' }}
                          >
                            {rule.category?.toUpperCase() || 'OTHER'}
                          </span>
                          <span className="text-sm font-medium truncate" style={{ color: currentColors.text.primary }}>
                            {rule.rule_name}
                          </span>
                        </div>
                        {rule.description && (
                          <p className="text-xs line-clamp-1" style={{ color: currentColors.text.secondary }}>
                            {rule.description}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {yaraRules.length === 0 && !loadingYara && (
                <p className="text-sm text-center py-4" style={{ color: currentColors.text.secondary }}>
                  Click "Find Rules" to search for related YARA detection rules
                </p>
              )}
            </div>

            {/* OTX Pulses - Correlation */}
            <div
              className="p-4 rounded-lg border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Radio size={20} style={{ color: '#06b6d4' }} />
                  <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    OTX Pulses
                  </h3>
                </div>
                {otxPulses.length === 0 && !loadingOtx && (
                  <button
                    onClick={loadOtxPulses}
                    className="px-3 py-1 rounded text-sm hover:opacity-80 transition-opacity"
                    style={{
                      backgroundColor: '#06b6d4',
                      color: '#fff'
                    }}
                  >
                    Find Pulses
                  </button>
                )}
              </div>

              {loadingOtx && (
                <div className="flex justify-center p-4">
                  <Loader2 size={20} className="animate-spin" style={{ color: '#06b6d4' }} />
                </div>
              )}

              {otxPulses.length > 0 && (
                <div>
                  <div className="mb-3 flex items-center justify-between">
                    <span className="text-xs" style={{ color: currentColors.text.secondary }}>
                      {otxPulses.length} threat intel pulses found
                    </span>
                    <button
                      onClick={() => navigate(`/cti/pulses?adversary=${encodeURIComponent(actorName)}`)}
                      className="px-2 py-1 rounded text-xs hover:opacity-80 flex items-center gap-1"
                      style={{ backgroundColor: '#06b6d420', color: '#06b6d4' }}
                    >
                      View All
                      <ExternalLink size={10} />
                    </button>
                  </div>

                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {otxPulses.slice(0, 5).map((pulse) => (
                      <div
                        key={pulse.id}
                        className="p-2 rounded border"
                        style={{
                          backgroundColor: currentColors.bg.primary,
                          borderColor: currentColors.border.default
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="px-1.5 py-0.5 rounded text-xs"
                            style={{
                              backgroundColor: pulse.tlp === 'white' ? '#f3f4f6' : pulse.tlp === 'green' ? '#10b981' : '#f59e0b',
                              color: pulse.tlp === 'white' ? '#000' : '#fff',
                              border: pulse.tlp === 'white' ? '1px solid #d1d5db' : 'none'
                            }}
                          >
                            TLP:{pulse.tlp?.toUpperCase()}
                          </span>
                          <span className="text-xs" style={{ color: currentColors.text.muted }}>
                            {pulse.indicator_count} IOCs
                          </span>
                        </div>
                        <p className="text-sm font-medium line-clamp-2" style={{ color: currentColors.text.primary }}>
                          {pulse.name}
                        </p>
                        {pulse.tags.length > 0 && (
                          <div className="flex gap-1 flex-wrap mt-1">
                            {pulse.tags.slice(0, 3).map((tag, i) => (
                              <span
                                key={i}
                                className="px-1 py-0.5 rounded text-xs"
                                style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.muted }}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {otxPulses.length === 0 && !loadingOtx && (
                <p className="text-sm text-center py-4" style={{ color: currentColors.text.secondary }}>
                  Click "Find Pulses" to search for related OTX threat intel
                </p>
              )}
            </div>

            {/* Malpedia Link */}
            {actor.url && (
              <div className="pt-4 border-t" style={{ borderColor: currentColors.border.default }}>
                <a
                  href={actor.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-sm hover:underline"
                  style={{ color: currentColors.accent.primary }}
                >
                  <ExternalLink size={14} />
                  View on Malpedia
                </a>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default ActorDetailsPanel;
