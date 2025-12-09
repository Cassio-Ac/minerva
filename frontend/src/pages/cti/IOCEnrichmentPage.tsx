/**
 * IOC Enrichment Page
 * Página para enriquecer IOCs usando LLM e visualizar threat intelligence
 */

import React, { useState } from 'react';
import {
  Brain,
  Shield,
  Loader2,
  AlertCircle,
  Check,
  Target,
  TrendingUp,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import iocEnrichmentService, { EnrichedIOC, EnrichFromFeedResponse } from '../../services/cti/iocEnrichmentService';

const IOCEnrichmentPage: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [selectedFeed, setSelectedFeed] = useState<string>('');
  const [limit, setLimit] = useState<number>(10);
  const [loading, setLoading] = useState(false);
  const [enrichResult, setEnrichResult] = useState<EnrichFromFeedResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const availableFeeds = [
    { id: 'diamondfox_c2', name: 'DiamondFox C2 Panels (Unit42)' },
    { id: 'sslbl', name: 'abuse.ch SSL Blacklist' },
    { id: 'openphish', name: 'OpenPhish' },
    { id: 'serpro', name: 'SERPRO (BR Gov)' },
    { id: 'urlhaus', name: 'URLhaus' },
    { id: 'threatfox', name: 'ThreatFox' },
    { id: 'emerging_threats', name: 'Emerging Threats' },
    { id: 'alienvault_reputation', name: 'AlienVault Reputation' },
    { id: 'blocklist_de', name: 'blocklist.de' },
    { id: 'greensnow', name: 'GreenSnow' },
    { id: 'cins_badguys', name: 'CINS Score Bad Guys' },
  ];

  const handleEnrichFromFeed = async () => {
    if (!selectedFeed) {
      setError('Selecione um feed');
      return;
    }

    setLoading(true);
    setError(null);
    setEnrichResult(null);

    try {
      const result = await iocEnrichmentService.enrichFromFeed({
        feed_type: selectedFeed,
        limit: limit,
      });
      setEnrichResult(result);
    } catch (err: any) {
      setError(`Erro ao enriquecer IOCs: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical':
      case 'high':
        return '#dc2626'; // red
      case 'medium':
        return '#f59e0b'; // orange
      case 'low':
        return '#3b82f6'; // blue
      default:
        return '#6b7280'; // gray
    }
  };

  const getThreatTypeColor = (threatType: string): string => {
    switch (threatType) {
      case 'c2':
      case 'malware_delivery':
      case 'data_exfiltration':
        return '#dc2626'; // red
      case 'phishing':
        return '#f59e0b'; // orange
      case 'reconnaissance':
        return '#3b82f6'; // blue
      default:
        return '#6b7280'; // gray
    }
  };

  return (
    <div className="h-full overflow-y-auto p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Brain size={32} style={{ color: currentColors.text.primary }} />
          <h1 className="text-3xl font-semibold" style={{ color: currentColors.text.primary }}>
            IOC Enrichment com LLM
          </h1>
        </div>
        <p className="text-sm" style={{ color: currentColors.text.secondary }}>
          Enriqueça IOCs com contexto de threat intelligence usando LLM e MITRE ATT&CK
        </p>
      </div>

      {/* Controls */}
      <div className="p-6 rounded-lg mb-6" style={{ backgroundColor: currentColors.bg.primary }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm mb-2" style={{ color: currentColors.text.secondary }}>
              Selecione um Feed para Enriquecer
            </label>
            <select
              value={selectedFeed}
              onChange={(e) => setSelectedFeed(e.target.value)}
              className="w-full p-2 rounded border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.primary,
                borderColor: currentColors.border.default,
              }}
            >
              <option value="">-- Selecione --</option>
              {availableFeeds.map((feed) => (
                <option key={feed.id} value={feed.id}>
                  {feed.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm mb-2" style={{ color: currentColors.text.secondary }}>
              Limite de IOCs
            </label>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="w-full p-2 rounded border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.primary,
                borderColor: currentColors.border.default,
              }}
            >
              <option value={1}>1 IOC</option>
              <option value={3}>3 IOCs</option>
              <option value={5}>5 IOCs</option>
              <option value={10}>10 IOCs</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleEnrichFromFeed}
          disabled={loading || !selectedFeed}
          className="mt-4 px-6 py-2 rounded flex items-center gap-2 disabled:opacity-50 hover:opacity-90 transition-opacity"
          style={{
            backgroundColor: currentColors.accent.primary,
            color: '#fff',
          }}
        >
          {loading ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Enriquecendo...
            </>
          ) : (
            <>
              <Brain size={16} />
              Enriquecer
            </>
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-lg mb-6 flex items-start gap-3" style={{ backgroundColor: '#fee2e2' }}>
          <AlertCircle size={20} color="#dc2626" />
          <div className="flex-1">
            <p className="text-sm" style={{ color: '#991b1b' }}>{error}</p>
          </div>
          <button onClick={() => setError(null)} className="text-sm" style={{ color: '#991b1b' }}>
            ×
          </button>
        </div>
      )}

      {/* Results */}
      {enrichResult && (
        <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <h2 className="text-xl font-semibold mb-4" style={{ color: currentColors.text.primary }}>
            Resultado do Enrichment
          </h2>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Feed</p>
              <p className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                {enrichResult.feed_name}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>IOCs Fetched</p>
              <p className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                {enrichResult.iocs_fetched}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>IOCs Enriquecidos</p>
              <p className="text-lg font-semibold" style={{ color: '#10b981' }}>
                {enrichResult.iocs_enriched}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Status</p>
              <div className="flex items-center gap-2">
                <Check size={16} color="#10b981" />
                <span className="text-sm" style={{ color: '#10b981' }}>{enrichResult.status}</span>
              </div>
            </div>
          </div>

          <div className="border-t pt-4 mb-4" style={{ borderColor: currentColors.border.default }}></div>

          {/* Enriched IOCs */}
          <h3 className="text-lg font-semibold mb-3" style={{ color: currentColors.text.primary }}>
            IOCs Enriquecidos
          </h3>

          <div className="space-y-4">
            {enrichResult.enriched_iocs.map((enrichedIOC: EnrichedIOC, index: number) => (
              <div
                key={index}
                className="border rounded-lg overflow-hidden"
                style={{ borderColor: currentColors.border.default }}
              >
                {/* IOC Header */}
                <div className="p-4 flex items-center gap-3" style={{ backgroundColor: currentColors.bg.secondary }}>
                  <Target size={16} />
                  <p className="font-mono text-sm flex-1" style={{ color: currentColors.text.primary }}>
                    {enrichedIOC.value.substring(0, 80)}
                    {enrichedIOC.value.length > 80 ? '...' : ''}
                  </p>
                  <span
                    className="px-2 py-1 rounded text-xs"
                    style={{ backgroundColor: '#3b82f6', color: '#fff' }}
                  >
                    {enrichedIOC.type}
                  </span>
                </div>

                {/* Enrichment Data */}
                <div className="p-4 space-y-4">
                  {/* Threat Type & Severity */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>
                        Threat Type
                      </p>
                      <span
                        className="px-2 py-1 rounded text-xs"
                        style={{ backgroundColor: getThreatTypeColor(enrichedIOC.enrichment.threat_type), color: '#fff' }}
                      >
                        {enrichedIOC.enrichment.threat_type}
                      </span>
                    </div>
                    <div>
                      <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>
                        Severity
                      </p>
                      <div className="flex items-center gap-2">
                        <Shield size={16} color={getSeverityColor(enrichedIOC.enrichment.severity)} />
                        <span
                          className="px-2 py-1 rounded text-xs"
                          style={{ backgroundColor: getSeverityColor(enrichedIOC.enrichment.severity), color: '#fff' }}
                        >
                          {enrichedIOC.enrichment.severity.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Summary */}
                  <div>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>
                      Summary
                    </p>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>
                      {enrichedIOC.enrichment.summary}
                    </p>
                  </div>

                  {/* MITRE ATT&CK Techniques */}
                  {enrichedIOC.enrichment.techniques && enrichedIOC.enrichment.techniques.length > 0 && (
                    <div>
                      <p className="text-xs mb-2 flex items-center gap-2" style={{ color: currentColors.text.secondary }}>
                        <TrendingUp size={14} /> MITRE ATT&CK Techniques
                      </p>
                      <div className="flex gap-2 flex-wrap">
                        {enrichedIOC.enrichment.techniques.map((tech, i) => (
                          <span
                            key={i}
                            className="px-2 py-1 rounded text-xs border"
                            style={{
                              borderColor: '#dc2626',
                              color: '#dc2626',
                            }}
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tactics */}
                  {enrichedIOC.enrichment.tactics && enrichedIOC.enrichment.tactics.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>
                        Tactics
                      </p>
                      <div className="flex gap-2 flex-wrap">
                        {enrichedIOC.enrichment.tactics.map((tactic, i) => (
                          <span
                            key={i}
                            className="px-2 py-1 rounded text-xs border"
                            style={{
                              borderColor: currentColors.border.default,
                              color: currentColors.text.secondary,
                            }}
                          >
                            {tactic}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Detection Methods */}
                  {enrichedIOC.enrichment.detection_methods && enrichedIOC.enrichment.detection_methods.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>
                        Detection Methods
                      </p>
                      <ul className="space-y-1">
                        {enrichedIOC.enrichment.detection_methods.map((method, i) => (
                          <li key={i} className="text-sm" style={{ color: currentColors.text.primary }}>
                            {i + 1}. {method}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex gap-2 flex-wrap pt-2 border-t" style={{ borderColor: currentColors.border.default }}>
                    <span
                      className="px-2 py-1 rounded text-xs border"
                      style={{
                        borderColor: currentColors.border.default,
                        color: currentColors.text.secondary,
                      }}
                    >
                      Confidence: {enrichedIOC.enrichment.confidence}
                    </span>
                    {enrichedIOC.enrichment.llm_used && (
                      <span
                        className="px-2 py-1 rounded text-xs border flex items-center gap-1"
                        style={{
                          borderColor: currentColors.border.default,
                          color: currentColors.text.secondary,
                        }}
                      >
                        <Brain size={12} />
                        {enrichedIOC.enrichment.llm_used}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default IOCEnrichmentPage;
