/**
 * IOC Search Page
 * Busca um IOC específico no MISP e OTX (AlienVault)
 */

import React, { useState } from 'react';
import {
  Search,
  Shield,
  Loader2,
  AlertCircle,
  Check,
  X,
  Globe,
  Hash,
  ExternalLink,
  Eye,
  Brain,
  Target,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import mispFeedsService, { MISPIoC, OTXResult, IOCSearchResult, LLMEnrichmentResult } from '../../services/cti/mispFeedsService';

const IOCSearchPage: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [iocValue, setIocValue] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [searchResult, setSearchResult] = useState<IOCSearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!iocValue.trim()) {
      setError('Digite um IOC para buscar');
      return;
    }

    setLoading(true);
    setError(null);
    setSearchResult(null);

    try {
      // Search in both MISP and OTX
      const result = await mispFeedsService.searchIoC(iocValue.trim());
      setSearchResult(result);
    } catch (err: any) {
      setError(`Erro ao buscar IOC: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ip':
      case 'domain':
      case 'url':
        return <Globe size={16} />;
      case 'hash':
        return <Hash size={16} />;
      default:
        return <ExternalLink size={16} />;
    }
  };

  const getTypeColor = (type: string): string => {
    switch (type) {
      case 'ip':
        return '#3b82f6'; // blue
      case 'url':
        return '#8b5cf6'; // purple
      case 'hash':
        return '#06b6d4'; // cyan
      case 'domain':
        return '#10b981'; // green
      default:
        return '#6b7280'; // gray
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return '#dc2626'; // red
      case 'high':
        return '#f59e0b'; // orange
      case 'medium':
        return '#eab308'; // yellow
      case 'low':
        return '#10b981'; // green
      default:
        return '#6b7280'; // gray
    }
  };

  return (
    <div className="h-full overflow-y-auto p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Search size={32} style={{ color: currentColors.text.primary }} />
          <h1 className="text-3xl font-semibold" style={{ color: currentColors.text.primary }}>
            Busca de IOC
          </h1>
        </div>
        <p className="text-sm" style={{ color: currentColors.text.secondary }}>
          Busque um IOC (IP, domain, URL, hash) no MISP e OTX (AlienVault)
        </p>
      </div>

      {/* Search Box */}
      <div className="p-6 rounded-lg mb-6" style={{ backgroundColor: currentColors.bg.primary }}>
        <label className="block text-sm mb-2" style={{ color: currentColors.text.secondary }}>
          IOC para Buscar
        </label>
        <div className="flex gap-3">
          <input
            type="text"
            value={iocValue}
            onChange={(e) => setIocValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Ex: 192.168.1.1, evil.com, md5hash..."
            className="flex-1 p-3 rounded border"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              borderColor: currentColors.border.default,
            }}
          />
          <button
            onClick={handleSearch}
            disabled={loading}
            className="px-6 py-3 rounded flex items-center gap-2 disabled:opacity-50 hover:opacity-90 transition-opacity"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: '#fff',
            }}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Buscando...
              </>
            ) : (
              <>
                <Search size={16} />
                Buscar
              </>
            )}
          </button>
        </div>
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
      {searchResult && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* MISP Result */}
          <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
            <div className="flex items-center gap-3 mb-4">
              <Shield size={24} style={{ color: currentColors.accent.primary }} />
              <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                MISP Database
              </h2>
            </div>

            {searchResult.misp.found && searchResult.misp.ioc ? (
              <div>
                <div className="flex items-center gap-2 mb-4 p-3 rounded" style={{ backgroundColor: '#d1fae5' }}>
                  <Check size={20} color="#10b981" />
                  <span className="text-sm font-semibold" style={{ color: '#065f46' }}>
                    IOC Encontrado no MISP!
                  </span>
                </div>

                {/* Source badge */}
                {searchResult.misp.source && (
                  <div className="mb-3">
                    <span className="px-2 py-1 rounded text-xs" style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.secondary }}>
                      Fonte: {searchResult.misp.source === 'database' ? 'Database' : 'Live Feeds'}
                    </span>
                  </div>
                )}

                <div className="space-y-3">
                  <div>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Valor</p>
                    <p className="font-mono text-sm" style={{ color: currentColors.text.primary }}>
                      {searchResult.misp.ioc.value}
                    </p>
                  </div>

                  <div className="flex gap-2 flex-wrap">
                    <span
                      className="px-2 py-1 rounded text-xs"
                      style={{ backgroundColor: getTypeColor(searchResult.misp.ioc.type), color: '#fff' }}
                    >
                      {getTypeIcon(searchResult.misp.ioc.type)}
                      <span className="ml-1">{searchResult.misp.ioc.type}</span>
                    </span>
                    {searchResult.misp.ioc.malware_family && (
                      <span className="px-2 py-1 rounded text-xs" style={{ backgroundColor: '#dc2626', color: '#fff' }}>
                        Malware: {searchResult.misp.ioc.malware_family}
                      </span>
                    )}
                    {searchResult.misp.ioc.confidence && (
                      <span
                        className="px-2 py-1 rounded text-xs border"
                        style={{ borderColor: currentColors.border.default, color: currentColors.text.secondary }}
                      >
                        Confidence: {searchResult.misp.ioc.confidence}
                      </span>
                    )}
                  </div>

                  {searchResult.misp.ioc.context && (
                    <div>
                      <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Contexto</p>
                      <p className="text-sm" style={{ color: currentColors.text.primary }}>
                        {searchResult.misp.ioc.context}
                      </p>
                    </div>
                  )}

                  {searchResult.misp.ioc.tags && searchResult.misp.ioc.tags.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Tags</p>
                      <div className="flex gap-2 flex-wrap">
                        {searchResult.misp.ioc.tags.map((tag, i) => (
                          <span
                            key={i}
                            className="px-2 py-1 rounded text-xs border"
                            style={{
                              borderColor: currentColors.border.primary,
                              color: currentColors.text.secondary,
                            }}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2 p-3 rounded" style={{ backgroundColor: '#fef3c7' }}>
                <X size={20} color="#d97706" />
                <span className="text-sm" style={{ color: '#78350f' }}>
                  {searchResult.misp.message || 'IOC não encontrado no MISP'}
                </span>
              </div>
            )}
          </div>

          {/* OTX Result */}
          <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
            <div className="flex items-center gap-3 mb-4">
              <Eye size={24} style={{ color: currentColors.accent.secondary }} />
              <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                OTX (AlienVault)
              </h2>
            </div>

            {searchResult.otx.found ? (
              <div>
                <div className="flex items-center gap-2 mb-4 p-3 rounded" style={{ backgroundColor: '#d1fae5' }}>
                  <Check size={20} color="#10b981" />
                  <span className="text-sm font-semibold" style={{ color: '#065f46' }}>
                    IOC Encontrado no OTX!
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Pulses</p>
                    <p className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                      {searchResult.otx.pulses}
                    </p>
                  </div>

                  {searchResult.otx.malware_families && searchResult.otx.malware_families.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Malware Families</p>
                      <div className="flex gap-2 flex-wrap">
                        {searchResult.otx.malware_families.map((family, i) => (
                          <span
                            key={i}
                            className="px-2 py-1 rounded text-xs"
                            style={{ backgroundColor: '#dc2626', color: '#fff' }}
                          >
                            {family}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {searchResult.otx.tags && searchResult.otx.tags.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Tags</p>
                      <div className="flex gap-2 flex-wrap">
                        {searchResult.otx.tags.slice(0, 10).map((tag, i) => (
                          <span
                            key={i}
                            className="px-2 py-1 rounded text-xs border"
                            style={{
                              borderColor: currentColors.border.primary,
                              color: currentColors.text.secondary,
                            }}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {searchResult.otx.pulse_names && searchResult.otx.pulse_names.length > 0 && (
                    <div>
                      <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Recent Pulses</p>
                      <div className="space-y-1">
                        {searchResult.otx.pulse_names.map((pulse, i) => (
                          <p key={i} className="text-xs" style={{ color: currentColors.text.primary }}>
                            • {pulse}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2 p-3 rounded" style={{ backgroundColor: '#fef3c7' }}>
                <AlertCircle size={20} color="#d97706" />
                <span className="text-sm" style={{ color: '#78350f' }}>
                  {searchResult.otx.message || 'IOC não encontrado no OTX'}
                </span>
              </div>
            )}
          </div>

          {/* LLM Enrichment Result */}
          {searchResult.enrichment && !searchResult.enrichment.error && (
            <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
              <div className="flex items-center gap-3 mb-4">
                <Brain size={24} style={{ color: '#8b5cf6' }} />
                <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                  LLM Enrichment
                </h2>
              </div>

              <div className="space-y-4">
                {/* Threat Type & Severity */}
                <div className="flex gap-2 flex-wrap">
                  <span
                    className="px-3 py-1 rounded text-xs font-semibold"
                    style={{ backgroundColor: '#8b5cf6', color: '#fff' }}
                  >
                    {searchResult.enrichment.threat_type.toUpperCase()}
                  </span>
                  <span
                    className="px-3 py-1 rounded text-xs font-semibold"
                    style={{ backgroundColor: getSeverityColor(searchResult.enrichment.severity), color: '#fff' }}
                  >
                    {searchResult.enrichment.severity.toUpperCase()}
                  </span>
                  <span
                    className="px-3 py-1 rounded text-xs border"
                    style={{ borderColor: currentColors.border.default, color: currentColors.text.secondary }}
                  >
                    Confidence: {searchResult.enrichment.confidence}
                  </span>
                </div>

                {/* Summary */}
                <div>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Análise</p>
                  <p className="text-sm" style={{ color: currentColors.text.primary }}>
                    {searchResult.enrichment.summary}
                  </p>
                </div>

                {/* MITRE ATT&CK Techniques */}
                {searchResult.enrichment.techniques && searchResult.enrichment.techniques.length > 0 && (
                  <div>
                    <p className="text-xs mb-2 flex items-center gap-2" style={{ color: currentColors.text.secondary }}>
                      <Target size={14} />
                      MITRE ATT&CK Techniques
                    </p>
                    <div className="flex gap-2 flex-wrap">
                      {searchResult.enrichment.techniques.map((tech, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 rounded text-xs font-mono"
                          style={{ backgroundColor: '#dc2626', color: '#fff' }}
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tactics */}
                {searchResult.enrichment.tactics && searchResult.enrichment.tactics.length > 0 && (
                  <div>
                    <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Tactics</p>
                    <div className="flex gap-2 flex-wrap">
                      {searchResult.enrichment.tactics.map((tactic, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 rounded text-xs capitalize"
                          style={{ backgroundColor: '#f59e0b', color: '#fff' }}
                        >
                          {tactic.replace(/-/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Detection Methods */}
                {searchResult.enrichment.detection_methods && searchResult.enrichment.detection_methods.length > 0 && (
                  <div>
                    <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Detection Methods</p>
                    <div className="space-y-1">
                      {searchResult.enrichment.detection_methods.map((method, i) => (
                        <p key={i} className="text-xs" style={{ color: currentColors.text.primary }}>
                          • {method}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                {/* LLM Provider */}
                {searchResult.enrichment.llm_used && (
                  <div className="pt-2 border-t" style={{ borderColor: currentColors.border.default }}>
                    <p className="text-xs" style={{ color: currentColors.text.secondary }}>
                      Powered by: {searchResult.enrichment.llm_used}
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* LLM Enrichment Error */}
          {searchResult.enrichment && searchResult.enrichment.error && (
            <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
              <div className="flex items-center gap-3 mb-4">
                <Brain size={24} style={{ color: '#8b5cf6' }} />
                <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                  LLM Enrichment
                </h2>
              </div>
              <div className="flex items-center gap-2 p-3 rounded" style={{ backgroundColor: '#fee2e2' }}>
                <AlertCircle size={20} color="#dc2626" />
                <span className="text-sm" style={{ color: '#991b1b' }}>
                  Erro ao enriquecer IOC: {searchResult.enrichment.error}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default IOCSearchPage;
