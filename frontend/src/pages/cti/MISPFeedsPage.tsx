/**
 * MISP Feeds Page
 * Página para testar e visualizar feeds MISP de threat intelligence
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  CloudDownload,
  AlertCircle,
  Check,
  Loader2,
  Globe,
  Hash,
  ExternalLink,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import mispFeedsService, { FeedTestResult, AvailableFeed, MISPIoC } from '../../services/cti/mispFeedsService';

const MISPFeedsPage: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [availableFeeds, setAvailableFeeds] = useState<AvailableFeed[]>([]);
  const [selectedFeed, setSelectedFeed] = useState<string>('');
  const [limit, setLimit] = useState<number>(20);
  const [loading, setLoading] = useState(false);
  const [testResult, setTestResult] = useState<FeedTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAvailableFeeds();
  }, []);

  const loadAvailableFeeds = async () => {
    try {
      const feeds = await mispFeedsService.listAvailableFeeds();
      setAvailableFeeds(feeds);
    } catch (err: any) {
      setError(`Erro ao carregar feeds: ${err.message}`);
    }
  };

  const handleTestFeed = async () => {
    if (!selectedFeed) {
      setError('Selecione um feed');
      return;
    }

    setLoading(true);
    setError(null);
    setTestResult(null);

    try {
      const result = await mispFeedsService.testFeed(selectedFeed, limit);
      setTestResult(result);
    } catch (err: any) {
      setError(`Erro ao testar feed: ${err.response?.data?.detail || err.message}`);
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

  return (
    <div className="h-full overflow-y-auto p-6" style={{ backgroundColor: currentColors.bg.secondary }}>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Shield size={32} style={{ color: currentColors.text.primary }} />
          <h1 className="text-3xl font-semibold" style={{ color: currentColors.text.primary }}>
            MISP Threat Intelligence Feeds
          </h1>
        </div>
        <p className="text-sm" style={{ color: currentColors.text.secondary }}>
          Teste e visualize feeds públicos de threat intelligence (IOCs)
        </p>
      </div>

      {/* Controls */}
      <div className="p-6 rounded-lg mb-6" style={{ backgroundColor: currentColors.bg.primary }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm mb-2" style={{ color: currentColors.text.secondary }}>
              Selecione um Feed
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
                  {feed.name} ({feed.type})
                </option>
              ))}
            </select>
            {selectedFeed && (
              <p className="text-xs mt-2" style={{ color: currentColors.text.secondary }}>
                {availableFeeds.find(f => f.id === selectedFeed)?.description}
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm mb-2" style={{ color: currentColors.text.secondary }}>
              Limite de IOCs
            </label>
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(parseInt(e.target.value) || 20)}
              min="1"
              max="5000"
              className="w-full p-2 rounded border"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.primary,
                borderColor: currentColors.border.default,
              }}
            />
          </div>
        </div>

        <button
          onClick={handleTestFeed}
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
              Testando...
            </>
          ) : (
            <>
              <CloudDownload size={16} />
              Testar Feed
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
      {testResult && (
        <div className="p-6 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
          <h2 className="text-xl font-semibold mb-4" style={{ color: currentColors.text.primary }}>
            Resultado do Teste
          </h2>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Feed</p>
              <p className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                {testResult.feed_name}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Itens Processados</p>
              <p className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                {testResult.items_processed}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>IOCs Encontrados</p>
              <p className="text-lg font-semibold" style={{ color: '#10b981' }}>
                {testResult.iocs_found}
              </p>
            </div>
            <div className="p-4 rounded border" style={{ borderColor: currentColors.border.default }}>
              <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Status</p>
              <div className="flex items-center gap-2">
                <Check size={16} color="#10b981" />
                <span className="text-sm" style={{ color: '#10b981' }}>{testResult.status}</span>
              </div>
            </div>
          </div>

          <div className="border-t pt-4 mb-4" style={{ borderColor: currentColors.border.default }}></div>

          {/* IOC Samples */}
          <h3 className="text-lg font-semibold mb-3" style={{ color: currentColors.text.primary }}>
            Samples de IOCs
          </h3>

          <div className="space-y-3">
            {testResult.sample.map((ioc: MISPIoC, index: number) => (
              <div
                key={index}
                className="p-4 rounded border"
                style={{
                  backgroundColor: currentColors.bg.secondary,
                  borderColor: currentColors.border.primary,
                }}
              >
                <div className="flex items-start gap-3 mb-2">
                  {getTypeIcon(ioc.type)}
                  <div className="flex-1">
                    <p className="font-mono text-sm mb-2" style={{ color: currentColors.text.primary }}>
                      {ioc.value}
                    </p>
                    <div className="flex gap-2 flex-wrap mb-2">
                      <span
                        className="px-2 py-1 rounded text-xs"
                        style={{ backgroundColor: getTypeColor(ioc.type), color: '#fff' }}
                      >
                        {ioc.type}
                      </span>
                      {ioc.malware_family && (
                        <span className="px-2 py-1 rounded text-xs" style={{ backgroundColor: '#dc2626', color: '#fff' }}>
                          Malware: {ioc.malware_family}
                        </span>
                      )}
                      {ioc.confidence && (
                        <span
                          className="px-2 py-1 rounded text-xs border"
                          style={{ borderColor: currentColors.border.default, color: currentColors.text.secondary }}
                        >
                          Confidence: {ioc.confidence}
                        </span>
                      )}
                    </div>
                    <p className="text-sm mb-2" style={{ color: currentColors.text.secondary }}>
                      {ioc.context}
                    </p>
                    {ioc.tags && ioc.tags.length > 0 && (
                      <div className="flex gap-2 flex-wrap">
                        {ioc.tags.map((tag, i) => (
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
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>

          <p className="text-xs mt-4" style={{ color: currentColors.text.secondary }}>
            Feed URL: {testResult.feed_url}
          </p>
        </div>
      )}
    </div>
  );
};

export default MISPFeedsPage;
