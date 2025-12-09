/**
 * CTI Dashboard - Cyber Threat Intelligence
 *
 * Focused on IOC verification and MISP intelligence:
 * - IOC Search (MISP + OTX)
 * - IOC Enrichment with LLM
 * - MISP Feeds testing
 * - IOC Browser
 */

import React, { useState, useEffect } from 'react';
import { Target, Shield, Brain, Search, List, Database, RefreshCw, AlertTriangle, CheckCircle, XCircle, FileCode, Radio } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useSettingsStore } from '@stores/settingsStore';
import mispFeedsService, { IOCStats } from '../../services/cti/mispFeedsService';

const CTIDashboard: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const navigate = useNavigate();

  // Stats
  const [stats, setStats] = useState<IOCStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Quick search
  const [quickSearch, setQuickSearch] = useState('');
  const [searching, setSearching] = useState(false);
  const [searchResult, setSearchResult] = useState<any>(null);

  // Load stats on mount
  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await mispFeedsService.getStats();
      setStats(data);
    } catch (err: any) {
      console.error('Error loading stats:', err);
      setError('Failed to load IOC statistics');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickSearch = async () => {
    if (!quickSearch.trim()) return;

    setSearching(true);
    setSearchResult(null);
    try {
      const result = await mispFeedsService.searchIoC(quickSearch.trim());
      setSearchResult(result);
    } catch (err: any) {
      console.error('Error searching IOC:', err);
      setSearchResult({ error: 'Search failed' });
    } finally {
      setSearching(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleQuickSearch();
    }
  };

  // IOC type icons
  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ip': return '🌐';
      case 'domain': return '🔗';
      case 'url': return '🔗';
      case 'hash': return '#️⃣';
      case 'email': return '📧';
      default: return '📄';
    }
  };

  return (
    <div
      className="h-full overflow-y-auto p-6"
      style={{ backgroundColor: currentColors.bg.secondary }}
    >
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Target size={32} style={{ color: currentColors.accent.primary }} />
          <h1 className="text-3xl font-semibold" style={{ color: currentColors.text.primary }}>
            CTI - IOC Intelligence
          </h1>
        </div>
        <p className="text-sm" style={{ color: currentColors.text.secondary }}>
          Search and verify Indicators of Compromise (IOCs) using MISP feeds and threat intelligence sources.
        </p>
      </div>

      {/* Quick Search Bar */}
      <div
        className="mb-6 p-4 rounded-lg"
        style={{ backgroundColor: currentColors.bg.primary }}
      >
        <div className="flex items-center gap-3 mb-3">
          <Search size={20} style={{ color: currentColors.accent.primary }} />
          <h2 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
            Quick IOC Search
          </h2>
        </div>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              placeholder="Enter IP, domain, URL, or hash to verify..."
              value={quickSearch}
              onChange={(e) => setQuickSearch(e.target.value)}
              onKeyPress={handleKeyPress}
              className="w-full px-4 py-3 rounded-lg text-sm focus:outline-none focus:ring-2"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.primary,
                border: `1px solid ${currentColors.border.default}`,
              }}
            />
          </div>
          <button
            onClick={handleQuickSearch}
            disabled={searching || !quickSearch.trim()}
            className="px-6 py-3 rounded-lg font-medium flex items-center gap-2 transition-colors"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
              opacity: searching || !quickSearch.trim() ? 0.6 : 1
            }}
          >
            {searching ? (
              <RefreshCw size={18} className="animate-spin" />
            ) : (
              <Search size={18} />
            )}
            Search
          </button>
        </div>

        {/* Quick Search Result */}
        {searchResult && (
          <div className="mt-4 p-4 rounded-lg" style={{ backgroundColor: currentColors.bg.secondary }}>
            {searchResult.error ? (
              <div className="flex items-center gap-2 text-red-500">
                <XCircle size={18} />
                <span>{searchResult.error}</span>
              </div>
            ) : (
              <div className="space-y-3">
                {/* MISP Result */}
                <div className="flex items-start gap-3">
                  {searchResult.misp?.found ? (
                    <CheckCircle size={18} style={{ color: '#10b981' }} />
                  ) : (
                    <XCircle size={18} style={{ color: currentColors.text.muted }} />
                  )}
                  <div>
                    <span className="font-medium" style={{ color: currentColors.text.primary }}>MISP: </span>
                    <span style={{ color: searchResult.misp?.found ? '#10b981' : currentColors.text.secondary }}>
                      {searchResult.misp?.found ? 'Found' : 'Not found'}
                    </span>
                    {searchResult.misp?.ioc && (
                      <span className="ml-2 text-sm" style={{ color: currentColors.text.secondary }}>
                        ({searchResult.misp.ioc.type} - {searchResult.misp.ioc.malware_family || 'Unknown'})
                      </span>
                    )}
                  </div>
                </div>

                {/* OTX Result */}
                <div className="flex items-start gap-3">
                  {searchResult.otx?.found ? (
                    <CheckCircle size={18} style={{ color: '#10b981' }} />
                  ) : (
                    <XCircle size={18} style={{ color: currentColors.text.muted }} />
                  )}
                  <div>
                    <span className="font-medium" style={{ color: currentColors.text.primary }}>OTX: </span>
                    <span style={{ color: searchResult.otx?.found ? '#10b981' : currentColors.text.secondary }}>
                      {searchResult.otx?.found ? `Found in ${searchResult.otx.pulses} pulses` : 'Not found'}
                    </span>
                  </div>
                </div>

                {/* View Full Details */}
                <button
                  onClick={() => navigate('/cti/search')}
                  className="mt-2 text-sm underline"
                  style={{ color: currentColors.accent.primary }}
                >
                  View full analysis →
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Stats Overview */}
      {loading ? (
        <div className="flex items-center justify-center py-8">
          <RefreshCw size={24} className="animate-spin" style={{ color: currentColors.accent.primary }} />
        </div>
      ) : error ? (
        <div className="text-center py-8">
          <AlertTriangle size={32} style={{ color: currentColors.accent.error }} className="mx-auto mb-2" />
          <p style={{ color: currentColors.text.secondary }}>{error}</p>
          <button
            onClick={loadStats}
            className="mt-2 px-4 py-2 rounded text-sm"
            style={{ backgroundColor: currentColors.accent.primary, color: currentColors.text.inverse }}
          >
            Retry
          </button>
        </div>
      ) : stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Database size={20} style={{ color: currentColors.accent.primary }} />
              <span className="text-sm" style={{ color: currentColors.text.secondary }}>Total IOCs</span>
            </div>
            <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
              {stats.total_iocs.toLocaleString()}
            </p>
          </div>

          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Shield size={20} style={{ color: currentColors.accent.secondary }} />
              <span className="text-sm" style={{ color: currentColors.text.secondary }}>Active Feeds</span>
            </div>
            <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
              {stats.feeds_count}
            </p>
          </div>

          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <div className="flex items-center gap-2 mb-2">
              <List size={20} style={{ color: '#f59e0b' }} />
              <span className="text-sm" style={{ color: currentColors.text.secondary }}>IOC Types</span>
            </div>
            <p className="text-3xl font-bold" style={{ color: currentColors.text.primary }}>
              {Object.keys(stats.by_type).length}
            </p>
          </div>

          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: currentColors.bg.primary }}
          >
            <div className="flex items-center gap-2 mb-2">
              <RefreshCw size={20} style={{ color: '#10b981' }} />
              <span className="text-sm" style={{ color: currentColors.text.secondary }}>Last Sync</span>
            </div>
            <p className="text-lg font-medium" style={{ color: currentColors.text.primary }}>
              {stats.last_sync ? new Date(stats.last_sync).toLocaleDateString() : 'Never'}
            </p>
          </div>
        </div>
      )}

      {/* IOCs by Type */}
      {stats && Object.keys(stats.by_type).length > 0 && (
        <div
          className="mb-6 p-4 rounded-lg"
          style={{ backgroundColor: currentColors.bg.primary }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: currentColors.text.primary }}>
            IOCs by Type
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {Object.entries(stats.by_type).map(([type, count]) => (
              <button
                key={type}
                onClick={() => navigate('/cti/iocs')}
                className="p-3 rounded-lg text-left hover:opacity-80 transition-opacity"
                style={{ backgroundColor: currentColors.bg.secondary }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span>{getTypeIcon(type)}</span>
                  <span className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                    {type.toUpperCase()}
                  </span>
                </div>
                <p className="text-xl font-bold" style={{ color: currentColors.accent.primary }}>
                  {(count as number).toLocaleString()}
                </p>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* IOC Search Card */}
        <button
          onClick={() => navigate('/cti/search')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#10b981';
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: '#10b98120' }}>
              <Search size={24} style={{ color: '#10b981' }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              IOC Search
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            Search IOCs across MISP database, OTX (AlienVault), and get LLM-powered analysis with MITRE ATT&CK mapping.
          </p>
        </button>

        {/* IOC Browser Card */}
        <button
          onClick={() => navigate('/cti/iocs')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#f59e0b';
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: '#f59e0b20' }}>
              <List size={24} style={{ color: '#f59e0b' }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              IOC Browser
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            Browse and filter all saved IOCs by type (IP, domain, URL, hash), feed source, TLP level, and confidence.
          </p>
        </button>

        {/* MISP Feeds Card */}
        <button
          onClick={() => navigate('/cti/feeds')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = currentColors.accent.primary;
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: `${currentColors.accent.primary}20` }}>
              <Shield size={24} style={{ color: currentColors.accent.primary }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              MISP Feeds
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            Test and preview public threat intelligence feeds. 15+ feeds including DiamondFox, SSL Blacklist, URLhaus.
          </p>
        </button>

        {/* IOC Enrichment Card */}
        <button
          onClick={() => navigate('/cti/enrichment')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = currentColors.accent.secondary;
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: `${currentColors.accent.secondary}20` }}>
              <Brain size={24} style={{ color: currentColors.accent.secondary }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              IOC Enrichment
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            Batch enrich IOCs with LLM analysis. Get threat type, severity, MITRE techniques, and detection methods.
          </p>
        </button>

        {/* YARA Rules Card */}
        <button
          onClick={() => navigate('/cti/yara')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#8b5cf6';
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: '#8b5cf620' }}>
              <FileCode size={24} style={{ color: '#8b5cf6' }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              YARA Rules
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            Browse 5,800+ detection rules from Neo23x0/signature-base. Filter by category, threat actor, and MITRE ATT&CK.
          </p>
        </button>

        {/* OTX Pulses Card */}
        <button
          onClick={() => navigate('/cti/pulses')}
          className="p-5 rounded-lg border-2 text-left hover:shadow-lg transition-all"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#06b6d4';
            e.currentTarget.style.transform = 'translateY(-2px)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = currentColors.border.default;
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg" style={{ backgroundColor: '#06b6d420' }}>
              <Radio size={24} style={{ color: '#06b6d4' }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
              OTX Pulses
            </h3>
          </div>
          <p className="text-sm" style={{ color: currentColors.text.secondary }}>
            View threat intelligence feeds from AlienVault OTX. 50+ pulses with 54,000+ indicators from subscribed sources.
          </p>
        </button>
      </div>
    </div>
  );
};

export default CTIDashboard;
