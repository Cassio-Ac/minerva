/**
 * YARA Rules Browser Page
 * Browse and search YARA detection rules from Signature Base + Malpedia
 */

import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  FileCode,
  Search,
  ChevronRight,
  AlertCircle,
  Loader2,
  Copy,
  Check,
  X,
  Shield,
  Users,
  ExternalLink,
  Code,
  Bug,
  Database,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import yaraService, { YaraRule, YaraRuleDetail, YaraStats, CategoryItem, MalwareFamilyItem } from '../../services/cti/yaraService';

const YARARulesPage: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [searchParams, setSearchParams] = useSearchParams();

  // Stats
  const [stats, setStats] = useState<YaraStats | null>(null);
  const [categories, setCategories] = useState<CategoryItem[]>([]);
  const [malwareFamilies, setMalwareFamilies] = useState<MalwareFamilyItem[]>([]);

  // Rules list
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters - initialize from URL params
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [selectedCategory, setSelectedCategory] = useState(searchParams.get('category') || '');
  const [selectedFamily, setSelectedFamily] = useState(searchParams.get('malware_family') || '');
  const [selectedSource, setSelectedSource] = useState(searchParams.get('source') || '');

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 30;

  // Selected rule detail
  const [selectedRule, setSelectedRule] = useState<YaraRuleDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [copied, setCopied] = useState(false);

  // Load initial data
  useEffect(() => {
    loadStats();
    loadCategories();
    loadMalwareFamilies();
  }, []);

  // Track if initial load from URL was done
  const [initialLoadDone, setInitialLoadDone] = useState(false);

  // Check for URL params on mount and trigger search
  useEffect(() => {
    const urlSearch = searchParams.get('search');
    const urlCategory = searchParams.get('category');
    const urlFamily = searchParams.get('malware_family');
    const urlThreatActor = searchParams.get('threat_actor');
    const urlSource = searchParams.get('source');

    let searchTerm = '';

    // If threat_actor is in URL, use it as search term (for cross-correlation links)
    if (urlThreatActor) {
      searchTerm = urlThreatActor;
      setSearch(urlThreatActor);
    } else if (urlSearch) {
      searchTerm = urlSearch;
      setSearch(urlSearch);
    }
    if (urlCategory) {
      setSelectedCategory(urlCategory);
    }
    if (urlFamily) {
      setSelectedFamily(urlFamily);
    }
    if (urlSource) {
      setSelectedSource(urlSource);
    }

    // Load rules - either with URL params or default
    const loadWithParams = async () => {
      setLoading(true);
      try {
        const params: any = { page: 1, page_size: pageSize };
        // Use search for threat_actor (field often empty, but name is in rule_name/description)
        if (searchTerm) params.search = searchTerm;
        if (urlCategory) params.category = urlCategory;
        if (urlFamily) params.malware_family = urlFamily;
        if (urlSource) params.source = urlSource;
        // Note: threat_actor field is mostly empty in ES, so we rely on search instead

        const data = await yaraService.listRules(params);
        setRules(data.rules);
        setTotal(data.total);
        setInitialLoadDone(true);
      } catch (err: any) {
        setError(err.response?.data?.detail || err.message);
        setInitialLoadDone(true);
      } finally {
        setLoading(false);
      }
    };
    loadWithParams();
  }, []); // Only run once on mount

  // Load rules when filters change manually (after initial load)
  useEffect(() => {
    if (!initialLoadDone) return;
    loadRules();
  }, [page, selectedCategory, selectedFamily, selectedSource]);

  const loadStats = async () => {
    try {
      const data = await yaraService.getStats();
      setStats(data);
    } catch (err) {
      console.error('Error loading stats:', err);
    }
  };

  const loadCategories = async () => {
    try {
      const data = await yaraService.getCategories();
      setCategories(data);
    } catch (err) {
      console.error('Error loading categories:', err);
    }
  };

  const loadMalwareFamilies = async () => {
    try {
      const data = await yaraService.getMalwareFamilies();
      setMalwareFamilies(data);
    } catch (err) {
      console.error('Error loading malware families:', err);
    }
  };

  const loadRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: any = {
        page,
        page_size: pageSize,
      };
      if (search) params.search = search;
      if (selectedCategory) params.category = selectedCategory;
      if (selectedFamily) params.malware_family = selectedFamily;
      if (selectedSource) params.source = selectedSource;

      const data = await yaraService.listRules(params);
      setRules(data.rules);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setPage(1);
    // Update URL params
    const params = new URLSearchParams();
    if (search) params.set('search', search);
    if (selectedCategory) params.set('category', selectedCategory);
    if (selectedFamily) params.set('malware_family', selectedFamily);
    if (selectedSource) params.set('source', selectedSource);
    setSearchParams(params);
    loadRules();
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const handleRuleClick = async (rule: YaraRule) => {
    setLoadingDetail(true);
    try {
      const detail = await yaraService.getRuleDetail(rule.id);
      setSelectedRule(detail);
    } catch (err) {
      console.error('Error loading rule detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleCopyRule = () => {
    if (selectedRule?.rule_content) {
      navigator.clipboard.writeText(selectedRule.rule_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getCategoryColor = (category: string | null): string => {
    const cat = category?.toLowerCase() || '';
    if (cat.includes('apt')) return '#ef4444';
    if (cat.includes('crime')) return '#f59e0b';
    if (cat.includes('generic')) return '#3b82f6';
    if (cat.includes('malware')) return '#8b5cf6';
    if (cat.includes('exploit')) return '#ec4899';
    if (cat.includes('hack')) return '#06b6d4';
    if (cat.includes('webshell')) return '#10b981';
    if (cat.includes('thor')) return '#6366f1';
    if (cat.includes('vuln')) return '#f97316';
    return '#6b7280';
  };

  const getSourceBadge = (source: string) => {
    if (source === 'malpedia') {
      return { color: '#8b5cf6', label: 'Malpedia' };
    }
    return { color: '#3b82f6', label: 'SigBase' };
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div
      className="h-full overflow-hidden flex flex-col"
      style={{ backgroundColor: currentColors.bg.secondary }}
    >
      {/* Header */}
      <div className="px-6 py-4 flex-shrink-0" style={{ borderBottom: `1px solid ${currentColors.border.default}` }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileCode size={28} style={{ color: currentColors.accent.primary }} />
            <div>
              <h1 className="text-2xl font-semibold" style={{ color: currentColors.text.primary }}>
                YARA Rules Browser
              </h1>
              <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                {stats ? `${stats.total_rules.toLocaleString()} detection rules from Signature Base + Malpedia` : 'Loading...'}
              </p>
            </div>
          </div>

          {/* Stats Cards */}
          {stats && (
            <div className="flex gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold" style={{ color: currentColors.accent.primary }}>
                  {stats.total_rules.toLocaleString()}
                </p>
                <p className="text-xs" style={{ color: currentColors.text.secondary }}>Total Rules</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold" style={{ color: '#3b82f6' }}>
                  {(stats.by_source?.signature_base || 0).toLocaleString()}
                </p>
                <p className="text-xs" style={{ color: currentColors.text.secondary }}>Signature Base</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold" style={{ color: '#8b5cf6' }}>
                  {(stats.by_source?.malpedia || 0).toLocaleString()}
                </p>
                <p className="text-xs" style={{ color: currentColors.text.secondary }}>Malpedia</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold" style={{ color: '#10b981' }}>
                  {stats.total_families || Object.keys(stats.by_malware_family || {}).length}
                </p>
                <p className="text-xs" style={{ color: currentColors.text.secondary }}>Families</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Search and Filters */}
      <div className="px-6 py-3 flex-shrink-0" style={{ backgroundColor: currentColors.bg.primary }}>
        <div className="flex items-center gap-3">
          {/* Search */}
          <div className="flex-1 relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 transform -translate-y-1/2"
              style={{ color: currentColors.text.secondary }}
            />
            <input
              type="text"
              placeholder="Search rules, threats, actors, malware families..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyPress={handleKeyPress}
              className="w-full pl-10 pr-4 py-2 rounded-lg text-sm focus:outline-none focus:ring-2"
              style={{
                backgroundColor: currentColors.bg.secondary,
                color: currentColors.text.primary,
                border: `1px solid ${currentColors.border.default}`,
              }}
            />
          </div>

          {/* Source Filter */}
          <select
            value={selectedSource}
            onChange={(e) => { setSelectedSource(e.target.value); setPage(1); }}
            className="px-3 py-2 rounded-lg text-sm"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              border: `1px solid ${currentColors.border.default}`,
            }}
          >
            <option value="">All Sources</option>
            <option value="signature_base">Signature Base ({stats?.by_source?.signature_base || 0})</option>
            <option value="malpedia">Malpedia ({stats?.by_source?.malpedia || 0})</option>
          </select>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => { setSelectedCategory(e.target.value); setPage(1); }}
            className="px-3 py-2 rounded-lg text-sm"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              border: `1px solid ${currentColors.border.default}`,
            }}
          >
            <option value="">All Categories</option>
            {categories.map((cat) => (
              <option key={cat.name} value={cat.name}>
                {cat.name} ({cat.count})
              </option>
            ))}
          </select>

          {/* Malware Family Filter */}
          <select
            value={selectedFamily}
            onChange={(e) => { setSelectedFamily(e.target.value); setPage(1); }}
            className="px-3 py-2 rounded-lg text-sm"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              border: `1px solid ${currentColors.border.default}`,
            }}
          >
            <option value="">All Families</option>
            {malwareFamilies.map((fam) => (
              <option key={fam.name} value={fam.name}>
                {fam.name} ({fam.count})
              </option>
            ))}
          </select>

          {/* Search Button */}
          <button
            onClick={handleSearch}
            className="px-4 py-2 rounded-lg flex items-center gap-2"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
          >
            <Search size={16} />
            Search
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Rules List */}
        <div
          className="w-1/2 overflow-y-auto p-4"
          style={{ borderRight: `1px solid ${currentColors.border.default}` }}
        >
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={32} className="animate-spin" style={{ color: currentColors.accent.primary }} />
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg flex items-center gap-3" style={{ backgroundColor: '#fee2e2' }}>
              <AlertCircle size={20} color="#dc2626" />
              <p className="text-sm" style={{ color: '#991b1b' }}>{error}</p>
            </div>
          ) : rules.length === 0 ? (
            <div className="text-center py-12">
              <FileCode size={48} className="mx-auto mb-4" style={{ color: currentColors.text.muted }} />
              <p style={{ color: currentColors.text.secondary }}>No rules found</p>
            </div>
          ) : (
            <>
              {/* Results count */}
              <p className="text-sm mb-4" style={{ color: currentColors.text.secondary }}>
                Showing {((page - 1) * pageSize) + 1}-{Math.min(page * pageSize, total)} of {total.toLocaleString()} rules
              </p>

              {/* Rules */}
              <div className="space-y-2">
                {rules.map((rule) => (
                  <button
                    key={rule.id}
                    onClick={() => handleRuleClick(rule)}
                    className="w-full p-3 rounded-lg text-left hover:opacity-90 transition-all border"
                    style={{
                      backgroundColor: selectedRule?.id === rule.id ? currentColors.bg.tertiary : currentColors.bg.primary,
                      borderColor: selectedRule?.id === rule.id ? currentColors.accent.primary : currentColors.border.default,
                    }}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className="px-2 py-0.5 rounded text-xs font-medium"
                          style={{ backgroundColor: getSourceBadge(rule.source).color, color: '#fff' }}
                        >
                          {getSourceBadge(rule.source).label}
                        </span>
                        <span
                          className="px-2 py-0.5 rounded text-xs font-medium"
                          style={{ backgroundColor: getCategoryColor(rule.category), color: '#fff' }}
                        >
                          {rule.category || 'other'}
                        </span>
                      </div>
                      <ChevronRight size={16} style={{ color: currentColors.text.muted }} />
                    </div>

                    <p className="font-medium text-sm mb-1" style={{ color: currentColors.text.primary }}>
                      {rule.rule_name}
                    </p>

                    {rule.malware_family && (
                      <p className="text-xs mb-1" style={{ color: '#8b5cf6' }}>
                        <Bug size={12} className="inline mr-1" />
                        {rule.malware_family}
                        {rule.malware_aliases && rule.malware_aliases.length > 0 && (
                          <span className="text-gray-400"> ({rule.malware_aliases.slice(0, 2).join(', ')})</span>
                        )}
                      </p>
                    )}

                    {rule.threat_name && (
                      <p className="text-xs mb-1" style={{ color: currentColors.accent.error }}>
                        <Shield size={12} className="inline mr-1" />
                        {rule.threat_name}
                      </p>
                    )}

                    {rule.threat_actor && (
                      <p className="text-xs mb-1" style={{ color: currentColors.accent.warning }}>
                        <Users size={12} className="inline mr-1" />
                        {rule.threat_actor}
                      </p>
                    )}

                    {rule.description && (
                      <p className="text-xs line-clamp-2" style={{ color: currentColors.text.secondary }}>
                        {rule.description}
                      </p>
                    )}

                    {/* Tags and MITRE */}
                    <div className="flex gap-1 flex-wrap mt-2">
                      {rule.mitre_attack?.slice(0, 3).map((t, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 rounded text-xs"
                          style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.accent.primary }}
                        >
                          {t}
                        </span>
                      ))}
                      {rule.mitre_attack && rule.mitre_attack.length > 3 && (
                        <span className="text-xs" style={{ color: currentColors.text.muted }}>
                          +{rule.mitre_attack.length - 3} more
                        </span>
                      )}
                    </div>
                  </button>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-3 py-1.5 rounded text-sm disabled:opacity-50"
                    style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary }}
                  >
                    Previous
                  </button>
                  <span className="text-sm" style={{ color: currentColors.text.secondary }}>
                    Page {page} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="px-3 py-1.5 rounded text-sm disabled:opacity-50"
                    style={{ backgroundColor: currentColors.bg.primary, color: currentColors.text.primary }}
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Rule Detail Panel */}
        <div className="w-1/2 overflow-y-auto p-4">
          {loadingDetail ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={32} className="animate-spin" style={{ color: currentColors.accent.primary }} />
            </div>
          ) : selectedRule ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className="px-2 py-0.5 rounded text-xs font-medium"
                      style={{ backgroundColor: getSourceBadge(selectedRule.source).color, color: '#fff' }}
                    >
                      {getSourceBadge(selectedRule.source).label}
                    </span>
                    <span
                      className="px-2 py-0.5 rounded text-xs font-medium"
                      style={{ backgroundColor: getCategoryColor(selectedRule.category), color: '#fff' }}
                    >
                      {selectedRule.category || 'other'}
                    </span>
                  </div>
                  <h2 className="text-xl font-semibold" style={{ color: currentColors.text.primary }}>
                    {selectedRule.rule_name}
                  </h2>
                </div>
                <button
                  onClick={() => setSelectedRule(null)}
                  className="p-1 rounded hover:opacity-80"
                  style={{ color: currentColors.text.muted }}
                >
                  <X size={20} />
                </button>
              </div>

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-3">
                {selectedRule.malware_family && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Malware Family</p>
                    <p className="text-sm font-medium" style={{ color: '#8b5cf6' }}>
                      {selectedRule.malware_family}
                    </p>
                    {selectedRule.malware_aliases && selectedRule.malware_aliases.length > 0 && (
                      <p className="text-xs mt-1" style={{ color: currentColors.text.muted }}>
                        AKA: {selectedRule.malware_aliases.join(', ')}
                      </p>
                    )}
                  </div>
                )}
                {selectedRule.threat_name && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Threat</p>
                    <p className="text-sm font-medium" style={{ color: currentColors.accent.error }}>
                      {selectedRule.threat_name}
                    </p>
                  </div>
                )}
                {selectedRule.threat_actor && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Actor</p>
                    <p className="text-sm font-medium" style={{ color: currentColors.accent.warning }}>
                      {selectedRule.threat_actor}
                    </p>
                  </div>
                )}
                {selectedRule.author && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Author</p>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>{selectedRule.author}</p>
                  </div>
                )}
                {selectedRule.date && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Date</p>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>{selectedRule.date}</p>
                  </div>
                )}
                {selectedRule.severity && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Severity</p>
                    <p className="text-sm" style={{ color: currentColors.text.primary }}>{selectedRule.severity}</p>
                  </div>
                )}
              </div>

              {/* Description */}
              {selectedRule.description && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Description</p>
                  <p className="text-sm" style={{ color: currentColors.text.primary }}>{selectedRule.description}</p>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {selectedRule.mitre_attack && selectedRule.mitre_attack.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>MITRE ATT&CK</p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedRule.mitre_attack.map((t, i) => (
                      <a
                        key={i}
                        href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-1 rounded text-xs flex items-center gap-1 hover:opacity-80"
                        style={{ backgroundColor: currentColors.accent.primary + '20', color: currentColors.accent.primary }}
                      >
                        {t}
                        <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedRule.tags && selectedRule.tags.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Tags</p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedRule.tags.map((tag, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 rounded text-xs"
                        style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {selectedRule.references && selectedRule.references.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>References</p>
                  <div className="space-y-1">
                    {selectedRule.references.map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs flex items-center gap-1 hover:underline truncate"
                        style={{ color: currentColors.accent.primary }}
                      >
                        <ExternalLink size={10} />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Rule Content */}
              <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs" style={{ color: currentColors.text.secondary }}>
                    <Code size={12} className="inline mr-1" />
                    Rule Content ({selectedRule.strings_count} strings)
                  </p>
                  <button
                    onClick={handleCopyRule}
                    className="px-2 py-1 rounded text-xs flex items-center gap-1 hover:opacity-80"
                    style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <pre
                  className="text-xs overflow-x-auto p-3 rounded"
                  style={{
                    backgroundColor: currentColors.bg.secondary,
                    color: currentColors.text.primary,
                    maxHeight: '400px',
                  }}
                >
                  {selectedRule.rule_content}
                </pre>
              </div>

              {/* Source info */}
              <div className="text-xs space-y-1" style={{ color: currentColors.text.muted }}>
                <p>
                  <Database size={10} className="inline mr-1" />
                  Source: {selectedRule.source} / {selectedRule.source_file}
                </p>
                {selectedRule.synced_at && (
                  <p>Synced: {new Date(selectedRule.synced_at).toLocaleString()}</p>
                )}
                {selectedRule.source_url && (
                  <a
                    href={selectedRule.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 hover:underline"
                    style={{ color: currentColors.accent.primary }}
                  >
                    <ExternalLink size={10} />
                    View Source
                  </a>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <FileCode size={64} className="mb-4" style={{ color: currentColors.text.muted }} />
              <p className="text-lg font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Select a rule
              </p>
              <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                Click on a rule from the list to view its details and content
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default YARARulesPage;
