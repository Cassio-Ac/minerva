/**
 * OTX Pulses Feed Page
 * Browse threat intelligence feeds from AlienVault OTX
 */

import React, { useState, useEffect } from 'react';
import {
  Radio,
  Search,
  ChevronRight,
  AlertCircle,
  Loader2,
  X,
  Users,
  Globe,
  ExternalLink,
  Shield,
  Target,
  Hash,
  Link as LinkIcon,
  CheckCircle,
  Clock,
  List,
  Calendar,
} from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';
import otxService, { OTXPulse, PulseDetailResponse, AdversaryItem, TagItem } from '../../services/cti/otxService';

const OTXPulsesPage: React.FC = () => {
  const { currentColors } = useSettingsStore();

  // Pulses list
  const [pulses, setPulses] = useState<OTXPulse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [selectedAdversary, setSelectedAdversary] = useState<string>('');
  const [adversaries, setAdversaries] = useState<AdversaryItem[]>([]);
  const [tags, setTags] = useState<TagItem[]>([]);

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 20;

  // Selected pulse detail
  const [selectedPulse, setSelectedPulse] = useState<PulseDetailResponse | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // View mode
  const [viewMode, setViewMode] = useState<'list' | 'timeline'>('timeline');

  // Load initial data
  useEffect(() => {
    loadAdversaries();
    loadTags();
  }, []);

  // Load pulses when filters change
  useEffect(() => {
    loadPulses();
  }, [page, selectedAdversary]);

  const loadAdversaries = async () => {
    try {
      const data = await otxService.getAdversaries();
      setAdversaries(data);
    } catch (err) {
      console.error('Error loading adversaries:', err);
    }
  };

  const loadTags = async () => {
    try {
      const data = await otxService.getTags(30);
      setTags(data);
    } catch (err) {
      console.error('Error loading tags:', err);
    }
  };

  const loadPulses = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: any = {
        page,
        page_size: pageSize,
      };
      if (search) params.search = search;
      if (selectedAdversary) params.adversary = selectedAdversary;

      const data = await otxService.listPulses(params);
      setPulses(data.pulses);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setPage(1);
    loadPulses();
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const handlePulseClick = async (pulse: OTXPulse) => {
    setLoadingDetail(true);
    try {
      const detail = await otxService.getPulseDetail(pulse.id);
      setSelectedPulse(detail);
    } catch (err) {
      console.error('Error loading pulse detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const getTLPColor = (tlp: string | null): string => {
    switch (tlp?.toLowerCase()) {
      case 'white': return '#ffffff';
      case 'green': return '#10b981';
      case 'amber': return '#f59e0b';
      case 'red': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getIndicatorIcon = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'ipv4':
      case 'ipv6':
        return <Globe size={14} />;
      case 'domain':
      case 'hostname':
        return <Globe size={14} />;
      case 'url':
      case 'uri':
        return <LinkIcon size={14} />;
      case 'filehash-md5':
      case 'filehash-sha1':
      case 'filehash-sha256':
        return <Hash size={14} />;
      default:
        return <Target size={14} />;
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('pt-BR', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const formatRelativeTime = (dateStr: string | null) => {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
    return `${Math.floor(diffDays / 365)} years ago`;
  };

  const totalPages = Math.ceil(total / pageSize);

  // Group pulses by date for timeline view
  const groupPulsesByDate = (pulsesToGroup: OTXPulse[]) => {
    const groups: Record<string, OTXPulse[]> = {};
    pulsesToGroup.forEach(pulse => {
      const date = pulse.created ? new Date(pulse.created).toLocaleDateString('pt-BR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      }) : 'Unknown Date';
      if (!groups[date]) groups[date] = [];
      groups[date].push(pulse);
    });
    return Object.entries(groups);
  };

  const groupedPulses = groupPulsesByDate(pulses);

  return (
    <div
      className="h-full overflow-hidden flex flex-col"
      style={{ backgroundColor: currentColors.bg.secondary }}
    >
      {/* Header */}
      <div className="px-6 py-4 flex-shrink-0" style={{ borderBottom: `1px solid ${currentColors.border.default}` }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Radio size={28} style={{ color: '#06b6d4' }} />
            <div>
              <h1 className="text-2xl font-semibold" style={{ color: currentColors.text.primary }}>
                OTX Pulse Feeds
              </h1>
              <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                {total} threat intelligence pulses from AlienVault OTX
              </p>
            </div>
          </div>

          {/* Stats */}
          <div className="flex gap-6">
            <div className="text-center">
              <p className="text-2xl font-bold" style={{ color: '#06b6d4' }}>
                {total}
              </p>
              <p className="text-xs" style={{ color: currentColors.text.secondary }}>Pulses</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold" style={{ color: '#10b981' }}>
                {adversaries.length}
              </p>
              <p className="text-xs" style={{ color: currentColors.text.secondary }}>Adversaries</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold" style={{ color: '#f59e0b' }}>
                {tags.length}
              </p>
              <p className="text-xs" style={{ color: currentColors.text.secondary }}>Tags</p>
            </div>
          </div>
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
              placeholder="Search pulses by name, description, adversary..."
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

          {/* Adversary Filter */}
          <select
            value={selectedAdversary}
            onChange={(e) => { setSelectedAdversary(e.target.value); setPage(1); }}
            className="px-3 py-2 rounded-lg text-sm min-w-[200px]"
            style={{
              backgroundColor: currentColors.bg.secondary,
              color: currentColors.text.primary,
              border: `1px solid ${currentColors.border.default}`,
            }}
          >
            <option value="">All Adversaries</option>
            {adversaries.map((adv) => (
              <option key={adv.name} value={adv.name}>
                {adv.name} ({adv.count})
              </option>
            ))}
          </select>

          {/* Search Button */}
          <button
            onClick={handleSearch}
            className="px-4 py-2 rounded-lg flex items-center gap-2"
            style={{
              backgroundColor: '#06b6d4',
              color: '#fff',
            }}
          >
            <Search size={16} />
            Search
          </button>

          {/* View Mode Toggle */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: `1px solid ${currentColors.border.default}` }}>
            <button
              onClick={() => setViewMode('list')}
              className="px-3 py-2 flex items-center gap-1"
              style={{
                backgroundColor: viewMode === 'list' ? '#06b6d4' : currentColors.bg.secondary,
                color: viewMode === 'list' ? '#fff' : currentColors.text.secondary,
              }}
            >
              <List size={16} />
            </button>
            <button
              onClick={() => setViewMode('timeline')}
              className="px-3 py-2 flex items-center gap-1"
              style={{
                backgroundColor: viewMode === 'timeline' ? '#06b6d4' : currentColors.bg.secondary,
                color: viewMode === 'timeline' ? '#fff' : currentColors.text.secondary,
              }}
            >
              <Calendar size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Pulses List */}
        <div
          className="w-1/2 overflow-y-auto p-4"
          style={{ borderRight: `1px solid ${currentColors.border.default}` }}
        >
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={32} className="animate-spin" style={{ color: '#06b6d4' }} />
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg flex items-center gap-3" style={{ backgroundColor: '#fee2e2' }}>
              <AlertCircle size={20} color="#dc2626" />
              <p className="text-sm" style={{ color: '#991b1b' }}>{error}</p>
            </div>
          ) : pulses.length === 0 ? (
            <div className="text-center py-12">
              <Radio size={48} className="mx-auto mb-4" style={{ color: currentColors.text.muted }} />
              <p style={{ color: currentColors.text.secondary }}>No pulses found</p>
            </div>
          ) : (
            <>
              {/* Results count */}
              <p className="text-sm mb-4" style={{ color: currentColors.text.secondary }}>
                Showing {((page - 1) * pageSize) + 1}-{Math.min(page * pageSize, total)} of {total} pulses
              </p>

              {/* Timeline View */}
              {viewMode === 'timeline' ? (
                <div className="relative">
                  {/* Timeline line */}
                  <div
                    className="absolute left-3 top-0 bottom-0 w-0.5"
                    style={{ backgroundColor: currentColors.border.default }}
                  />

                  {groupedPulses.map(([dateStr, datePulses]) => (
                    <div key={dateStr} className="mb-6">
                      {/* Date Header */}
                      <div className="flex items-center gap-3 mb-3 sticky top-0 z-10 py-2" style={{ backgroundColor: currentColors.bg.secondary }}>
                        <div
                          className="w-6 h-6 rounded-full flex items-center justify-center z-10"
                          style={{ backgroundColor: '#06b6d4' }}
                        >
                          <Calendar size={12} color="#fff" />
                        </div>
                        <span className="text-sm font-medium" style={{ color: currentColors.text.primary }}>
                          {dateStr}
                        </span>
                        <span
                          className="px-2 py-0.5 rounded-full text-xs"
                          style={{ backgroundColor: currentColors.bg.tertiary, color: currentColors.text.secondary }}
                        >
                          {datePulses.length} pulse{datePulses.length > 1 ? 's' : ''}
                        </span>
                      </div>

                      {/* Pulses for this date */}
                      <div className="ml-9 space-y-2">
                        {datePulses.map((pulse) => (
                          <button
                            key={pulse.id}
                            onClick={() => handlePulseClick(pulse)}
                            className="w-full p-3 rounded-lg text-left hover:opacity-90 transition-all border relative"
                            style={{
                              backgroundColor: selectedPulse?.pulse.id === pulse.id ? currentColors.bg.tertiary : currentColors.bg.primary,
                              borderColor: selectedPulse?.pulse.id === pulse.id ? '#06b6d4' : currentColors.border.default,
                            }}
                          >
                            {/* Timeline connector */}
                            <div
                              className="absolute -left-6 top-4 w-3 h-0.5"
                              style={{ backgroundColor: currentColors.border.default }}
                            />

                            <div className="flex items-start justify-between gap-2">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1 flex-wrap">
                                  <span
                                    className="px-1.5 py-0.5 rounded text-xs font-medium"
                                    style={{
                                      backgroundColor: getTLPColor(pulse.tlp),
                                      color: pulse.tlp?.toLowerCase() === 'white' ? '#000' : '#fff',
                                      border: pulse.tlp?.toLowerCase() === 'white' ? '1px solid #ccc' : 'none'
                                    }}
                                  >
                                    TLP:{pulse.tlp?.toUpperCase() || 'N/A'}
                                  </span>
                                  <span className="text-xs" style={{ color: currentColors.text.muted }}>
                                    {pulse.indicator_count.toLocaleString()} IOCs
                                  </span>
                                  {pulse.adversary && (
                                    <span className="text-xs flex items-center gap-1" style={{ color: '#ef4444' }}>
                                      <Users size={10} />
                                      {pulse.adversary}
                                    </span>
                                  )}
                                </div>
                                <h3 className="font-medium text-sm line-clamp-2" style={{ color: currentColors.text.primary }}>
                                  {pulse.name}
                                </h3>
                                {pulse.tags.length > 0 && (
                                  <div className="flex gap-1 flex-wrap mt-1">
                                    {pulse.tags.slice(0, 3).map((tag, i) => (
                                      <span
                                        key={i}
                                        className="px-1.5 py-0.5 rounded text-xs"
                                        style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.secondary }}
                                      >
                                        {tag}
                                      </span>
                                    ))}
                                    {pulse.tags.length > 3 && (
                                      <span className="text-xs" style={{ color: currentColors.text.muted }}>
                                        +{pulse.tags.length - 3}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                              <ChevronRight size={14} style={{ color: currentColors.text.muted }} />
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
              /* List View */
              <div className="space-y-3">
                {pulses.map((pulse) => (
                  <button
                    key={pulse.id}
                    onClick={() => handlePulseClick(pulse)}
                    className="w-full p-4 rounded-lg text-left hover:opacity-90 transition-all border"
                    style={{
                      backgroundColor: selectedPulse?.pulse.id === pulse.id ? currentColors.bg.tertiary : currentColors.bg.primary,
                      borderColor: selectedPulse?.pulse.id === pulse.id ? '#06b6d4' : currentColors.border.default,
                    }}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          {/* TLP Badge */}
                          <span
                            className="px-2 py-0.5 rounded text-xs font-medium"
                            style={{
                              backgroundColor: getTLPColor(pulse.tlp),
                              color: pulse.tlp?.toLowerCase() === 'white' ? '#000' : '#fff',
                              border: pulse.tlp?.toLowerCase() === 'white' ? '1px solid #ccc' : 'none'
                            }}
                          >
                            TLP:{pulse.tlp?.toUpperCase() || 'N/A'}
                          </span>
                          {/* Indicator count */}
                          <span className="text-xs" style={{ color: currentColors.text.muted }}>
                            {pulse.indicator_count.toLocaleString()} IOCs
                          </span>
                          {/* MISP export status */}
                          {pulse.exported_to_misp && (
                            <CheckCircle size={12} style={{ color: '#10b981' }} />
                          )}
                        </div>
                        <h3 className="font-medium text-sm line-clamp-2" style={{ color: currentColors.text.primary }}>
                          {pulse.name}
                        </h3>
                      </div>
                      <ChevronRight size={16} style={{ color: currentColors.text.muted }} />
                    </div>

                    {/* Adversary */}
                    {pulse.adversary && (
                      <p className="text-xs mb-2 flex items-center gap-1" style={{ color: '#ef4444' }}>
                        <Users size={12} />
                        {pulse.adversary}
                      </p>
                    )}

                    {/* Date */}
                    <div className="flex items-center gap-2 text-xs mb-2" style={{ color: currentColors.text.secondary }}>
                      <Clock size={12} />
                      <span>{formatRelativeTime(pulse.created)}</span>
                      <span>•</span>
                      <span>{formatDate(pulse.created)}</span>
                    </div>

                    {/* Tags */}
                    {pulse.tags.length > 0 && (
                      <div className="flex gap-1 flex-wrap">
                        {pulse.tags.slice(0, 4).map((tag, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 rounded text-xs"
                            style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.secondary }}
                          >
                            {tag}
                          </span>
                        ))}
                        {pulse.tags.length > 4 && (
                          <span className="text-xs" style={{ color: currentColors.text.muted }}>
                            +{pulse.tags.length - 4}
                          </span>
                        )}
                      </div>
                    )}

                    {/* MITRE ATT&CK */}
                    {pulse.attack_ids.length > 0 && (
                      <div className="flex gap-1 flex-wrap mt-2">
                        {pulse.attack_ids.slice(0, 3).map((t, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 rounded text-xs"
                            style={{ backgroundColor: '#06b6d420', color: '#06b6d4' }}
                          >
                            {t}
                          </span>
                        ))}
                        {pulse.attack_ids.length > 3 && (
                          <span className="text-xs" style={{ color: currentColors.text.muted }}>
                            +{pulse.attack_ids.length - 3}
                          </span>
                        )}
                      </div>
                    )}
                  </button>
                ))}
              </div>
              )}

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

        {/* Pulse Detail Panel */}
        <div className="w-1/2 overflow-y-auto p-4">
          {loadingDetail ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={32} className="animate-spin" style={{ color: '#06b6d4' }} />
            </div>
          ) : selectedPulse ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className="px-2 py-0.5 rounded text-xs font-medium"
                      style={{
                        backgroundColor: getTLPColor(selectedPulse.pulse.tlp),
                        color: selectedPulse.pulse.tlp?.toLowerCase() === 'white' ? '#000' : '#fff',
                        border: selectedPulse.pulse.tlp?.toLowerCase() === 'white' ? '1px solid #ccc' : 'none'
                      }}
                    >
                      TLP:{selectedPulse.pulse.tlp?.toUpperCase() || 'N/A'}
                    </span>
                    {selectedPulse.pulse.exported_to_misp && (
                      <span className="px-2 py-0.5 rounded text-xs" style={{ backgroundColor: '#10b981', color: '#fff' }}>
                        <CheckCircle size={10} className="inline mr-1" />
                        Exported to MISP
                      </span>
                    )}
                  </div>
                  <h2 className="text-lg font-semibold" style={{ color: currentColors.text.primary }}>
                    {selectedPulse.pulse.name}
                  </h2>
                  {selectedPulse.pulse.author_name && (
                    <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                      by {selectedPulse.pulse.author_name}
                    </p>
                  )}
                </div>
                <button
                  onClick={() => setSelectedPulse(null)}
                  className="p-1 rounded hover:opacity-80"
                  style={{ color: currentColors.text.muted }}
                >
                  <X size={20} />
                </button>
              </div>

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 gap-3">
                {selectedPulse.pulse.adversary && (
                  <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                    <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Adversary</p>
                    <p className="text-sm font-medium" style={{ color: '#ef4444' }}>
                      <Users size={12} className="inline mr-1" />
                      {selectedPulse.pulse.adversary}
                    </p>
                  </div>
                )}
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Indicators</p>
                  <p className="text-sm font-medium" style={{ color: '#06b6d4' }}>
                    {selectedPulse.pulse.indicator_count.toLocaleString()} IOCs
                  </p>
                </div>
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Created</p>
                  <p className="text-sm" style={{ color: currentColors.text.primary }}>
                    {formatDate(selectedPulse.pulse.created)}
                  </p>
                </div>
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Modified</p>
                  <p className="text-sm" style={{ color: currentColors.text.primary }}>
                    {formatDate(selectedPulse.pulse.modified)}
                  </p>
                </div>
              </div>

              {/* Description */}
              {selectedPulse.pulse.description && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-1" style={{ color: currentColors.text.secondary }}>Description</p>
                  <p className="text-sm whitespace-pre-wrap" style={{ color: currentColors.text.primary }}>
                    {selectedPulse.pulse.description}
                  </p>
                </div>
              )}

              {/* Targeted Countries */}
              {selectedPulse.pulse.targeted_countries.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>
                    <Globe size={12} className="inline mr-1" />
                    Targeted Countries
                  </p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedPulse.pulse.targeted_countries.map((country, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 rounded text-xs"
                        style={{ backgroundColor: currentColors.bg.secondary, color: currentColors.text.primary }}
                      >
                        {country}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Malware Families */}
              {selectedPulse.pulse.malware_families.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>
                    <Shield size={12} className="inline mr-1" />
                    Malware Families
                  </p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedPulse.pulse.malware_families.map((family, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 rounded text-xs"
                        style={{ backgroundColor: '#ef444420', color: '#ef4444' }}
                      >
                        {family}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {selectedPulse.pulse.attack_ids.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>MITRE ATT&CK</p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedPulse.pulse.attack_ids.map((t, i) => (
                      <a
                        key={i}
                        href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-1 rounded text-xs flex items-center gap-1 hover:opacity-80"
                        style={{ backgroundColor: '#06b6d420', color: '#06b6d4' }}
                      >
                        {t}
                        <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedPulse.pulse.tags.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>Tags</p>
                  <div className="flex gap-2 flex-wrap">
                    {selectedPulse.pulse.tags.map((tag, i) => (
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

              {/* Sample Indicators */}
              <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs" style={{ color: currentColors.text.secondary }}>
                    <Target size={12} className="inline mr-1" />
                    Sample Indicators ({selectedPulse.indicators_shown} of {selectedPulse.indicators_total})
                  </p>
                </div>
                <div className="space-y-2 max-h-[300px] overflow-y-auto">
                  {selectedPulse.indicators.slice(0, 20).map((indicator, i) => (
                    <div
                      key={i}
                      className="p-2 rounded text-sm flex items-start gap-2"
                      style={{ backgroundColor: currentColors.bg.secondary }}
                    >
                      <span style={{ color: '#06b6d4' }}>
                        {getIndicatorIcon(indicator.type)}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="font-mono text-xs truncate" style={{ color: currentColors.text.primary }}>
                          {indicator.value}
                        </p>
                        <p className="text-xs" style={{ color: currentColors.text.muted }}>
                          {indicator.type}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* References */}
              {selectedPulse.pulse.references && selectedPulse.pulse.references.length > 0 && (
                <div className="p-3 rounded-lg" style={{ backgroundColor: currentColors.bg.primary }}>
                  <p className="text-xs mb-2" style={{ color: currentColors.text.secondary }}>References</p>
                  <div className="space-y-1">
                    {selectedPulse.pulse.references.slice(0, 5).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs flex items-center gap-1 hover:underline truncate"
                        style={{ color: '#06b6d4' }}
                      >
                        <ExternalLink size={10} />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Source info */}
              <div className="text-xs space-y-1" style={{ color: currentColors.text.muted }}>
                <p>Pulse ID: {selectedPulse.pulse.pulse_id}</p>
                <p>Synced: {new Date(selectedPulse.pulse.synced_at).toLocaleString()}</p>
                <a
                  href={`https://otx.alienvault.com/pulse/${selectedPulse.pulse.pulse_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 hover:underline"
                  style={{ color: '#06b6d4' }}
                >
                  <ExternalLink size={10} />
                  View on OTX
                </a>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <Radio size={64} className="mb-4" style={{ color: currentColors.text.muted }} />
              <p className="text-lg font-medium mb-2" style={{ color: currentColors.text.primary }}>
                Select a pulse
              </p>
              <p className="text-sm" style={{ color: currentColors.text.secondary }}>
                Click on a pulse from the feed to view its details and indicators
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OTXPulsesPage;
