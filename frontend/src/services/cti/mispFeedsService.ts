/**
 * MISP Feeds Service
 * Service para interagir com feeds MISP de threat intelligence
 */

import { api } from '../api';

export interface MISPFeed {
  id: string;
  name: string;
  url: string;
  feed_type: string;
  description?: string;
  is_active: boolean;
  last_sync?: string;
  iocs_count?: number;
}

export interface MISPIoC {
  id?: string;
  type: string;
  subtype?: string;
  value: string;
  context?: string;
  tags?: string[];
  malware_family?: string;
  threat_actor?: string;
  tlp?: string;
  first_seen?: string;
  confidence?: string;
  to_ids?: boolean;
}

export interface FeedTestResult {
  status: string;
  feed_type: string;
  feed_name: string;
  feed_url: string;
  items_processed: number;
  iocs_found: number;
  sample: MISPIoC[];
}

export interface AvailableFeed {
  id: string;
  name: string;
  url: string;
  type: string;
  description: string;
  requires_auth: boolean;
}

export interface IOCStats {
  total_iocs: number;
  by_type: Record<string, number>;
  by_tlp: Record<string, number>;
  by_confidence: Record<string, number>;
  by_feed: Record<string, number>;
  feeds_count: number;
  last_sync: string | null;
}

export interface OTXResult {
  found: boolean;
  pulses: number;
  tags?: string[];
  malware_families?: string[] | null;
  pulse_names?: string[];
  message: string;
}

export interface LLMEnrichmentResult {
  threat_type: string;
  severity: string;
  techniques: string[];
  tactics: string[];
  summary: string;
  detection_methods: string[];
  confidence: string;
  llm_used?: string;
  error?: string;
}

export interface IOCSearchResult {
  misp: {
    found: boolean;
    ioc?: MISPIoC;
    source?: string | null;
    message?: string;
  };
  otx: OTXResult;
  enrichment?: LLMEnrichmentResult | null;
}

class MISPFeedsService {
  /**
   * Lista feeds disponíveis para configuração
   */
  async listAvailableFeeds(): Promise<AvailableFeed[]> {
    const response = await api.get('/cti/misp/feeds/available');
    return response.data.feeds;
  }

  /**
   * Lista feeds configurados
   */
  async listFeeds(): Promise<MISPFeed[]> {
    const response = await api.get('/cti/misp/feeds');
    return response.data;
  }

  /**
   * Testa um feed específico (sem persistir no banco)
   */
  async testFeed(
    feedType: string,
    limit: number = 5,
    otxApiKey?: string,
    usePagination?: boolean
  ): Promise<FeedTestResult> {
    const params: any = { limit };
    if (otxApiKey) params.otx_api_key = otxApiKey;
    if (usePagination !== undefined) params.use_pagination = usePagination;

    const response = await api.post(`/cti/misp/feeds/test/${feedType}`, null, { params });
    return response.data;
  }

  /**
   * Sincroniza feed para o banco de dados
   */
  async syncFeed(
    feedType: string,
    limit: number = 100,
    otxApiKey?: string
  ): Promise<any> {
    const params: any = { limit };
    if (otxApiKey) params.otx_api_key = otxApiKey;

    const response = await api.post(`/cti/misp/feeds/sync/${feedType}`, null, { params });
    return response.data;
  }

  /**
   * Busca IOC por valor (MISP + OTX)
   */
  async searchIoC(value: string): Promise<IOCSearchResult> {
    const response = await api.get('/cti/misp/iocs/search', {
      params: { value }
    });
    return response.data;
  }

  /**
   * Obtém estatísticas de IOCs
   */
  async getStats(): Promise<IOCStats> {
    const response = await api.get('/cti/misp/iocs/stats');
    return response.data;
  }

  /**
   * Lista IOCs com filtros opcionais
   */
  async listIOCs(params: {
    search?: string;
    ioc_type?: string;
    threat_actor?: string;
    malware_family?: string;
    feed_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    iocs: MISPIoC[];
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
  }> {
    const response = await api.get('/cti/misp/iocs', { params });
    return response.data;
  }
}

export default new MISPFeedsService();
