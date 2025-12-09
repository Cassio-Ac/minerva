/**
 * IOC Enrichment Service
 * Service para enriquecer IOCs usando LLM e threat intelligence
 */

import { api } from '../api';
import { MISPIoC } from './mispFeedsService';

export interface IOCEnrichment {
  threat_type: 'c2' | 'phishing' | 'malware_delivery' | 'data_exfiltration' | 'reconnaissance' | 'other';
  severity: 'critical' | 'high' | 'medium' | 'low';
  techniques: string[];
  tactics: string[];
  summary: string;
  detection_methods: string[];
  confidence: 'high' | 'medium' | 'low' | 'none';
  llm_used?: string;
  enriched_at?: string;
  error?: string;
}

export interface EnrichedIOC extends MISPIoC {
  enrichment: IOCEnrichment;
}

export interface EnrichSingleRequest {
  ioc_type: string;
  ioc_value: string;
  context?: string;
  malware_family?: string;
  threat_actor?: string;
  tags?: string;
  llm_provider?: string;
}

export interface EnrichFromFeedRequest {
  feed_type: string;
  limit?: number;
  llm_provider?: string;
}

export interface EnrichFromFeedResponse {
  status: string;
  feed_type: string;
  feed_name: string;
  iocs_fetched: number;
  iocs_enriched: number;
  enriched_iocs: EnrichedIOC[];
}

class IOCEnrichmentService {
  /**
   * Enriquece um único IOC
   */
  async enrichSingle(request: EnrichSingleRequest): Promise<{ status: string; ioc: MISPIoC; enrichment: IOCEnrichment }> {
    const response = await api.post('/cti/ioc-enrichment/enrich-single', null, {
      params: request
    });
    return response.data;
  }

  /**
   * Busca IOCs de um feed e enriquece
   */
  async enrichFromFeed(request: EnrichFromFeedRequest): Promise<EnrichFromFeedResponse> {
    const response = await api.post('/cti/ioc-enrichment/enrich-from-feed', null, {
      params: request
    });
    return response.data;
  }

  /**
   * Obtém estatísticas de enrichment
   */
  async getStats(): Promise<any> {
    const response = await api.get('/cti/ioc-enrichment/stats');
    return response.data;
  }
}

export default new IOCEnrichmentService();
