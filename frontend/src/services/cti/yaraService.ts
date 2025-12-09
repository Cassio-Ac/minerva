/**
 * YARA Rules Service
 * API client for unified YARA rules (Signature Base + Malpedia)
 */

import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';
const YARA_BASE = `${API_URL}/api/v1/cti/yara`;

// Helper to get auth token
const getAuthToken = (): string | null => {
  const authStorage = localStorage.getItem('dashboard-auth-storage');
  if (authStorage) {
    try {
      const { state } = JSON.parse(authStorage);
      return state?.token || null;
    } catch (error) {
      console.error('Error parsing auth storage:', error);
      return null;
    }
  }
  return null;
};

// ==================== TYPES ====================

export interface YaraRule {
  id: string;
  rule_name: string;
  source: string;
  source_file: string | null;
  category: string | null;
  threat_name: string | null;
  threat_actor: string | null;
  malware_family: string | null;
  malware_aliases: string[] | null;
  description: string | null;
  author: string | null;
  tags: string[];
  mitre_attack: string[];
  severity: string | null;
  strings_count: number;
  is_active: boolean;
  synced_at: string | null;
}

export interface YaraRuleDetail extends YaraRule {
  rule_content: string;
  rule_hash: string | null;
  source_url: string | null;
  references: string[];
  date: string | null;
  version: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface YaraRulesListResponse {
  total: number;
  page: number;
  page_size: number;
  rules: YaraRule[];
}

export interface YaraStats {
  total_rules: number;
  active_rules: number;
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  by_threat_actor: Record<string, number>;
  by_malware_family: Record<string, number>;
  total_families: number;
  last_sync: string | null;
}

export interface CategoryItem {
  name: string;
  count: number;
}

export interface ThreatActorItem {
  name: string;
  count: number;
}

export interface MalwareFamilyItem {
  name: string;
  count: number;
}

export interface SignatureBaseIOC {
  id: string;
  value: string;
  type: string;
  description: string | null;
  source_file: string | null;
  hash_type: string | null;
  is_active: boolean;
  synced_at: string;
}

export interface IOCsListResponse {
  total: number;
  page: number;
  page_size: number;
  iocs: SignatureBaseIOC[];
}

export interface IOCStats {
  total: number;
  by_type: Record<string, number>;
  by_hash_type: Record<string, number>;
}

// ==================== YARA RULES API ====================

export const yaraService = {
  /**
   * List YARA rules with filters
   * Searches unified index (Signature Base + Malpedia)
   */
  async listRules(params?: {
    search?: string;
    category?: string;
    threat_actor?: string;
    malware_family?: string;
    mitre_attack?: string;
    source?: string;
    tags?: string;
    page?: number;
    page_size?: number;
  }): Promise<YaraRulesListResponse> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/rules`, {
      params,
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get YARA rule details including content
   */
  async getRuleDetail(ruleId: string): Promise<YaraRuleDetail> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/rules/${ruleId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get YARA statistics
   */
  async getStats(): Promise<YaraStats> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/stats`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get categories list
   */
  async getCategories(): Promise<CategoryItem[]> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/categories`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data.categories;
  },

  /**
   * Get threat actors list
   */
  async getThreatActors(): Promise<ThreatActorItem[]> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/threat-actors`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data.threat_actors;
  },

  /**
   * Get malware families list (from Malpedia)
   */
  async getMalwareFamilies(): Promise<MalwareFamilyItem[]> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/malware-families`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data.malware_families;
  },

  // ==================== SIGNATURE BASE IOCs ====================

  /**
   * List Signature Base IOCs
   */
  async listIOCs(params?: {
    search?: string;
    ioc_type?: string;
    hash_type?: string;
    page?: number;
    page_size?: number;
  }): Promise<IOCsListResponse> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/iocs`, {
      params,
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get IOC statistics
   */
  async getIOCStats(): Promise<IOCStats> {
    const token = getAuthToken();
    const response = await axios.get(`${YARA_BASE}/iocs/stats`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  }
};

export default yaraService;
