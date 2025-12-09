/**
 * OTX Pulses Service
 * API client for AlienVault OTX pulse feeds
 */

import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';
const OTX_BASE = `${API_URL}/api/v1/cti/otx`;

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

export interface OTXPulse {
  id: string;
  pulse_id: string;
  name: string;
  description: string | null;
  author_name: string | null;
  created: string | null;
  modified: string | null;
  tlp: string | null;
  adversary: string | null;
  targeted_countries: string[];
  industries: string[];
  tags: string[];
  indicator_count: number;
  attack_ids: string[];
  malware_families: string[];
  exported_to_misp: boolean;
  synced_at: string;
}

export interface PulsesListResponse {
  total: number;
  page: number;
  page_size: number;
  pulses: OTXPulse[];
}

export interface PulseIndicator {
  id: string;
  type: string;
  value: string;
  title: string | null;
  description: string | null;
  created: string | null;
}

export interface PulseDetailResponse {
  pulse: OTXPulse & { references: string[] };
  indicators: PulseIndicator[];
  indicators_shown: number;
  indicators_total: number;
}

export interface AdversaryItem {
  name: string;
  count: number;
}

export interface TagItem {
  name: string;
  count: number;
}

export interface PulseStats {
  total_pulses: number;
  total_indicators: number;
  unique_adversaries: number;
  by_tlp: Record<string, number>;
  last_sync: string | null;
}

// ==================== OTX PULSES API ====================

export const otxService = {
  /**
   * List OTX pulses with filters
   */
  async listPulses(params?: {
    search?: string;
    adversary?: string;
    tag?: string;
    page?: number;
    page_size?: number;
  }): Promise<PulsesListResponse> {
    const token = getAuthToken();
    const response = await axios.get(`${OTX_BASE}/pulses`, {
      params,
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get pulse details with indicators
   */
  async getPulseDetail(pulseId: string): Promise<PulseDetailResponse> {
    const token = getAuthToken();
    const response = await axios.get(`${OTX_BASE}/pulses/${pulseId}/detail`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get list of adversaries
   */
  async getAdversaries(): Promise<AdversaryItem[]> {
    const token = getAuthToken();
    const response = await axios.get(`${OTX_BASE}/adversaries`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data.adversaries;
  },

  /**
   * Get list of common tags
   */
  async getTags(limit: number = 50): Promise<TagItem[]> {
    const token = getAuthToken();
    const response = await axios.get(`${OTX_BASE}/tags`, {
      params: { limit },
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data.tags;
  },

  /**
   * Get pulse statistics
   */
  async getStats(): Promise<PulseStats> {
    const token = getAuthToken();
    const response = await axios.get(`${OTX_BASE}/pulses/stats`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  }
};

export default otxService;
