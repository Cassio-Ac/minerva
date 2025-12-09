/**
 * CTI Service - Cyber Threat Intelligence API Client
 *
 * Handles communication with CTI backend endpoints:
 * - Actors (threat actors from Malpedia)
 * - Families (malware families from Malpedia)
 * - Techniques (MITRE ATT&CK techniques)
 */

import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';
const CTI_BASE = `${API_URL}/api/v1/cti`;

// Helper to get auth token from Zustand persist storage
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

export interface Actor {
  name: string;
  aka?: string[] | null;
  explicacao?: string;
  familias_relacionadas?: string[];
  url?: string;
  referencias?: Array<{desc: string; url: string}>;
  country?: string;
}

export interface ActorListResponse {
  total: number;
  page: number;
  page_size: number;
  actors: Actor[];
}

export interface Family {
  name: string;
  os?: string;
  aka?: string[] | null;
  descricao?: string;
  url?: string;
  status?: string;
  update?: string;
  referencias?: Array<{desc: string; url: string}>;
  yara_rules?: string[];
  actors?: string[];
}

export interface FamilyListResponse {
  total: number;
  page: number;
  page_size: number;
  families: Family[];
}

export interface FamilyDetail extends Family {
  yara_rules?: Array<{
    rule_name: string;
    tlp: string;
    rule_raw?: string;
  }>;
  actors?: string[];
}

export interface Technique {
  technique_id: string;
  name: string;
  description?: string;
  tactics?: string[];
  url?: string;
  is_subtechnique?: boolean;
  parent_id?: string;
}

export interface TechniqueListResponse {
  total: number;
  techniques: Technique[];
}

export interface Tactic {
  tactic_id: string;
  name: string;
  description?: string;
  url?: string;
}

export interface MatrixResponse {
  tactics: Tactic[];
  techniques: Technique[];
  matrix: Record<string, string[]>; // tactic_id -> technique_ids
}

export interface TechniqueDetail extends Technique {
  technique_name: string;
  mitigations?: Array<{
    mitigation_id: string;
    name: string;
    description?: string;
  }>;
}

export interface HighlightRequest {
  actors?: string[];
  families?: string[];
  mode?: 'union' | 'intersection';
}

export interface HighlightResponse {
  highlighted_techniques: string[];
  technique_details: Record<string, Technique>;
  message?: string;
}

export interface CTIStats {
  total_tactics: number;
  total_techniques: number;
  total_subtechniques: number;
  total_mitigations: number;
  matrix_size: string;
}

export interface ActorGeopoliticalData {
  found: boolean;
  country?: string;
  state_sponsor?: string;
  military_unit?: string;
  targeted_countries: string[];
  targeted_sectors: string[];
  incident_type?: string;
  attribution_confidence?: string;
  additional_aliases: string[];
  misp_refs: string[];
  description?: string;
}

export interface CountryActors {
  country: string;
  count: number;
  actors: string[];
}

export interface ActorsByCountryResponse {
  countries: CountryActors[];
  total_actors: number;
  countries_with_actors: number;
}

// ==================== ACTORS API ====================

export const ctiActorsApi = {
  /**
   * List threat actors with optional filters
   */
  async listActors(params?: {
    search?: string;
    country?: string;
    page?: number;
    page_size?: number;
    server_id?: string;
  }): Promise<ActorListResponse> {
    const token = getAuthToken();
    const response = await axios.get(`${CTI_BASE}/actors`, {
      params,
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return response.data;
  },

  /**
   * Get detailed information about a specific actor
   */
  async getActorDetail(actorName: string, params?: {
    include_families?: boolean;
    server_id?: string;
  }): Promise<Actor> {
    const response = await axios.get(`${CTI_BASE}/actors/${actorName}`, {
      params,
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get all unique countries from threat actors
   */
  async getActorCountries(serverId?: string): Promise<string[]> {
    const response = await axios.get(`${CTI_BASE}/actors/meta/countries`, {
      params: { server_id: serverId },
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data.countries;
  },

  /**
   * Get threat actors grouped by country (from MISP Galaxy)
   */
  async getActorsByCountry(): Promise<ActorsByCountryResponse> {
    const response = await axios.get(`${CTI_BASE}/galaxy/actors-by-country`, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  }
};

// ==================== FAMILIES API ====================

export const ctiFamiliesApi = {
  /**
   * List malware families with optional filters
   */
  async listFamilies(params?: {
    search?: string;
    os_filter?: string;
    page?: number;
    page_size?: number;
    server_id?: string;
  }): Promise<FamilyListResponse> {
    const response = await axios.get(`${CTI_BASE}/families`, {
      params,
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get detailed information about a specific malware family
   */
  async getFamilyDetail(familyName: string, params?: {
    include_yara?: boolean;
    server_id?: string;
  }): Promise<FamilyDetail> {
    const response = await axios.get(`${CTI_BASE}/families/${familyName}`, {
      params,
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get threat actors using this malware family
   */
  async getFamilyActors(familyName: string, serverId?: string): Promise<string[]> {
    const response = await axios.get(`${CTI_BASE}/families/${familyName}/actors`, {
      params: { server_id: serverId },
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data.actors;
  },

  /**
   * Get YARA rules for a malware family
   */
  async getFamilyYara(familyName: string, serverId?: string): Promise<any> {
    const response = await axios.get(`${CTI_BASE}/families/${familyName}/yara`, {
      params: { server_id: serverId },
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  }
};

// ==================== TECHNIQUES API ====================

export const ctiTechniquesApi = {
  /**
   * List MITRE ATT&CK techniques
   */
  async listTechniques(params?: {
    include_subtechniques?: boolean;
    tactic?: string;
  }): Promise<TechniqueListResponse> {
    const response = await axios.get(`${CTI_BASE}/techniques`, {
      params,
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get ATT&CK matrix structure (tactics × techniques)
   */
  async getMatrix(): Promise<MatrixResponse> {
    const response = await axios.get(`${CTI_BASE}/techniques/matrix`, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get detailed information about a specific technique
   */
  async getTechniqueDetail(techniqueId: string): Promise<TechniqueDetail> {
    const response = await axios.get(`${CTI_BASE}/techniques/${techniqueId}`, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Highlight techniques based on selected actors/families
   */
  async highlightTechniques(request: HighlightRequest): Promise<HighlightResponse> {
    const response = await axios.post(`${CTI_BASE}/techniques/highlight`, request, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get statistics about ATT&CK data
   */
  async getStats(): Promise<CTIStats> {
    const response = await axios.get(`${CTI_BASE}/techniques/stats`, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  }
};

// ==================== ENRICHMENT API ====================

export interface ActorTechniquesResponse {
  actor: string;
  techniques_count: number;
  techniques: string[];
  from_cache: boolean;
}

export const ctiEnrichmentApi = {
  /**
   * Get geopolitical data for a threat actor from MISP Galaxy
   */
  async getActorGeopoliticalData(actorName: string): Promise<ActorGeopoliticalData> {
    const response = await axios.get(`${CTI_BASE}/enrichment/geopolitical/${actorName}`, {
      headers: {
        Authorization: `Bearer ${getAuthToken()}`
      }
    });
    return response.data;
  },

  /**
   * Get MITRE ATT&CK techniques for a specific actor
   */
  async getActorTechniques(actorName: string): Promise<ActorTechniquesResponse> {
    const response = await axios.post(`${CTI_BASE}/enrichment/enrich`,
      { actors: [actorName], force: false },
      {
        headers: {
          Authorization: `Bearer ${getAuthToken()}`
        }
      }
    );
    return response.data[0]; // Return first result
  }
};

// ==================== UNIFIED CTI SERVICE ====================

export const ctiService = {
  actors: ctiActorsApi,
  families: ctiFamiliesApi,
  techniques: ctiTechniquesApi,
  enrichment: ctiEnrichmentApi
};

export default ctiService;
