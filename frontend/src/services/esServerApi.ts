/**
 * Elasticsearch Server API Client
 * Serviços para gerenciar servidores ES
 */

import axios from 'axios';
import {
  ElasticsearchServer,
  ESServerCreate,
  ESServerUpdate,
  ESServerTestResult,
  ESIndexInfo,
} from '../types/elasticsearch';
import { API_URL } from '../config/api';

const BASE_PATH = '/es-servers';

export const esServerApi = {
  /**
   * Lista todos os servidores ES
   */
  async list(activeOnly = false, includeStats = false): Promise<ElasticsearchServer[]> {
    const url = `${API_URL}${BASE_PATH}/`;
    console.log('Fetching servers from:', url);
    const response = await axios.get(url, {
      params: {
        active_only: activeOnly,
        include_stats: includeStats,
      },
    });
    console.log('Servers response:', response.data);
    return response.data;
  },

  /**
   * Obtém servidor por ID
   */
  async get(serverId: string): Promise<ElasticsearchServer> {
    const response = await axios.get(`${API_URL}${BASE_PATH}/${serverId}`);
    return response.data;
  },

  /**
   * Obtém servidor padrão
   */
  async getDefault(): Promise<ElasticsearchServer> {
    const response = await axios.get(`${API_URL}${BASE_PATH}/default`);
    return response.data;
  },

  /**
   * Cria novo servidor
   */
  async create(server: ESServerCreate): Promise<ElasticsearchServer> {
    const response = await axios.post(`${API_URL}${BASE_PATH}/`, server);
    return response.data;
  },

  /**
   * Atualiza servidor
   */
  async update(serverId: string, updates: ESServerUpdate): Promise<ElasticsearchServer> {
    const response = await axios.patch(`${API_URL}${BASE_PATH}/${serverId}`, updates);
    return response.data;
  },

  /**
   * Deleta servidor
   */
  async delete(serverId: string): Promise<void> {
    await axios.delete(`${API_URL}${BASE_PATH}/${serverId}`);
  },

  /**
   * Testa conexão com servidor
   */
  async testConnection(serverId: string): Promise<ESServerTestResult> {
    const response = await axios.post(`${API_URL}${BASE_PATH}/${serverId}/test`);
    return response.data;
  },

  /**
   * Lista índices do servidor
   */
  async listIndices(serverId: string): Promise<ESIndexInfo[]> {
    const response = await axios.get(`${API_URL}${BASE_PATH}/${serverId}/indices`);
    return response.data;
  },
};
