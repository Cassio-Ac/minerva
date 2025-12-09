/**
 * API Service
 * REST API client for backend communication
 */

import axios, { AxiosInstance } from 'axios';
import type {
  Dashboard,
  DashboardListItem,
  DashboardCreate,
  DashboardUpdate,
  Widget,
  WidgetCreate,
  WidgetUpdate,
  WidgetPosition,
  ChatRequest,
  ChatResponse,
} from '@types/index';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: `${API_URL}/api/v1`,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token from Zustand persist storage
        const authStorage = localStorage.getItem('dashboard-auth-storage');
        if (authStorage) {
          try {
            const { state } = JSON.parse(authStorage);
            if (state?.token) {
              config.headers.Authorization = `Bearer ${state.token}`;
            }
          } catch (error) {
            console.error('Error parsing auth storage:', error);
          }
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        console.error('API Error:', error.response?.data || error.message);
        return Promise.reject(error);
      }
    );
  }

  // ========== Dashboards ==========

  async listDashboards(params?: {
    skip?: number;
    limit?: number;
    index?: string;
    tags?: string;
  }): Promise<DashboardListItem[]> {
    const response = await this.client.get<DashboardListItem[]>('/dashboards', {
      params,
    });
    return response.data;
  }

  async getDashboard(dashboardId: string): Promise<Dashboard> {
    const response = await this.client.get<Dashboard>(
      `/dashboards/${dashboardId}`
    );
    return response.data;
  }

  async createDashboard(data: DashboardCreate): Promise<Dashboard> {
    const response = await this.client.post<Dashboard>('/dashboards', data);
    return response.data;
  }

  async updateDashboard(
    dashboardId: string,
    data: DashboardUpdate
  ): Promise<Dashboard> {
    const response = await this.client.patch<Dashboard>(
      `/dashboards/${dashboardId}`,
      data
    );
    return response.data;
  }

  async deleteDashboard(dashboardId: string): Promise<void> {
    await this.client.delete(`/dashboards/${dashboardId}`);
  }

  async duplicateDashboard(
    dashboardId: string,
    newTitle?: string
  ): Promise<Dashboard> {
    const response = await this.client.post<Dashboard>(
      `/dashboards/${dashboardId}/duplicate`,
      null,
      { params: { new_title: newTitle } }
    );
    return response.data;
  }

  // ========== Widgets ==========

  async createWidget(data: WidgetCreate): Promise<Widget> {
    const response = await this.client.post<Widget>('/widgets', data);
    return response.data;
  }

  async updateWidgetPosition(
    widgetId: string,
    position: WidgetPosition
  ): Promise<Widget> {
    const response = await this.client.patch<Widget>(
      `/widgets/${widgetId}/position`,
      position
    );
    return response.data;
  }

  async updateWidget(
    widgetId: string,
    data: WidgetUpdate
  ): Promise<Widget> {
    const response = await this.client.patch<Widget>(
      `/widgets/${widgetId}`,
      data
    );
    return response.data;
  }

  async deleteWidget(widgetId: string): Promise<void> {
    await this.client.delete(`/widgets/${widgetId}`);
  }

  // ========== Chat ==========

  async chat(request: ChatRequest): Promise<ChatResponse> {
    const response = await this.client.post<ChatResponse>('/chat', request);
    return response.data;
  }

  async executeQuery(
    index: string,
    query: Record<string, any>,
    serverId?: string,
    timeRange?: any
  ): Promise<any> {
    const response = await this.client.post('/chat/execute', {
      index,
      query,
      server_id: serverId,
      time_range: timeRange,
    });
    return response.data;
  }

  // ========== Elasticsearch ==========

  async getESServers(): Promise<any[]> {
    const response = await this.client.get('/es-servers/');
    return response.data;
  }

  async listIndices(pattern: string = '*'): Promise<any[]> {
    const response = await this.client.get('/elasticsearch/indices', {
      params: { pattern },
    });
    return response.data;
  }

  async getMapping(indexName: string): Promise<any> {
    const response = await this.client.get(
      `/elasticsearch/indices/${indexName}/mapping`
    );
    return response.data;
  }

  async getFields(indexName: string): Promise<any[]> {
    const response = await this.client.get(
      `/elasticsearch/indices/${indexName}/fields`
    );
    return response.data;
  }

  async elasticsearchHealth(): Promise<any> {
    const response = await this.client.get('/elasticsearch/health');
    return response.data;
  }

  // ========== Conversations ==========

  async createConversation(data: {
    title: string;
    index: string;
    server_id?: string;
    created_by?: string;
  }): Promise<any> {
    const response = await this.client.post('/conversations', data);
    return response.data;
  }

  async listConversations(params?: {
    skip?: number;
    limit?: number;
    index?: string;
    created_by?: string;
  }): Promise<any[]> {
    const response = await this.client.get('/conversations', { params });
    return response.data;
  }

  async getConversation(conversationId: string): Promise<any> {
    const response = await this.client.get(`/conversations/${conversationId}`);
    return response.data;
  }

  async updateConversation(conversationId: string, data: { title?: string }): Promise<any> {
    const response = await this.client.patch(`/conversations/${conversationId}`, data);
    return response.data;
  }

  async addMessageToConversation(
    conversationId: string,
    data: {
      role: string;
      content: string;
      widget?: any;
    }
  ): Promise<any> {
    const response = await this.client.post(`/conversations/${conversationId}/messages`, data);
    return response.data;
  }

  async deleteConversation(conversationId: string): Promise<void> {
    await this.client.delete(`/conversations/${conversationId}`);
  }

  // ========== Downloads ==========
  async listDownloads(): Promise<any[]> {
    const response = await this.client.get('/downloads');
    return response.data;
  }

  async downloadFile(downloadId: string): Promise<Blob> {
    const response = await this.client.get(`/downloads/${downloadId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  async deleteDownload(downloadId: string): Promise<void> {
    await this.client.delete(`/downloads/${downloadId}`);
  }

  // ========== CSV Upload ==========
  async uploadCSV(formData: FormData): Promise<any> {
    const response = await this.client.post('/csv-upload/', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  // ========== Index Access Management ==========
  async listUserIndexAccess(userId: string): Promise<any[]> {
    const response = await this.client.get(`/index-access/user/${userId}`);
    return response.data;
  }

  async createIndexAccess(data: {
    user_id: string;
    es_server_id: string;
    index_name: string;
    can_read?: boolean;
    can_write?: boolean;
    can_create?: boolean;
  }): Promise<any> {
    const response = await this.client.post('/index-access/', data);
    return response.data;
  }

  async updateIndexAccess(accessId: string, data: {
    can_read?: boolean;
    can_write?: boolean;
    can_create?: boolean;
  }): Promise<any> {
    const response = await this.client.patch(`/index-access/${accessId}`, data);
    return response.data;
  }

  async deleteIndexAccess(accessId: string): Promise<void> {
    await this.client.delete(`/index-access/${accessId}`);
  }

  // ========== Generic HTTP methods ==========
  // Para uso direto quando não há método específico

  async get<T = any>(url: string, config?: any): Promise<{ data: T }> {
    return await this.client.get<T>(url, config);
  }

  async post<T = any>(url: string, data?: any, config?: any): Promise<{ data: T }> {
    return await this.client.post<T>(url, data, config);
  }

  async patch<T = any>(url: string, data?: any, config?: any): Promise<{ data: T }> {
    return await this.client.patch<T>(url, data, config);
  }

  async delete<T = any>(url: string, config?: any): Promise<{ data: T }> {
    return await this.client.delete<T>(url, config);
  }
}

// Export singleton instance
export const api = new ApiService();
