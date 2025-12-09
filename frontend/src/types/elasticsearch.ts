/**
 * Elasticsearch Server Types
 * TypeScript types matching backend Pydantic models
 */

export interface ESServerConnection {
  url: string;
  username?: string | null;
  password?: string | null;
  verify_ssl: boolean;
  timeout: number;
}

export interface ESServerMetadata {
  created_at: string;
  updated_at: string;
  last_test?: string | null;
  last_test_status?: 'success' | 'failed' | 'pending' | null;
  last_error?: string | null;
  version?: string | null;
}

export interface ESServerStats {
  total_indices: number;
  total_documents: number;
  cluster_health?: 'green' | 'yellow' | 'red' | null;
  cluster_name?: string | null;
  node_count: number;
}

export interface ElasticsearchServer {
  id: string;
  name: string;
  description?: string | null;
  connection: ESServerConnection;
  metadata: ESServerMetadata;
  stats: ESServerStats;
  is_active: boolean;
  is_default: boolean;
}

export interface ESServerCreate {
  name: string;
  description?: string | null;
  connection: ESServerConnection;
  is_default?: boolean;
}

export interface ESServerUpdate {
  name?: string;
  description?: string | null;
  connection?: ESServerConnection;
  is_active?: boolean;
  is_default?: boolean;
}

export interface ESServerTestResult {
  success: boolean;
  message: string;
  version?: string | null;
  cluster_name?: string | null;
  cluster_health?: 'green' | 'yellow' | 'red' | null;
  node_count?: number | null;
  error?: string | null;
}

export interface ESIndexInfo {
  name: string;
  doc_count: number;
  size_in_bytes: number;
  health?: 'green' | 'yellow' | 'red' | null;
  status?: 'open' | 'close' | null;
  primary_shards: number;
  replica_shards: number;
}
