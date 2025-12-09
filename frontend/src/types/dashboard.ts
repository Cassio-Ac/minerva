/**
 * Dashboard Types
 * TypeScript types matching backend Pydantic models
 */

import { Widget } from './widget';

export interface DashboardLayout {
  cols: number;         // Number of columns (default: 12)
  row_height: number;   // Row height in pixels (default: 30)
  width: number;        // Total width in pixels (default: 1600)
}

export interface DashboardMetadata {
  created_at: string;
  updated_at: string;
  created_by?: string;
  is_public: boolean;
  tags: string[];
  version: number;
}

export interface Dashboard {
  id: string;
  title: string;
  description?: string;
  layout: DashboardLayout;
  widgets: Widget[];
  index: string;          // Elasticsearch index
  metadata: DashboardMetadata;
}

export interface DashboardListItem {
  id: string;
  title: string;
  description?: string;
  index: string;
  widget_count: number;
  created_at: string;
  updated_at: string;
  tags: string[];
}

// Create/Update schemas
export interface DashboardCreate {
  title: string;
  description?: string;
  index: string;
  layout?: DashboardLayout;
  widgets?: Widget[];
  tags?: string[];
}

export interface DashboardUpdate {
  title?: string;
  description?: string;
  layout?: DashboardLayout;
  widgets?: Widget[];
  tags?: string[];
}
