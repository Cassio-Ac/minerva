/**
 * Widget Types
 * TypeScript types matching backend Pydantic models
 */

import type { TimeRange } from './chat';

export type VisualizationType = 'pie' | 'bar' | 'line' | 'metric' | 'table' | 'area' | 'scatter';

export interface WidgetPosition {
  x: number;      // Grid column
  y: number;      // Grid row
  w: number;      // Width (grid units)
  h: number;      // Height (grid units)
}

export interface WidgetData {
  query: Record<string, any>;           // Elasticsearch query
  results?: Record<string, any>;        // Cached results
  config?: Record<string, any>;         // Plotly config
  last_updated?: string;                // Last execution timestamp
}

export interface WidgetMetadata {
  created_at: string;
  updated_at: string;
  created_by?: string;
  version: number;
}

export interface Widget {
  id: string;
  title: string;
  type: VisualizationType;
  position: WidgetPosition;
  data: WidgetData;
  index?: string;  // Elasticsearch index for this widget
  fixedTimeRange?: TimeRange;  // Fixed time range (overrides global timeRange)
  metadata: WidgetMetadata;
}

// Create/Update schemas
export interface WidgetCreate {
  title: string;
  type: VisualizationType;
  position: WidgetPosition;
  data: WidgetData;
}

export interface WidgetUpdate {
  title?: string;
  type?: VisualizationType;
  position?: WidgetPosition;
  data?: WidgetData;
  fixedTimeRange?: TimeRange;  // Allow setting or clearing fixed time range
}
