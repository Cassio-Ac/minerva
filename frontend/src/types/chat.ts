/**
 * Chat Types
 */

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp?: string;
}

export interface TimeRange {
  type: 'preset' | 'custom';
  preset?: string;
  from?: string;
  to?: string;
  label: string;
}

export interface ChatRequest {
  message: string;
  index: string;
  server_id?: string;
  time_range?: TimeRange;
  context?: ChatMessage[];
}

export interface ChatResponse {
  explanation: string;
  visualization_type?: string;
  query?: Record<string, any>;
  needs_clarification: boolean;
  widget?: Record<string, any>;
}
