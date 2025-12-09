/**
 * API Configuration
 * Centralized API URL configuration
 */

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8002';
export const API_URL = `${API_BASE_URL}/api/v1`;
