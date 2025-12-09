/**
 * useLLMProvider Hook
 * Hook para buscar informações do provedor LLM padrão
 */

import { useState, useEffect } from 'react';
import axios from 'axios';
import { API_URL } from '../config/api';

interface LLMProvider {
  id: string;
  name: string;
  provider_type: 'anthropic' | 'openai' | 'databricks';
  model_name: string;
  is_default: boolean;
}

export const useLLMProvider = () => {
  const [provider, setProvider] = useState<LLMProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDefaultProvider = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get(`${API_URL}/llm-providers`);
      const providers = response.data as LLMProvider[];

      // Buscar o provedor padrão
      const defaultProvider = providers.find((p) => p.is_default);
      setProvider(defaultProvider || null);
    } catch (err: any) {
      console.error('Error loading LLM provider:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDefaultProvider();
  }, []);

  return {
    provider,
    loading,
    error,
    refresh: loadDefaultProvider,
  };
};
