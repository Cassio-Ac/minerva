/**
 * CSVUploadPage - Upload de arquivos CSV para índices do Elasticsearch
 * Disponível para usuários POWER e OPERATOR
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useAuthStore } from '@stores/authStore';
import { useSettingsStore } from '@stores/settingsStore';

interface ESServer {
  id: string;
  name: string;
  description: string;
  is_active: boolean;
}

interface UploadResult {
  success: boolean;
  message: string;
  index_name: string;
  documents_processed: number;
  documents_indexed: number;
  created_index: boolean;
  errors: string[];
  mapping?: any;
}

export const CSVUploadPage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const { currentColors } = useSettingsStore();

  const [servers, setServers] = useState<ESServer[]>([]);
  const [selectedServer, setSelectedServer] = useState<string>('');
  const [indexName, setIndexName] = useState<string>('');
  const [file, setFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingServers, setIsLoadingServers] = useState(true);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Verificar se usuário tem permissão
  if (!user?.can_upload_csv) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: currentColors.bg.secondary }}
      >
        <div
          className="rounded-lg p-8 border text-center max-w-md"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <div className="text-6xl mb-4">🚫</div>
          <h2 className="text-2xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
            Acesso Negado
          </h2>
          <p className="text-sm mb-6" style={{ color: currentColors.text.muted }}>
            Você não tem permissão para fazer upload de arquivos CSV.
          </p>
          <button
            onClick={() => navigate('/')}
            className="px-4 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
          >
            Voltar ao Menu
          </button>
        </div>
      </div>
    );
  }

  useEffect(() => {
    loadServers();
  }, []);

  const loadServers = async () => {
    try {
      setIsLoadingServers(true);
      const data = await api.getESServers();
      const activeServers = data.filter((s: ESServer) => s.is_active);
      setServers(activeServers);
      if (activeServers.length > 0) {
        setSelectedServer(activeServers[0].id);
      }
    } catch (err: any) {
      console.error('Error loading servers:', err);
      setError('Erro ao carregar servidores Elasticsearch');
    } finally {
      setIsLoadingServers(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.name.endsWith('.csv')) {
        setError('Por favor, selecione um arquivo CSV (.csv)');
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setError(null);
      setResult(null);
    }
  };

  const handleUpload = async () => {
    if (!file || !selectedServer || !indexName.trim()) {
      setError('Por favor, preencha todos os campos');
      return;
    }

    try {
      setIsLoading(true);
      setError(null);
      setResult(null);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('index_name', indexName.trim());
      formData.append('es_server_id', selectedServer);

      const response = await api.uploadCSV(formData);
      setResult(response);

      // Limpar formulário em caso de sucesso
      if (response.success) {
        setFile(null);
        setIndexName('');
        const fileInput = document.getElementById('csv-file-input') as HTMLInputElement;
        if (fileInput) fileInput.value = '';
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Erro ao fazer upload do arquivo');
      console.error('Error uploading CSV:', err);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoadingServers) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: currentColors.bg.secondary }}
      >
        <div style={{ color: currentColors.text.primary }}>Carregando servidores...</div>
      </div>
    );
  }

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{
        backgroundColor: currentColors.bg.secondary,
        color: currentColors.text.primary,
      }}
    >
      {/* Header */}
      <header
        className="border-b"
        style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default,
        }}
      >
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate('/')}
                className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
                style={{ color: currentColors.text.secondary }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                }}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M10 19l-7-7m0 0l7-7m-7 7h18"
                  />
                </svg>
                <span className="font-medium">Menu</span>
              </button>

              <div
                className="h-8 w-px"
                style={{ backgroundColor: currentColors.border.default }}
              ></div>

              <div>
                <h1 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                  Upload CSV
                </h1>
                <p className="text-sm" style={{ color: currentColors.text.muted }}>
                  Importar dados de arquivo CSV para o Elasticsearch
                </p>
              </div>
            </div>

            <button
              onClick={() => navigate('/downloads')}
              className="px-4 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: 'transparent',
                color: currentColors.text.secondary,
                border: `1px solid ${currentColors.border.default}`,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              📥 Downloads
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 max-w-4xl w-full mx-auto px-6 py-8">
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <h2 className="text-xl font-semibold mb-6" style={{ color: currentColors.text.primary }}>
            Configurações do Upload
          </h2>

          {/* Servidor Elasticsearch */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
              Servidor Elasticsearch
            </label>
            <select
              value={selectedServer}
              onChange={(e) => setSelectedServer(e.target.value)}
              disabled={isLoading}
              className="w-full px-4 py-2 rounded-lg border transition-colors"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary,
              }}
            >
              {servers.map((server) => (
                <option key={server.id} value={server.id}>
                  {server.name} {server.description && `- ${server.description}`}
                </option>
              ))}
            </select>
          </div>

          {/* Nome do Índice */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
              Nome do Índice
            </label>
            <input
              type="text"
              value={indexName}
              onChange={(e) => setIndexName(e.target.value)}
              disabled={isLoading}
              placeholder="Ex: meus_dados, vendas_2024, logs_sistema"
              className="w-full px-4 py-2 rounded-lg border transition-colors"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary,
              }}
            />
            <p className="text-xs mt-1" style={{ color: currentColors.text.muted }}>
              Se o índice não existir, será criado automaticamente. Se existir, os dados serão validados e adicionados.
            </p>
          </div>

          {/* Arquivo CSV */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2" style={{ color: currentColors.text.primary }}>
              Arquivo CSV
            </label>
            <input
              id="csv-file-input"
              type="file"
              accept=".csv"
              onChange={handleFileChange}
              disabled={isLoading}
              className="w-full px-4 py-2 rounded-lg border transition-colors"
              style={{
                backgroundColor: currentColors.bg.secondary,
                borderColor: currentColors.border.default,
                color: currentColors.text.primary,
              }}
            />
            {file && (
              <p className="text-sm mt-2" style={{ color: currentColors.text.secondary }}>
                📄 {file.name} ({(file.size / 1024).toFixed(2)} KB)
              </p>
            )}
          </div>

          {/* Botão Upload */}
          <button
            onClick={handleUpload}
            disabled={!file || !selectedServer || !indexName.trim() || isLoading}
            className="w-full px-6 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              backgroundColor: currentColors.accent.primary,
              color: currentColors.text.inverse,
            }}
            onMouseEnter={(e) => {
              if (!isLoading && file && selectedServer && indexName.trim()) {
                e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.accent.primary;
            }}
          >
            {isLoading ? '⏳ Enviando...' : '📤 Fazer Upload'}
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div
            className="mt-6 rounded-lg p-4 border"
            style={{
              backgroundColor: currentColors.accent.error + '20',
              borderColor: currentColors.accent.error,
              color: currentColors.accent.error,
            }}
          >
            <div className="flex items-start gap-3">
              <span className="text-xl">❌</span>
              <div className="flex-1">
                <h3 className="font-semibold mb-1">Erro no Upload</h3>
                <p className="text-sm">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Success Result */}
        {result && result.success && (
          <div
            className="mt-6 rounded-lg p-4 border"
            style={{
              backgroundColor: currentColors.accent.success + '20',
              borderColor: currentColors.accent.success,
              color: currentColors.accent.success,
            }}
          >
            <div className="flex items-start gap-3">
              <span className="text-xl">✅</span>
              <div className="flex-1">
                <h3 className="font-semibold mb-2">Upload Concluído com Sucesso!</h3>
                <div className="text-sm space-y-1" style={{ color: currentColors.text.primary }}>
                  <p>📊 <strong>Índice:</strong> {result.index_name}</p>
                  <p>📄 <strong>Documentos processados:</strong> {result.documents_processed}</p>
                  <p>✅ <strong>Documentos indexados:</strong> {result.documents_indexed}</p>
                  <p>
                    {result.created_index ? (
                      <>🆕 <strong>Índice criado</strong> (primeira vez)</>
                    ) : (
                      <>📝 <strong>Dados adicionados ao índice existente</strong></>
                    )}
                  </p>
                </div>
                {result.errors && result.errors.length > 0 && (
                  <div className="mt-3">
                    <p className="font-semibold text-sm" style={{ color: currentColors.accent.warning }}>
                      ⚠️ Avisos:
                    </p>
                    <ul className="list-disc list-inside text-xs mt-1" style={{ color: currentColors.text.muted }}>
                      {result.errors.map((err, idx) => (
                        <li key={idx}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Info Box */}
        <div
          className="mt-8 rounded-lg p-4 border"
          style={{
            backgroundColor: currentColors.bg.primary,
            borderColor: currentColors.border.default,
          }}
        >
          <h3 className="font-semibold mb-3" style={{ color: currentColors.text.primary }}>
            ℹ️ Informações sobre Upload de CSV
          </h3>
          <ul className="space-y-2 text-sm" style={{ color: currentColors.text.secondary }}>
            <li>• O arquivo deve estar no formato CSV com cabeçalho na primeira linha</li>
            <li>• Os tipos de dados são detectados automaticamente (texto, número, data, etc.)</li>
            <li>• Se o índice não existir, será criado com mapeamento automático</li>
            <li>• Se o índice existir, o CSV deve ter os mesmos campos</li>
            <li>• Campos adicionais são automaticamente adicionados: _upload_timestamp e _uploaded_by</li>
            {user?.has_index_restrictions && (
              <li className="font-semibold" style={{ color: currentColors.accent.warning }}>
                ⚠️ Você tem restrições de acesso. Só pode fazer upload para índices autorizados.
              </li>
            )}
          </ul>
        </div>
      </div>
    </div>
  );
};
