/**
 * DownloadsPage - Listagem e download de arquivos gerados
 * Sistema seguro com controle de acesso por ownership
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useAuthStore } from '@stores/authStore';
import { useSettingsStore } from '@stores/settingsStore';

interface Download {
  id: string;
  filename: string;
  original_name: string;
  file_type: string;
  file_size: number;
  description: string | null;
  dashboard_id: string | null;
  download_count: number;
  created_at: string;
  expires_at: string | null;
  user_id: string;
}

export const DownloadsPage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const { currentColors } = useSettingsStore();

  const [downloads, setDownloads] = useState<Download[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDownloads();
  }, []);

  const loadDownloads = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await api.listDownloads();
      setDownloads(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Erro ao carregar downloads');
      console.error('Error loading downloads:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownload = async (download: Download) => {
    try {
      const blob = await api.downloadFile(download.id);

      // Criar URL temporária para download
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = download.original_name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      // Recarregar lista para atualizar contador
      await loadDownloads();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao baixar arquivo');
      console.error('Error downloading file:', err);
    }
  };

  const handleDelete = async (download: Download) => {
    if (!confirm(`Tem certeza que deseja deletar "${download.original_name}"?`)) {
      return;
    }

    try {
      await api.deleteDownload(download.id);
      await loadDownloads();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao deletar arquivo');
      console.error('Error deleting download:', err);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleString('pt-BR');
  };

  const getFileIcon = (fileType: string): string => {
    switch (fileType) {
      case 'html':
        return '🌐';
      case 'pdf':
        return '📄';
      case 'png':
      case 'jpg':
      case 'jpeg':
        return '🖼️';
      default:
        return '📁';
    }
  };

  if (isLoading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: currentColors.bg.secondary }}
      >
        <div style={{ color: currentColors.text.primary }}>Carregando downloads...</div>
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
                  Downloads
                </h1>
                <p className="text-sm" style={{ color: currentColors.text.muted }}>
                  Arquivos gerados e disponíveis para download
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {user?.can_upload_csv && (
                <button
                  onClick={() => navigate('/csv-upload')}
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
                  📤 Upload CSV
                </button>
              )}

              <button
                onClick={loadDownloads}
                className="px-4 py-2 rounded-lg transition-colors"
                style={{
                  backgroundColor: currentColors.accent.primary,
                  color: currentColors.text.inverse,
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                }}
              >
                🔄 Atualizar
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {error && (
          <div
            className="rounded-lg p-4 mb-6 border"
            style={{
              backgroundColor: currentColors.accent.error + '20',
              borderColor: currentColors.accent.error,
              color: currentColors.accent.error,
            }}
          >
            {error}
          </div>
        )}

        {downloads.length === 0 ? (
          <div
            className="rounded-lg p-12 border text-center"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderColor: currentColors.border.default,
            }}
          >
            <div className="text-6xl mb-4">📭</div>
            <h3 className="text-xl font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Nenhum arquivo disponível
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Arquivos gerados pelo sistema aparecerão aqui para download.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {downloads.map((download) => (
              <div
                key={download.id}
                className="rounded-lg p-4 border"
                style={{
                  backgroundColor: currentColors.bg.primary,
                  borderColor: currentColors.border.default,
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    <div className="text-3xl">{getFileIcon(download.file_type)}</div>

                    <div className="flex-1">
                      <h3
                        className="text-lg font-semibold"
                        style={{ color: currentColors.text.primary }}
                      >
                        {download.original_name}
                      </h3>

                      <div className="flex items-center gap-4 mt-1 text-sm" style={{ color: currentColors.text.muted }}>
                        <span>{formatFileSize(download.file_size)}</span>
                        <span>•</span>
                        <span>{download.file_type.toUpperCase()}</span>
                        <span>•</span>
                        <span>{formatDate(download.created_at)}</span>
                        <span>•</span>
                        <span>{download.download_count} download(s)</span>
                      </div>

                      {download.description && (
                        <p className="mt-2 text-sm" style={{ color: currentColors.text.secondary }}>
                          {download.description}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDownload(download)}
                      className="px-4 py-2 rounded-lg transition-colors"
                      style={{
                        backgroundColor: currentColors.accent.primary,
                        color: currentColors.text.inverse,
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = currentColors.accent.primaryHover;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = currentColors.accent.primary;
                      }}
                    >
                      ⬇️ Baixar
                    </button>

                    {(user?.can_configure_system || download.user_id === user?.id) && (
                      <button
                        onClick={() => handleDelete(download)}
                        className="px-4 py-2 rounded-lg transition-colors"
                        style={{
                          backgroundColor: 'transparent',
                          color: currentColors.accent.error,
                          border: `1px solid ${currentColors.accent.error}`,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = currentColors.accent.error + '15';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = 'transparent';
                        }}
                      >
                        🗑️ Deletar
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
