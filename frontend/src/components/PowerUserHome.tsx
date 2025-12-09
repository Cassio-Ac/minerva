/**
 * PowerUserHome Component
 * Home page para power users e operators com acesso aos módulos de inteligência
 */

import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useSettingsStore } from '@stores/settingsStore';
import { useAuthStore } from '@stores/authStore';
import { API_URL } from '../config/api';

interface Conversation {
  id: string;
  title: string;
  created_at: string;
  message_count: number;
}

export const PowerUserHome: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const { token, user } = useAuthStore();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Buscar conversas recentes
        const convResponse = await fetch(`${API_URL}/conversations?limit=5`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (convResponse.ok) {
          const convData = await convResponse.json();
          setConversations(convData);
        }
      } catch (error) {
        console.error('Error fetching data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [token]);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m atrás`;
    if (diffHours < 24) return `${diffHours}h atrás`;
    if (diffDays < 7) return `${diffDays}d atrás`;
    return date.toLocaleDateString('pt-BR');
  };

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
              🧠 Minerva Intelligence
            </h1>
            <p className="text-lg" style={{ color: currentColors.text.secondary }}>
              Bem-vindo, {user?.full_name || user?.username} · {user?.role === 'operator' ? 'Operador' : 'Power User'}
            </p>
          </div>
          <div className="text-6xl">
            ⚡
          </div>
        </div>
      </div>

      {/* Módulos de Inteligência */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <h2 className="text-2xl font-bold mb-6" style={{ color: currentColors.text.primary }}>
          🎯 Módulos de Inteligência
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Link
            to="/rss"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">📡</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              RSS Intelligence
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              800+ artigos, 38 fontes, chat RAG
            </p>
          </Link>

          <Link
            to="/telegram"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">💬</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Telegram Intelligence
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              150+ grupos, busca, análise temporal
            </p>
          </Link>

          <Link
            to="/cve"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">🔒</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              CVE Intelligence
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Tracking de vulnerabilidades
            </p>
          </Link>

          <Link
            to="/breaches"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">🚨</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Data Breaches
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Análise de vazamentos de dados
            </p>
          </Link>
        </div>
      </div>

      {/* Ferramentas e Ações */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <h2 className="text-2xl font-bold mb-6" style={{ color: currentColors.text.primary }}>
          🛠️ Ferramentas
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Link
            to="/chat"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">🤖</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Chat com IA
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Análise e insights com LLM
            </p>
          </Link>

          <Link
            to="/knowledge"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">📚</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Knowledge Base
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Documentos e chunks para RAG
            </p>
          </Link>

          <Link
            to="/dashboards"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">📊</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Dashboards
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Visualizações personalizadas
            </p>
          </Link>

          <Link
            to="/downloads"
            className="rounded-xl p-6 border hover:shadow-lg transition-all"
            style={{
              backgroundColor: currentColors.bg.tertiary,
              borderColor: currentColors.border.default
            }}
          >
            <div className="text-4xl mb-3">📥</div>
            <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
              Downloads
            </h3>
            <p className="text-sm" style={{ color: currentColors.text.muted }}>
              Arquivos exportados
            </p>
          </Link>
        </div>
      </div>

      {/* Atividade Recente */}
      <div className="rounded-2xl shadow-xl p-8" style={{
        backgroundColor: currentColors.bg.primary
      }}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
            💬 Conversas com IA Recentes
          </h2>
          <Link
            to="/chat"
            className="text-sm hover:underline"
            style={{ color: currentColors.accent.primary }}
          >
            Ver todas
          </Link>
        </div>

        {loading ? (
          <div className="text-center py-8" style={{ color: currentColors.text.muted }}>
            Carregando...
          </div>
        ) : conversations.length === 0 ? (
          <div className="text-center py-8" style={{ color: currentColors.text.muted }}>
            <div className="text-4xl mb-3">📭</div>
            <p className="mb-4">Nenhuma conversa ainda</p>
            <Link
              to="/chat"
              className="inline-block px-6 py-3 rounded-lg font-medium"
              style={{
                backgroundColor: currentColors.accent.primary,
                color: currentColors.text.inverse
              }}
            >
              Iniciar nova conversa
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {conversations.map((conv) => (
              <Link
                key={conv.id}
                to={`/chat?conversation=${conv.id}`}
                className="block rounded-lg p-5 border hover:shadow-md transition-all"
                style={{
                  backgroundColor: currentColors.bg.tertiary,
                  borderColor: currentColors.border.default
                }}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="font-semibold mb-2" style={{ color: currentColors.text.primary }}>
                      {conv.title || 'Sem título'}
                    </h3>
                    <p className="text-sm" style={{ color: currentColors.text.muted }}>
                      {conv.message_count} mensagens · {formatDate(conv.created_at)}
                    </p>
                  </div>
                  <div className="text-2xl ml-4">💬</div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
