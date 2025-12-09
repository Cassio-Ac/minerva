import React, { useState } from 'react';
import { Clock, ExternalLink, Tag, X, Sparkles, Users, Shield } from 'lucide-react';
import { useSettingsStore } from '@stores/settingsStore';

interface Article {
  content_hash: string;
  title: string;
  summary: string;
  link: string;
  published: string;
  feed_name: string;
  category: string;
  tags?: string[];
  author?: string;
  // Malpedia enrichment fields
  enriched_summary?: string;
  actors_mentioned?: string[];
  families_mentioned?: string[];
  enriched_at?: string;
}

interface NewsGridProps {
  articles: Article[];
}

const NewsGrid: React.FC<NewsGridProps> = ({ articles }) => {
  const { currentColors } = useSettingsStore();
  const [selectedArticle, setSelectedArticle] = useState<Article | null>(null);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m atrás`;
    if (diffHours < 24) return `${diffHours}h atrás`;
    if (diffDays < 7) return `${diffDays}d atrás`;

    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: 'short',
      year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      'AI': 'bg-purple-600 text-white',
      'Cybersecurity': 'bg-red-600 text-white',
      'Threat Intel': 'bg-orange-600 text-white',
      'Vendors/Research': 'bg-blue-600 text-white',
    };
    return colors[category] || 'bg-gray-600 text-white';
  };

  // Strip HTML tags and decode entities
  const cleanText = (html: string) => {
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || '';
  };

  if (articles.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-12"
        style={{ color: currentColors.text.secondary }}
      >
        <Tag size={48} className="mb-4 opacity-50" />
        <p className="text-lg">Nenhuma notícia encontrada</p>
        <p className="text-sm mt-2">Tente ajustar os filtros</p>
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 pb-8">
        {articles.map((article) => (
          <div
            key={article.content_hash}
            className="rounded-lg shadow-md hover:shadow-lg transition-all duration-200 cursor-pointer overflow-hidden group"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderWidth: '1px',
              borderStyle: 'solid',
              borderColor: currentColors.border.default,
            }}
            onClick={() => setSelectedArticle(article)}
          >
            {/* Header with category badge */}
            <div
              className="p-4"
              style={{
                borderBottomWidth: '1px',
                borderBottomStyle: 'solid',
                borderBottomColor: currentColors.border.default,
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className={`px-2 py-1 text-xs font-semibold rounded ${getCategoryColor(article.category)}`}>
                  {article.category}
                </span>
                <div
                  className="flex items-center text-xs"
                  style={{ color: currentColors.text.secondary }}
                >
                  <Clock size={12} className="mr-1" />
                  {formatDate(article.published)}
                </div>
              </div>
              <h3
                className="font-semibold text-base line-clamp-2 group-hover:text-blue-500 transition-colors"
                style={{ color: currentColors.text.primary }}
              >
                {cleanText(article.title)}
              </h3>
            </div>

            {/* Content */}
            <div className="p-4">
              {/* Enrichment indicator */}
              {article.enriched_at && (
                <div className="flex items-center gap-1 text-xs mb-2 text-purple-600">
                  <Sparkles size={12} />
                  <span className="font-semibold">AI Enriquecido</span>
                </div>
              )}

              <p
                className="text-sm line-clamp-3 mb-4"
                style={{ color: currentColors.text.secondary }}
              >
                {cleanText(article.enriched_summary || article.summary)}
              </p>

              {/* Malpedia enrichment badges */}
              {(article.actors_mentioned && article.actors_mentioned.length > 0) ||
               (article.families_mentioned && article.families_mentioned.length > 0) ? (
                <div className="mb-3 space-y-2">
                  {article.actors_mentioned && article.actors_mentioned.length > 0 && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <div className="flex items-center gap-1 text-xs text-red-600">
                        <Users size={12} />
                        <span className="font-semibold">Atores:</span>
                      </div>
                      {article.actors_mentioned.slice(0, 2).map((actor, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 text-xs rounded bg-red-100 text-red-800 font-medium"
                        >
                          {actor}
                        </span>
                      ))}
                      {article.actors_mentioned.length > 2 && (
                        <span className="text-xs text-red-600">
                          +{article.actors_mentioned.length - 2}
                        </span>
                      )}
                    </div>
                  )}

                  {article.families_mentioned && article.families_mentioned.length > 0 && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <div className="flex items-center gap-1 text-xs text-orange-600">
                        <Shield size={12} />
                        <span className="font-semibold">Malware:</span>
                      </div>
                      {article.families_mentioned.slice(0, 2).map((family, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 text-xs rounded bg-orange-100 text-orange-800 font-medium"
                        >
                          {family}
                        </span>
                      ))}
                      {article.families_mentioned.length > 2 && (
                        <span className="text-xs text-orange-600">
                          +{article.families_mentioned.length - 2}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ) : null}

              {/* Footer */}
              <div className="flex items-center justify-between text-xs">
                <span
                  className="font-medium truncate flex-1"
                  style={{ color: currentColors.text.secondary }}
                >
                  {article.feed_name}
                </span>
                <a
                  href={article.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="flex items-center text-blue-500 hover:underline ml-2"
                >
                  <ExternalLink size={14} className="mr-1" />
                  Abrir
                </a>
              </div>

              {/* Tags */}
              {article.tags && article.tags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {article.tags.slice(0, 3).map((tag, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 text-xs rounded"
                      style={{
                        backgroundColor: currentColors.bg.secondary,
                        color: currentColors.text.secondary,
                      }}
                    >
                      {tag}
                    </span>
                  ))}
                  {article.tags.length > 3 && (
                    <span
                      className="px-2 py-0.5 text-xs"
                      style={{ color: currentColors.text.secondary }}
                    >
                      +{article.tags.length - 3}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Article Detail Modal */}
      {selectedArticle && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedArticle(null)}
        >
          <div
            className="rounded-lg shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col"
            style={{
              backgroundColor: currentColors.bg.primary,
              borderWidth: '1px',
              borderStyle: 'solid',
              borderColor: currentColors.border.default,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div
              className="p-6 flex items-start justify-between"
              style={{
                borderBottomWidth: '1px',
                borderBottomStyle: 'solid',
                borderBottomColor: currentColors.border.default,
              }}
            >
              <div className="flex-1 pr-4">
                <span className={`px-2 py-1 text-xs font-semibold rounded ${getCategoryColor(selectedArticle.category)}`}>
                  {selectedArticle.category}
                </span>
                <h2
                  className="text-2xl font-bold mt-3"
                  style={{ color: currentColors.text.primary }}
                >
                  {cleanText(selectedArticle.title)}
                </h2>
                <div
                  className="flex items-center gap-4 mt-2 text-sm"
                  style={{ color: currentColors.text.secondary }}
                >
                  <span>{selectedArticle.feed_name}</span>
                  <span>•</span>
                  <span>{formatDate(selectedArticle.published)}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedArticle(null)}
                className="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                style={{ color: currentColors.text.secondary }}
              >
                <X size={24} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto flex-1">
              {/* Enrichment indicator */}
              {selectedArticle.enriched_at && (
                <div className="flex items-center gap-2 text-sm mb-4 px-3 py-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                  <Sparkles size={16} className="text-purple-600" />
                  <span className="font-semibold text-purple-900 dark:text-purple-300">
                    Conteúdo enriquecido com IA
                  </span>
                </div>
              )}

              <p
                className="text-base leading-relaxed whitespace-pre-wrap"
                style={{ color: currentColors.text.primary }}
              >
                {cleanText(selectedArticle.enriched_summary || selectedArticle.summary)}
              </p>

              {/* Malpedia enrichment sections */}
              {selectedArticle.actors_mentioned && selectedArticle.actors_mentioned.length > 0 && (
                <div className="mt-6">
                  <div className="flex items-center gap-2 mb-3">
                    <Users size={16} className="text-red-600" />
                    <h3 className="text-sm font-semibold text-red-900 dark:text-red-300">
                      Atores de Ameaça Mencionados
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedArticle.actors_mentioned.map((actor, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1.5 text-sm rounded bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-300 font-medium"
                      >
                        {actor}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedArticle.families_mentioned && selectedArticle.families_mentioned.length > 0 && (
                <div className="mt-6">
                  <div className="flex items-center gap-2 mb-3">
                    <Shield size={16} className="text-orange-600" />
                    <h3 className="text-sm font-semibold text-orange-900 dark:text-orange-300">
                      Famílias de Malware Mencionadas
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedArticle.families_mentioned.map((family, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1.5 text-sm rounded bg-orange-100 dark:bg-orange-900/20 text-orange-800 dark:text-orange-300 font-medium"
                      >
                        {family}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedArticle.tags && selectedArticle.tags.length > 0 && (
                <div className="mt-6">
                  <h3
                    className="text-sm font-semibold mb-2"
                    style={{ color: currentColors.text.secondary }}
                  >
                    Tags:
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedArticle.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 text-sm rounded"
                        style={{
                          backgroundColor: currentColors.bg.secondary,
                          color: currentColors.text.secondary,
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div
              className="p-6"
              style={{
                borderTopWidth: '1px',
                borderTopStyle: 'solid',
                borderTopColor: currentColors.border.default,
              }}
            >
              <a
                href={selectedArticle.link}
                target="_blank"
                rel="noopener noreferrer"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
              >
                <ExternalLink size={20} />
                Ler artigo completo no site original
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default NewsGrid;
