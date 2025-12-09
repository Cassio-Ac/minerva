import React, { useState, useEffect } from 'react';
import { useSettingsStore } from '../stores/settingsStore';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { API_URL, API_BASE_URL } from '../config/api';
import {
  BookOpen,
  Plus,
  Edit2,
  Trash2,
  Search,
  Tag,
  AlertCircle,
  Eye,
  EyeOff
} from 'lucide-react';

interface KnowledgeDoc {
  id: string;
  title: string;
  content: string;
  category: string | null;
  tags: string[];
  related_indices: string[];
  priority: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export const KnowledgeBase: React.FC = () => {
  const { currentColors } = useSettingsStore();
  const [knowledgeDocs, setKnowledgeDocs] = useState<KnowledgeDoc[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddDocForm, setShowAddDocForm] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/knowledge-docs/`);
      const data = await response.json();
      setKnowledgeDocs(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const deleteKnowledgeDoc = async (id: string) => {
    if (!confirm('Are you sure you want to delete this document?')) return;

    try {
      await fetch(`${API_URL}/knowledge-docs/${id}`, {
        method: 'DELETE'
      });
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete');
    }
  };

  const createKnowledgeDoc = async (docData: any) => {
    try {
      const response = await fetch(`${API_URL}/knowledge-docs/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(docData)
      });

      if (!response.ok) {
        throw new Error('Failed to create document');
      }

      await loadData();
      setShowAddDocForm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create document');
    }
  };

  const filteredDocs = knowledgeDocs.filter(doc =>
    doc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    doc.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
    doc.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div style={{ padding: '20px' }}>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{
          margin: 0,
          marginBottom: '8px',
          color: currentColors.text,
          fontSize: '24px',
          fontWeight: 600
        }}>
          Knowledge Base
        </h2>
        <p style={{
          margin: 0,
          color: currentColors.textSecondary,
          fontSize: '14px'
        }}>
          Crie documentos que ajudam a IA a entender melhor seus dados do Elasticsearch
        </p>
      </div>

      {/* Search Bar and Actions */}
      <div style={{ marginBottom: '20px', display: 'flex', gap: '12px', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search
            size={16}
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: currentColors.text?.muted || currentColors.textSecondary
            }}
          />
          <input
            type="text"
            placeholder="Buscar documentos..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px 10px 40px',
              background: currentColors.bg?.secondary || currentColors.cardBg || '#f3f4f6',
              border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
              borderRadius: '6px',
              color: currentColors.text?.primary || currentColors.text || '#111827',
              fontSize: '14px'
            }}
          />
        </div>

        <button
          onClick={() => setShowAddDocForm(true)}
          style={{
            padding: '10px 16px',
            background: '#3b82f6',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: 500,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            whiteSpace: 'nowrap'
          }}
        >
          <Plus size={16} />
          Novo Documento
        </button>
      </div>

      {/* Error Message */}
      {error && (
        <div style={{
          padding: '12px',
          background: '#FEE2E2',
          border: '1px solid #FCA5A5',
          borderRadius: '6px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          color: '#991B1B'
        }}>
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          color: currentColors.textSecondary
        }}>
          Carregando...
        </div>
      ) : (
        <>
          {showAddDocForm && (
            <AddDocumentForm
              onSubmit={createKnowledgeDoc}
              onCancel={() => setShowAddDocForm(false)}
              currentColors={currentColors}
            />
          )}
          <KnowledgeDocsList
            docs={filteredDocs}
            onDelete={deleteKnowledgeDoc}
            currentColors={currentColors}
          />
        </>
      )}
    </div>
  );
};

// Add Document Form Component
const AddDocumentForm: React.FC<{
  onSubmit: (data: any) => void;
  onCancel: () => void;
  currentColors: any;
}> = ({ onSubmit, onCancel, currentColors }) => {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [category, setCategory] = useState('');
  const [tags, setTags] = useState('');
  const [relatedIndices, setRelatedIndices] = useState('');
  const [priority, setPriority] = useState('5');
  const [availableIndices, setAvailableIndices] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [filteredIndices, setFilteredIndices] = useState<string[]>([]);
  const [showPreview, setShowPreview] = useState(false);

  // Buscar índices disponíveis ao montar o componente
  useEffect(() => {
    const fetchIndices = async () => {
      try {
        // Primeiro buscar servidores disponíveis
        const serversResponse = await fetch(`${API_URL}/es-servers/`);
        if (!serversResponse.ok) return;

        const servers = await serversResponse.json();
        if (servers.length === 0) return;

        // Usar o primeiro servidor (default)
        const serverId = servers[0].id;

        // Buscar índices do servidor
        const indicesResponse = await fetch(`${API_URL}/es-servers/${serverId}/indices`);
        if (indicesResponse.ok) {
          const data = await indicesResponse.json();
          // Extrair apenas os nomes dos índices
          const indexNames = data.map((index: any) => index.name);
          setAvailableIndices(indexNames);
          console.log('📚 Loaded indices:', indexNames);
        }
      } catch (error) {
        console.error('Error fetching indices:', error);
      }
    };
    fetchIndices();
  }, []);

  // Atualizar sugestões quando o usuário digitar
  const handleIndicesChange = (value: string) => {
    setRelatedIndices(value);

    // Pegar o último termo digitado (após a última vírgula)
    const terms = value.split(',');
    const currentTerm = terms[terms.length - 1].trim().toLowerCase();

    if (currentTerm.length > 0) {
      const matches = availableIndices.filter(index =>
        index.toLowerCase().includes(currentTerm)
      );
      setFilteredIndices(matches);
      setShowSuggestions(matches.length > 0);
    } else {
      setShowSuggestions(false);
    }
  };

  // Adicionar índice selecionado
  const addIndex = (index: string) => {
    const terms = relatedIndices.split(',').map(t => t.trim()).filter(Boolean);
    // Remove o último termo incompleto e adiciona o selecionado
    terms.pop();
    terms.push(index);
    setRelatedIndices(terms.join(', ') + ', ');
    setShowSuggestions(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const docData = {
      title,
      content,
      category: category || null,
      tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      related_indices: relatedIndices.split(',').map(i => i.trim()).filter(Boolean),
      priority: parseInt(priority, 10),
      is_active: true
    };

    onSubmit(docData);
  };

  return (
    <div style={{
      background: currentColors.cardBg,
      border: `2px solid ${currentColors.primary}`,
      borderRadius: '8px',
      padding: '20px',
      marginBottom: '20px',
      position: 'relative',
      zIndex: 100
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h3 style={{ margin: 0, color: currentColors.text, fontSize: '18px', fontWeight: 600 }}>
          Novo Documento
        </h3>
        <button
          onClick={onCancel}
          style={{
            padding: '6px',
            background: 'none',
            border: 'none',
            color: currentColors.textSecondary,
            cursor: 'pointer'
          }}
        >
          ✕
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'grid', gap: '16px' }}>
          {/* Title */}
          <div>
            <label style={{
              display: 'block',
              marginBottom: '6px',
              color: currentColors.text,
              fontSize: '14px',
              fontWeight: 500
            }}>
              Título *
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
              placeholder="Ex: Como Investigar Erros 500"
              style={{
                width: '100%',
                padding: '10px 12px',
                background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                borderRadius: '6px',
                color: currentColors.text?.primary || currentColors.text || '#111827',
                fontSize: '14px'
              }}
            />
          </div>

          {/* Content */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{
                color: currentColors.text,
                fontSize: '14px',
                fontWeight: 500
              }}>
                Conteúdo * (Suporta Markdown)
              </label>
              <button
                type="button"
                onClick={() => setShowPreview(!showPreview)}
                style={{
                  padding: '4px 8px',
                  background: 'transparent',
                  border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                  borderRadius: '4px',
                  color: currentColors.text?.primary || currentColors.text || '#111827',
                  fontSize: '12px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                {showPreview ? <><EyeOff size={14} /> Editar</> : <><Eye size={14} /> Preview</>}
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: showPreview ? '1fr 1fr' : '1fr', gap: '12px' }}>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                required
                rows={12}
                placeholder="# Como Investigar Erros 500&#10;&#10;## Passo 1: Verifique os logs&#10;Procure por padrões comuns de erro..."
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                  border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                  borderRadius: '6px',
                  color: currentColors.text?.primary || currentColors.text || '#111827',
                  fontSize: '14px',
                  fontFamily: 'monospace',
                  resize: 'vertical'
                }}
              />

              {showPreview && (
                <div style={{
                  padding: '10px 12px',
                  background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                  border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                  borderRadius: '6px',
                  minHeight: '300px',
                  maxHeight: '400px',
                  overflowY: 'auto'
                }}>
                  <div style={{
                    color: currentColors.text?.primary || currentColors.text || '#111827',
                    fontSize: '14px',
                    lineHeight: '1.6'
                  }}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {content || '*Escreva algo para ver o preview...*'}
                    </ReactMarkdown>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            {/* Category */}
            <div>
              <label style={{
                display: 'block',
                marginBottom: '6px',
                color: currentColors.text,
                fontSize: '14px',
                fontWeight: 500
              }}>
                Categoria
              </label>
              <input
                type="text"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                placeholder="Ex: troubleshooting, business-rules"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                  border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                  borderRadius: '6px',
                  color: currentColors.text?.primary || currentColors.text || '#111827',
                  fontSize: '14px'
                }}
              />
            </div>

            {/* Priority */}
            <div>
              <label style={{
                display: 'block',
                marginBottom: '6px',
                color: currentColors.text,
                fontSize: '14px',
                fontWeight: 500
              }}>
                Prioridade (0-10)
              </label>
              <input
                type="number"
                min="0"
                max="10"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                  border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                  borderRadius: '6px',
                  color: currentColors.text?.primary || currentColors.text || '#111827',
                  fontSize: '14px'
                }}
              />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label style={{
              display: 'block',
              marginBottom: '6px',
              color: currentColors.text,
              fontSize: '14px',
              fontWeight: 500
            }}>
              Tags (separadas por vírgula)
            </label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="Ex: errors, 500, debugging"
              style={{
                width: '100%',
                padding: '10px 12px',
                background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                borderRadius: '6px',
                color: currentColors.text?.primary || currentColors.text || '#111827',
                fontSize: '14px'
              }}
            />
          </div>

          {/* Related Indices */}
          <div style={{ position: 'relative', zIndex: 10 }}>
            <label style={{
              display: 'block',
              marginBottom: '6px',
              color: currentColors.text,
              fontSize: '14px',
              fontWeight: 500
            }}>
              Índices Relacionados (separados por vírgula)
            </label>
            <input
              type="text"
              value={relatedIndices}
              onChange={(e) => handleIndicesChange(e.target.value)}
              onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
              onFocus={() => handleIndicesChange(relatedIndices)}
              placeholder="Digite para buscar índices... Ex: logs-app-*"
              style={{
                width: '100%',
                padding: '10px 12px',
                background: currentColors.bg?.secondary || currentColors.bgSecondary || '#f3f4f6',
                border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                borderRadius: '6px',
                color: currentColors.text?.primary || currentColors.text || '#111827',
                fontSize: '14px'
              }}
            />

            {/* Sugestões */}
            {showSuggestions && filteredIndices.length > 0 && (
              <div style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                right: 0,
                marginTop: '4px',
                background: currentColors.bg?.primary || currentColors.cardBg || '#ffffff',
                border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                borderRadius: '6px',
                maxHeight: '200px',
                overflowY: 'auto',
                zIndex: 9999,
                boxShadow: '0 10px 25px rgba(0, 0, 0, 0.15)'
              }}>
                {filteredIndices.slice(0, 10).map((index, i) => (
                  <div
                    key={i}
                    onClick={() => addIndex(index)}
                    style={{
                      padding: '10px 12px',
                      cursor: 'pointer',
                      borderBottom: i < filteredIndices.length - 1 ? `1px solid ${currentColors.border?.default || currentColors.border || '#e5e7eb'}` : 'none',
                      fontSize: '14px',
                      color: currentColors.text?.primary || currentColors.text || '#111827',
                      fontFamily: 'monospace'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = currentColors.bg?.hover || currentColors.bgSecondary || '#f3f4f6';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'transparent';
                    }}
                  >
                    {index}
                  </div>
                ))}
              </div>
            )}

            <div style={{ marginTop: '4px', fontSize: '12px', color: currentColors.textSecondary }}>
              Esse documento será sugerido automaticamente quando esses índices forem mencionados
            </div>
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '16px' }}>
            <button
              type="button"
              onClick={onCancel}
              style={{
                padding: '10px 20px',
                background: 'transparent',
                border: `1px solid ${currentColors.border?.default || currentColors.border || '#d1d5db'}`,
                borderRadius: '6px',
                color: currentColors.text?.primary || currentColors.text || '#111827',
                fontSize: '14px',
                fontWeight: 500,
                cursor: 'pointer'
              }}
            >
              Cancelar
            </button>
            <button
              type="submit"
              style={{
                padding: '10px 20px',
                background: '#3b82f6',
                border: 'none',
                borderRadius: '6px',
                color: 'white',
                fontSize: '14px',
                fontWeight: 500,
                cursor: 'pointer'
              }}
            >
              Criar Documento
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

// Knowledge Documents List Component
const KnowledgeDocsList: React.FC<{
  docs: KnowledgeDoc[];
  onDelete: (id: string) => void;
  currentColors: any;
}> = ({ docs, onDelete, currentColors }) => {
  if (docs.length === 0) {
    return (
      <div style={{
        textAlign: 'center',
        padding: '60px 20px',
        color: currentColors.textSecondary
      }}>
        <BookOpen size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
        <p style={{ margin: '0 0 8px 0', fontSize: '16px', fontWeight: 500 }}>
          Nenhum documento ainda
        </p>
        <p style={{ margin: 0, fontSize: '14px' }}>
          Clique em "Novo Documento" para adicionar conhecimento que ajuda a IA
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gap: '16px' }}>
      {docs.map(doc => (
        <div
          key={doc.id}
          style={{
            background: currentColors.cardBg,
            border: `1px solid ${currentColors.border}`,
            borderRadius: '8px',
            padding: '16px',
            transition: 'all 0.2s'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '12px' }}>
            <div style={{ flex: 1 }}>
              <h3 style={{
                margin: '0 0 8px 0',
                color: currentColors.text,
                fontSize: '16px',
                fontWeight: 600
              }}>
                {doc.title}
              </h3>
              <p style={{
                margin: 0,
                color: currentColors.textSecondary,
                fontSize: '14px',
                lineHeight: '1.5',
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                overflow: 'hidden'
              }}>
                {doc.content.split('\n')[0]}
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                style={{
                  padding: '6px',
                  background: 'none',
                  border: `1px solid ${currentColors.border}`,
                  borderRadius: '4px',
                  color: currentColors.textSecondary,
                  cursor: 'pointer'
                }}
                title="Edit"
              >
                <Edit2 size={14} />
              </button>
              <button
                onClick={() => onDelete(doc.id)}
                style={{
                  padding: '6px',
                  background: 'none',
                  border: `1px solid ${currentColors.border}`,
                  borderRadius: '4px',
                  color: '#EF4444',
                  cursor: 'pointer'
                }}
                title="Delete"
              >
                <Trash2 size={14} />
              </button>
            </div>
          </div>

          {doc.tags.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px' }}>
              {doc.tags.map(tag => (
                <span
                  key={tag}
                  style={{
                    padding: '4px 8px',
                    background: currentColors.bgSecondary,
                    border: `1px solid ${currentColors.border}`,
                    borderRadius: '12px',
                    fontSize: '12px',
                    color: currentColors.textSecondary,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  <Tag size={10} />
                  {tag}
                </span>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', fontSize: '12px', color: currentColors.textSecondary }}>
            {doc.category && (
              <>
                <span>{doc.category}</span>
                <span>•</span>
              </>
            )}
            <span>Priority: {doc.priority}</span>
            <span>•</span>
            <span>{new Date(doc.created_at).toLocaleDateString()}</span>
          </div>
        </div>
      ))}
    </div>
  );
};
