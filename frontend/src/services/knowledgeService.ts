/**
 * Knowledge Service
 * Serviço para buscar e formatar contexto para LLM
 */

const API_BASE = `${import.meta.env.VITE_API_URL || 'http://localhost:8002'}/api/v1`;

interface IndexContext {
  id: string;
  index_pattern: string;
  description: string | null;
  business_context: string | null;
  tips: string | null;
  field_descriptions: Record<string, string>;
  query_examples: Array<{ question: string; description: string }>;
}

interface KnowledgeDoc {
  id: string;
  title: string;
  content: string;
  category: string | null;
  tags: string[];
  related_indices: string[];
  priority: number;
}

export class KnowledgeService {
  /**
   * Busca contexto de um índice específico
   */
  static async getIndexContext(indexPattern: string): Promise<string | null> {
    try {
      const response = await fetch(
        `${API_BASE}/index-contexts/by-pattern/${encodeURIComponent(indexPattern)}`
      );

      if (!response.ok) {
        return null;
      }

      const context: IndexContext | null = await response.json();

      // Verificar se context está válido
      if (!context || typeof context !== 'object' || !context.index_pattern) {
        // Contexto não existe ou é inválido - isso é normal se não foi cadastrado ainda
        return null;
      }

      // Formatar contexto para LLM
      const parts: string[] = [];

      parts.push(`📊 **Index Pattern**: ${context.index_pattern}`);

      if (context.description) {
        parts.push(`**Description**: ${context.description}`);
      }

      if (context.business_context) {
        parts.push(`\n**Business Context**: ${context.business_context}`);
      }

      if (Object.keys(context.field_descriptions).length > 0) {
        parts.push(`\n**Important Fields**:`);
        Object.entries(context.field_descriptions).forEach(([field, desc]) => {
          parts.push(`  - \`${field}\`: ${desc}`);
        });
      }

      if (context.query_examples && context.query_examples.length > 0) {
        parts.push(`\n**Common Queries**:`);
        context.query_examples.forEach((example) => {
          parts.push(`  - "${example.question}"`);
          if (example.description) {
            parts.push(`    ${example.description}`);
          }
        });
      }

      if (context.tips) {
        parts.push(`\n💡 **Tips**: ${context.tips}`);
      }

      return parts.join('\n');
    } catch (error) {
      console.error('Error fetching index context:', error);
      return null;
    }
  }

  /**
   * Busca documentos de conhecimento relacionados aos índices
   */
  static async getRelatedDocs(indexPatterns: string[]): Promise<string[]> {
    if (indexPatterns.length === 0) {
      return [];
    }

    try {
      const docs: KnowledgeDoc[] = [];

      // Buscar documentos para cada índice
      for (const pattern of indexPatterns) {
        const response = await fetch(
          `${API_BASE}/knowledge-docs/?index_pattern=${encodeURIComponent(pattern)}`
        );

        if (response.ok) {
          const data: KnowledgeDoc[] = await response.json();
          docs.push(...data);
        }
      }

      // Remover duplicados e ordenar por prioridade
      const uniqueDocs = Array.from(
        new Map(docs.map((doc) => [doc.id, doc])).values()
      ).sort((a, b) => b.priority - a.priority);

      // Formatar documentos (limitar conteúdo para não sobrecarregar)
      return uniqueDocs.slice(0, 3).map((doc) => {
        const parts: string[] = [];

        parts.push(`📚 **${doc.title}**`);

        if (doc.category) {
          parts.push(`Category: ${doc.category}`);
        }

        if (doc.tags.length > 0) {
          parts.push(`Tags: ${doc.tags.join(', ')}`);
        }

        // Limitar conteúdo a ~500 caracteres
        let content = doc.content;
        if (content.length > 500) {
          content = content.substring(0, 500) + '... (truncated)';
        }

        parts.push(`\n${content}`);

        return parts.join('\n');
      });
    } catch (error) {
      console.error('Error fetching related docs:', error);
      return [];
    }
  }

  /**
   * Busca documentos por pesquisa textual
   */
  static async searchDocs(query: string, limit: number = 3): Promise<string[]> {
    try {
      const response = await fetch(
        `${API_BASE}/knowledge-docs/search?query=${encodeURIComponent(query)}&limit=${limit}`,
        { method: 'POST' }
      );

      if (!response.ok) {
        return [];
      }

      const data = await response.json();
      const results = data.results || [];

      return results.map((result: any) => {
        const parts: string[] = [];

        parts.push(`📚 **${result.title}**`);

        if (result.category) {
          parts.push(`Category: ${result.category}`);
        }

        if (result.tags && result.tags.length > 0) {
          parts.push(`Tags: ${result.tags.join(', ')}`);
        }

        parts.push(`\n${result.excerpt}`);

        return parts.join('\n');
      });
    } catch (error) {
      console.error('Error searching docs:', error);
      return [];
    }
  }

  /**
   * Extrai padrões de índice de uma mensagem do usuário
   */
  static extractIndexPatterns(message: string): string[] {
    const patterns: string[] = [];

    // Regex para padrões comuns de índice Elasticsearch
    // Exemplos: logs-app-*, metrics-*, .kibana, etc.
    const indexRegex = /\b([\w.-]+\*?)\b/g;
    const matches = message.match(indexRegex);

    if (matches) {
      // Filtrar apenas padrões que parecem ser nomes de índice
      matches.forEach((match) => {
        // Deve ter letras/números, pode ter hífen, ponto, underscore, asterisco
        if (/^[\w.-]+\*?$/.test(match)) {
          // Excluir palavras comuns que não são índices
          const excludeWords = [
            'the',
            'and',
            'for',
            'with',
            'from',
            'this',
            'that',
            'index',
            'data',
            'show',
            'get',
            'find',
          ];

          if (!excludeWords.includes(match.toLowerCase())) {
            patterns.push(match);
          }
        }
      });
    }

    return [...new Set(patterns)]; // Remover duplicados
  }

  /**
   * Monta contexto completo para enviar ao LLM
   */
  static async buildContext(
    userMessage: string,
    currentIndex?: string
  ): Promise<string> {
    const contextParts: string[] = [];

    // 1. Contexto do índice atual (se houver)
    if (currentIndex) {
      const indexContext = await this.getIndexContext(currentIndex);
      if (indexContext) {
        contextParts.push('## Current Index Context\n');
        contextParts.push(indexContext);
      }
    }

    // 2. Extrair índices mencionados na mensagem
    const mentionedIndices = this.extractIndexPatterns(userMessage);

    // Buscar contextos dos índices mencionados
    for (const pattern of mentionedIndices.slice(0, 2)) {
      // Limitar a 2 para não sobrecarregar
      if (pattern !== currentIndex) {
        // Não duplicar
        const context = await this.getIndexContext(pattern);
        if (context) {
          contextParts.push(`\n## Context for ${pattern}\n`);
          contextParts.push(context);
        }
      }
    }

    // 3. Buscar documentos relacionados
    const allIndices = currentIndex
      ? [currentIndex, ...mentionedIndices]
      : mentionedIndices;

    if (allIndices.length > 0) {
      const relatedDocs = await this.getRelatedDocs(allIndices);

      if (relatedDocs.length > 0) {
        contextParts.push('\n## Related Knowledge\n');
        contextParts.push(relatedDocs.join('\n\n---\n\n'));
      }
    }

    // 4. Buscar documentos por palavras-chave (se não encontrou por índice)
    if (contextParts.length === 0) {
      // Extrair palavras-chave importantes da mensagem
      const keywords = userMessage
        .toLowerCase()
        .match(/\b(error|performance|slow|timeout|500|debug|investigate)\b/g);

      if (keywords && keywords.length > 0) {
        const searchResults = await this.searchDocs(keywords[0]);

        if (searchResults.length > 0) {
          contextParts.push('## Relevant Documentation\n');
          contextParts.push(searchResults.join('\n\n---\n\n'));
        }
      }
    }

    return contextParts.join('\n');
  }
}
