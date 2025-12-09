# Sistema de Knowledge Base

## Visão Geral

O Sistema de Knowledge Base permite adicionar contexto e documentação que ajuda a LLM a entender melhor os dados do Elasticsearch, resultando em respostas mais precisas e úteis.

## Arquitetura

### Componentes

**Backend (FastAPI):**
- Models: `IndexContext`, `KnowledgeDocument`
- APIs: `/api/v1/index-contexts`, `/api/v1/knowledge-docs`
- Tabelas PostgreSQL: `index_contexts`, `knowledge_documents`

**Frontend (React + TypeScript):**
- Componente: `KnowledgeBase` (Settings)
- Serviço: `knowledgeService.ts`
- Integração automática com chat

### Tipos de Conhecimento

#### 1. **Index Contexts** (Contexto por Índice)
Contexto específico para cada padrão de índice Elasticsearch.

**Campos:**
- `index_pattern`: Padrão do índice (e.g., "logs-app-*")
- `description`: Descrição geral do índice
- `business_context`: Contexto de negócio
- `field_descriptions`: Descrição de campos importantes
- `query_examples`: Exemplos de queries comuns
- `tips`: Dicas para análise

**Exemplo:**
```json
{
  "index_pattern": "logs-app-*",
  "description": "Application logs from main API service",
  "business_context": "Contains logs from REST API including errors and warnings",
  "field_descriptions": {
    "status_code": "HTTP status code (200, 404, 500, etc.)",
    "endpoint": "API route called",
    "duration_ms": "Request duration in milliseconds"
  },
  "query_examples": [
    {
      "question": "Show me 500 errors from last 24h",
      "description": "Filter by status_code:500 and use last 24h time range"
    }
  ],
  "tips": "When investigating 5xx errors, check 'error_code' field first"
}
```

#### 2. **Knowledge Documents** (Documentação Livre)
Documentos markdown com conhecimento geral, guias, troubleshooting, etc.

**Campos:**
- `title`: Título do documento
- `content`: Conteúdo em markdown
- `category`: Categoria (troubleshooting, business-rules, etc.)
- `tags`: Tags para busca
- `related_indices`: Índices relacionados
- `priority`: Prioridade (0-10, maior = mais importante)

**Exemplo:**
```json
{
  "title": "How to Investigate 500 Errors",
  "content": "# Investigating 500 Errors\n\n## Step 1: Identify the Pattern\n...",
  "category": "troubleshooting",
  "tags": ["errors", "500", "debugging"],
  "related_indices": ["logs-app-*", "logs-api-*"],
  "priority": 10
}
```

## Como Usar

### 1. Adicionar Contexto de Índice

**Via UI (Settings → Knowledge Base → Index Contexts):**
1. Clique em "Add Context" (quando implementado)
2. Preencha:
   - Index Pattern (ex: logs-app-*)
   - Description
   - Business Context
   - Field Descriptions
   - Query Examples
   - Tips
3. Salve

**Via API:**
```bash
curl -X POST http://localhost:8000/api/v1/index-contexts/ \
  -H "Content-Type: application/json" \
  -d '{
    "es_server_id": "default",
    "index_pattern": "logs-app-*",
    "description": "Application logs",
    "field_descriptions": {
      "status_code": "HTTP status code"
    }
  }'
```

### 2. Adicionar Documento de Conhecimento

**Via UI (Settings → Knowledge Base → Knowledge Documents):**
1. Clique em "Add Document" (quando implementado)
2. Preencha:
   - Title
   - Content (suporta Markdown)
   - Category
   - Tags
   - Related Indices
   - Priority
3. Salve

**Via API:**
```bash
curl -X POST http://localhost:8000/api/v1/knowledge-docs/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Error Investigation Guide",
    "content": "# Guide...",
    "category": "troubleshooting",
    "tags": ["errors", "debugging"],
    "related_indices": ["logs-*"],
    "priority": 10
  }'
```

### 3. Como o Chat Usa o Conhecimento

O chat automaticamente:

1. **Detecta índices mencionados** na pergunta do usuário
2. **Busca contexto** dos índices detectados
3. **Busca documentos relacionados** aos índices
4. **Faz busca textual** se não encontrar por índice
5. **Injeta contexto** no prompt para a LLM

**Exemplo de fluxo:**

```
Usuário: "Por que temos tantos erros 500 no logs-app-*?"

Sistema:
1. Detecta índice: "logs-app-*"
2. Busca Index Context de "logs-app-*"
3. Busca Knowledge Docs relacionados a "logs-app-*"
4. Busca docs com palavra-chave "500"
5. Monta contexto completo
6. Envia para LLM:

   Context:
   ## Current Index Context
   📊 Index Pattern: logs-app-*
   Description: Application logs from main API service
   Business Context: Contains logs from REST API...

   Important Fields:
   - status_code: HTTP status code (200, 404, 500, etc.)
   - error_code: Internal error code for 5xx responses

   ## Related Knowledge
   📚 How to Investigate 500 Errors
   Category: troubleshooting
   Tags: errors, 500, debugging

   # Investigating 500 Errors
   Step 1: Identify the Pattern...

   User Question: Por que temos tantos erros 500 no logs-app-*?

LLM: [Usa todo esse contexto para dar resposta precisa e específica]
```

## API Endpoints

### Index Contexts

#### Listar Contextos
```bash
GET /api/v1/index-contexts/
GET /api/v1/index-contexts/?index_pattern=logs-*
GET /api/v1/index-contexts/?es_server_id=default
```

#### Obter Contexto
```bash
GET /api/v1/index-contexts/{id}
GET /api/v1/index-contexts/by-pattern/{index_pattern}
```

#### Criar Contexto
```bash
POST /api/v1/index-contexts/
Content-Type: application/json

{
  "es_server_id": "default",
  "index_pattern": "logs-app-*",
  "description": "...",
  "business_context": "...",
  "field_descriptions": {...},
  "query_examples": [...],
  "tips": "..."
}
```

#### Atualizar Contexto
```bash
PATCH /api/v1/index-contexts/{id}
Content-Type: application/json

{
  "description": "New description",
  "is_active": false
}
```

#### Deletar Contexto
```bash
DELETE /api/v1/index-contexts/{id}
```

#### Preview Formatação LLM
```bash
POST /api/v1/index-contexts/{id}/llm-context
```

### Knowledge Documents

#### Listar Documentos
```bash
GET /api/v1/knowledge-docs/
GET /api/v1/knowledge-docs/?category=troubleshooting
GET /api/v1/knowledge-docs/?tag=errors
GET /api/v1/knowledge-docs/?index_pattern=logs-*
```

#### Obter Documento
```bash
GET /api/v1/knowledge-docs/{id}
```

#### Criar Documento
```bash
POST /api/v1/knowledge-docs/
Content-Type: application/json

{
  "title": "Guide Title",
  "content": "# Markdown content...",
  "category": "troubleshooting",
  "tags": ["errors", "debugging"],
  "related_indices": ["logs-*"],
  "priority": 10
}
```

#### Atualizar Documento
```bash
PATCH /api/v1/knowledge-docs/{id}
Content-Type: application/json

{
  "priority": 5,
  "is_active": false
}
```

#### Deletar Documento
```bash
DELETE /api/v1/knowledge-docs/{id}
```

#### Buscar Documentos
```bash
POST /api/v1/knowledge-docs/search?query=500+errors&limit=5
```

#### Listar Categorias
```bash
GET /api/v1/knowledge-docs/categories/list
```

#### Listar Tags
```bash
GET /api/v1/knowledge-docs/tags/list
```

#### Preview Formatação LLM
```bash
POST /api/v1/knowledge-docs/{id}/llm-context?max_length=1000
```

## Frontend Service

### KnowledgeService

Serviço TypeScript para integração com chat.

**Métodos principais:**

```typescript
// Buscar contexto de índice específico
const context = await KnowledgeService.getIndexContext('logs-app-*');

// Buscar documentos relacionados a índices
const docs = await KnowledgeService.getRelatedDocs(['logs-app-*', 'metrics-*']);

// Buscar documentos por palavra-chave
const results = await KnowledgeService.searchDocs('500 errors');

// Extrair índices mencionados em mensagem
const indices = KnowledgeService.extractIndexPatterns('Check logs-app-* for errors');

// Montar contexto completo para LLM
const fullContext = await KnowledgeService.buildContext(
  'Why so many 500 errors?',
  'logs-app-*'  // índice atual
);
```

## Integração com Chat

### ✅ Integração Completa e Automática

O sistema está **totalmente integrado** com os componentes de chat. O contexto da Knowledge Base é automaticamente injetado em todas as mensagens enviadas ao LLM.

**Componentes integrados:**
- ✅ `ChatPage.tsx`: Página dedicada de chat com conversas persistentes
- ✅ `ChatPanel.tsx`: Painel de chat no dashboard

**Como funciona:**

Quando o usuário envia uma mensagem:

1. O `KnowledgeService.buildContext()` é chamado automaticamente
2. O contexto é montado com:
   - Contexto do índice atual
   - Contextos de índices mencionados na mensagem
   - Documentos relacionados aos índices
   - Busca por palavras-chave (se não encontrar por índice)
3. A mensagem enriquecida é enviada ao LLM no formato:

```
## Current Index Context
📊 Index Pattern: logs-app-*
Description: Application logs from main API service
...

## Related Knowledge
📚 How to Investigate 500 Errors
...

---

User Question: Why so many 500 errors?
```

**Não é necessário nenhuma configuração adicional!** O sistema funciona automaticamente assim que você adicionar contextos e documentos via Settings → Knowledge Base.

### Manual

Você também pode buscar contexto manualmente:

```typescript
// Buscar apenas contexto de índice
const indexContext = await KnowledgeService.getIndexContext('logs-app-*');

// Buscar apenas documentos
const docs = await KnowledgeService.searchDocs('troubleshooting');

// Combinar como quiser
const customContext = `
${indexContext || ''}

${docs.join('\n\n')}
`;
```

## Boas Práticas

### Index Contexts

1. **Seja específico**: Descreva o que o índice realmente contém
2. **Foque no importante**: Não descreva todos os campos, só os principais
3. **Dê exemplos**: Query examples ajudam muito a LLM
4. **Contexto de negócio**: Explique o "porquê" dos dados
5. **Atualize regularmente**: Mantenha contexto atualizado com mudanças

### Knowledge Documents

1. **Use Markdown**: Estruture bem o conteúdo
2. **Seja conciso**: LLM tem limite de tokens
3. **Priorize bem**: Use `priority` para documentos importantes
4. **Tags relevantes**: Facilita busca por palavras-chave
5. **Relacione índices**: Vincule docs aos índices corretos

### Organização

**Categorias sugeridas:**
- `troubleshooting`: Guias de investigação
- `business-rules`: Regras de negócio
- `data-dictionary`: Dicionário de dados
- `best-practices`: Melhores práticas
- `alerts`: Documentação de alertas
- `onboarding`: Onboarding para novos usuários

**Tags sugeridas:**
- `errors`, `performance`, `debugging`
- `critical`, `high-priority`
- `dashboard`, `metrics`, `logs`
- `production`, `staging`

## Limitações e Considerações

### Tamanho do Contexto

- LLMs têm limite de tokens (~4000-8000)
- Contexto é limitado automaticamente:
  - Máximo 2 index contexts por query
  - Máximo 3 knowledge docs
  - Documentos truncados em ~500 caracteres

### Performance

- Busca de contexto adiciona ~200-500ms à query
- Cache pode ser implementado se necessário
- Considere usar apenas para queries complexas

### Privacidade

- Contexto é enviado para LLM junto com a pergunta
- Não adicione informações sensíveis em contextos
- Use apenas metadados e descrições genéricas

## Roadmap

### ✅ Implementado

- [x] Sistema de Index Contexts (contexto por índice)
- [x] Sistema de Knowledge Documents (documentação livre)
- [x] APIs REST completas (CRUD + Search)
- [x] Interface UI no Settings
- [x] Integração automática com chat
- [x] Busca por index pattern
- [x] Busca textual em documentos
- [x] Formatação LLM otimizada
- [x] Priorização de documentos
- [x] Sistema de tags e categorias

### 🔮 Melhorias Futuras

- [ ] Editor Markdown com preview
- [ ] Formulários de criação/edição inline
- [ ] Cache de contextos frequentes
- [ ] Busca semântica (embeddings)
- [ ] Sugestões automáticas de contexto
- [ ] Versionamento de documentos
- [ ] Importar/exportar contextos
- [ ] Templates de documentos
- [ ] Analytics de uso
- [ ] Feedback de qualidade

## Exemplos Práticos

### Exemplo 1: Logs de Aplicação

**Index Context:**
```json
{
  "index_pattern": "logs-app-prod-*",
  "description": "Production application logs",
  "business_context": "Critical service handling payments and user auth",
  "field_descriptions": {
    "transaction_id": "Unique transaction identifier for payment tracking",
    "error_type": "Error classification: PAYMENT_FAILED, AUTH_ERROR, TIMEOUT",
    "user_tier": "User subscription tier: free, premium, enterprise"
  },
  "tips": "Payment errors spike during promotions. Check user_tier for context."
}
```

**Knowledge Doc:**
```markdown
# Payment Error Investigation

## Common Causes

### PAYMENT_FAILED
- Check payment gateway status page
- Verify API keys are not expired
- Check rate limits

### AUTH_ERROR
- Usually token expiration
- Check Redis cache health

### TIMEOUT
- Database connection pool exhausted
- Third-party API slow response
```

### Exemplo 2: Métricas de Performance

**Index Context:**
```json
{
  "index_pattern": "metrics-api-*",
  "description": "API performance metrics",
  "business_context": "Tracks p50, p95, p99 latencies for all endpoints",
  "field_descriptions": {
    "endpoint": "API route path",
    "method": "HTTP method (GET, POST, etc.)",
    "p95_ms": "95th percentile latency in milliseconds",
    "error_rate": "Percentage of failed requests"
  },
  "query_examples": [
    {
      "question": "Which endpoints are slowest?",
      "description": "Aggregate by endpoint, sort by avg(p95_ms) desc"
    }
  ],
  "tips": "p95 > 1000ms is critical. Check database indexes first."
}
```

## Troubleshooting

### Contexto não aparece no chat

1. Verifique se contexto está ativo (`is_active: true`)
2. Confirme que `index_pattern` corresponde ao índice usado
3. Verifique console do browser por erros de rede
4. Teste endpoint diretamente: `GET /api/v1/index-contexts/by-pattern/{pattern}`

### Busca de documentos não funciona

1. Verifique se `related_indices` está preenchido
2. Confirme que documentos estão ativos
3. Teste busca diretamente: `POST /api/v1/knowledge-docs/search?query=...`
4. Verifique se tags/category estão corretos

### LLM não usa o contexto

1. Verifique se contexto está sendo enviado (log do request)
2. Contexto pode estar muito grande (truncado)
3. LLM pode precisar de instrução explícita para usar contexto
4. Ajuste o prompt template

## Suporte

Para dúvidas ou problemas:
1. Verifique esta documentação
2. Verifique logs do backend: `docker logs dashboard-ai-backend`
3. Teste APIs diretamente com curl/Postman
4. Verifique dados no PostgreSQL:
   ```sql
   SELECT * FROM index_contexts;
   SELECT * FROM knowledge_documents;
   ```
