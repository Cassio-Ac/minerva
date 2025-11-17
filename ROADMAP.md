# Dashboard AI v2.0 - Roadmap

## ✅ Fase 1: Core Features (CONCLUÍDO)

### Base de Conhecimento do Índice
- [x] Criar IndexMappingService
- [x] Gerar relatório com campos, tipos e exemplos
- [x] Integrar base de conhecimento no prompt da LLM
- [x] Testar integração

**Arquivos:**
- `backend/app/services/index_mapping_service.py`
- `backend/app/services/llm_service.py` (integração)

### WebSocket Real-Time Sync
- [x] Instalar dependências (python-socketio, socket.io-client)
- [x] Criar WebSocket server no backend
- [x] Implementar eventos de broadcast (widget add/update/delete)
- [x] Criar WebSocket client no frontend
- [x] Integrar WebSocket com Zustand store
- [x] Testar sincronização entre múltiplas abas

**Arquivos:**
- `backend/app/websocket/manager.py`
- `backend/app/websocket/__init__.py`
- `backend/app/main.py` (integração Socket.IO)
- `backend/app/api/v1/dashboards.py` (broadcasts)
- `frontend/src/services/websocket.ts`
- `frontend/src/stores/dashboardStore.ts` (integração)
- `frontend/src/App.tsx` (inicialização)

### Visualizações e Elasticsearch
- [x] 7 tipos de visualização (pie, bar, line, area, metric, table, scatter)
- [x] ElasticsearchService para executar queries
- [x] Processamento de agregações
- [x] Integração com dados reais
- [x] Chat com Databricks Claude funcionando

---

## 🚧 Fase 2: Interface Multi-Servidor Elasticsearch (EM ANDAMENTO)

### Backend - Gerenciamento de Servidores
- [ ] Criar modelo `ElasticsearchServer` (Pydantic)
- [ ] Service para CRUD de servidores ES
- [ ] API endpoints:
  - [ ] `POST /api/v1/es-servers/` - Criar servidor
  - [ ] `GET /api/v1/es-servers/` - Listar servidores
  - [ ] `GET /api/v1/es-servers/{id}` - Obter servidor
  - [ ] `PATCH /api/v1/es-servers/{id}` - Atualizar servidor
  - [ ] `DELETE /api/v1/es-servers/{id}` - Deletar servidor
  - [ ] `POST /api/v1/es-servers/{id}/test` - Testar conexão
  - [ ] `GET /api/v1/es-servers/{id}/indices` - Listar índices

### Backend - Gerenciamento de Conexões
- [ ] Pool de conexões ES por servidor
- [ ] Validação de credenciais
- [ ] Health check de servidores
- [ ] Criptografia de senhas (bcrypt ou similar)

### Frontend - UI de Servidores
- [ ] Página de gerenciamento de servidores
  - [ ] Lista de servidores com status
  - [ ] Formulário para adicionar servidor
  - [ ] Edição inline de servidores
  - [ ] Botão de teste de conexão
- [ ] Seletor de servidor no dashboard
- [ ] Explorador de índices por servidor
  - [ ] Tree view de índices
  - [ ] Busca/filtro de índices
  - [ ] Visualização de mapping

### Integração
- [ ] Atualizar dashboard para armazenar `server_id`
- [ ] Modificar queries para usar servidor selecionado
- [ ] Migração de dados existentes

**Arquivos a criar:**
- `backend/app/models/elasticsearch_server.py`
- `backend/app/services/es_server_service.py`
- `backend/app/api/v1/es_servers.py`
- `frontend/src/types/elasticsearch.ts`
- `frontend/src/services/esServerApi.ts`
- `frontend/src/pages/ESServersManager.tsx`
- `frontend/src/components/ESServerSelector.tsx`
- `frontend/src/components/IndexExplorer.tsx`

---

## 📋 Fase 3: Melhorias de UX

### Indicadores Visuais
- [ ] Indicador de conexão WebSocket (online/offline)
- [ ] Badge de status do servidor ES
- [ ] Loading skeletons para widgets
- [ ] Progress bar para queries lentas
- [ ] Toast notifications para ações

### Estados de Loading
- [ ] Skeleton loaders para dashboard
- [ ] Shimmer effect em widgets carregando
- [ ] Spinner para chat aguardando LLM
- [ ] Loading state no seletor de índices

### Mensagens de Erro
- [ ] Error boundaries React
- [ ] Mensagens amigáveis para erros ES
- [ ] Sugestões de correção em erros de query
- [ ] Retry automático para erros temporários

### Confirmações e Validações
- [ ] Modal de confirmação ao deletar widget
- [ ] Confirmação ao deletar dashboard
- [ ] Validação de queries antes de executar
- [ ] Aviso ao sair com mudanças não salvas

**Arquivos a criar:**
- `frontend/src/components/ConnectionStatus.tsx`
- `frontend/src/components/LoadingSkeleton.tsx`
- `frontend/src/components/ErrorBoundary.tsx`
- `frontend/src/components/ConfirmDialog.tsx`
- `frontend/src/components/Toast.tsx`

---

## 🚀 Fase 4: Funcionalidades Avançadas

### Múltiplos Dashboards
- [ ] CRUD completo de dashboards
- [ ] Lista de dashboards na sidebar
- [ ] Criar dashboard a partir de template
- [ ] Duplicar dashboard existente
- [ ] Favoritar dashboards

### Compartilhamento
- [ ] Gerar URL pública para dashboard
- [ ] Configurar permissões (view-only, edit)
- [ ] Compartilhar via link ou QR code
- [ ] Embed de dashboards em iframe

### Exportação
- [ ] Exportar dashboard como JSON
- [ ] Exportar widgets como PDF
- [ ] Exportar dados de widgets como CSV/Excel
- [ ] Snapshot de dashboard (imagem)

### Templates
- [ ] Templates pré-configurados por use case
  - [ ] Security Monitoring
  - [ ] Application Logs
  - [ ] Business Metrics
  - [ ] Infrastructure Monitoring
- [ ] Galeria de templates
- [ ] Salvar dashboard como template

**Arquivos a criar:**
- `frontend/src/pages/DashboardList.tsx`
- `frontend/src/pages/TemplateGallery.tsx`
- `frontend/src/components/ShareDialog.tsx`
- `frontend/src/components/ExportDialog.tsx`
- `backend/app/services/export_service.py`
- `backend/app/services/template_service.py`

---

## ⚡ Fase 5: Performance e Otimização

### Cache
- [ ] Redis cache para queries ES frequentes
- [ ] Cache de mappings de índices
- [ ] TTL configurável por tipo de query
- [ ] Invalidação de cache ao atualizar dados

### Paginação
- [ ] Paginação server-side para tabelas
- [ ] Virtual scrolling para listas longas
- [ ] Load more incremental

### Lazy Loading
- [ ] Lazy loading de widgets fora da viewport
- [ ] Carregar dados apenas quando widget visível
- [ ] Defer de queries para widgets não críticos

### Otimizações ES
- [ ] Query optimization suggestions
- [ ] Índice de histórico de queries lentas
- [ ] Profiling de queries

**Arquivos a criar:**
- `backend/app/services/cache_service.py`
- `backend/app/services/query_optimizer.py`
- `frontend/src/hooks/useVirtualScroll.ts`
- `frontend/src/hooks/useLazyWidget.ts`

---

## 🔒 Fase 6: Segurança e Autenticação (Futuro)

- [ ] Sistema de autenticação (JWT)
- [ ] Controle de acesso baseado em roles
- [ ] Auditoria de ações
- [ ] Rate limiting de queries
- [ ] Sanitização de inputs

---

## 📊 Fase 7: Novas Visualizações (Futuro)

- [ ] Heatmap
- [ ] Treemap
- [ ] Sankey diagram
- [ ] Network graph
- [ ] Geo maps
- [ ] Custom visualizations (plugin system)

---

## Status Geral

**Fase 1:** ✅ 100% Concluído
**Fase 2:** 🚧 0% (Próxima)
**Fase 3:** ⏳ 0%
**Fase 4:** ⏳ 0%
**Fase 5:** ⏳ 0%
**Fase 6:** 💡 Planejado
**Fase 7:** 💡 Planejado

---

**Última atualização:** 2025-11-06
**Versão atual:** v2.0.0
