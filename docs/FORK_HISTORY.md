# Fork History - Intelligence Platform

Este projeto foi criado a partir do **Dashboard AI v2.0** em **14 de Janeiro de 2025**.

---

## 🎯 Motivo do Fork

O Dashboard AI v2.0 foi desenvolvido como uma **plataforma de agregação de KPIs**, focando em:
- Dashboards operacionais
- Visualizações de métricas
- Widgets drag-and-drop
- Time ranges globais

A **Intelligence Platform** surge com um propósito diferente: **análise de inteligência estratégica**, focando em:
- Correlação entre múltiplas fontes de dados
- Análise temporal de eventos
- Extração de insights
- Alertas e relatórios de inteligência
- Timeline de eventos

Dado que são **produtos com propósitos distintos**, a decisão foi fazer um **fork independente** ao invés de manter como branches do mesmo repositório.

---

## ✅ O que foi MANTIDO (Esqueleto reutilizado)

### Autenticação e Segurança
- ✅ Sistema de autenticação JWT
- ✅ SSO com Microsoft Entra ID (Azure AD)
- ✅ Sistema de usuários e permissões (roles: admin, power, operator, reader)
- ✅ Criptografia de secrets (Fernet + PBKDF2)
- ✅ Audit logs
- ✅ Profile management com fotos

### Arquitetura Backend
- ✅ FastAPI + SQLAlchemy
- ✅ PostgreSQL para metadados
- ✅ Redis para cache e pub/sub
- ✅ Alembic para migrations
- ✅ Estrutura de services, models, schemas, API endpoints

### LLM Integration
- ✅ Multi-provider support (Anthropic Claude, OpenAI, Databricks)
- ✅ LLM factory pattern
- ✅ API key encryption
- ✅ Provider selection dinâmica

### Frontend Base
- ✅ React 18 + TypeScript
- ✅ Vite como build tool
- ✅ TailwindCSS
- ✅ Sistema de temas (6 temas: light, dark, monokai, dracula, nord, solarized)
- ✅ Zustand para state management
- ✅ Socket.io para WebSocket

### Infraestrutura
- ✅ Docker + Docker Compose
- ✅ Nginx (para produção)
- ✅ Health checks
- ✅ Volume management

---

## ❌ O que foi REMOVIDO (Específico de KPIs)

### Features de Dashboard
- ❌ Widget system (WidgetCard, WidgetEditModal)
- ❌ Grid layout drag-and-drop (react-grid-layout)
- ❌ Time range global para dashboards
- ❌ Fixed time range per widget
- ❌ Dashboard editor com posicionamento de widgets
- ❌ CSV upload para Elasticsearch
- ❌ Elasticsearch como fonte principal de dados

### Visualizações de KPI
- ❌ Plotly charts (pie, bar, line, metric, table)
- ❌ Dashboard grid responsivo
- ❌ Widget configuration modal
- ❌ Dashboard sharing

### Elasticsearch Integration
- ❌ ES server selector
- ❌ Index field viewer
- ❌ MCP per index configuration
- ❌ Query execution via ES DSL

---

## 🆕 O que será ADICIONADO (Novo - Intelligence focused)

### Intelligence Core
- 🆕 Intelligence report engine
- 🆕 Data source connectors (múltiplas fontes além de ES)
- 🆕 Correlation analysis entre fontes
- 🆕 Entity extraction (pessoas, lugares, organizações)
- 🆕 Timeline view de eventos
- 🆕 Alert system configurável
- 🆕 Tag system e categorização

### Data Processing
- 🆕 Multi-source data ingestion
- 🆕 Data normalization layer
- 🆕 Event correlation engine
- 🆕 Pattern detection
- 🆕 Anomaly detection

### Visualization (Intelligence-focused)
- 🆕 Timeline view
- 🆕 Network graphs (relações entre entidades)
- 🆕 Geo-spatial visualization
- 🆕 Heatmaps temporais
- 🆕 Correlation matrices

### Reporting
- 🆕 Intelligence reports (PDF, Excel)
- 🆕 Executive summaries
- 🆕 Scheduled reports
- 🆕 Report templates

---

## 📊 Comparação: Dashboard AI v2 vs Intelligence Platform

| Aspecto | Dashboard AI v2 | Intelligence Platform |
|---------|-----------------|----------------------|
| **Propósito** | Agregação de KPIs | Análise de Inteligência |
| **Foco** | Métricas operacionais | Insights estratégicos |
| **Fontes** | Elasticsearch principalmente | Múltiplas fontes |
| **Visualização** | Dashboards com widgets | Timeline, graphs, reports |
| **Time Handling** | Time ranges fixos/globais | Event-based timeline |
| **Output** | Gráficos interativos | Relatórios + alertas |
| **Usuário típico** | Analista de negócios | Analista de inteligência |
| **Use Case** | Monitoring de métricas | Investigação e correlação |

---

## 🔄 Sincronização com Upstream (Dashboard AI v2)

### Estratégia de Sincronização

A Intelligence Platform é um **fork independente**. Sincronização com o Dashboard AI v2 será **seletiva** e apenas para:

✅ **Trazer do upstream (cherry-pick)**:
- Bugfixes de segurança (autenticação, SSO, criptografia)
- Melhorias em LLM integration
- Correções no sistema de permissões
- Updates de dependências críticas

❌ **NÃO trazer**:
- Features específicas de dashboard/KPI
- Mudanças em visualizações Plotly
- Alterações no widget system
- Features de Elasticsearch-specific

### Como sincronizar (quando necessário)

```bash
# No repositório Intelligence Platform
git remote add upstream https://github.com/seu-usuario/dashboard-ai-v2.git
git fetch upstream

# Cherry-pick commit específico
git cherry-pick <commit-hash>

# Ou merge branch específica (cuidado com conflitos)
git merge upstream/bugfix-sso
```

### Última sincronização
- **Data**: 2025-01-14 (fork inicial)
- **Commit**: `c6ead62` - "docs: add reboot guide and automation scripts"
- **Próxima**: Apenas quando houver bugfix crítico de segurança

---

## 🗓️ Timeline de Desenvolvimento

### Fase 1: Fork e Setup (Semana 1 - 2025-01-14)
- ✅ Fork repositório
- ✅ Renomear projeto (intelligence-platform)
- ✅ Atualizar docker-compose, package.json, README
- ✅ Documentar fork history
- ✅ Limpar features de dashboard/KPI (pendente)

### Fase 2: Core Intelligence (Semanas 2-4)
- 🔲 Modelo IntelligenceReport
- 🔲 API para ingestão de dados
- 🔲 UI para visualizar relatórios
- 🔲 Sistema de tags/categorias
- 🔲 Busca e filtros

### Fase 3: Multi-Source Integration (Semanas 5-8)
- 🔲 Data source connectors
- 🔲 Data normalization layer
- 🔲 Timeline de eventos
- 🔲 Correlation engine básico

### Fase 4: Advanced Features (Semanas 9-12)
- 🔲 Alert system
- 🔲 Report generation (PDF, Excel)
- 🔲 Network graphs
- 🔲 Entity extraction
- 🔲 Geo-spatial visualization

---

## 💡 Lições Aprendidas do Dashboard AI v2

### O que funcionou bem (manter)
- ✅ Arquitetura FastAPI + SQLAlchemy + PostgreSQL
- ✅ Sistema de auth/SSO bem estruturado
- ✅ Multi-provider LLM com factory pattern
- ✅ Sistema de temas no frontend
- ✅ Docker Compose para desenvolvimento

### O que pode melhorar
- ⚠️ Excesso de dependência do Elasticsearch (diversificar fontes)
- ⚠️ Widget system muito acoplado ao Plotly (criar abstração)
- ⚠️ Time range global complexo (event-based é mais flexível)
- ⚠️ Falta de testes automatizados (adicionar desde o início)

---

## 🎯 Filosofia do Fork

Este fork segue a filosofia de **"aproveitar o esqueleto, trocar a carne"**:

1. **Reutilizar** toda a infraestrutura sólida (auth, LLM, infra)
2. **Remover** features específicas do domínio anterior (KPIs, dashboards)
3. **Adicionar** features específicas do novo domínio (intelligence, correlation)
4. **Divergir** com confiança - não ter medo de deletar código que não faz sentido
5. **Independência** - este é um produto diferente, não uma versão do Dashboard AI

---

## 📚 Referências

- **Repositório upstream**: https://github.com/seu-usuario/dashboard-ai-v2
- **Documentação Dashboard AI v2**: Ver docs/ no repositório original
- **Data do fork**: 2025-01-14
- **Commit base**: `c6ead62`

---

**Mantido por**: [Seu Nome/Equipe]  
**Última atualização**: 2025-01-14
