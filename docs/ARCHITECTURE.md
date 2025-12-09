# Dashboard AI v2 - Arquitetura do Sistema

## 📋 Visão Geral

Sistema de dashboards interativos com IA para análise de dados do Elasticsearch. Permite criar visualizações através de conversação em linguagem natural, com suporte a múltiplos índices, temas personalizáveis e colaboração em tempo real.

## 🏗️ Arquitetura de Alto Nível

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │  Chat Panel  │  │   Settings   │      │
│  │   Editor     │  │  (AI Chat)   │  │    Page      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                           │                                  │
│                    WebSocket + REST API                      │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────┐
│                     Backend (FastAPI)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │   Chat API   │  │  WebSocket   │      │
│  │   Service    │  │   + LLM      │  │   Server     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
└─────────────────────────────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
    ┌───────────▼──────────┐  ┌──────────▼─────────┐
    │   PostgreSQL         │  │  Elasticsearch     │
    │  (Metadados App)     │  │  (Dados Negócio)   │
    │                      │  │                    │
    │  • Dashboards        │  │  • vazamentos      │
    │  • Conversations     │  │  • tickets_jira    │
    │  • ES Servers        │  │  • logs            │
    │  • LLM Providers     │  │  • ... (n índices) │
    │  • Users (futuro)    │  │                    │
    └──────────────────────┘  └────────────────────┘
```

## 🗄️ Camada de Persistência

### **PostgreSQL - Metadados da Aplicação**

Armazena toda a configuração e estado do sistema:

#### **Tabelas Principais:**

1. **`dashboards`**
   - Dashboards completos com widgets
   - Layout, configurações visuais
   - Associação com índices ES
   - Versionamento

2. **`conversations`**
   - Histórico de conversas com IA
   - Mensagens com widgets anexados
   - Contexto de chat preservado

3. **`es_servers`**
   - Configuração de clusters ES
   - Credenciais criptografadas (Fernet)
   - Suporte multi-cluster

4. **`llm_providers`**
   - Múltiplos provedores LLM
   - Anthropic, OpenAI, Databricks
   - API keys criptografadas (Fernet + PBKDF2)

5. **`users`** (planejado)
   - Autenticação e autorização
   - Gestão de permissões

**Criptografia:**
- Senhas ES: Fernet symmetric encryption
- API Keys LLM: Fernet + PBKDF2 (100k iterations)
- Keys armazenadas no ambiente (.env)

### **Elasticsearch - Apenas Consultas**

**NÃO armazena metadados da aplicação!**

Uso:
- ✅ Executar queries nos índices de negócio
- ✅ Agregações e análises
- ✅ Buscar dados para widgets
- ❌ NÃO guarda dashboards
- ❌ NÃO guarda conversas

## 🎨 Sistema de Temas

### **Estrutura de Temas**

O sistema suporta 6 temas pré-definidos armazenados em `settingsStore.ts`:

```typescript
themes = {
  light: { /* cores claras */ },
  dark: { /* cores escuras */ },
  monokai: { /* inspirado no editor */ },
  dracula: { /* roxo escuro */ },
  nord: { /* azul gelo */ },
  solarized: { /* amarelo/azul */ }
}
```

### **Paleta de Cores por Tema**

Cada tema define:
- **bg**: primary, secondary, tertiary, hover
- **text**: primary, secondary, muted, inverse
- **border**: default, hover
- **accent**: primary, primaryHover

### **Aplicação de Temas**

1. **Store Global** (`settingsStore`):
   ```typescript
   currentTheme: 'dark'  // selecionado
   currentColors: { ... } // paleta ativa
   ```

2. **Persistência**:
   - localStorage: `theme` key
   - Carrega automaticamente ao iniciar

3. **Aplicação Dinâmica**:
   - Todos componentes usam `style={{ color: currentColors.text.primary }}`
   - Sem classes CSS fixas
   - Re-render automático ao trocar tema

### **Componentes Tematizados**

- ✅ Dashboard Editor (header, sidebar, canvas)
- ✅ Chat Panel (mensagens, input, botões)
- ✅ Widget Cards (header, conteúdo, footer)
- ✅ Settings Page (formulário, botões)
- ✅ Gráficos Plotly (cores, grid, texto)
- ✅ Modais (fundo, bordas, inputs)

## ⚙️ Sistema de Configurações

### **Settings Store** (`settingsStore.ts`)

Estado global das configurações do usuário:

```typescript
{
  currentTheme: string,           // tema selecionado
  currentColors: ColorPalette,    // paleta ativa

  // Métodos
  setTheme(theme: string): void,  // trocar tema
  getThemeStyles(): object        // utilitário de estilos
}
```

### **Persistência**

- **localStorage**: chave `theme`
- **Auto-load**: ao montar app
- **Auto-save**: ao trocar tema

### **Settings Page**

Interface para configurações do usuário:
- Seletor de tema visual (6 opções)
- Preview em tempo real
- Salvamento instantâneo

## 🔄 Fluxo de Dados - Widgets

### **1. Criação de Widget via Chat**

```
Usuário → "mostre um gráfico de pizza"
    ↓
ChatPanel envia mensagem
    ↓
Backend LLM Service:
  - Analisa requisição
  - Consulta campos do índice ES
  - Gera query Elasticsearch
  - Executa query no ES
  - Formata dados para Plotly
    ↓
Retorna: {
  explanation: "...",
  widget: {
    title: "...",
    type: "pie",
    data: {
      query: { /* ES query */ },
      results: { data: [...] },
      config: { colors, layout, plotly }
    }
  }
}
    ↓
ChatPanel adiciona ao dashboard:
  - newWidget.id = `widget-${Date.now()}`
  - newWidget.index = selectedIndex
  - newWidget.data.last_updated = new Date()
    ↓
useDashboardStore.addWidget(newWidget)
    ↓
Auto-save dashboard (500ms debounce)
    ↓
PostgreSQL: UPDATE dashboards SET widgets=[...]
```

### **2. Carregamento de Dashboard**

```
Página carrega
    ↓
DashboardEditor useEffect (mount):
  - isInitialized = false
  - Busca dashboard do PostgreSQL
  - setCurrentDashboard(dashboard)
  - isInitialized = true (previne loop)
    ↓
Dashboard carregado com widgets:
  widgets = [{
    id, title, type, position,
    data: {
      query: { /* ES query */ },
      config: { /* Plotly config */ }
      // NÃO tem results nem last_updated!
    },
    index: "vazamentos"
  }]
    ↓
WidgetCard useEffect para cada widget:
  - Verifica se tem dados recentes (<5s)
  - Se não, executa query:
      * Usa widget.index (próprio do widget)
      * Envia query SEM timeRange (query já tem range)
      * Recebe results do ES
      * updateWidgetData(id, {results, config, last_updated})
    ↓
Widget renderiza com dados
```

### **3. Mudança de Time Range**

```
Usuário troca período: "30 dias" → "6 meses"
    ↓
TimeRangePicker onChange
    ↓
useDashboardStore.setTimeRange({
  type: 'preset',
  preset: 'now-6M',
  from: 'now-6M',
  to: 'now',
  label: 'Últimos 6 meses'
})
    ↓
Store chama refreshAllWidgets() (100ms delay)
    ↓
Para cada widget:
  1. Clona query original
  2. Atualiza range no query:
     - query.bool.filter[].range[field].gte = 'now-6M'
     - query.bool.filter[].range[field].lte = 'now'
  3. Executa query atualizada
  4. updateWidgetData(id, {results, config, query})
    ↓
Widgets re-renderizam com novos dados
```

### **4. Salvamento de Dashboard**

```
Usuário clica "Salvar"
    ↓
handleSaveDashboard():
  - Monta objeto: { widgets: [...] }
  - PATCH /api/v1/dashboards/{id}
    ↓
Backend:
  - dashboard_service_sql.update()
  - PostgreSQL: UPDATE dashboards SET widgets=?, updated_at=NOW()
    ↓
Frontend recebe dashboard atualizado
    ↓
refreshAllWidgets():
  - Re-executa todas as queries
  - Atualiza dados dos widgets
    ↓
Alert "Dashboard salvo com sucesso!"
```

### **5. Widgets Multi-Índice**

Cada widget é **independente** e mantém seu próprio índice:

```typescript
widget = {
  id: "widget-123",
  title: "Timeline Vazamentos",
  index: "vazamentos",  // ← índice próprio!
  data: {
    query: { /* query para 'vazamentos' */ }
  }
}

widget2 = {
  id: "widget-456",
  title: "CVEs Críticas",
  index: "tickets_jira",  // ← índice diferente!
  data: {
    query: { /* query para 'tickets_jira' */ }
  }
}
```

**Vantagens:**
- ✅ Dashboard pode ter widgets de múltiplos índices
- ✅ Cada widget mantém seu contexto
- ✅ Não depende de seletor global
- ✅ Queries sempre no índice correto

## 🔌 WebSocket - Colaboração Real-Time

### **Arquitetura WebSocket**

```
Cliente 1                 Backend (Socket.IO)           Cliente 2
   │                              │                          │
   ├─ Connect ──────────────────▶ │                          │
   │  ◀──────── Connected ────────┤                          │
   │                              │                          │
   ├─ join_dashboard ───────────▶ │                          │
   │  ◀──────── Joined ───────────┤                          │
   │                              │ ◀──── join_dashboard ────┤
   │                              ├────────── Joined ───────▶│
   │                              │                          │
   ├─ widget_added ──────────────▶ │                          │
   │                              ├─ broadcast ─────────────▶│
   │                              │  (widget_added)          │
   │                              │                          │
   │                              │ ◀──── widget_updated ────┤
   │ ◀─ broadcast ────────────────┤                          │
   │  (widget_updated)            │                          │
```

### **Eventos Suportados**

1. **`join_dashboard`**
   - Cliente entra em uma room do dashboard
   - Recebe atualizações desse dashboard

2. **`leave_dashboard`**
   - Cliente sai da room
   - Para de receber atualizações

3. **`widget_added`**
   - Broadcast quando widget é criado
   - Outros clientes adicionam automaticamente

4. **`widget_updated`**
   - Broadcast quando widget muda
   - Sincroniza mudanças entre usuários

5. **`widget_deleted`**
   - Broadcast quando widget é removido
   - Remove para todos

6. **`positions_updated`**
   - Broadcast quando layout muda (drag & drop)
   - Sincroniza posições

## 📊 Gráficos e Visualizações

### **Tipos Suportados**

1. **pie** - Gráfico de Pizza
2. **bar** - Gráfico de Barras
3. **line** - Gráfico de Linhas
4. **area** - Gráfico de Área
5. **scatter** - Gráfico de Dispersão
6. **metric** - Indicador Numérico
7. **table** - Tabela de Dados

### **PlotlyChart Component**

Responsável por renderizar visualizações:

```typescript
<PlotlyChart
  type={widget.type}
  data={widget.data.results}  // ← dados da query ES
  config={widget.data.config} // ← cores, layout
/>
```

**Processamento:**
- Formata labels (converte timestamps para datas)
- Aplica cores do tema atual
- Configura layout responsivo
- Desabilita mode bar (controles Plotly)

### **Formatação de Datas**

Timestamps são automaticamente convertidos:
```typescript
formatLabel(1730937600000) → "07/11/2025"
```

Detecta:
- Números > 1000000000000 (timestamp em ms)
- Strings que parseiam para timestamps

## 🔐 Segurança

### **Criptografia de Credenciais**

1. **Senhas Elasticsearch** (Fernet)
   ```python
   from cryptography.fernet import Fernet

   key = os.getenv("ENCRYPTION_KEY")
   f = Fernet(key)
   encrypted = f.encrypt(password.encode())
   ```

2. **API Keys LLM** (Fernet + PBKDF2)
   ```python
   # Key derivation
   kdf = PBKDF2HMAC(
       algorithm=hashes.SHA256(),
       length=32,
       salt=salt,
       iterations=100000
   )

   # Encryption
   key = base64.urlsafe_b64encode(kdf.derive(master_key))
   f = Fernet(key)
   encrypted = f.encrypt(api_key.encode())
   ```

### **Gestão de Keys**

- Master key em `.env`: `ENCRYPTION_KEY`
- Nunca retornada em APIs
- Descriptografada apenas internamente
- Salt único por registro (LLM providers)

## 🚀 Performance e Otimizações

### **Debouncing**

1. **Auto-save Dashboard**: 500ms após mudanças
2. **Widget Position Update**: 1000ms após drag

### **Caching**

1. **Widget Data**: last_updated timestamp
   - Se dados < 5s, não re-executa query
   - Evita queries duplicadas

2. **Theme Settings**: localStorage
   - Carrega instantaneamente

### **Lazy Loading**

1. **Widgets**: Query executada apenas quando necessário
2. **Índices ES**: Carregados sob demanda

### **WebSocket Reconnection**

- Reconexão automática em caso de queda
- Re-join no dashboard após reconectar
- Buffer de eventos durante desconexão

## 📦 Deploy e Infraestrutura

### **Requirements**

- **Frontend**: Node.js 18+, React 18, Vite
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy
- **Database**: PostgreSQL 14+
- **Cache** (opcional): Redis 7+
- **Search**: Elasticsearch 8+

### **Variáveis de Ambiente**

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/dashboard_ai

# Elasticsearch
ES_URL=http://localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=changeme

# Security
ENCRYPTION_KEY=<fernet-key>
SECRET_KEY=<jwt-secret>

# LLM
ANTHROPIC_API_KEY=sk-...
```

### **Migrations**

```bash
# Aplicar migrations
alembic upgrade head

# Criar nova migration
alembic revision --autogenerate -m "description"
```

## 🔍 Monitoramento e Logs

### **Logging Levels**

- **DEBUG**: Queries SQL, chamadas LLM
- **INFO**: Requisições API, eventos WebSocket
- **WARNING**: Falhas de conexão, retries
- **ERROR**: Exceções, falhas críticas

### **Métricas Importantes**

- Tempo de resposta de queries ES
- Taxa de acerto de cache
- Número de conexões WebSocket ativas
- Dashboards criados por dia
- Mensagens de chat processadas

## 📚 Referências

- **Frontend**: React 18, TypeScript, Zustand, Plotly.js
- **Backend**: FastAPI, SQLAlchemy, Socket.IO
- **Database**: PostgreSQL, Alembic
- **Search**: Elasticsearch Python Client
- **LLM**: Anthropic Claude, OpenAI, Databricks

---

**Versão**: 2.0.0
**Última Atualização**: 2025-11-07
**Autores**: Dashboard AI Team + Claude Code
