# 🛠️ Plano de Refatoração - Dashboard AI v2.0

**Data:** 2025-11-06
**Score Atual:** 6.5/10
**Meta:** 8.5/10 (Production-ready)

---

## 📊 Resumo Executivo

O sistema está **funcional e testado** (MVP), mas precisa de **refinamento crítico** antes de produção. Principais gaps: logging excessivo, error handling fraco, sem autenticação, e falta de testes.

**Esforço Estimado Total:** 4-7 semanas

---

## 🔴 Sprint 1: Crítico (Semana 1-2)

### 1.1 Sistema de Logging Estruturado

**Problema:** 40+ `console.log` em produção com emojis

**Solução:**
```typescript
// frontend/src/utils/logger.ts
const isDev = import.meta.env.DEV;

export const logger = {
  debug: (message: string, ...args: any[]) => {
    if (isDev) console.log(`[DEBUG] ${message}`, ...args);
  },
  info: (message: string, ...args: any[]) => {
    if (isDev) console.info(`[INFO] ${message}`, ...args);
  },
  error: (message: string, ...args: any[]) => {
    console.error(`[ERROR] ${message}`, ...args);
    // TODO: Send to error tracking service (Sentry)
  },
  warn: (message: string, ...args: any[]) => {
    console.warn(`[WARN] ${message}`, ...args);
  },
};
```

**Arquivos a modificar:**
- ✅ Criar `frontend/src/utils/logger.ts`
- 🔄 Substituir em `dashboardStore.ts` (58 ocorrências)
- 🔄 Substituir em `websocket.ts` (25 ocorrências)
- 🔄 Substituir em `WidgetCard.tsx` (8 ocorrências)
- 🔄 Substituir em demais componentes

**Esforço:** 2-3 horas

---

### 1.2 Constantes de Configuração

**Problema:** Números mágicos espalhados pelo código

**Solução:**
```typescript
// frontend/src/constants/config.ts
export const TIMING = {
  AUTO_SAVE_DELAY: 500,         // Debounce for auto-save after widget add/remove
  POSITION_SAVE_DELAY: 1000,    // Debounce for drag-and-drop position save
  REFRESH_DELAY: 100,           // Delay before refreshing widgets after time range change
  WEBSOCKET_TIMEOUT: 20000,     // WebSocket connection timeout
  RECONNECT_INTERVAL: 5000,     // WebSocket reconnection interval
} as const;

export const GRID_LAYOUT = {
  COLS: 12,                     // Number of columns in dashboard grid
  ROW_HEIGHT: 60,               // Height of each grid row in pixels
  WIDGET_DEFAULT_WIDTH: 4,      // Default widget width in grid units
  WIDGET_DEFAULT_HEIGHT: 4,     // Default widget height in grid units
  WIDGET_MIN_WIDTH: 2,          // Minimum widget width
  WIDGET_MIN_HEIGHT: 3,         // Minimum widget height
} as const;

export const TIME_RANGE = {
  DEFAULT_PRESET: 'now-30d',    // Default time range
  DEFAULT_LABEL: 'Últimos 30 dias',
} as const;

export const API = {
  BASE_URL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  TIMEOUT: 30000,               // API request timeout
} as const;
```

**Arquivos a modificar:**
- ✅ Criar `frontend/src/constants/config.ts`
- 🔄 Importar em `dashboardStore.ts`
- 🔄 Importar em `ChatPanel.tsx`
- 🔄 Importar em `DashboardGrid.tsx`
- 🔄 Importar em `TimeRangePicker.tsx`

**Esforço:** 1-2 horas

---

### 1.3 Error Handling Robusto

**Problema:** `catch (error: any)` sem tratamento adequado

**Solução:**
```typescript
// frontend/src/utils/errorHandler.ts
export class AppError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const handleError = (error: unknown): AppError => {
  if (error instanceof AppError) {
    return error;
  }

  if (error instanceof Error) {
    return new AppError(error.message, 'UNKNOWN_ERROR');
  }

  if (typeof error === 'string') {
    return new AppError(error, 'STRING_ERROR');
  }

  return new AppError('An unexpected error occurred', 'GENERIC_ERROR');
};

// Usage in stores
try {
  await api.getDashboard(dashboardId);
} catch (error) {
  const appError = handleError(error);
  logger.error('Failed to load dashboard:', appError);
  set({
    error: appError.message,
    errorCode: appError.code
  });
}
```

**Arquivos a modificar:**
- ✅ Criar `frontend/src/utils/errorHandler.ts`
- 🔄 Atualizar `dashboardStore.ts` (5 catch blocks)
- 🔄 Atualizar `ChatPanel.tsx` (2 catch blocks)
- 🔄 Atualizar `DashboardEditor.tsx` (3 catch blocks)

**Esforço:** 3-4 horas

---

### 1.4 Debounce no Auto-save

**Problema:** Múltiplos `setTimeout` sem cancelamento

**Solução:**
```typescript
// frontend/src/stores/dashboardStore.ts
import { debounce } from 'lodash-es';

export const useDashboardStore = create<DashboardStore>((set, get) => {
  // Create debounced save function outside store
  const debouncedSave = debounce(() => {
    const state = get();
    if (state.currentDashboard) {
      api.updateDashboard(state.currentDashboard.id, {
        widgets: state.widgets,
      }).catch((error) => {
        const appError = handleError(error);
        logger.error('Auto-save failed:', appError);
      });
    }
  }, TIMING.AUTO_SAVE_DELAY);

  return {
    // ...

    addWidget: (widget, skipBroadcast = false) => {
      set((state) => ({
        widgets: [...state.widgets, widget],
      }));

      if (!skipBroadcast) {
        debouncedSave();
      }
    },

    updateWidgetPosition: (widgetId, position, skipBroadcast = false) => {
      set((state) => ({
        widgets: state.widgets.map((w) =>
          w.id === widgetId
            ? { ...w, position, metadata: { ...w.metadata, updated_at: new Date().toISOString() } }
            : w
        ),
      }));

      if (!skipBroadcast) {
        debouncedSave();
      }
    },

    removeWidget: (widgetId, skipBroadcast = false) => {
      set((state) => ({
        widgets: state.widgets.filter((w) => w.id !== widgetId),
      }));

      if (!skipBroadcast) {
        debouncedSave();
      }
    },
  };
});
```

**Arquivos a modificar:**
- 🔄 `dashboardStore.ts` - Implementar debounce
- 🔄 `package.json` - Adicionar `lodash-es`

**Esforço:** 1 hora

---

### 1.5 Autenticação Básica (Backend)

**Problema:** Endpoints públicos sem autenticação

**Solução:**
```python
# backend/app/core/security.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta

SECRET_KEY = "your-secret-key-here"  # Move to .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

# Usage in endpoints
from app.core.security import get_current_user

@router.get("/dashboards")
async def list_dashboards(
    current_user: str = Depends(get_current_user)
):
    # Only return dashboards owned by current_user
    ...
```

**Arquivos a criar/modificar:**
- ✅ Criar `backend/app/core/security.py`
- ✅ Criar `backend/app/api/v1/auth.py` (login, register)
- 🔄 Adicionar dependency em todos endpoints sensíveis
- 🔄 Adicionar `user_id` ao modelo Dashboard/Widget

**Esforço:** 1 dia (8 horas)

---

## 🟡 Sprint 2: Importante (Semana 3-4)

### 2.1 Quebrar Funções Grandes

**Problema:** `llm_service.py` tem função com 300+ linhas

**Solução:**
```python
# backend/app/services/llm_service.py

class LLMService:
    async def process_message(self, request: ChatRequest) -> ChatResponse:
        """Main orchestration - delegates to specialized methods"""
        if self.llm_available:
            return await self._process_with_llm(request)
        return await self._process_with_mock(request)

    async def _process_with_llm(self, request: ChatRequest) -> ChatResponse:
        """Process using real LLM"""
        knowledge_base = await self._build_knowledge_base(request.index)
        system_prompt = self._build_system_prompt(request, knowledge_base)
        llm_response = await self._call_llm(system_prompt, request.message)
        return self._format_response(llm_response)

    async def _build_knowledge_base(self, index: str) -> str:
        """Build index knowledge base from mapping"""
        mapping = await self.es_service.get_index_mapping(index)
        return self._format_mapping_for_llm(mapping)

    def _build_system_prompt(
        self,
        request: ChatRequest,
        knowledge_base: str
    ) -> str:
        """Construct system prompt with context"""
        # 50 lines focused on prompt building
        ...

    async def _call_llm(self, system: str, message: str) -> Dict:
        """Call LLM API and parse response"""
        # 30 lines focused on LLM call
        ...

    def _format_response(self, llm_result: Dict) -> ChatResponse:
        """Format LLM result into ChatResponse"""
        # 40 lines focused on response formatting
        ...
```

**Benefícios:**
- Cada função tem < 50 linhas
- Fácil de testar individualmente
- Fácil de entender responsabilidades

**Esforço:** 4-6 horas

---

### 2.2 Extrair Componentes Grandes

**Problema:** `ESServersManager.tsx` tem 490 linhas

**Solução:**
```
frontend/src/pages/ESServersManager/
  ├── index.tsx                   # 80 lines - orchestration
  ├── components/
  │   ├── ServerList.tsx          # 100 lines - list UI
  │   ├── ServerCard.tsx          # 60 lines - individual card
  │   ├── AddServerModal.tsx      # 150 lines - modal form
  │   └── TestConnection.tsx      # 40 lines - test button
  ├── hooks/
  │   ├── useESServers.ts         # 80 lines - CRUD operations
  │   └── useServerValidation.ts  # 40 lines - form validation
  └── types.ts                    # 30 lines - local types
```

**Esforço:** 6-8 horas

---

### 2.3 Error Boundaries (React)

**Problema:** Sem error boundaries para capturar crashes

**Solução:**
```typescript
// frontend/src/components/ErrorBoundary.tsx
import React, { Component, ErrorInfo, ReactNode } from 'react';
import { logger } from '@/utils/logger';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    logger.error('React Error Boundary caught error:', error, errorInfo);
    // TODO: Send to error tracking service
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-red-600 mb-4">
              Algo deu errado
            </h1>
            <p className="text-gray-600 mb-4">
              {this.state.error?.message || 'Erro desconhecido'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-blue-600 text-white rounded"
            >
              Recarregar Página
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Usage in App.tsx
function App() {
  return (
    <ErrorBoundary>
      <Router>
        <Routes>
          {/* ... */}
        </Routes>
      </Router>
    </ErrorBoundary>
  );
}
```

**Esforço:** 2 horas

---

### 2.4 Testes Unitários (Backend)

**Problema:** 0% de cobertura de testes

**Solução:**
```python
# backend/tests/services/test_llm_service.py
import pytest
from app.services.llm_service import LLMService
from app.schemas.chat import ChatRequest

@pytest.fixture
def llm_service():
    return LLMService()

@pytest.mark.asyncio
async def test_process_message_with_mock(llm_service):
    """Test mock processing when LLM not available"""
    request = ChatRequest(
        message="Show me a pie chart",
        index="test-index",
    )

    response = await llm_service.process_message(request)

    assert response.explanation
    assert response.widget is not None
    assert response.widget.type in ['pie', 'bar', 'line']

@pytest.mark.asyncio
async def test_build_knowledge_base(llm_service):
    """Test knowledge base generation from mapping"""
    mapping = {
        "properties": {
            "timestamp": {"type": "date"},
            "message": {"type": "text"},
        }
    }

    kb = llm_service._format_mapping_for_llm(mapping)

    assert "timestamp" in kb
    assert "DATE" in kb
    assert "message" in kb

# Run with: pytest backend/tests/ -v
```

**Esforço:** 2-3 dias (16-24 horas)

---

### 2.5 Validação de Input (Backend)

**Problema:** Queries ES passadas sem validação

**Solução:**
```python
# backend/app/core/validators.py
from typing import Dict, Any
from fastapi import HTTPException

ALLOWED_QUERY_KEYS = {
    "query", "aggs", "size", "from", "sort", "_source"
}

ALLOWED_QUERY_TYPES = {
    "match", "term", "terms", "range", "bool", "exists", "wildcard"
}

def validate_es_query(query: Dict[str, Any]) -> None:
    """Validate ES query structure to prevent injection"""

    # Check top-level keys
    invalid_keys = set(query.keys()) - ALLOWED_QUERY_KEYS
    if invalid_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid query keys: {invalid_keys}"
        )

    # Validate query structure
    if "query" in query:
        _validate_query_clause(query["query"])

    # Validate aggs structure
    if "aggs" in query:
        _validate_aggs_clause(query["aggs"])

def _validate_query_clause(clause: Dict[str, Any]) -> None:
    """Recursively validate query clause"""
    for query_type, query_body in clause.items():
        if query_type not in ALLOWED_QUERY_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Query type '{query_type}' not allowed"
            )

        # Recursive validation for bool queries
        if query_type == "bool" and isinstance(query_body, dict):
            for bool_key in ["must", "should", "filter", "must_not"]:
                if bool_key in query_body:
                    clauses = query_body[bool_key]
                    if isinstance(clauses, list):
                        for sub_clause in clauses:
                            _validate_query_clause(sub_clause)

# Usage in endpoint
from app.core.validators import validate_es_query

@router.post("/execute")
async def execute_query(request: ExecuteQueryRequest):
    validate_es_query(request.query)  # Validate before execution
    result = await es_service.execute_query(...)
    return result
```

**Esforço:** 4-6 horas

---

## 🟢 Sprint 3: Melhorias (Semana 5-6)

### 3.1 Testes E2E (Frontend)

**Solução:** Playwright
```typescript
// frontend/e2e/dashboard.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Dashboard Editor', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:5173');
  });

  test('should create widget via chat', async ({ page }) => {
    // Select server and index
    await page.click('[data-testid="server-selector"]');
    await page.click('text=Local Elasticsearch');

    await page.click('[data-testid="index-selector"]');
    await page.click('text=vazamentos');

    // Open chat
    await page.click('[data-testid="chat-toggle"]');

    // Send message
    await page.fill('[data-testid="chat-input"]', 'Show me a pie chart');
    await page.click('[data-testid="chat-send"]');

    // Wait for widget
    await expect(page.locator('[data-testid="widget-card"]')).toBeVisible();
  });

  test('should change time range and refresh widgets', async ({ page }) => {
    // Assume widget exists
    const initialDataCount = await page
      .locator('[data-testid="widget-data-count"]')
      .textContent();

    // Change time range
    await page.click('[data-testid="time-range-picker"]');
    await page.click('text=Últimos 7 dias');

    // Wait for refresh
    await page.waitForTimeout(500);

    const newDataCount = await page
      .locator('[data-testid="widget-data-count"]')
      .textContent();

    expect(newDataCount).not.toBe(initialDataCount);
  });
});
```

**Esforço:** 1-2 dias (8-16 horas)

---

### 3.2 Event Bus (Desacoplar WebSocket)

**Problema:** Dependência circular entre WebSocket e Store

**Solução:**
```typescript
// frontend/src/utils/eventBus.ts
type EventCallback = (...args: any[]) => void;

class EventBus {
  private events: Map<string, EventCallback[]> = new Map();

  on(event: string, callback: EventCallback) {
    if (!this.events.has(event)) {
      this.events.set(event, []);
    }
    this.events.get(event)!.push(callback);
  }

  off(event: string, callback: EventCallback) {
    const callbacks = this.events.get(event);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  emit(event: string, ...args: any[]) {
    const callbacks = this.events.get(event);
    if (callbacks) {
      callbacks.forEach((callback) => callback(...args));
    }
  }
}

export const eventBus = new EventBus();

// Usage in websocket.ts
import { eventBus } from '@/utils/eventBus';

socket.on('widget:added', (widget) => {
  eventBus.emit('widget:added', widget);
});

// Usage in dashboardStore.ts
import { eventBus } from '@/utils/eventBus';

eventBus.on('widget:added', (widget) => {
  get().addWidget(widget, true);  // skipBroadcast = true
});
```

**Esforço:** 3-4 horas

---

### 3.3 Performance Monitoring

**Solução:**
```typescript
// frontend/src/utils/performance.ts
export const measurePerformance = (
  name: string,
  fn: () => void | Promise<void>
) => {
  const start = performance.now();

  const result = fn();

  if (result instanceof Promise) {
    return result.finally(() => {
      const duration = performance.now() - start;
      logger.debug(`[PERF] ${name}: ${duration.toFixed(2)}ms`);
    });
  }

  const duration = performance.now() - start;
  logger.debug(`[PERF] ${name}: ${duration.toFixed(2)}ms`);
  return result;
};

// Usage
await measurePerformance('Refresh all widgets', async () => {
  await refreshAllWidgets();
});
```

**Esforço:** 2 horas

---

### 3.4 Storybook para Componentes

**Solução:**
```typescript
// frontend/src/components/WidgetCard.stories.tsx
import type { Meta, StoryObj } from '@storybook/react';
import { WidgetCard } from './WidgetCard';

const meta: Meta<typeof WidgetCard> = {
  title: 'Components/WidgetCard',
  component: WidgetCard,
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof WidgetCard>;

export const PieChart: Story = {
  args: {
    widget: {
      id: 'widget-1',
      title: 'Top 10 Categories',
      type: 'pie',
      position: { x: 0, y: 0, w: 4, h: 4 },
      data: {
        query: {},
        results: { total: 100 },
        config: {
          data: [
            { label: 'Category A', value: 30 },
            { label: 'Category B', value: 25 },
            { label: 'Category C', value: 20 },
          ],
        },
      },
      metadata: {
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        version: 1,
      },
    },
  },
};

export const Loading: Story = {
  args: {
    widget: {
      ...PieChart.args.widget,
      data: {
        query: {},
      },
    },
  },
};
```

**Esforço:** 1-2 dias (8-16 horas)

---

## 📈 Roadmap de Qualidade

```
Semana 1-2: Sprint 1 (Crítico)
├── Logging estruturado       ██████████ 100%
├── Constantes                ██████████ 100%
├── Error handling            ██████████ 100%
├── Debounce                  ██████████ 100%
└── Autenticação              ███████░░░  70%

Semana 3-4: Sprint 2 (Importante)
├── Quebrar funções           ████████░░  80%
├── Extrair componentes       ███████░░░  70%
├── Error boundaries          ██████████ 100%
├── Testes unitários          ████░░░░░░  40%
└── Validação input           ████████░░  80%

Semana 5-6: Sprint 3 (Melhorias)
├── Testes E2E                ███░░░░░░░  30%
├── Event bus                 ██████░░░░  60%
├── Performance monitor       ████████░░  80%
└── Storybook                 ██░░░░░░░░  20%

Score Esperado por Sprint:
- Após Sprint 1: 6.5 → 7.5
- Após Sprint 2: 7.5 → 8.2
- Após Sprint 3: 8.2 → 8.5
```

---

## 🎯 Métricas de Sucesso

### Antes (Atual)
- Console logs: 40+
- Error handling: Básico
- Code coverage: 0%
- Funções longas: 5+ com 200+ linhas
- Security: Sem auth

### Depois (Meta)
- Console logs: 0 em produção (todos via logger)
- Error handling: Robusto com tipos
- Code coverage: 60%+
- Funções longas: Máximo 50 linhas
- Security: JWT auth + validação

---

## 💰 Custo vs Benefício

| Refatoração | Esforço | Impacto | Prioridade |
|-------------|---------|---------|------------|
| Logging | 3h | Alto | 🔴 Crítico |
| Constantes | 2h | Médio | 🔴 Crítico |
| Error handling | 4h | Alto | 🔴 Crítico |
| Debounce | 1h | Alto | 🔴 Crítico |
| Autenticação | 8h | Alto | 🔴 Crítico |
| Quebrar funções | 6h | Médio | 🟡 Importante |
| Testes unitários | 24h | Alto | 🟡 Importante |
| Testes E2E | 16h | Médio | 🟢 Melhoria |
| Storybook | 16h | Baixo | 🟢 Melhoria |

**Total Sprint 1:** ~18 horas (2-3 dias)
**Total Sprint 2:** ~40 horas (5 dias)
**Total Sprint 3:** ~40 horas (5 dias)

**Total Geral:** ~98 horas (2.5 semanas com 1 dev)

---

## 🚀 Início Rápido

### Começar AGORA (30 minutos)

1. **Criar logger utility:**
```bash
# Crie o arquivo
touch frontend/src/utils/logger.ts

# Copie o código da seção 1.1
# Substitua 3-5 console.log como teste
```

2. **Criar constants:**
```bash
touch frontend/src/constants/config.ts

# Copie o código da seção 1.2
# Substitua 2-3 magic numbers como teste
```

3. **Git commit:**
```bash
git add .
git commit -m "refactor: add logger utility and config constants"
```

**Resultado:** Qualidade +0.3 pontos em 30 minutos! 🎉

---

## 📚 Recursos

### Ferramentas Recomendadas
- **Logging:** Winston, Pino (estruturado)
- **Error Tracking:** Sentry (produção)
- **Testing:** Jest + Playwright
- **Linting:** ESLint + Prettier (já configurado)
- **Type checking:** TypeScript strict mode
- **Pre-commit:** Husky + lint-staged

### Leitura Recomendada
- Clean Code (Robert C. Martin)
- Refactoring (Martin Fowler)
- React patterns: https://patterns.dev
- TypeScript best practices: https://typescript-eslint.io

---

**Documento criado em:** 2025-11-06
**Revisão sugerida:** A cada sprint (semanal)
