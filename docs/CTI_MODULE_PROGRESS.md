# 🚀 CTI Module - Progress Report

**Data**: 2025-11-19
**Status**: Phase 1 - Backend Foundation (In Progress)

---

## ✅ Completado

### 1. Estrutura Modular Criada

**Arquitetura completamente isolada e modular**:

```
intelligence-platform/
├── backend/app/cti/              ← NOVO MÓDULO CTI
│   ├── __init__.py
│   ├── README.md                 ← Documentação completa do módulo
│   ├── models/                   ← Futuros models (se necessário)
│   │   └── __init__.py
│   ├── schemas/                  ← Pydantic schemas ✅
│   │   ├── __init__.py
│   │   ├── actor.py              ← Schemas de actors ✅
│   │   ├── family.py             ← Schemas de families ✅
│   │   └── technique.py          ← Schemas de techniques ✅
│   ├── services/                 ← Business logic ✅
│   │   ├── __init__.py
│   │   └── malpedia_service.py   ← Acesso aos dados Malpedia ✅
│   └── api/                      ← API endpoints ✅
│       ├── __init__.py
│       └── actors.py             ← Endpoint de actors ✅
│
├── backend/app/tasks/cti/        ← Celery tasks (futuro)
│   └── __init__.py
│
├── frontend/src/pages/cti/       ← Frontend pages (futuro)
├── frontend/src/components/cti/  ← Frontend components (futuro)
└── frontend/src/services/cti/    ← Frontend services (futuro)
```

---

### 2. Backend - Schemas (Pydantic)

**Arquivo**: `backend/app/cti/schemas/actor.py`

✅ **ActorBase** - Schema base
✅ **ActorReference** - Referências/sources
✅ **ActorResponse** - Response com referências
✅ **ActorDetailResponse** - Response detalhado com técnicas
✅ **ActorListResponse** - Response de lista paginada

**Arquivo**: `backend/app/cti/schemas/family.py`

✅ **FamilyBase** - Schema base
✅ **FamilyReference** - Referências
✅ **YaraRule** - YARA rules
✅ **FamilyResponse** - Response com YARA e referências
✅ **AttackTechnique** - Técnicas ATT&CK
✅ **FamilyDetailResponse** - Response com técnicas
✅ **FamilyListResponse** - Response de lista
✅ **FamilyFilterRequest** - Request de filtros

**Arquivo**: `backend/app/cti/schemas/technique.py`

✅ **TacticInfo** - Informações de táticas
✅ **MitigationInfo** - Informações de mitigações
✅ **TechniqueBase** - Schema base
✅ **TechniqueResponse** - Response com mitigações
✅ **TechniqueDetailResponse** - Response detalhado
✅ **TechniqueListResponse** - Response de lista
✅ **TechniqueMatrixResponse** - Response para matriz
✅ **TechniqueHighlightRequest** - Request de highlight
✅ **TechniqueHighlightResponse** - Response de highlight

---

### 3. Backend - Services

**Arquivo**: `backend/app/cti/services/malpedia_service.py`

**Classe**: `MalpediaService`

**Métodos Implementados**:

#### Actors
- ✅ `get_actors()` - Lista atores com busca e paginação
- ✅ `get_actor_by_name()` - Busca ator por nome exato
- ✅ `get_actor_families()` - Lista famílias relacionadas ao ator

#### Families
- ✅ `get_families()` - Lista famílias com filtros (OS, busca, paginação)
- ✅ `get_family_by_name()` - Busca família por nome
- ✅ `get_families_by_names()` - Batch query de múltiplas famílias
- ✅ `get_family_actors()` - Lista atores que usam uma família
  - **Nota**: Computa relacionamento reverso (Family→Actor) porque campo `actors` está vazio

#### Statistics
- ✅ `get_stats()` - Estatísticas gerais (total actors, families, distribuição por OS, top actors)

**Features**:
- ✅ Conexão com Elasticsearch via `get_elasticsearch_client()`
- ✅ Suporte a múltiplos servidores ES (via `server_id`)
- ✅ Logging detalhado
- ✅ Tratamento de erros
- ✅ Paginação eficiente
- ✅ Exclusão de YARA content por padrão (reduz payload)
- ✅ Singleton pattern

---

### 4. Backend - API Endpoints

**Arquivo**: `backend/app/cti/api/actors.py`

**Router**: `/api/v1/cti/actors`

**Endpoints Implementados**:

#### `GET /api/v1/cti/actors`
- Lista atores com busca e paginação
- Query params: `search`, `page`, `page_size`, `server_id`
- Response: `ActorListResponse`
- Autenticação: ✅ Required (`get_current_user`)

#### `GET /api/v1/cti/actors/{actor_name}`
- Detalhes de um ator específico
- Path param: `actor_name`
- Query param: `server_id`
- Response: `ActorDetailResponse`
- Inclui: nome, aliases, descrição, famílias, referências, estatísticas
- Autenticação: ✅ Required

#### `GET /api/v1/cti/actors/{actor_name}/families`
- Lista famílias associadas a um ator
- Path param: `actor_name`
- Query param: `server_id`
- Response: `{actor, total, families}`
- Autenticação: ✅ Required

**Features**:
- ✅ Validação de entrada (Pydantic)
- ✅ Tratamento de erros (404, 500)
- ✅ Logging detalhado
- ✅ Documentação OpenAPI automática

---

### 5. Integration com Main App

**Arquivo**: `backend/app/main.py`

**Mudanças**:
```python
# Import isolado
from app.cti.api import actors as cti_actors  # CTI Module (isolated)

# Router registration isolado
# CTI Module (Cyber Threat Intelligence) - Modular & Isolated
app.include_router(cti_actors.router, prefix="/api/v1/cti", tags=["CTI"])
```

**Impacto**:
- ✅ ZERO mudanças no código existente
- ✅ Módulo completamente isolado
- ✅ Fácil de remover/desabilitar se necessário
- ✅ Tags separadas no Swagger UI

---

## 📚 Documentação Criada

1. ✅ **`backend/app/cti/README.md`**
   - Estrutura completa do módulo
   - Guia de integração
   - Guidelines de desenvolvimento
   - Troubleshooting

2. ✅ **`docs/CTI_FEATURES_RESEARCH.md`** (7000+ palavras)
   - Análise detalhada dos dados Malpedia
   - Opções de integração MITRE ATT&CK
   - Opções de integração MISP
   - Desafios técnicos e soluções

3. ✅ **`docs/CTI_FEATURES_SUMMARY.md`** (Executive Summary)
   - Resumo executivo
   - Decisões necessárias
   - Recomendações
   - Roadmap

4. ✅ **`docs/CTI_DASHBOARD_MOCKUP.md`** (UI/UX)
   - Mockup visual completo
   - Fluxos de usuário
   - Especificações de componentes

---

## 🧪 Como Testar (Quando Backend Rodando)

### 1. Swagger UI

Acesse: `http://localhost:8001/docs`

Procure pela seção **"CTI"** na lista de tags.

### 2. Test Manual com curl

**Listar atores**:
```bash
# Login primeiro para obter token
TOKEN=$(curl -s -X POST "http://localhost:8001/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

# Listar atores
curl -s "http://localhost:8001/api/v1/cti/actors?page=1&page_size=10" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Buscar actor
curl -s "http://localhost:8001/api/v1/cti/actors?search=Sandworm" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Detalhes de um actor
curl -s "http://localhost:8001/api/v1/cti/actors/Sandworm" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Famílias do actor
curl -s "http://localhost:8001/api/v1/cti/actors/Sandworm/families" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### 3. Response Examples

**Lista de atores** (`GET /api/v1/cti/actors`):
```json
{
  "total": 864,
  "actors": [
    {
      "name": "APT28",
      "aka": ["Fancy Bear", "Sofacy"],
      "explicacao": "Russian threat actor...",
      "familias_relacionadas": ["win.xagent", "win.zebrocy"],
      "url": "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28",
      "referencias": [...]
    }
  ],
  "page": 1,
  "page_size": 10
}
```

**Detalhes do ator** (`GET /api/v1/cti/actors/Sandworm`):
```json
{
  "name": "Sandworm",
  "aka": ["TeleBots", "Voodoo Bear"],
  "explicacao": "...",
  "familias_relacionadas": ["win.industroyer", "win.olympicdestroyer"],
  "url": "...",
  "referencias": [...],
  "total_families": 12,
  "total_techniques": 0,
  "techniques": []
}
```

---

## 🎯 Próximos Passos

### Imediato (Week 1 - Backend)

1. ⬜ **Criar Families API** (`backend/app/cti/api/families.py`)
   - `GET /api/v1/cti/families` - List families
   - `GET /api/v1/cti/families/{family_name}` - Family details
   - `GET /api/v1/cti/families/{family_name}/actors` - Actors using family
   - `GET /api/v1/cti/families/{family_name}/yara` - Get YARA rules

2. ⬜ **Criar ATT&CK Service** (`backend/app/cti/services/attack_service.py`)
   - Load MITRE ATT&CK STIX data
   - Methods: `get_techniques()`, `get_technique()`, `get_tactics()`, `get_matrix()`
   - Cache techniques in memory (LRU cache)

3. ⬜ **Criar Techniques API** (`backend/app/cti/api/techniques.py`)
   - `GET /api/v1/cti/techniques` - List techniques
   - `GET /api/v1/cti/techniques/{technique_id}` - Technique details
   - `GET /api/v1/cti/techniques/matrix` - Full matrix structure
   - `POST /api/v1/cti/techniques/highlight` - Highlight based on selection

4. ⬜ **Criar Enrichment Service** (`backend/app/cti/services/enrichment_service.py`)
   - Map Malpedia families to ATT&CK techniques
   - Use Malpedia API (requires API key)
   - Store enriched data in new ES index: `cti_techniques`

5. ⬜ **Criar Celery Task** (`backend/app/tasks/cti/enrichment_tasks.py`)
   - Batch enrichment of all 3,578 families
   - Run: `celery -A app.celery_app worker -Q cti_enrichment`

### Week 2 - Frontend Foundation

6. ⬜ **Criar CTI Service** (`frontend/src/services/cti/ctiService.ts`)
   - API client para endpoints CTI
   - Methods: `getActors()`, `getFamilies()`, `getTechniques()`, etc.

7. ⬜ **Criar CTI Dashboard Page** (`frontend/src/pages/cti/CTIDashboard.tsx`)
   - Layout com 3 colunas: Actors, Families, Matrix
   - State management para seleções
   - Integração com CTI service

8. ⬜ **Criar Selection Lists** (`frontend/src/components/cti/SelectionList.tsx`)
   - Componente reutilizável para actors/families
   - Search, filters, multi-select

9. ⬜ **Criar ATT&CK Matrix** (`frontend/src/components/cti/AttackMatrix.tsx`)
   - Visualização da matriz 14 tactics × 200 techniques
   - Highlight baseado em seleções
   - Hover tooltips

### Week 3 - Polish & Export

10. ⬜ **Criar Technique Details Panel** (`frontend/src/components/cti/TechniqueDetails.tsx`)
    - Painel lateral com detalhes da técnica
    - Lista de families/actors usando
    - Mitigations e detection

11. ⬜ **Implementar Export**
    - Export ATT&CK Navigator JSON
    - Export CSV (families, techniques)
    - Export PNG (matrix screenshot)

12. ⬜ **Testing & Documentation**
    - Unit tests (backend services)
    - Integration tests (API endpoints)
    - E2E tests (frontend)
    - Update documentation

---

## 💡 Vantagens da Arquitetura Modular

### ✅ Isolamento Completo
- Módulo CTI não interfere com código existente
- Pode ser desenvolvido, testado e deployado independentemente
- Fácil de desabilitar (remover 2 linhas de `main.py`)

### ✅ Manutenibilidade
- Código organizado por domínio (CTI)
- README específico do módulo
- Fácil onboarding de novos desenvolvedores

### ✅ Testabilidade
- Testes isolados em `backend/tests/cti/`
- Mocks fáceis (service layer separado)
- CI/CD pode rodar testes CTI separadamente

### ✅ Escalabilidade
- Fácil adicionar novas features (MISP, etc.)
- Pode virar microserviço se necessário
- Pode ter seu próprio rate limiting

### ✅ Documentação
- Documentação técnica no código
- README do módulo
- Research docs separados

---

## 🔧 Dependencies Necessárias

**Adicionar em `requirements.txt`**:
```
mitreattack-python==3.0.3    # ATT&CK STIX data
stix2==3.0.1                 # STIX format support
```

**Instalar**:
```bash
cd backend
pip install mitreattack-python stix2
```

---

## 📊 Status Overview

| Componente | Status | Progresso |
|-----------|--------|----------|
| **Estrutura de Pastas** | ✅ Complete | 100% |
| **Schemas (Pydantic)** | ✅ Complete | 100% |
| **Malpedia Service** | ✅ Complete | 100% |
| **Actors API** | ✅ Complete | 100% |
| **Integration (main.py)** | ✅ Complete | 100% |
| **Documentation** | ✅ Complete | 100% |
| **Families API** | ⬜ Pending | 0% |
| **ATT&CK Service** | ⬜ Pending | 0% |
| **Techniques API** | ⬜ Pending | 0% |
| **Enrichment** | ⬜ Pending | 0% |
| **Frontend** | ⬜ Pending | 0% |

**Overall Progress**: **~40%** (Backend Foundation Complete)

---

## 🚀 Ready to Continue!

O módulo CTI está com a base sólida criada. Quando o backend estiver rodando, você já pode testar os endpoints de actors:

```
http://localhost:8001/docs#/CTI
```

**Próximo passo recomendado**: Criar Families API endpoint.

---

**Documented with ❤️ for ADINT**
