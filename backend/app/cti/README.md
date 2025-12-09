# 🎯 CTI Module - Cyber Threat Intelligence

**Version**: 1.0.0
**Status**: In Development

---

## ⚠️ IMPORTANTE: Portas do Projeto

Este projeto usa **portas customizadas**. Ao criar documentação ou exemplos:

- ✅ Backend API: `http://localhost:8001` (NÃO 8000!)
- ✅ Swagger UI: `http://localhost:8001/docs`
- ✅ Frontend: `http://localhost:5174` (NÃO 5173!)

**📖 Consulte [`/PORTS_REFERENCE.md`](../../../PORTS_REFERENCE.md) para detalhes completos.**

---

## 📁 Estrutura Modular

Este módulo é **completamente isolado** do restante da aplicação. Pode ser desenvolvido, testado e mantido independentemente.

```
backend/app/cti/
├── __init__.py                 # Module initialization
├── README.md                   # This file
├── models/                     # CTI-specific models (se necessário)
│   ├── __init__.py
│   └── ...
├── schemas/                    # Pydantic schemas para CTI
│   ├── __init__.py
│   ├── actor.py               # Actor schemas
│   ├── family.py              # Malware family schemas
│   ├── technique.py           # ATT&CK technique schemas
│   └── misp.py                # MISP schemas (Phase 2)
├── services/                   # Business logic
│   ├── __init__.py
│   ├── malpedia_service.py    # Malpedia data access
│   ├── attack_service.py      # ATT&CK integration
│   ├── enrichment_service.py  # Data enrichment
│   └── misp_service.py        # MISP integration (Phase 2)
└── api/                        # API endpoints
    ├── __init__.py
    ├── actors.py              # Actor endpoints
    ├── families.py            # Family endpoints
    ├── techniques.py          # Technique endpoints
    └── dashboard.py           # Dashboard endpoints

backend/app/tasks/cti/
├── __init__.py
├── enrichment_tasks.py        # Celery tasks for enrichment
└── misp_tasks.py              # MISP sync tasks (Phase 2)
```

---

## 🔌 Integration Points

### 1. API Registration

**File**: `backend/app/main.py`

```python
# Add CTI router
from app.cti.api import actors, families, techniques, dashboard

app.include_router(actors.router, prefix="/api/v1/cti")
app.include_router(families.router, prefix="/api/v1/cti")
app.include_router(techniques.router, prefix="/api/v1/cti")
app.include_router(dashboard.router, prefix="/api/v1/cti")
```

### 2. Celery Tasks Registration

**File**: `backend/app/celery_app.py`

```python
# Import CTI tasks
from app.tasks.cti import enrichment_tasks, misp_tasks

# Tasks are auto-discovered, no additional config needed
```

### 3. Frontend Route

**File**: `frontend/src/App.tsx`

```typescript
// Add CTI route
import CTIDashboard from './pages/cti/CTIDashboard';

<Route path="/cti" element={<CTIDashboard />} />
```

---

## 🗄️ Data Sources

### Elasticsearch Indices

**Existing** (read-only):
- `malpedia_actors` - Threat actors
- `malpedia_families` - Malware families

**New** (created by CTI module):
- `cti_techniques` - ATT&CK techniques enriched data
- `cti_misp_iocs` - MISP IOCs (Phase 2)

---

## 🚀 Development Guidelines

### Adding New CTI Features

1. Create service in `services/`
2. Create schema in `schemas/`
3. Create API in `api/`
4. Register API in `main.py`
5. Update this README

### Testing

```bash
# Run CTI tests only
pytest backend/tests/cti/

# Run specific test
pytest backend/tests/cti/test_malpedia_service.py
```

### Environment Variables

**Required**:
```env
# Malpedia API (for enrichment)
MALPEDIA_API_KEY=your_api_key_here
MALPEDIA_API_URL=https://malpedia.caad.fkie.fraunhofer.de/api
```

**Optional** (Phase 2):
```env
# MISP Integration
MISP_URL=https://misp.instance.com
MISP_API_KEY=your_misp_key
MISP_VERIFY_SSL=true
```

---

## 📦 Dependencies

**Python packages** (add to `requirements.txt`):
```
mitreattack-python==3.0.3    # ATT&CK STIX data
pymisp==2.4.179              # MISP integration (Phase 2)
stix2==3.0.1                 # STIX format support
```

Install:
```bash
pip install mitreattack-python stix2
# pip install pymisp  # Phase 2
```

---

## 🎯 Implementation Phases

### Phase 1: ATT&CK Dashboard (Current)

**Week 1: Backend Foundation**
- ✅ Module structure created
- ⬜ Malpedia service (read actors/families)
- ⬜ ATT&CK service (load STIX data)
- ⬜ Enrichment service (add techniques to families)
- ⬜ Celery task for batch enrichment

**Week 2: API Layer**
- ⬜ Actors API (list, search, get by ID)
- ⬜ Families API (list, search, filter)
- ⬜ Techniques API (list, get by ID)
- ⬜ Dashboard API (aggregations, stats)

**Week 3: Frontend**
- ⬜ CTI dashboard page
- ⬜ Actor/family selection lists
- ⬜ ATT&CK matrix component
- ⬜ Technique details panel
- ⬜ Export functionality

### Phase 2: MISP Integration (Future)

- ⬜ MISP service
- ⬜ IOC storage in Elasticsearch
- ⬜ Sync tasks
- ⬜ IOC timeline UI
- ⬜ Correlation views

---

## 🔒 Security Considerations

1. **API Keys**: Store in environment variables, never commit
2. **Rate Limiting**: Implement on CTI endpoints
3. **Data Access**: Respect existing auth/permissions
4. **Input Validation**: Use Pydantic schemas
5. **CORS**: CTI endpoints follow main app CORS config

---

## 📊 Performance

### Caching Strategy

```python
# Cache actors/families (30 minutes)
@lru_cache(maxsize=100)
def get_actor(actor_id: str):
    ...

# Cache techniques (1 hour)
@lru_cache(maxsize=500)
def get_technique(technique_id: str):
    ...
```

### Elasticsearch Optimization

- Use `_source` filtering to reduce payload
- Implement pagination (default 20, max 100)
- Use aggregations for stats
- Create index aliases for versioning

---

## 🐛 Troubleshooting

### Common Issues

**1. Malpedia API 401 Unauthorized**
```
Solution: Check MALPEDIA_API_KEY in .env
```

**2. ATT&CK data not loading**
```
Solution: Run enrichment task to populate cti_techniques index
celery -A app.celery_app worker --loglevel=info -Q cti_enrichment
```

**3. Frontend can't connect to CTI API**
```
Solution: Verify CTI routers are registered in main.py
Check http://localhost:8000/docs for /api/v1/cti endpoints
```

---

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- [MISP Project](https://www.misp-project.org/)
- [Research Docs](../../docs/CTI_FEATURES_RESEARCH.md)

---

**Maintainer**: ADINT Team
**Last Updated**: 2025-11-19
