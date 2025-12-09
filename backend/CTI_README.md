# 🎯 CTI Module - Quick Reference

**Status**: ✅ Operacional | **Coverage**: 100% (864/864) | **Docs**: 10 arquivos

---

## 🚀 Quick Commands

### Daily Operations

```bash
# Sincronizar Malpedia (incremental)
PYTHONPATH=$PWD venv/bin/python3 sync_malpedia.py

# Enriquecer novos actors
PYTHONPATH=$PWD venv/bin/python3 populate_cti_cache_optimized.py

# LLM inference (se necessário)
PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py
```

### Health Check

```bash
# Verificar contagens
curl -s http://localhost:9200/malpedia_actors/_count | jq '.count'
curl -s http://localhost:9200/cti_enrichment_cache/_count | jq '.count'

# Status geral
curl -s http://localhost:8001/api/v1/cti/techniques/stats | jq
```

---

## 📚 Documentação

| Documento | Quando Usar |
|-----------|-------------|
| **[../ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md)** ⭐ | Executar operações, troubleshooting |
| **[../CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md)** | Entender arquitetura |
| **[../CTI_DOCUMENTATION_SUMMARY.md](../CTI_DOCUMENTATION_SUMMARY.md)** | Visão geral executiva |

---

## 🔧 Scripts Disponíveis

| Script | Função | Tempo Médio |
|--------|--------|-------------|
| `sync_malpedia.py` | Sincronização incremental | 2-5 min |
| `populate_cti_cache_optimized.py` | MITRE enrichment | 5 min |
| `enrich_missing_actors.py` | LLM inference | 30-40 min |
| `populate_top_apt_cache.py` | Top APTs only | 1 min |

---

## 📊 Métricas Atuais

- **Actors**: 864
- **Families**: 3,591
- **Enrichments**: 864 (100%)
- **MITRE Oficial**: 171 (19.8%)
- **LLM Inference**: 693 (80.2%)

---

## 🌐 API Endpoints

```
GET  /api/v1/cti/actors              # Lista actors
GET  /api/v1/cti/actors/{name}       # Detalhes
GET  /api/v1/cti/families            # Lista families
GET  /api/v1/cti/techniques          # Lista técnicas
GET  /api/v1/cti/techniques/stats    # Estatísticas
POST /api/v1/cti/enrich/{name}       # Enrichment manual
```

---

**Para mais detalhes**: [../ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md)
