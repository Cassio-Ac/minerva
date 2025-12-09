# 🔄 MISP Feed Synchronization Schedule

**Status**: ✅ Implementado e ativo

---

## 📅 Frequências Configuradas

### MISP Feeds
- **Frequência**: 4x por dia
- **Horários**: 00:00, 06:00, 12:00, 18:00 (America/Sao_Paulo - UTC-3)
- **Intervalo**: A cada 6 horas
- **Razão**: Feeds MISP são atualizados frequentemente com novas ameaças e IOCs

### RSS Feeds (contexto)
- **Frequência**: 2x por dia
- **Horários**: 08:00, 20:00 (America/Sao_Paulo - UTC-3)

### Malpedia Enrichment (contexto)
- **Frequência**: 1x por dia
- **Horário**: 02:00 (America/Sao_Paulo - UTC-3)

---

## 🏗️ Arquitetura da Sincronização

### Task Celery: `sync_all_misp_feeds`

**Localização**: `app/tasks/misp_tasks.py`

**Processo**:
1. Busca todos os feeds MISP ativos no database
2. Para cada feed:
   - Baixa manifest.json do feed
   - Parse dos IOCs
   - Upsert na tabela `iocs` (evita duplicados)
   - Atualiza `last_synced_at` do feed
3. Log de resumo com estatísticas

**Logs gerados**:
```
🚀 Starting MISP feed synchronization...
📊 Found 15 active MISP feeds to sync
🔄 Syncing feed: URLhaus Malware URLs
✅ URLhaus Malware URLs: 123 IOCs imported
...
📊 MISP Sync Summary:
- Total feeds: 15
- Successful: 15
- Failed: 0
- Total IOCs imported: 1,234
✅ MISP feed synchronization completed successfully
```

---

## 📊 Feeds MISP Configurados

Total: **14 feeds ativos** (75% de cobertura dos feeds padrão MISP)

| Feed | Provider | Tipo | Descrição |
|------|----------|------|-----------|
| URLhaus | abuse.ch | URL | URLs distribuindo malware |
| ThreatFox | abuse.ch | Mixed | IOCs de malware (IPs, URLs, hashes) |
| OpenPhish | openphish.com | URL | URLs de phishing |
| DiamondFox C2 | Unit42 | URL | C2 panels DiamondFox |
| SSL Blacklist | abuse.ch | Hash | Fingerprints SSL de malware |
| GreenSnow | blocklist | IP | IPs maliciosos |
| blocklist.de | blocklist | IP | IPs atacantes |
| DigitalSide | DigitalSide | Mixed | Threat intelligence feed |
| Emerging Threats | ProofPoint | IP | IPs comprometidos |
| AlienVault | AlienVault | IP | IP reputation |
| **Feodo** | **abuse.ch** | **IP** | **Botnet C2 (Emotet, TrickBot)** ⭐ NOVO |
| **Malware Bazaar** | **abuse.ch** | **Hash** | **MD5/SHA256 malware samples** ⭐ NOVO |
| **PhishTank** | **PhishTank** | **URL** | **URLs phishing verificadas** ⭐ NOVO |
| **FireHOL Level 1** | **FireHOL** | **IP** | **IP ranges maliciosos** ⭐ NOVO |

---

## 🔧 Configuração Celery Beat

**Arquivo**: `app/celery_app.py`

```python
beat_schedule={
    "sync-misp-feeds": {
        "task": "app.tasks.misp_tasks.sync_all_misp_feeds",
        "schedule": crontab(minute=0, hour="0,6,12,18"),
    },
}
```

---

## 🚀 Uso Manual

### Sincronizar todos os feeds agora
```bash
# Via API (requer autenticação)
curl -X POST "http://localhost:8001/api/v1/cti/misp/feeds/sync-all" \
  -H "Authorization: Bearer $TOKEN"

# Via Celery task diretamente
cd backend
PYTHONPATH=$PWD venv/bin/celery -A app.celery_app call app.tasks.misp_tasks.sync_all_misp_feeds
```

### Sincronizar um feed específico
```bash
# Via API
curl -X POST "http://localhost:8001/api/v1/cti/misp/feeds/{feed_id}/sync" \
  -H "Authorization: Bearer $TOKEN"

# Via Celery task
cd backend
PYTHONPATH=$PWD venv/bin/celery -A app.celery_app call \
  app.tasks.misp_tasks.sync_single_feed --args='["feed-uuid-here"]'
```

---

## 📈 Monitoramento

### Via Logs
```bash
# Ver logs do Celery worker
tail -f /var/log/celery/worker.log | grep MISP

# Ver logs do Celery beat (scheduler)
tail -f /var/log/celery/beat.log | grep sync-misp-feeds
```

### Via Database
```sql
-- Ver última sincronização de cada feed
SELECT
  name,
  last_synced_at,
  NOW() - last_synced_at AS time_since_sync
FROM misp_feeds
WHERE is_active = true
ORDER BY last_synced_at DESC;

-- Ver IOCs importados nas últimas 24h
SELECT
  COUNT(*) as total,
  ioc_type,
  source
FROM iocs
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY ioc_type, source
ORDER BY total DESC;
```

### Via API
```bash
# Stats de IOCs
curl "http://localhost:8001/api/v1/cti/misp/iocs/stats" \
  -H "Authorization: Bearer $TOKEN"

# Listar feeds com última sync
curl "http://localhost:8001/api/v1/cti/misp/feeds?is_active=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

## ⚙️ Troubleshooting

### Sync não está rodando
```bash
# Verificar se Celery Beat está ativo
ps aux | grep celery.*beat

# Verificar schedule configurado
cd backend
PYTHONPATH=$PWD venv/bin/python3 -c "
from app.celery_app import celery_app
print(celery_app.conf.beat_schedule)
"
```

### Feed específico falhando
```bash
# Ver logs de erro
tail -f /var/log/celery/worker.log | grep "Error syncing feed"

# Testar manualmente
curl -X POST "http://localhost:8001/api/v1/cti/misp/feeds/{feed_id}/sync" \
  -H "Authorization: Bearer $TOKEN" -v
```

### Performance lenta
- Ajustar `worker_concurrency` em celery_app.py
- Considerar reduzir frequência (ex: 2x por dia)
- Adicionar índices na tabela `iocs` se necessário

---

## 📝 Próximos Passos

- [ ] Adicionar alertas quando sync falha
- [ ] Dashboard de monitoramento de feeds
- [ ] Métricas de qualidade dos feeds (taxa de duplicados, etc)
- [ ] Configuração de frequência por feed (alguns mais críticos)
- [ ] Retenção de IOCs antigos (cleanup de IOCs > 90 dias sem atividade)

---

**Última atualização**: 2025-01-21
**Mantido por**: Intelligence Platform Team
