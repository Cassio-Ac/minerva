# Minerva CTI - Celery Tasks Architecture

## Overview

Minerva uses Celery for background task processing with Redis as broker/backend.
All tasks run on the `minerva-celery` systemd service with 4 concurrent workers.

**Timezone:** America/Sao_Paulo (UTC-3)

---

## Task Modules

| Module | File | Description |
|--------|------|-------------|
| RSS Tasks | `app/tasks/rss_tasks.py` | RSS feed collection from 40+ security sources |
| Malpedia Tasks | `app/tasks/malpedia_tasks.py` | Malpedia Library sync + Family/Actor sync to ES |
| MISP Tasks | `app/tasks/misp_tasks.py` | MISP feed synchronization (IOCs) |
| OTX Tasks | `app/tasks/otx_tasks.py` | AlienVault OTX pulse sync and enrichment |
| Signature Base | `app/tasks/signature_base_tasks.py` | Neo23x0 YARA rules and IOCs |
| CaveiraTech | `app/tasks/caveiratech_tasks.py` | Brazilian security news crawler |

---

## All Registered Tasks

### RSS Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `collect_all_rss_feeds` | Every 2h (00:00, 02:00...) | Collect from all 40+ RSS sources |
| `collect_category` | On-demand | Collect specific category |
| `collect_specific_sources` | On-demand | Collect from specific sources |

### Malpedia Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `sync_malpedia_library_rss` | On-demand | Sync library via RSS (incremental) |
| `sync_malpedia_library_bibtex` | On-demand | Sync library via BibTeX (full, 17k+ entries) |
| `sync_malpedia_library_full` | On-demand | Both RSS + BibTeX |
| `enrich_malpedia_library` | Daily 02:00 | LLM enrichment of library articles |
| `get_malpedia_library_stats` | On-demand | Get library statistics |
| `check_malpedia_status` | On-demand | Check enrichment checkpoint |
| **`sync_malpedia_families_to_es`** | On-demand | **Sync 3604 families from disk to ES** |
| **`sync_malpedia_actors_to_es`** | On-demand | **Sync 864 actors from disk to ES** |
| **`sync_malpedia_all_to_es`** | On-demand | **Sync both families + actors** |

### MISP Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `sync_all_misp_feeds` | Every 2h | Sync all configured MISP feeds |
| `sync_single_feed` | On-demand | Sync specific feed by ID |
| `quick_sync_all_feeds` | On-demand | Quick sync (skip existing) |

### OTX Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `sync_otx_pulses` | Daily 09:00, 21:00 | Sync pulses from AlienVault OTX |
| `bulk_enrich_iocs` | Daily 03:00 | Bulk IOC enrichment |
| `export_pulses_to_misp` | Daily 04:00 | Export pulses to MISP format |
| `reset_otx_daily_usage` | Daily 00:00 | Reset API usage counters |
| `test_otx_connection` | On-demand | Test OTX API connectivity |

### Signature Base Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `sync_signature_base_yara` | Daily 05:00 | Sync Neo23x0 YARA rules |
| `sync_signature_base_iocs` | Daily 05:30 | Sync Neo23x0 IOCs (C2, hashes) |
| `sync_signature_base_all` | On-demand | Sync both YARA + IOCs |
| `get_signature_base_stats` | On-demand | Get statistics |

### CaveiraTech Tasks
| Task | Schedule | Description |
|------|----------|-------------|
| `sync_caveiratech` | Daily 10:00, 22:00 | Crawl Brazilian security news |
| `full_sync_caveiratech` | On-demand | Full historical sync |
| `get_caveiratech_stats` | On-demand | Get crawler statistics |

---

## Beat Schedule (Automated Tasks)

```
┌──────────────────────────────────────────────────────────────────┐
│ MINERVA CELERY BEAT SCHEDULE (Timezone: America/Sao_Paulo)       │
├──────────────────────────────────────────────────────────────────┤
│ 00:00 │ reset-otx-daily-usage                                    │
│ 02:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 02:00 │ enrich-malpedia-library                                  │
│ 03:00 │ bulk-enrich-iocs-otx                                     │
│ 04:00 │ export-otx-pulses-to-misp, collect-rss-feeds             │
│ 05:00 │ sync-signature-base-yara                                 │
│ 05:30 │ sync-signature-base-iocs                                 │
│ 06:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 08:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 09:00 │ sync-otx-pulses                                          │
│ 10:00 │ sync-caveiratech, collect-rss-feeds, sync-misp-feeds     │
│ 12:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 14:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 16:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 18:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 20:00 │ collect-rss-feeds, sync-misp-feeds                       │
│ 21:00 │ sync-otx-pulses                                          │
│ 22:00 │ sync-caveiratech, collect-rss-feeds, sync-misp-feeds     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Data Sources & Elasticsearch Indices

### Malpedia Data Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     MALPEDIA DATA ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  External Source                    Disk Storage                        │
│  ┌──────────────┐                  ┌─────────────────────────────────┐  │
│  │ Malpedia API │ ─── enriched ──► │ /media/witcher/Expansion/       │  │
│  │ (3607 families)                 │   backend_minerva/MALPEDIA/     │  │
│  └──────────────┘                  │   ├── families_enriched/ (3604) │  │
│                                    │   └── actors_enriched/   (864)  │  │
│                                    └───────────────┬─────────────────┘  │
│                                                    │                    │
│                                                    ▼                    │
│                          Celery Tasks: sync_malpedia_families_to_es    │
│                                        sync_malpedia_actors_to_es      │
│                                                    │                    │
│                                                    ▼                    │
│                               ┌─────────────────────────────────────┐   │
│                               │      ELASTICSEARCH INDICES          │   │
│                               │  ┌─────────────────────────────┐    │   │
│                               │  │ malpedia_families (3604)    │    │   │
│                               │  │ - name, url, os, aka        │    │   │
│                               │  │ - actors, yara_rules        │    │   │
│                               │  │ - descricao (LLM enriched)  │    │   │
│                               │  │ - referencias               │    │   │
│                               │  └─────────────────────────────┘    │   │
│                               │  ┌─────────────────────────────┐    │   │
│                               │  │ malpedia_actors (864)       │    │   │
│                               │  │ - name, country, synonyms   │    │   │
│                               │  │ - families, urls            │    │   │
│                               │  └─────────────────────────────┘    │   │
│                               └─────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### YARA Rules Unified Index

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     YARA RULES UNIFIED INDEX                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────┐     ┌─────────────────────────────────────┐   │
│  │ Signature Base      │     │        cti_yara_rules               │   │
│  │ (Neo23x0)          ├────►│        UNIFIED INDEX                │   │
│  │ 5877 rules         │     │                                     │   │
│  └─────────────────────┘     │  Total: 6463 rules                 │   │
│                              │  - 5877 from Signature Base         │   │
│  ┌─────────────────────┐     │  - 586 from Malpedia               │   │
│  │ Malpedia YARA       │     │                                     │   │
│  │ (Fraunhofer)       ├────►│  486 unique malware families        │   │
│  │ 586 rules          │     │  with associated YARA rules         │   │
│  └─────────────────────┘     └─────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### All Elasticsearch Indices

| Index | Documents | Source | Description |
|-------|-----------|--------|-------------|
| `malpedia_families` | 3,604 | Malpedia API | Malware families enriched with LLM |
| `malpedia_actors` | 864 | Malpedia API | Threat actors with attributions |
| `malpedia_library` | ~17,000 | Malpedia BibTeX | Academic papers & reports |
| `cti_yara_rules` | 6,463 | Sig Base + Malpedia | Unified YARA detection rules |
| `cti_misp_iocs` | ~54,000+ | MISP Feeds | IOCs from threat feeds |
| `otx_pulses` | ~50+ | AlienVault OTX | Threat intelligence pulses |
| `otx_indicators` | ~54,000+ | AlienVault OTX | IOCs from OTX |
| `rss_articles` | ~10,000+ | RSS Feeds | Security news articles |
| `caveiratech_news` | ~500+ | CaveiraTech | Brazilian security news |

---

## Running Tasks Manually

### Via Celery CLI

```bash
# Sync Malpedia families from disk to ES
/var/www/minerva/backend/venv/bin/celery -A app.celery_app call app.tasks.malpedia_tasks.sync_malpedia_families_to_es

# Sync Malpedia actors from disk to ES
/var/www/minerva/backend/venv/bin/celery -A app.celery_app call app.tasks.malpedia_tasks.sync_malpedia_actors_to_es

# Sync both
/var/www/minerva/backend/venv/bin/celery -A app.celery_app call app.tasks.malpedia_tasks.sync_malpedia_all_to_es

# Sync Signature Base YARA rules
/var/www/minerva/backend/venv/bin/celery -A app.celery_app call app.tasks.signature_base_tasks.sync_signature_base_yara

# Sync MISP feeds
/var/www/minerva/backend/venv/bin/celery -A app.celery_app call app.tasks.misp_tasks.sync_all_misp_feeds
```

### Via Python

```python
from app.tasks.malpedia_tasks import sync_malpedia_families_to_es
result = sync_malpedia_families_to_es.delay()
print(result.get())  # Wait for result
```

---

## Service Management

```bash
# Celery Worker
sudo systemctl status minerva-celery
sudo systemctl restart minerva-celery
sudo journalctl -u minerva-celery -f

# Celery Beat (scheduler) - if enabled
sudo systemctl status minerva-celery-beat
sudo systemctl restart minerva-celery-beat

# Check registered tasks
/var/www/minerva/backend/venv/bin/celery -A app.celery_app inspect registered

# Check active tasks
/var/www/minerva/backend/venv/bin/celery -A app.celery_app inspect active

# Check scheduled tasks
/var/www/minerva/backend/venv/bin/celery -A app.celery_app inspect scheduled
```

---

## Configuration Files

| File | Description |
|------|-------------|
| `/var/www/minerva/backend/app/celery_app.py` | Celery app configuration |
| `/var/www/minerva/backend/app/tasks/*.py` | Task definitions |
| `/etc/systemd/system/minerva-celery.service` | Worker systemd service |
| `/etc/systemd/system/minerva-celery-beat.service` | Beat scheduler service |

---

## Environment Variables

Required in systemd service or `.env`:

```bash
DATABASE_URL=postgresql+asyncpg://minerva:MinervaDB2024@localhost:5432/minerva_db
REDIS_URL=redis://localhost:6379/0
ES_URL=https://localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=<password>
```

---

## Recent Changes (2025-12-09)

### Added Malpedia Disk-to-ES Sync Tasks

Three new tasks added to `malpedia_tasks.py`:

1. **`sync_malpedia_families_to_es`**
   - Reads from `/media/witcher/Expansion/backend_minerva/MALPEDIA/families_enriched/`
   - Indexes 3,604 enriched family JSONs to `malpedia_families` index
   - Incremental: skips existing documents

2. **`sync_malpedia_actors_to_es`**
   - Reads from `/media/witcher/Expansion/backend_minerva/MALPEDIA/actors_enriched/`
   - Indexes 864 enriched actor JSONs to `malpedia_actors` index
   - Incremental: skips existing documents

3. **`sync_malpedia_all_to_es`**
   - Runs both families and actors sync

### Sync Results (First Run)

```
FAMILIES SYNC:
- Total files: 3,604
- Previously existing: 1,000
- New documents sent: 2,604
- Errors: 0

ACTORS SYNC:
- Total files: 864
- Already synced: 864
- New documents sent: 0
- Errors: 0
```

---

*Last updated: 2025-12-09*
