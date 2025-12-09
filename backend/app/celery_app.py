"""
Celery Application
Background task processing and scheduling for RSS collection
"""

from celery import Celery
from celery.schedules import crontab
import os

# Redis connection for Celery broker and backend
# Default to localhost for local development, redis:6379 for Docker
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "minerva",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.rss_tasks", "app.tasks.malpedia_tasks", "app.tasks.misp_tasks", "app.tasks.otx_tasks", "app.tasks.caveiratech_tasks", "app.tasks.signature_base_tasks"]
)

# Celery configuration
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="America/Sao_Paulo",  # UTC-3
    enable_utc=False,

    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        "master_name": "mymaster"
    },

    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,

    # Beat schedule (periodic tasks)
    beat_schedule={
        # RSS collection - every 2 hours
        "collect-rss-feeds": {
            "task": "app.tasks.rss_tasks.collect_all_rss_feeds",
            "schedule": crontab(minute=0, hour="*/2"),  # Every 2 hours (00:00, 02:00, 04:00, ...)
        },

        # Malpedia Library RSS/BibTeX - DISABLED (run on-demand only via API)
        # BibTeX is the full library (17k+ entries), download manually when needed
        # RSS available at /api/v1/malpedia-library/sync-now/rss
        # BibTeX available at /api/v1/malpedia-library/sync-now/bibtex

        # Malpedia enrichment - 1x per day (02:00 Brazil time)
        "enrich-malpedia-library": {
            "task": "app.tasks.malpedia_tasks.enrich_malpedia_library",
            "schedule": crontab(minute=0, hour=2),  # 02:00 AM
        },

        # MISP feeds sync - every 2 hours
        "sync-misp-feeds": {
            "task": "app.tasks.misp_tasks.sync_all_misp_feeds",
            "schedule": crontab(minute=0, hour="*/2"),  # Every 2 hours
        },

        # OTX pulse sync - 2x per day (09:00 and 21:00 Brazil time)
        "sync-otx-pulses": {
            "task": "app.tasks.otx_tasks.sync_otx_pulses",
            "schedule": crontab(minute=0, hour="9,21"),  # 09:00 and 21:00
        },

        # OTX bulk IOC enrichment - 1x per day (03:00 Brazil time)
        "bulk-enrich-iocs-otx": {
            "task": "app.tasks.otx_tasks.bulk_enrich_iocs",
            "schedule": crontab(minute=0, hour=3),  # 03:00 AM
        },

        # OTX to MISP export - 1x per day (04:00 Brazil time)
        "export-otx-pulses-to-misp": {
            "task": "app.tasks.otx_tasks.export_pulses_to_misp",
            "schedule": crontab(minute=0, hour=4),  # 04:00 AM
        },

        # Reset OTX daily usage counters - 1x per day (00:00 Brazil time)
        "reset-otx-daily-usage": {
            "task": "app.tasks.otx_tasks.reset_otx_daily_usage",
            "schedule": crontab(minute=0, hour=0),  # Midnight
        },

        # CaveiraTech crawler - 2x per day (10:00 and 22:00 Brazil time)
        "sync-caveiratech": {
            "task": "app.tasks.caveiratech_tasks.sync_caveiratech",
            "schedule": crontab(minute=0, hour="10,22"),  # 10:00 and 22:00
            "kwargs": {"max_pages": 10},  # Incremental sync (latest 10 pages)
        },

        # Signature Base YARA rules - 1x per day (05:00 Brazil time)
        # Neo23x0/signature-base is updated frequently with new detection rules
        "sync-signature-base-yara": {
            "task": "app.tasks.signature_base_tasks.sync_signature_base_yara",
            "schedule": crontab(minute=0, hour=5),  # Daily 05:00 AM
        },

        # Signature Base IOCs - 1x per day (05:30 Brazil time)
        "sync-signature-base-iocs": {
            "task": "app.tasks.signature_base_tasks.sync_signature_base_iocs",
            "schedule": crontab(minute=30, hour=5),  # Daily 05:30 AM
        },
    },
)

# Optional: Task annotations for rate limiting
celery_app.conf.task_annotations = {
    "app.tasks.rss_tasks.collect_all_rss_feeds": {"rate_limit": "1/m"},  # Max 1/min
}


if __name__ == "__main__":
    celery_app.start()
