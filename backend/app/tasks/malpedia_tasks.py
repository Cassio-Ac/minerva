"""
Malpedia Celery Tasks
Background tasks for Malpedia Library collection and enrichment

Tasks:
- sync_malpedia_library_rss: Sync via RSS feed (incremental, frequent)
- sync_malpedia_library_bibtex: Sync via BibTeX (full, weekly)
- sync_malpedia_library_full: Sync both sources
- enrich_malpedia_library: LLM enrichment of articles
- sync_malpedia_families_to_es: Sync enriched families from disk to ES
- sync_malpedia_actors_to_es: Sync enriched actors from disk to ES
"""

import logging
import asyncio
import sys
import json
import os
from pathlib import Path
from typing import Optional

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.celery_app import celery_app
from app.core.config import settings

logger = logging.getLogger(__name__)

# Malpedia enriched data directories
MALPEDIA_DATA_DIR = "/media/witcher/Expansion/backend_minerva/MALPEDIA"
FAMILIES_DIR = f"{MALPEDIA_DATA_DIR}/families_enriched"
ACTORS_DIR = f"{MALPEDIA_DATA_DIR}/actors_enriched"

# Elasticsearch indices
INDEX_FAMILIES = "malpedia_families"
INDEX_ACTORS = "malpedia_actors"


# ============================================================
# MALPEDIA LIBRARY COLLECTION TASKS (RSS + BibTeX)
# ============================================================

@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_library_rss", bind=True)
def sync_malpedia_library_rss(self):
    """
    Periodic task: Sync Malpedia Library via RSS feed

    Fetches latest library entries from RSS feed and indexes to Elasticsearch.
    Fast incremental sync - run frequently (2x/day).

    Returns:
        Sync stats
    """
    logger.info("Starting Malpedia Library RSS sync task")

    try:
        from app.services.malpedia_library_service import run_malpedia_library_rss_sync

        result = asyncio.run(run_malpedia_library_rss_sync())

        logger.info(f"Malpedia Library RSS sync completed: {result}")
        return result

    except Exception as e:
        logger.error(f"Malpedia Library RSS sync failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries), max_retries=3)


@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_library_bibtex", bind=True)
def sync_malpedia_library_bibtex(self):
    """
    Periodic task: Sync Malpedia Library via BibTeX download

    Downloads complete BibTeX bibliography and indexes to Elasticsearch.
    Full sync - run less frequently (1x/week).

    Returns:
        Sync stats
    """
    logger.info("Starting Malpedia Library BibTeX sync task")

    try:
        from app.services.malpedia_library_service import run_malpedia_library_bibtex_sync

        result = asyncio.run(run_malpedia_library_bibtex_sync())

        logger.info(f"Malpedia Library BibTeX sync completed: {result}")
        return result

    except Exception as e:
        logger.error(f"Malpedia Library BibTeX sync failed: {e}")
        raise self.retry(exc=e, countdown=120 * (2 ** self.request.retries), max_retries=2)


@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_library_full", bind=True)
def sync_malpedia_library_full(self):
    """
    Full sync task: Sync Malpedia Library from both RSS and BibTeX

    Returns:
        Combined sync stats
    """
    logger.info("Starting FULL Malpedia Library sync task (RSS + BibTeX)")

    try:
        from app.services.malpedia_library_service import run_malpedia_library_full_sync

        result = asyncio.run(run_malpedia_library_full_sync())

        logger.info(f"Full Malpedia Library sync completed: {result}")
        return result

    except Exception as e:
        logger.error(f"Full Malpedia Library sync failed: {e}")
        raise self.retry(exc=e, countdown=180 * (2 ** self.request.retries), max_retries=2)


@celery_app.task(name="app.tasks.malpedia_tasks.get_malpedia_library_stats")
def get_malpedia_library_stats():
    """
    Get Malpedia Library stats from Elasticsearch

    Returns:
        Stats dict
    """
    logger.info("Getting Malpedia Library stats")

    try:
        from app.services.malpedia_library_service import MalpediaLibraryService

        async def _get_stats():
            service = MalpediaLibraryService()
            try:
                return await service.get_stats()
            finally:
                await service.close()

        result = asyncio.run(_get_stats())
        return result

    except Exception as e:
        logger.error(f"Error getting Malpedia Library stats: {e}")
        return {'error': str(e)}


# ============================================================
# MALPEDIA LIBRARY ENRICHMENT TASKS (LLM)
# ============================================================


@celery_app.task(name="app.tasks.malpedia_tasks.enrich_malpedia_library", bind=True)
def enrich_malpedia_library(self):
    """
    Periodic task: Enrich Malpedia Library articles with LLM

    Connects to EXTERNAL Elasticsearch (localhost:9200 from BHACK_2025 project)
    and enriches Malpedia Library BibTeX entries with:
    - LLM-generated summaries (2-3 sentences)
    - Actor mentions (APTs)
    - Malware family mentions

    Runs according to beat schedule (default: 1x per day at 02:00)
    """
    logger.info("🎯 Starting Malpedia Library enrichment task")

    try:
        # Import and run the async enrichment pipeline
        from malpedia_pipeline import enrich_all_articles

        # Run async pipeline in sync context
        result = asyncio.run(enrich_all_articles())

        logger.info(f"✅ Malpedia enrichment completed: {result}")
        return {
            "status": "success",
            "message": "Malpedia enrichment completed successfully",
            "result": result
        }

    except FileNotFoundError as e:
        logger.error(f"❌ Checkpoint or log file not found: {e}")
        # Don't retry for file errors
        return {
            "status": "error",
            "message": f"File error: {str(e)}"
        }

    except ConnectionError as e:
        logger.error(f"❌ Elasticsearch connection error: {e}")
        # Retry with exponential backoff for connection errors
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries), max_retries=3)

    except Exception as e:
        logger.error(f"❌ Malpedia enrichment failed: {e}", exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries), max_retries=2)


@celery_app.task(name="app.tasks.malpedia_tasks.check_malpedia_status", bind=True)
def check_malpedia_status(self):
    """
    Utility task: Check status of Malpedia enrichment

    Returns:
        dict: Current checkpoint status
    """
    logger.info("📊 Checking Malpedia enrichment status")

    try:
        import json
        from pathlib import Path

        checkpoint_file = Path("/app/malpedia_enrichment_checkpoint.json")

        if not checkpoint_file.exists():
            return {
                "status": "not_started",
                "message": "No checkpoint file found. Enrichment hasn't started yet."
            }

        with open(checkpoint_file, 'r') as f:
            checkpoint = json.load(f)

        return {
            "status": "in_progress" if checkpoint.get("total_processed", 0) > 0 else "not_started",
            "checkpoint": checkpoint
        }

    except Exception as e:
        logger.error(f"❌ Failed to check Malpedia status: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# ============================================================
# MALPEDIA FAMILIES/ACTORS SYNC FROM DISK TO ELASTICSEARCH
# ============================================================

def _get_es_client():
    """Get Elasticsearch client with credentials from settings"""
    from elasticsearch import Elasticsearch
    import urllib3

    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    es = Elasticsearch(
        [settings.ES_URL],
        basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD),
        verify_certs=False,
        ssl_show_warn=False
    )

    if not es.ping():
        raise ConnectionError("Cannot connect to Elasticsearch")

    return es


def _get_existing_ids(es, index_name):
    """Get all existing document IDs from an index"""
    ids_existentes = set()

    try:
        if not es.indices.exists(index=index_name):
            logger.info(f"Index '{index_name}' does not exist, will be created")
            return ids_existentes

        query = {"_source": False, "query": {"match_all": {}}}

        scroll = es.search(index=index_name, body=query, scroll='2m', size=10000)
        scroll_id = scroll['_scroll_id']
        hits = scroll['hits']['hits']

        for hit in hits:
            ids_existentes.add(str(hit['_id']))

        while len(hits) > 0:
            scroll = es.scroll(scroll_id=scroll_id, scroll='2m')
            scroll_id = scroll['_scroll_id']
            hits = scroll['hits']['hits']
            for hit in hits:
                ids_existentes.add(str(hit['_id']))

        es.clear_scroll(scroll_id=scroll_id)
        logger.info(f"Found {len(ids_existentes)} existing IDs in {index_name}")

    except Exception as e:
        logger.warning(f"Error checking existing IDs: {e}")

    return ids_existentes


@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_families_to_es", bind=True)
def sync_malpedia_families_to_es(self):
    """
    Sync Malpedia families from disk (enriched JSONs) to Elasticsearch

    Reads from /media/witcher/Expansion/backend_minerva/MALPEDIA/families_enriched/
    and indexes to malpedia_families index.

    Skips already existing documents (incremental sync).
    """
    from elasticsearch.helpers import streaming_bulk

    logger.info("="*70)
    logger.info("🚀 MALPEDIA FAMILIES SYNC - Starting")
    logger.info("="*70)

    if not os.path.exists(FAMILIES_DIR):
        logger.error(f"Directory not found: {FAMILIES_DIR}")
        return {"status": "error", "message": f"Directory not found: {FAMILIES_DIR}"}

    try:
        es = _get_es_client()
        logger.info("✅ Connected to Elasticsearch")

        # Get existing IDs
        ids_existentes = _get_existing_ids(es, INDEX_FAMILIES)

        # Get all JSON files
        arquivos = list(Path(FAMILIES_DIR).glob("*.json"))
        total = len(arquivos)
        logger.info(f"📁 Total files: {total}")

        if total == 0:
            return {"status": "warning", "message": "No files found"}

        enviados = 0
        pulados = 0
        erros = 0

        def gerar_acoes():
            nonlocal pulados
            for arquivo in arquivos:
                try:
                    with open(arquivo, 'r', encoding='utf-8') as f:
                        doc = json.load(f)

                    doc_id = arquivo.stem

                    if doc_id in ids_existentes:
                        pulados += 1
                        continue

                    # Clean empty date fields
                    if 'update' in doc and doc['update'] == '':
                        doc['update'] = None

                    yield {
                        '_index': INDEX_FAMILIES,
                        '_id': doc_id,
                        '_source': doc
                    }
                except Exception as e:
                    logger.error(f"Error reading {arquivo.name}: {e}")

        logger.info("🚀 Sending in bulk...")

        for success, info in streaming_bulk(es, gerar_acoes(), chunk_size=500, raise_on_error=False):
            if success:
                enviados += 1
                if enviados % 500 == 0:
                    logger.info(f"   ✅ {enviados} sent...")
            else:
                erros += 1

        logger.info("="*70)
        logger.info(f"📊 FAMILIES SYNC COMPLETE")
        logger.info(f"   Total: {total}")
        logger.info(f"   Skipped (existing): {pulados}")
        logger.info(f"   Sent: {enviados}")
        logger.info(f"   Errors: {erros}")
        logger.info("="*70)

        return {
            "status": "success",
            "total": total,
            "skipped": pulados,
            "sent": enviados,
            "errors": erros
        }

    except Exception as e:
        logger.error(f"❌ Families sync failed: {e}", exc_info=True)
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries), max_retries=3)


@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_actors_to_es", bind=True)
def sync_malpedia_actors_to_es(self):
    """
    Sync Malpedia actors from disk (enriched JSONs) to Elasticsearch

    Reads from /media/witcher/Expansion/backend_minerva/MALPEDIA/actors_enriched/
    and indexes to malpedia_actors index.

    Skips already existing documents (incremental sync).
    """
    from elasticsearch.helpers import streaming_bulk

    logger.info("="*70)
    logger.info("🚀 MALPEDIA ACTORS SYNC - Starting")
    logger.info("="*70)

    if not os.path.exists(ACTORS_DIR):
        logger.error(f"Directory not found: {ACTORS_DIR}")
        return {"status": "error", "message": f"Directory not found: {ACTORS_DIR}"}

    try:
        es = _get_es_client()
        logger.info("✅ Connected to Elasticsearch")

        # Get existing IDs
        ids_existentes = _get_existing_ids(es, INDEX_ACTORS)

        # Get all JSON files
        arquivos = list(Path(ACTORS_DIR).glob("*.json"))
        total = len(arquivos)
        logger.info(f"📁 Total files: {total}")

        if total == 0:
            return {"status": "warning", "message": "No files found"}

        enviados = 0
        pulados = 0
        erros = 0

        def gerar_acoes():
            nonlocal pulados
            for arquivo in arquivos:
                try:
                    with open(arquivo, 'r', encoding='utf-8') as f:
                        doc = json.load(f)

                    doc_id = arquivo.stem

                    if doc_id in ids_existentes:
                        pulados += 1
                        continue

                    yield {
                        '_index': INDEX_ACTORS,
                        '_id': doc_id,
                        '_source': doc
                    }
                except Exception as e:
                    logger.error(f"Error reading {arquivo.name}: {e}")

        logger.info("🚀 Sending in bulk...")

        for success, info in streaming_bulk(es, gerar_acoes(), chunk_size=500, raise_on_error=False):
            if success:
                enviados += 1
                if enviados % 500 == 0:
                    logger.info(f"   ✅ {enviados} sent...")
            else:
                erros += 1

        logger.info("="*70)
        logger.info(f"📊 ACTORS SYNC COMPLETE")
        logger.info(f"   Total: {total}")
        logger.info(f"   Skipped (existing): {pulados}")
        logger.info(f"   Sent: {enviados}")
        logger.info(f"   Errors: {erros}")
        logger.info("="*70)

        return {
            "status": "success",
            "total": total,
            "skipped": pulados,
            "sent": enviados,
            "errors": erros
        }

    except Exception as e:
        logger.error(f"❌ Actors sync failed: {e}", exc_info=True)
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries), max_retries=3)


@celery_app.task(name="app.tasks.malpedia_tasks.sync_malpedia_all_to_es", bind=True)
def sync_malpedia_all_to_es(self):
    """
    Sync both families and actors from disk to Elasticsearch
    """
    logger.info("🚀 Starting FULL Malpedia disk-to-ES sync")

    families_result = sync_malpedia_families_to_es.apply()
    actors_result = sync_malpedia_actors_to_es.apply()

    return {
        "status": "success",
        "families": families_result.result,
        "actors": actors_result.result
    }
