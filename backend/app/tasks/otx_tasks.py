"""
Celery Tasks for OTX Operations

Automated tasks for:
- OTX Pulse sync (2x/day)
- Bulk IOC enrichment (1x/day)
- MISP export (1x/day)
"""
from app.celery_app import celery_app
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.otx_tasks.sync_otx_pulses")
def sync_otx_pulses():
    """
    Sincroniza pulses subscritos do OTX

    Executa 2x/dia: 09:00 e 21:00 (Brazil time)
    """
    logger.info("🔄 Starting scheduled OTX pulse sync...")

    try:
        asyncio.run(_run_pulse_sync())
        logger.info("✅ OTX pulse sync completed successfully")
        return {"status": "success", "time": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"❌ OTX pulse sync failed: {e}")
        return {"status": "failed", "error": str(e)}


async def _run_pulse_sync():
    """Helper para executar sync de pulses direto para Elasticsearch"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.otx_pulse_sync_service import OTXPulseSyncService

    # Criar nova engine para evitar problemas de event loop
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = OTXPulseSyncService(session)
        # Nova arquitetura: sync direto para Elasticsearch
        stats = await service.sync_to_elasticsearch(limit=100)
        logger.info(f"📊 ES Sync stats: pulses={stats.get('pulses_fetched', 0)}, created={stats.get('indicators_created', 0)}, updated={stats.get('indicators_updated', 0)}")

    await engine.dispose()
    return stats


@celery_app.task(name="app.tasks.otx_tasks.bulk_enrich_iocs")
def bulk_enrich_iocs():
    """
    DEPRECATED: Esta task usava tabelas PostgreSQL que foram removidas.

    Na nova arquitetura, os IOCs são enriquecidos durante o sync para Elasticsearch.
    """
    logger.warning("⚠️ bulk_enrich_iocs is DEPRECATED - IOCs are now enriched during ES sync")
    return {"status": "deprecated", "message": "Task deprecated - IOCs enriched during ES sync"}


async def _run_bulk_enrichment():
    """Helper para executar bulk enrichment de forma assíncrona"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.otx_bulk_enrichment_service import OTXBulkEnrichmentService

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = OTXBulkEnrichmentService(session)
        stats = await service.enrich_high_priority_batch(batch_size=200)
        logger.info(f"📊 Enrichment stats: {stats}")

    await engine.dispose()
    return stats


@celery_app.task(name="app.tasks.otx_tasks.export_pulses_to_misp")
def export_pulses_to_misp():
    """
    DEPRECATED: Esta task usava tabelas PostgreSQL que foram removidas.

    Na nova arquitetura, os dados OTX vão direto para Elasticsearch unified_iocs.
    """
    logger.warning("⚠️ export_pulses_to_misp is DEPRECATED - OTX data now goes directly to ES")
    return {"status": "deprecated", "message": "Task deprecated - OTX data goes directly to ES"}


async def _run_misp_export():
    """Helper para executar MISP export de forma assíncrona"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.otx_misp_exporter import OTXMISPExporter

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        exporter = OTXMISPExporter(session)
        stats = await exporter.export_pending_pulses(limit=20)
        logger.info(f"📊 Export stats: {stats}")

    await engine.dispose()
    return stats


@celery_app.task(name="app.tasks.otx_tasks.reset_otx_daily_usage")
def reset_otx_daily_usage():
    """
    Reseta contadores de uso diário das chaves OTX

    Executa 1x/dia: 00:00 (Brazil time)
    """
    logger.info("🔄 Resetting OTX daily usage counters...")

    try:
        asyncio.run(_run_reset_usage())
        logger.info("✅ OTX usage counters reset successfully")
        return {"status": "success", "time": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"❌ Reset usage counters failed: {e}")
        return {"status": "failed", "error": str(e)}


async def _run_reset_usage():
    """Helper para resetar contadores de forma assíncrona"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.otx_key_manager import OTXKeyManager

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        key_manager = OTXKeyManager(session)
        await key_manager.reset_daily_usage()
        logger.info("✅ All OTX key usage counters reset to 0")

    await engine.dispose()


# Manual task para teste rápido
@celery_app.task(name="app.tasks.otx_tasks.test_otx_connection")
def test_otx_connection():
    """
    Testa conexão com OTX API

    Task manual para validar que o sistema está funcionando
    """
    logger.info("🔍 Testing OTX connection...")

    try:
        asyncio.run(_test_connection())
        logger.info("✅ OTX connection test passed")
        return {"status": "success", "message": "OTX connection is working"}

    except Exception as e:
        logger.error(f"❌ OTX connection test failed: {e}")
        return {"status": "failed", "error": str(e)}


async def _test_connection():
    """Helper para testar conexão OTX"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.otx_key_manager import OTXKeyManager
    import requests

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        key_manager = OTXKeyManager(session)
        key = await key_manager.get_available_key()

        if not key:
            await engine.dispose()
            raise Exception("No OTX API keys available")

        # Testar via REST API (mais rapido que SDK)
        headers = {"X-OTX-API-KEY": key.api_key}
        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers,
            params={"limit": 1, "page": 1},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

    await engine.dispose()

    if data and 'results' in data:
        logger.info(f"✅ OTX API is responding. Found {len(data.get('results', []))} pulses.")
        return True
    else:
        raise Exception("OTX API returned no data")
