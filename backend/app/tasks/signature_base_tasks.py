"""
Celery Tasks for Signature Base Operations

Automated tasks for:
- YARA rules sync from Neo23x0/signature-base (1x/week)
- IOC sync (C2, hashes, filenames) (1x/week)
"""
from app.celery_app import celery_app
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.signature_base_tasks.sync_signature_base_yara")
def sync_signature_base_yara():
    """
    Sincroniza regras YARA do Signature Base

    Executa 1x/semana (Domingo 03:00 Brazil time)
    Processa ~730 arquivos YARA com milhares de regras
    """
    logger.info("Starting Signature Base YARA sync...")

    try:
        result = asyncio.run(_run_yara_sync())
        logger.info(f"Signature Base YARA sync completed: {result}")
        return {"status": "success", "time": datetime.utcnow().isoformat(), "stats": result}

    except Exception as e:
        logger.error(f"Signature Base YARA sync failed: {e}")
        return {"status": "failed", "error": str(e)}


async def _run_yara_sync():
    """Helper para executar sync de YARA de forma assíncrona"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.signature_base_sync_service import SignatureBaseSyncService

    # Criar nova engine para evitar problemas de event loop
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = SignatureBaseSyncService(session)
        stats = await service.sync_yara_rules()
        logger.info(f"YARA sync stats: {stats}")

    await engine.dispose()
    return stats


@celery_app.task(name="app.tasks.signature_base_tasks.sync_signature_base_iocs")
def sync_signature_base_iocs():
    """
    Sincroniza IOCs do Signature Base (C2, hashes, filenames)

    Executa 1x/semana (Domingo 04:00 Brazil time)
    """
    logger.info("Starting Signature Base IOC sync...")

    try:
        result = asyncio.run(_run_ioc_sync())
        logger.info(f"Signature Base IOC sync completed: {result}")
        return {"status": "success", "time": datetime.utcnow().isoformat(), "stats": result}

    except Exception as e:
        logger.error(f"Signature Base IOC sync failed: {e}")
        return {"status": "failed", "error": str(e)}


async def _run_ioc_sync():
    """Helper para executar sync de IOCs de forma assíncrona"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.signature_base_sync_service import SignatureBaseSyncService

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = SignatureBaseSyncService(session)
        stats = await service.sync_iocs()
        logger.info(f"IOC sync stats: {stats}")

    await engine.dispose()
    return stats


@celery_app.task(name="app.tasks.signature_base_tasks.sync_signature_base_all")
def sync_signature_base_all():
    """
    Sincroniza tudo do Signature Base (YARA + IOCs)

    Task manual para sincronização completa
    """
    logger.info("Starting full Signature Base sync...")

    try:
        yara_result = asyncio.run(_run_yara_sync())
        ioc_result = asyncio.run(_run_ioc_sync())

        result = {
            "yara": yara_result,
            "iocs": ioc_result,
        }

        logger.info(f"Full Signature Base sync completed: {result}")
        return {"status": "success", "time": datetime.utcnow().isoformat(), "stats": result}

    except Exception as e:
        logger.error(f"Full Signature Base sync failed: {e}")
        return {"status": "failed", "error": str(e)}


@celery_app.task(name="app.tasks.signature_base_tasks.get_signature_base_stats")
def get_signature_base_stats():
    """
    Retorna estatísticas das regras YARA e IOCs sincronizados
    """
    logger.info("Getting Signature Base stats...")

    try:
        result = asyncio.run(_get_stats())
        return {"status": "success", "stats": result}

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {"status": "failed", "error": str(e)}


async def _get_stats():
    """Helper para obter estatísticas"""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from app.core.config import settings
    from app.cti.services.signature_base_sync_service import SignatureBaseSyncService

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = SignatureBaseSyncService(session)
        stats = await service.get_stats()

    await engine.dispose()
    return stats
