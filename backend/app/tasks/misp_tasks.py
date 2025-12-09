"""
MISP Feed Synchronization Tasks
Periodic tasks for syncing IOCs from all available MISP feeds
"""

from celery import shared_task
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.core.config import settings
from app.cti.services.misp_feed_service import MISPFeedService
from app.cti.models.misp_feed import MISPFeed
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@shared_task(name="app.tasks.misp_tasks.sync_all_misp_feeds")
def sync_all_misp_feeds():
    """
    Celery task para sincronizar TODOS os feeds MISP disponíveis

    Agenda: A cada 2 horas
    Razão: Feeds MISP são atualizados frequentemente com novas ameaças
    """
    logger.info("🚀 Starting MISP feed synchronization (ALL feeds)...")

    try:
        # Run async function in sync context
        result = asyncio.run(_sync_all_feeds_async())
        logger.info("✅ MISP feed synchronization completed successfully")
        return result

    except Exception as e:
        logger.error(f"❌ MISP feed synchronization failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise


async def _sync_all_feeds_async():
    """
    Sincroniza TODOS os feeds MISP disponíveis (versão async)
    """
    # Criar engine async
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = MISPFeedService(session)

        # Sincronizar TODOS os feeds disponíveis (não apenas os configurados)
        available_feeds = service.FEEDS

        total_feeds = len(available_feeds)
        successful = 0
        failed = 0
        total_imported = 0
        results = []

        logger.info(f"📊 Processing {total_feeds} available MISP feeds")

        for feed_id, feed_info in available_feeds.items():
            feed_name = feed_info["name"]
            requires_auth = feed_info.get("requires_auth", False)

            # Skip feeds that require auth (OTX) - handled separately
            if requires_auth:
                logger.info(f"⏭️ Skipping {feed_name} (requires authentication)")
                continue

            try:
                logger.info(f"🔄 Syncing feed: {feed_name} ({feed_id})")

                # Check if feed exists in database, create if not
                feed_record = await service.get_feed_by_name(feed_name)
                if not feed_record:
                    feed_record = await service.create_feed({
                        "name": feed_name,
                        "feed_type": feed_id,
                        "url": feed_info["url"],
                        "is_active": True,
                    })
                    logger.info(f"📝 Created feed record: {feed_name}")

                feed_record_id = str(feed_record.id)

                # Fetch IOCs from the feed
                iocs = []
                limit = 5000  # Higher limit for scheduled sync

                if feed_id == "circl_osint":
                    iocs = service.fetch_circl_feed(limit=50)  # MISP events are heavy
                elif feed_id == "urlhaus":
                    iocs = service.fetch_urlhaus_feed(limit=limit)
                elif feed_id == "threatfox":
                    iocs = service.fetch_threatfox_feed(limit=limit)
                elif feed_id == "botvrij":
                    iocs = service.fetch_circl_feed(limit=30)  # Similar format to CIRCL
                elif feed_id == "openphish":
                    iocs = service.fetch_openphish_feed(limit=limit)
                elif feed_id == "serpro":
                    iocs = service.fetch_serpro_feed(limit=limit)
                elif feed_id == "bambenek_dga":
                    iocs = service.fetch_bambenek_dga_feed(limit=limit)
                elif feed_id == "emerging_threats":
                    iocs = service.fetch_emerging_threats_feed(limit=limit)
                elif feed_id == "alienvault_reputation":
                    iocs = service.fetch_alienvault_reputation_feed(limit=limit)
                elif feed_id == "sslbl":
                    iocs = service.fetch_sslbl_feed(limit=limit)
                elif feed_id == "digitalside":
                    iocs = service.fetch_digitalside_feed(limit=50)  # MISP events
                elif feed_id == "blocklist_de":
                    iocs = service.fetch_blocklist_de_feed(limit=limit)
                elif feed_id == "greensnow":
                    iocs = service.fetch_greensnow_feed(limit=limit)
                elif feed_id == "diamondfox_c2":
                    iocs = service.fetch_diamondfox_c2_feed(limit=limit)
                elif feed_id == "cins_badguys":
                    iocs = service.fetch_cins_badguys_feed(limit=limit)
                else:
                    logger.warning(f"⚠️ No fetch method for feed: {feed_id}")
                    continue

                if iocs:
                    # Import IOCs to database
                    imported = await service.import_iocs(iocs, feed_record_id)
                    total_imported += imported
                    successful += 1
                    results.append({
                        "feed": feed_name,
                        "status": "success",
                        "fetched": len(iocs),
                        "imported": imported
                    })
                    logger.info(f"✅ {feed_name}: {len(iocs)} fetched, {imported} imported")
                else:
                    results.append({
                        "feed": feed_name,
                        "status": "empty",
                        "fetched": 0,
                        "imported": 0
                    })
                    logger.warning(f"⚠️ {feed_name}: No IOCs fetched")

            except Exception as e:
                failed += 1
                results.append({
                    "feed": feed_name,
                    "status": "error",
                    "error": str(e)
                })
                logger.error(f"❌ Error syncing feed {feed_name}: {e}")
                continue

        # Log resumo
        summary = f"""
📊 MISP Sync Summary:
- Total feeds available: {total_feeds}
- Feeds synced: {successful}
- Feeds failed: {failed}
- Total IOCs imported: {total_imported}
- Timestamp: {datetime.now().isoformat()}
"""
        logger.info(summary)

    # Fechar engine
    await engine.dispose()

    return {
        "status": "completed",
        "total_feeds": total_feeds,
        "successful": successful,
        "failed": failed,
        "total_imported": total_imported,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }


@shared_task(name="app.tasks.misp_tasks.sync_single_feed")
def sync_single_feed(feed_type: str, limit: int = 1000):
    """
    Celery task para sincronizar um feed MISP específico

    Args:
        feed_type: ID do tipo de feed (ex: "urlhaus", "threatfox")
        limit: Número máximo de IOCs para buscar
    """
    logger.info(f"🚀 Starting sync for MISP feed: {feed_type}")

    try:
        result = asyncio.run(_sync_single_feed_async(feed_type, limit))
        logger.info(f"✅ MISP feed {feed_type} synchronized successfully")
        return result

    except Exception as e:
        logger.error(f"❌ MISP feed {feed_type} sync failed: {e}")
        raise


async def _sync_single_feed_async(feed_type: str, limit: int = 1000):
    """
    Sincroniza um feed MISP específico (versão async)
    """
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = MISPFeedService(session)

        # Get feed info
        if feed_type not in service.FEEDS:
            raise ValueError(f"Unknown feed type: {feed_type}")

        feed_info = service.FEEDS[feed_type]
        feed_name = feed_info["name"]

        # Get or create feed record
        feed_record = await service.get_feed_by_name(feed_name)
        if not feed_record:
            feed_record = await service.create_feed({
                "name": feed_name,
                "feed_type": feed_type,
                "url": feed_info["url"],
                "is_active": True,
            })

        feed_record_id = str(feed_record.id)

        # Fetch IOCs
        iocs = []
        if feed_type == "circl_osint":
            iocs = service.fetch_circl_feed(limit=min(limit, 100))
        elif feed_type == "urlhaus":
            iocs = service.fetch_urlhaus_feed(limit=limit)
        elif feed_type == "threatfox":
            iocs = service.fetch_threatfox_feed(limit=limit)
        elif feed_type == "openphish":
            iocs = service.fetch_openphish_feed(limit=limit)
        elif feed_type == "serpro":
            iocs = service.fetch_serpro_feed(limit=limit)
        elif feed_type == "bambenek_dga":
            iocs = service.fetch_bambenek_dga_feed(limit=limit)
        elif feed_type == "emerging_threats":
            iocs = service.fetch_emerging_threats_feed(limit=limit)
        elif feed_type == "alienvault_reputation":
            iocs = service.fetch_alienvault_reputation_feed(limit=limit)
        elif feed_type == "sslbl":
            iocs = service.fetch_sslbl_feed(limit=limit)
        elif feed_type == "digitalside":
            iocs = service.fetch_digitalside_feed(limit=min(limit, 100))
        elif feed_type == "blocklist_de":
            iocs = service.fetch_blocklist_de_feed(limit=limit)
        elif feed_type == "greensnow":
            iocs = service.fetch_greensnow_feed(limit=limit)
        elif feed_type == "diamondfox_c2":
            iocs = service.fetch_diamondfox_c2_feed(limit=limit)
        elif feed_type == "cins_badguys":
            iocs = service.fetch_cins_badguys_feed(limit=limit)

        # Import IOCs
        imported = 0
        if iocs:
            imported = await service.import_iocs(iocs, feed_record_id)
            logger.info(f"✅ {feed_name}: {len(iocs)} fetched, {imported} imported")

        result = {
            "feed": feed_name,
            "feed_type": feed_type,
            "status": "success",
            "fetched": len(iocs),
            "imported": imported,
            "timestamp": datetime.now().isoformat()
        }

    await engine.dispose()
    return result


# Quick sync task for manual triggering
@shared_task(name="app.tasks.misp_tasks.quick_sync_all_feeds")
def quick_sync_all_feeds():
    """
    Quick sync - fetch fewer IOCs per feed for faster initial population
    """
    logger.info("🚀 Starting QUICK MISP feed synchronization...")

    try:
        result = asyncio.run(_quick_sync_async())
        logger.info("✅ Quick MISP sync completed")
        return result
    except Exception as e:
        logger.error(f"❌ Quick MISP sync failed: {e}")
        raise


async def _quick_sync_async():
    """Quick sync with lower limits"""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = MISPFeedService(session)

        results = []
        total_imported = 0

        # Quick sync configuration (lower limits)
        quick_feeds = [
            ("urlhaus", 500),
            ("threatfox", 500),
            ("openphish", 500),
            ("serpro", 1000),
            ("emerging_threats", 1000),
            ("alienvault_reputation", 1000),
            ("sslbl", 300),
            ("blocklist_de", 1000),
            ("greensnow", 1000),
            ("diamondfox_c2", 200),
            ("cins_badguys", 1000),
            ("bambenek_dga", 500),
        ]

        for feed_type, limit in quick_feeds:
            try:
                feed_info = service.FEEDS.get(feed_type)
                if not feed_info:
                    continue

                feed_name = feed_info["name"]
                logger.info(f"🔄 Quick sync: {feed_name} (limit={limit})")

                # Get or create feed record
                feed_record = await service.get_feed_by_name(feed_name)
                if not feed_record:
                    feed_record = await service.create_feed({
                        "name": feed_name,
                        "feed_type": feed_type,
                        "url": feed_info["url"],
                        "is_active": True,
                    })

                # Fetch IOCs
                iocs = []
                if feed_type == "urlhaus":
                    iocs = service.fetch_urlhaus_feed(limit=limit)
                elif feed_type == "threatfox":
                    iocs = service.fetch_threatfox_feed(limit=limit)
                elif feed_type == "openphish":
                    iocs = service.fetch_openphish_feed(limit=limit)
                elif feed_type == "serpro":
                    iocs = service.fetch_serpro_feed(limit=limit)
                elif feed_type == "emerging_threats":
                    iocs = service.fetch_emerging_threats_feed(limit=limit)
                elif feed_type == "alienvault_reputation":
                    iocs = service.fetch_alienvault_reputation_feed(limit=limit)
                elif feed_type == "sslbl":
                    iocs = service.fetch_sslbl_feed(limit=limit)
                elif feed_type == "blocklist_de":
                    iocs = service.fetch_blocklist_de_feed(limit=limit)
                elif feed_type == "greensnow":
                    iocs = service.fetch_greensnow_feed(limit=limit)
                elif feed_type == "diamondfox_c2":
                    iocs = service.fetch_diamondfox_c2_feed(limit=limit)
                elif feed_type == "cins_badguys":
                    iocs = service.fetch_cins_badguys_feed(limit=limit)
                elif feed_type == "bambenek_dga":
                    iocs = service.fetch_bambenek_dga_feed(limit=limit)

                # Import
                if iocs:
                    imported = await service.import_iocs(iocs, str(feed_record.id))
                    total_imported += imported
                    results.append({"feed": feed_name, "imported": imported})
                    logger.info(f"✅ {feed_name}: {imported} imported")

            except Exception as e:
                logger.error(f"❌ Error in quick sync {feed_type}: {e}")
                continue

        logger.info(f"📊 Quick sync complete: {total_imported} total IOCs imported")

    await engine.dispose()

    return {
        "status": "completed",
        "total_imported": total_imported,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }
