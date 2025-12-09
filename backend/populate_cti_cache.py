"""
Populate CTI Enrichment Cache

Pre-download and cache MITRE ATT&CK techniques for all Malpedia actors.
This eliminates the wait time when users select actors for the first time.

Run with:
    PYTHONPATH=/path/to/backend python3 populate_cti_cache.py
"""

import asyncio
import logging
from app.cti.services.enrichment_cache_service import get_enrichment_cache_service
from app.db.elasticsearch import get_es_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Populate cache for all actors"""

    logger.info("=" * 80)
    logger.info("🚀 CTI Cache Population - Starting")
    logger.info("=" * 80)

    try:
        # Get cache service
        cache_service = get_enrichment_cache_service()

        # Get current cache stats
        logger.info("\n📊 Current cache stats:")
        stats = await cache_service.get_cache_stats()
        logger.info(f"   Index exists: {stats.get('index_exists', False)}")
        logger.info(f"   Total cached: {stats.get('total_cached', 0)}")

        # Get all actors from Malpedia
        logger.info("\n🔍 Fetching all actors from Malpedia...")
        es = await get_es_client()

        result = await es.search(
            index="malpedia_actors",
            body={
                "query": {"match_all": {}},
                "size": 10000,
                "_source": ["name", "aka"]
            }
        )

        actors = [hit['_source'] for hit in result['hits']['hits']]
        total = len(actors)

        logger.info(f"✅ Found {total} actors\n")

        # Process each actor
        enriched = 0
        cached = 0
        not_mapped = 0
        errors = 0

        for i, actor in enumerate(actors, 1):
            actor_name = actor['name']

            # Progress indicator
            if i % 10 == 0 or i == 1:
                logger.info(f"\n📈 Progress: {i}/{total} ({i/total*100:.1f}%)")

            try:
                logger.info(f"   [{i}/{total}] Processing: {actor_name}")

                # Check if already cached
                cached_techniques = await cache_service.get_cached_techniques(
                    actor_name,
                    max_age_hours=24
                )

                if cached_techniques is not None:
                    logger.info(f"      ✓ Already cached: {len(cached_techniques)} techniques")
                    cached += 1
                    continue

                # Enrich and cache
                techniques = await cache_service.enrich_and_cache_actor(actor_name)

                if techniques and len(techniques) > 0:
                    logger.info(f"      ✓ Enriched: {len(techniques)} techniques")
                    enriched += 1
                else:
                    logger.info(f"      ⚠ No MITRE mapping found")
                    not_mapped += 1

            except Exception as e:
                logger.error(f"      ✗ Error: {e}")
                errors += 1
                continue

        # Final stats
        logger.info("\n" + "=" * 80)
        logger.info("✅ Cache Population Complete!")
        logger.info("=" * 80)
        logger.info(f"\n📊 Summary:")
        logger.info(f"   Total actors:        {total}")
        logger.info(f"   Already cached:      {cached}")
        logger.info(f"   Newly enriched:      {enriched}")
        logger.info(f"   Not mapped:          {not_mapped}")
        logger.info(f"   Errors:              {errors}")
        logger.info(f"   Success rate:        {(enriched + cached)/total*100:.1f}%")

        # Final cache stats
        logger.info("\n📊 Final cache stats:")
        final_stats = await cache_service.get_cache_stats()
        logger.info(f"   Total cached:        {final_stats.get('total_cached', 0)}")

        logger.info("\n🎉 Done! Users will now experience instant highlighting.\n")

    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
