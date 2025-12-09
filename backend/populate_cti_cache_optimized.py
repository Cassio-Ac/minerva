"""
Optimized CTI Enrichment Cache Population

Pre-download and cache MITRE ATT&CK techniques for Malpedia actors.
Uses batching and delays to prevent Elasticsearch overload.

Run with:
    PYTHONPATH=/path/to/backend python3 populate_cti_cache_optimized.py
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

# Configuration
BATCH_SIZE = 10  # Process 10 actors at a time
DELAY_BETWEEN_ACTORS = 0.5  # 500ms delay between actors
DELAY_BETWEEN_BATCHES = 5  # 5 seconds delay between batches
MAX_ACTORS = None  # Set to number to limit (e.g., 100), or None for all


async def main():
    """Populate cache with batching and delays"""

    logger.info("=" * 80)
    logger.info("🚀 Optimized CTI Cache Population - Starting")
    logger.info("=" * 80)
    logger.info(f"⚙️ Configuration:")
    logger.info(f"   Batch size: {BATCH_SIZE}")
    logger.info(f"   Delay between actors: {DELAY_BETWEEN_ACTORS}s")
    logger.info(f"   Delay between batches: {DELAY_BETWEEN_BATCHES}s")
    logger.info(f"   Max actors: {MAX_ACTORS or 'All'}")
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
        logger.info("\n🔍 Fetching actors from Malpedia...")
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

        # Apply limit if configured
        if MAX_ACTORS:
            actors = actors[:MAX_ACTORS]

        total = len(actors)
        logger.info(f"✅ Found {total} actors to process\n")

        # Process stats
        enriched = 0
        cached = 0
        not_mapped = 0
        errors = 0

        # Process in batches
        for batch_idx in range(0, total, BATCH_SIZE):
            batch = actors[batch_idx:batch_idx + BATCH_SIZE]
            batch_num = (batch_idx // BATCH_SIZE) + 1
            total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

            logger.info(f"\n{'='*80}")
            logger.info(f"📦 Batch {batch_num}/{total_batches} (actors {batch_idx+1}-{min(batch_idx+BATCH_SIZE, total)})")
            logger.info(f"{'='*80}")

            for i, actor in enumerate(batch, start=batch_idx + 1):
                actor_name = actor['name']

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
                    else:
                        # Enrich and cache
                        techniques = await cache_service.enrich_and_cache_actor(actor_name)

                        if techniques and len(techniques) > 0:
                            logger.info(f"      ✓ Enriched: {len(techniques)} techniques")
                            enriched += 1
                        else:
                            logger.info(f"      ⚠ No MITRE mapping found")
                            not_mapped += 1

                    # Delay between actors
                    if i < total:
                        await asyncio.sleep(DELAY_BETWEEN_ACTORS)

                except Exception as e:
                    logger.error(f"      ✗ Error: {e}")
                    errors += 1
                    continue

            # Progress update after each batch
            processed = min(batch_idx + BATCH_SIZE, total)
            logger.info(f"\n📈 Progress: {processed}/{total} ({processed/total*100:.1f}%)")
            logger.info(f"   Enriched: {enriched} | Cached: {cached} | Not mapped: {not_mapped} | Errors: {errors}")

            # Delay between batches (except after last batch)
            if batch_idx + BATCH_SIZE < total:
                logger.info(f"⏸️ Waiting {DELAY_BETWEEN_BATCHES}s before next batch...")
                await asyncio.sleep(DELAY_BETWEEN_BATCHES)

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
        if total > 0:
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
