"""
Populate CTI Cache for Top APT Groups

Pre-download and cache MITRE ATT&CK techniques for the most important/commonly researched APT groups.
This provides instant highlighting for the most relevant threat actors.

Run with:
    PYTHONPATH=/path/to/backend python3 populate_top_apt_cache.py
"""

import asyncio
import logging
from app.cti.services.enrichment_cache_service import get_enrichment_cache_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Top APT groups to pre-cache (most commonly researched)
TOP_APT_GROUPS = [
    # Russian APTs
    "APT28", "APT29", "Turla", "Sandworm", "Gamaredon", "APT44",
    # Chinese APTs
    "APT1", "APT10", "APT40", "APT41", "Winnti Group", "Mustang Panda", "APT27",
    # North Korean APTs
    "Lazarus Group", "APT38", "Kimsuky", "Andariel",
    # Iranian APTs
    "APT33", "APT34", "APT35", "APT39", "Charming Kitten", "MuddyWater",
    # Middle East APTs
    "Gaza Cybergang", "Molerats",
    # Other Notable Groups
    "FIN7", "FIN8", "Carbanak", "Cobalt Group",
    "Wizard Spider", "GOLD SOUTHFIELD",
    "Silence",
    # Advanced Persistent Threats
    "Equation", "Regin", "The Dukes",
    # Southeast Asia
    "Naikon", "OceanLotus", "BRONZE UNION",
    # Additional Russian
    "Dragonfly", "Energetic Bear", "TEMP.Veles",
    # Additional Chinese
    "menuPass", "Stone Panda", "APT3", "APT12", "APT17", "APT19",
    # Additional North Korean
    "TEMP.Hermit",
    # Additional Iranian
    "TEMP.Zagros", "Rocket Kitten",
    # Cybercrime
    "TA505", "Carbanak", "FIN6"
]


async def main():
    """Populate cache for top APT groups"""

    logger.info("=" * 80)
    logger.info("🚀 Top APT Groups Cache Population - Starting")
    logger.info("=" * 80)
    logger.info(f"📋 Will process {len(TOP_APT_GROUPS)} top APT groups")
    logger.info("=" * 80)

    try:
        # Get cache service
        cache_service = get_enrichment_cache_service()

        # Get current cache stats
        logger.info("\n📊 Current cache stats:")
        stats = await cache_service.get_cache_stats()
        logger.info(f"   Index exists: {stats.get('index_exists', False)}")
        logger.info(f"   Total cached: {stats.get('total_cached', 0)}")

        total = len(TOP_APT_GROUPS)
        enriched = 0
        cached = 0
        not_found = 0
        not_mapped = 0
        errors = 0

        # Process each APT group
        for i, actor_name in enumerate(TOP_APT_GROUPS, 1):
            logger.info(f"\n[{i}/{total}] Processing: {actor_name}")

            try:
                # Check if already cached
                cached_techniques = await cache_service.get_cached_techniques(
                    actor_name,
                    max_age_hours=24
                )

                if cached_techniques is not None:
                    logger.info(f"   ✓ Already cached: {len(cached_techniques)} techniques")
                    cached += 1
                    continue

                # Enrich and cache
                techniques = await cache_service.enrich_and_cache_actor(actor_name)

                if techniques is None:
                    logger.info(f"   ⚠ Actor not found in Malpedia")
                    not_found += 1
                elif len(techniques) > 0:
                    logger.info(f"   ✓ Enriched: {len(techniques)} techniques")
                    enriched += 1
                else:
                    logger.info(f"   ⚠ No MITRE mapping found")
                    not_mapped += 1

                # Small delay to avoid overloading ES
                if i < total:
                    await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"   ✗ Error: {e}")
                errors += 1
                continue

            # Progress update every 10 actors
            if i % 10 == 0:
                logger.info(f"\n📈 Progress: {i}/{total} ({i/total*100:.1f}%)")
                logger.info(f"   Enriched: {enriched} | Cached: {cached} | Not found: {not_found} | Not mapped: {not_mapped} | Errors: {errors}")

        # Final stats
        logger.info("\n" + "=" * 80)
        logger.info("✅ Top APT Cache Population Complete!")
        logger.info("=" * 80)
        logger.info(f"\n📊 Summary:")
        logger.info(f"   Total APT groups:    {total}")
        logger.info(f"   Already cached:      {cached}")
        logger.info(f"   Newly enriched:      {enriched}")
        logger.info(f"   Not found in DB:     {not_found}")
        logger.info(f"   Not mapped:          {not_mapped}")
        logger.info(f"   Errors:              {errors}")
        logger.info(f"   Success rate:        {(enriched + cached)/total*100:.1f}%")

        # Final cache stats
        logger.info("\n📊 Final cache stats:")
        final_stats = await cache_service.get_cache_stats()
        logger.info(f"   Total cached:        {final_stats.get('total_cached', 0)}")

        logger.info("\n🎉 Done! Top APT groups now have instant highlighting.\n")

    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
