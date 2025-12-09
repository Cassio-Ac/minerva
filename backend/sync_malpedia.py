#!/usr/bin/env python3
"""
Malpedia Synchronization Script

Script para sincronizar dados do Malpedia de forma incremental.
Pode ser executado manualmente ou via Celery task.

Usage:
    # Sincronizar tudo
    PYTHONPATH=/path/to/backend python3 sync_malpedia.py

    # Apenas atores
    PYTHONPATH=/path/to/backend python3 sync_malpedia.py --actors

    # Apenas famílias
    PYTHONPATH=/path/to/backend python3 sync_malpedia.py --families

Author: Angello Cassio
Date: 2025-11-19
"""

import asyncio
import argparse
import logging
import sys
from datetime import datetime

from app.services.malpedia_sync_service import sync_all_actors, sync_all_families

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main(sync_actors: bool = True, sync_families: bool = True):
    """
    Main synchronization function

    Args:
        sync_actors: Whether to sync actors
        sync_families: Whether to sync families
    """
    logger.info("\n" + "="*80)
    logger.info("🚀 MALPEDIA SYNCHRONIZATION")
    logger.info("="*80)
    logger.info(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)

    results = {}

    # Sync actors
    if sync_actors:
        try:
            logger.info("\n📥 Synchronizing ACTORS...")
            actor_stats = await sync_all_actors()
            results["actors"] = actor_stats

            if "error" not in actor_stats:
                logger.info(f"✅ Actors sync completed:")
                logger.info(f"   • New: {len(actor_stats['new'])}")
                logger.info(f"   • Updated: {len(actor_stats['updated'])}")
                logger.info(f"   • Unchanged: {actor_stats['unchanged']}")
                logger.info(f"   • Errors: {len(actor_stats['errors'])}")
            else:
                logger.error(f"❌ Actors sync failed: {actor_stats['error']}")
                return 1

        except Exception as e:
            logger.error(f"❌ Fatal error syncing actors: {e}", exc_info=True)
            return 1

    # Sync families
    if sync_families:
        try:
            logger.info("\n📥 Synchronizing FAMILIES...")
            family_stats = await sync_all_families()
            results["families"] = family_stats

            if family_stats.get("status") == "not_implemented":
                logger.warning("⚠️ Families sync not yet implemented")
            else:
                logger.info("✅ Families sync completed")

        except Exception as e:
            logger.error(f"❌ Fatal error syncing families: {e}", exc_info=True)
            return 1

    # Final summary
    logger.info("\n" + "="*80)
    logger.info("✅ SYNCHRONIZATION COMPLETE!")
    logger.info("="*80)
    logger.info(f"⏰ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Print actors to enrich
    if "actors" in results and len(results["actors"].get("new", [])) + len(results["actors"].get("updated", [])) > 0:
        actors_to_enrich = results["actors"]["new"] + results["actors"]["updated"]
        logger.info(f"\n💡 Next steps:")
        logger.info(f"   {len(actors_to_enrich)} actors need enrichment with MITRE ATT&CK")
        logger.info(f"   Run: python3 populate_cti_cache.py")

    logger.info("="*80 + "\n")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Synchronize Malpedia data incrementally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync everything
  python3 sync_malpedia.py

  # Sync only actors
  python3 sync_malpedia.py --actors

  # Sync only families
  python3 sync_malpedia.py --families
        """
    )

    parser.add_argument(
        "--actors",
        action="store_true",
        help="Sync only actors"
    )

    parser.add_argument(
        "--families",
        action="store_true",
        help="Sync only families"
    )

    args = parser.parse_args()

    # If no specific flag, sync both
    if not args.actors and not args.families:
        sync_actors = True
        sync_families = True
    else:
        sync_actors = args.actors
        sync_families = args.families

    try:
        exit_code = asyncio.run(main(sync_actors, sync_families))
        sys.exit(exit_code)

    except KeyboardInterrupt:
        logger.warning("\n\n⚠️ Interrupted by user")
        sys.exit(1)

    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)
