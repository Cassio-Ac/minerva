#!/usr/bin/env python3
"""
LLM Enrichment for Missing Actors

Enriquece atores que ainda não têm mapeamento MITRE ATT&CK.
Prioriza APTs conhecidos e processa em batches com checkpoint.

Usage:
    PYTHONPATH=$PWD venv/bin/python3 enrich_missing_actors.py [--limit N] [--force]

Args:
    --limit N: Processar apenas os primeiros N atores
    --force: Re-enriquecer mesmo atores já processados

Author: Claude + Angello Cassio
Date: 2025-11-20
"""

import asyncio
import argparse
import logging
import sys
from datetime import datetime
from typing import List, Dict, Any

from app.db.elasticsearch import get_es_client
from app.cti.services.enrichment_cache_service import get_enrichment_cache_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Top-tier APTs (prioridade máxima)
TOP_APTS = [
    "Lazarus Group", "APT28", "APT29", "APT41", "APT1", "APT10",
    "Turla", "Kimsuky", "APT38", "APT37", "Winnti Group",
    "Equation Group", "APT3", "APT12", "APT17", "APT19",
    "Charming Kitten", "UNC2452", "HAFNIUM", "LAPSUS$"
]


async def get_all_actors() -> List[str]:
    """Busca todos os atores do Malpedia"""
    es = await get_es_client()

    result = await es.search(
        index="malpedia_actors",
        body={
            "size": 10000,
            "query": {"match_all": {}},
            "_source": ["name"]
        }
    )

    actors = [hit["_source"]["name"] for hit in result["hits"]["hits"]]
    logger.info(f"📊 Total actors in Malpedia: {len(actors)}")
    return actors


async def get_enriched_actors() -> List[str]:
    """Busca atores já enriquecidos"""
    es = await get_es_client()

    result = await es.search(
        index="cti_enrichment_cache",
        body={
            "size": 10000,
            "query": {"match_all": {}},
            "_source": ["actor_name"]
        }
    )

    enriched = [hit["_source"]["actor_name"] for hit in result["hits"]["hits"]]
    logger.info(f"✅ Already enriched: {len(enriched)}")
    return enriched


def prioritize_actors(actors: List[str]) -> List[str]:
    """Ordena atores por prioridade (TOP APTs primeiro)"""
    top_tier = [a for a in actors if a in TOP_APTS]
    others = [a for a in actors if a not in TOP_APTS]

    # Ordena alfabeticamente dentro de cada grupo
    top_tier.sort()
    others.sort()

    prioritized = top_tier + others

    logger.info(f"🎯 Prioritized: {len(top_tier)} top-tier APTs, {len(others)} others")
    return prioritized


async def enrich_actor(cache_service, actor_name: str, idx: int, total: int) -> bool:
    """Enriquece um único ator com MITRE ATT&CK"""
    try:
        logger.info(f"\n[{idx}/{total}] 🔄 Enriching: {actor_name}")

        # Enriquece e salva no cache
        techniques = await cache_service.enrich_and_cache_actor(actor_name)

        if techniques:
            logger.info(f"   ✅ {actor_name}: {len(techniques)} techniques mapped")
            return True
        else:
            logger.warning(f"   ⚠️  {actor_name}: No techniques found (may not be in MITRE database)")
            return True  # Ainda conta como sucesso (ator processado)

    except Exception as e:
        logger.error(f"   ❌ {actor_name}: Error - {e}")
        return False


async def main(limit: int = None, force: bool = False):
    """Main enrichment function"""

    logger.info("="*80)
    logger.info("🚀 MITRE ATT&CK ENRICHMENT - Starting")
    logger.info("="*80)
    logger.info(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)

    # Get enrichment service
    cache_service = get_enrichment_cache_service()

    # Get all actors
    all_actors = await get_all_actors()

    if force:
        # Force mode: enriquecer todos
        logger.info("⚠️  FORCE MODE: Will re-enrich all actors")
        to_enrich = all_actors
    else:
        # Normal mode: apenas não enriquecidos
        enriched_actors = await get_enriched_actors()
        to_enrich = [a for a in all_actors if a not in enriched_actors]
        logger.info(f"🆕 Actors needing enrichment: {len(to_enrich)}")

    if not to_enrich:
        logger.info("✅ All actors already enriched!")
        return 0

    # Prioriza APTs conhecidos
    to_enrich = prioritize_actors(to_enrich)

    # Apply limit if specified
    if limit:
        original_count = len(to_enrich)
        to_enrich = to_enrich[:limit]
        logger.info(f"📊 Limited to first {limit} actors (from {original_count})")

    logger.info(f"\n🔄 Processing {len(to_enrich)} actors...")
    logger.info("="*80)

    # Process actors
    stats = {
        "total": len(to_enrich),
        "success": 0,
        "failed": 0,
        "failed_actors": []
    }

    for idx, actor_name in enumerate(to_enrich, 1):
        success = await enrich_actor(cache_service, actor_name, idx, stats["total"])

        if success:
            stats["success"] += 1
        else:
            stats["failed"] += 1
            stats["failed_actors"].append(actor_name)

        # Progress update every 10 actors
        if idx % 10 == 0:
            logger.info(f"\n📊 Progress: {idx}/{stats['total']} ({stats['success']} success, {stats['failed']} failed)")

    # Final stats
    logger.info("\n" + "="*80)
    logger.info("✅ ENRICHMENT COMPLETE!")
    logger.info("="*80)
    logger.info(f"\n📊 Summary:")
    logger.info(f"   Total processed:  {stats['total']}")
    logger.info(f"   Success:          {stats['success']}")
    logger.info(f"   Failed:           {stats['failed']}")

    if stats['failed_actors']:
        logger.info(f"\n❌ Failed actors:")
        for actor in stats['failed_actors']:
            logger.info(f"   - {actor}")

    logger.info(f"\n⏰ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)

    return 0 if stats['failed'] == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrich missing actors with MITRE ATT&CK mapping using LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enrich all missing actors
  python3 enrich_missing_actors.py

  # Enrich only first 50 missing actors
  python3 enrich_missing_actors.py --limit 50

  # Re-enrich ALL actors (force mode)
  python3 enrich_missing_actors.py --force

  # Re-enrich first 20 actors
  python3 enrich_missing_actors.py --force --limit 20
        """
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Limit processing to first N actors"
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-enrich all actors, even if already cached"
    )

    args = parser.parse_args()

    try:
        exit_code = asyncio.run(main(limit=args.limit, force=args.force))
        sys.exit(exit_code)

    except KeyboardInterrupt:
        logger.warning("\n\n⚠️  Interrupted by user")
        logger.info("💡 You can run the script again - it will resume from where it left off")
        sys.exit(1)

    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)
