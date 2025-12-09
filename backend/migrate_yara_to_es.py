#!/usr/bin/env python3
"""
YARA Migration Script

Migrates all YARA rules to unified Elasticsearch index:
- Signature Base rules from PostgreSQL
- Malpedia rules from Elasticsearch (malpedia_families)
"""

import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv(Path(__file__).parent / ".env")

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.cti.services.yara_elasticsearch_service import run_full_yara_migration


async def main():
    print("=" * 60)
    print("YARA Rules Migration to Elasticsearch")
    print("=" * 60)
    print()

    result = await run_full_yara_migration()

    print()
    print("=" * 60)
    print("MIGRATION RESULTS")
    print("=" * 60)

    for migration in result.get("migrations", []):
        source = migration.get("source", "unknown")
        total = migration.get("total", 0)
        migrated = migration.get("migrated", 0)
        errors = migration.get("errors", 0)
        print(f"\n{source.upper()}:")
        print(f"  Total: {total}")
        print(f"  Migrated: {migrated}")
        print(f"  Errors: {errors}")

    print()
    print("FINAL STATS:")
    stats = result.get("final_stats", {})
    print(f"  Total rules in ES: {stats.get('total_rules', 0)}")
    print(f"  Active rules: {stats.get('active_rules', 0)}")
    print(f"  By source: {stats.get('by_source', {})}")

    return result


if __name__ == "__main__":
    result = asyncio.run(main())
    if result.get("status") == "success":
        print("\n✅ Migration completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)
