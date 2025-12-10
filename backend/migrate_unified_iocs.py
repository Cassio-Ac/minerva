#!/usr/bin/env python3
"""
Migrate all IOCs to unified Elasticsearch index.
Run from backend directory: python migrate_unified_iocs.py
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def main():
    # Load environment
    from dotenv import load_dotenv
    load_dotenv()

    print("=" * 60)
    print("UNIFIED IOC MIGRATION")
    print("=" * 60)

    # Import after env is loaded
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from app.core.config import settings
    from app.cti.services.unified_ioc_service import UnifiedIOCMigration, UnifiedIOCService

    # Create database session
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Create service and ensure index
        service = UnifiedIOCService()
        print("\n[1/4] Creating index...")
        await service.ensure_index()
        print("     Index created!")
        await service.close()

        # Run migration
        migration = UnifiedIOCMigration(session)

        print("\n[2/4] Migrating MISP IOCs...")
        misp_stats = await migration.migrate_misp_iocs(batch_size=1000)
        print(f"     MISP: created={misp_stats['created']}, updated={misp_stats['updated']}, errors={misp_stats['errors']}")

        print("\n[3/4] Migrating OTX indicators...")
        otx_stats = await migration.migrate_otx_indicators(batch_size=1000)
        print(f"     OTX: created={otx_stats['created']}, updated={otx_stats['updated']}, errors={otx_stats['errors']}")

        # Final stats
        print("\n[4/4] Getting final statistics...")
        service = UnifiedIOCService()
        stats = await service.get_stats()
        await service.close()

        print("\n" + "=" * 60)
        print("MIGRATION COMPLETE")
        print("=" * 60)
        print(f"Total IOCs:        {stats['total_iocs']:,}")
        print(f"Active IOCs:       {stats['active_iocs']:,}")
        print(f"Multi-source:      {stats['multi_source_iocs']:,}")
        print(f"High confidence:   {stats['high_confidence_iocs']:,}")
        print(f"Avg confidence:    {stats['avg_confidence']:.1f}")
        print(f"Avg sources/IOC:   {stats['avg_sources_per_ioc']:.2f}")
        print("\nBy Type:")
        for ioc_type, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
            print(f"  {ioc_type}: {count:,}")
        print("\nBy Source:")
        for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
            print(f"  {source}: {count:,}")

    await engine.dispose()
    print("\nDone!")

if __name__ == "__main__":
    asyncio.run(main())
