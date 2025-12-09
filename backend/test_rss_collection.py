#!/usr/bin/env python3
"""
Test RSS Collection
Quick script to test a single RSS source collection
"""
import asyncio
import sys
from elasticsearch import Elasticsearch
from app.services.rss_collector import RSSCollectorService
from app.db.session import get_db_session
from sqlalchemy import select
from app.models.rss import RSSSource, RSSCategory

async def test_collection():
    # Connect to Elasticsearch
    es = Elasticsearch(['http://localhost:9200'])

    # Create collector
    collector = RSSCollectorService(es, "rss-articles")

    # Get database session
    async for db in get_db_session():
        # Get one RSS source to test
        result = await db.execute(
            select(RSSSource, RSSCategory.name)
            .join(RSSCategory, RSSSource.category_id == RSSCategory.id)
            .where(RSSSource.name == "TechCrunch")
            .limit(1)
        )

        row = result.first()
        if not row:
            print("❌ TechCrunch source not found")
            return

        source, category_name = row
        print(f"✅ Found source: {source.name} ({source.url})")
        print(f"📁 Category: {category_name}")

        # Collect from this source
        result = await collector.collect_source(
            db,
            source,
            category_name,
            triggered_by="test",
            days_filter=7,
            max_articles=10  # Just 10 articles for testing
        )

        print(f"\n📊 Result: {result}")
        break

if __name__ == "__main__":
    asyncio.run(test_collection())
