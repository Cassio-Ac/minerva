#!/usr/bin/env python3
"""
Malpedia Import Script
Imports BibTeX library with optional RSS enrichment
"""

import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from elasticsearch import Elasticsearch
from app.services.malpedia_collector import MalpediaCollectorService
from app.core.config import settings

# Elasticsearch connection
ES_URL = settings.ES_URL or "http://localhost:9200"

def main():
    """Execute Malpedia import"""
    print("=" * 70)
    print("MALPEDIA IMPORT - BibTeX + RSS Enrichment")
    print("=" * 70)
    print()

    # Connect to Elasticsearch
    print("🔌 Connecting to Elasticsearch...")
    es = Elasticsearch([ES_URL])

    if not es.ping():
        print("❌ Failed to connect to Elasticsearch")
        return 1

    print("✅ Connected to Elasticsearch")
    print()

    # Initialize collector
    collector = MalpediaCollectorService(es, index_alias="rss-articles")

    # Import from URL with RSS enrichment
    print("📚 Starting import...")
    print("  - Source: BibTeX library")
    print("  - Enrichment: RSS feed enabled")
    print("  - LLM: Disabled (on-demand in chat)")
    print()

    result = collector.import_from_url(
        url="https://malpedia.caad.fkie.fraunhofer.de/library/download",
        download_path="/tmp/malpedia_import.bib",
        batch_size=1000,
        enrich_with_rss=False,  # Disabled - RSS doesn't have useful summaries
        update_existing=True
    )

    # Print results
    print()
    print("=" * 70)
    print("IMPORT COMPLETED")
    print("=" * 70)
    print()

    if result.get("status") == "success":
        print(f"✅ Status: SUCCESS")
        print(f"📊 Entries found: {result.get('entries_found', 0):,}")
        print(f"✨ New entries: {result.get('entries_new', 0):,}")
        print(f"🔄 Duplicates: {result.get('entries_duplicate', 0):,}")
        print(f"⏱️  Duration: {result.get('duration_seconds', 0)}s")
        print()
        print(f"📁 Source: {result.get('source', 'N/A')}")
        print(f"📂 Category: {result.get('category', 'N/A')}")
        return 0
    else:
        print(f"❌ Status: ERROR")
        print(f"Error: {result.get('error', 'Unknown error')}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
