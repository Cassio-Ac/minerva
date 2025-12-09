"""
Manual RSS Collection Script
Collects RSS feeds and stores articles in Elasticsearch
"""

import asyncio
import sys
import feedparser
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import select, text
from app.db.database import AsyncSessionLocal
from app.db.elasticsearch import get_es_client
from app.models.rss import RSSSource, RSSCategory


def generate_article_id(link: str, title: str) -> str:
    """Generate unique article ID from link and title"""
    content = f"{link}|{title}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def parse_rss_date(date_str: str) -> datetime:
    """Parse RSS date string to datetime"""
    if not date_str:
        return datetime.now(timezone.utc)

    try:
        # feedparser returns a time.struct_time
        import time
        if hasattr(date_str, 'tm_year'):
            dt = datetime(*date_str[:6])
            return dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)
    except:
        return datetime.now(timezone.utc)


async def collect_feed(source: RSSSource, category_name: str, es_client: Any) -> int:
    """Collect articles from a single RSS feed"""
    print(f"\n📡 Collecting: {source.name}")
    print(f"   URL: {source.url}")

    try:
        # Parse RSS feed
        feed = feedparser.parse(source.url)

        if feed.bozo:
            print(f"   ⚠️  Feed has issues: {feed.bozo_exception}")

        entries = feed.entries[:50]  # Limit to 50 articles
        print(f"   Found {len(entries)} articles")

        articles_indexed = 0

        for entry in entries:
            try:
                # Generate article ID
                article_id = generate_article_id(
                    entry.get('link', ''),
                    entry.get('title', '')
                )

                # Parse published date
                published_parsed = entry.get('published_parsed')
                if published_parsed:
                    published_dt = datetime(*published_parsed[:6], tzinfo=timezone.utc)
                else:
                    published_dt = datetime.now(timezone.utc)

                # Extract summary/content
                summary = entry.get('summary', '')
                content = entry.get('content', [{}])[0].get('value', summary) if 'content' in entry else summary

                # Extract tags
                tags = [tag.get('term', '') for tag in entry.get('tags', [])]

                # Create article document
                article_doc = {
                    "article_id": article_id,
                    "source_id": str(source.id),
                    "title": entry.get('title', 'No title'),
                    "link": entry.get('link', ''),
                    "published": published_dt.isoformat(),
                    "summary": summary[:1000],  # Limit summary size
                    "content": content[:5000],  # Limit content size
                    "author": entry.get('author', ''),
                    "tags": tags,
                    "category": category_name,
                    "feed_name": source.name,
                    "language": "en",
                    "created_at": datetime.now(timezone.utc).isoformat()
                }

                # Index in Elasticsearch
                await es_client.index(
                    index="rss-articles",
                    id=article_id,
                    document=article_doc,
                    refresh=False  # Don't refresh immediately for better performance
                )

                articles_indexed += 1

            except Exception as e:
                print(f"   ❌ Error processing article: {e}")
                continue

        # Refresh index after all articles
        if articles_indexed > 0:
            await es_client.indices.refresh(index="rss-articles")

        print(f"   ✅ Indexed {articles_indexed} articles")
        return articles_indexed

    except Exception as e:
        print(f"   ❌ Error collecting feed: {e}")
        return 0


async def collect_all_feeds():
    """Collect all active RSS feeds"""
    print("🚀 Starting RSS collection...\n")

    # Initialize Elasticsearch
    es_client = await get_es_client()

    total_articles = 0

    async with AsyncSessionLocal() as db:
        # Get all active sources with their categories
        result = await db.execute(
            select(RSSSource, RSSCategory)
            .join(RSSCategory, RSSSource.category_id == RSSCategory.id)
            .where(RSSSource.is_active == True)
        )

        sources_with_categories = result.all()

        print(f"📋 Found {len(sources_with_categories)} active feeds\n")

        for source, category in sources_with_categories:
            articles_count = await collect_feed(source, category.name, es_client)
            total_articles += articles_count

            # Update source stats
            await db.execute(
                text("""
                    UPDATE rss_sources
                    SET
                        last_collected_at = NOW(),
                        last_collection_status = 'success',
                        total_articles_collected = total_articles_collected + :articles_count
                    WHERE id = :source_id
                """),
                {"articles_count": articles_count, "source_id": str(source.id)}
            )

        await db.commit()

    print(f"\n✅ Collection completed!")
    print(f"📊 Total articles indexed: {total_articles}")


if __name__ == "__main__":
    asyncio.run(collect_all_feeds())
