"""
RSS Collector Service
Fetches RSS feeds, parses them, and stores articles in Elasticsearch
Adapted from original rss_feed.py with async/await pattern
"""

import logging
import hashlib
import time
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

import feedparser
import requests
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from elasticsearch import Elasticsearch

from app.models.rss import RSSSource, RSSCategory, RSSCollectionRun
from app.services.rss_elasticsearch import RSSElasticsearchService

logger = logging.getLogger(__name__)


class RSSCollectorService:
    """
    RSS Feed Collector Service
    Fetches RSS feeds and stores articles in Elasticsearch
    """

    def __init__(self, es_client: Elasticsearch, index_alias: str = "rss-articles"):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Minerva-Intelligence-Platform/1.0"})
        self.es_service = RSSElasticsearchService(es_client, index_alias)
        self.max_retries = 3
        self.retry_delay_seconds = 2

    async def fetch_feed(self, url: str, timeout: int = 20) -> Optional[feedparser.FeedParserDict]:
        """
        Fetch and parse RSS feed with retries

        Args:
            url: RSS feed URL
            timeout: Request timeout in seconds

        Returns:
            Parsed feed or None if failed
        """
        last_error = None

        for attempt in range(self.max_retries):
            try:
                # Fetch feed
                response = await asyncio.to_thread(
                    self.session.get, url, timeout=timeout
                )
                response.raise_for_status()

                # Parse feed
                feed = await asyncio.to_thread(
                    feedparser.parse, response.content
                )

                # Check for errors
                if getattr(feed, 'bozo', False):
                    bozo_exception = getattr(feed, 'bozo_exception', None)
                    logger.warning(f"⚠️ Bozo flag set for {url}: {bozo_exception}")
                    # Continue anyway, feed might still be usable

                logger.info(f"✅ Fetched feed: {url} ({len(feed.entries)} entries)")
                return feed

            except requests.exceptions.Timeout as e:
                last_error = f"Timeout: {e}"
                logger.warning(f"⏱️ Attempt {attempt + 1}/{self.max_retries} timeout for {url}")

            except requests.exceptions.RequestException as e:
                last_error = f"Request error: {e}"
                logger.warning(f"❌ Attempt {attempt + 1}/{self.max_retries} failed for {url}: {e}")

            except Exception as e:
                last_error = f"Unexpected error: {e}"
                logger.error(f"💥 Unexpected error parsing {url}: {e}")

            # Wait before retry (exponential backoff)
            if attempt < self.max_retries - 1:
                wait_time = self.retry_delay_seconds * (attempt + 1)
                logger.info(f"⏳ Waiting {wait_time}s before retry...")
                await asyncio.sleep(wait_time)

        # All retries failed
        logger.error(f"❌ Failed to fetch {url} after {self.max_retries} attempts: {last_error}")
        return None

    def extract_articles_from_feed(
        self,
        feed: feedparser.FeedParserDict,
        source: RSSSource,
        category_name: str,
        min_datetime: Optional[datetime] = None,
        max_articles: int = 100
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Extract and format articles from parsed feed

        Args:
            feed: Parsed feedparser dict
            source: RSS source model
            category_name: Category name
            min_datetime: Filter articles older than this (optional)
            max_articles: Maximum articles to extract

        Returns:
            Tuple of (articles list, feed_metadata dict)
        """
        articles = []
        feed_info = getattr(feed, 'feed', {})

        # Extract feed metadata
        feed_metadata = {
            "title": getattr(feed_info, 'title', source.name),
            "description": getattr(feed_info, 'description', ''),
            "link": getattr(feed_info, 'link', ''),
            "updated": getattr(feed_info, 'updated', ''),
        }

        # Process entries
        for entry in feed.entries[:max_articles]:  # Limit articles per feed
            try:
                # Parse published date - try multiple fields
                published_dt = None

                # Try published_parsed first (most reliable)
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    try:
                        published_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                    except (TypeError, ValueError) as e:
                        logger.debug(f"Failed to parse published_parsed: {e}")

                # Try updated_parsed if published_parsed failed
                if not published_dt and hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    try:
                        published_dt = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)
                    except (TypeError, ValueError) as e:
                        logger.debug(f"Failed to parse updated_parsed: {e}")

                # Try parsing string dates if parsed dates failed
                if not published_dt:
                    from dateutil import parser as date_parser
                    for field in ['published', 'updated', 'created']:
                        date_str = entry.get(field)
                        if date_str:
                            try:
                                published_dt = date_parser.parse(date_str)
                                # Ensure timezone-aware
                                if published_dt.tzinfo is None:
                                    published_dt = published_dt.replace(tzinfo=timezone.utc)
                                break
                            except Exception as e:
                                logger.debug(f"Failed to parse {field} string: {e}")

                # Try extracting date from description/summary (for feeds like Malpedia)
                if not published_dt:
                    import re
                    from dateutil import parser as date_parser

                    # Check description and summary fields
                    for field in ['description', 'summary']:
                        content = entry.get(field, '')
                        if content:
                            # Look for YYYY-MM-DD pattern (common in Malpedia)
                            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', content)
                            if date_match:
                                try:
                                    date_str = date_match.group(1)
                                    published_dt = date_parser.parse(date_str)
                                    # Ensure timezone-aware
                                    if published_dt.tzinfo is None:
                                        published_dt = published_dt.replace(tzinfo=timezone.utc)
                                    logger.debug(f"Extracted date from {field}: {date_str}")
                                    break
                                except Exception as e:
                                    logger.debug(f"Failed to parse date from {field}: {e}")

                # Fallback to now if all parsing failed
                if not published_dt:
                    logger.warning(f"No valid date found for article '{entry.get('title', 'Unknown')}' from {source.name}, using current time")
                    published_dt = datetime.now(timezone.utc)

                published_iso = published_dt.isoformat()

                # Filter by date if specified
                if min_datetime and published_dt < min_datetime:
                    continue

                # Generate content hash for deduplication
                hash_source = f"{entry.get('title', '')}{entry.get('link', '')}{published_iso}"
                content_hash = hashlib.md5(hash_source.encode('utf-8')).hexdigest()

                # Extract tags
                tags = []
                if hasattr(entry, 'tags'):
                    tags = [tag.term for tag in entry.tags if hasattr(tag, 'term')]

                # Parse feed_updated to ISO format if present
                feed_updated_iso = None
                if feed_metadata.get('updated'):
                    try:
                        from dateutil import parser as date_parser
                        feed_updated_dt = date_parser.parse(feed_metadata['updated'])
                        # Ensure timezone-aware
                        if feed_updated_dt.tzinfo is None:
                            feed_updated_dt = feed_updated_dt.replace(tzinfo=timezone.utc)
                        feed_updated_iso = feed_updated_dt.isoformat()
                    except Exception:
                        # If parsing fails, skip feed_updated field
                        pass

                # Build article document
                article = {
                    # Timestamps
                    "@timestamp": published_iso,
                    "published": published_iso,
                    "collected_at": datetime.now(timezone.utc).isoformat(),

                    # Content
                    "title": entry.get('title', '').strip(),
                    "link": entry.get('link', '').strip(),
                    "summary": entry.get('summary', entry.get('description', '')).strip(),
                    "author": entry.get('author', '').strip(),
                    "tags": tags,
                    "content_hash": content_hash,

                    # Feed metadata
                    "feed_name": source.name,
                    "feed_title": feed_metadata['title'],
                    "feed_description": feed_metadata['description'],
                    "feed_link": feed_metadata['link'],

                    # Categorization
                    "category": category_name,
                    "source_type": "rss_feed",
                }

                # Only add feed_updated if we successfully parsed it
                if feed_updated_iso:
                    article["feed_updated"] = feed_updated_iso

                articles.append(article)

            except Exception as e:
                logger.error(f"❌ Error processing entry: {e}")
                continue

        logger.info(f"📝 Extracted {len(articles)} articles from {source.name}")
        return articles, feed_metadata

    async def collect_source(
        self,
        db: AsyncSession,
        source: RSSSource,
        category_name: str,
        triggered_by: str = "manual",
        executed_by: Optional[str] = None,
        days_filter: Optional[int] = None,
        max_articles: int = 100
    ) -> Dict[str, Any]:
        """
        Collect articles from a single RSS source

        Args:
            db: Database session
            source: RSS source to collect
            category_name: Category name
            triggered_by: Who triggered (scheduler, manual, api)
            executed_by: User ID if manual
            days_filter: Only collect articles from last N days
            max_articles: Max articles per feed

        Returns:
            Collection stats dict
        """
        started_at = datetime.now(timezone.utc)

        # Create collection run record
        run = RSSCollectionRun(
            source_id=source.id,
            started_at=started_at,
            status="running",
            triggered_by=triggered_by,
            executed_by=executed_by,
        )
        db.add(run)
        await db.flush()  # Get run.id

        try:
            # Fetch feed
            logger.info(f"🔍 Collecting: {source.name} ({source.url})")
            feed = await self.fetch_feed(source.url)

            if not feed:
                # Mark as error
                run.status = "error"
                run.error_message = "Failed to fetch feed"
                run.finished_at = datetime.now(timezone.utc)
                run.duration_seconds = int((run.finished_at - started_at).total_seconds())
                await db.commit()
                return {"status": "error", "error": "Failed to fetch feed"}

            # Calculate min datetime if days filter
            min_datetime = None
            if days_filter and days_filter > 0:
                min_datetime = datetime.now(timezone.utc) - timedelta(days=days_filter)

            # Extract articles
            articles, feed_metadata = self.extract_articles_from_feed(
                feed, source, category_name, min_datetime, max_articles
            )

            # Store feed metadata in run
            run.feed_metadata = feed_metadata

            # Update source metadata
            source.feed_title = feed_metadata.get('title')
            source.feed_link = feed_metadata.get('link')

            # Bulk index to Elasticsearch
            if articles:
                import asyncio
                result = await asyncio.to_thread(self.es_service.bulk_index_articles, articles)
                articles_new = result['created']
                articles_duplicate = result['failed']  # Failed = already exists
            else:
                articles_new = 0
                articles_duplicate = 0

            # Update collection run
            run.status = "success"
            run.articles_found = len(articles)
            run.articles_new = articles_new
            run.articles_duplicate = articles_duplicate
            run.finished_at = datetime.now(timezone.utc)
            run.duration_seconds = int((run.finished_at - started_at).total_seconds())

            # Update source stats
            source.last_collected_at = run.finished_at
            source.last_collection_status = "success"
            source.last_error_message = None
            source.total_articles_collected += articles_new

            await db.commit()

            logger.info(
                f"✅ Collection complete: {source.name} | "
                f"Found: {len(articles)} | New: {articles_new} | Duplicates: {articles_duplicate}"
            )

            return {
                "status": "success",
                "articles_found": len(articles),
                "articles_new": articles_new,
                "articles_duplicate": articles_duplicate,
                "duration_seconds": run.duration_seconds,
            }

        except Exception as e:
            logger.error(f"❌ Error collecting {source.name}: {e}")

            # Mark run as error
            run.status = "error"
            run.error_message = str(e)
            run.finished_at = datetime.now(timezone.utc)
            run.duration_seconds = int((run.finished_at - started_at).total_seconds())

            # Update source
            source.last_collected_at = run.finished_at
            source.last_collection_status = "error"
            source.last_error_message = str(e)

            await db.commit()

            return {
                "status": "error",
                "error": str(e),
                "duration_seconds": run.duration_seconds,
            }

    async def collect_all_active_sources(
        self,
        db: AsyncSession,
        category_ids: Optional[List[str]] = None,
        triggered_by: str = "scheduler",
        days_filter: Optional[int] = None,
        max_articles: int = 100
    ) -> Dict[str, Any]:
        """
        Collect from all active RSS sources (optionally filtered by category)

        Args:
            db: Database session
            category_ids: Optional list of category IDs to filter
            triggered_by: Who triggered collection
            days_filter: Only collect articles from last N days
            max_articles: Max articles per feed

        Returns:
            Overall stats dict
        """
        started_at = datetime.now(timezone.utc)
        logger.info(f"🚀 Starting bulk RSS collection (triggered_by: {triggered_by})")

        # Build query
        query = select(RSSSource, RSSCategory.name).join(
            RSSCategory, RSSSource.category_id == RSSCategory.id
        ).where(
            RSSSource.is_active == True,
            RSSCategory.is_active == True
        )

        if category_ids:
            query = query.where(RSSSource.category_id.in_(category_ids))

        result = await db.execute(query)
        sources_with_categories = result.all()

        if not sources_with_categories:
            logger.warning("⚠️ No active sources found")
            return {"status": "no_sources", "sources_collected": 0}

        logger.info(f"📚 Found {len(sources_with_categories)} active sources to collect")

        # Collect from each source
        total_articles_found = 0
        total_articles_new = 0
        total_articles_duplicate = 0
        sources_success = 0
        sources_error = 0

        for source, category_name in sources_with_categories:
            result = await self.collect_source(
                db, source, category_name,
                triggered_by=triggered_by,
                days_filter=days_filter,
                max_articles=max_articles
            )

            if result['status'] == 'success':
                sources_success += 1
                total_articles_found += result.get('articles_found', 0)
                total_articles_new += result.get('articles_new', 0)
                total_articles_duplicate += result.get('articles_duplicate', 0)
            else:
                sources_error += 1

        finished_at = datetime.now(timezone.utc)
        duration = int((finished_at - started_at).total_seconds())

        summary = {
            "status": "completed",
            "sources_total": len(sources_with_categories),
            "sources_success": sources_success,
            "sources_error": sources_error,
            "articles_found": total_articles_found,
            "articles_new": total_articles_new,
            "articles_duplicate": total_articles_duplicate,
            "duration_seconds": duration,
        }

        logger.info(
            f"🎉 Bulk collection completed | "
            f"Sources: {sources_success}/{len(sources_with_categories)} | "
            f"Articles: {total_articles_new} new, {total_articles_duplicate} duplicates | "
            f"Duration: {duration}s"
        )

        return summary
