"""
CaveiraTech Crawler Service

Crawler para coletar noticias do site CaveiraTech e indexar no Elasticsearch.
Integrado ao sistema RSS existente (mesmo indice rss-articles).

Author: Angello Cassio
Date: 2025-12-03
"""

import hashlib
import logging
import time
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from app.db.elasticsearch import get_es_client
from app.core.config import settings

logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============

BASE_URL = "https://caveiratech.com"
ES_INDEX = "rss-articles"
FEED_NAME = "CaveiraTech"
SOURCE_TYPE = "crawler"
REQUEST_DELAY = 1  # seconds between requests


class CaveiraTechCrawlerService:
    """Service for crawling CaveiraTech news"""

    def __init__(self):
        self.es_client = None
        self.http_client = None

    async def _get_es_client(self):
        """Get Elasticsearch client"""
        if self.es_client is None:
            self.es_client = await get_es_client()
        return self.es_client

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get HTTP client with proper headers"""
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                timeout=30.0,
                follow_redirects=True
            )
        return self.http_client

    async def close(self):
        """Close HTTP client"""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None

    async def get_page_content(self, url: str) -> Optional[str]:
        """Download page content"""
        try:
            client = await self._get_http_client()
            response = await client.get(url)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None

    def extract_articles_from_page(self, html: str) -> List[Dict[str, str]]:
        """Extract articles from HTML page"""
        soup = BeautifulSoup(html, 'html.parser')
        articles = []

        post_divs = soup.find_all('div', class_='post')

        for post_div in post_divs:
            try:
                # Extract date
                date_div = post_div.find('div', class_='date')
                if not date_div:
                    continue

                date_text = date_div.get_text(strip=True)
                date_parts = date_text.split()
                date = None
                for part in date_parts:
                    if len(part) == 10 and part.count('-') == 2:
                        try:
                            datetime.strptime(part, '%Y-%m-%d')
                            date = part
                            break
                        except ValueError:
                            continue

                if not date:
                    continue

                # Extract link and title
                title_link = post_div.find('a', href=lambda x: x and x.startswith('/post/'))
                if not title_link:
                    continue

                link = urljoin(BASE_URL, title_link.get('href', ''))

                title_h = title_link.find('h', class_='post')
                if not title_h:
                    title = title_link.get_text(strip=True)
                else:
                    title = title_h.get_text(strip=True)

                # Clean title
                title = title.lstrip('🔹️ ').lstrip('🔸 ').lstrip('▪️ ').strip()

                # Extract summary
                summary_p = post_div.find('p', class_='summary_text')
                summary = ""
                if summary_p:
                    summary = summary_p.get_text(strip=True)
                    summary = summary.lstrip('🔹 ').lstrip('🔸 ').lstrip('▪️ ').strip()

                if date and title and link:
                    articles.append({
                        'date': date,
                        'title': title,
                        'link': link,
                        'summary': summary
                    })

            except Exception as e:
                logger.warning(f"Error processing post: {e}")
                continue

        return articles

    async def get_total_pages(self) -> int:
        """Discover total number of pages"""
        html = await self.get_page_content(BASE_URL)
        if not html:
            return 1

        soup = BeautifulSoup(html, 'html.parser')
        page_links = soup.find_all('a', href=lambda x: x and '/page/' in x)

        max_page = 1
        for link in page_links:
            try:
                page_num = int(link.get_text(strip=True).replace('[', '').replace(']', ''))
                max_page = max(max_page, page_num)
            except ValueError:
                continue

        return max_page

    def create_es_document(self, article: Dict[str, str]) -> Dict[str, Any]:
        """Create Elasticsearch document"""
        content_hash = hashlib.sha256(article['link'].encode()).hexdigest()

        published_dt = datetime.strptime(article['date'], '%Y-%m-%d')
        published = published_dt.isoformat() + 'Z'

        now = datetime.utcnow().isoformat() + 'Z'

        return {
            '@timestamp': now,
            'title': article['title'],
            'link': article['link'],
            'summary': article['summary'],
            'published': published,
            'collected_at': now,
            'feed_name': FEED_NAME,
            'feed_link': BASE_URL,
            'feed_title': 'CaveiraTech - Noticias de Ciberseguranca',
            'feed_description': 'Portal de noticias sobre ciberseguranca, hacking e tecnologia',
            'source_type': SOURCE_TYPE,
            'content_hash': content_hash,
            'language': 'pt',
            'category': 'cybersecurity',
            'tags': ['ciberseguranca', 'hacking', 'tecnologia', 'brasil'],
            'rss_enriched': False,
            'enriched_summary': None,
            'sentiment': None,
            'actors_mentioned': [],
            'families_mentioned': []
        }

    async def index_articles(self, articles: List[Dict[str, Any]]) -> int:
        """Index articles in Elasticsearch"""
        if not articles:
            return 0

        es = await self._get_es_client()

        # Ensure index exists
        try:
            exists = await es.indices.exists(index=ES_INDEX)
            if not exists:
                await es.indices.create(index=ES_INDEX)
        except Exception as e:
            logger.warning(f"Index check/create warning: {e}")

        # Bulk index
        operations = []
        for article in articles:
            operations.append({'index': {'_index': ES_INDEX, '_id': article['content_hash']}})
            operations.append(article)

        try:
            response = await es.bulk(operations=operations, refresh=True)

            # Count successful
            success = 0
            if 'items' in response:
                for item in response['items']:
                    if 'index' in item and item['index'].get('result') in ['created', 'updated']:
                        success += 1
            return success
        except Exception as e:
            logger.error(f"Error indexing articles: {e}")
            return 0

    async def crawl(
        self,
        start_page: int = 1,
        end_page: Optional[int] = None,
        max_pages: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute the crawler

        Args:
            start_page: Starting page number
            end_page: Ending page number (auto-detect if None)
            max_pages: Maximum pages to crawl (for quick sync)

        Returns:
            Stats dict with total_found, total_indexed, pages_crawled
        """
        logger.info(f"Starting CaveiraTech crawler...")

        try:
            # Discover total pages if not specified
            if end_page is None:
                total_pages = await self.get_total_pages()
                if max_pages:
                    end_page = min(start_page + max_pages - 1, total_pages)
                else:
                    end_page = total_pages
                logger.info(f"Total pages available: {total_pages}, will crawl to page {end_page}")

            total_articles = 0
            total_indexed = 0
            pages_crawled = 0

            for page_num in range(start_page, end_page + 1):
                # Build page URL
                if page_num == 1:
                    url = BASE_URL
                else:
                    url = f"{BASE_URL}/page/{page_num}"

                logger.info(f"Processing page {page_num}/{end_page}: {url}")

                # Download page
                html = await self.get_page_content(url)
                if not html:
                    logger.warning(f"Failed to fetch page {page_num}, skipping...")
                    continue

                # Extract articles
                articles = self.extract_articles_from_page(html)
                logger.info(f"Found {len(articles)} articles on page {page_num}")

                if articles:
                    # Convert to ES format
                    es_documents = [self.create_es_document(article) for article in articles]

                    # Index
                    indexed = await self.index_articles(es_documents)
                    logger.info(f"Indexed {indexed} articles from page {page_num}")

                    total_articles += len(articles)
                    total_indexed += indexed

                pages_crawled += 1

                # Rate limiting
                if page_num < end_page:
                    await asyncio.sleep(REQUEST_DELAY)

            result = {
                'source': FEED_NAME,
                'pages_crawled': pages_crawled,
                'total_found': total_articles,
                'total_indexed': total_indexed,
                'start_page': start_page,
                'end_page': end_page,
                'timestamp': datetime.utcnow().isoformat()
            }

            logger.info(f"CaveiraTech crawl completed: {result}")
            return result

        finally:
            await self.close()

    async def get_stats(self) -> Dict[str, Any]:
        """Get CaveiraTech articles stats from Elasticsearch"""
        es = await self._get_es_client()

        try:
            response = await es.search(
                index=ES_INDEX,
                body={
                    "size": 0,
                    "query": {
                        "term": {"feed_name": FEED_NAME}
                    },
                    "aggs": {
                        "total_count": {"value_count": {"field": "content_hash"}},
                        "latest_article": {"max": {"field": "published"}},
                        "oldest_article": {"min": {"field": "published"}},
                        "by_month": {
                            "date_histogram": {
                                "field": "published",
                                "calendar_interval": "month",
                                "format": "yyyy-MM"
                            }
                        }
                    }
                }
            )

            aggs = response.get('aggregations', {})

            return {
                'source': FEED_NAME,
                'total_articles': response['hits']['total']['value'],
                'latest_article': aggs.get('latest_article', {}).get('value_as_string'),
                'oldest_article': aggs.get('oldest_article', {}).get('value_as_string'),
                'articles_by_month': [
                    {'month': b['key_as_string'], 'count': b['doc_count']}
                    for b in aggs.get('by_month', {}).get('buckets', [])
                ]
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {
                'source': FEED_NAME,
                'total_articles': 0,
                'error': str(e)
            }


# Singleton instance
_crawler_service: Optional[CaveiraTechCrawlerService] = None


def get_caveiratech_crawler() -> CaveiraTechCrawlerService:
    """Get singleton crawler service"""
    global _crawler_service
    if _crawler_service is None:
        _crawler_service = CaveiraTechCrawlerService()
    return _crawler_service


async def run_caveiratech_sync(max_pages: Optional[int] = 10) -> Dict[str, Any]:
    """
    Run CaveiraTech sync (for use in tasks/endpoints)

    Args:
        max_pages: Max pages to crawl (default 10 for incremental sync)

    Returns:
        Sync result stats
    """
    crawler = CaveiraTechCrawlerService()
    try:
        return await crawler.crawl(max_pages=max_pages)
    finally:
        await crawler.close()
