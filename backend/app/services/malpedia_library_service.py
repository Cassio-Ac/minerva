"""
Malpedia Library Service

Servico para coletar e sincronizar a biblioteca do Malpedia via:
- RSS Feed (ultimas entradas): https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest
- BibTeX Download (biblioteca completa): https://malpedia.caad.fkie.fraunhofer.de/library/download

Integra com o sistema de RSS existente (mesmo indice rss-articles) e indexa
artigos academicos sobre malware para enriquecimento posterior.

Author: Angello Cassio
Date: 2025-12-03
"""

import hashlib
import logging
import re
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from xml.etree import ElementTree

import httpx

from app.db.elasticsearch import get_es_client
from app.core.config import settings

logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============

BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de"
RSS_URL = f"{BASE_URL}/feeds/rss/latest"
BIBTEX_URL = f"{BASE_URL}/library/download"

ES_INDEX = "rss-articles"  # Same index as RSS feeds
FEED_NAME = "Malpedia Library"
SOURCE_TYPE = "malpedia_library"
REQUEST_DELAY = 1  # seconds between requests


class MalpediaLibraryService:
    """Service for collecting Malpedia Library articles via RSS and BibTeX"""

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
                    'User-Agent': 'Mozilla/5.0 (compatible; IntelligencePlatform/1.0)'
                },
                timeout=60.0,
                follow_redirects=True
            )
        return self.http_client

    async def close(self):
        """Close HTTP client"""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None

    # ============= RSS FEED COLLECTION =============

    async def fetch_rss_feed(self) -> Optional[str]:
        """Download RSS feed content"""
        try:
            client = await self._get_http_client()
            response = await client.get(RSS_URL)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Error fetching RSS feed: {e}")
            return None

    def parse_rss_feed(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse RSS feed XML into article list"""
        articles = []

        try:
            root = ElementTree.fromstring(xml_content)
            channel = root.find('channel')

            if channel is None:
                logger.warning("No channel found in RSS feed")
                return articles

            for item in channel.findall('item'):
                try:
                    title = item.find('title')
                    link = item.find('link')
                    description = item.find('description')
                    pub_date = item.find('pubDate')
                    guid = item.find('guid')

                    if title is not None and link is not None:
                        article = {
                            'title': title.text.strip() if title.text else '',
                            'link': link.text.strip() if link.text else '',
                            'summary': description.text.strip() if description is not None and description.text else '',
                            'pub_date': pub_date.text.strip() if pub_date is not None and pub_date.text else None,
                            'guid': guid.text.strip() if guid is not None and guid.text else link.text.strip()
                        }
                        articles.append(article)

                except Exception as e:
                    logger.warning(f"Error parsing RSS item: {e}")
                    continue

        except ElementTree.ParseError as e:
            logger.error(f"Error parsing RSS XML: {e}")

        return articles

    # ============= BIBTEX COLLECTION =============

    async def fetch_bibtex(self) -> Optional[str]:
        """Download BibTeX file"""
        try:
            client = await self._get_http_client()
            response = await client.get(BIBTEX_URL)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Error fetching BibTeX: {e}")
            return None

    def parse_bibtex(self, bibtex_content: str) -> List[Dict[str, Any]]:
        """Parse BibTeX content into article list"""
        articles = []

        # Pattern to match BibTeX entries
        entry_pattern = r'@(\w+)\{([^,]+),\s*([\s\S]*?)\n\}'

        for match in re.finditer(entry_pattern, bibtex_content):
            try:
                entry_type = match.group(1)  # article, inproceedings, misc, etc.
                entry_key = match.group(2)   # Citation key
                entry_body = match.group(3)  # Fields

                # Parse fields
                fields = {}
                field_pattern = r'(\w+)\s*=\s*\{([^}]*)\}'
                for field_match in re.finditer(field_pattern, entry_body):
                    field_name = field_match.group(1).lower()
                    field_value = field_match.group(2).strip()
                    fields[field_name] = field_value

                # Build article object
                article = {
                    'bibtex_key': entry_key,
                    'bibtex_type': entry_type,
                    'title': fields.get('title', ''),
                    'authors': fields.get('author', ''),
                    'year': fields.get('year', ''),
                    'link': fields.get('url', fields.get('howpublished', '')),
                    'journal': fields.get('journal', ''),
                    'booktitle': fields.get('booktitle', ''),
                    'publisher': fields.get('publisher', ''),
                    'abstract': fields.get('abstract', ''),
                    'keywords': fields.get('keywords', ''),
                    'doi': fields.get('doi', ''),
                    'malpedia_id': fields.get('malpedia_id', ''),
                }

                # Clean URL from howpublished field
                if article['link'].startswith('\\url{'):
                    article['link'] = article['link'].replace('\\url{', '').rstrip('}')

                if article['title']:
                    articles.append(article)

            except Exception as e:
                logger.warning(f"Error parsing BibTeX entry: {e}")
                continue

        return articles

    # ============= ELASTICSEARCH INDEXING =============

    def create_es_document_from_rss(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """Create Elasticsearch document from RSS article"""
        content_hash = hashlib.sha256(article['guid'].encode()).hexdigest()

        # Parse pub date
        published = None
        if article.get('pub_date'):
            try:
                # RFC 2822 format: "Mon, 01 Dec 2025 12:00:00 GMT"
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(article['pub_date'])
                published = dt.isoformat()
            except Exception:
                published = article['pub_date']

        now = datetime.utcnow().isoformat() + 'Z'

        return {
            '@timestamp': now,
            'title': article['title'],
            'link': article['link'],
            'summary': article['summary'],
            'published': published,
            'collected_at': now,
            'feed_name': FEED_NAME,
            'feed_link': RSS_URL,
            'feed_title': 'Malpedia Library - Latest References',
            'feed_description': 'Academic papers and reports on malware analysis',
            'source_type': SOURCE_TYPE,
            'content_hash': content_hash,
            'language': 'en',
            'category': 'malware_research',
            'tags': ['malpedia', 'malware', 'research', 'academic'],
            'rss_enriched': False,
            'enriched_summary': None,
            'sentiment': None,
            'actors_mentioned': [],
            'families_mentioned': []
        }

    def create_es_document_from_bibtex(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """Create Elasticsearch document from BibTeX entry"""
        content_hash = hashlib.sha256(article['bibtex_key'].encode()).hexdigest()

        # Build published date from year
        published = None
        if article.get('year'):
            try:
                published = f"{article['year']}-01-01T00:00:00Z"
            except Exception:
                pass

        now = datetime.utcnow().isoformat() + 'Z'

        # Build summary from available fields
        summary_parts = []
        if article.get('abstract'):
            summary_parts.append(article['abstract'])
        elif article.get('journal'):
            summary_parts.append(f"Published in {article['journal']}")
        elif article.get('booktitle'):
            summary_parts.append(f"Presented at {article['booktitle']}")

        if article.get('authors'):
            summary_parts.append(f"Authors: {article['authors']}")

        summary = ' | '.join(summary_parts) if summary_parts else ''

        # Build tags from keywords
        tags = ['malpedia', 'malware', 'research', 'academic', 'bibtex']
        if article.get('keywords'):
            keyword_list = [k.strip() for k in article['keywords'].split(',')]
            tags.extend(keyword_list[:5])  # Limit to 5 keywords

        return {
            '@timestamp': now,
            'title': article['title'],
            'link': article['link'] or f"{BASE_URL}/library",
            'summary': summary,
            'published': published,
            'collected_at': now,
            'feed_name': FEED_NAME,
            'feed_link': BIBTEX_URL,
            'feed_title': 'Malpedia Library - BibTeX Database',
            'feed_description': 'Complete bibliography of malware research papers',
            'source_type': SOURCE_TYPE,
            'content_hash': content_hash,
            'bibtex_key': article['bibtex_key'],
            'bibtex_type': article['bibtex_type'],
            'authors': article['authors'],
            'year': article['year'],
            'journal': article.get('journal'),
            'booktitle': article.get('booktitle'),
            'publisher': article.get('publisher'),
            'doi': article.get('doi'),
            'malpedia_id': article.get('malpedia_id'),
            'language': 'en',
            'category': 'malware_research',
            'tags': tags,
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

    # ============= SYNC FUNCTIONS =============

    async def sync_rss(self) -> Dict[str, Any]:
        """
        Sync Malpedia Library via RSS feed (incremental)

        Returns:
            Stats dict with total_found, total_indexed
        """
        logger.info("Starting Malpedia Library RSS sync...")

        try:
            # Fetch RSS
            xml_content = await self.fetch_rss_feed()
            if not xml_content:
                return {'error': 'Failed to fetch RSS feed'}

            # Parse RSS
            articles = self.parse_rss_feed(xml_content)
            logger.info(f"Found {len(articles)} articles in RSS feed")

            if not articles:
                return {
                    'source': 'RSS',
                    'total_found': 0,
                    'total_indexed': 0,
                    'timestamp': datetime.utcnow().isoformat()
                }

            # Convert to ES format
            es_documents = [self.create_es_document_from_rss(article) for article in articles]

            # Index
            indexed = await self.index_articles(es_documents)
            logger.info(f"Indexed {indexed} articles from RSS feed")

            return {
                'source': 'RSS',
                'total_found': len(articles),
                'total_indexed': indexed,
                'timestamp': datetime.utcnow().isoformat()
            }

        finally:
            await self.close()

    async def sync_bibtex(self) -> Dict[str, Any]:
        """
        Sync Malpedia Library via BibTeX download (full sync)

        Returns:
            Stats dict with total_found, total_indexed
        """
        logger.info("Starting Malpedia Library BibTeX sync...")

        try:
            # Fetch BibTeX
            bibtex_content = await self.fetch_bibtex()
            if not bibtex_content:
                return {'error': 'Failed to fetch BibTeX file'}

            # Parse BibTeX
            articles = self.parse_bibtex(bibtex_content)
            logger.info(f"Found {len(articles)} entries in BibTeX file")

            if not articles:
                return {
                    'source': 'BibTeX',
                    'total_found': 0,
                    'total_indexed': 0,
                    'timestamp': datetime.utcnow().isoformat()
                }

            # Convert to ES format
            es_documents = [self.create_es_document_from_bibtex(article) for article in articles]

            # Index in batches (BibTeX can be large)
            batch_size = 500
            total_indexed = 0

            for i in range(0, len(es_documents), batch_size):
                batch = es_documents[i:i + batch_size]
                indexed = await self.index_articles(batch)
                total_indexed += indexed
                logger.info(f"Indexed batch {i//batch_size + 1}: {indexed} articles")
                await asyncio.sleep(0.5)  # Rate limiting

            logger.info(f"Total indexed from BibTeX: {total_indexed}")

            return {
                'source': 'BibTeX',
                'total_found': len(articles),
                'total_indexed': total_indexed,
                'timestamp': datetime.utcnow().isoformat()
            }

        finally:
            await self.close()

    async def sync_all(self) -> Dict[str, Any]:
        """
        Sync both RSS and BibTeX sources

        Returns:
            Combined stats
        """
        logger.info("Starting full Malpedia Library sync (RSS + BibTeX)...")

        rss_result = await self.sync_rss()

        # Small delay between sources
        await asyncio.sleep(REQUEST_DELAY)

        # Reinitialize for BibTeX
        self.http_client = None
        bibtex_result = await self.sync_bibtex()

        return {
            'rss': rss_result,
            'bibtex': bibtex_result,
            'total_found': rss_result.get('total_found', 0) + bibtex_result.get('total_found', 0),
            'total_indexed': rss_result.get('total_indexed', 0) + bibtex_result.get('total_indexed', 0),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def get_stats(self) -> Dict[str, Any]:
        """Get Malpedia Library stats from Elasticsearch"""
        es = await self._get_es_client()

        try:
            response = await es.search(
                index=ES_INDEX,
                body={
                    "size": 0,
                    "query": {
                        "term": {"source_type": SOURCE_TYPE}
                    },
                    "aggs": {
                        "total_count": {"value_count": {"field": "content_hash"}},
                        "latest_article": {"max": {"field": "published"}},
                        "oldest_article": {"min": {"field": "published"}},
                        "by_year": {
                            "terms": {
                                "field": "year.keyword",
                                "size": 20,
                                "order": {"_key": "desc"}
                            }
                        },
                        "by_type": {
                            "terms": {
                                "field": "bibtex_type.keyword",
                                "size": 10
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
                'articles_by_year': [
                    {'year': b['key'], 'count': b['doc_count']}
                    for b in aggs.get('by_year', {}).get('buckets', [])
                ],
                'articles_by_type': [
                    {'type': b['key'], 'count': b['doc_count']}
                    for b in aggs.get('by_type', {}).get('buckets', [])
                ]
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {
                'source': FEED_NAME,
                'total_articles': 0,
                'error': str(e)
            }


# ============= CONVENIENCE FUNCTIONS =============

async def run_malpedia_library_rss_sync() -> Dict[str, Any]:
    """Run Malpedia Library RSS sync (for use in tasks/endpoints)"""
    service = MalpediaLibraryService()
    try:
        return await service.sync_rss()
    finally:
        await service.close()


async def run_malpedia_library_bibtex_sync() -> Dict[str, Any]:
    """Run Malpedia Library BibTeX sync (for use in tasks/endpoints)"""
    service = MalpediaLibraryService()
    try:
        return await service.sync_bibtex()
    finally:
        await service.close()


async def run_malpedia_library_full_sync() -> Dict[str, Any]:
    """Run full Malpedia Library sync (RSS + BibTeX)"""
    service = MalpediaLibraryService()
    try:
        return await service.sync_all()
    finally:
        await service.close()
