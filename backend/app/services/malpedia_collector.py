"""
Malpedia BibTeX Collector Service
Imports Malpedia bibliographic library from BibTeX files
Optionally enriches with RSS feed data
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from pathlib import Path
import hashlib

from elasticsearch import Elasticsearch
import feedparser

from app.services.bibtex_parser import BibTeXParser
from app.services.rss_elasticsearch import RSSElasticsearchService

logger = logging.getLogger(__name__)


class MalpediaCollectorService:
    """
    Malpedia Library Collector

    Pipeline:
    1. Downloads BibTeX library (17,595 entries)
    2. Optionally enriches with RSS feed data
    3. Indexes to Elasticsearch
    4. NO LLM enrichment (done on-demand in chat)
    """

    def __init__(self, es_client: Elasticsearch, index_alias: str = "rss-articles"):
        self.parser = BibTeXParser()
        self.es_service = RSSElasticsearchService(es_client, index_alias)
        self.source_name = "Malpedia Library"
        self.category = "Threat Intelligence"
        self.rss_feed_url = "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest"
        self._rss_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def _load_rss_feed(self) -> Dict[str, Dict[str, Any]]:
        """
        Load RSS feed and build cache by title

        Returns:
            Dict mapping titles to RSS entry data
        """
        if self._rss_cache is not None:
            return self._rss_cache

        logger.info(f"Loading RSS feed from: {self.rss_feed_url}")
        cache = {}

        try:
            feed = feedparser.parse(self.rss_feed_url)

            for entry in feed.entries:
                title = entry.get('title', '')
                if title:
                    # Normalize title (lowercase, strip whitespace)
                    normalized_title = title.strip().lower()
                    cache[normalized_title] = {
                        'summary': entry.get('summary', ''),
                        'description': entry.get('description', ''),
                        'published': entry.get('published', ''),
                        'link': entry.get('link', '')
                    }

            logger.info(f"Cached {len(cache)} RSS entries by title")
            self._rss_cache = cache
            return cache

        except Exception as e:
            logger.warning(f"Failed to load RSS feed: {e}")
            self._rss_cache = {}
            return {}

    def _enrich_with_rss(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich BibTeX document with RSS feed data

        Args:
            doc: Elasticsearch document from BibTeX

        Returns:
            Enhanced document with RSS data
        """
        # Ensure RSS cache is loaded
        rss_cache = self._load_rss_feed()

        # Get document title and normalize
        title = doc.get('title', '').strip().lower()

        if not title or title not in rss_cache:
            return doc

        # Get RSS data by title
        rss_data = rss_cache[title]

        # Enrich summary if empty
        if not doc.get('summary') and rss_data.get('summary'):
            doc['summary'] = rss_data['summary']

        # Add RSS-specific metadata
        doc['rss_enriched'] = True
        doc['rss_enriched_at'] = datetime.now(timezone.utc).isoformat()

        return doc

    def import_from_file(
        self,
        file_path: str,
        batch_size: int = 1000,
        enrich_with_rss: bool = True,
        update_existing: bool = False
    ) -> Dict[str, Any]:
        """
        Import Malpedia BibTeX file to Elasticsearch

        Args:
            file_path: Path to .bib file
            batch_size: Number of documents to index per batch
            enrich_with_rss: Whether to enrich BibTeX with RSS feed data

        Returns:
            Import statistics dict
        """
        started_at = datetime.now(timezone.utc)
        logger.info(f"Starting Malpedia import from: {file_path}")
        logger.info(f"RSS enrichment: {'enabled' if enrich_with_rss else 'disabled'}")

        try:
            # Verify file exists
            if not Path(file_path).exists():
                raise FileNotFoundError(f"BibTeX file not found: {file_path}")

            # Parse BibTeX file
            logger.info("Parsing BibTeX file...")
            entries = self.parser.parse_file(file_path)
            logger.info(f"Parsed {len(entries)} BibTeX entries")

            if not entries:
                return {
                    "status": "no_data",
                    "message": "No entries found in BibTeX file",
                    "entries_found": 0,
                    "entries_new": 0,
                    "entries_duplicate": 0
                }

            # Convert to ES documents
            logger.info("Converting to Elasticsearch documents...")
            docs = self.parser.convert_to_elasticsearch_docs(
                entries,
                self.source_name,
                self.category
            )

            # Enrich with RSS feed data if enabled
            if enrich_with_rss:
                logger.info("Enriching with RSS feed data...")
                enriched_count = 0
                for doc in docs:
                    original_summary = doc.get('summary')
                    doc = self._enrich_with_rss(doc)
                    if doc.get('rss_enriched'):
                        enriched_count += 1

                logger.info(f"Enriched {enriched_count}/{len(docs)} documents with RSS data")

            # Set operation type for Elasticsearch
            if update_existing:
                for doc in docs:
                    doc['_es_op_type'] = 'index'  # Upsert mode

            # Index in batches
            total_new = 0
            total_duplicate = 0

            for i in range(0, len(docs), batch_size):
                batch = docs[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (len(docs) + batch_size - 1) // batch_size

                logger.info(f"Indexing batch {batch_num}/{total_batches} ({len(batch)} documents)...")

                result = self.es_service.bulk_index_articles(batch)
                total_new += result['created']
                total_duplicate += result['failed']

            finished_at = datetime.now(timezone.utc)
            duration = int((finished_at - started_at).total_seconds())

            stats = {
                "status": "success",
                "entries_found": len(entries),
                "entries_new": total_new,
                "entries_duplicate": total_duplicate,
                "duration_seconds": duration,
                "source": self.source_name,
                "category": self.category,
                "file_path": file_path
            }

            logger.info(
                f"Malpedia import completed | "
                f"Found: {len(entries)} | New: {total_new} | Duplicates: {total_duplicate} | "
                f"Duration: {duration}s"
            )

            return stats

        except Exception as e:
            logger.error(f"Error importing Malpedia BibTeX: {e}")
            finished_at = datetime.now(timezone.utc)
            duration = int((finished_at - started_at).total_seconds())

            return {
                "status": "error",
                "error": str(e),
                "duration_seconds": duration,
                "file_path": file_path
            }

    def import_from_url(
        self,
        url: str = "https://malpedia.caad.fkie.fraunhofer.de/library/download",
        download_path: str = "/tmp/malpedia.bib",
        batch_size: int = 1000,
        enrich_with_rss: bool = True,
        update_existing: bool = False
    ) -> Dict[str, Any]:
        """
        Download and import Malpedia BibTeX from URL

        Args:
            url: URL to download .bib file
            download_path: Temporary path to save downloaded file
            batch_size: Batch size for indexing
            enrich_with_rss: Whether to enrich with RSS feed data

        Returns:
            Import statistics dict
        """
        import requests

        logger.info(f"Downloading Malpedia BibTeX from: {url}")

        try:
            # Download file
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            # Save to temporary file
            Path(download_path).write_bytes(response.content)
            logger.info(f"Downloaded to: {download_path}")

            # Import from file
            return self.import_from_file(download_path, batch_size, enrich_with_rss, update_existing)

        except requests.RequestException as e:
            logger.error(f"Error downloading Malpedia BibTeX: {e}")
            return {
                "status": "error",
                "error": f"Download failed: {str(e)}",
                "url": url
            }

    def get_stats(self) -> Dict[str, Any]:
        """
        Get Malpedia-specific statistics from Elasticsearch

        Returns:
            Stats dict with Malpedia document counts
        """
        try:
            # Count Malpedia documents
            count_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"source_type": "bibtex"}},
                            {"term": {"feed_name.keyword": self.source_name}}
                        ]
                    }
                }
            }

            count_result = self.es_service.es.count(
                index=self.es_service.index_alias,
                body=count_query
            )

            total = count_result["count"]

            # Get date range
            aggs_query = {
                "size": 0,
                "query": count_query["query"],
                "aggs": {
                    "date_range": {
                        "stats": {"field": "published"}
                    },
                    "by_year": {
                        "date_histogram": {
                            "field": "published",
                            "calendar_interval": "year",
                            "format": "yyyy"
                        }
                    },
                    "by_organization": {
                        "terms": {
                            "field": "organization.keyword",
                            "size": 20
                        }
                    }
                }
            }

            aggs_result = self.es_service.es.search(
                index=self.es_service.index_alias,
                body=aggs_query
            )

            aggs = aggs_result["aggregations"]
            date_stats = aggs["date_range"]

            return {
                "total_entries": total,
                "oldest_entry": date_stats.get("min_as_string"),
                "newest_entry": date_stats.get("max_as_string"),
                "entries_by_year": [
                    {"year": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs["by_year"]["buckets"]
                ],
                "top_organizations": [
                    {"name": b["key"], "count": b["doc_count"]}
                    for b in aggs["by_organization"]["buckets"]
                ]
            }

        except Exception as e:
            logger.error(f"Error getting Malpedia stats: {e}")
            return {
                "total_entries": 0,
                "error": str(e)
            }
