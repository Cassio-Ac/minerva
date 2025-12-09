"""
BibTeX Parser Service
Parse BibTeX files and extract bibliographic entries
"""

import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class BibTeXParser:
    """Parser for BibTeX bibliographic files"""

    def __init__(self):
        # Regex patterns for BibTeX parsing
        self.entry_pattern = re.compile(
            r'@(\w+)\{([^,]+),\s*\n(.*?)\n\}',
            re.DOTALL
        )
        self.field_pattern = re.compile(
            r'(\w+)\s*=\s*\{(.+?)\}',
            re.DOTALL
        )

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a BibTeX file and extract all entries

        Args:
            file_path: Path to .bib file

        Returns:
            List of parsed entries as dictionaries
        """
        logger.info(f"Parsing BibTeX file: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            entries = self._parse_content(content)
            logger.info(f"Successfully parsed {len(entries)} BibTeX entries")

            return entries

        except Exception as e:
            logger.error(f"Error parsing BibTeX file: {e}")
            raise

    def parse_content(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse BibTeX content string

        Args:
            content: BibTeX content as string

        Returns:
            List of parsed entries
        """
        return self._parse_content(content)

    def _parse_content(self, content: str) -> List[Dict[str, Any]]:
        """
        Internal method to parse BibTeX content

        Args:
            content: BibTeX file content

        Returns:
            List of entry dictionaries
        """
        entries = []

        # Find all @online entries
        for match in self.entry_pattern.finditer(content):
            entry_type = match.group(1)
            entry_id = match.group(2).strip()
            fields_text = match.group(3)

            # Parse fields
            fields = {}
            for field_match in self.field_pattern.finditer(fields_text):
                field_name = field_match.group(1).strip()
                field_value = field_match.group(2).strip()
                # Remove extra braces if present (e.g., {{Title}} -> Title)
                field_value = re.sub(r'^\{+|\}+$', '', field_value)
                fields[field_name] = field_value

            # Build entry dict
            entry = {
                'entry_type': entry_type,
                'entry_id': entry_id,
                **fields
            }

            entries.append(entry)

        return entries

    def convert_to_elasticsearch_docs(
        self,
        entries: List[Dict[str, Any]],
        source_name: str = "Malpedia Library",
        category: str = "Threat Intelligence"
    ) -> List[Dict[str, Any]]:
        """
        Convert BibTeX entries to Elasticsearch document format

        Args:
            entries: List of BibTeX entries
            source_name: Name of the source
            category: Category name

        Returns:
            List of ES-compatible documents
        """
        docs = []
        collected_at = datetime.now(timezone.utc).isoformat()

        for entry in entries:
            try:
                # Parse date field
                date_str = entry.get('date', '')
                published_dt = self._parse_date(date_str)
                published_iso = published_dt.isoformat() if published_dt else collected_at

                # Build document
                doc = {
                    # Timestamps
                    "@timestamp": published_iso,
                    "published": published_iso,
                    "collected_at": collected_at,

                    # Content
                    "title": entry.get('title', '').strip(),
                    "link": entry.get('url', '').strip(),
                    "author": entry.get('author', '').strip(),
                    "organization": entry.get('organization', '').strip(),
                    "language": entry.get('language', 'English').strip(),

                    # BibTeX specific
                    "entry_id": entry.get('entry_id', '').strip(),
                    "entry_type": entry.get('entry_type', 'online').strip(),
                    "urldate": entry.get('urldate', '').strip(),

                    # Metadata
                    "feed_name": source_name,
                    "category": category,
                    "source_type": "bibtex",

                    # Use entry_id as content hash for deduplication
                    "content_hash": entry.get('entry_id', '').strip(),
                }

                docs.append(doc)

            except Exception as e:
                logger.warning(f"Error converting entry {entry.get('entry_id', 'unknown')}: {e}")
                continue

        logger.info(f"Converted {len(docs)} BibTeX entries to ES documents")
        return docs

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string from BibTeX
        Supports formats: YYYY-MM-DD, YYYY-MM, YYYY

        Args:
            date_str: Date string from BibTeX

        Returns:
            datetime object or None
        """
        if not date_str:
            return None

        # Try YYYY-MM-DD
        try:
            return datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        except ValueError:
            pass

        # Try YYYY-MM
        try:
            return datetime.strptime(date_str, '%Y-%m').replace(tzinfo=timezone.utc)
        except ValueError:
            pass

        # Try YYYY
        try:
            return datetime.strptime(date_str, '%Y').replace(tzinfo=timezone.utc)
        except ValueError:
            pass

        logger.debug(f"Could not parse date: {date_str}")
        return None
