"""
Unified IOC Correlation Engine

Handles merging of IOC data from multiple sources, tracking relationships,
and maintaining data integrity across correlations.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class IOCCorrelationEngine:
    """Engine for correlating IOCs across multiple sources"""

    # TLP ordering (higher = more restrictive)
    TLP_ORDER = {
        "white": 0,
        "clear": 0,  # Alias for white
        "green": 1,
        "amber": 2,
        "amber+strict": 3,
        "red": 4
    }

    def correlate(
        self,
        existing_doc: Dict[str, Any],
        new_source: Dict[str, Any],
        source_name: str
    ) -> Dict[str, Any]:
        """
        Correlate new source data with existing IOC document.

        Strategy:
        - Add new source to sources array (or update if same source)
        - Merge tags, references, mitre_attack (union)
        - Update last_seen timestamp
        - Prefer non-null values for threat_actor, malware_family
        - Use most restrictive TLP

        Args:
            existing_doc: Current IOC document from Elasticsearch
            new_source: New source data in unified format
            source_name: Name of the source (misp, otx, etc.)

        Returns:
            Updated document ready for indexing
        """
        now = datetime.now(timezone.utc).isoformat()

        # Copy existing doc to avoid mutation
        doc = dict(existing_doc)

        # Find if source already exists in sources array
        source_index = self._find_source_index(doc.get("sources", []), source_name)

        # Build new source entry
        new_source_entry = self._build_source_entry(new_source, source_name, now)

        if source_index is not None:
            # Update existing source
            existing_source = doc["sources"][source_index]
            new_source_entry["first_seen_by_source"] = existing_source.get("first_seen_by_source")
            doc["sources"][source_index] = new_source_entry
        else:
            # Add new source
            if "sources" not in doc:
                doc["sources"] = []
            doc["sources"].append(new_source_entry)

            # Update source tracking
            doc["source_count"] = len(doc["sources"])
            source_names = doc.get("source_names", [])
            if source_name not in source_names:
                doc["source_names"] = source_names + [source_name]

        # Merge array fields (union, deduplicated)
        doc["tags"] = self._merge_arrays(
            doc.get("tags", []),
            new_source.get("tags", [])
        )
        doc["mitre_attack"] = self._merge_arrays(
            doc.get("mitre_attack", []),
            new_source.get("attack_ids", [])
        )
        doc["references"] = self._merge_arrays(
            doc.get("references", []),
            new_source.get("references", [])
        )
        doc["targeted_countries"] = self._merge_arrays(
            doc.get("targeted_countries", []),
            new_source.get("targeted_countries", [])
        )
        doc["targeted_industries"] = self._merge_arrays(
            doc.get("targeted_industries", []),
            new_source.get("industries", [])
        )
        doc["campaigns"] = self._merge_arrays(
            doc.get("campaigns", []),
            new_source.get("campaigns", [])
        )

        # Prefer non-null values for key attribution fields
        doc = self._merge_attribution(doc, new_source)

        # Update TLP (use most restrictive)
        doc["tlp"] = self._get_most_restrictive_tlp(
            doc.get("tlp", "white"),
            new_source.get("tlp", "white")
        )

        # Update timestamps
        doc["last_seen"] = now
        doc["last_updated"] = now

        # Preserve first_seen from earliest source
        doc["first_seen"] = self._get_earliest_date(
            doc.get("first_seen"),
            new_source.get("first_seen")
        )

        return doc

    def create_new_document(
        self,
        normalized_value: str,
        value_hash: str,
        ioc_type: str,
        source_name: str,
        source_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new IOC document structure from first source.

        Args:
            normalized_value: Normalized IOC value
            value_hash: SHA256 hash for deduplication
            ioc_type: IOC type (ip, domain, url, hash, email)
            source_name: Name of the source
            source_data: Source data in unified format

        Returns:
            New document ready for indexing
        """
        now = datetime.now(timezone.utc).isoformat()

        source_entry = self._build_source_entry(source_data, source_name, now)

        return {
            # Identification
            "ioc_id": value_hash[:16],
            "ioc_value": normalized_value,
            "ioc_value_hash": value_hash,
            "ioc_type": ioc_type,
            "ioc_subtype": source_data.get("subtype"),

            # Sources
            "sources": [source_entry],
            "source_count": 1,
            "source_names": [source_name],

            # Attribution
            "threat_type": source_data.get("threat_type"),
            "malware_family": source_data.get("malware_family"),
            "threat_actor": source_data.get("threat_actor"),
            "campaigns": source_data.get("campaigns", []),

            # Classification
            "tags": source_data.get("tags", []),
            "mitre_attack": source_data.get("attack_ids", []),
            "tlp": source_data.get("tlp", "white"),

            # Targeting
            "targeted_countries": source_data.get("targeted_countries", []),
            "targeted_industries": source_data.get("industries", []),
            "references": source_data.get("references", []),

            # Timestamps
            "first_seen": source_data.get("first_seen") or now,
            "last_seen": now,
            "last_updated": now,
            "created_at": now,

            # Status
            "is_active": True,
            "is_false_positive": False,
            "to_ids": source_data.get("to_ids", True),

            # Enrichment (to be filled later)
            "enrichment": None,
            "geo": None
        }

    def _find_source_index(self, sources: List[Dict], source_name: str) -> Optional[int]:
        """Find index of source in sources array"""
        for i, src in enumerate(sources):
            if src.get("source_name") == source_name:
                return i
        return None

    def _build_source_entry(
        self,
        source_data: Dict[str, Any],
        source_name: str,
        now: str
    ) -> Dict[str, Any]:
        """Build source entry object for sources array"""
        return {
            "source_name": source_name,
            "source_id": source_data.get("source_id"),
            "source_ref": source_data.get("source_ref"),
            "source_confidence": source_data.get("confidence", 1.0),
            "source_reputation": source_data.get("reputation"),
            "first_seen_by_source": source_data.get("first_seen") or now,
            "last_seen_by_source": now,
            "context": source_data.get("context"),
            "raw_data": source_data.get("raw_data")
        }

    def _merge_arrays(self, arr1: List, arr2: List) -> List:
        """Merge two arrays with deduplication, preserving order"""
        if not arr1 and not arr2:
            return []

        seen = set()
        result = []

        for item in (arr1 or []):
            if item and item not in seen:
                seen.add(item)
                result.append(item)

        for item in (arr2 or []):
            if item and item not in seen:
                seen.add(item)
                result.append(item)

        return result

    def _merge_attribution(
        self,
        doc: Dict[str, Any],
        new_source: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merge attribution fields (malware_family, threat_actor, threat_type).
        Prefer non-null values, but don't overwrite existing data.
        """
        attribution_fields = ["malware_family", "threat_actor", "threat_type"]

        for field in attribution_fields:
            current = doc.get(field)
            new_value = new_source.get(field)

            if new_value and not current:
                doc[field] = new_value
            elif new_value and current and new_value != current:
                # Both have values, store in a list or comma-separated
                # For now, keep first (could be enhanced to store multiple)
                pass

        return doc

    def _get_most_restrictive_tlp(self, tlp1: str, tlp2: str) -> str:
        """Return the most restrictive TLP level"""
        order1 = self.TLP_ORDER.get(tlp1.lower() if tlp1 else "white", 0)
        order2 = self.TLP_ORDER.get(tlp2.lower() if tlp2 else "white", 0)

        if order2 > order1:
            return tlp2.lower() if tlp2 else "white"
        return tlp1.lower() if tlp1 else "white"

    def _get_earliest_date(
        self,
        date1: Optional[str],
        date2: Optional[str]
    ) -> Optional[str]:
        """Return the earliest of two ISO date strings"""
        if not date1:
            return date2
        if not date2:
            return date1

        try:
            d1 = datetime.fromisoformat(date1.replace('Z', '+00:00'))
            d2 = datetime.fromisoformat(date2.replace('Z', '+00:00'))
            return date1 if d1 < d2 else date2
        except (ValueError, AttributeError):
            return date1

    def get_correlation_summary(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of correlations for an IOC.

        Returns:
            Summary with source count, confidence, and key attributes
        """
        sources = doc.get("sources", [])

        return {
            "ioc_value": doc.get("ioc_value"),
            "ioc_type": doc.get("ioc_type"),
            "source_count": len(sources),
            "source_names": [s.get("source_name") for s in sources],
            "is_multi_source": len(sources) > 1,
            "has_attribution": bool(
                doc.get("threat_actor") or doc.get("malware_family")
            ),
            "has_mitre": bool(doc.get("mitre_attack")),
            "tag_count": len(doc.get("tags", [])),
            "confidence_score": doc.get("confidence_score", 0),
            "confidence_level": doc.get("confidence_level", "unknown"),
            "tlp": doc.get("tlp", "white")
        }


# Singleton instance
_engine = None

def get_correlation_engine() -> IOCCorrelationEngine:
    """Get singleton correlation engine instance"""
    global _engine
    if _engine is None:
        _engine = IOCCorrelationEngine()
    return _engine
