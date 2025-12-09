"""
CTI Enrichment Service

Maps Malpedia threat actors and malware families to MITRE ATT&CK techniques.

Strategy:
1. For Actors: Extract MITRE Group ID from 'aka' field (e.g., "G0007")
2. Query MITRE ATT&CK data to get techniques used by those groups
3. For Families: Get actors that use the family, then get their techniques
4. Return unified list of technique IDs to highlight in the matrix
"""

import logging
import re
from typing import List, Set, Dict, Any, Optional
from elasticsearch import Elasticsearch

from .attack_service import get_attack_service
from app.db.elasticsearch import get_es_client
from app.core.config import settings

logger = logging.getLogger(__name__)


class EnrichmentService:
    """
    Service to enrich Malpedia data with MITRE ATT&CK techniques
    """

    def __init__(self):
        self.attack_service = get_attack_service()
        self.es_client: Optional[Elasticsearch] = None
        # Regex to match MITRE Group IDs (format: G####)
        self.group_id_pattern = re.compile(r'^G\d{4}$')
        # Cache for MITRE group mappings (name/alias -> STIX ID)
        self._mitre_group_cache: Optional[Dict[str, str]] = None

    async def _get_es_client(self):
        """Get or create Elasticsearch client (async)"""
        if self.es_client is None:
            self.es_client = await get_es_client()
        return self.es_client

    def _build_mitre_group_cache(self) -> Dict[str, str]:
        """
        Build complete mapping of MITRE group names/aliases to STIX IDs

        Returns:
            Dictionary mapping group name/alias (lowercase) -> STIX ID

        Example:
            {
                "apt28": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",
                "fancy bear": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",
                "g0007": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",
                ...
            }
        """
        if self._mitre_group_cache is not None:
            return self._mitre_group_cache

        logger.info("🔨 Building MITRE ATT&CK group mapping cache...")

        # Load MITRE ATT&CK data
        self.attack_service._ensure_loaded()
        groups = self.attack_service._attack_data.get_groups(remove_revoked_deprecated=True)

        mapping = {}

        for group in groups:
            stix_id = group.id

            # Add group name
            if hasattr(group, 'name'):
                mapping[group.name.lower()] = stix_id

            # Add all aliases
            if hasattr(group, 'aliases'):
                for alias in group.aliases:
                    mapping[alias.lower()] = stix_id

            # Add external ID (G####)
            if hasattr(group, 'external_references'):
                for ref in group.external_references:
                    if ref.source_name == 'mitre-attack' and hasattr(ref, 'external_id'):
                        mapping[ref.external_id.lower()] = stix_id

        self._mitre_group_cache = mapping
        logger.info(f"✅ Built mapping cache with {len(mapping)} entries for {len(groups)} groups")

        return mapping

    def _find_mitre_group_stix_id(self, actor_name: str, aka_list: Optional[List[str]] = None) -> Optional[str]:
        """
        Find MITRE group STIX ID by searching actor name and all aliases

        Args:
            actor_name: Actor name from Malpedia (e.g., "APT28")
            aka_list: List of aliases from Malpedia (e.g., ["G0007", "Fancy Bear", ...])

        Returns:
            STIX ID if found, None otherwise
        """
        # Build cache if not exists
        cache = self._build_mitre_group_cache()

        # Search candidates: actor name + all aliases
        candidates = [actor_name]
        if aka_list:
            candidates.extend(aka_list)

        # Try each candidate (case-insensitive)
        for candidate in candidates:
            if candidate:
                stix_id = cache.get(candidate.lower())
                if stix_id:
                    logger.info(f"✅ Found MITRE mapping: '{candidate}' -> {stix_id}")
                    return stix_id

        logger.warning(f"⚠️ No MITRE mapping found for actor '{actor_name}' (tried: {candidates})")
        return None

    # ==================== ACTOR ENRICHMENT ====================

    def _extract_mitre_group_id(self, aka_list: Optional[List[str]]) -> Optional[str]:
        """
        Extract MITRE Group ID from actor's 'aka' field

        Args:
            aka_list: List of aliases (e.g., ["APT 28", "G0007", "Fancy Bear"])

        Returns:
            MITRE Group ID (e.g., "G0007") or None if not found
        """
        if not aka_list:
            return None

        for alias in aka_list:
            if self.group_id_pattern.match(alias):
                return alias

        return None

    async def _get_actor_from_es(self, actor_name: str, server_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get actor document from Elasticsearch

        Args:
            actor_name: Actor name (e.g., "APT28")
            server_id: Optional Elasticsearch server ID

        Returns:
            Actor document or None if not found
        """
        try:
            es = await self._get_es_client()

            # Query for actor
            query = {
                "query": {
                    "term": {
                        "name.keyword": actor_name
                    }
                }
            }

            result = await es.search(
                index="malpedia_actors",
                body=query,
                size=1
            )

            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_source']
            else:
                logger.warning(f"⚠️ Actor not found in ES: {actor_name}")
                return None

        except Exception as e:
            logger.error(f"❌ Error fetching actor from ES: {e}")
            return None

    async def get_techniques_for_actor(
        self,
        actor_name: str,
        server_id: Optional[str] = None,
        use_cache: bool = True
    ) -> List[str]:
        """
        Get MITRE ATT&CK techniques used by a threat actor

        Strategy:
        1. Check cache first (if use_cache=True)
        2. If not in cache or expired, perform enrichment
        3. Save to cache for future use

        Args:
            actor_name: Actor name (e.g., "APT28", "Fancy Bear", etc.)
            server_id: Optional Elasticsearch server ID
            use_cache: Whether to use cached results (default True)

        Returns:
            List of technique IDs (e.g., ["T1003.003", "T1566.001", ...])
        """
        logger.info(f"🔍 Getting techniques for actor: {actor_name} (use_cache={use_cache})")

        # Try cache first
        if use_cache:
            try:
                from .enrichment_cache_service import get_enrichment_cache_service
                cache_service = get_enrichment_cache_service()
                cached = await cache_service.get_cached_techniques(actor_name)
                if cached is not None:
                    logger.info(f"✅ Using cached techniques for {actor_name}: {len(cached)} techniques")
                    return cached
            except Exception as e:
                logger.warning(f"⚠️ Cache lookup failed, falling back to live enrichment: {e}")

        # 1. Get actor from Elasticsearch
        actor_doc = await self._get_actor_from_es(actor_name, server_id)
        if not actor_doc:
            logger.warning(f"⚠️ Actor not found in Elasticsearch: {actor_name}")
            return []

        # 2. Find MITRE group STIX ID using actor name + all aliases
        aka_list = actor_doc.get('aka', [])
        group_stix_id = self._find_mitre_group_stix_id(actor_name, aka_list)

        if not group_stix_id:
            logger.warning(f"⚠️ No MITRE ATT&CK mapping found for actor: {actor_name}")
            return []

        # 3. Get techniques used by this group
        self.attack_service._ensure_loaded()
        techniques_data = self.attack_service._attack_data.get_techniques_used_by_group(group_stix_id)

        # 4. Extract technique IDs
        technique_ids = []
        for tech_data in techniques_data:
            tech_obj = tech_data['object']

            if hasattr(tech_obj, 'external_references'):
                for ref in tech_obj.external_references:
                    if ref.source_name == 'mitre-attack' and hasattr(ref, 'external_id'):
                        technique_ids.append(ref.external_id)
                        break

        logger.info(f"✅ Found {len(technique_ids)} techniques for actor {actor_name}")

        # Save to cache for future use
        if use_cache and technique_ids:
            try:
                from .enrichment_cache_service import get_enrichment_cache_service
                cache_service = get_enrichment_cache_service()
                await cache_service.save_enrichment(
                    actor_name=actor_name,
                    techniques=technique_ids,
                    mitre_stix_id=group_stix_id,
                    aliases=aka_list
                )
                logger.info(f"💾 Saved enrichment to cache for {actor_name}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to save to cache: {e}")

        return technique_ids

    # ==================== FAMILY ENRICHMENT ====================

    async def _get_family_from_es(self, family_name: str, server_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get family document from Elasticsearch

        Args:
            family_name: Family name (e.g., "win.caddywiper")
            server_id: Optional Elasticsearch server ID

        Returns:
            Family document or None if not found
        """
        try:
            es = await self._get_es_client()

            # Query for family
            query = {
                "query": {
                    "term": {
                        "name.keyword": family_name
                    }
                }
            }

            result = await es.search(
                index="malpedia_families",
                body=query,
                size=1
            )

            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_source']
            else:
                logger.warning(f"⚠️ Family not found in ES: {family_name}")
                return None

        except Exception as e:
            logger.error(f"❌ Error fetching family from ES: {e}")
            return None

    async def get_techniques_for_family(self, family_name: str, server_id: Optional[str] = None) -> List[str]:
        """
        Get MITRE ATT&CK techniques used by a malware family

        Strategy: Get actors that use this family, then get their techniques

        Args:
            family_name: Family name (e.g., "win.caddywiper")
            server_id: Optional Elasticsearch server ID

        Returns:
            List of technique IDs
        """
        logger.info(f"🔍 Getting techniques for family: {family_name}")

        # 1. Get family from Elasticsearch
        family_doc = await self._get_family_from_es(family_name, server_id)
        if not family_doc:
            logger.warning(f"⚠️ Family not found: {family_name}")
            return []

        # 2. Get actors that use this family
        actors = family_doc.get('actors', [])
        if not actors:
            logger.warning(f"⚠️ No actors associated with family: {family_name}")
            return []

        logger.info(f"✅ Found {len(actors)} actors for family {family_name}: {actors[:5]}...")

        # 3. Get techniques for each actor
        all_techniques = set()
        for actor_name in actors:
            actor_techniques = await self.get_techniques_for_actor(actor_name, server_id)
            all_techniques.update(actor_techniques)

        logger.info(f"✅ Found {len(all_techniques)} techniques for family {family_name} (via {len(actors)} actors)")
        return list(all_techniques)

    # ==================== UNIFIED ENRICHMENT ====================

    async def highlight_techniques(
        self,
        actors: Optional[List[str]] = None,
        families: Optional[List[str]] = None,
        mode: str = 'union',
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get techniques to highlight based on selected actors and families

        Args:
            actors: List of actor names (e.g., ["APT28", "APT29"])
            families: List of family names (e.g., ["win.caddywiper"])
            mode: 'union' (OR) or 'intersection' (AND)
            server_id: Optional Elasticsearch server ID

        Returns:
            {
                "highlighted_techniques": ["T1003.003", "T1566.001", ...],
                "technique_details": {...},
                "stats": {
                    "total_techniques": 150,
                    "actors_processed": 2,
                    "families_processed": 1
                }
            }
        """
        logger.info(f"🎯 Highlighting techniques (mode: {mode})")
        logger.info(f"   Actors: {actors}")
        logger.info(f"   Families: {families}")

        actors = actors or []
        families = families or []

        if not actors and not families:
            logger.warning("⚠️ No actors or families provided")
            return {
                "highlighted_techniques": [],
                "technique_details": {},
                "stats": {
                    "total_techniques": 0,
                    "actors_processed": 0,
                    "families_processed": 0
                }
            }

        # Collect techniques
        actor_techniques_sets = []
        family_techniques_sets = []

        # Import cache service
        from .enrichment_cache_service import get_enrichment_cache_service
        cache_service = get_enrichment_cache_service()

        # Process actors (WITH CACHE)
        for actor_name in actors:
            logger.info(f"🔍 Processing actor: {actor_name}")

            # Try cache first (24h TTL)
            techniques = await cache_service.get_cached_techniques(actor_name, max_age_hours=24)

            if techniques is not None:
                logger.info(f"✅ Cache HIT for {actor_name}: {len(techniques)} techniques")
            else:
                # Cache MISS - enrich and cache
                logger.info(f"❌ Cache MISS for {actor_name} - enriching...")
                techniques = await self.get_techniques_for_actor(actor_name, server_id)

                if techniques:
                    # Save to cache for next time
                    await cache_service.save_enrichment(
                        actor_name=actor_name,
                        techniques=techniques
                    )
                    logger.info(f"💾 Cached {len(techniques)} techniques for {actor_name}")

            if techniques:
                actor_techniques_sets.append(set(techniques))

        # Process families
        for family_name in families:
            techniques = await self.get_techniques_for_family(family_name, server_id)
            if techniques:
                family_techniques_sets.append(set(techniques))

        # Combine all sets
        all_sets = actor_techniques_sets + family_techniques_sets

        if not all_sets:
            logger.warning("⚠️ No techniques found for any actor or family")
            return {
                "highlighted_techniques": [],
                "technique_details": {},
                "stats": {
                    "total_techniques": 0,
                    "actors_processed": len(actors),
                    "families_processed": len(families)
                },
                "message": "No MITRE ATT&CK mappings found for selected actors/families"
            }

        # Apply mode (union or intersection)
        if mode == 'intersection':
            # Get techniques present in ALL selected actors/families
            result_techniques = set.intersection(*all_sets) if all_sets else set()
        else:  # union (default)
            # Get techniques present in ANY selected actor/family
            result_techniques = set.union(*all_sets) if all_sets else set()

        highlighted_techniques = sorted(list(result_techniques))

        # Get technique details for highlighting
        technique_details = {}
        for tech_id in highlighted_techniques:
            tech = self.attack_service.get_technique(tech_id)
            if tech:
                technique_details[tech_id] = tech

        logger.info(f"✅ Highlighted {len(highlighted_techniques)} techniques")

        return {
            "highlighted_techniques": highlighted_techniques,
            "technique_details": technique_details,
            "stats": {
                "total_techniques": len(highlighted_techniques),
                "actors_processed": len(actor_techniques_sets),
                "families_processed": len(family_techniques_sets)
            }
        }


# Singleton instance
_enrichment_service: Optional[EnrichmentService] = None


def get_enrichment_service() -> EnrichmentService:
    """Get singleton instance of EnrichmentService"""
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = EnrichmentService()
    return _enrichment_service
