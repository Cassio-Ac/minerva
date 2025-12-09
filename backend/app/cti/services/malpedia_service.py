"""
Malpedia Service - Acesso aos dados Malpedia no Elasticsearch

Este serviço lê os dados EXISTENTES dos índices malpedia_actors e malpedia_families.
Não modifica ou cria novos dados.
"""

import logging
from typing import List, Dict, Any, Optional
from elasticsearch import AsyncElasticsearch

from app.services.es_client_factory import ESClientFactory

logger = logging.getLogger(__name__)


class MalpediaService:
    """
    Service para acessar dados Malpedia no Elasticsearch

    Lê dados dos índices:
    - malpedia_actors (864 atores)
    - malpedia_families (3,578 famílias)
    """

    def __init__(self, server_id: Optional[str] = None):
        """
        Initialize service

        Args:
            server_id: Optional ES server ID. If None, uses default.
        """
        self.server_id = server_id
        self._es_client: Optional[AsyncElasticsearch] = None

    async def _get_es_client(self) -> AsyncElasticsearch:
        """Get Elasticsearch client"""
        if self._es_client is None:
            factory = ESClientFactory()
            self._es_client = await factory.get_client(server_id=self.server_id)
        return self._es_client

    # ==================== ACTORS ====================

    async def get_actors(
        self,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """
        Get list of threat actors

        Args:
            search: Optional search query
            page: Page number (1-indexed)
            page_size: Items per page (max 100)

        Returns:
            {
                "total": int,
                "actors": [list of actors],
                "page": int,
                "page_size": int
            }
        """
        es = await self._get_es_client()

        # Build query
        if search:
            query = {
                "bool": {
                    "should": [
                        {"match": {"name": {"query": search, "boost": 2}}},
                        {"match": {"aka": search}},
                        {"match": {"explicacao": search}}
                    ],
                    "minimum_should_match": 1
                }
            }
        else:
            query = {"match_all": {}}

        # Calculate pagination
        from_idx = (page - 1) * page_size

        try:
            response = await es.search(
                index="malpedia_actors",
                body={
                    "query": query,
                    "from": from_idx,
                    "size": min(page_size, 100),
                    "sort": [{"name.keyword": "asc"}],
                    "_source": ["name", "aka", "explicacao", "familias_relacionadas", "url", "referencias"]
                }
            )

            actors = [hit["_source"] for hit in response["hits"]["hits"]]
            total = response["hits"]["total"]["value"]

            logger.info(f"📊 Retrieved {len(actors)} actors (total: {total})")

            return {
                "total": total,
                "actors": actors,
                "page": page,
                "page_size": page_size
            }

        except Exception as e:
            logger.error(f"❌ Error getting actors: {e}")
            raise

    async def get_actor_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get actor by exact name

        Args:
            name: Actor name (case-insensitive)

        Returns:
            Actor document or None
        """
        es = await self._get_es_client()

        try:
            response = await es.search(
                index="malpedia_actors",
                body={
                    "query": {
                        "term": {"name.keyword": name}
                    },
                    "size": 1
                }
            )

            if response["hits"]["total"]["value"] > 0:
                actor = response["hits"]["hits"][0]["_source"]
                logger.info(f"✅ Found actor: {name}")
                return actor
            else:
                logger.warning(f"⚠️ Actor not found: {name}")
                return None

        except Exception as e:
            logger.error(f"❌ Error getting actor {name}: {e}")
            raise

    async def get_actor_families(self, actor_name: str) -> List[str]:
        """
        Get list of malware families associated with an actor

        Args:
            actor_name: Actor name

        Returns:
            List of family names (e.g., ["win.emotet", "win.trickbot"])
        """
        actor = await self.get_actor_by_name(actor_name)
        if actor and "familias_relacionadas" in actor:
            families = actor["familias_relacionadas"]
            if families and len(families) > 0:
                logger.info(f"🔗 Actor {actor_name} has {len(families)} families")
                return families
        return []

    # ==================== FAMILIES ====================

    async def get_families(
        self,
        search: Optional[str] = None,
        os_filter: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """
        Get list of malware families

        Args:
            search: Optional search query
            os_filter: Filter by OS (e.g., ["Windows", "Linux"])
            page: Page number (1-indexed)
            page_size: Items per page (max 100)

        Returns:
            {
                "total": int,
                "families": [list of families],
                "page": int,
                "page_size": int
            }
        """
        es = await self._get_es_client()

        # Build query
        must_clauses = []

        if search:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"match": {"name": {"query": search, "boost": 2}}},
                        {"match": {"aka": search}},
                        {"match": {"descricao": search}}
                    ],
                    "minimum_should_match": 1
                }
            })

        if os_filter and len(os_filter) > 0:
            must_clauses.append({
                "terms": {"os.keyword": os_filter}
            })

        if must_clauses:
            query = {"bool": {"must": must_clauses}}
        else:
            query = {"match_all": {}}

        # Calculate pagination
        from_idx = (page - 1) * page_size

        try:
            response = await es.search(
                index="malpedia_families",
                body={
                    "query": query,
                    "from": from_idx,
                    "size": min(page_size, 100),
                    "sort": [{"name.keyword": "asc"}],
                    "_source": {
                        "excludes": ["yara_rules.conteudo"]  # Exclude large YARA content
                    }
                }
            )

            families = [hit["_source"] for hit in response["hits"]["hits"]]
            total = response["hits"]["total"]["value"]

            logger.info(f"📊 Retrieved {len(families)} families (total: {total})")

            return {
                "total": total,
                "families": families,
                "page": page,
                "page_size": page_size
            }

        except Exception as e:
            logger.error(f"❌ Error getting families: {e}")
            raise

    async def get_family_by_name(self, name: str, include_yara: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get family by exact name

        Args:
            name: Family name (e.g., "IsaacWiper")
            include_yara: Include YARA rule content (can be large)

        Returns:
            Family document or None
        """
        es = await self._get_es_client()

        try:
            # Build source filter
            source_config = None
            if not include_yara:
                source_config = {"excludes": ["yara_rules.conteudo"]}

            response = await es.search(
                index="malpedia_families",
                body={
                    "query": {
                        "term": {"name.keyword": name}
                    },
                    "size": 1,
                    "_source": source_config
                }
            )

            if response["hits"]["total"]["value"] > 0:
                family = response["hits"]["hits"][0]["_source"]
                logger.info(f"✅ Found family: {name}")
                return family
            else:
                logger.warning(f"⚠️ Family not found: {name}")
                return None

        except Exception as e:
            logger.error(f"❌ Error getting family {name}: {e}")
            raise

    async def get_families_by_names(self, names: List[str]) -> List[Dict[str, Any]]:
        """
        Get multiple families by names (batch query)

        Args:
            names: List of family names

        Returns:
            List of family documents
        """
        if not names or len(names) == 0:
            return []

        es = await self._get_es_client()

        try:
            response = await es.search(
                index="malpedia_families",
                body={
                    "query": {
                        "terms": {"name.keyword": names}
                    },
                    "size": min(len(names), 1000),
                    "_source": {
                        "excludes": ["yara_rules.conteudo"]
                    }
                }
            )

            families = [hit["_source"] for hit in response["hits"]["hits"]]
            logger.info(f"✅ Retrieved {len(families)}/{len(names)} families")
            return families

        except Exception as e:
            logger.error(f"❌ Error getting families: {e}")
            raise

    async def get_family_actors(self, family_name: str) -> List[str]:
        """
        Get list of actors associated with a family

        NOTE: The 'actors' field in malpedia_families is EMPTY in current data.
        This method computes the relationship by querying actors.

        Args:
            family_name: Family name

        Returns:
            List of actor names using this family
        """
        es = await self._get_es_client()

        try:
            # Query actors that have this family in familias_relacionadas
            response = await es.search(
                index="malpedia_actors",
                body={
                    "query": {
                        "term": {"familias_relacionadas.keyword": family_name}
                    },
                    "size": 1000,
                    "_source": ["name"]
                }
            )

            actors = [hit["_source"]["name"] for hit in response["hits"]["hits"]]
            logger.info(f"🔗 Family {family_name} used by {len(actors)} actors")
            return actors

        except Exception as e:
            logger.error(f"❌ Error getting actors for family {family_name}: {e}")
            raise

    # ==================== STATISTICS ====================

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get general statistics about Malpedia data

        Returns:
            {
                "total_actors": int,
                "total_families": int,
                "families_by_os": {os: count},
                "top_actors_by_families": [{actor, count}]
            }
        """
        es = await self._get_es_client()

        try:
            # Get total counts
            actors_count = await es.count(index="malpedia_actors")
            families_count = await es.count(index="malpedia_families")

            # Get families by OS
            os_agg = await es.search(
                index="malpedia_families",
                body={
                    "size": 0,
                    "aggs": {
                        "os_distribution": {
                            "terms": {
                                "field": "os.keyword",
                                "size": 20
                            }
                        }
                    }
                }
            )

            os_stats = {
                bucket["key"]: bucket["doc_count"]
                for bucket in os_agg["aggregations"]["os_distribution"]["buckets"]
            }

            # Get top actors by number of families
            actors = await self.get_actors(page=1, page_size=1000)
            top_actors = sorted(
                [
                    {
                        "actor": a["name"],
                        "families_count": len(a.get("familias_relacionadas", []))
                    }
                    for a in actors["actors"]
                ],
                key=lambda x: x["families_count"],
                reverse=True
            )[:10]

            stats = {
                "total_actors": actors_count["count"],
                "total_families": families_count["count"],
                "families_by_os": os_stats,
                "top_actors_by_families": top_actors
            }

            logger.info(f"📊 Stats: {stats['total_actors']} actors, {stats['total_families']} families")
            return stats

        except Exception as e:
            logger.error(f"❌ Error getting stats: {e}")
            raise


# Singleton instance
_malpedia_service: Optional[MalpediaService] = None


def get_malpedia_service(server_id: Optional[str] = None) -> MalpediaService:
    """Get singleton instance of MalpediaService"""
    global _malpedia_service
    if _malpedia_service is None or (_malpedia_service.server_id != server_id):
        _malpedia_service = MalpediaService(server_id=server_id)
    return _malpedia_service
