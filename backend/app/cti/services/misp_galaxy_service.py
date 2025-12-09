"""
MISP Galaxy Service
Import e gerenciamento de clusters do MISP Galaxy
"""
import httpx
import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert

from app.cti.models.galaxy_cluster import GalaxyCluster, GalaxyRelationship

logger = logging.getLogger(__name__)


class MISPGalaxyService:
    """Service para importar e gerenciar clusters MISP Galaxy"""

    # Base URL do repositório MISP Galaxy
    GITHUB_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"

    # Clusters disponíveis
    AVAILABLE_CLUSTERS = {
        "threat-actor": f"{GITHUB_BASE}/threat-actor.json",
        "malpedia": f"{GITHUB_BASE}/malpedia.json",
        "tool": f"{GITHUB_BASE}/tool.json",
        "ransomware": f"{GITHUB_BASE}/ransomware.json",
        "botnet": f"{GITHUB_BASE}/botnet.json",
        "exploit-kit": f"{GITHUB_BASE}/exploit-kit.json",
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def download_cluster(self, cluster_type: str) -> Dict:
        """
        Download cluster JSON do GitHub

        Args:
            cluster_type: Tipo de cluster (threat-actor, malpedia, tool, etc)

        Returns:
            Dict com dados do cluster
        """
        if cluster_type not in self.AVAILABLE_CLUSTERS:
            raise ValueError(f"Cluster type '{cluster_type}' not available")

        url = self.AVAILABLE_CLUSTERS[cluster_type]
        logger.info(f"📥 Downloading {cluster_type} from {url}")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    def parse_cluster_value(self, cluster_type: str, value_data: Dict) -> Dict:
        """
        Parse um valor do cluster para o formato do banco

        Args:
            cluster_type: Tipo de cluster
            value_data: Dados brutos do valor

        Returns:
            Dict com dados parseados
        """
        meta = value_data.get("meta", {})

        # Dados comuns
        parsed = {
            "galaxy_type": cluster_type,
            "uuid_galaxy": value_data.get("uuid"),
            "value": value_data.get("value"),
            "description": value_data.get("description"),
            "synonyms": meta.get("synonyms"),
            "refs": meta.get("refs"),
            "raw_meta": meta,
        }

        # Metadados específicos de threat-actor
        if cluster_type == "threat-actor":
            parsed.update({
                "country": meta.get("country"),
                "attribution_confidence": self._parse_confidence(meta.get("attribution-confidence")),
                "suspected_state_sponsor": meta.get("cfr-suspected-state-sponsor"),
                "suspected_victims": meta.get("cfr-suspected-victims"),
                "target_category": meta.get("cfr-target-category"),
                "type_of_incident": meta.get("cfr-type-of-incident"),
                "targeted_sector": meta.get("targeted-sector"),
                "motive": meta.get("motive"),
            })

        # Metadados específicos de malware
        elif cluster_type in ["malpedia", "ransomware"]:
            parsed.update({
                "malware_type": meta.get("type"),
            })

        return parsed

    def _parse_confidence(self, value: any) -> Optional[int]:
        """Convert confidence string/int to int"""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    async def import_cluster(
        self,
        cluster_type: str,
        limit: Optional[int] = None,
        skip_relationships: bool = False
    ) -> Dict:
        """
        Importa um cluster do MISP Galaxy

        Args:
            cluster_type: Tipo de cluster (threat-actor, malpedia, etc)
            limit: Limite de valores para importar (None = todos)
            skip_relationships: Se True, não importa relacionamentos

        Returns:
            Dict com estatísticas da importação
        """
        logger.info(f"🚀 Starting import of {cluster_type} cluster")

        # 1. Download cluster
        cluster_data = await self.download_cluster(cluster_type)
        values = cluster_data.get("values", [])
        total_values = len(values)

        if limit:
            values = values[:limit]
            logger.info(f"⚠️  Limiting import to {limit} values (total: {total_values})")

        logger.info(f"📊 Found {len(values)} values to import")

        # 2. Parse e prepara dados para batch insert
        clusters_to_insert = []
        for value_data in values:
            try:
                parsed = self.parse_cluster_value(cluster_type, value_data)
                clusters_to_insert.append(parsed)
            except Exception as e:
                logger.error(f"❌ Error parsing value {value_data.get('value', 'unknown')}: {e}")
                continue

        # 3. Batch insert com upsert (on conflict do update)
        imported_count = 0

        for cluster_data in clusters_to_insert:
            try:
                stmt = insert(GalaxyCluster).values(**cluster_data)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["uuid_galaxy"],
                    set_={
                        "value": stmt.excluded.value,
                        "description": stmt.excluded.description,
                        "synonyms": stmt.excluded.synonyms,
                        "refs": stmt.excluded.refs,
                        "country": stmt.excluded.country,
                        "attribution_confidence": stmt.excluded.attribution_confidence,
                        "raw_meta": stmt.excluded.raw_meta,
                    }
                )
                await self.db.execute(stmt)
                imported_count += 1
            except Exception as e:
                logger.error(f"❌ Error inserting {cluster_data.get('value')}: {e}")
                continue

        await self.db.commit()
        logger.info(f"✅ Imported {imported_count} clusters")

        # 4. Import relationships (se não pulado)
        relationships_count = 0
        if not skip_relationships:
            logger.info(f"🔗 Importing relationships...")
            relationships_count = await self._import_relationships(values)

        return {
            "cluster_type": cluster_type,
            "total_available": total_values,
            "total_processed": len(values),
            "imported": imported_count,
            "relationships": relationships_count,
        }

    async def _import_relationships(self, values: List[Dict]) -> int:
        """
        Importa relacionamentos entre clusters

        Args:
            values: Lista de valores do cluster

        Returns:
            Número de relacionamentos importados
        """
        count = 0
        for value_data in values:
            uuid_galaxy = value_data.get("uuid")
            related = value_data.get("related", [])

            if not related or not uuid_galaxy:
                continue

            # Busca cluster source no banco
            stmt = select(GalaxyCluster).where(GalaxyCluster.uuid_galaxy == uuid_galaxy)
            result = await self.db.execute(stmt)
            source_cluster = result.scalar_one_or_none()

            if not source_cluster:
                continue

            # Insere relacionamentos
            for rel in related:
                try:
                    relationship = GalaxyRelationship(
                        source_cluster_id=source_cluster.id,
                        dest_cluster_uuid=rel.get("dest-uuid"),
                        relationship_type=rel.get("type", "unknown"),
                        tags=rel.get("tags", []),
                    )
                    self.db.add(relationship)
                    count += 1
                except Exception as e:
                    logger.error(f"Error creating relationship: {e}")
                    continue

        await self.db.commit()
        logger.info(f"✅ Imported {count} relationships")
        return count

    async def get_stats(self) -> Dict:
        """Obtém estatísticas dos clusters importados"""
        # Total por tipo
        stmt = select(
            GalaxyCluster.galaxy_type,
            func.count(GalaxyCluster.id)
        ).group_by(GalaxyCluster.galaxy_type)

        result = await self.db.execute(stmt)
        by_type = {row[0]: row[1] for row in result.all()}

        # Total de relacionamentos
        stmt = select(func.count(GalaxyRelationship.id))
        result = await self.db.execute(stmt)
        total_relationships = result.scalar()

        # Total por país (threat-actors)
        stmt = select(
            GalaxyCluster.country,
            func.count(GalaxyCluster.id)
        ).where(
            GalaxyCluster.galaxy_type == "threat-actor"
        ).where(
            GalaxyCluster.country.isnot(None)
        ).group_by(GalaxyCluster.country)

        result = await self.db.execute(stmt)
        by_country = {row[0]: row[1] for row in result.all()}

        stats = {
            "total_clusters": sum(by_type.values()),
            "by_type": by_type,
            "by_country": by_country,
            "total_relationships": total_relationships,
        }

        return stats

    async def search_clusters(
        self,
        query: Optional[str] = None,
        cluster_type: Optional[str] = None,
        country: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict:
        """
        Busca clusters com filtros

        Args:
            query: Texto para buscar em value e synonyms
            cluster_type: Filtrar por tipo
            country: Filtrar por país
            limit: Limite de resultados
            offset: Offset para paginação

        Returns:
            Dict com clusters e total
        """
        stmt = select(GalaxyCluster)

        # Filtros
        if cluster_type:
            stmt = stmt.where(GalaxyCluster.galaxy_type == cluster_type)

        if country:
            stmt = stmt.where(GalaxyCluster.country == country)

        if query:
            stmt = stmt.where(
                (GalaxyCluster.value.ilike(f"%{query}%")) |
                (GalaxyCluster.description.ilike(f"%{query}%"))
            )

        # Count total
        count_stmt = select(func.count()).select_from(stmt.alias())
        result = await self.db.execute(count_stmt)
        total = result.scalar()

        # Paginação
        stmt = stmt.limit(limit).offset(offset)
        result = await self.db.execute(stmt)
        clusters = result.scalars().all()

        return {
            "clusters": [c.to_dict() for c in clusters],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    async def get_cluster_by_name(self, name: str, cluster_type: Optional[str] = None) -> Optional[GalaxyCluster]:
        """
        Busca cluster por nome exato

        Args:
            name: Nome do cluster
            cluster_type: Tipo (opcional)

        Returns:
            Cluster ou None
        """
        stmt = select(GalaxyCluster).where(GalaxyCluster.value == name)

        if cluster_type:
            stmt = stmt.where(GalaxyCluster.galaxy_type == cluster_type)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
