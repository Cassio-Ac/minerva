"""
MISP Galaxy API Endpoints
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import logging

from app.db.database import get_db
from app.api.v1.auth import get_current_user
from app.cti.services.misp_galaxy_service import MISPGalaxyService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/galaxy", tags=["MISP Galaxy"])


@router.post("/import/{cluster_type}", summary="Import MISP Galaxy cluster")
async def import_galaxy_cluster(
    cluster_type: str,
    limit: Optional[int] = Query(None, description="Limit number of clusters to import"),
    skip_relationships: bool = Query(False, description="Skip importing relationships"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Import a MISP Galaxy cluster from GitHub

    **Available cluster types:**
    - threat-actor (864 entries)
    - malpedia (3,260 malware families)
    - tool (605 tools)
    - ransomware (300+ ransomware families)
    - botnet (132 botnets)
    - exploit-kit (52 exploit kits)

    **Example:**
    ```
    POST /api/v1/cti/galaxy/import/threat-actor?limit=100
    ```

    Returns statistics about the import.
    """
    service = MISPGalaxyService(db)

    try:
        result = await service.import_cluster(
            cluster_type=cluster_type,
            limit=limit,
            skip_relationships=skip_relationships
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error importing galaxy cluster: {e}")
        raise HTTPException(status_code=500, detail=f"Import failed: {str(e)}")


@router.get("/stats", summary="Get Galaxy statistics")
async def get_galaxy_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get statistics about imported Galaxy clusters

    Returns:
    - Total clusters imported
    - Count by cluster type
    - Count by country (for threat-actors)
    - Total relationships
    """
    service = MISPGalaxyService(db)
    stats = await service.get_stats()
    return stats


@router.get("/clusters", summary="Search Galaxy clusters")
async def search_galaxy_clusters(
    query: Optional[str] = Query(None, description="Search term (name or description)"),
    cluster_type: Optional[str] = Query(None, description="Filter by cluster type"),
    country: Optional[str] = Query(None, description="Filter by country (threat-actors only)"),
    limit: int = Query(default=100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Search and filter Galaxy clusters

    **Filters:**
    - `query`: Search in name and description
    - `cluster_type`: threat-actor, malpedia, tool, etc
    - `country`: ISO country code (CN, RU, US, etc)

    **Example:**
    ```
    GET /api/v1/cti/galaxy/clusters?cluster_type=threat-actor&country=CN&limit=50
    ```

    Returns paginated list of clusters.
    """
    service = MISPGalaxyService(db)

    result = await service.search_clusters(
        query=query,
        cluster_type=cluster_type,
        country=country,
        limit=limit,
        offset=offset
    )

    return result


@router.get("/clusters/{cluster_name}", summary="Get cluster by name")
async def get_cluster_by_name(
    cluster_name: str,
    cluster_type: Optional[str] = Query(None, description="Filter by cluster type"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get detailed information about a specific cluster by name

    **Example:**
    ```
    GET /api/v1/cti/galaxy/clusters/APT28?cluster_type=threat-actor
    ```

    Returns cluster details or 404 if not found.
    """
    service = MISPGalaxyService(db)

    cluster = await service.get_cluster_by_name(cluster_name, cluster_type)

    if not cluster:
        raise HTTPException(
            status_code=404,
            detail=f"Cluster '{cluster_name}' not found"
        )

    return cluster.to_dict()


@router.get("/actors-by-country", summary="Get threat actors grouped by country")
async def get_actors_by_country(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get threat actors grouped by country with counts

    Returns list of countries with actor counts for world map visualization.
    Each entry includes:
    - country: ISO 2-letter country code
    - count: Number of threat actors from that country
    - actors: List of actor names

    **Example response:**
    ```json
    {
        "countries": [
            {"country": "CN", "count": 45, "actors": ["APT1", "APT10", ...]},
            {"country": "RU", "count": 38, "actors": ["APT28", "APT29", ...]},
            ...
        ],
        "total_actors": 864,
        "countries_with_actors": 25
    }
    ```
    """
    from sqlalchemy import select, func
    from app.cti.models.galaxy_cluster import GalaxyCluster

    # Get actors grouped by country
    stmt = select(
        GalaxyCluster.country,
        func.count(GalaxyCluster.id).label('count'),
        func.array_agg(GalaxyCluster.value).label('actors')
    ).where(
        GalaxyCluster.galaxy_type == "threat-actor"
    ).where(
        GalaxyCluster.country.isnot(None)
    ).where(
        GalaxyCluster.country != ""
    ).group_by(
        GalaxyCluster.country
    ).order_by(
        func.count(GalaxyCluster.id).desc()
    )

    result = await db.execute(stmt)
    rows = result.all()

    countries = []
    total_actors = 0
    for row in rows:
        countries.append({
            "country": row.country,
            "count": row.count,
            "actors": sorted(row.actors) if row.actors else []
        })
        total_actors += row.count

    return {
        "countries": countries,
        "total_actors": total_actors,
        "countries_with_actors": len(countries)
    }


@router.get("/available", summary="List available cluster types")
async def list_available_clusters(
    current_user: dict = Depends(get_current_user),
):
    """
    List available cluster types for import

    Returns information about each available cluster type.
    """
    return {
        "clusters": [
            {
                "type": "threat-actor",
                "description": "Threat actors and APT groups (864 entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["threat-actor"]
            },
            {
                "type": "malpedia",
                "description": "Malware families from Malpedia (3,260 entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["malpedia"]
            },
            {
                "type": "tool",
                "description": "Tools used by attackers (605 entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["tool"]
            },
            {
                "type": "ransomware",
                "description": "Ransomware families (300+ entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["ransomware"]
            },
            {
                "type": "botnet",
                "description": "Botnet families (132 entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["botnet"]
            },
            {
                "type": "exploit-kit",
                "description": "Exploit kits (52 entries)",
                "url": MISPGalaxyService.AVAILABLE_CLUSTERS["exploit-kit"]
            },
        ]
    }
