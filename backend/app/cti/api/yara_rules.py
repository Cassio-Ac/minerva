"""
YARA Rules API Endpoints

Browse, search and filter YARA rules from unified Elasticsearch index
(Signature Base + Malpedia)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from app.db.database import get_db
from app.db.elasticsearch import get_es_client
from app.cti.models.yara_rule import YaraSyncHistory, SignatureBaseIOC
from app.cti.services.yara_elasticsearch_service import YARAElasticsearchService
from app.models.user import User
from app.core.dependencies import get_current_user
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()


# ====== SCHEMAS ======

class YaraRuleResponse(BaseModel):
    id: str
    rule_name: str
    source: str
    source_file: Optional[str]
    category: Optional[str]
    threat_name: Optional[str]
    threat_actor: Optional[str]
    malware_family: Optional[str]
    malware_aliases: Optional[List[str]]
    description: Optional[str]
    author: Optional[str]
    tags: List[str]
    mitre_attack: List[str]
    severity: Optional[str]
    strings_count: int
    is_active: bool
    synced_at: Optional[datetime]

    class Config:
        from_attributes = True


class YaraRuleDetailResponse(YaraRuleResponse):
    rule_content: str
    rule_hash: Optional[str]
    source_url: Optional[str]
    references: List[str]
    date: Optional[str]
    version: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class YaraRulesListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    rules: List[YaraRuleResponse]


class YaraStatsResponse(BaseModel):
    total_rules: int
    active_rules: int
    by_category: dict
    by_source: dict
    by_threat_actor: dict
    by_malware_family: dict
    total_families: Optional[int] = None
    last_sync: Optional[datetime]


class SignatureBaseIOCResponse(BaseModel):
    id: str
    value: str
    type: str
    description: Optional[str]
    source_file: Optional[str]
    hash_type: Optional[str]
    is_active: bool
    synced_at: datetime

    class Config:
        from_attributes = True


class IOCsListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    iocs: List[SignatureBaseIOCResponse]


# ====== YARA RULES ENDPOINTS (Elasticsearch) ======

@router.get("/rules", response_model=YaraRulesListResponse)
async def list_yara_rules(
    search: Optional[str] = Query(None, description="Search in rule name, description, threat, family"),
    category: Optional[str] = Query(None, description="Filter by category"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor"),
    malware_family: Optional[str] = Query(None, description="Filter by malware family"),
    mitre_attack: Optional[str] = Query(None, description="Filter by MITRE ATT&CK technique"),
    source: Optional[str] = Query(None, description="Filter by source (signature_base, malpedia)"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user)
):
    """
    List YARA rules with filtering and pagination.

    Searches unified index with rules from:
    - Signature Base (Neo23x0)
    - Malpedia (Fraunhofer)
    """
    service = YARAElasticsearchService()

    try:
        tags_list = tags.split(",") if tags else None

        result = await service.search_rules(
            search=search,
            source=source,
            category=category,
            threat_actor=threat_actor,
            malware_family=malware_family,
            mitre_attack=mitre_attack,
            tags=tags_list,
            page=page,
            page_size=page_size
        )

        rules = []
        for r in result.get("rules", []):
            rules.append(YaraRuleResponse(
                id=r.get("id") or r.get("rule_id", ""),
                rule_name=r.get("rule_name", ""),
                source=r.get("source", ""),
                source_file=r.get("source_file"),
                category=r.get("category"),
                threat_name=r.get("threat_name"),
                threat_actor=r.get("threat_actor"),
                malware_family=r.get("malware_family"),
                malware_aliases=r.get("malware_aliases", []),
                description=r.get("description"),
                author=r.get("author"),
                tags=r.get("tags", []) or [],
                mitre_attack=r.get("mitre_attack", []) or [],
                severity=r.get("severity"),
                strings_count=r.get("strings_count", 0) or 0,
                is_active=r.get("is_active", True),
                synced_at=r.get("synced_at")
            ))

        return YaraRulesListResponse(
            total=result.get("total", 0),
            page=page,
            page_size=page_size,
            rules=rules
        )
    finally:
        await service.close()


@router.get("/rules/{rule_id}", response_model=YaraRuleDetailResponse)
async def get_yara_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific YARA rule including full content
    """
    service = YARAElasticsearchService()

    try:
        rule = await service.get_rule_by_id(rule_id)

        if not rule:
            raise HTTPException(status_code=404, detail="YARA rule not found")

        return YaraRuleDetailResponse(
            id=rule.get("id") or rule.get("rule_id", ""),
            rule_name=rule.get("rule_name", ""),
            rule_hash=rule.get("rule_hash"),
            source=rule.get("source", ""),
            source_file=rule.get("source_file"),
            source_url=rule.get("source_url"),
            category=rule.get("category"),
            threat_name=rule.get("threat_name"),
            threat_actor=rule.get("threat_actor"),
            malware_family=rule.get("malware_family"),
            malware_aliases=rule.get("malware_aliases", []),
            rule_content=rule.get("rule_content", ""),
            description=rule.get("description"),
            author=rule.get("author"),
            references=rule.get("references", []) or [],
            date=rule.get("date"),
            version=rule.get("version"),
            tags=rule.get("tags", []) or [],
            mitre_attack=rule.get("mitre_attack", []) or [],
            severity=rule.get("severity"),
            strings_count=rule.get("strings_count", 0) or 0,
            is_active=rule.get("is_active", True),
            synced_at=rule.get("synced_at"),
            created_at=rule.get("created_at"),
            updated_at=rule.get("updated_at")
        )
    finally:
        await service.close()


@router.get("/stats", response_model=YaraStatsResponse)
async def get_yara_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get statistics about YARA rules from unified index
    """
    service = YARAElasticsearchService()

    try:
        stats = await service.get_stats()

        # Get last sync from PostgreSQL history
        sync_result = await session.execute(
            select(YaraSyncHistory.completed_at)
            .where(YaraSyncHistory.status == 'completed')
            .order_by(YaraSyncHistory.completed_at.desc())
            .limit(1)
        )
        last_sync_row = sync_result.scalar_one_or_none()

        return YaraStatsResponse(
            total_rules=stats.get("total_rules", 0),
            active_rules=stats.get("active_rules", 0),
            by_category=stats.get("by_category", {}),
            by_source=stats.get("by_source", {}),
            by_threat_actor=stats.get("by_threat_actor", {}),
            by_malware_family=stats.get("by_malware_family", {}),
            total_families=stats.get("total_families"),
            last_sync=last_sync_row
        )
    finally:
        await service.close()


@router.get("/categories")
async def get_categories(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of unique categories with counts
    """
    service = YARAElasticsearchService()

    try:
        categories = await service.get_categories()
        return {"categories": [{"name": c["category"], "count": c["count"]} for c in categories]}
    finally:
        await service.close()


@router.get("/threat-actors")
async def get_threat_actors(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of unique threat actors with counts
    """
    service = YARAElasticsearchService()

    try:
        actors = await service.get_threat_actors()
        return {"threat_actors": [{"name": a["threat_actor"], "count": a["count"]} for a in actors]}
    finally:
        await service.close()


@router.get("/malware-families")
async def get_malware_families(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of unique malware families with counts
    """
    service = YARAElasticsearchService()

    try:
        families = await service.get_malware_families()
        return {"malware_families": [{"name": f["malware_family"], "count": f["count"]} for f in families]}
    finally:
        await service.close()


# ====== SIGNATURE BASE IOCs ENDPOINTS (PostgreSQL) ======

@router.get("/iocs", response_model=IOCsListResponse)
async def list_signature_base_iocs(
    search: Optional[str] = Query(None, description="Search in value or description"),
    ioc_type: Optional[str] = Query(None, description="Filter by type (c2, hash, filename)"),
    hash_type: Optional[str] = Query(None, description="Filter by hash type (md5, sha1, sha256)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List Signature Base IOCs (C2, hashes, filenames)
    """
    query = select(SignatureBaseIOC).where(SignatureBaseIOC.is_active == True)
    count_query = select(func.count(SignatureBaseIOC.id)).where(SignatureBaseIOC.is_active == True)

    if search:
        search_filter = or_(
            SignatureBaseIOC.value.ilike(f"%{search}%"),
            SignatureBaseIOC.description.ilike(f"%{search}%")
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    if ioc_type:
        query = query.where(SignatureBaseIOC.type == ioc_type)
        count_query = count_query.where(SignatureBaseIOC.type == ioc_type)

    if hash_type:
        query = query.where(SignatureBaseIOC.hash_type == hash_type)
        count_query = count_query.where(SignatureBaseIOC.hash_type == hash_type)

    # Get total count
    total_result = await session.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    offset = (page - 1) * page_size
    query = query.order_by(SignatureBaseIOC.synced_at.desc()).offset(offset).limit(page_size)

    result = await session.execute(query)
    iocs = result.scalars().all()

    return IOCsListResponse(
        total=total,
        page=page,
        page_size=page_size,
        iocs=[SignatureBaseIOCResponse(
            id=str(i.id),
            value=i.value,
            type=i.type,
            description=i.description,
            source_file=i.source_file,
            hash_type=i.hash_type,
            is_active=i.is_active,
            synced_at=i.synced_at
        ) for i in iocs]
    )


@router.get("/iocs/stats")
async def get_ioc_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get statistics about Signature Base IOCs
    """
    # Total IOCs
    total_result = await session.execute(
        select(func.count(SignatureBaseIOC.id)).where(SignatureBaseIOC.is_active == True)
    )
    total = total_result.scalar()

    # By type
    type_result = await session.execute(
        select(SignatureBaseIOC.type, func.count(SignatureBaseIOC.id))
        .where(SignatureBaseIOC.is_active == True)
        .group_by(SignatureBaseIOC.type)
    )
    by_type = {row[0]: row[1] for row in type_result.fetchall()}

    # By hash type (for hash IOCs)
    hash_result = await session.execute(
        select(SignatureBaseIOC.hash_type, func.count(SignatureBaseIOC.id))
        .where(SignatureBaseIOC.is_active == True)
        .where(SignatureBaseIOC.type == 'hash')
        .group_by(SignatureBaseIOC.hash_type)
    )
    by_hash_type = {row[0] or "unknown": row[1] for row in hash_result.fetchall()}

    return {
        "total": total,
        "by_type": by_type,
        "by_hash_type": by_hash_type
    }
