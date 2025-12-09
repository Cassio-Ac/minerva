"""
OTX API Keys Management Endpoints

API para gerenciar chaves OTX com rotação automática
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.cti.services.otx_key_manager import OTXKeyManager
from app.cti.services.otx_service_v2 import OTXServiceV2
from app.cti.models.otx_api_key import OTXAPIKey
from app.models.user import User
from app.core.dependencies import get_current_user, require_role
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID

router = APIRouter()


# Schemas
class OTXKeyCreate(BaseModel):
    name: str
    api_key: str
    description: Optional[str] = None
    is_primary: bool = False
    daily_limit: int = 9000


class OTXKeyResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    is_active: bool
    is_primary: bool
    current_usage: int
    daily_limit: int
    health_status: str
    error_count: int
    is_available: bool

    class Config:
        from_attributes = True


class OTXKeyStatsResponse(BaseModel):
    total_keys: int
    available_keys: int
    exhausted_keys: int
    total_usage_today: int
    total_capacity: int
    usage_percentage: float
    keys: List[dict]


class EnrichIOCRequest(BaseModel):
    indicator: str


# Endpoints

@router.get("/keys", response_model=List[OTXKeyResponse])
async def list_otx_keys(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Lista todas as chaves OTX configuradas

    Requer: role admin ou power
    """
    stmt = select(OTXAPIKey).order_by(OTXAPIKey.is_primary.desc(), OTXAPIKey.name)
    result = await session.execute(stmt)
    keys = result.scalars().all()

    return [
        OTXKeyResponse(
            id=key.id,
            name=key.name,
            description=key.description,
            is_active=key.is_active,
            is_primary=key.is_primary,
            current_usage=key.current_usage,
            daily_limit=key.daily_limit,
            health_status=key.health_status or "unknown",
            error_count=key.error_count,
            is_available=key.is_available()
        )
        for key in keys
    ]


@router.get("/keys/stats", response_model=OTXKeyStatsResponse)
async def get_otx_keys_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Retorna estatísticas de uso das chaves OTX

    Requer: role admin ou power
    """
    key_manager = OTXKeyManager(session)
    stats = await key_manager.get_key_stats()

    return OTXKeyStatsResponse(**stats)


@router.post("/keys", response_model=OTXKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_otx_key(
    key_data: OTXKeyCreate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Adiciona uma nova chave OTX

    Requer: role admin
    """
    key_manager = OTXKeyManager(session)

    try:
        new_key = await key_manager.add_key(
            name=key_data.name,
            api_key=key_data.api_key,
            description=key_data.description,
            is_primary=key_data.is_primary,
            daily_limit=key_data.daily_limit
        )

        return OTXKeyResponse(
            id=new_key.id,
            name=new_key.name,
            description=new_key.description,
            is_active=new_key.is_active,
            is_primary=new_key.is_primary,
            current_usage=new_key.current_usage,
            daily_limit=new_key.daily_limit,
            health_status=new_key.health_status or "unknown",
            error_count=new_key.error_count,
            is_available=new_key.is_available()
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to add OTX key: {str(e)}"
        )


@router.post("/keys/{key_id}/activate")
async def activate_otx_key(
    key_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Ativa uma chave OTX

    Requer: role admin
    """
    key_manager = OTXKeyManager(session)
    await key_manager.activate_key(str(key_id))

    return {"status": "success", "message": f"Key {key_id} activated"}


@router.post("/keys/{key_id}/deactivate")
async def deactivate_otx_key(
    key_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Desativa uma chave OTX

    Requer: role admin
    """
    key_manager = OTXKeyManager(session)
    await key_manager.deactivate_key(str(key_id))

    return {"status": "success", "message": f"Key {key_id} deactivated"}


@router.post("/keys/{key_id}/health-check")
async def health_check_otx_key(
    key_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Executa health check em uma chave OTX

    Requer: role admin ou power
    """
    stmt = select(OTXAPIKey).where(OTXAPIKey.id == key_id)
    result = await session.execute(stmt)
    key = result.scalar_one_or_none()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OTX key not found"
        )

    key_manager = OTXKeyManager(session)
    is_healthy = await key_manager.health_check_key(key)

    return {
        "status": "success",
        "key_id": key_id,
        "is_healthy": is_healthy,
        "health_status": key.health_status
    }


@router.post("/keys/reset-usage")
async def reset_daily_usage(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Reseta uso diário de todas as chaves

    Normalmente executado via Celery task às 00:00 UTC
    Requer: role admin
    """
    key_manager = OTXKeyManager(session)
    await key_manager.reset_daily_usage()

    return {"status": "success", "message": "Daily usage reset for all keys"}


@router.post("/enrich", response_model=dict)
async def enrich_ioc_with_otx(
    request: EnrichIOCRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enriquece um IOC usando OTX com rotação automática de chaves

    Busca em múltiplos endpoints:
    - general, reputation, geo, malware, passive_dns, whois, etc

    Requer: autenticação
    """
    otx_service = OTXServiceV2(session)

    result = await otx_service.enrich_indicator(request.indicator)

    if not result.get('found'):
        return result

    return result
