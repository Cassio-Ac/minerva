"""
SSO Providers Management Endpoints (Admin Only)
Gerencia configuração de provedores SSO
"""
import logging
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.db.database import get_db
from app.models.sso_provider import SSOProvider
from app.models.user import User, UserRole
from app.core.dependencies import get_current_active_user
from app.services.ad_sync_service import ADSyncService, get_ad_sync_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sso-providers", tags=["SSO Providers (Admin)"])


# Pydantic schemas
class SSOProviderCreate(BaseModel):
    """Schema para criar SSO provider"""
    name: str = Field(..., min_length=1, max_length=100, description="Nome do provider (ex: Microsoft Entra ID - Empresa X)")
    provider_type: str = Field(..., description="Tipo: 'entra_id', 'google', 'okta'")
    client_id: str = Field(..., min_length=1, max_length=255)
    client_secret: str = Field(..., min_length=1, description="Será criptografado no banco")
    tenant_id: Optional[str] = Field(None, description="Tenant ID (para Entra ID)")
    authority_url: Optional[str] = Field(None, description="Authority URL customizada (opcional)")
    redirect_uri: str = Field(..., description="Redirect URI (ex: http://localhost:8000/api/v1/auth/sso/callback/entra_id)")
    scopes: List[str] = Field(default=["openid", "profile", "email"], description="Scopes OAuth2")
    default_role: str = Field(default="reader", description="Role padrão para novos usuários")
    auto_provision: bool = Field(default=True, description="Auto-provisionar novos usuários")
    is_active: bool = Field(default=True, description="Provider ativo")


class SSOProviderUpdate(BaseModel):
    """Schema para atualizar SSO provider"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    client_id: Optional[str] = Field(None, min_length=1, max_length=255)
    client_secret: Optional[str] = Field(None, description="Se fornecido, será criptografado. Se None, mantém existente")
    tenant_id: Optional[str] = None
    authority_url: Optional[str] = None
    redirect_uri: Optional[str] = None
    scopes: Optional[List[str]] = None
    default_role: Optional[str] = None
    auto_provision: Optional[bool] = None
    is_active: Optional[bool] = None


class SSOProviderResponse(BaseModel):
    """Schema de resposta para SSO provider"""
    id: str
    name: str
    provider_type: str
    client_id: str
    tenant_id: Optional[str]
    authority_url: Optional[str]
    redirect_uri: str
    scopes: List[str]
    default_role: str
    auto_provision: bool
    is_active: bool
    created_at: str
    updated_at: str
    user_count: int = 0  # Número de usuários vinculados


def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Dependency para garantir que apenas admins acessem"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can manage SSO providers"
        )
    return current_user


@router.post("/", response_model=SSOProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_sso_provider(
    provider_data: SSOProviderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Criar novo SSO provider (Admin only)

    Exemplo para Microsoft Entra ID:
    ```json
    {
        "name": "Microsoft Entra ID - Minha Empresa",
        "provider_type": "entra_id",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "tenant_id": "your-tenant-id",
        "redirect_uri": "http://localhost:8000/api/v1/auth/sso/callback/entra_id",
        "scopes": ["openid", "profile", "email", "User.Read"],
        "default_role": "reader",
        "auto_provision": true
    }
    ```
    """
    try:
        # Criar provider
        provider = SSOProvider(
            name=provider_data.name,
            provider_type=provider_data.provider_type,
            client_id=provider_data.client_id,
            tenant_id=provider_data.tenant_id,
            authority_url=provider_data.authority_url,
            redirect_uri=provider_data.redirect_uri,
            default_role=provider_data.default_role,
            auto_provision=provider_data.auto_provision,
            is_active=provider_data.is_active,
            created_by_id=current_user.id,
        )

        # Criptografar e armazenar client secret
        provider.set_client_secret(provider_data.client_secret)

        # Armazenar scopes
        provider.set_scopes_list(provider_data.scopes)

        db.add(provider)
        await db.commit()
        await db.refresh(provider)

        logger.info(f"✅ Created SSO provider: {provider.name} ({provider.provider_type})")

        # Contar usuários (0 para novo provider)
        return SSOProviderResponse(
            **provider.to_dict(),
            user_count=0
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating SSO provider: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create SSO provider: {str(e)}"
        )


@router.get("/", response_model=List[SSOProviderResponse])
async def list_sso_providers(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Listar todos os SSO providers (Admin only)

    Inclui contagem de usuários vinculados a cada provider
    """
    result_providers = await db.execute(select(SSOProvider))
    providers = result_providers.scalars().all()

    result = []
    for provider in providers:
        # Contar usuários vinculados
        result_count = await db.execute(
            select(func.count(User.id)).where(User.sso_provider_id == provider.id)
        )
        user_count = result_count.scalar() or 0

        result.append(
            SSOProviderResponse(
                **provider.to_dict(),
                user_count=user_count
            )
        )

    return result


@router.get("/{provider_id}", response_model=SSOProviderResponse)
async def get_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Buscar SSO provider por ID (Admin only)
    """
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO Provider not found"
        )

    # Contar usuários
    result_count = await db.execute(
        select(func.count(User.id)).where(User.sso_provider_id == provider.id)
    )
    user_count = result_count.scalar() or 0

    return SSOProviderResponse(
        **provider.to_dict(),
        user_count=user_count
    )


@router.patch("/{provider_id}", response_model=SSOProviderResponse)
async def update_sso_provider(
    provider_id: str,
    update_data: SSOProviderUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Atualizar SSO provider (Admin only)

    Apenas campos fornecidos serão atualizados
    """
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO Provider not found"
        )

    try:
        # Atualizar campos se fornecidos
        update_dict = update_data.model_dump(exclude_unset=True)

        if "name" in update_dict:
            provider.name = update_dict["name"]

        if "client_id" in update_dict:
            provider.client_id = update_dict["client_id"]

        if "client_secret" in update_dict and update_dict["client_secret"]:
            provider.set_client_secret(update_dict["client_secret"])

        if "tenant_id" in update_dict:
            provider.tenant_id = update_dict["tenant_id"]

        if "authority_url" in update_dict:
            provider.authority_url = update_dict["authority_url"]

        if "redirect_uri" in update_dict:
            provider.redirect_uri = update_dict["redirect_uri"]

        if "scopes" in update_dict:
            provider.set_scopes_list(update_dict["scopes"])

        if "default_role" in update_dict:
            provider.default_role = update_dict["default_role"]

        if "auto_provision" in update_dict:
            provider.auto_provision = update_dict["auto_provision"]

        if "is_active" in update_dict:
            provider.is_active = update_dict["is_active"]

        provider.updated_at = datetime.utcnow()

        await db.commit()
        await db.refresh(provider)

        logger.info(f"✅ Updated SSO provider: {provider.name}")

        # Contar usuários
        result_count = await db.execute(
            select(func.count(User.id)).where(User.sso_provider_id == provider.id)
        )
        user_count = result_count.scalar() or 0

        return SSOProviderResponse(
            **provider.to_dict(),
            user_count=user_count
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating SSO provider: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update SSO provider: {str(e)}"
        )


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Deletar SSO provider (Admin only)

    CUIDADO: Usuários vinculados terão sso_provider_id = NULL (SET NULL)
    mas ainda existirão no sistema
    """
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO Provider not found"
        )

    # Verificar quantos usuários serão afetados
    result_count = await db.execute(
        select(func.count(User.id)).where(User.sso_provider_id == provider.id)
    )
    user_count = result_count.scalar() or 0

    if user_count > 0:
        logger.warning(
            f"⚠️ Deleting SSO provider {provider.name} will affect {user_count} users"
        )

    try:
        await db.delete(provider)
        await db.commit()

        logger.info(f"🗑️ Deleted SSO provider: {provider.name}")

    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting SSO provider: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete SSO provider: {str(e)}"
        )


@router.post("/{provider_id}/sync")
async def manual_sync(
    provider_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Sincronizar manualmente usuários deste provider com AD (Admin only)

    Verifica status de TODOS os usuários SSO no Microsoft Entra ID e:
    - Desativa usuários que foram desativados no AD
    - Desativa usuários que não existem mais no AD
    - Atualiza timestamps de sincronização

    Returns:
        {
            "total_checked": int,
            "deactivated": int,
            "activated": int,
            "errors": int,
            "details": List[Dict]
        }
    """
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO Provider not found"
        )

    if provider.provider_type != "entra_id":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Manual sync only supported for Entra ID providers"
        )

    try:
        logger.info(f"🔄 Starting manual AD sync for provider: {provider.name}")

        sync_service = get_ad_sync_service(provider)
        results = await sync_service.sync_all_sso_users(db)

        logger.info(
            f"✅ Manual sync completed: {results['total_checked']} checked, "
            f"{results['deactivated']} deactivated, {results['errors']} errors"
        )

        return results

    except Exception as e:
        logger.error(f"Error during manual sync: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync users: {str(e)}"
        )


@router.get("/{provider_id}/users")
async def list_provider_users(
    provider_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Listar todos os usuários vinculados a este SSO provider (Admin only)

    Útil para visualizar usuários SSO e seus status de sincronização
    """
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO Provider not found"
        )

    result_users = await db.execute(select(User).where(User.sso_provider_id == provider.id))
    users = result_users.scalars().all()

    return [
        {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "sso_email": user.sso_email,
            "external_id": user.external_id,
            "role": user.role.value if hasattr(user.role, 'value') else user.role,
            "is_active": user.is_active,
            "ad_account_enabled": user.ad_account_enabled,
            "sync_status": user.sync_status,
            "last_sso_login": user.last_sso_login.isoformat() if user.last_sso_login else None,
            "last_ad_sync": user.last_ad_sync.isoformat() if user.last_ad_sync else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
        for user in users
    ]
