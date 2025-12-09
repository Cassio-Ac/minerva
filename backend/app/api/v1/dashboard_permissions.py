"""
Dashboard Permissions API
Gerenciamento de ownership, visibilidade e compartilhamento de dashboards
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.dashboard_permission import DashboardVisibility
from app.services.dashboard_permission_service import DashboardPermissionService
from app.db.database import get_db

router = APIRouter()


# Pydantic models
class PermissionCreate(BaseModel):
    dashboard_id: str
    visibility: DashboardVisibility = DashboardVisibility.PRIVATE
    allow_edit_by_others: bool = False
    allow_copy: bool = True


class PermissionUpdate(BaseModel):
    visibility: Optional[DashboardVisibility] = None
    allow_edit_by_others: Optional[bool] = None
    allow_copy: Optional[bool] = None


class ShareCreate(BaseModel):
    user_id: str
    can_edit: bool = False


@router.post("/")
async def create_permission(
    data: PermissionCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Criar permissão para dashboard
    Apenas o owner pode criar
    """
    # Verificar se dashboard existe e se user é owner
    # TODO: adicionar verificação de ownership do dashboard

    permission = await DashboardPermissionService.create_permission(
        db=db,
        dashboard_id=data.dashboard_id,
        owner_id=str(current_user.id),
        visibility=data.visibility,
        allow_edit_by_others=data.allow_edit_by_others,
        allow_copy=data.allow_copy
    )

    return {
        "id": str(permission.id),
        "dashboard_id": permission.dashboard_id,
        "owner_id": str(permission.owner_id),
        "visibility": permission.visibility.value,
        "allow_edit_by_others": permission.allow_edit_by_others,
        "allow_copy": permission.allow_copy,
        "created_at": permission.created_at.isoformat(),
    }


@router.get("/{dashboard_id}")
async def get_permission(
    dashboard_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Obter permissão de um dashboard"""
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Verificar se user pode ver as permissões
    can_view = await DashboardPermissionService.can_view_dashboard(
        db, dashboard_id, str(current_user.id)
    )

    if not can_view:
        raise HTTPException(status_code=403, detail="Not authorized")

    return {
        "id": str(permission.id),
        "dashboard_id": permission.dashboard_id,
        "owner_id": str(permission.owner_id),
        "visibility": permission.visibility.value,
        "allow_edit_by_others": permission.allow_edit_by_others,
        "allow_copy": permission.allow_copy,
        "created_at": permission.created_at.isoformat(),
        "updated_at": permission.updated_at.isoformat(),
    }


@router.patch("/{dashboard_id}")
async def update_permission(
    dashboard_id: str,
    data: PermissionUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Atualizar permissão de dashboard
    Apenas owner pode atualizar
    """
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Verificar se é owner
    if str(permission.owner_id) != str(current_user.id) and not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Only owner can update permissions")

    updated = await DashboardPermissionService.update_permission(
        db=db,
        dashboard_id=dashboard_id,
        visibility=data.visibility,
        allow_edit_by_others=data.allow_edit_by_others,
        allow_copy=data.allow_copy
    )

    return {
        "id": str(updated.id),
        "dashboard_id": updated.dashboard_id,
        "owner_id": str(updated.owner_id),
        "visibility": updated.visibility.value,
        "allow_edit_by_others": updated.allow_edit_by_others,
        "allow_copy": updated.allow_copy,
        "updated_at": updated.updated_at.isoformat(),
    }


@router.delete("/{dashboard_id}")
async def delete_permission(
    dashboard_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Deletar permissão (apenas owner ou admin)"""
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if str(permission.owner_id) != str(current_user.id) and not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Only owner can delete permissions")

    await DashboardPermissionService.delete_permission(db, dashboard_id)

    return {"status": "success", "message": "Permission deleted"}


@router.post("/{dashboard_id}/share")
async def share_dashboard(
    dashboard_id: str,
    data: ShareCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Compartilhar dashboard com usuário específico
    Apenas owner pode compartilhar
    """
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if str(permission.owner_id) != str(current_user.id) and not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Only owner can share dashboards")

    share = await DashboardPermissionService.share_with_user(
        db=db,
        dashboard_id=dashboard_id,
        user_id=data.user_id,
        can_edit=data.can_edit
    )

    if not share:
        raise HTTPException(status_code=400, detail="Could not share dashboard")

    return {
        "id": str(share.id),
        "permission_id": str(share.permission_id),
        "user_id": str(share.user_id),
        "can_edit": share.can_edit,
        "created_at": share.created_at.isoformat(),
    }


@router.delete("/{dashboard_id}/share/{user_id}")
async def unshare_dashboard(
    dashboard_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Remover compartilhamento (apenas owner)"""
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if str(permission.owner_id) != str(current_user.id) and not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Only owner can unshare dashboards")

    success = await DashboardPermissionService.unshare_with_user(
        db=db,
        dashboard_id=dashboard_id,
        user_id=user_id
    )

    if not success:
        raise HTTPException(status_code=404, detail="Share not found")

    return {"status": "success", "message": "Dashboard unshared"}


@router.get("/{dashboard_id}/shares")
async def list_shares(
    dashboard_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Listar usuários com quem o dashboard está compartilhado"""
    permission = await DashboardPermissionService.get_permission(db, dashboard_id)

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Apenas owner pode ver shares
    if str(permission.owner_id) != str(current_user.id) and not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Only owner can view shares")

    shares = await DashboardPermissionService.get_dashboard_shares(db, dashboard_id)

    return shares


@router.get("/{dashboard_id}/can-view")
async def check_can_view(
    dashboard_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verificar se usuário pode visualizar dashboard"""
    can_view = await DashboardPermissionService.can_view_dashboard(
        db, dashboard_id, str(current_user.id)
    )

    return {"can_view": can_view}


@router.get("/{dashboard_id}/can-edit")
async def check_can_edit(
    dashboard_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verificar se usuário pode editar dashboard"""
    can_edit = await DashboardPermissionService.can_edit_dashboard(
        db, dashboard_id, str(current_user.id)
    )

    return {"can_edit": can_edit}
