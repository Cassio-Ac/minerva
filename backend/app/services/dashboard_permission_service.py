"""
Dashboard Permission Service
Gerenciamento de ownership e permissões de dashboards
"""
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
import uuid

from app.models.dashboard_permission import DashboardPermission, DashboardShare, DashboardVisibility
from app.models.user import User


class DashboardPermissionService:
    """Service for managing dashboard permissions"""

    @staticmethod
    async def create_permission(
        db: AsyncSession,
        dashboard_id: str,
        owner_id: str,
        visibility: DashboardVisibility = DashboardVisibility.PRIVATE,
        allow_edit_by_others: bool = False,
        allow_copy: bool = True
    ) -> DashboardPermission:
        """Create dashboard permission"""
        permission = DashboardPermission(
            dashboard_id=dashboard_id,
            owner_id=uuid.UUID(owner_id),
            visibility=visibility,
            allow_edit_by_others=allow_edit_by_others,
            allow_copy=allow_copy
        )

        db.add(permission)
        await db.commit()
        await db.refresh(permission)

        return permission

    @staticmethod
    async def get_permission(
        db: AsyncSession,
        dashboard_id: str
    ) -> Optional[DashboardPermission]:
        """Get permission for dashboard"""
        result = await db.execute(
            select(DashboardPermission).where(
                DashboardPermission.dashboard_id == dashboard_id
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def update_permission(
        db: AsyncSession,
        dashboard_id: str,
        visibility: Optional[DashboardVisibility] = None,
        allow_edit_by_others: Optional[bool] = None,
        allow_copy: Optional[bool] = None
    ) -> Optional[DashboardPermission]:
        """Update dashboard permission"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        if not permission:
            return None

        if visibility is not None:
            permission.visibility = visibility
        if allow_edit_by_others is not None:
            permission.allow_edit_by_others = allow_edit_by_others
        if allow_copy is not None:
            permission.allow_copy = allow_copy

        await db.commit()
        await db.refresh(permission)

        return permission

    @staticmethod
    async def delete_permission(db: AsyncSession, dashboard_id: str) -> bool:
        """Delete dashboard permission"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        if not permission:
            return False

        await db.delete(permission)
        await db.commit()

        return True

    @staticmethod
    async def can_view_dashboard(
        db: AsyncSession,
        dashboard_id: str,
        user_id: str
    ) -> bool:
        """Check if user can view dashboard"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        # Se não tem permissão configurada, assume que é público (backward compatibility)
        if not permission:
            return True

        # Owner sempre pode ver
        if str(permission.owner_id) == user_id:
            return True

        # Se é público, qualquer um pode ver
        if permission.visibility == DashboardVisibility.PUBLIC:
            return True

        # Se é compartilhado, verificar shares
        if permission.visibility == DashboardVisibility.SHARED:
            result = await db.execute(
                select(DashboardShare).where(
                    and_(
                        DashboardShare.permission_id == permission.id,
                        DashboardShare.user_id == uuid.UUID(user_id)
                    )
                )
            )
            share = result.scalar_one_or_none()
            return share is not None

        # Privado e não é owner
        return False

    @staticmethod
    async def can_edit_dashboard(
        db: AsyncSession,
        dashboard_id: str,
        user_id: str
    ) -> bool:
        """Check if user can edit dashboard"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        # Se não tem permissão configurada, assume que pode editar (backward compatibility)
        if not permission:
            return True

        # Owner sempre pode editar
        if str(permission.owner_id) == user_id:
            return True

        # Se permite edição por outros
        if permission.allow_edit_by_others:
            # E o usuário pode ver o dashboard
            can_view = await DashboardPermissionService.can_view_dashboard(db, dashboard_id, user_id)
            return can_view

        # Se é compartilhado com permissão de edição
        if permission.visibility == DashboardVisibility.SHARED:
            result = await db.execute(
                select(DashboardShare).where(
                    and_(
                        DashboardShare.permission_id == permission.id,
                        DashboardShare.user_id == uuid.UUID(user_id),
                        DashboardShare.can_edit == True
                    )
                )
            )
            share = result.scalar_one_or_none()
            return share is not None

        return False

    @staticmethod
    async def share_with_user(
        db: AsyncSession,
        dashboard_id: str,
        user_id: str,
        can_edit: bool = False
    ) -> Optional[DashboardShare]:
        """Share dashboard with specific user"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        if not permission:
            return None

        # Verificar se já não está compartilhado
        result = await db.execute(
            select(DashboardShare).where(
                and_(
                    DashboardShare.permission_id == permission.id,
                    DashboardShare.user_id == uuid.UUID(user_id)
                )
            )
        )
        existing_share = result.scalar_one_or_none()

        if existing_share:
            # Atualizar permissão
            existing_share.can_edit = can_edit
            await db.commit()
            await db.refresh(existing_share)
            return existing_share

        # Criar novo share
        share = DashboardShare(
            permission_id=permission.id,
            user_id=uuid.UUID(user_id),
            can_edit=can_edit
        )

        db.add(share)
        await db.commit()
        await db.refresh(share)

        return share

    @staticmethod
    async def unshare_with_user(
        db: AsyncSession,
        dashboard_id: str,
        user_id: str
    ) -> bool:
        """Unshare dashboard with user"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        if not permission:
            return False

        result = await db.execute(
            select(DashboardShare).where(
                and_(
                    DashboardShare.permission_id == permission.id,
                    DashboardShare.user_id == uuid.UUID(user_id)
                )
            )
        )
        share = result.scalar_one_or_none()

        if not share:
            return False

        await db.delete(share)
        await db.commit()

        return True

    @staticmethod
    async def get_dashboard_shares(
        db: AsyncSession,
        dashboard_id: str
    ) -> List[dict]:
        """Get all users dashboard is shared with"""
        permission = await DashboardPermissionService.get_permission(db, dashboard_id)

        if not permission:
            return []

        result = await db.execute(
            select(DashboardShare, User).join(
                User, DashboardShare.user_id == User.id
            ).where(
                DashboardShare.permission_id == permission.id
            )
        )

        shares = result.all()

        return [
            {
                "share_id": str(share.DashboardShare.id),
                "user_id": str(share.User.id),
                "username": share.User.username,
                "email": share.User.email,
                "full_name": share.User.full_name,
                "can_edit": share.DashboardShare.can_edit,
                "shared_at": share.DashboardShare.created_at.isoformat()
            }
            for share in shares
        ]
