"""
Audit Logs API Endpoints (Admin Only)
Consulta logs de auditoria do sistema
"""
import logging
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.db.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.core.dependencies import get_current_active_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs (Admin)"])


# Pydantic schemas
class AuditLogResponse(BaseModel):
    """Schema de resposta para audit log"""
    id: str
    event_type: str
    category: str
    severity: str
    user_id: Optional[str]
    target_user_id: Optional[str]
    sso_provider_id: Optional[str]
    description: str
    metadata: Optional[dict]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: str

    # Informações relacionadas (joins)
    user_username: Optional[str] = None
    target_user_username: Optional[str] = None
    sso_provider_name: Optional[str] = None


def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Dependency para garantir que apenas admins acessem"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view audit logs"
        )
    return current_user


@router.get("/", response_model=List[AuditLogResponse])
async def list_audit_logs(
    category: Optional[str] = Query(None, description="Filtrar por categoria: authentication, configuration, user_management, sync"),
    event_type: Optional[str] = Query(None, description="Filtrar por tipo de evento"),
    severity: Optional[str] = Query(None, description="Filtrar por severidade: info, warning, error, critical"),
    user_id: Optional[str] = Query(None, description="Filtrar por ID do usuário que realizou a ação"),
    sso_provider_id: Optional[str] = Query(None, description="Filtrar por ID do provider SSO"),
    days: int = Query(7, description="Últimos N dias (padrão: 7)"),
    limit: int = Query(100, description="Limite de resultados (padrão: 100, máximo: 1000)"),
    offset: int = Query(0, description="Offset para paginação"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Listar audit logs com filtros (Admin only)

    Retorna logs dos últimos N dias, ordenados do mais recente para o mais antigo
    """
    # Validar limit
    if limit > 1000:
        limit = 1000

    # Data mínima (últimos N dias)
    min_date = datetime.utcnow() - timedelta(days=days)

    # Construir query
    query = select(AuditLog).where(AuditLog.created_at >= min_date)

    # Aplicar filtros
    if category:
        query = query.where(AuditLog.category == category)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if severity:
        query = query.where(AuditLog.severity == severity)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if sso_provider_id:
        query = query.where(AuditLog.sso_provider_id == sso_provider_id)

    # Ordenar por data (mais recente primeiro)
    query = query.order_by(desc(AuditLog.created_at))

    # Aplicar paginação
    query = query.offset(offset).limit(limit)

    # Executar query
    result = await db.execute(query)
    logs = result.scalars().all()

    # Preparar resposta com informações relacionadas
    response = []
    for log in logs:
        log_dict = log.to_dict()

        # Buscar username do usuário (se houver)
        if log.user_id:
            user_result = await db.execute(
                select(User).where(User.id == log.user_id)
            )
            user = user_result.scalar_one_or_none()
            log_dict["user_username"] = user.username if user else None

        # Buscar username do usuário alvo (se houver)
        if log.target_user_id:
            target_result = await db.execute(
                select(User).where(User.id == log.target_user_id)
            )
            target_user = target_result.scalar_one_or_none()
            log_dict["target_user_username"] = target_user.username if target_user else None

        # Buscar nome do provider SSO (se houver)
        if log.sso_provider_id:
            from app.models.sso_provider import SSOProvider
            provider_result = await db.execute(
                select(SSOProvider).where(SSOProvider.id == log.sso_provider_id)
            )
            provider = provider_result.scalar_one_or_none()
            log_dict["sso_provider_name"] = provider.name if provider else None

        response.append(AuditLogResponse(**log_dict))

    return response


@router.get("/stats")
async def get_audit_stats(
    days: int = Query(7, description="Últimos N dias (padrão: 7)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Obter estatísticas de audit logs (Admin only)

    Retorna contagens por categoria, evento, severidade, etc.
    """
    min_date = datetime.utcnow() - timedelta(days=days)

    # Total de logs
    total_result = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.created_at >= min_date)
    )
    total = total_result.scalar() or 0

    # Por categoria
    category_result = await db.execute(
        select(AuditLog.category, func.count(AuditLog.id))
        .where(AuditLog.created_at >= min_date)
        .group_by(AuditLog.category)
    )
    by_category = {row[0]: row[1] for row in category_result.all()}

    # Por severidade
    severity_result = await db.execute(
        select(AuditLog.severity, func.count(AuditLog.id))
        .where(AuditLog.created_at >= min_date)
        .group_by(AuditLog.severity)
    )
    by_severity = {row[0]: row[1] for row in severity_result.all()}

    # Top 10 event types
    event_result = await db.execute(
        select(AuditLog.event_type, func.count(AuditLog.id))
        .where(AuditLog.created_at >= min_date)
        .group_by(AuditLog.event_type)
        .order_by(desc(func.count(AuditLog.id)))
        .limit(10)
    )
    top_events = {row[0]: row[1] for row in event_result.all()}

    return {
        "period_days": days,
        "total_logs": total,
        "by_category": by_category,
        "by_severity": by_severity,
        "top_events": top_events
    }


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Buscar audit log por ID (Admin only)
    """
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found"
        )

    log_dict = log.to_dict()

    # Buscar informações relacionadas
    if log.user_id:
        user_result = await db.execute(select(User).where(User.id == log.user_id))
        user = user_result.scalar_one_or_none()
        log_dict["user_username"] = user.username if user else None

    if log.target_user_id:
        target_result = await db.execute(select(User).where(User.id == log.target_user_id))
        target_user = target_result.scalar_one_or_none()
        log_dict["target_user_username"] = target_user.username if target_user else None

    if log.sso_provider_id:
        from app.models.sso_provider import SSOProvider
        provider_result = await db.execute(
            select(SSOProvider).where(SSOProvider.id == log.sso_provider_id)
        )
        provider = provider_result.scalar_one_or_none()
        log_dict["sso_provider_name"] = provider.name if provider else None

    return AuditLogResponse(**log_dict)
