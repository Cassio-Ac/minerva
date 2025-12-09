"""
Audit Service
Serviço para registrar eventos de auditoria no sistema
"""
import logging
from typing import Dict, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import (
    AuditLog,
    AuditEventType,
    AuditCategory,
    AuditSeverity
)
from app.db.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class AuditService:
    """Service para registrar eventos de auditoria"""

    @staticmethod
    async def log_event(
        event_type: str,
        category: str,
        description: str,
        severity: str = AuditSeverity.INFO,
        user_id: Optional[str] = None,
        target_user_id: Optional[str] = None,
        sso_provider_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        db: Optional[AsyncSession] = None
    ) -> AuditLog:
        """
        Registra um evento de auditoria

        Args:
            event_type: Tipo do evento (usar constantes de AuditEventType)
            category: Categoria (usar constantes de AuditCategory)
            description: Descrição legível do evento
            severity: Severidade (usar constantes de AuditSeverity)
            user_id: ID do usuário que realizou a ação (opcional)
            target_user_id: ID do usuário afetado (opcional)
            sso_provider_id: ID do provider SSO (opcional)
            metadata: Dados adicionais em formato JSON (opcional)
            ip_address: IP do cliente (opcional)
            user_agent: User Agent do browser (opcional)
            db: Sessão do banco (opcional, cria uma nova se não fornecida)

        Returns:
            AuditLog object criado
        """
        try:
            # Se não forneceu uma sessão, criar uma nova
            close_db = False
            if db is None:
                db = AsyncSessionLocal()
                close_db = True

            audit_log = AuditLog(
                event_type=event_type,
                category=category,
                severity=severity,
                user_id=user_id,
                target_user_id=target_user_id,
                sso_provider_id=sso_provider_id,
                description=description,
                metadata=metadata or {},
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.utcnow()
            )

            db.add(audit_log)
            await db.commit()
            await db.refresh(audit_log)

            logger.info(
                f"📝 Audit log created: {event_type} | {category} | {description}"
            )

            if close_db:
                await db.close()

            return audit_log

        except Exception as e:
            logger.error(f"❌ Error creating audit log: {e}", exc_info=True)
            if db:
                await db.rollback()
            raise

    @staticmethod
    async def log_sso_login_success(
        user_id: str,
        sso_provider_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None
    ):
        """Log de login SSO bem-sucedido"""
        return await AuditService.log_event(
            event_type=AuditEventType.SSO_LOGIN_SUCCESS,
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.INFO,
            description=f"Usuário realizou login via SSO com sucesso",
            user_id=user_id,
            sso_provider_id=sso_provider_id,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent
        )

    @staticmethod
    async def log_sso_login_failed(
        sso_provider_id: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None
    ):
        """Log de falha de login SSO"""
        return await AuditService.log_event(
            event_type=AuditEventType.SSO_LOGIN_FAILED,
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            description=f"Falha no login SSO: {reason}",
            sso_provider_id=sso_provider_id,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent
        )

    @staticmethod
    async def log_ad_sync_completed(
        sso_provider_id: str,
        total_checked: int,
        deactivated: int,
        activated: int,
        errors: int,
        metadata: Optional[Dict] = None
    ):
        """Log de sincronização com AD completa"""
        severity = AuditSeverity.INFO
        if errors > 0:
            severity = AuditSeverity.WARNING if deactivated == 0 else AuditSeverity.ERROR

        return await AuditService.log_event(
            event_type=AuditEventType.AD_SYNC_COMPLETED,
            category=AuditCategory.SYNC,
            severity=severity,
            description=(
                f"Sincronização AD completa: {total_checked} verificados, "
                f"{deactivated} desativados, {activated} ativados, {errors} erros"
            ),
            sso_provider_id=sso_provider_id,
            metadata=metadata or {
                "total_checked": total_checked,
                "deactivated": deactivated,
                "activated": activated,
                "errors": errors
            }
        )

    @staticmethod
    async def log_user_created(
        admin_user_id: str,
        created_user_id: str,
        username: str,
        role: str,
        metadata: Optional[Dict] = None
    ):
        """Log de criação de usuário"""
        return await AuditService.log_event(
            event_type=AuditEventType.USER_CREATED,
            category=AuditCategory.USER_MANAGEMENT,
            severity=AuditSeverity.INFO,
            description=f"Usuário '{username}' criado com role '{role}'",
            user_id=admin_user_id,
            target_user_id=created_user_id,
            metadata=metadata
        )

    @staticmethod
    async def log_user_role_changed(
        admin_user_id: str,
        target_user_id: str,
        username: str,
        old_role: str,
        new_role: str,
        metadata: Optional[Dict] = None
    ):
        """Log de mudança de role de usuário"""
        return await AuditService.log_event(
            event_type=AuditEventType.USER_ROLE_CHANGED,
            category=AuditCategory.USER_MANAGEMENT,
            severity=AuditSeverity.INFO,
            description=f"Role do usuário '{username}' alterada de '{old_role}' para '{new_role}'",
            user_id=admin_user_id,
            target_user_id=target_user_id,
            metadata=metadata or {
                "old_role": old_role,
                "new_role": new_role
            }
        )

    @staticmethod
    async def log_sso_provider_created(
        admin_user_id: str,
        sso_provider_id: str,
        provider_name: str,
        provider_type: str,
        metadata: Optional[Dict] = None
    ):
        """Log de criação de SSO provider"""
        return await AuditService.log_event(
            event_type=AuditEventType.SSO_PROVIDER_CREATED,
            category=AuditCategory.CONFIGURATION,
            severity=AuditSeverity.INFO,
            description=f"SSO Provider '{provider_name}' ({provider_type}) criado",
            user_id=admin_user_id,
            sso_provider_id=sso_provider_id,
            metadata=metadata
        )

    @staticmethod
    async def log_sso_provider_updated(
        admin_user_id: str,
        sso_provider_id: str,
        provider_name: str,
        changes: Dict,
        metadata: Optional[Dict] = None
    ):
        """Log de atualização de SSO provider"""
        return await AuditService.log_event(
            event_type=AuditEventType.SSO_PROVIDER_UPDATED,
            category=AuditCategory.CONFIGURATION,
            severity=AuditSeverity.INFO,
            description=f"SSO Provider '{provider_name}' atualizado",
            user_id=admin_user_id,
            sso_provider_id=sso_provider_id,
            metadata=metadata or {"changes": changes}
        )

    @staticmethod
    async def log_sso_provider_deleted(
        admin_user_id: str,
        sso_provider_id: str,
        provider_name: str,
        affected_users: int,
        metadata: Optional[Dict] = None
    ):
        """Log de exclusão de SSO provider"""
        return await AuditService.log_event(
            event_type=AuditEventType.SSO_PROVIDER_DELETED,
            category=AuditCategory.CONFIGURATION,
            severity=AuditSeverity.WARNING if affected_users > 0 else AuditSeverity.INFO,
            description=(
                f"SSO Provider '{provider_name}' deletado "
                f"({affected_users} usuários afetados)"
            ),
            user_id=admin_user_id,
            sso_provider_id=sso_provider_id,
            metadata=metadata or {"affected_users": affected_users}
        )


def get_audit_service() -> AuditService:
    """Factory para criar AuditService"""
    return AuditService()
