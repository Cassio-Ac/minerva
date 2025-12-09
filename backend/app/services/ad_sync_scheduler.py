"""
AD Sync Scheduler Service
Sincronização periódica automática de usuários SSO com Active Directory
"""
import logging
import asyncio
from datetime import datetime
from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.models.sso_provider import SSOProvider
from app.services.ad_sync_service import get_ad_sync_service
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class ADSyncScheduler:
    """Scheduler para sincronização periódica com AD"""

    def __init__(self, interval_hours: int = 6):
        """
        Args:
            interval_hours: Intervalo em horas entre sincronizações (padrão: 6 horas)
        """
        self.interval_hours = interval_hours
        self.interval_seconds = interval_hours * 3600
        self.is_running = False
        self.task = None

    async def sync_all_providers(self):
        """
        Sincroniza todos os providers SSO ativos do tipo Entra ID

        Verifica status de TODOS os usuários SSO em TODOS os providers ativos
        e desativa contas que foram desativadas/removidas do AD
        """
        logger.info("🔄 Starting scheduled AD sync for all providers...")

        try:
            # Criar sessão do banco
            async with AsyncSessionLocal() as db:
                # Buscar todos os providers Entra ID ativos
                result = await db.execute(
                    select(SSOProvider).where(
                        SSOProvider.provider_type == "entra_id",
                        SSOProvider.is_active == True
                    )
                )
                providers = result.scalars().all()

                if not providers:
                    logger.info("ℹ️ No active Entra ID providers found - skipping sync")
                    return

                logger.info(f"📋 Found {len(providers)} active Entra ID provider(s)")

                # Sincronizar cada provider
                total_checked = 0
                total_deactivated = 0
                total_activated = 0
                total_errors = 0

                for provider in providers:
                    try:
                        logger.info(f"🔄 Syncing provider: {provider.name}")

                        sync_service = get_ad_sync_service(provider)
                        results = await sync_service.sync_all_sso_users(db)

                        total_checked += results["total_checked"]
                        total_deactivated += results["deactivated"]
                        total_activated += results.get("activated", 0)
                        total_errors += results["errors"]

                        logger.info(
                            f"✅ Provider {provider.name}: "
                            f"{results['total_checked']} checked, "
                            f"{results['deactivated']} deactivated, "
                            f"{results.get('activated', 0)} activated, "
                            f"{results['errors']} errors"
                        )

                    except Exception as e:
                        logger.error(
                            f"❌ Error syncing provider {provider.name}: {e}",
                            exc_info=True
                        )
                        total_errors += 1

                # Log resumo final
                logger.info(
                    f"✅ Scheduled AD sync completed: "
                    f"{total_checked} users checked, "
                    f"{total_deactivated} deactivated, "
                    f"{total_activated} activated, "
                    f"{total_errors} errors"
                )

                # Registrar audit log para cada provider sincronizado
                for provider in providers:
                    try:
                        await AuditService.log_ad_sync_completed(
                            sso_provider_id=str(provider.id),
                            total_checked=total_checked,
                            deactivated=total_deactivated,
                            activated=total_activated,
                            errors=total_errors,
                            metadata={
                                "provider_name": provider.name,
                                "provider_type": provider.provider_type,
                                "scheduled": True
                            }
                        )
                    except Exception as audit_error:
                        logger.error(f"Failed to create audit log: {audit_error}")

        except Exception as e:
            logger.error(f"❌ Error in scheduled AD sync: {e}", exc_info=True)

    async def run(self):
        """
        Executa loop de sincronização periódica

        Sincroniza imediatamente na inicialização e depois a cada N horas
        """
        self.is_running = True
        logger.info(
            f"🚀 AD Sync Scheduler started (interval: {self.interval_hours} hours)"
        )

        # Primeira sincronização imediata (após 1 minuto de startup)
        logger.info("⏰ First AD sync will run in 1 minute...")
        await asyncio.sleep(60)

        while self.is_running:
            try:
                start_time = datetime.now()
                logger.info(f"🕐 Starting scheduled AD sync at {start_time}")

                await self.sync_all_providers()

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                logger.info(f"✅ Sync completed in {duration:.2f} seconds")

                # Aguardar próximo intervalo
                logger.info(
                    f"⏰ Next sync in {self.interval_hours} hours "
                    f"({self.interval_seconds} seconds)"
                )
                await asyncio.sleep(self.interval_seconds)

            except asyncio.CancelledError:
                logger.info("🛑 AD Sync Scheduler cancelled")
                break
            except Exception as e:
                logger.error(f"❌ Error in AD sync loop: {e}", exc_info=True)
                # Em caso de erro, tentar novamente em 1 hora
                logger.info("⏰ Retrying in 1 hour due to error...")
                await asyncio.sleep(3600)

        self.is_running = False
        logger.info("✅ AD Sync Scheduler stopped")

    def start(self):
        """Inicia o scheduler em background"""
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self.run())
            logger.info("✅ AD Sync Scheduler task created")
        else:
            logger.warning("⚠️ AD Sync Scheduler already running")

    async def stop(self):
        """Para o scheduler"""
        if self.task and not self.task.done():
            self.is_running = False
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            logger.info("✅ AD Sync Scheduler stopped")


# Instância global do scheduler
_ad_sync_scheduler = None


def get_ad_sync_scheduler(interval_hours: int = 6) -> ADSyncScheduler:
    """
    Factory para obter instância global do scheduler

    Args:
        interval_hours: Intervalo em horas entre sincronizações (padrão: 6 horas)

    Returns:
        ADSyncScheduler instance
    """
    global _ad_sync_scheduler
    if _ad_sync_scheduler is None:
        _ad_sync_scheduler = ADSyncScheduler(interval_hours=interval_hours)
    return _ad_sync_scheduler
