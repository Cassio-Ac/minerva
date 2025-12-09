"""
OTX Key Manager

Service para gerenciar chaves OTX com rotação automática
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.cti.models.otx_api_key import OTXAPIKey
from datetime import datetime, timedelta
import logging
from typing import Optional
import asyncio

logger = logging.getLogger(__name__)


class OTXKeyManager:
    """
    Gerenciador de chaves OTX com rotação automática

    Features:
    - Seleciona chave disponível automaticamente
    - Rotaciona entre múltiplas chaves
    - Tracking de uso e erros
    - Health checks
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self._lock = asyncio.Lock()  # Thread-safe para concorrência

    async def get_available_key(self) -> Optional[OTXAPIKey]:
        """
        Retorna uma chave OTX disponível para uso

        Lógica de seleção:
        1. Chave primária (is_primary=True) se disponível
        2. Chave com menor uso atual
        3. None se nenhuma chave disponível
        """
        async with self._lock:
            # Buscar todas as chaves ativas
            stmt = select(OTXAPIKey).where(
                OTXAPIKey.is_active == True
            ).order_by(
                OTXAPIKey.is_primary.desc(),  # Primárias primeiro
                OTXAPIKey.current_usage.asc()  # Menor uso primeiro
            )

            result = await self.session.execute(stmt)
            keys = result.scalars().all()

            if not keys:
                logger.error("❌ No OTX API keys configured")
                return None

            # Verificar chaves disponíveis
            for key in keys:
                if key.is_available():
                    logger.info(f"✅ Selected OTX key: {key.name} (usage: {key.current_usage}/{key.daily_limit})")
                    return key

            logger.warning("⚠️ All OTX keys exhausted or unavailable")
            return None

    async def record_request(self, key: OTXAPIKey, success: bool = True):
        """
        Registra uso de uma chave

        Args:
            key: Chave usada
            success: Se a request foi bem sucedida
        """
        async with self._lock:
            if success:
                key.increment_usage()
                key.reset_error_count()
                key.health_status = "ok"
            else:
                key.record_error()

                # Se muitos erros, marcar como unhealthy
                if key.error_count > 5:
                    key.health_status = "error"
                    logger.warning(f"⚠️ Key {key.name} marked as unhealthy (too many errors)")

            await self.session.commit()

    async def record_rate_limit_error(self, key: OTXAPIKey):
        """
        Registra que uma chave atingiu rate limit

        Args:
            key: Chave que atingiu rate limit
        """
        async with self._lock:
            key.health_status = "rate_limited"
            key.current_usage = key.daily_limit  # Marcar como esgotada
            key.record_error()
            await self.session.commit()

            logger.warning(f"⚠️ Key {key.name} hit rate limit")

    async def reset_daily_usage(self):
        """
        Reseta uso diário de todas as chaves

        Deve ser chamado diariamente (cron job ou Celery task)
        """
        async with self._lock:
            stmt = update(OTXAPIKey).values(
                current_usage=0,
                requests_today=0,
                error_count=0,
                health_status="unknown"
            )

            await self.session.execute(stmt)
            await self.session.commit()

            logger.info("✅ Reset daily usage for all OTX keys")

    async def get_key_stats(self) -> dict:
        """
        Retorna estatísticas de uso das chaves
        """
        stmt = select(OTXAPIKey).where(OTXAPIKey.is_active == True)
        result = await self.session.execute(stmt)
        keys = result.scalars().all()

        total_keys = len(keys)
        available_keys = sum(1 for k in keys if k.is_available())
        total_usage = sum(k.current_usage for k in keys)
        total_capacity = sum(k.daily_limit for k in keys)

        return {
            "total_keys": total_keys,
            "available_keys": available_keys,
            "exhausted_keys": total_keys - available_keys,
            "total_usage_today": total_usage,
            "total_capacity": total_capacity,
            "usage_percentage": round((total_usage / total_capacity * 100), 2) if total_capacity > 0 else 0,
            "keys": [
                {
                    "name": k.name,
                    "is_primary": k.is_primary,
                    "is_available": k.is_available(),
                    "usage": k.current_usage,
                    "limit": k.daily_limit,
                    "health": k.health_status,
                    "errors": k.error_count
                }
                for k in keys
            ]
        }

    async def health_check_key(self, key: OTXAPIKey) -> bool:
        """
        Verifica se uma chave está funcionando

        Args:
            key: Chave para verificar

        Returns:
            True se a chave está ok, False caso contrário
        """
        try:
            from OTXv2 import OTXv2

            otx = OTXv2(key.api_key)

            # Tentar buscar informações do usuário (lightweight request)
            user_info = otx.get('/api/v1/users/me')

            if user_info and 'username' in user_info:
                async with self._lock:
                    key.health_status = "ok"
                    key.last_health_check = datetime.utcnow()
                    key.reset_error_count()
                    await self.session.commit()

                logger.info(f"✅ Health check OK for key {key.name}")
                return True
            else:
                raise Exception("Invalid response from OTX API")

        except Exception as e:
            logger.error(f"❌ Health check failed for key {key.name}: {e}")

            async with self._lock:
                key.health_status = "error"
                key.last_health_check = datetime.utcnow()
                key.record_error()
                await self.session.commit()

            return False

    async def add_key(
        self,
        name: str,
        api_key: str,
        description: str = None,
        is_primary: bool = False,
        daily_limit: int = 9000
    ) -> OTXAPIKey:
        """
        Adiciona uma nova chave OTX

        Args:
            name: Nome da chave
            api_key: Chave OTX
            description: Descrição
            is_primary: Se é chave primária
            daily_limit: Limite diário de requests

        Returns:
            Chave criada
        """
        new_key = OTXAPIKey(
            name=name,
            api_key=api_key,
            description=description,
            is_active=True,
            is_primary=is_primary,
            daily_limit=daily_limit
        )

        self.session.add(new_key)
        await self.session.commit()
        await self.session.refresh(new_key)

        logger.info(f"✅ Added new OTX key: {name}")

        # Fazer health check imediato
        await self.health_check_key(new_key)

        return new_key

    async def deactivate_key(self, key_id: str):
        """
        Desativa uma chave

        Args:
            key_id: ID da chave
        """
        stmt = update(OTXAPIKey).where(
            OTXAPIKey.id == key_id
        ).values(is_active=False)

        await self.session.execute(stmt)
        await self.session.commit()

        logger.info(f"✅ Deactivated OTX key: {key_id}")

    async def activate_key(self, key_id: str):
        """
        Ativa uma chave

        Args:
            key_id: ID da chave
        """
        stmt = update(OTXAPIKey).where(
            OTXAPIKey.id == key_id
        ).values(is_active=True)

        await self.session.execute(stmt)
        await self.session.commit()

        logger.info(f"✅ Activated OTX key: {key_id}")
