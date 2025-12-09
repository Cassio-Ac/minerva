"""
Active Directory Sync Service
Sincroniza usuários SSO com Microsoft Entra ID via Graph API
"""
import httpx
import logging
from typing import Dict, List
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.sso_provider import SSOProvider
from app.models.user import User

logger = logging.getLogger(__name__)


class ADSyncService:
    """Service para sincronizar usuários com Microsoft Entra ID"""

    def __init__(self, provider: SSOProvider):
        self.provider = provider
        self.graph_api_base = "https://graph.microsoft.com/v1.0"

    async def get_app_access_token(self) -> str:
        """
        Obtém access token de aplicação (não de usuário) para consultas administrativas

        Usa client_credentials flow (app-only authentication)
        Requer permissões: User.Read.All, Directory.Read.All

        Returns:
            Access token válido
        """
        token_url = f"https://login.microsoftonline.com/{self.provider.tenant_id}/oauth2/v2.0/token"

        data = {
            "client_id": self.provider.client_id,
            "client_secret": self.provider.get_client_secret(),
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )

        if response.status_code != 200:
            logger.error(f"Failed to get app token: {response.status_code} {response.text}")
            raise Exception(f"Failed to get app access token: {response.text}")

        return response.json()["access_token"]

    async def check_user_status(self, external_id: str) -> Dict:
        """
        Verifica status de um usuário específico no Microsoft Entra ID

        Args:
            external_id: Object ID do usuário no AD

        Returns:
            {
                "exists": bool,
                "accountEnabled": bool,
                "displayName": str,
                "mail": str,
                "userPrincipalName": str
            }
        """
        try:
            token = await self.get_app_access_token()

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.graph_api_base}/users/{external_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    params={
                        "$select": "accountEnabled,displayName,mail,userPrincipalName,id"
                    },
                    timeout=30.0
                )

            if response.status_code == 404:
                logger.warning(f"User {external_id} not found in AD")
                return {"exists": False}

            if response.status_code != 200:
                logger.error(f"Graph API error: {response.status_code} {response.text}")
                raise Exception(f"Failed to check user status: {response.text}")

            data = response.json()

            return {
                "exists": True,
                "accountEnabled": data.get("accountEnabled", False),
                "displayName": data.get("displayName"),
                "mail": data.get("mail"),
                "userPrincipalName": data.get("userPrincipalName"),
            }

        except Exception as e:
            logger.error(f"Error checking user {external_id}: {e}")
            return {
                "exists": False,
                "error": str(e)
            }

    async def _sync_user_photo(self, user: User) -> bool:
        """
        Sincroniza foto do perfil do usuário com Entra ID

        Atualiza foto se:
        - Usuário não tem foto OU
        - Foto tem mais de 30 dias

        Args:
            user: Objeto User do SQLAlchemy

        Returns:
            True se atualizou foto, False caso contrário
        """
        try:
            from app.services.profile_photo_service import ProfilePhotoService

            # Verificar se precisa atualizar foto
            should_update = (
                not user.profile_photo_url or
                not user.photo_updated_at or
                (datetime.now(timezone.utc) - user.photo_updated_at).days > 30
            )

            if not should_update:
                logger.debug(f"Skipping photo sync for {user.username} (recently updated)")
                return False

            logger.info(f"🔄 Syncing photo for user {user.username}...")
            result = await ProfilePhotoService.sync_photo_from_entra_id(user, self.provider)

            if result:
                logger.info(f"✅ Photo synced for {user.username}")

            return result

        except Exception as e:
            logger.warning(f"⚠️ Failed to sync photo for {user.username}: {e}")
            # Não falhar o sync por causa da foto
            return False

    async def sync_all_sso_users(self, db: AsyncSession) -> Dict:
        """
        Sincroniza TODOS os usuários SSO do Dashboard com o AD

        Para cada usuário SSO ativo:
        1. Consulta status no AD
        2. Se desativado ou não existe → desativa no Dashboard
        3. Se ativo → mantém sincronizado
        4. Atualiza foto do perfil (Entra ID) se necessário (>30 dias)

        Args:
            db: Sessão do banco de dados

        Returns:
            {
                "total_checked": int,
                "deactivated": int,
                "activated": int,
                "errors": int,
                "details": List[Dict]
            }
        """
        # Buscar todos usuários SSO deste provider
        result = await db.execute(
            select(User).where(
                User.sso_provider_id == self.provider.id,
                User.external_id.isnot(None)
            )
        )
        users = result.scalars().all()

        results = {
            "total_checked": len(users),
            "deactivated": 0,
            "activated": 0,
            "errors": 0,
            "details": []
        }

        logger.info(f"🔄 Starting AD sync for {len(users)} users...")

        for user in users:
            try:
                ad_status = await self.check_user_status(user.external_id)

                # Atualizar timestamp de sincronização
                user.last_ad_sync = datetime.now(timezone.utc).replace(tzinfo=None)

                if not ad_status.get("exists", False):
                    # Usuário não existe mais no AD
                    user.ad_account_enabled = False
                    user.sync_status = "not_found"

                    if user.is_active:
                        user.is_active = False
                        results["deactivated"] += 1
                        results["details"].append({
                            "user": user.username,
                            "email": user.email,
                            "action": "deactivated",
                            "reason": "not_found_in_ad"
                        })
                        logger.warning(f"⚠️ Deactivated user {user.username} (not found in AD)")

                elif not ad_status.get("accountEnabled", False):
                    # Usuário desativado no AD
                    user.ad_account_enabled = False
                    user.sync_status = "synced"

                    if user.is_active:
                        user.is_active = False
                        results["deactivated"] += 1
                        results["details"].append({
                            "user": user.username,
                            "email": user.email,
                            "action": "deactivated",
                            "reason": "disabled_in_ad"
                        })
                        logger.warning(f"⚠️ Deactivated user {user.username} (disabled in AD)")

                else:
                    # Usuário ativo no AD
                    user.ad_account_enabled = True
                    user.sync_status = "synced"

                    # Se estava desativado no Dashboard por causa do AD, reativar
                    # (mas não reativa se admin desativado manualmente)
                    if not user.is_active and user.sync_status in ["not_found", "synced"]:
                        # Apenas reativar se foi desativado automaticamente
                        # (não temos flag para isso, então deixamos desativado)
                        pass

                    # Atualizar foto do perfil (se Entra ID)
                    if self.provider.provider_type == "entra_id":
                        await self._sync_user_photo(user)

            except Exception as e:
                user.sync_status = "error"
                results["errors"] += 1
                results["details"].append({
                    "user": user.username,
                    "email": user.email,
                    "action": "error",
                    "error": str(e)
                })
                logger.error(f"❌ Error syncing user {user.username}: {e}")

        await db.commit()

        logger.info(
            f"✅ AD sync completed: {results['total_checked']} checked, "
            f"{results['deactivated']} deactivated, {results['errors']} errors"
        )

        return results


def get_ad_sync_service(provider: SSOProvider) -> ADSyncService:
    """Factory para criar ADSyncService"""
    return ADSyncService(provider)
