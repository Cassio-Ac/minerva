"""
SSO Authentication Service
Gerencia o fluxo OAuth2/OIDC para autenticação SSO
"""
import secrets
import logging
import httpx
from typing import Dict, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.sso_provider import SSOProvider
from app.models.user import User, UserRole

logger = logging.getLogger(__name__)


class SSOAuthService:
    """Service para autenticação via SSO (OAuth2/OIDC)"""

    def __init__(self, provider: SSOProvider):
        self.provider = provider

    def generate_state(self) -> str:
        """Gera state aleatório para CSRF protection"""
        return secrets.token_urlsafe(32)

    def generate_nonce(self) -> str:
        """Gera nonce aleatório para ID token validation"""
        return secrets.token_urlsafe(32)

    def get_authorization_url(self, state: str, nonce: str) -> str:
        """
        Retorna URL para redirecionar usuário ao provider SSO

        Args:
            state: State parameter para CSRF protection
            nonce: Nonce para ID token validation

        Returns:
            URL completa do authorization endpoint
        """
        return self.provider.get_authorize_url(state, nonce)

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict:
        """
        Troca authorization code por access token

        Args:
            code: Authorization code recebido do provider
            redirect_uri: Redirect URI usado na autorização (deve ser idêntico)

        Returns:
            Dict com tokens: {
                "access_token": str,
                "token_type": "Bearer",
                "expires_in": int,
                "refresh_token": str (opcional),
                "id_token": str (opcional)
            }
        """
        token_url = self.provider.get_token_url()

        data = {
            "client_id": self.provider.client_id,
            "client_secret": self.provider.get_client_secret(),
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )

        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.status_code} {response.text}")
            raise Exception(f"Failed to exchange code for token: {response.text}")

        return response.json()

    async def get_user_info(self, access_token: str) -> Dict:
        """
        Busca informações do usuário usando access token

        Args:
            access_token: Access token obtido do provider

        Returns:
            Dict com informações do usuário:
            {
                "id": str,              # Object ID
                "email": str,
                "name": str,
                "given_name": str,
                "family_name": str,
                ...
            }
        """
        userinfo_url = self.provider.get_userinfo_url()

        async with httpx.AsyncClient() as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )

        if response.status_code != 200:
            logger.error(f"Get user info failed: {response.status_code} {response.text}")
            raise Exception(f"Failed to get user info: {response.text}")

        user_info = response.json()

        # Normalizar campos dependendo do provider
        if self.provider.provider_type == "entra_id":
            # Microsoft Graph API retorna:
            # - id: Object ID
            # - mail ou userPrincipalName: email
            # - displayName: nome completo
            return {
                "id": user_info.get("id"),
                "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                "name": user_info.get("displayName"),
                "given_name": user_info.get("givenName"),
                "family_name": user_info.get("surname"),
            }

        elif self.provider.provider_type == "google":
            # Google OAuth2 retorna:
            # - id: Google User ID
            # - email: email
            # - name: nome completo
            return {
                "id": user_info.get("id"),
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "given_name": user_info.get("given_name"),
                "family_name": user_info.get("family_name"),
            }

        else:
            return user_info

    async def provision_or_update_user(
        self,
        db: AsyncSession,
        user_info: Dict,
        check_ad_status: bool = True
    ) -> User:
        """
        Cria ou atualiza usuário local baseado em informações do SSO

        Args:
            db: Sessão do banco de dados
            user_info: Informações do usuário retornadas pelo provider
            check_ad_status: Se True, verifica status no AD antes de criar/atualizar

        Returns:
            User object (criado ou atualizado)

        Raises:
            Exception: Se usuário está desativado no AD ou outros erros
        """
        external_id = user_info["id"]
        email = user_info["email"]
        name = user_info.get("name", "")

        # Se check_ad_status, verificar se conta está ativa no AD
        if check_ad_status and self.provider.provider_type == "entra_id":
            from app.services.ad_sync_service import ADSyncService

            sync_service = ADSyncService(self.provider)
            ad_status = await sync_service.check_user_status(external_id)

            if not ad_status["exists"]:
                raise Exception(
                    "Conta não encontrada no Microsoft Entra ID. "
                    "Contate o administrador do sistema."
                )

            if not ad_status.get("accountEnabled", False):
                raise Exception(
                    "Sua conta foi desativada no sistema corporativo. "
                    "Contate o administrador."
                )

        # Buscar usuário existente
        result = await db.execute(
            select(User).where(
                User.sso_provider_id == self.provider.id,
                User.external_id == external_id
            )
        )
        user = result.scalar_one_or_none()

        if user:
            # Atualizar usuário existente
            logger.info(f"Updating existing SSO user: {email}")

            user.sso_email = email
            user.last_sso_login = datetime.now(timezone.utc).replace(tzinfo=None)
            user.last_ad_sync = datetime.now(timezone.utc).replace(tzinfo=None)
            user.ad_account_enabled = True
            user.sync_status = "synced"

            # Atualizar nome se mudou
            if name and name != user.full_name:
                user.full_name = name

            # Sincronizar foto do perfil (se ainda não tem ou está desatualizada)
            if self.provider.provider_type == "entra_id":
                from app.services.profile_photo_service import ProfilePhotoService
                try:
                    # Atualizar foto se não tem ou se passou mais de 7 dias
                    should_update_photo = (
                        not user.profile_photo_url or
                        not user.photo_updated_at or
                        (datetime.now(timezone.utc) - user.photo_updated_at).days > 7
                    )

                    if should_update_photo:
                        logger.info(f"Syncing profile photo for user {email}...")
                        await ProfilePhotoService.sync_photo_from_entra_id(user, self.provider)
                except Exception as e:
                    logger.error(f"Failed to sync profile photo: {e}")
                    # Não falhar o login por causa da foto

            await db.commit()
            await db.refresh(user)

            return user

        else:
            # Auto-provisioning: criar novo usuário
            if not self.provider.auto_provision:
                raise Exception(
                    "Auto-provisioning está desativado. "
                    "Contate o administrador para criar sua conta."
                )

            logger.info(f"Auto-provisioning new SSO user: {email}")

            # Gerar username único a partir do email
            username_base = email.split("@")[0].lower()
            username = username_base

            # Se username já existe, adicionar sufixo numérico
            counter = 1
            while True:
                result = await db.execute(
                    select(User).where(User.username == username)
                )
                if result.scalar_one_or_none() is None:
                    break
                username = f"{username_base}{counter}"
                counter += 1

            # Criar novo usuário com role padrão
            user = User(
                username=username,
                email=email,
                sso_email=email,
                full_name=name or username,
                hashed_password="",  # Sem senha local (SSO only)
                role=UserRole(self.provider.default_role),
                sso_provider_id=self.provider.id,
                external_id=external_id,
                is_active=True,
                last_sso_login=datetime.now(timezone.utc).replace(tzinfo=None),
                last_ad_sync=datetime.now(timezone.utc).replace(tzinfo=None),
                ad_account_enabled=True,
                sync_status="synced",
            )

            db.add(user)
            await db.commit()
            await db.refresh(user)

            logger.info(
                f"✅ Auto-provisioned user: {email} as {self.provider.default_role}"
            )

            # Buscar foto do perfil para novo usuário
            if self.provider.provider_type == "entra_id":
                from app.services.profile_photo_service import ProfilePhotoService
                try:
                    logger.info(f"Fetching profile photo for new user {email}...")
                    await ProfilePhotoService.sync_photo_from_entra_id(user, self.provider)
                    await db.commit()
                    await db.refresh(user)
                except Exception as e:
                    logger.error(f"Failed to sync profile photo: {e}")
                    # Não falhar o login por causa da foto

            return user


def get_sso_auth_service(provider: SSOProvider) -> SSOAuthService:
    """Factory para criar SSOAuthService"""
    return SSOAuthService(provider)
