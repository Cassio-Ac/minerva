"""
Profile Photo Service
Gerencia fotos de perfil de usuários (busca do Entra ID, cache local, etc)
"""
import os
import logging
import httpx
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from app.models.sso_provider import SSOProvider
from app.models.user import User

logger = logging.getLogger(__name__)

# Diretório base para fotos
PHOTO_DIR = Path("static/profile-photos")
PHOTO_DIR.mkdir(parents=True, exist_ok=True)


class ProfilePhotoService:
    """Service para gerenciar fotos de perfil"""

    @staticmethod
    async def fetch_photo_from_entra_id(
        provider: SSOProvider,
        user_external_id: str,
        access_token: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Busca foto do usuário do Microsoft Entra ID via Graph API

        Args:
            provider: Provider SSO configurado
            user_external_id: Object ID do usuário no Entra ID
            access_token: Access token (opcional, gera um novo se não fornecido)

        Returns:
            Bytes da imagem ou None se não encontrada
        """
        try:
            # Se não tem access token, gerar um usando client credentials
            if not access_token:
                logger.info(f"Getting app-only access token for photo fetch...")
                token_url = f"https://login.microsoftonline.com/{provider.tenant_id}/oauth2/v2.0/token"

                data = {
                    "client_id": provider.client_id,
                    "client_secret": provider.get_client_secret(),
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                }

                async with httpx.AsyncClient() as client:
                    token_response = await client.post(
                        token_url,
                        data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=30.0
                    )

                if token_response.status_code != 200:
                    logger.error(f"Failed to get access token: {token_response.text}")
                    return None

                access_token = token_response.json()["access_token"]

            # Buscar foto do usuário
            photo_url = f"https://graph.microsoft.com/v1.0/users/{user_external_id}/photo/$value"

            async with httpx.AsyncClient() as client:
                photo_response = await client.get(
                    photo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30.0
                )

            if photo_response.status_code == 200:
                logger.info(f"✅ Fetched profile photo for user {user_external_id}")
                return photo_response.content

            elif photo_response.status_code == 404:
                logger.info(f"ℹ️ User {user_external_id} has no profile photo in Entra ID")
                return None

            else:
                logger.warning(
                    f"⚠️ Failed to fetch photo: {photo_response.status_code} {photo_response.text}"
                )
                return None

        except Exception as e:
            logger.error(f"❌ Error fetching photo from Entra ID: {e}", exc_info=True)
            return None

    @staticmethod
    def save_photo_locally(user_id: str, photo_bytes: bytes) -> str:
        """
        Salva foto localmente no disco

        Args:
            user_id: ID do usuário
            photo_bytes: Bytes da imagem

        Returns:
            URL relativa da foto salva
        """
        try:
            # Determinar extensão baseado nos magic bytes
            if photo_bytes.startswith(b'\x89PNG'):
                ext = 'png'
            elif photo_bytes.startswith(b'\xff\xd8\xff'):
                ext = 'jpg'
            elif photo_bytes.startswith(b'RIFF') and photo_bytes[8:12] == b'WEBP':
                ext = 'webp'
            else:
                ext = 'jpg'  # Default

            # Caminho do arquivo
            filename = f"{user_id}.{ext}"
            filepath = PHOTO_DIR / filename

            # Salvar arquivo
            with open(filepath, 'wb') as f:
                f.write(photo_bytes)

            # Retornar URL relativa
            photo_url = f"/static/profile-photos/{filename}"
            logger.info(f"✅ Saved photo locally: {photo_url}")

            return photo_url

        except Exception as e:
            logger.error(f"❌ Error saving photo locally: {e}", exc_info=True)
            return None

    @staticmethod
    def delete_photo_locally(user_id: str) -> bool:
        """
        Remove foto local do usuário

        Args:
            user_id: ID do usuário

        Returns:
            True se removeu com sucesso, False caso contrário
        """
        try:
            # Tentar remover todos os formatos possíveis
            for ext in ['jpg', 'jpeg', 'png', 'webp']:
                filepath = PHOTO_DIR / f"{user_id}.{ext}"
                if filepath.exists():
                    filepath.unlink()
                    logger.info(f"✅ Deleted local photo: {filepath}")
                    return True

            logger.info(f"ℹ️ No local photo found for user {user_id}")
            return False

        except Exception as e:
            logger.error(f"❌ Error deleting photo: {e}", exc_info=True)
            return False

    @staticmethod
    async def sync_photo_from_entra_id(user: User, provider: SSOProvider) -> bool:
        """
        Sincroniza foto do usuário com Entra ID

        Busca foto do Graph API e salva localmente, atualizando o User model

        Args:
            user: Objeto User do SQLAlchemy
            provider: Provider SSO

        Returns:
            True se atualizou a foto, False caso contrário
        """
        try:
            if not user.external_id:
                logger.warning(f"User {user.username} has no external_id - cannot sync photo")
                return False

            # Buscar foto do Entra ID
            photo_bytes = await ProfilePhotoService.fetch_photo_from_entra_id(
                provider=provider,
                user_external_id=user.external_id
            )

            if photo_bytes:
                # Salvar localmente
                photo_url = ProfilePhotoService.save_photo_locally(
                    user_id=str(user.id),
                    photo_bytes=photo_bytes
                )

                if photo_url:
                    # Atualizar User model
                    user.profile_photo_url = photo_url
                    user.photo_source = 'entra_id'
                    user.photo_updated_at = datetime.now(timezone.utc)

                    logger.info(f"✅ Synced photo for user {user.username}")
                    return True

            else:
                # Usuário não tem foto no Entra ID
                # Manter foto padrão ou existente
                if not user.profile_photo_url:
                    user.photo_source = 'default'

                logger.info(f"ℹ️ User {user.username} has no photo in Entra ID")
                return False

        except Exception as e:
            logger.error(f"❌ Error syncing photo for user {user.username}: {e}", exc_info=True)
            return False

    @staticmethod
    def get_photo_path(user: User) -> str:
        """
        Retorna a URL da foto do usuário (local ou padrão)

        Args:
            user: Objeto User

        Returns:
            URL da foto (relativa)
        """
        if user.profile_photo_url:
            return user.profile_photo_url
        else:
            # Foto padrão (avatar genérico)
            return "/static/profile-photos/default.svg"


def get_profile_photo_service() -> ProfilePhotoService:
    """Factory para criar ProfilePhotoService"""
    return ProfilePhotoService()
