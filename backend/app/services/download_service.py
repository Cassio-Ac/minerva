"""
Download Service
Gerenciamento de arquivos de download
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import uuid
import logging

from app.models.download import Download
from app.models.user import User

logger = logging.getLogger(__name__)

# Diretório de downloads
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DOWNLOADS_DIR = BASE_DIR / "static" / "downloads"


class DownloadService:
    """Service para gerenciar downloads"""

    @staticmethod
    async def create_download(
        db: AsyncSession,
        user_id: str,
        file_path: str,
        original_name: str,
        file_type: str,
        description: Optional[str] = None,
        dashboard_id: Optional[str] = None,
        expires_in_days: Optional[int] = None
    ) -> Download:
        """
        Criar registro de download para um arquivo

        Args:
            db: Sessão do banco
            user_id: ID do usuário dono do arquivo
            file_path: Caminho completo do arquivo no servidor
            original_name: Nome original/amigável do arquivo
            file_type: Tipo do arquivo (html, pdf, png, etc)
            description: Descrição opcional
            dashboard_id: ID do dashboard relacionado (opcional)
            expires_in_days: Dias até expiração (opcional)

        Returns:
            Registro de download criado
        """
        # Verificar se arquivo existe
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Obter tamanho do arquivo
        file_size = path.stat().st_size

        # Calcular expiração
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Criar registro
        download = Download(
            filename=path.name,
            original_name=original_name,
            file_type=file_type,
            file_size=file_size,
            file_path=str(path.absolute()),
            user_id=uuid.UUID(user_id),
            description=description,
            dashboard_id=dashboard_id,
            expires_at=expires_at
        )

        db.add(download)
        await db.commit()
        await db.refresh(download)

        logger.info(f"Created download record: {download.id} ({download.filename})")

        return download

    @staticmethod
    async def get_download(
        db: AsyncSession,
        download_id: str
    ) -> Optional[Download]:
        """Buscar download por ID"""
        try:
            download_uuid = uuid.UUID(download_id)
        except ValueError:
            return None

        stmt = select(Download).where(Download.id == download_uuid)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_user_downloads(
        db: AsyncSession,
        user_id: str
    ) -> list[Download]:
        """Listar todos os downloads de um usuário"""
        stmt = select(Download).where(
            Download.user_id == uuid.UUID(user_id)
        ).order_by(Download.created_at.desc())

        result = await db.execute(stmt)
        return result.scalars().all()

    @staticmethod
    async def delete_download(
        db: AsyncSession,
        download_id: str,
        delete_file: bool = True
    ) -> bool:
        """
        Deletar registro de download

        Args:
            db: Sessão do banco
            download_id: ID do download
            delete_file: Se deve deletar arquivo físico também

        Returns:
            True se deletado com sucesso
        """
        download = await DownloadService.get_download(db, download_id)
        if not download:
            return False

        # Deletar arquivo físico se solicitado
        if delete_file:
            file_path = Path(download.file_path)
            if file_path.exists():
                try:
                    file_path.unlink()
                    logger.info(f"Deleted file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

        # Deletar registro
        await db.delete(download)
        await db.commit()

        logger.info(f"Deleted download record: {download_id}")
        return True

    @staticmethod
    async def cleanup_expired(db: AsyncSession) -> int:
        """
        Remover downloads expirados

        Returns:
            Número de downloads removidos
        """
        now = datetime.utcnow()

        # Buscar downloads expirados
        stmt = select(Download).where(
            Download.expires_at.isnot(None),
            Download.expires_at < now
        )

        result = await db.execute(stmt)
        expired = result.scalars().all()

        count = 0
        for download in expired:
            # Deletar arquivo físico
            file_path = Path(download.file_path)
            if file_path.exists():
                try:
                    file_path.unlink()
                    logger.info(f"Deleted expired file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting expired file {file_path}: {e}")

            # Deletar registro
            await db.delete(download)
            count += 1

        if count > 0:
            await db.commit()
            logger.info(f"Cleaned up {count} expired downloads")

        return count
