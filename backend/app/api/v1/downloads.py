"""
Downloads API - Sistema seguro de downloads com controle de acesso
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path
from datetime import datetime, timedelta
from typing import List
import logging
import uuid

from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.download import Download
from app.db.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

# Diretório de downloads (relativo ao diretório do projeto)
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
DOWNLOADS_DIR = BASE_DIR / "static" / "downloads"

# Retenção de arquivos (em dias)
RETENTION_DAYS = 1


async def cleanup_old_files():
    """
    Remove arquivos com mais de RETENTION_DAYS dias do diretório de downloads
    Executado em background task e remove também registros do banco
    """
    try:
        if not DOWNLOADS_DIR.exists():
            logger.warning(f"Downloads directory does not exist: {DOWNLOADS_DIR}")
            return

        now = datetime.now()
        cutoff_time = now - timedelta(days=RETENTION_DAYS)

        deleted_count = 0
        total_size = 0

        # Iterar sobre todos os arquivos no diretório
        for file_path in DOWNLOADS_DIR.iterdir():
            if file_path.is_file():
                # Obter timestamp de modificação
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)

                # Se arquivo é mais antigo que cutoff_time, deletar
                if file_mtime < cutoff_time:
                    file_size = file_path.stat().st_size
                    try:
                        file_path.unlink()
                        deleted_count += 1
                        total_size += file_size
                        logger.info(f"Deleted old file: {file_path.name} (age: {now - file_mtime})")
                    except Exception as e:
                        logger.error(f"Error deleting file {file_path.name}: {e}")

        if deleted_count > 0:
            logger.info(f"Cleanup complete: deleted {deleted_count} files, freed {total_size / 1024 / 1024:.2f} MB")
        else:
            logger.debug("Cleanup complete: no old files found")

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")


@router.get("/")
async def list_downloads(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Listar arquivos disponíveis para download do usuário
    Apenas retorna arquivos do próprio usuário (exceto admins que veem tudo)

    Returns:
        Lista de arquivos com metadados
    """
    # Construir query
    if current_user.can_configure_system:
        # Admin vê todos os arquivos
        stmt = select(Download).order_by(Download.created_at.desc())
    else:
        # Usuário normal vê apenas seus próprios arquivos
        stmt = select(Download).where(
            Download.user_id == current_user.id
        ).order_by(Download.created_at.desc())

    result = await db.execute(stmt)
    downloads = result.scalars().all()

    return [
        {
            "id": str(download.id),
            "filename": download.filename,
            "original_name": download.original_name,
            "file_type": download.file_type,
            "file_size": download.file_size,
            "description": download.description,
            "dashboard_id": download.dashboard_id,
            "download_count": download.download_count,
            "created_at": download.created_at.isoformat(),
            "expires_at": download.expires_at.isoformat() if download.expires_at else None,
            "user_id": str(download.user_id),
        }
        for download in downloads
    ]


@router.get("/{download_id}/download")
async def download_file(
    download_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Download seguro de arquivo por ID
    Valida ownership antes de servir arquivo

    Args:
        download_id: UUID do registro de download
        current_user: Usuário autenticado
        db: Sessão do banco de dados

    Returns:
        Arquivo para download

    Raises:
        HTTPException: 404 se não encontrado, 403 se sem permissão
    """
    try:
        download_uuid = uuid.UUID(download_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid download ID format")

    # Buscar registro no banco
    stmt = select(Download).where(Download.id == download_uuid)
    result = await db.execute(stmt)
    download = result.scalar_one_or_none()

    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verificar ownership (admin pode baixar tudo)
    if not current_user.can_configure_system and download.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to download this file")

    # Verificar se arquivo ainda existe
    file_path = Path(download.file_path)
    if not file_path.exists():
        logger.error(f"File not found on disk: {file_path}")
        raise HTTPException(status_code=404, detail="File not found on server")

    # Incrementar contador de downloads
    download.download_count += 1
    await db.commit()

    # Log do download
    logger.info(f"User {current_user.username} downloading file: {download.filename} (count: {download.download_count})")

    # Servir arquivo
    media_type = "text/html" if download.file_type == "html" else "application/octet-stream"
    return FileResponse(
        path=str(file_path),
        filename=download.original_name,
        media_type=media_type
    )


@router.delete("/{download_id}")
async def delete_download(
    download_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Deletar arquivo de download
    Apenas owner ou admin podem deletar

    Args:
        download_id: UUID do registro
        current_user: Usuário autenticado
        db: Sessão do banco

    Returns:
        Status da operação
    """
    try:
        download_uuid = uuid.UUID(download_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid download ID format")

    # Buscar registro
    stmt = select(Download).where(Download.id == download_uuid)
    result = await db.execute(stmt)
    download = result.scalar_one_or_none()

    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verificar ownership
    if not current_user.can_configure_system and download.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")

    # Deletar arquivo físico
    file_path = Path(download.file_path)
    if file_path.exists():
        try:
            file_path.unlink()
            logger.info(f"Deleted file: {file_path}")
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")

    # Deletar registro do banco
    await db.delete(download)
    await db.commit()

    logger.info(f"User {current_user.username} deleted download: {download.filename}")

    return {
        "status": "success",
        "message": "File deleted successfully"
    }


@router.post("/cleanup")
async def trigger_cleanup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger manual cleanup of old files
    Apenas admin

    Args:
        current_user: Usuário autenticado
        db: Sessão do banco

    Returns:
        Status da operação
    """
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    logger.info(f"Manual cleanup triggered by user: {current_user.username}")

    # Cleanup físico
    await cleanup_old_files()

    # Cleanup de registros órfãos (sem arquivo físico)
    stmt = select(Download)
    result = await db.execute(stmt)
    downloads = result.scalars().all()

    orphaned_count = 0
    for download in downloads:
        file_path = Path(download.file_path)
        if not file_path.exists():
            await db.delete(download)
            orphaned_count += 1

    if orphaned_count > 0:
        await db.commit()
        logger.info(f"Removed {orphaned_count} orphaned download records")

    return {
        "status": "success",
        "message": f"Cleanup completed. Files older than {RETENTION_DAYS} day(s) removed. {orphaned_count} orphaned records cleaned.",
        "orphaned_records_removed": orphaned_count
    }
