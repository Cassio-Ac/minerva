"""
Credentials Cleanup Service

Gerencia a limpeza automática de arquivos HTML de consultas antigas.
- Remove arquivos HTML com mais de 7 dias
- Atualiza status no banco para "expired"
"""

import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.credentials.models.external_query import ExternalQuery

logger = logging.getLogger(__name__)

# Configurações
RETENTION_DAYS = 7
DOWNLOADS_DIR = Path(__file__).parent.parent.parent.parent / "downloads" / "credentials"


async def cleanup_expired_credentials():
    """
    Remove arquivos HTML de consultas com mais de 7 dias.
    Atualiza o status para 'expired' no banco.
    """
    logger.info("🧹 Iniciando cleanup de credenciais expiradas...")

    cutoff_date = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    files_deleted = 0
    records_updated = 0

    try:
        async with AsyncSessionLocal() as session:
            # Busca consultas antigas com arquivos
            result = await session.execute(
                select(ExternalQuery).where(
                    ExternalQuery.created_at < cutoff_date,
                    ExternalQuery.status != 'expired',
                    ExternalQuery.result_html_path.isnot(None)
                )
            )
            expired_queries = result.scalars().all()

            for query in expired_queries:
                # Remove arquivo HTML se existir
                if query.result_html_path:
                    html_path = Path(query.result_html_path)
                    if html_path.exists():
                        html_path.unlink()
                        files_deleted += 1
                        logger.info(f"   Deletado: {html_path.name}")

                # Remove arquivo de resultado se existir
                if query.result_file_path:
                    file_path = Path(query.result_file_path)
                    if file_path.exists():
                        file_path.unlink()
                        files_deleted += 1

                # Atualiza status para expirado
                query.status = 'expired'
                query.result_html_path = None
                query.result_file_path = None
                records_updated += 1

            await session.commit()

        logger.info(f"✅ Cleanup concluído: {files_deleted} arquivos deletados, {records_updated} registros atualizados")

    except Exception as e:
        logger.error(f"❌ Erro no cleanup: {e}")
        raise


async def get_query_with_availability(query_id: str) -> dict:
    """
    Retorna informações da consulta com indicação se HTML ainda está disponível.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ExternalQuery).where(ExternalQuery.id == query_id)
        )
        query = result.scalar_one_or_none()

        if not query:
            return None

        # Verifica se o HTML ainda existe
        html_available = False
        if query.result_html_path:
            html_path = Path(query.result_html_path)
            html_available = html_path.exists()

        # Calcula dias restantes
        days_old = (datetime.utcnow() - query.created_at).days
        days_remaining = max(0, RETENTION_DAYS - days_old)

        return {
            "query": query,
            "html_available": html_available,
            "days_remaining": days_remaining,
            "is_expired": query.status == 'expired' or days_old >= RETENTION_DAYS
        }


async def periodic_cleanup_task():
    """
    Task que executa o cleanup a cada 6 horas.
    """
    while True:
        try:
            await cleanup_expired_credentials()
        except Exception as e:
            logger.error(f"Erro no cleanup periódico: {e}")

        # Aguarda 6 horas
        await asyncio.sleep(6 * 60 * 60)


# Função para iniciar o cleanup scheduler
def start_cleanup_scheduler():
    """Inicia o scheduler de cleanup em background."""
    asyncio.create_task(periodic_cleanup_task())
    logger.info("✅ Credentials cleanup scheduler iniciado (a cada 6 horas)")
