"""
Script para migrar ES Servers do Elasticsearch para PostgreSQL
Executa uma única vez após atualização do sistema
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.db.database import AsyncSessionLocal
from app.db.models import ESServer as ESServerDB
from app.services.es_server_service import get_es_server_service
from sqlalchemy import select
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def migrate_es_servers():
    """Migra ES servers do Elasticsearch para PostgreSQL"""

    logger.info("🔄 Starting ES servers migration...")

    # 1. Buscar servidores do Elasticsearch
    es_service = get_es_server_service()

    try:
        es_servers = await es_service.list(active_only=False, include_stats=False)
        logger.info(f"📋 Found {len(es_servers)} ES servers in Elasticsearch")

        if not es_servers:
            logger.warning("⚠️ No ES servers found in Elasticsearch")
            return

        # 2. Salvar no PostgreSQL
        async with AsyncSessionLocal() as db:
            migrated_count = 0

            for server in es_servers:
                # Verificar se já existe
                stmt = select(ESServerDB).where(ESServerDB.id == server.id)
                result = await db.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    logger.info(f"⏭️ Server {server.name} already exists in PostgreSQL, skipping")
                    continue

                # Criar no PostgreSQL
                db_server = ESServerDB(
                    id=server.id,
                    name=server.name,
                    description=server.description,
                    url=server.connection.url,
                    username=server.connection.username,
                    password=server.connection.password,  # Auto-criptografa
                    is_active=server.is_active,
                    created_at=server.metadata.created_at,
                    updated_at=server.metadata.updated_at,
                )

                db.add(db_server)
                migrated_count += 1
                logger.info(f"✅ Migrated: {server.name} ({server.id})")

            await db.commit()
            logger.info(f"✅ Migration complete! Migrated {migrated_count} servers")

    except Exception as e:
        logger.error(f"❌ Error during migration: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(migrate_es_servers())
