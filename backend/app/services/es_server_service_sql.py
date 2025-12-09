"""
Elasticsearch Server Service - SQL Version
CRUD operations for ES servers in PostgreSQL
"""

from typing import List, Optional
from datetime import datetime
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.models import ESServer as ESServerDB
from app.models.elasticsearch_server import (
    ElasticsearchServer,
    ESServerCreate,
    ESServerUpdate,
)

logger = logging.getLogger(__name__)


class ESServerServiceSQL:
    """Service para operações de ES Server usando PostgreSQL"""

    async def create(self, db: AsyncSession, server_data: ESServerCreate) -> ElasticsearchServer:
        """Cria um novo servidor ES"""
        try:
            # Se for default, remover flag de outros servidores
            if server_data.is_default:
                await self._unset_all_defaults(db)

            # Criar servidor
            db_server = ESServerDB(
                name=server_data.name,
                description=server_data.description,
                url=server_data.connection.url,
                username=server_data.connection.username,
                password=server_data.connection.password,  # Auto-criptografa via property
                use_ssl=server_data.connection.url.startswith('https://'),
                verify_certs=server_data.connection.verify_ssl,
                is_default=server_data.is_default,
                is_active=True,
            )

            db.add(db_server)
            await db.flush()
            await db.refresh(db_server)

            logger.info(f"✅ ES Server created in SQL: {db_server.id}")
            return self._to_pydantic(db_server)

        except Exception as e:
            logger.error(f"❌ Error creating ES server: {e}")
            raise

    async def get(self, db: AsyncSession, server_id: str) -> Optional[ElasticsearchServer]:
        """Busca servidor por ID"""
        try:
            stmt = select(ESServerDB).where(ESServerDB.id == server_id)
            result = await db.execute(stmt)
            db_server = result.scalar_one_or_none()

            if db_server:
                return self._to_pydantic(db_server)
            return None

        except Exception as e:
            logger.error(f"❌ Error getting ES server {server_id}: {e}")
            return None

    async def list(
        self,
        db: AsyncSession,
        active_only: bool = False,
    ) -> List[ElasticsearchServer]:
        """Lista servidores ES"""
        try:
            stmt = select(ESServerDB)

            if active_only:
                stmt = stmt.where(ESServerDB.is_active == True)

            # Ordenar por default primeiro, depois por nome
            stmt = stmt.order_by(ESServerDB.is_default.desc(), ESServerDB.name)

            result = await db.execute(stmt)
            db_servers = result.scalars().all()

            servers = [self._to_pydantic(s) for s in db_servers]
            logger.info(f"✅ Listed {len(servers)} ES servers from SQL")
            return servers

        except Exception as e:
            logger.error(f"❌ Error listing ES servers: {e}")
            return []

    async def update(
        self, db: AsyncSession, server_id: str, updates: ESServerUpdate
    ) -> Optional[ElasticsearchServer]:
        """Atualiza servidor ES"""
        try:
            # Verificar se existe
            current = await self.get(db, server_id)
            if not current:
                return None

            # Se vai se tornar default, remover flag de outros
            if updates.is_default:
                await self._unset_all_defaults(db)

            # Preparar updates
            update_dict = {}
            if updates.name is not None:
                update_dict["name"] = updates.name
            if updates.description is not None:
                update_dict["description"] = updates.description
            if updates.is_default is not None:
                update_dict["is_default"] = updates.is_default
            if updates.is_active is not None:
                update_dict["is_active"] = updates.is_active

            # Connection updates
            if updates.connection:
                if updates.connection.url:
                    update_dict["url"] = updates.connection.url
                if updates.connection.username:
                    update_dict["username"] = updates.connection.username
                if updates.connection.password:
                    # Password será criptografado automaticamente
                    db_server = await db.get(ESServerDB, server_id)
                    db_server.password = updates.connection.password
                if updates.connection.use_ssl is not None:
                    update_dict["use_ssl"] = updates.connection.use_ssl
                if updates.connection.verify_certs is not None:
                    update_dict["verify_certs"] = updates.connection.verify_certs

            update_dict["updated_at"] = datetime.utcnow()

            stmt = (
                update(ESServerDB)
                .where(ESServerDB.id == server_id)
                .values(**update_dict)
                .returning(ESServerDB)
            )

            result = await db.execute(stmt)
            await db.flush()
            db_server = result.scalar_one_or_none()

            if db_server:
                logger.info(f"✅ ES Server updated in SQL: {server_id}")
                return self._to_pydantic(db_server)
            return None

        except Exception as e:
            logger.error(f"❌ Error updating ES server {server_id}: {e}")
            raise

    async def delete_server(self, db: AsyncSession, server_id: str) -> bool:
        """Deleta servidor ES"""
        try:
            stmt = delete(ESServerDB).where(ESServerDB.id == server_id)
            result = await db.execute(stmt)
            await db.flush()

            if result.rowcount > 0:
                logger.info(f"✅ ES Server deleted from SQL: {server_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"❌ Error deleting ES server {server_id}: {e}")
            return False

    async def get_default(self, db: AsyncSession) -> Optional[ElasticsearchServer]:
        """Retorna servidor default"""
        try:
            stmt = select(ESServerDB).where(
                ESServerDB.is_default == True,
                ESServerDB.is_active == True
            )
            result = await db.execute(stmt)
            db_server = result.scalar_one_or_none()

            if db_server:
                return self._to_pydantic(db_server)
            return None

        except Exception as e:
            logger.error(f"❌ Error getting default ES server: {e}")
            return None

    async def _unset_all_defaults(self, db: AsyncSession):
        """Remove flag is_default de todos os servidores"""
        try:
            stmt = update(ESServerDB).values(is_default=False).where(ESServerDB.is_default == True)
            await db.execute(stmt)
            await db.flush()
        except Exception as e:
            logger.error(f"❌ Error unsetting defaults: {e}")

    async def get_indices(self, db: AsyncSession, server_id: str) -> List:
        """
        Lista índices do servidor Elasticsearch

        Args:
            db: Sessão do banco
            server_id: ID do servidor

        Returns:
            Lista de índices
        """
        from app.models.elasticsearch_server import ESIndexInfo
        from elasticsearch import AsyncElasticsearch

        # Buscar servidor no SQL
        server = await self.get(db, server_id)
        if not server:
            logger.warning(f"Server {server_id} not found in SQL")
            return []

        try:
            # Criar cliente ES para este servidor usando a connection configurada
            es_client = AsyncElasticsearch(
                hosts=[server.connection.url],
                basic_auth=(
                    (server.connection.username, server.connection.password)
                    if server.connection.username and server.connection.password
                    else None
                ),
                verify_certs=server.connection.verify_ssl,
                request_timeout=server.connection.timeout,
            )

            # Buscar índices via cat API
            cat_indices = await es_client.cat.indices(format="json")

            await es_client.close()

            # Processar resultados
            indices = []
            for idx in cat_indices:
                name = idx.get("index", "")
                # Ignorar índices do sistema
                if name.startswith("."):
                    continue

                # Converter store.size (vem como string tipo "249b", "1.2kb", etc)
                store_size_str = idx.get("store.size", "0")
                try:
                    # Remover sufixos (b, kb, mb, gb) e converter
                    import re
                    size_match = re.match(r'([\d.]+)([a-z]+)?', str(store_size_str))
                    if size_match:
                        number = float(size_match.group(1))
                        unit = size_match.group(2) or 'b'
                        # Converter para bytes
                        multipliers = {'b': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3}
                        size_in_bytes = int(number * multipliers.get(unit.lower(), 1))
                    else:
                        size_in_bytes = 0
                except:
                    size_in_bytes = 0

                indices.append(
                    ESIndexInfo(
                        name=name,
                        doc_count=int(idx.get("docs.count", 0) or 0),
                        size_in_bytes=size_in_bytes,
                        health=idx.get("health"),
                        status=idx.get("status"),
                        primary_shards=int(idx.get("pri", 0) or 0),
                        replica_shards=int(idx.get("rep", 0) or 0),
                    )
                )

            logger.info(f"📚 Listed {len(indices)} indices from server {server.name}")
            return sorted(indices, key=lambda x: x.name)

        except Exception as e:
            logger.error(f"Error listing indices from server {server_id}: {e}")
            return []

    def _to_pydantic(self, db_server: ESServerDB) -> ElasticsearchServer:
        """Converte SQLAlchemy model para Pydantic model"""
        from app.models.elasticsearch_server import ESServerConnection, ESServerMetadata, ESServerStats

        return ElasticsearchServer(
            id=str(db_server.id),
            name=db_server.name,
            description=db_server.description,
            connection=ESServerConnection(
                url=db_server.url,
                username=db_server.username,
                password=db_server.password,  # Auto-descriptografa via property
                verify_ssl=db_server.verify_certs,
                timeout=30,  # Default timeout
            ),
            metadata=ESServerMetadata(
                created_at=db_server.created_at,
                updated_at=db_server.updated_at,
            ),
            stats=ESServerStats(),
            is_default=db_server.is_default,
            is_active=db_server.is_active,
        )


# Singleton instance
_es_server_service_sql: Optional[ESServerServiceSQL] = None


def get_es_server_service_sql() -> ESServerServiceSQL:
    """Retorna instância do service"""
    global _es_server_service_sql
    if _es_server_service_sql is None:
        _es_server_service_sql = ESServerServiceSQL()
    return _es_server_service_sql
