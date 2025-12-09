"""
Dashboard Service - SQL Version
CRUD operations for dashboards in PostgreSQL
"""

from typing import List, Optional
from datetime import datetime
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.models import Dashboard as DashboardDB
from app.models.dashboard import Dashboard, DashboardListItem
from app.schemas.dashboard import DashboardCreate, DashboardUpdate

logger = logging.getLogger(__name__)


class DashboardServiceSQL:
    """Service para operações de Dashboard usando PostgreSQL"""

    async def create(
        self, db: AsyncSession, dashboard_data: DashboardCreate, dashboard_id: Optional[str] = None
    ) -> Dashboard:
        """Cria um novo dashboard"""
        try:
            # Criar dashboard object
            dashboard = Dashboard(
                id=dashboard_id or Dashboard.model_fields["id"].default_factory(),
                title=dashboard_data.title,
                description=dashboard_data.description,
                index=dashboard_data.index,
                server_id=dashboard_data.server_id,
                layout=dashboard_data.layout or Dashboard.model_fields["layout"].default_factory(),
                widgets=dashboard_data.widgets or [],
            )

            if dashboard_data.tags:
                dashboard.metadata.tags = dashboard_data.tags

            # Preparar para salvamento (remover results dos widgets)
            widgets_clean = []
            for widget in dashboard.widgets:
                widget_dict = widget.model_dump(mode='json')
                if "data" in widget_dict and "results" in widget_dict["data"]:
                    # Remover results - não persistir cache
                    del widget_dict["data"]["results"]
                widgets_clean.append(widget_dict)

            # Converter para SQLAlchemy model
            db_dashboard = DashboardDB(
                id=dashboard.id,
                title=dashboard.title,
                description=dashboard.description,
                index=dashboard.index,
                server_id=dashboard.server_id,
                layout=dashboard.layout.model_dump(),
                widgets=widgets_clean,
                is_public=dashboard.metadata.is_public,
                tags=dashboard.metadata.tags,
                version=str(dashboard.metadata.version),
                created_by=dashboard.metadata.created_by,
                created_at=dashboard.metadata.created_at,
                updated_at=dashboard.metadata.updated_at,
            )

            db.add(db_dashboard)
            await db.flush()
            await db.refresh(db_dashboard)

            logger.info(f"✅ Dashboard created in SQL: {dashboard.id}")
            return self._to_pydantic(db_dashboard)

        except Exception as e:
            logger.error(f"❌ Error creating dashboard: {e}")
            raise

    async def get(self, db: AsyncSession, dashboard_id: str) -> Optional[Dashboard]:
        """Busca dashboard por ID"""
        try:
            stmt = select(DashboardDB).where(DashboardDB.id == dashboard_id)
            result = await db.execute(stmt)
            db_dashboard = result.scalar_one_or_none()

            if db_dashboard:
                return self._to_pydantic(db_dashboard)
            return None

        except Exception as e:
            logger.error(f"❌ Error getting dashboard {dashboard_id}: {e}")
            return None

    async def update(
        self, db: AsyncSession, dashboard_id: str, updates: DashboardUpdate
    ) -> Optional[Dashboard]:
        """Atualiza dashboard"""
        try:
            # Buscar dashboard atual
            current = await self.get(db, dashboard_id)

            # Se não existe, criar automaticamente
            if not current:
                logger.info(f"Dashboard {dashboard_id} not found, creating automatically...")
                dashboard_data = DashboardCreate(
                    title="Meu Dashboard",
                    description="Dashboard criado automaticamente",
                    index="vazamentos",
                    widgets=updates.widgets or [],
                )
                return await self.create(db, dashboard_data, dashboard_id=dashboard_id)

            # Preparar updates
            update_dict = {}
            if updates.title is not None:
                update_dict["title"] = updates.title
            if updates.description is not None:
                update_dict["description"] = updates.description
            if updates.layout is not None:
                update_dict["layout"] = updates.layout.model_dump()
            if updates.tags is not None:
                update_dict["tags"] = updates.tags

            # Widgets (limpar results)
            if updates.widgets is not None:
                widgets_clean = []
                for widget in updates.widgets:
                    widget_dict = widget.model_dump(mode='json') if hasattr(widget, "model_dump") else widget
                    if isinstance(widget_dict, dict) and "data" in widget_dict and "results" in widget_dict["data"]:
                        del widget_dict["data"]["results"]
                    widgets_clean.append(widget_dict)
                update_dict["widgets"] = widgets_clean

            # Atualizar timestamp e version
            update_dict["updated_at"] = datetime.utcnow()

            stmt = (
                update(DashboardDB)
                .where(DashboardDB.id == dashboard_id)
                .values(**update_dict)
                .returning(DashboardDB)
            )

            result = await db.execute(stmt)
            await db.flush()
            db_dashboard = result.scalar_one_or_none()

            if db_dashboard:
                logger.info(f"✅ Dashboard updated in SQL: {dashboard_id}")
                return self._to_pydantic(db_dashboard)
            return None

        except Exception as e:
            logger.error(f"❌ Error updating dashboard {dashboard_id}: {e}")
            raise

    async def delete_dashboard(self, db: AsyncSession, dashboard_id: str) -> bool:
        """Deleta dashboard"""
        try:
            stmt = delete(DashboardDB).where(DashboardDB.id == dashboard_id)
            result = await db.execute(stmt)
            await db.flush()

            if result.rowcount > 0:
                logger.info(f"✅ Dashboard deleted from SQL: {dashboard_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"❌ Error deleting dashboard {dashboard_id}: {e}")
            return False

    async def list(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 10,
        index: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[DashboardListItem]:
        """Lista dashboards com filtros"""
        try:
            stmt = select(DashboardDB)

            # Aplicar filtros
            if index:
                stmt = stmt.where(DashboardDB.index == index)
            if tags:
                # PostgreSQL: tags @> ARRAY['tag1', 'tag2']
                stmt = stmt.where(DashboardDB.tags.contains(tags))

            # Ordenar por updated_at desc
            stmt = stmt.order_by(DashboardDB.updated_at.desc())

            # Paginação
            stmt = stmt.offset(skip).limit(limit)

            result = await db.execute(stmt)
            db_dashboards = result.scalars().all()

            # Converter para DashboardListItem
            dashboards = []
            for db_dash in db_dashboards:
                dashboards.append(
                    DashboardListItem(
                        id=db_dash.id,
                        title=db_dash.title,
                        description=db_dash.description,
                        index=db_dash.index,
                        widget_count=len(db_dash.widgets),
                        created_at=db_dash.created_at,
                        updated_at=db_dash.updated_at,
                        tags=db_dash.tags,
                    )
                )

            logger.info(f"✅ Listed {len(dashboards)} dashboards from SQL")
            return dashboards

        except Exception as e:
            logger.error(f"❌ Error listing dashboards: {e}")
            return []

    def _to_pydantic(self, db_dashboard: DashboardDB) -> Dashboard:
        """Converte SQLAlchemy model para Pydantic model"""
        from app.models.dashboard import DashboardLayout, DashboardMetadata
        from app.models.widget import Widget

        return Dashboard(
            id=db_dashboard.id,
            title=db_dashboard.title,
            description=db_dashboard.description,
            index=db_dashboard.index,
            server_id=db_dashboard.server_id,
            layout=DashboardLayout(**db_dashboard.layout),
            widgets=[Widget(**w) for w in db_dashboard.widgets],
            metadata=DashboardMetadata(
                created_at=db_dashboard.created_at,
                updated_at=db_dashboard.updated_at,
                created_by=db_dashboard.created_by,
                is_public=db_dashboard.is_public,
                tags=db_dashboard.tags,
                version=int(db_dashboard.version.split(".")[0]) if db_dashboard.version else 1,
            ),
        )


# Singleton instance
_dashboard_service_sql: Optional[DashboardServiceSQL] = None


def get_dashboard_service_sql() -> DashboardServiceSQL:
    """Retorna instância do service"""
    global _dashboard_service_sql
    if _dashboard_service_sql is None:
        _dashboard_service_sql = DashboardServiceSQL()
    return _dashboard_service_sql
