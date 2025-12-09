"""
Dashboard Service
CRUD operations for dashboards in Elasticsearch
"""

from typing import List, Optional
from datetime import datetime
import logging

from app.db.elasticsearch import get_es_client
from app.models.dashboard import Dashboard, DashboardListItem
from app.schemas.dashboard import DashboardCreate, DashboardUpdate

logger = logging.getLogger(__name__)


class DashboardService:
    """Service para operações de Dashboard"""

    INDEX_NAME = "dashboards"

    async def create(self, dashboard_data: DashboardCreate, dashboard_id: Optional[str] = None) -> Dashboard:
        """Cria um novo dashboard"""
        es = await get_es_client()

        # Criar dashboard object
        dashboard = Dashboard(
            id=dashboard_id or Dashboard.model_fields["id"].default_factory(),  # Permite ID customizado
            title=dashboard_data.title,
            description=dashboard_data.description,
            index=dashboard_data.index,
            layout=dashboard_data.layout or Dashboard.model_fields["layout"].default_factory(),
            widgets=dashboard_data.widgets or [],
            metadata=Dashboard.model_fields["metadata"].default_factory()
        )

        if dashboard_data.tags:
            dashboard.metadata.tags = dashboard_data.tags

        # Preparar para salvamento (remover results dos widgets)
        dashboard_dict = dashboard.model_dump(mode='json')
        if 'widgets' in dashboard_dict:
            for widget in dashboard_dict['widgets']:
                if 'data' in widget and 'results' in widget['data']:
                    # Remover results - não persistir cache
                    del widget['data']['results']

        # Salvar no ES
        try:
            await es.index(
                index=self.INDEX_NAME,
                id=dashboard.id,
                document=dashboard_dict,
                refresh=True,
            )

            logger.info(f"✅ Dashboard created: {dashboard.id}")
            return dashboard

        except Exception as e:
            logger.error(f"❌ Error creating dashboard: {e}")
            raise

    async def get(self, dashboard_id: str) -> Optional[Dashboard]:
        """Busca dashboard por ID"""
        es = await get_es_client()

        try:
            result = await es.get(index=self.INDEX_NAME, id=dashboard_id)
            dashboard_dict = result["_source"]
            return Dashboard(**dashboard_dict)

        except Exception as e:
            logger.error(f"❌ Error getting dashboard {dashboard_id}: {e}")
            return None

    async def update(self, dashboard_id: str, updates: DashboardUpdate) -> Optional[Dashboard]:
        """Atualiza dashboard"""
        es = await get_es_client()

        try:
            # Buscar dashboard atual
            current = await self.get(dashboard_id)

            # Se não existe, criar automaticamente
            if not current:
                logger.info(f"Dashboard {dashboard_id} not found, creating automatically...")
                dashboard_data = DashboardCreate(
                    title="Meu Dashboard",
                    description="Dashboard criado automaticamente",
                    index="vazamentos",
                    widgets=updates.widgets or []
                )
                return await self.create(dashboard_data, dashboard_id=dashboard_id)

            # Atualizar campos
            update_dict = updates.model_dump(exclude_unset=True)

            if "widgets" in update_dict:
                current.widgets = update_dict["widgets"]
            if "title" in update_dict:
                current.title = update_dict["title"]
            if "description" in update_dict:
                current.description = update_dict["description"]
            if "layout" in update_dict:
                current.layout = update_dict["layout"]
            if "tags" in update_dict:
                current.metadata.tags = update_dict["tags"]

            # Atualizar timestamp
            current.metadata.updated_at = datetime.now()
            current.metadata.version += 1

            # Preparar para salvamento (remover results dos widgets)
            dashboard_dict = current.model_dump(mode='json')
            if 'widgets' in dashboard_dict:
                for widget in dashboard_dict['widgets']:
                    if 'data' in widget and 'results' in widget['data']:
                        # Remover results - não persistir cache
                        del widget['data']['results']

            # Salvar no ES
            await es.index(
                index=self.INDEX_NAME,
                id=dashboard_id,
                document=dashboard_dict,
                refresh=True,
            )

            logger.info(f"✅ Dashboard updated: {dashboard_id} (v{current.metadata.version})")
            return current

        except Exception as e:
            logger.error(f"❌ Error updating dashboard {dashboard_id}: {e}")
            raise

    async def delete(self, dashboard_id: str) -> bool:
        """Deleta dashboard"""
        es = await get_es_client()

        try:
            await es.delete(index=self.INDEX_NAME, id=dashboard_id, refresh=True)
            logger.info(f"✅ Dashboard deleted: {dashboard_id}")
            return True

        except Exception as e:
            logger.error(f"❌ Error deleting dashboard {dashboard_id}: {e}")
            return False

    async def list(
        self,
        skip: int = 0,
        limit: int = 10,
        index: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[DashboardListItem]:
        """Lista dashboards com filtros"""
        es = await get_es_client()

        # Construir query
        query = {"bool": {"must": []}}

        if index:
            query["bool"]["must"].append({"term": {"index": index}})

        if tags:
            query["bool"]["must"].append({"terms": {"metadata.tags": tags}})

        if not query["bool"]["must"]:
            query = {"match_all": {}}

        try:
            result = await es.search(
                index=self.INDEX_NAME,
                query=query,
                from_=skip,
                size=limit,
                sort=[{"metadata.updated_at": {"order": "desc"}}],
            )

            dashboards = []
            for hit in result["hits"]["hits"]:
                data = hit["_source"]
                dashboards.append(
                    DashboardListItem(
                        id=data["id"],
                        title=data["title"],
                        description=data.get("description"),
                        index=data["index"],
                        widget_count=len(data.get("widgets", [])),
                        created_at=data["metadata"]["created_at"],
                        updated_at=data["metadata"]["updated_at"],
                        tags=data["metadata"].get("tags", []),
                    )
                )

            logger.info(f"✅ Listed {len(dashboards)} dashboards")
            return dashboards

        except Exception as e:
            logger.error(f"❌ Error listing dashboards: {e}")
            return []


# Singleton instance
_dashboard_service: Optional[DashboardService] = None


def get_dashboard_service() -> DashboardService:
    """Retorna instância do service"""
    global _dashboard_service
    if _dashboard_service is None:
        _dashboard_service = DashboardService()
    return _dashboard_service
