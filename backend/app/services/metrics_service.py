"""
Metrics Service
Coleta e gerencia métricas do sistema
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

from app.models.system_metric import SystemMetric

logger = logging.getLogger(__name__)


class MetricsService:
    """Service para coletar e consultar métricas do sistema"""

    @staticmethod
    async def record_metric(
        db: AsyncSession,
        metric_type: str,
        metric_name: str,
        value: float,
        unit: Optional[str] = None,
        labels: Optional[Dict[str, Any]] = None
    ) -> SystemMetric:
        """
        Registra uma métrica no banco

        Args:
            db: Database session
            metric_type: Tipo da métrica (usage, performance, error, cache, resource)
            metric_name: Nome da métrica
            value: Valor da métrica
            unit: Unidade da métrica (opcional)
            labels: Labels adicionais (opcional)

        Returns:
            SystemMetric criado
        """
        try:
            metric = SystemMetric(
                metric_type=metric_type,
                metric_name=metric_name,
                value=value,
                unit=unit,
                labels=labels or {},
                timestamp=datetime.utcnow()
            )

            db.add(metric)
            await db.commit()
            await db.refresh(metric)

            logger.debug(f"📊 Metric recorded: {metric_type}.{metric_name} = {value}{unit or ''}")
            return metric

        except Exception as e:
            logger.error(f"❌ Error recording metric: {e}")
            await db.rollback()
            raise

    @staticmethod
    async def get_metrics_summary(
        db: AsyncSession,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Retorna resumo das métricas das últimas N horas

        Args:
            db: Database session
            hours: Número de horas para buscar (padrão: 24h)

        Returns:
            Dicionário com resumo das métricas
        """
        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Total de requests (usage.request_count)
            stmt = select(func.sum(SystemMetric.value)).where(
                and_(
                    SystemMetric.metric_type == 'usage',
                    SystemMetric.metric_name == 'request_count',
                    SystemMetric.timestamp >= since
                )
            )
            result = await db.execute(stmt)
            total_requests = result.scalar() or 0

            # Tempo médio de resposta (performance.response_time)
            stmt = select(func.avg(SystemMetric.value)).where(
                and_(
                    SystemMetric.metric_type == 'performance',
                    SystemMetric.metric_name == 'response_time',
                    SystemMetric.timestamp >= since
                )
            )
            result = await db.execute(stmt)
            avg_response_time = result.scalar() or 0

            # Total de erros (error.error_count)
            stmt = select(func.sum(SystemMetric.value)).where(
                and_(
                    SystemMetric.metric_type == 'error',
                    SystemMetric.metric_name == 'error_count',
                    SystemMetric.timestamp >= since
                )
            )
            result = await db.execute(stmt)
            total_errors = result.scalar() or 0

            # Cache hit rate médio (cache.hit_rate)
            stmt = select(func.avg(SystemMetric.value)).where(
                and_(
                    SystemMetric.metric_type == 'cache',
                    SystemMetric.metric_name == 'hit_rate',
                    SystemMetric.timestamp >= since
                )
            )
            result = await db.execute(stmt)
            avg_cache_hit_rate = result.scalar() or 0

            # Usuários ativos (contar user_id únicos nos últimos 15 minutos)
            # Buscar métricas recentes (últimos 15 min) que tenham user_id nos labels
            recent_time = datetime.utcnow() - timedelta(minutes=15)
            stmt = select(SystemMetric.labels).where(
                and_(
                    SystemMetric.metric_type == 'usage',
                    SystemMetric.metric_name == 'request_count',
                    SystemMetric.timestamp >= recent_time,
                    SystemMetric.labels.has_key('user_id')  # Apenas métricas com user_id
                )
            )
            result = await db.execute(stmt)
            labels_list = result.scalars().all()

            # Contar user_ids únicos
            unique_users = set()
            for labels in labels_list:
                if labels and 'user_id' in labels:
                    unique_users.add(labels['user_id'])

            active_users = len(unique_users)

            return {
                "period_hours": hours,
                "total_requests": int(total_requests),
                "avg_response_time_ms": round(avg_response_time, 2),
                "total_errors": int(total_errors),
                "error_rate_percent": round((total_errors / total_requests * 100) if total_requests > 0 else 0, 2),
                "avg_cache_hit_rate_percent": round(avg_cache_hit_rate, 2),
                "active_users": int(active_users),
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"❌ Error getting metrics summary: {e}")
            raise

    @staticmethod
    async def get_time_series(
        db: AsyncSession,
        metric_type: str,
        metric_name: str,
        hours: int = 24,
        interval_minutes: int = 60
    ) -> List[Dict[str, Any]]:
        """
        Retorna série temporal de uma métrica específica

        Args:
            db: Database session
            metric_type: Tipo da métrica
            metric_name: Nome da métrica
            hours: Número de horas para buscar
            interval_minutes: Intervalo de agregação em minutos

        Returns:
            Lista com dados da série temporal
        """
        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Query com agregação por intervalo
            stmt = select(
                func.date_trunc('hour', SystemMetric.timestamp).label('time_bucket'),
                func.avg(SystemMetric.value).label('avg_value'),
                func.min(SystemMetric.value).label('min_value'),
                func.max(SystemMetric.value).label('max_value'),
                func.count(SystemMetric.id).label('count')
            ).where(
                and_(
                    SystemMetric.metric_type == metric_type,
                    SystemMetric.metric_name == metric_name,
                    SystemMetric.timestamp >= since
                )
            ).group_by('time_bucket').order_by('time_bucket')

            result = await db.execute(stmt)
            rows = result.all()

            return [
                {
                    "timestamp": row.time_bucket.isoformat(),
                    "avg_value": round(float(row.avg_value), 2),
                    "min_value": round(float(row.min_value), 2),
                    "max_value": round(float(row.max_value), 2),
                    "count": row.count
                }
                for row in rows
            ]

        except Exception as e:
            logger.error(f"❌ Error getting time series: {e}")
            raise

    @staticmethod
    async def get_top_endpoints(
        db: AsyncSession,
        hours: int = 24,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Retorna endpoints mais acessados

        Args:
            db: Database session
            hours: Número de horas para buscar
            limit: Número máximo de resultados

        Returns:
            Lista com endpoints e contagens
        """
        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Query para buscar métricas com label 'endpoint'
            stmt = select(SystemMetric).where(
                and_(
                    SystemMetric.metric_type == 'usage',
                    SystemMetric.metric_name == 'request_count',
                    SystemMetric.timestamp >= since,
                    SystemMetric.labels.isnot(None)
                )
            )

            result = await db.execute(stmt)
            metrics = result.scalars().all()

            # Agregar por endpoint
            endpoint_counts: Dict[str, float] = {}
            for metric in metrics:
                if metric.labels and 'endpoint' in metric.labels:
                    endpoint = metric.labels['endpoint']
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + metric.value

            # Ordenar e limitar
            sorted_endpoints = sorted(
                endpoint_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]

            return [
                {"endpoint": endpoint, "requests": int(count)}
                for endpoint, count in sorted_endpoints
            ]

        except Exception as e:
            logger.error(f"❌ Error getting top endpoints: {e}")
            raise

    @staticmethod
    async def cleanup_old_metrics(
        db: AsyncSession,
        days: int = 30
    ) -> int:
        """
        Remove métricas antigas do banco

        Args:
            db: Database session
            days: Número de dias para manter (padrão: 30 dias)

        Returns:
            Número de registros deletados
        """
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            stmt = select(SystemMetric).where(SystemMetric.timestamp < cutoff)
            result = await db.execute(stmt)
            old_metrics = result.scalars().all()

            count = len(old_metrics)

            for metric in old_metrics:
                await db.delete(metric)

            await db.commit()

            logger.info(f"🧹 Cleaned up {count} old metrics (older than {days} days)")
            return count

        except Exception as e:
            logger.error(f"❌ Error cleaning up metrics: {e}")
            await db.rollback()
            raise


# Singleton instance
_metrics_service: Optional[MetricsService] = None


def get_metrics_service() -> MetricsService:
    """
    Get or create MetricsService singleton

    Returns:
        MetricsService instance
    """
    global _metrics_service
    if _metrics_service is None:
        _metrics_service = MetricsService()
    return _metrics_service
