"""
SystemMetric Model
Armazena métricas do sistema para monitoramento
"""

from sqlalchemy import Column, String, Float, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid

from app.db.database import Base


class SystemMetric(Base):
    """
    Modelo para métricas do sistema

    Tipos de métricas:
    - usage: métricas de uso (requests, active_users, etc)
    - performance: métricas de performance (response_time, query_time, etc)
    - error: métricas de erro (error_count, error_rate, etc)
    - cache: métricas de cache (hit_rate, miss_rate, etc)
    - resource: métricas de recursos (memory_usage, cpu_usage, etc)
    """

    __tablename__ = "system_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tipo e nome da métrica
    metric_type = Column(String(50), nullable=False, index=True)  # usage, performance, error, cache, resource
    metric_name = Column(String(100), nullable=False, index=True)  # request_count, response_time, etc

    # Valor e unidade
    value = Column(Float, nullable=False)
    unit = Column(String(20), nullable=True)  # ms, bytes, count, percent, etc

    # Labels adicionais (ex: {endpoint: "/api/chat", method: "POST"})
    labels = Column(JSONB, nullable=True)

    # Timestamp da métrica
    timestamp = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)

    # Metadados
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    # Índice composto para queries eficientes
    __table_args__ = (
        Index('idx_system_metrics_type_name_timestamp', 'metric_type', 'metric_name', 'timestamp'),
    )

    def __repr__(self):
        return f"<SystemMetric {self.metric_type}.{self.metric_name}={self.value}{self.unit or ''}>"
