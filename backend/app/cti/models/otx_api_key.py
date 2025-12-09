"""
OTX API Key Model

Model para gerenciar múltiplas chaves OTX com rotação automática
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from app.db.database import Base
from datetime import datetime
import uuid


class OTXAPIKey(Base):
    """
    Model para armazenar chaves de API do AlienVault OTX

    Features:
    - Múltiplas chaves para rotação
    - Rate limit tracking
    - Auto-rotação quando limite é atingido
    - Desabilitar chaves manualmente
    """
    __tablename__ = "otx_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Key info
    name = Column(String(200), nullable=False)  # "Production Key 1", "Backup Key", etc
    api_key = Column(String(500), nullable=False, unique=True)  # Chave OTX
    description = Column(Text)  # Notas sobre a chave

    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_primary = Column(Boolean, default=False, nullable=False)  # Chave primária preferencial

    # Rate limiting tracking
    requests_count = Column(Integer, default=0, nullable=False)  # Total de requests
    requests_today = Column(Integer, default=0, nullable=False)  # Requests hoje
    last_request_at = Column(DateTime)  # Última request
    last_error_at = Column(DateTime)  # Último erro
    error_count = Column(Integer, default=0, nullable=False)  # Contador de erros consecutivos

    # Rate limit info (OTX: ~10,000 requests/day)
    daily_limit = Column(Integer, default=9000, nullable=False)  # Limite conservador
    current_usage = Column(Integer, default=0, nullable=False)  # Uso atual

    # Health check
    last_health_check = Column(DateTime)
    health_status = Column(String(50), default="unknown")  # ok, rate_limited, error, unknown

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(UUID(as_uuid=True))  # User que criou

    def __repr__(self):
        return f"<OTXAPIKey(name='{self.name}', active={self.is_active}, usage={self.current_usage}/{self.daily_limit})>"

    def is_available(self) -> bool:
        """Verifica se a chave está disponível para uso"""
        if not self.is_active:
            return False

        # Se atingiu o limite diário
        if self.current_usage >= self.daily_limit:
            return False

        # Se teve muitos erros consecutivos (>5)
        if self.error_count > 5:
            return False

        return True

    def increment_usage(self):
        """Incrementa contadores de uso"""
        self.requests_count += 1
        self.requests_today += 1
        self.current_usage += 1
        self.last_request_at = datetime.utcnow()

    def record_error(self):
        """Registra erro"""
        self.error_count += 1
        self.last_error_at = datetime.utcnow()

    def reset_error_count(self):
        """Reseta contador de erros após sucesso"""
        self.error_count = 0

    def reset_daily_usage(self):
        """Reseta uso diário (rodar às 00:00 UTC)"""
        self.current_usage = 0
        self.requests_today = 0
