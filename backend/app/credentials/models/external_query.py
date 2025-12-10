"""
External Query Model - Armazena histórico de consultas externas

Cada consulta a bots de leak é registrada para auditoria e cache.
"""

from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.db.database import Base


class ExternalQuery(Base):
    """Modelo para armazenar consultas externas a bots de leak"""

    __tablename__ = "external_queries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Informações da consulta
    query_type = Column(String(50), nullable=False)  # email, cpf, phone, domain, etc.
    query_value = Column(String(500), nullable=False)  # valor consultado

    # Bot utilizado
    bot_id = Column(String(50), nullable=False)  # ID do bot Telegram
    bot_name = Column(String(100), nullable=True)  # Nome do bot

    # Resultado
    found = Column(Boolean, default=False)
    result_count = Column(Integer, default=0)
    result_preview = Column(Text, nullable=True)  # Preview do resultado (texto)
    result_html_path = Column(String(500), nullable=True)  # Caminho do HTML baixado
    result_file_path = Column(String(500), nullable=True)  # Caminho de arquivo adicional
    raw_response = Column(JSON, nullable=True)  # Resposta bruta do bot

    # Metadados
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100), nullable=True)  # Usuário que fez a consulta
    telegram_account = Column(String(100), nullable=True)  # Conta Telegram usada

    # Status
    status = Column(String(20), default="pending")  # pending, processing, completed, error
    error_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ExternalQuery {self.query_type}:{self.query_value[:20]}...>"
