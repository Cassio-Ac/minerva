"""
Telegram Account Model
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.db.database import Base


class TelegramAccount(Base):
    """Telegram Account model for storing Telegram API credentials"""

    __tablename__ = "telegram_accounts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, unique=True, index=True)  # Nome amigável (ex: "Paloma")
    api_id_encrypted = Column(String, nullable=False)  # API ID criptografado
    api_hash_encrypted = Column(String, nullable=False)  # API Hash criptografado
    phone_encrypted = Column(String, nullable=False)  # Telefone criptografado
    session_name = Column(String, nullable=False, unique=True)  # Nome do arquivo de sessão (ex: "session_paloma")
    is_active = Column(Boolean, default=True, nullable=False)  # Se a conta está ativa

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<TelegramAccount {self.name}>"
