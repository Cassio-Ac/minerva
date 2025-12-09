"""
Download Model - Rastreamento de arquivos gerados
"""
from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.database import Base


class Download(Base):
    """
    Modelo para rastrear arquivos gerados e disponíveis para download
    """
    __tablename__ = "downloads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Informações do arquivo
    filename = Column(String, nullable=False, unique=True, index=True)
    original_name = Column(String, nullable=False)  # Nome amigável
    file_type = Column(String, nullable=False)  # html, pdf, png, etc
    file_size = Column(Integer, nullable=False)  # Tamanho em bytes
    file_path = Column(String, nullable=False)  # Caminho completo no servidor

    # Ownership
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    user = relationship("User", back_populates="downloads")

    # Metadados
    description = Column(String, nullable=True)  # Descrição opcional
    dashboard_id = Column(String, nullable=True)  # Se relacionado a um dashboard

    # Controle
    is_public = Column(Boolean, default=False)  # Se pode ser acessado sem autenticação
    download_count = Column(Integer, default=0)  # Contador de downloads

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # Data de expiração opcional

    def __repr__(self):
        return f"<Download(id={self.id}, filename={self.filename}, user_id={self.user_id})>"
