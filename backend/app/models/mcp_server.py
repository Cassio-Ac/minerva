"""
MCP Server Model
Armazena configurações de servidores Model Context Protocol
"""

from sqlalchemy import Column, String, Boolean, JSON, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base
import enum


class MCPType(str, enum.Enum):
    """Tipos de conexão MCP"""
    STDIO = "stdio"  # Processo local via stdin/stdout
    HTTP = "http"    # API REST via HTTP
    SSE = "sse"      # Server-Sent Events


class MCPServer(Base):
    """
    Modelo para servidores MCP (Model Context Protocol)

    Permite integração com ferramentas externas como:
    - filesystem: acesso a arquivos locais
    - github: integração com GitHub API
    - postgres: acesso a bancos de dados
    - slack: integração com Slack
    - etc.
    """
    __tablename__ = "mcp_servers"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True, index=True)
    type = Column(String, nullable=False)  # 'stdio', 'http', or 'sse'

    # Configuração STDIO (processo local)
    command = Column(String, nullable=True)  # e.g. "npx", "python", "node"
    args = Column(JSON, nullable=True)  # e.g. ["-m", "mcp_server_filesystem", "/path"]
    env = Column(JSON, nullable=True)  # Variáveis de ambiente

    # Configuração HTTP/SSE (servidor remoto)
    url = Column(String, nullable=True)  # e.g. "http://localhost:3000/mcp"

    # Metadata
    description = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    index_configs = relationship("IndexMCPConfig", back_populates="mcp_server", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<MCPServer {self.name} ({self.type})>"

    def to_dict(self):
        """Converte para dicionário"""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value if isinstance(self.type, enum.Enum) else self.type,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "url": self.url,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
