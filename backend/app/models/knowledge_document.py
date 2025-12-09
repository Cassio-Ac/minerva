"""
Knowledge Document Model
Documentos de conhecimento para enriquecer contexto da LLM
"""

from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.sql import func
from app.db.database import Base


class KnowledgeDocument(Base):
    """
    Documento de Conhecimento

    Armazena documentação, guias e conhecimento geral que pode
    ajudar a LLM a entender melhor o domínio de negócio e dados.
    """
    __tablename__ = "knowledge_documents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=False)  # Markdown supported

    # Categorização
    category = Column(String, nullable=True, index=True)  # e.g., "troubleshooting", "business-rules"
    tags = Column(ARRAY(String), nullable=True)  # ["logs", "performance", "errors"]
    related_indices = Column(ARRAY(String), nullable=True)  # ["logs-app-*", "metrics-*"]

    # Prioridade (0-10, maior = mais importante)
    priority = Column(Integer, default=0, nullable=False)

    # Metadata
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def to_dict(self):
        """Serializa para dicionário"""
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "tags": self.tags or [],
            "related_indices": self.related_indices or [],
            "priority": self.priority,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

    def get_llm_context(self, max_length: int = 1000) -> str:
        """
        Retorna contexto formatado para LLM

        Args:
            max_length: Tamanho máximo do conteúdo (trunca se necessário)
        """
        context_parts = [f"# {self.title}"]

        if self.category:
            context_parts.append(f"Category: {self.category}")

        if self.tags:
            context_parts.append(f"Tags: {', '.join(self.tags)}")

        if self.related_indices:
            context_parts.append(f"Related Indices: {', '.join(self.related_indices)}")

        # Conteúdo (pode ser truncado)
        content = self.content
        if len(content) > max_length:
            content = content[:max_length] + "... [truncated]"

        context_parts.append("")  # Linha em branco
        context_parts.append(content)

        return "\n".join(context_parts)

    def get_excerpt(self, length: int = 200) -> str:
        """
        Retorna um trecho do conteúdo

        Args:
            length: Tamanho máximo do trecho
        """
        if len(self.content) <= length:
            return self.content

        # Tenta cortar em uma quebra de linha
        excerpt = self.content[:length]
        last_newline = excerpt.rfind('\n')

        if last_newline > length // 2:  # Se tiver quebra na segunda metade
            excerpt = excerpt[:last_newline]

        return excerpt.rstrip() + "..."

    def matches_indices(self, index_patterns: list[str]) -> bool:
        """
        Verifica se o documento está relacionado a algum dos índices

        Args:
            index_patterns: Lista de padrões de índice (e.g., ["logs-app-*"])

        Returns:
            True se houver match
        """
        if not self.related_indices:
            return False

        for doc_pattern in self.related_indices:
            for search_pattern in index_patterns:
                # Match exato
                if doc_pattern == search_pattern:
                    return True

                # Match com wildcard
                if doc_pattern.endswith('*'):
                    prefix = doc_pattern[:-1]
                    if search_pattern.startswith(prefix):
                        return True

                if search_pattern.endswith('*'):
                    prefix = search_pattern[:-1]
                    if doc_pattern.startswith(prefix):
                        return True

        return False
