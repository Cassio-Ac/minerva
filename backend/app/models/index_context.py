"""
Index Context Model
Armazena contexto e descrições de índices Elasticsearch
"""

from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from app.db.database import Base


class IndexContext(Base):
    """
    Contexto de Índice Elasticsearch

    Armazena informações que ajudam a LLM a entender melhor
    um índice Elasticsearch específico.
    """
    __tablename__ = "index_contexts"

    id = Column(String, primary_key=True, index=True)
    es_server_id = Column(String, nullable=False, index=True)
    index_pattern = Column(String, nullable=False, index=True)  # e.g., "logs-app-*"

    # Descrições
    description = Column(Text, nullable=True)  # Descrição geral do índice
    business_context = Column(Text, nullable=True)  # Contexto de negócio
    tips = Column(Text, nullable=True)  # Dicas para analisar esse índice

    # Estruturados (JSON)
    field_descriptions = Column(JSONB, nullable=True)  # {"field_name": "description"}
    query_examples = Column(JSONB, nullable=True)  # [{"question": "...", "description": "..."}]

    # Metadata
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def to_dict(self):
        """Serializa para dicionário"""
        return {
            "id": self.id,
            "es_server_id": self.es_server_id,
            "index_pattern": self.index_pattern,
            "description": self.description,
            "business_context": self.business_context,
            "tips": self.tips,
            "field_descriptions": self.field_descriptions or {},
            "query_examples": self.query_examples or [],
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

    def get_llm_context(self) -> str:
        """
        Retorna contexto formatado para LLM
        """
        context_parts = []

        # Descrição principal
        if self.description:
            context_parts.append(f"Index: {self.index_pattern}")
            context_parts.append(f"Description: {self.description}")

        # Contexto de negócio
        if self.business_context:
            context_parts.append(f"Business Context: {self.business_context}")

        # Descrições de campos
        if self.field_descriptions:
            context_parts.append("Field Descriptions:")
            for field, desc in self.field_descriptions.items():
                context_parts.append(f"  - {field}: {desc}")

        # Exemplos de queries
        if self.query_examples:
            context_parts.append("Common Queries:")
            for example in self.query_examples:
                if isinstance(example, dict) and 'question' in example:
                    context_parts.append(f"  - {example['question']}")
                    if 'description' in example:
                        context_parts.append(f"    {example['description']}")

        # Dicas
        if self.tips:
            context_parts.append(f"Tips: {self.tips}")

        return "\n".join(context_parts)
