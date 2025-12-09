"""
Index Mapping Service
Gera base de conhecimento detalhada sobre índices Elasticsearch
"""

from typing import Dict, Any, List, Optional
import logging
from app.db.elasticsearch import get_es_client

logger = logging.getLogger(__name__)


class IndexMappingService:
    """Service para gerar base de conhecimento de índices ES"""

    async def generate_knowledge_base(self, index: str) -> str:
        """
        Gera base de conhecimento completa do índice para a LLM

        Args:
            index: Nome do índice

        Returns:
            String formatada com informações detalhadas do índice
        """
        try:
            es = await get_es_client()

            # 1. Verificar se índice existe
            exists = await es.indices.exists(index=index)
            if not exists:
                return f"⚠️ Índice '{index}' não existe"

            # 2. Buscar mapping
            mapping_response = await es.indices.get_mapping(index=index)
            mapping = mapping_response[index]["mappings"]
            properties = mapping.get("properties", {})

            # 3. Buscar exemplos de documentos
            sample_docs = await es.search(
                index=index,
                size=3,
                body={"query": {"match_all": {}}}
            )

            # 4. Buscar estatísticas do índice
            count_response = await es.count(index=index)
            total_docs = count_response["count"]

            # 5. Gerar relatório formatado
            knowledge = self._format_knowledge_base(
                index=index,
                properties=properties,
                sample_docs=sample_docs["hits"]["hits"],
                total_docs=total_docs
            )

            logger.info(f"✅ Generated knowledge base for index '{index}' ({len(knowledge)} chars)")
            return knowledge

        except Exception as e:
            logger.error(f"❌ Error generating knowledge base for '{index}': {e}")
            return f"Erro ao gerar base de conhecimento: {str(e)}"

    def _format_knowledge_base(
        self,
        index: str,
        properties: Dict[str, Any],
        sample_docs: List[Dict[str, Any]],
        total_docs: int
    ) -> str:
        """
        Formata a base de conhecimento em texto estruturado

        Args:
            index: Nome do índice
            properties: Properties do mapping
            sample_docs: Documentos de exemplo
            total_docs: Total de documentos

        Returns:
            Base de conhecimento formatada
        """
        lines = []

        # Header
        lines.append(f"📊 BASE DE CONHECIMENTO DO ÍNDICE: {index}")
        lines.append(f"Total de documentos: {total_docs:,}")
        lines.append("")

        # Campos disponíveis
        lines.append("📋 CAMPOS DISPONÍVEIS:")
        lines.append("")

        for field_name, field_props in sorted(properties.items()):
            field_type = field_props.get("type", "object")

            # Coletar valores de exemplo deste campo
            examples = self._get_field_examples(field_name, sample_docs)

            # Determinar se é agregável
            aggregatable = self._is_aggregatable(field_type, field_props)

            # Formatar linha do campo
            agg_marker = "✓ AGREGÁVEL" if aggregatable else "✗ NÃO AGREGÁVEL"
            lines.append(f"• **{field_name}**")
            lines.append(f"  - Tipo: {field_type}")
            lines.append(f"  - {agg_marker}")

            if examples:
                lines.append(f"  - Exemplos: {', '.join(examples[:3])}")

            # Detectar se o campo contém JSON
            contains_json = self._field_contains_json(field_name, sample_docs)

            # Instruções específicas por tipo
            if field_type == "text":
                if contains_json:
                    lines.append(f"  - 🔍 Este campo contém JSON como string. Para extrair valores:")
                    lines.append(f"    • Use Painless script com indexOf() e substring()")
                    lines.append(f"    • Veja seção PAINLESS SCRIPTING nas regras gerais")
                if "fields" in field_props and "keyword" in field_props["fields"]:
                    lines.append(f"  - 💡 Use '{field_name}.keyword' para agregações")
                else:
                    lines.append(f"  - ⚠️ Campo text sem .keyword - não use para agregações")
            elif field_type == "keyword":
                lines.append(f"  - 💡 Use '{field_name}' diretamente para agregações (já é keyword)")
            elif field_type == "date":
                lines.append(f"  - 💡 Use para date_histogram e filtros de range temporal")
            elif field_type in ["long", "integer", "short", "byte", "double", "float"]:
                lines.append(f"  - 💡 Use para range, stats, sum, avg, min, max")

            lines.append("")

        # Exemplos de documentos
        if sample_docs:
            lines.append("📄 EXEMPLOS DE DOCUMENTOS:")
            lines.append("")
            for i, hit in enumerate(sample_docs[:2], 1):
                source = hit["_source"]
                lines.append(f"Exemplo {i}:")
                lines.append(f"```json")
                import json
                lines.append(json.dumps(source, indent=2, ensure_ascii=False))
                lines.append(f"```")
                lines.append("")

        # Sugestões de análises
        lines.append("💡 SUGESTÕES DE ANÁLISES POSSÍVEIS:")
        lines.append("")

        # Identificar campos agregáveis
        keyword_fields = [k for k, v in properties.items()
                          if v.get("type") == "keyword" or
                          (v.get("type") == "text" and "keyword" in v.get("fields", {}))]
        numeric_fields = [k for k, v in properties.items()
                          if v.get("type") in ["long", "integer", "short", "double", "float"]]
        date_fields = [k for k, v in properties.items() if v.get("type") == "date"]

        if keyword_fields:
            lines.append(f"• Distribuições (pie/bar): {', '.join(keyword_fields[:3])}")
        if numeric_fields:
            lines.append(f"• Estatísticas (metric): {', '.join(numeric_fields[:3])}")
        if date_fields:
            lines.append(f"• Evolução temporal (line/area): {', '.join(date_fields[:3])}")

        return "\n".join(lines)

    def _get_field_examples(self, field_name: str, docs: List[Dict[str, Any]]) -> List[str]:
        """
        Extrai exemplos de valores de um campo dos documentos

        Args:
            field_name: Nome do campo
            docs: Lista de documentos

        Returns:
            Lista de valores de exemplo (como strings)
        """
        examples = []
        for doc in docs:
            source = doc.get("_source", {})
            if field_name in source:
                value = source[field_name]
                # Converter para string e limitar tamanho
                value_str = str(value)
                if len(value_str) > 50:
                    value_str = value_str[:47] + "..."
                if value_str not in examples:
                    examples.append(value_str)
        return examples[:5]  # Máximo 5 exemplos

    def _field_contains_json(self, field_name: str, docs: List[Dict[str, Any]]) -> bool:
        """
        Detecta se um campo contém dados JSON como string

        Args:
            field_name: Nome do campo
            docs: Lista de documentos

        Returns:
            True se o campo parece conter JSON
        """
        import json
        for doc in docs:
            source = doc.get("_source", {})
            if field_name in source:
                value = source[field_name]
                if isinstance(value, str):
                    # Tentar detectar se é JSON
                    value_stripped = value.strip()
                    if (value_stripped.startswith('{') and value_stripped.endswith('}')) or \
                       (value_stripped.startswith('[') and value_stripped.endswith(']')):
                        try:
                            json.loads(value_stripped)
                            return True
                        except:
                            pass
        return False

    def _is_aggregatable(self, field_type: str, field_props: Dict[str, Any]) -> bool:
        """
        Verifica se um campo pode ser usado em agregações

        Args:
            field_type: Tipo do campo
            field_props: Propriedades do campo

        Returns:
            True se for agregável
        """
        # Tipos naturalmente agregáveis
        aggregatable_types = [
            "keyword", "long", "integer", "short", "byte",
            "double", "float", "boolean", "date", "ip"
        ]

        if field_type in aggregatable_types:
            return True

        # Text com subfield keyword
        if field_type == "text" and "fields" in field_props:
            if "keyword" in field_props["fields"]:
                return True

        return False


# Singleton instance
_mapping_service: Optional[IndexMappingService] = None


def get_mapping_service() -> IndexMappingService:
    """Retorna instância do service"""
    global _mapping_service
    if _mapping_service is None:
        _mapping_service = IndexMappingService()
    return _mapping_service
