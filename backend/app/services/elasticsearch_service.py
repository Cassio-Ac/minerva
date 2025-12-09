"""
Elasticsearch Query Service
Executa queries e processa resultados para visualizações
"""

from typing import Dict, Any, List, Optional
import logging
import hashlib
import json
from app.db.elasticsearch import get_es_client
from app.services.es_client_factory import ESClientFactory
from app.services.cache_service import get_cache_service

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """Service para executar queries Elasticsearch"""

    async def execute_query(
        self,
        index: str,
        query: Dict[str, Any],
        server_id: Optional[str] = None,
        use_cache: bool = True,
        cache_ttl: int = 300
    ) -> Dict[str, Any]:
        """
        Executa query no Elasticsearch e retorna resultados processados

        Args:
            index: Nome do índice
            query: Query Elasticsearch
            server_id: ID do servidor ES (opcional, usa padrão se None)
            use_cache: Se deve usar cache Redis (padrão: True)
            cache_ttl: Tempo de vida do cache em segundos (padrão: 5 minutos)

        Returns:
            Dicionário com resultados processados
        """
        try:
            # Generate cache key
            cache_key = None
            cache_service = get_cache_service()

            if use_cache and cache_service.enabled:
                cache_params = {
                    "index": index,
                    "query": query,
                    "server_id": server_id or "default"
                }
                query_hash = hashlib.md5(
                    json.dumps(cache_params, sort_keys=True).encode()
                ).hexdigest()[:12]
                cache_key = f"es:query:{index}:{query_hash}"

                # Try to get from cache
                cached_result = await cache_service.get(cache_key)
                if cached_result:
                    logger.info(f"🎯 Cache HIT for query on index {index}")
                    return cached_result

            # Cache miss or cache disabled: execute query
            logger.info(
                f"🔍 Executing ES query on index: {index} "
                f"(server: {server_id or 'default'}, cache: {use_cache})"
            )

            # Usar factory para obter cliente correto
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            logger.info(f"📝 Query: {json.dumps(query, indent=2)}")

            # Executar query
            response = await es.search(
                index=index,
                body=query
            )

            logger.info(f"✅ Query executed successfully. Hits: {response['hits']['total']['value']}")

            # Debug: log aggregations if present
            if "aggregations" in response:
                logger.debug(f"Aggregations found: {list(response['aggregations'].keys())}")

            # Processar resultados
            processed_results = self._process_results(response, query)

            # Cache the result
            if use_cache and cache_key and cache_service.enabled:
                await cache_service.set(cache_key, processed_results, cache_ttl)
                logger.info(f"💾 Cached query result for {cache_ttl}s (key: {cache_key})")

            return processed_results

        except Exception as e:
            logger.error(f"❌ Error executing ES query: {e}")
            raise

    def _process_results(
        self,
        response: Dict[str, Any],
        query: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Processa resultados do ES para formato de visualização

        Args:
            response: Resposta do Elasticsearch
            query: Query original

        Returns:
            Dados processados para visualização
        """
        results = {
            "total": response["hits"]["total"]["value"],
            "took": response["took"],
            "data": []
        }

        # Se tem agregações, processar
        if "aggregations" in response or "aggs" in response:
            aggs = response.get("aggregations") or response.get("aggs")
            logger.info(f"🔍 Raw aggregations: {aggs}")
            results["data"] = self._process_aggregations(aggs)
            logger.info(f"📊 Processed data: {results['data']}")

        # Se não tem agregações, retornar documentos
        else:
            results["data"] = self._process_hits(response["hits"]["hits"])

        return results

    def _process_aggregations(self, aggs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Processa agregações do ES

        Args:
            aggs: Agregações do Elasticsearch

        Returns:
            Lista de dados formatados para visualização
        """
        data = []

        # Procurar pela agregação "result" (padrão que usamos)
        if "result" in aggs:
            result_agg = aggs["result"]

            # Terms aggregation (para pie/bar charts)
            if "buckets" in result_agg:
                for bucket in result_agg["buckets"]:
                    data.append({
                        "label": str(bucket.get("key", "")),
                        "value": bucket.get("doc_count", 0)
                    })

            # Cardinality aggregation (para metrics)
            elif "value" in result_agg:
                data.append({
                    "label": "Total",
                    "value": int(result_agg["value"])
                })

            # Date histogram (para line charts)
            elif "buckets" in result_agg:
                for bucket in result_agg["buckets"]:
                    data.append({
                        "label": bucket.get("key_as_string", bucket.get("key", "")),
                        "value": bucket.get("doc_count", 0)
                    })

        # Se não encontrou "result", tentar processar a primeira agregação
        elif len(aggs) > 0:
            first_key = list(aggs.keys())[0]
            first_agg = aggs[first_key]

            if "buckets" in first_agg:
                for bucket in first_agg["buckets"]:
                    data.append({
                        "label": str(bucket.get("key", "")),
                        "value": bucket.get("doc_count", 0)
                    })
            elif "value" in first_agg:
                data.append({
                    "label": "Total",
                    "value": int(first_agg["value"])
                })

        return data

    def _process_hits(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processa documentos retornados

        Args:
            hits: Lista de hits do ES

        Returns:
            Lista de documentos processados
        """
        data = []
        for hit in hits:
            source = hit.get("_source", {})
            # Para tabelas, incluir todos os campos do documento
            row = {"_id": hit.get("_id")}
            row.update(source)
            data.append(row)
        return data

    async def get_index_mapping(
        self, index: str, server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Obtém o mapping de um índice

        Args:
            index: Nome do índice
            server_id: ID do servidor ES (opcional)

        Returns:
            Mapping do índice
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)
            mapping = await es.indices.get_mapping(index=index)
            return mapping

        except Exception as e:
            logger.error(f"❌ Error getting mapping for index {index}: {e}")
            raise

    async def get_fields(
        self, index: str, server_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Extrai campos de um índice com tipos e propriedades

        Args:
            index: Nome do índice
            server_id: ID do servidor ES (opcional)

        Returns:
            Lista de campos com nome, tipo e propriedades
        """
        try:
            mapping = await self.get_index_mapping(index, server_id)

            # Extrair campos do mapping
            fields = []

            # Mapping está no formato: {index_name: {mappings: {properties: {...}}}}
            for idx_name, idx_data in mapping.items():
                properties = idx_data.get("mappings", {}).get("properties", {})
                fields.extend(self._extract_fields_from_properties(properties))

            logger.info(f"✅ Extracted {len(fields)} fields from index {index}")
            return fields

        except Exception as e:
            logger.error(f"❌ Error getting fields for index {index}: {e}")
            raise

    def _extract_fields_from_properties(
        self, properties: Dict[str, Any], prefix: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Extrai campos recursivamente do mapping properties

        Args:
            properties: Dict de properties do mapping
            prefix: Prefixo para campos aninhados

        Returns:
            Lista de campos extraídos
        """
        fields = []

        for field_name, field_props in properties.items():
            full_name = f"{prefix}{field_name}" if prefix else field_name
            field_type = field_props.get("type", "object")

            # Campo com tipo definido
            if field_type != "object":
                fields.append({
                    "name": full_name,
                    "type": field_type,
                    "aggregatable": field_props.get("aggregatable", True),
                    "searchable": field_props.get("searchable", True),
                })

            # Se tem sub-properties (nested ou object), processar recursivamente
            if "properties" in field_props:
                nested_fields = self._extract_fields_from_properties(
                    field_props["properties"],
                    prefix=f"{full_name}."
                )
                fields.extend(nested_fields)

            # Se tem fields (multi-fields)
            if "fields" in field_props:
                for sub_field_name, sub_field_props in field_props["fields"].items():
                    fields.append({
                        "name": f"{full_name}.{sub_field_name}",
                        "type": sub_field_props.get("type", "unknown"),
                        "aggregatable": sub_field_props.get("aggregatable", True),
                        "searchable": sub_field_props.get("searchable", True),
                    })

        return fields

    async def list_indices(
        self, pattern: str = "*", server_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lista índices Elasticsearch que correspondem ao padrão

        Args:
            pattern: Padrão de índices (ex: 'log-*', default: '*')
            server_id: ID do servidor ES (opcional)

        Returns:
            Lista de dicionários com informações dos índices
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Obter informações dos índices via cat API
            # Formato: index,docs.count,store.size
            indices_response = await es.cat.indices(
                index=pattern,
                format="json",
                h="index,docs.count,store.size",
                s="index:asc"
            )

            # Filtrar índices do sistema (começam com .)
            indices = [
                {
                    "name": idx["index"],
                    "docs_count": int(idx.get("docs.count", 0) or 0),
                    "size": idx.get("store.size", "0b")
                }
                for idx in indices_response
                if not idx["index"].startswith(".")
            ]

            logger.info(f"✅ Found {len(indices)} indices matching pattern '{pattern}'")
            return indices

        except Exception as e:
            logger.error(f"❌ Error listing indices with pattern '{pattern}': {e}")
            raise

    async def get_index_mapping(
        self, index: str, server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Obtém o mapping completo de um índice

        Args:
            index: Nome do índice
            server_id: ID do servidor ES (opcional)

        Returns:
            Mapping do índice
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            mapping = await es.indices.get_mapping(index=index)

            logger.info(f"✅ Got mapping for index {index}")
            return mapping

        except Exception as e:
            logger.error(f"❌ Error getting mapping for index {index}: {e}")
            raise

    async def cluster_health(
        self, server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Obtém informações de saúde do cluster Elasticsearch

        Args:
            server_id: ID do servidor ES (opcional)

        Returns:
            Informações de saúde do cluster
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            health = await es.cluster.health()

            logger.info(f"✅ Cluster health: {health['status']}")
            return health

        except Exception as e:
            logger.error(f"❌ Error getting cluster health: {e}")
            raise

    async def test_connection(
        self, index: str, server_id: Optional[str] = None
    ) -> bool:
        """
        Testa se consegue conectar e acessar o índice

        Args:
            index: Nome do índice
            server_id: ID do servidor ES (opcional)

        Returns:
            True se conectou com sucesso
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)
            exists = await es.indices.exists(index=index)

            if exists:
                logger.info(f"✅ Index {index} exists and is accessible")
                return True
            else:
                logger.warning(f"⚠️ Index {index} does not exist")
                return False

        except Exception as e:
            logger.error(f"❌ Error testing connection to index {index}: {e}")
            return False


# Singleton instance
_es_service: Optional[ElasticsearchService] = None


def get_es_service() -> ElasticsearchService:
    """Retorna instância do service"""
    global _es_service
    if _es_service is None:
        _es_service = ElasticsearchService()
    return _es_service
