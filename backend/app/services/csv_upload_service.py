"""
CSV Upload Service
Gerencia o upload, validação e ingestão de arquivos CSV no Elasticsearch
"""
import csv
import io
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from elasticsearch import AsyncElasticsearch

from app.services.es_client_factory import ESClientFactory

logger = logging.getLogger(__name__)


class CSVUploadService:
    """Service para processar e fazer upload de arquivos CSV para o Elasticsearch"""

    def __init__(self):
        self.es_factory = ESClientFactory()

    async def process_and_upload_csv(
        self,
        file_content: bytes,
        index_name: str,
        es_server_id: str,
        user_id: str,
        force_create: bool = False
    ) -> Dict[str, Any]:
        """
        Processa um arquivo CSV e faz upload para o Elasticsearch

        Args:
            file_content: Conteúdo do arquivo CSV em bytes
            index_name: Nome do índice de destino
            es_server_id: ID do servidor Elasticsearch
            user_id: ID do usuário que está fazendo upload
            force_create: Se True, cria o índice mesmo se já existir (sobrescreve)

        Returns:
            Dicionário com resultado do upload:
            {
                "success": bool,
                "index_name": str,
                "documents_processed": int,
                "documents_indexed": int,
                "errors": List[str],
                "created_index": bool,
                "mapping": Dict (se criou índice)
            }

        Raises:
            ValueError: Se o CSV é inválido
            Exception: Se houver erro na conexão com Elasticsearch
        """
        try:
            # 1. Parse CSV
            logger.info(f"📊 Parsing CSV for index {index_name}")
            documents, headers = await self._parse_csv(file_content)

            if not documents:
                raise ValueError("CSV vazio ou sem dados válidos")

            logger.info(f"✅ Parsed {len(documents)} documents with {len(headers)} fields")

            # 2. Conectar ao Elasticsearch
            es = await self.es_factory.get_client(es_server_id)

            # 3. Verificar se índice existe
            index_exists = await es.indices.exists(index=index_name)

            created_index = False
            mapping = None

            if not index_exists:
                # 3a. Primeira vez: criar índice com mapping inferido
                logger.info(f"🆕 Index {index_name} doesn't exist. Creating with inferred mapping...")
                mapping = self._infer_mapping_from_data(documents, headers)
                await self._create_index(es, index_name, mapping)
                created_index = True
                logger.info(f"✅ Index {index_name} created successfully")

            else:
                # 3b. Índice existe: validar smart mapping
                logger.info(f"📋 Index {index_name} exists. Validating mapping compatibility...")
                is_compatible, errors = await self._validate_smart_mapping(
                    es, index_name, documents, headers
                )

                if not is_compatible:
                    error_msg = (
                        f"Formato do CSV não é compatível com o índice existente. "
                        f"Erros: {', '.join(errors)}"
                    )
                    logger.error(f"❌ {error_msg}")
                    return {
                        "success": False,
                        "index_name": index_name,
                        "documents_processed": len(documents),
                        "documents_indexed": 0,
                        "errors": errors,
                        "created_index": False,
                        "message": error_msg
                    }

                logger.info(f"✅ CSV is compatible with existing index mapping")

            # 4. Bulk upload dos documentos
            logger.info(f"📤 Uploading {len(documents)} documents to index {index_name}")
            indexed_count, errors = await self._bulk_index_documents(
                es, index_name, documents, user_id
            )

            logger.info(f"✅ Upload completed: {indexed_count}/{len(documents)} documents indexed")

            return {
                "success": True,
                "index_name": index_name,
                "documents_processed": len(documents),
                "documents_indexed": indexed_count,
                "errors": errors if errors else [],
                "created_index": created_index,
                "mapping": mapping if created_index else None,
                "message": f"Successfully uploaded {indexed_count} documents"
            }

        except ValueError as e:
            logger.error(f"❌ Validation error: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Error processing CSV upload: {e}")
            raise

    async def _parse_csv(self, file_content: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse arquivo CSV e retorna lista de documentos

        Args:
            file_content: Conteúdo do CSV em bytes

        Returns:
            Tupla com (lista de documentos, lista de headers)

        Raises:
            ValueError: Se CSV é inválido
        """
        try:
            # Decodificar bytes para string
            text_content = file_content.decode('utf-8-sig')  # utf-8-sig remove BOM se existir

            # Detectar delimitador automaticamente
            csv_file = io.StringIO(text_content)
            sample = csv_file.read(4096)
            csv_file.seek(0)

            try:
                sniffer = csv.Sniffer()
                dialect = sniffer.sniff(sample, delimiters=',;\t|')
                delimiter = dialect.delimiter
                logger.info(f"🔍 Detected CSV delimiter: '{delimiter}'")
            except csv.Error:
                # Se não conseguir detectar, usa vírgula por padrão
                delimiter = ','
                logger.warning("⚠️ Could not detect delimiter, using comma")

            # Usar DictReader para parsing
            reader = csv.DictReader(csv_file, delimiter=delimiter)

            if not reader.fieldnames:
                raise ValueError("CSV não possui cabeçalho")

            headers = list(reader.fieldnames)
            documents = []

            for row_num, row in enumerate(reader, start=2):  # Start at 2 (1 is header)
                # Remover campos vazios e converter valores
                doc = {}
                for key, value in row.items():
                    if key and value is not None and value.strip():  # Skip empty values
                        doc[key] = self._convert_value(value)

                if doc:  # Only add non-empty documents
                    documents.append(doc)

            if not documents:
                raise ValueError("CSV não contém linhas de dados válidas")

            return documents, headers

        except UnicodeDecodeError:
            raise ValueError("Arquivo não está em formato UTF-8 válido")
        except csv.Error as e:
            raise ValueError(f"Erro ao fazer parse do CSV: {e}")
        except Exception as e:
            raise ValueError(f"Erro ao processar CSV: {e}")

    def _convert_value(self, value: str) -> Any:
        """
        Converte valores CSV para tipos Python apropriados

        Args:
            value: Valor string do CSV

        Returns:
            Valor convertido (int, float, bool, ou str)
        """
        value = value.strip()

        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'

        # Try int
        try:
            if '.' not in value:
                return int(value)
        except ValueError:
            pass

        # Try float
        try:
            return float(value)
        except ValueError:
            pass

        # Keep as string
        return value

    def _infer_mapping_from_data(
        self, documents: List[Dict[str, Any]], headers: List[str]
    ) -> Dict[str, Any]:
        """
        Infere o mapping do Elasticsearch baseado nos dados do CSV

        Args:
            documents: Lista de documentos parseados
            headers: Lista de headers do CSV

        Returns:
            Mapping do Elasticsearch
        """
        properties = {}

        # Analisar tipos de cada campo baseado em TODOS os documentos (não apenas sample)
        # Isso garante que campos mistos (números + strings) sejam detectados corretamente
        for header in headers:
            field_types = set()

            # Verificar TODOS os documentos para garantir tipo correto
            for doc in documents:
                if header in doc:
                    value = doc[header]
                    field_types.add(type(value).__name__)

            # Determinar tipo do campo de forma conservadora:
            # Se tiver QUALQUER string, o campo é text (não numérico)
            has_string = 'str' in field_types
            has_int = 'int' in field_types
            has_float = 'float' in field_types
            has_bool = 'bool' in field_types

            if has_string:
                # Se tem string, SEMPRE é text (mesmo que tenha números também)

                # Calcular tamanho máximo do campo para definir ignore_above
                max_length = 0
                for doc in documents:
                    if header in doc and isinstance(doc[header], str):
                        max_length = max(max_length, len(doc[header]))

                # Definir ignore_above baseado no tamanho máximo encontrado
                # Adiciona 20% de margem de segurança
                ignore_above = min(32766, int(max_length * 1.2) + 50)  # Max Elasticsearch: 32766

                # Se campo tem valores pequenos (< 100 chars), use limite padrão menor
                if max_length < 100:
                    ignore_above = 256

                properties[header] = {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": ignore_above
                        }
                    }
                }
            elif has_float or (has_int and has_float):
                # Se tem float (e nenhuma string), é float
                properties[header] = {"type": "float"}
            elif has_int:
                # Se tem apenas int (e nenhuma string/float), é long
                properties[header] = {"type": "long"}
            elif has_bool:
                # Se tem apenas bool, é boolean
                properties[header] = {"type": "boolean"}
            else:
                # Fallback: text
                properties[header] = {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                }

        # Adicionar campo de timestamp do upload
        properties["_upload_timestamp"] = {"type": "date"}
        properties["_uploaded_by"] = {"type": "keyword"}

        mapping = {
            "properties": properties
        }

        return mapping

    async def _create_index(
        self, es: AsyncElasticsearch, index_name: str, mapping: Dict[str, Any]
    ) -> None:
        """
        Cria um novo índice no Elasticsearch

        Args:
            es: Cliente Elasticsearch
            index_name: Nome do índice
            mapping: Mapping a ser aplicado

        Raises:
            Exception: Se falhar ao criar índice
        """
        try:
            await es.indices.create(
                index=index_name,
                body={
                    "mappings": mapping,
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1
                    }
                }
            )
        except Exception as e:
            logger.error(f"❌ Error creating index {index_name}: {e}")
            raise

    async def _validate_smart_mapping(
        self,
        es: AsyncElasticsearch,
        index_name: str,
        documents: List[Dict[str, Any]],
        headers: List[str]
    ) -> Tuple[bool, List[str]]:
        """
        Valida se os dados do CSV são compatíveis com o mapping existente

        Args:
            es: Cliente Elasticsearch
            index_name: Nome do índice
            documents: Documentos a validar
            headers: Headers do CSV

        Returns:
            Tupla (is_compatible, errors)
        """
        errors = []

        try:
            # Obter mapping atual
            mapping_response = await es.indices.get_mapping(index=index_name)
            current_mapping = mapping_response[index_name]['mappings']['properties']

            # Validar cada header contra o mapping
            for header in headers:
                if header not in current_mapping:
                    errors.append(
                        f"Campo '{header}' não existe no índice. "
                        f"Campos esperados: {', '.join(current_mapping.keys())}"
                    )

            # Validar tipos de dados de alguns documentos de amostra
            sample_size = min(10, len(documents))
            for i, doc in enumerate(documents[:sample_size]):
                for field, value in doc.items():
                    if field in current_mapping:
                        expected_type = current_mapping[field].get('type', 'text')
                        value_type = type(value).__name__

                        # Validação básica de tipos
                        if expected_type in ('long', 'integer', 'short', 'byte'):
                            if value_type != 'int':
                                errors.append(
                                    f"Campo '{field}' deve ser numérico inteiro, "
                                    f"mas encontrado '{value_type}' no documento {i+1}"
                                )
                        elif expected_type in ('float', 'double'):
                            if value_type not in ('int', 'float'):
                                errors.append(
                                    f"Campo '{field}' deve ser numérico, "
                                    f"mas encontrado '{value_type}' no documento {i+1}"
                                )
                        elif expected_type == 'boolean':
                            if value_type != 'bool':
                                errors.append(
                                    f"Campo '{field}' deve ser booleano, "
                                    f"mas encontrado '{value_type}' no documento {i+1}"
                                )

            return len(errors) == 0, errors

        except Exception as e:
            logger.error(f"❌ Error validating mapping: {e}")
            return False, [f"Erro ao validar mapping: {str(e)}"]

    async def _bulk_index_documents(
        self,
        es: AsyncElasticsearch,
        index_name: str,
        documents: List[Dict[str, Any]],
        user_id: str
    ) -> Tuple[int, List[str]]:
        """
        Faz bulk index dos documentos no Elasticsearch

        Args:
            es: Cliente Elasticsearch
            index_name: Nome do índice
            documents: Lista de documentos a indexar
            user_id: ID do usuário fazendo upload

        Returns:
            Tupla (quantidade_indexada, lista_de_erros)
        """
        errors = []
        indexed_count = 0

        try:
            # Preparar bulk operations
            bulk_operations = []
            upload_timestamp = datetime.utcnow().isoformat()

            for doc in documents:
                # Adicionar metadados do upload
                doc["_upload_timestamp"] = upload_timestamp
                doc["_uploaded_by"] = user_id

                # Adicionar operação de index
                bulk_operations.append(
                    {"index": {"_index": index_name}}
                )
                bulk_operations.append(doc)

            # Executar bulk em lotes
            batch_size = 1000
            for i in range(0, len(bulk_operations), batch_size * 2):  # *2 porque cada doc tem 2 linhas
                batch = bulk_operations[i:i + (batch_size * 2)]

                response = await es.bulk(
                    operations=batch,
                    refresh=True  # Refresh para disponibilizar imediatamente
                )

                # Processar resposta
                if response.get('errors'):
                    for item in response['items']:
                        if 'error' in item.get('index', {}):
                            error = item['index']['error']
                            errors.append(f"Error indexing document: {error}")
                        else:
                            indexed_count += 1
                else:
                    indexed_count += len(batch) // 2  # Cada doc tem 2 linhas no bulk

            return indexed_count, errors

        except Exception as e:
            logger.error(f"❌ Error in bulk indexing: {e}")
            return indexed_count, [f"Bulk indexing error: {str(e)}"]


# Singleton instance
_csv_upload_service: Optional[CSVUploadService] = None


def get_csv_upload_service() -> CSVUploadService:
    """Retorna instância singleton do service"""
    global _csv_upload_service
    if _csv_upload_service is None:
        _csv_upload_service = CSVUploadService()
    return _csv_upload_service
