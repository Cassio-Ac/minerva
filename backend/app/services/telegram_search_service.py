"""
Telegram Search Service
Serviço para busca e análise de mensagens do Telegram indexadas no Elasticsearch
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import re
from app.services.elasticsearch_service import get_es_service
from app.services.es_client_factory import ESClientFactory
from app.db.database import AsyncSessionLocal
from app.models.telegram_blacklist import TelegramMessageBlacklist
from sqlalchemy import select

logger = logging.getLogger(__name__)


# Padrão de índices para mensagens do Telegram
INDEX_PATTERN = "telegram_messages_*"
INDEX_INFO = "telegram_groups"  # Index with group metadata


async def get_group_title_from_info(es, group_username: str) -> Optional[str]:
    """
    Busca o título do grupo no índice telegram_groups

    Args:
        es: Cliente Elasticsearch
        group_username: Username do grupo

    Returns:
        Título do grupo ou None se não encontrado
    """
    try:
        # Try both field names: 'username' (from csv source) and 'group_username' (from scraper)
        response = await es.search(
            index=INDEX_INFO,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"username": group_username}},
                            {"term": {"_id": group_username}}
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 1
            }
        )

        if response['hits']['total']['value'] > 0:
            source = response['hits']['hits'][0]['_source']
            # Try different field names for title
            return source.get('group_title') or source.get('name') or source.get('title')
        return None
    except Exception as e:
        logger.warning(f"⚠️ Could not fetch group title from telegram_groups: {e}")
        return None


async def get_active_blacklist_patterns() -> List[Dict[str, Any]]:
    """
    Retrieve all active blacklist patterns from database

    Returns:
        List of active blacklist patterns with their settings
    """
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(TelegramMessageBlacklist).where(
                TelegramMessageBlacklist.is_active == True
            )
            result = await session.execute(stmt)
            patterns = result.scalars().all()

            return [
                {
                    "pattern": p.pattern,
                    "is_regex": p.is_regex,
                    "case_sensitive": p.case_sensitive
                }
                for p in patterns
            ]
    except Exception as e:
        logger.error(f"❌ Error loading blacklist patterns: {e}")
        return []


def message_matches_blacklist(message: str, blacklist_patterns: List[Dict[str, Any]]) -> bool:
    """
    Check if a message matches any blacklist pattern

    Args:
        message: The message text to check
        blacklist_patterns: List of blacklist patterns to check against

    Returns:
        True if message matches any blacklist pattern, False otherwise
    """
    if not message or not blacklist_patterns:
        return False

    for pattern_obj in blacklist_patterns:
        pattern = pattern_obj["pattern"]
        is_regex = pattern_obj["is_regex"]
        case_sensitive = pattern_obj["case_sensitive"]

        try:
            if is_regex:
                # Use regex matching
                flags = 0 if case_sensitive else re.IGNORECASE
                if re.search(pattern, message, flags=flags):
                    return True
            else:
                # Simple substring matching
                search_message = message if case_sensitive else message.lower()
                search_pattern = pattern if case_sensitive else pattern.lower()
                if search_pattern in search_message:
                    return True
        except re.error as e:
            logger.warning(f"⚠️ Invalid regex pattern '{pattern}': {e}")
            continue

    return False


class TelegramSearchService:
    """Service para busca e análise de mensagens do Telegram"""

    def __init__(self):
        self.es_service = get_es_service()

    async def search_messages(
        self,
        text: str,
        is_exact_search: bool = False,
        page: int = 1,
        page_size: int = 50,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Busca por texto na mensagem com paginação

        Args:
            text: Texto a buscar
            is_exact_search: Se True, busca exata (substring). Se False, busca inteligente
            page: Número da página (começa em 1)
            page_size: Tamanho da página
            server_id: ID do servidor ES (opcional)

        Returns:
            Dicionário com mensagens encontradas e info de paginação
        """
        try:
            texto_lower = text.lower()

            if is_exact_search:
                # Busca exata com wildcard
                query = {
                    "bool": {
                        "should": [
                            {"wildcard": {"message": {"value": f"*{texto_lower}*", "case_insensitive": True, "boost": 2.0}}},
                            {"match_phrase": {"message": {"query": text, "boost": 1.0}}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                sort_order = [{"date.keyword": "desc"}]
            else:
                # Busca inteligente combinando match e wildcard
                query = {
                    "bool": {
                        "should": [
                            {"match": {"message": {"query": text, "operator": "and", "boost": 4.0}}},
                            {"match_phrase": {"message": {"query": text, "boost": 3.0}}},
                            {"wildcard": {"message": {"value": f"*{texto_lower}*", "case_insensitive": True, "boost": 2.0}}},
                            {"match": {"message": {"query": text, "fuzziness": "AUTO", "boost": 0.5}}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                sort_order = [{"_score": "desc"}, {"date.keyword": "desc"}]

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Get blacklist patterns first
            blacklist_patterns = await get_active_blacklist_patterns()

            # When blacklist is active, we need to fetch more results iteratively
            # to compensate for filtered messages
            if blacklist_patterns:
                # Start from the logical page offset, but we'll need to skip filtered messages
                collected_hits = []
                es_from = 0
                batch_size = 200  # Fetch in larger batches for efficiency
                max_iterations = 20  # Safety limit
                iterations = 0

                # Calculate how many valid messages we need to skip (for pagination)
                skip_count = (page - 1) * page_size
                skipped = 0
                total_filtered = 0

                while len(collected_hits) < page_size and iterations < max_iterations:
                    iterations += 1

                    response = await es.search(
                        index=INDEX_PATTERN,
                        body={
                            "query": query,
                            "from": es_from,
                            "size": batch_size,
                            "sort": sort_order,
                            "_source": ["id", "date", "message", "sender_info", "group_info"],
                            "track_total_hits": True
                        }
                    )

                    batch_hits = response['hits']['hits']
                    total_es = response['hits']['total']['value']

                    if not batch_hits:
                        # No more results from ES
                        break

                    # Filter this batch
                    for hit in batch_hits:
                        message_text = hit['_source'].get('message', '')
                        if not message_matches_blacklist(message_text, blacklist_patterns):
                            # Valid message (not blacklisted)
                            if skipped < skip_count:
                                # Still skipping for pagination
                                skipped += 1
                            else:
                                # Collect this message
                                collected_hits.append(hit)
                                if len(collected_hits) >= page_size:
                                    break
                        else:
                            total_filtered += 1

                    es_from += batch_size

                    # Check if we've exhausted ES results
                    if es_from >= total_es:
                        break

                logger.info(f"🚫 Filtered out {total_filtered} messages matching blacklist (iterations: {iterations})")

                # Determine if there are more results
                has_more = es_from < total_es or len(batch_hits) == batch_size

                return {
                    "total": total_es,
                    "hits": collected_hits,
                    "search_type": "exact" if is_exact_search else "intelligent",
                    "page": page,
                    "page_size": page_size,
                    "has_more": has_more and len(collected_hits) == page_size
                }
            else:
                # No blacklist - simple pagination
                es_from = (page - 1) * page_size

                response = await es.search(
                    index=INDEX_PATTERN,
                    body={
                        "query": query,
                        "from": es_from,
                        "size": page_size,
                        "sort": sort_order,
                        "_source": ["id", "date", "message", "sender_info", "group_info"],
                        "track_total_hits": True
                    }
                )

                hits = response['hits']['hits']
                total_es = response['hits']['total']['value']
                has_more = (es_from + page_size) < total_es

                return {
                    "total": total_es,
                    "hits": hits,
                    "search_type": "exact" if is_exact_search else "intelligent",
                    "page": page,
                    "page_size": page_size,
                    "has_more": has_more
                }

        except Exception as e:
            logger.error(f"❌ Error searching messages: {e}")
            raise

    async def search_by_user(
        self,
        search_term: str,
        page: int = 1,
        page_size: int = 50,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Busca mensagens por usuário (user_id, username ou nome completo) com paginação

        Args:
            search_term: Termo de busca (user_id, username ou nome)
            page: Número da página (começa em 1)
            page_size: Tamanho da página
            server_id: ID do servidor ES (opcional)

        Returns:
            Dicionário com mensagens encontradas e info de paginação
        """
        try:
            termo_lower = search_term.lower().strip()
            termo_original = search_term.strip()

            # Remove @ se presente
            if termo_lower.startswith('@'):
                termo_lower = termo_lower[1:]
                termo_original = termo_original[1:]

            should_clauses = []

            # Busca por USER_ID (exato)
            if termo_original.isdigit():
                should_clauses.append({
                    "term": {"sender_info.user_id": int(termo_original)}
                })

            # Busca por USERNAME
            should_clauses.extend([
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": "sender_info.username"}},
                            {"wildcard": {"sender_info.username": {"value": f"*{termo_lower}*", "case_insensitive": True}}}
                        ]
                    }
                },
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": "sender_info.username"}},
                            {"match": {"sender_info.username": {"query": termo_lower}}}
                        ]
                    }
                }
            ])

            # Busca por NOME COMPLETO
            should_clauses.extend([
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": "sender_info.full_name"}},
                            {"match_phrase": {"sender_info.full_name": {"query": termo_original, "slop": 1}}}
                        ]
                    }
                },
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": "sender_info.full_name"}},
                            {"match": {"sender_info.full_name": {"query": termo_original, "operator": "and", "fuzziness": "AUTO"}}}
                        ]
                    }
                },
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": "sender_info.full_name.keyword"}},
                            {"wildcard": {"sender_info.full_name.keyword": {"value": f"*{termo_original}*", "case_insensitive": True}}}
                        ]
                    }
                }
            ])

            query = {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Calculate ES pagination
            es_from = (page - 1) * page_size
            es_size = page_size

            response = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "from": es_from,
                    "size": es_size,
                    "sort": [{"date.keyword": "desc"}],
                    "_source": ["id", "date", "message", "sender_info", "group_info"],
                    "track_total_hits": True
                }
            )

            hits = response['hits']['hits']
            total = response['hits']['total']['value']

            # Calculate if there are more results
            has_more = (es_from + es_size) < total

            return {
                "total": total,
                "hits": hits,
                "search_term": search_term,
                "page": page,
                "page_size": page_size,
                "has_more": has_more
            }

        except Exception as e:
            logger.error(f"❌ Error searching by user: {e}")
            raise

    async def get_message_context(
        self,
        index_name: str,
        msg_id: int,
        group_id: Optional[int] = None,
        before: int = 10,
        after: int = 10,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Busca N mensagens antes e N depois de uma mensagem específica

        Args:
            index_name: Nome do índice onde a mensagem está
            msg_id: ID da mensagem
            group_id: ID do grupo (para filtrar em índices compartilhados)
            before: Quantidade de mensagens antes (padrão: 10)
            after: Quantidade de mensagens depois (padrão: 10)
            server_id: ID do servidor ES (opcional)

        Returns:
            Dicionário com contexto da mensagem
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Build query - filter by ID range AND group_id if provided
            query = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "id": {
                                    "gte": msg_id - before * 2,
                                    "lte": msg_id + after * 2
                                }
                            }
                        }
                    ]
                }
            }

            # Add group_id filter if provided (important for shared indices like telegram_messages_v2)
            if group_id is not None:
                query["bool"]["must"].append({
                    "term": {"group_info.group_id": group_id}
                })
                logger.info(f"📍 Filtering by group_id: {group_id}")

            # Buscar mensagens próximas por ID
            response = await es.search(
                index=index_name,
                body={
                    "query": query,
                    "size": 500,
                    "sort": [{"date.keyword": "asc"}]
                }
            )

            todas = response['hits']['hits']

            # Encontrar índice da mensagem selecionada
            idx_selecionada = None
            for i, hit in enumerate(todas):
                if hit['_source']['id'] == msg_id:
                    idx_selecionada = i
                    break

            logger.info(f"📍 Context search: msg_id={msg_id}, found at index={idx_selecionada}, total messages={len(todas)}")

            if idx_selecionada is None:
                logger.warning(f"⚠️ Message {msg_id} not found in results!")
                return {
                    "total": len(todas),
                    "messages": todas,
                    "selected_message_id": msg_id
                }

            # Extrair janela de contexto
            inicio = max(0, idx_selecionada - before)
            fim = min(len(todas), idx_selecionada + after + 1)

            contexto = todas[inicio:fim]

            logger.info(f"📍 Context window: inicio={inicio}, fim={fim}, selected_index_in_window={idx_selecionada - inicio}")

            # Extract group info
            # ALWAYS use index_name as source of truth for group_username (reliable)
            # Extract from index name: telegram_messages_groupname -> groupname
            group_username = index_name.replace('telegram_messages_', '')

            # Try to get group_title from telegram_info index first (most reliable)
            group_title = await get_group_title_from_info(es, group_username)

            if group_title:
                logger.info(f"✅ Found group_title in telegram_info: {group_title} for username: {group_username}")
            else:
                # Fallback: Try to get group_title from any message in context that matches the correct group
                logger.info(f"📍 Fallback: Looking for group_title in messages with username: {group_username}")
                for idx, hit in enumerate(contexto):
                    msg = hit['_source']
                    group_info = msg.get('group_info', {})
                    msg_username = group_info.get('group_username', '')
                    msg_title = group_info.get('group_title', '')

                    if idx < 3:  # Log first 3 messages for debugging
                        logger.info(f"📍 Message {idx}: group_username={msg_username}, group_title={msg_title}")

                    # Only use group_title if the group_username matches the index
                    if msg_username.lower() == group_username.lower():
                        group_title = msg_title
                        if group_title:
                            logger.info(f"✅ Found group_title in messages: {group_title} for username: {group_username}")
                            break

                if not group_title:
                    logger.warning(f"⚠️ No group_title found for username: {group_username}")

            # Log message IDs in context for debugging
            context_msg_ids = [hit['_source']['id'] for hit in contexto]
            logger.info(f"📍 Context message IDs: {context_msg_ids}")
            logger.info(f"📍 Looking for message ID: {msg_id}")

            return {
                "total": len(contexto),
                "messages": contexto,
                "selected_message_id": msg_id,
                "selected_index": idx_selecionada - inicio,
                "group_title": group_title,
                "group_username": group_username
            }

        except Exception as e:
            logger.error(f"❌ Error getting message context: {e}")
            raise

    async def get_statistics(
        self,
        period_days: Optional[int] = None,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retorna estatísticas gerais de grupos e usuários

        Args:
            period_days: Período em dias (None = all time)
            server_id: ID do servidor ES (opcional)

        Returns:
            Estatísticas gerais
        """
        try:
            query = {"match_all": {}}

            if period_days:
                data_inicio = datetime.utcnow() - timedelta(days=period_days)
                # Use date.keyword since date field is text type
                query = {
                    "range": {
                        "date.keyword": {
                            "gte": data_inicio.strftime("%Y-%m-%d")
                        }
                    }
                }

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Contar total de mensagens
            count_response = await es.count(
                index=INDEX_PATTERN,
                body={"query": query}
            )
            total_msgs = count_response['count']

            # Agregação de grupos
            response_grupos = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "total_grupos_unicos": {
                            "cardinality": {
                                "field": "group_info.group_username.keyword"
                            }
                        },
                        "top_grupos": {
                            "terms": {
                                "field": "group_info.group_username.keyword",
                                "size": 20,
                                "order": {"_count": "desc"}
                            },
                            "aggs": {
                                "titulo": {
                                    "terms": {
                                        "field": "group_info.group_title.keyword",
                                        "size": 1
                                    }
                                }
                            }
                        }
                    }
                }
            )

            # Agregação de usuários (apenas usuários com username - pesquisáveis)
            response_usuarios = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "total_usuarios_unicos": {
                            "filter": {
                                "exists": {"field": "sender_info.username"}
                            },
                            "aggs": {
                                "unique_users": {
                                    "cardinality": {
                                        "field": "sender_info.user_id"
                                    }
                                }
                            }
                        },
                        "top_usuarios": {
                            "terms": {
                                "field": "sender_info.user_id",
                                "size": 20,
                                "order": {"_count": "desc"},
                                "missing": 0
                            },
                            "aggs": {
                                "username": {
                                    "terms": {
                                        "field": "sender_info.username.keyword",
                                        "size": 1,
                                        "missing": "N/A"
                                    }
                                },
                                "full_name": {
                                    "terms": {
                                        "field": "sender_info.full_name.keyword",
                                        "size": 1,
                                        "missing": "Unknown"
                                    }
                                },
                                "top_grupos": {
                                    "terms": {
                                        "field": "group_info.group_username.keyword",
                                        "size": 5,
                                        "order": {"_count": "desc"}
                                    },
                                    "aggs": {
                                        "titulo": {
                                            "terms": {
                                                "field": "group_info.group_title.keyword",
                                                "size": 1
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )

            return {
                "total_mensagens": total_msgs,
                "total_grupos": response_grupos['aggregations']['total_grupos_unicos']['value'],
                "total_usuarios": response_usuarios['aggregations']['total_usuarios_unicos']['unique_users']['value'],
                "grupos": response_grupos['aggregations']['top_grupos']['buckets'],
                "usuarios": response_usuarios['aggregations']['top_usuarios']['buckets'],
                "period_days": period_days
            }

        except Exception as e:
            logger.error(f"❌ Error getting statistics: {e}")
            raise

    async def get_group_statistics(
        self,
        group_username: str,
        period_days: Optional[int] = None,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Estatísticas de um grupo específico

        Args:
            group_username: Username do grupo
            period_days: Período em dias (None = all time)
            server_id: ID do servidor ES (opcional)

        Returns:
            Estatísticas do grupo
        """
        try:
            # Use exact username (messages index preserves original case)
            query = {
                "bool": {
                    "must": [
                        {"term": {"group_info.group_username.keyword": group_username}}
                    ]
                }
            }

            if period_days:
                data_inicio = datetime.utcnow() - timedelta(days=period_days)
                # Use date.keyword since date field is text type
                query["bool"]["must"].append({
                    "range": {
                        "date.keyword": {
                            "gte": data_inicio.strftime("%Y-%m-%d")
                        }
                    }
                })

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Contar total de mensagens
            count_response = await es.count(
                index=INDEX_PATTERN,
                body={"query": query}
            )
            total_msgs = count_response['count']

            # Agregação de usuários do grupo
            response = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "top_usuarios": {
                            "terms": {
                                "field": "sender_info.user_id",
                                "size": 20,
                                "order": {"_count": "desc"},
                                "missing": 0
                            },
                            "aggs": {
                                "username": {
                                    "terms": {"field": "sender_info.username.keyword", "size": 1, "missing": "N/A"}
                                },
                                "full_name": {
                                    "terms": {"field": "sender_info.full_name.keyword", "size": 1, "missing": "Unknown"}
                                }
                            }
                        },
                        "titulo": {
                            "terms": {"field": "group_info.group_title.keyword", "size": 1}
                        }
                    }
                }
            )

            titulo_buckets = response['aggregations'].get('titulo', {}).get('buckets', [])
            titulo = titulo_buckets[0]['key'] if titulo_buckets else group_username

            return {
                "total_mensagens": total_msgs,
                "grupo_nome": titulo,
                "grupo_username": group_username,
                "usuarios": response['aggregations']['top_usuarios']['buckets'],
                "period_days": period_days
            }

        except Exception as e:
            logger.error(f"❌ Error getting group statistics: {e}")
            raise

    async def get_user_statistics(
        self,
        user_id: int,
        period_days: Optional[int] = None,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Estatísticas de um usuário específico

        Args:
            user_id: ID do usuário
            period_days: Período em dias (None = all time)
            server_id: ID do servidor ES (opcional)

        Returns:
            Estatísticas do usuário
        """
        try:
            query = {
                "bool": {
                    "must": [
                        {"term": {"sender_info.user_id": user_id}}
                    ]
                }
            }

            if period_days:
                data_inicio = datetime.utcnow() - timedelta(days=period_days)
                # Use date.keyword since date field is text type
                query["bool"]["must"].append({
                    "range": {
                        "date.keyword": {
                            "gte": data_inicio.strftime("%Y-%m-%d")
                        }
                    }
                })

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Contar total de mensagens
            count_response = await es.count(
                index=INDEX_PATTERN,
                body={"query": query}
            )
            total_msgs = count_response['count']

            # Agregação de grupos onde o usuário interage
            response = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "top_grupos": {
                            "terms": {
                                "field": "group_info.group_username.keyword",
                                "size": 20,
                                "order": {"_count": "desc"}
                            },
                            "aggs": {
                                "titulo": {
                                    "terms": {"field": "group_info.group_title.keyword", "size": 1}
                                }
                            }
                        },
                        "username": {
                            "terms": {"field": "sender_info.username.keyword", "size": 1, "missing": "N/A"}
                        },
                        "full_name": {
                            "terms": {"field": "sender_info.full_name.keyword", "size": 1, "missing": "Unknown"}
                        }
                    }
                }
            )

            username_buckets = response['aggregations'].get('username', {}).get('buckets', [])
            full_name_buckets = response['aggregations'].get('full_name', {}).get('buckets', [])

            username = username_buckets[0]['key'] if username_buckets else 'N/A'

            if full_name_buckets and full_name_buckets[0]['key']:
                nome = full_name_buckets[0]['key']
            elif username != 'N/A':
                nome = f"@{username}"
            else:
                nome = 'Unknown'

            return {
                "total_mensagens": total_msgs,
                "user_id": user_id,
                "username": username,
                "nome": nome,
                "grupos": response['aggregations']['top_grupos']['buckets'],
                "period_days": period_days
            }

        except Exception as e:
            logger.error(f"❌ Error getting user statistics: {e}")
            raise

    async def list_groups(
        self,
        server_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lista todos os grupos disponíveis

        Args:
            server_id: ID do servidor ES (opcional)

        Returns:
            Lista de grupos
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # telegram_groups has different field names depending on source
            # - csv source: username, name
            # - scraper source: group_username, group_title
            response = await es.search(
                index=INDEX_INFO,
                body={
                    "size": 10000,
                    # No sort - ES default order is fine for listing groups
                    "_source": ["username", "name", "group_title", "group_username", "group_id", "status", "total_messages_collected"]
                }
            )

            # Normalize the response to have consistent field names
            # Keep original case - messages index preserves original username case
            normalized_hits = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                username_raw = source.get('username') or source.get('group_username') or hit['_id']
                normalized = {
                    'title': source.get('name') or source.get('group_title') or hit['_id'],
                    'username': username_raw if username_raw else hit['_id'],
                    'id': source.get('group_id'),
                    'status': source.get('status'),
                    'total_messages': source.get('total_messages_collected', 0)
                }
                normalized_hits.append({'_source': normalized})

            return normalized_hits

        except Exception as e:
            logger.error(f"❌ Error listing groups: {e}")
            raise

    async def get_group_messages(
        self,
        group_username: str,
        page: int = 1,
        page_size: int = 20,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Lê mensagens de um grupo com paginação

        Args:
            group_username: Username do grupo
            page: Número da página (começa em 1)
            page_size: Tamanho da página (padrão: 20)
            server_id: ID do servidor ES (opcional)

        Returns:
            Mensagens paginadas do grupo
        """
        try:
            from_offset = (page - 1) * page_size
            # Use exact username (messages index preserves original case)

            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            response = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": {"term": {"group_info.group_username.keyword": group_username}},
                    "from": from_offset,
                    "size": page_size,
                    "sort": [{"date.keyword": "desc"}],
                    "_source": ["id", "date", "message", "sender_info", "group_info"]
                }
            )

            total = response['hits']['total']['value']
            hits = response['hits']['hits']

            titulo = group_username  # Default to username
            if hits:
                group_info = hits[0]['_source'].get('group_info', {})
                titulo = group_info.get('group_title') or group_username

            return {
                "mensagens": hits,
                "total": total,
                "titulo": titulo,
                "username": group_username,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size
            }

        except Exception as e:
            logger.error(f"❌ Error getting group messages: {e}")
            raise

    async def get_timeline(
        self,
        days: int = 30,
        server_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Timeline de mensagens por dia

        Args:
            days: Número de dias para timeline (padrão: 30)
            server_id: ID do servidor ES (opcional)

        Returns:
            Timeline com contagem de mensagens por dia
        """
        try:
            factory = ESClientFactory()
            es = await factory.get_client(server_id)

            # Calculate date range manually since date field is text type
            from datetime import datetime, timedelta
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)

            # Query para filtrar últimos N dias usando date.keyword
            query = {
                "range": {
                    "date.keyword": {
                        "gte": start_date.strftime("%Y-%m-%d"),
                        "lte": end_date.strftime("%Y-%m-%d")
                    }
                }
            }

            # Agregação por dia usando terms em date.keyword (já que date é texto)
            response = await es.search(
                index=INDEX_PATTERN,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "messages_per_day": {
                            "terms": {
                                "field": "date.keyword",
                                "size": days + 1,
                                "order": {"_key": "asc"}
                            }
                        }
                    }
                }
            )

            buckets = response['aggregations']['messages_per_day']['buckets']

            return {
                "total_days": len(buckets),
                "days": days,
                "timeline": [
                    {
                        "date": bucket['key'][:10],  # Extract just the date part (YYYY-MM-DD)
                        "count": bucket['doc_count']
                    }
                    for bucket in buckets
                ]
            }

        except Exception as e:
            logger.error(f"❌ Error getting timeline: {e}")
            raise


# Singleton instance
_telegram_service: Optional[TelegramSearchService] = None


def get_telegram_service() -> TelegramSearchService:
    """Retorna instância do service"""
    global _telegram_service
    if _telegram_service is None:
        _telegram_service = TelegramSearchService()
    return _telegram_service
