#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP Server - RSS News Intelligence
Permite que LLMs acessem diretamente o Elasticsearch de notícias RSS

Requisitos:
  pip install mcp requests python-dateutil elasticsearch

Uso:
  python mcp_rss_server.py

Ferramentas disponíveis:
  - search_rss_news: Busca notícias por query/filtros
  - get_rss_stats: Estatísticas de notícias coletadas
  - get_latest_news: Últimas notícias por categoria
  - get_news_by_date: Notícias de um período específico
  - get_sources_summary: Resumo de fontes RSS
"""
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
from mcp.server.fastmcp import FastMCP
from elasticsearch import Elasticsearch

# Configuração de logging para stderr (MCP usa stdout)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-rss-news")

# Configurações do Elasticsearch
ES_HOST = os.environ.get("ES_HOST", "localhost")
ES_PORT = int(os.environ.get("ES_PORT", "9200"))
ES_INDEX = "rss-articles"

# Inicializar ES Client
es_client = Elasticsearch([f"http://{ES_HOST}:{ES_PORT}"])

# Inicializar MCP Server
mcp = FastMCP("rss-news-intelligence")

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

def parse_date_filter(days: Optional[int] = None, date_from: Optional[str] = None) -> Optional[datetime]:
    """Converte filtro de data para datetime"""
    if date_from:
        try:
            return datetime.fromisoformat(date_from.replace('Z', '+00:00'))
        except ValueError:
            logger.warning(f"Data inválida: {date_from}")
            return None

    if days:
        return datetime.now(timezone.utc) - timedelta(days=days)

    return None


def build_es_query(
    query: Optional[str] = None,
    categories: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None
) -> Dict[str, Any]:
    """Constrói query do Elasticsearch"""
    must_clauses = []
    filter_clauses = []

    # Full-text search
    if query:
        must_clauses.append({
            "multi_match": {
                "query": query,
                "fields": ["title^3", "summary^2", "content", "tags"],
                "type": "best_fields",
                "operator": "or"
            }
        })

    # Category filter
    if categories:
        filter_clauses.append({"terms": {"category": categories}})

    # Source filter
    if sources:
        filter_clauses.append({"terms": {"feed_name": sources}})

    # Date range
    if date_from or date_to:
        range_query = {}
        if date_from:
            range_query["gte"] = date_from.isoformat()
        if date_to:
            range_query["lte"] = date_to.isoformat()
        filter_clauses.append({"range": {"published": range_query}})

    return {
        "bool": {
            "must": must_clauses if must_clauses else [{"match_all": {}}],
            "filter": filter_clauses
        }
    }


# ============================================================================
# FERRAMENTAS MCP
# ============================================================================

@mcp.tool()
def ping() -> str:
    """Health check do servidor MCP"""
    return "pong - MCP RSS News Intelligence Server is running"


@mcp.tool()
def search_rss_news(
    query: str = "",
    categories: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    days: int = 7,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Busca notícias RSS com filtros avançados

    Args:
        query: Texto para busca (busca em título, resumo, conteúdo)
        categories: Lista de categorias (ex: ["Inteligência Artificial", "Segurança da Informação"])
        sources: Lista de fontes RSS (ex: ["OpenAI News", "The Hacker News"])
        days: Número de dias para buscar (padrão: 7)
        limit: Número máximo de resultados (padrão: 20)

    Returns:
        Dict com total de resultados e lista de artigos

    Exemplo de uso pela LLM:
        "Quais são as últimas notícias sobre IA?"
        -> search_rss_news(query="inteligência artificial", days=3)

        "Notícias de segurança da semana passada"
        -> search_rss_news(categories=["Segurança da Informação"], days=7)
    """
    try:
        date_from = datetime.now(timezone.utc) - timedelta(days=days)

        es_query = build_es_query(
            query=query if query.strip() else None,
            categories=categories,
            sources=sources,
            date_from=date_from
        )

        search_body = {
            "query": es_query,
            "size": limit,
            "sort": [{"published": {"order": "desc"}}],
            "_source": ["article_id", "title", "link", "published", "summary",
                       "author", "tags", "category", "feed_name", "created_at"]
        }

        response = es_client.search(index=ES_INDEX, body=search_body)

        hits = response["hits"]
        total = hits["total"]["value"]
        articles = []

        for hit in hits["hits"]:
            source = hit["_source"]
            articles.append({
                "id": source.get("article_id"),
                "title": source.get("title"),
                "summary": source.get("summary", "")[:300],  # Limitar resumo
                "link": source.get("link"),
                "published": source.get("published"),
                "author": source.get("author"),
                "source": source.get("feed_name"),
                "category": source.get("category"),
                "tags": source.get("tags", [])
            })

        return {
            "total": total,
            "returned": len(articles),
            "articles": articles,
            "query_info": {
                "search_query": query if query.strip() else "all",
                "categories": categories or ["all"],
                "days": days,
                "limit": limit
            }
        }

    except Exception as e:
        logger.error(f"❌ Error searching RSS news: {e}")
        return {
            "error": str(e),
            "total": 0,
            "returned": 0,
            "articles": []
        }


@mcp.tool()
def get_rss_stats(days: int = 30) -> Dict[str, Any]:
    """
    Obtém estatísticas de notícias RSS coletadas

    Args:
        days: Número de dias para estatísticas (padrão: 30)

    Returns:
        Estatísticas: total de artigos, por categoria, por fonte, timeline

    Exemplo de uso pela LLM:
        "Quantas notícias foram coletadas esta semana?"
        -> get_rss_stats(days=7)
    """
    try:
        now = datetime.now(timezone.utc)
        date_from = now - timedelta(days=days)

        # Query para estatísticas
        stats_query = {
            "size": 0,
            "query": {
                "range": {
                    "created_at": {
                        "gte": date_from.isoformat()
                    }
                }
            },
            "aggs": {
                "total": {
                    "value_count": {"field": "article_id"}
                },
                "by_category": {
                    "terms": {"field": "category", "size": 20}
                },
                "by_source": {
                    "terms": {"field": "feed_name", "size": 50, "order": {"_count": "desc"}}
                },
                "timeline": {
                    "date_histogram": {
                        "field": "published",
                        "calendar_interval": "day",
                        "format": "yyyy-MM-dd",
                        "min_doc_count": 0
                    }
                }
            }
        }

        response = es_client.search(index=ES_INDEX, body=stats_query)
        aggs = response["aggregations"]

        return {
            "period_days": days,
            "total_articles": aggs["total"]["value"],
            "by_category": {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs["by_category"]["buckets"]
            },
            "top_sources": [
                {"name": bucket["key"], "count": bucket["doc_count"]}
                for bucket in aggs["by_source"]["buckets"][:10]
            ],
            "timeline": [
                {"date": bucket["key_as_string"], "count": bucket["doc_count"]}
                for bucket in aggs["timeline"]["buckets"]
            ]
        }

    except Exception as e:
        logger.error(f"❌ Error getting RSS stats: {e}")
        return {"error": str(e)}


@mcp.tool()
def get_latest_news(category: str = "", limit: int = 10) -> Dict[str, Any]:
    """
    Obtém as últimas notícias, opcionalmente filtradas por categoria

    Args:
        category: Categoria específica (opcional)
        limit: Número de notícias (padrão: 10)

    Returns:
        Lista das notícias mais recentes

    Exemplo de uso pela LLM:
        "Quais são as últimas notícias?"
        -> get_latest_news(limit=5)

        "Últimas notícias de IA"
        -> get_latest_news(category="Inteligência Artificial", limit=10)
    """
    try:
        query = {"match_all": {}}

        if category.strip():
            query = {"term": {"category": category}}

        search_body = {
            "query": query,
            "size": limit,
            "sort": [{"published": {"order": "desc"}}],
            "_source": ["title", "summary", "link", "published", "feed_name", "category", "tags"]
        }

        response = es_client.search(index=ES_INDEX, body=search_body)

        articles = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            articles.append({
                "title": source.get("title"),
                "summary": source.get("summary", "")[:200],
                "link": source.get("link"),
                "published": source.get("published"),
                "source": source.get("feed_name"),
                "category": source.get("category"),
                "tags": source.get("tags", [])[:5]
            })

        return {
            "category": category if category.strip() else "all",
            "count": len(articles),
            "articles": articles
        }

    except Exception as e:
        logger.error(f"❌ Error getting latest news: {e}")
        return {"error": str(e)}


@mcp.tool()
def get_news_by_date(date: str, category: str = "") -> Dict[str, Any]:
    """
    Obtém notícias de uma data específica

    Args:
        date: Data no formato YYYY-MM-DD (ex: "2025-11-15")
        category: Categoria opcional

    Returns:
        Notícias da data especificada

    Exemplo de uso pela LLM:
        "Quais foram as notícias de ontem?"
        -> get_news_by_date(date="2025-11-14")

        "Notícias de segurança do dia 10/11"
        -> get_news_by_date(date="2025-11-10", category="Segurança da Informação")
    """
    try:
        date_obj = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        date_from = date_obj.replace(hour=0, minute=0, second=0)
        date_to = date_obj.replace(hour=23, minute=59, second=59)

        query_clauses = [
            {"range": {"published": {
                "gte": date_from.isoformat(),
                "lte": date_to.isoformat()
            }}}
        ]

        if category.strip():
            query_clauses.append({"term": {"category": category}})

        search_body = {
            "query": {"bool": {"must": query_clauses}},
            "size": 100,
            "sort": [{"published": {"order": "desc"}}],
            "_source": ["title", "summary", "link", "published", "feed_name", "category"]
        }

        response = es_client.search(index=ES_INDEX, body=search_body)

        articles = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            articles.append({
                "title": source.get("title"),
                "summary": source.get("summary", "")[:200],
                "link": source.get("link"),
                "published": source.get("published"),
                "source": source.get("feed_name"),
                "category": source.get("category")
            })

        return {
            "date": date,
            "category": category if category.strip() else "all",
            "total": len(articles),
            "articles": articles
        }

    except ValueError:
        return {"error": f"Data inválida: {date}. Use formato YYYY-MM-DD"}
    except Exception as e:
        logger.error(f"❌ Error getting news by date: {e}")
        return {"error": str(e)}


@mcp.tool()
def get_sources_summary() -> Dict[str, Any]:
    """
    Obtém resumo de todas as fontes RSS configuradas

    Returns:
        Lista de fontes com contagem de artigos

    Exemplo de uso pela LLM:
        "Quais são as fontes RSS disponíveis?"
        -> get_sources_summary()
    """
    try:
        search_body = {
            "size": 0,
            "aggs": {
                "sources": {
                    "terms": {"field": "feed_name", "size": 100, "order": {"_count": "desc"}}
                },
                "categories": {
                    "terms": {"field": "category", "size": 50}
                }
            }
        }

        response = es_client.search(index=ES_INDEX, body=search_body)
        aggs = response["aggregations"]

        sources = []
        for bucket in aggs["sources"]["buckets"]:
            sources.append({
                "name": bucket["key"],
                "article_count": bucket["doc_count"]
            })

        categories = [
            {"name": bucket["key"], "count": bucket["doc_count"]}
            for bucket in aggs["categories"]["buckets"]
        ]

        return {
            "total_sources": len(sources),
            "total_articles": sum(s["article_count"] for s in sources),
            "sources": sources,
            "categories": categories
        }

    except Exception as e:
        logger.error(f"❌ Error getting sources summary: {e}")
        return {"error": str(e)}


@mcp.tool()
def analyze_trending_topics(days: int = 7, top_n: int = 20) -> Dict[str, Any]:
    """
    Analisa tópicos em alta baseado em tags e palavras-chave

    Args:
        days: Período de análise em dias (padrão: 7)
        top_n: Número de tópicos para retornar (padrão: 20)

    Returns:
        Tópicos mais frequentes no período

    Exemplo de uso pela LLM:
        "Quais são os tópicos em alta esta semana?"
        -> analyze_trending_topics(days=7)
    """
    try:
        date_from = datetime.now(timezone.utc) - timedelta(days=days)

        search_body = {
            "size": 0,
            "query": {
                "range": {
                    "published": {"gte": date_from.isoformat()}
                }
            },
            "aggs": {
                "trending_tags": {
                    "terms": {"field": "tags", "size": top_n}
                },
                "by_category": {
                    "terms": {"field": "category", "size": 10}
                }
            }
        }

        response = es_client.search(index=ES_INDEX, body=search_body)
        aggs = response["aggregations"]

        return {
            "period_days": days,
            "trending_tags": [
                {"tag": bucket["key"], "count": bucket["doc_count"]}
                for bucket in aggs["trending_tags"]["buckets"]
            ],
            "by_category": {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs["by_category"]["buckets"]
            }
        }

    except Exception as e:
        logger.error(f"❌ Error analyzing trending topics: {e}")
        return {"error": str(e)}


# ============================================================================
# MAIN - Servidor MCP
# ============================================================================

if __name__ == "__main__":
    # Teste de conectividade com ES
    try:
        info = es_client.info()
        logger.info(f"✅ Conectado ao Elasticsearch: {ES_HOST}:{ES_PORT}")
        logger.info(f"   Version: {info['version']['number']}")

        # Verificar se índice existe
        if es_client.indices.exists(index=ES_INDEX):
            count = es_client.count(index=ES_INDEX)
            logger.info(f"   Índice '{ES_INDEX}': {count['count']} documentos")
        else:
            logger.warning(f"⚠️ Índice '{ES_INDEX}' não existe")

    except Exception as e:
        logger.error(f"❌ Erro de conexão com ES: {e}")
        sys.exit(1)

    logger.info("🚀 Iniciando MCP RSS News Intelligence Server...")
    logger.info("🛠️ Ferramentas disponíveis:")
    logger.info("  - ping: Health check")
    logger.info("  - search_rss_news: Busca notícias com filtros avançados")
    logger.info("  - get_rss_stats: Estatísticas de notícias")
    logger.info("  - get_latest_news: Últimas notícias")
    logger.info("  - get_news_by_date: Notícias de data específica")
    logger.info("  - get_sources_summary: Resumo de fontes RSS")
    logger.info("  - analyze_trending_topics: Tópicos em alta")
    logger.info("")
    logger.info("💡 A LLM pode chamar essas ferramentas diretamente!")
    logger.info("   Exemplo: 'Quais notícias de IA foram publicadas hoje?'")
    logger.info("   -> LLM chama: search_rss_news(query='inteligência artificial', days=1)")

    # Roda servidor MCP via stdio
    mcp.run(transport="stdio")
