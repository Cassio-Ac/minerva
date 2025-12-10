"""
API Endpoints para Consulta de Credenciais no Data Lake (Elasticsearch)

Endpoints Otimizados (420M+ documentos):
- POST /credentials/datalake/count - Contador rápido de resultados
- POST /credentials/datalake/search-v2 - Busca inteligente com detecção automática
- GET /credentials/datalake/by-domain/{domain} - Busca otimizada por domínio

Endpoints Legacy:
- GET /credentials/datalake/search - Busca credenciais por termo
- GET /credentials/datalake/stats - Estatísticas do Data Lake
- GET /credentials/datalake/timeline - Timeline de ingestão
- GET /credentials/datalake/top-domains - Top domínios vazados
"""

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Optional, List, Literal
from fastapi import APIRouter, HTTPException, Query, Path
from pydantic import BaseModel, Field
from enum import Enum

from app.db.elasticsearch import ElasticsearchClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials/datalake", tags=["Credentials - Data Lake"])

# Index name
INDEX_NAME = "leaked_credentials"


# ============================================================
# Enums e Tipos
# ============================================================

class SearchMode(str, Enum):
    AUTO = "auto"
    EMAIL_DOMAIN = "email_domain"
    URL_DOMAIN = "url_domain"
    EMAIL_EXACT = "email_exact"
    CONTAINS = "contains"


class QueryType(str, Enum):
    """Tipo de query detectado automaticamente"""
    EMAIL_EXACT = "email_exact"      # joao@empresa.com -> term query
    EMAIL_DOMAIN = "email_domain"    # @empresa.com ou empresa.com -> term em dominio_email
    URL_DOMAIN = "url_domain"        # site.com -> term em dominio_url
    GENERIC = "generic"              # texto livre -> wildcard limitado


# ============================================================
# Funções de Detecção e Otimização
# ============================================================

def detect_query_type(query: str) -> tuple[QueryType, str]:
    """
    Detecta o tipo de busca ideal baseado no padrão do query.
    Retorna (tipo, valor_normalizado)
    """
    q = query.strip().lower()

    # Domínio de email com @: @empresa.com ou @empresa.com.br
    # DEVE vir antes da verificação de email completo!
    if q.startswith('@') and '.' in q:
        return QueryType.EMAIL_DOMAIN, q[1:]  # Remove @

    # Email completo: joao@empresa.com (tem algo ANTES do @)
    if '@' in q and not q.startswith('@'):
        parts = q.split('@')
        if len(parts) == 2 and parts[0] and '.' in parts[1]:
            return QueryType.EMAIL_EXACT, q

    # Parece domínio (tem . e parece TLD)
    domain_pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    if re.match(domain_pattern, q):
        # Pode ser email domain ou url domain - prioriza email
        return QueryType.EMAIL_DOMAIN, q

    # Genérico
    return QueryType.GENERIC, q


def build_optimized_query(query: str, mode: SearchMode) -> tuple[dict, str, int]:
    """
    Constrói query ES otimizada baseada no modo.
    Retorna (query_dict, tipo_detectado, timeout_seconds)
    """
    q = query.strip().lower()

    if mode == SearchMode.AUTO:
        query_type, normalized = detect_query_type(q)
    elif mode == SearchMode.EMAIL_DOMAIN:
        query_type, normalized = QueryType.EMAIL_DOMAIN, q.lstrip('@')
    elif mode == SearchMode.URL_DOMAIN:
        query_type, normalized = QueryType.URL_DOMAIN, q
    elif mode == SearchMode.EMAIL_EXACT:
        query_type, normalized = QueryType.EMAIL_EXACT, q
    else:  # CONTAINS
        query_type, normalized = QueryType.GENERIC, q

    # Constrói query baseada no tipo
    if query_type == QueryType.EMAIL_EXACT:
        # Term query - instantânea
        return {
            "term": {"usuario": normalized}
        }, "email_exact", 10

    elif query_type == QueryType.EMAIL_DOMAIN:
        # Term em dominio_email - muito rápida
        return {
            "term": {"dominio_email": normalized}
        }, "email_domain", 30

    elif query_type == QueryType.URL_DOMAIN:
        # Term em dominio_url - muito rápida
        return {
            "term": {"dominio_url": normalized}
        }, "url_domain", 30

    else:  # GENERIC
        # Busca otimizada com boost e limite
        return {
            "bool": {
                "should": [
                    # Match exato em domínios (mais relevante)
                    {"term": {"dominio_email": {"value": normalized, "boost": 10}}},
                    {"term": {"dominio_url": {"value": normalized, "boost": 10}}},
                    # Prefix em usuario (rápido)
                    {"prefix": {"usuario": {"value": normalized, "boost": 5}}},
                    # Wildcard limitado (mais lento)
                    {"wildcard": {"dominio_email": {"value": f"*{normalized}*", "boost": 2}}},
                    {"wildcard": {"dominio_url": {"value": f"*{normalized}*", "boost": 1}}},
                ],
                "minimum_should_match": 1
            }
        }, "generic", 60


# ============================================================
# Schemas
# ============================================================

class CredentialResult(BaseModel):
    """Resultado de uma credencial"""
    usuario: str
    senha: str
    url: Optional[str] = None
    dominio_email: Optional[str] = None
    dominio_url: Optional[str] = None
    complexidade_senha: Optional[str] = None
    forca_senha: Optional[int] = None
    tamanho_senha: Optional[int] = None
    data_breach: Optional[str] = None
    arquivo: Optional[str] = None
    grupo_telegram: Optional[str] = None
    padrao_detectado: Optional[str] = None


class SearchResponse(BaseModel):
    """Response da busca"""
    total: int
    page: int
    page_size: int
    total_pages: int
    results: List[CredentialResult]
    query: str
    search_time_ms: int


# ============================================================
# Schemas V2 - Otimizados
# ============================================================

class CountRequest(BaseModel):
    """Request para contagem rápida"""
    query: str = Field(..., min_length=2, description="Termo de busca")
    mode: SearchMode = Field(default=SearchMode.AUTO, description="Modo de busca")


class CountResponse(BaseModel):
    """Response da contagem"""
    count: int
    query: str
    mode: str
    detected_type: str
    search_time_ms: int
    estimated_load_time: str


class SearchV2Request(BaseModel):
    """Request para busca otimizada"""
    query: str = Field(..., min_length=2, description="Termo de busca")
    mode: SearchMode = Field(default=SearchMode.AUTO, description="Modo de busca")
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=10, le=200)


class SearchV2Response(BaseModel):
    """Response da busca otimizada"""
    total: int
    page: int
    page_size: int
    total_pages: int
    results: List[CredentialResult]
    query: str
    mode: str
    detected_type: str
    search_time_ms: int
    timed_out: bool = False


class DataLakeStats(BaseModel):
    """Estatísticas do Data Lake"""
    total_credentials: int
    unique_domains: int
    unique_email_domains: int
    by_complexity: dict
    by_pattern: dict
    recent_ingestions: int
    avg_password_strength: float


class TimelineItem(BaseModel):
    """Item da timeline"""
    date: str
    count: int


class TopDomainItem(BaseModel):
    """Item de top domínio"""
    domain: str
    count: int


# ============================================================
# NOVOS ENDPOINTS OTIMIZADOS (V2)
# ============================================================

@router.post("/count", response_model=CountResponse)
async def count_credentials(request: CountRequest):
    """
    Conta credenciais rapidamente sem retornar dados.
    Ideal para mostrar ao usuário quantos resultados existem antes de carregar.

    Performance:
    - Domínio de email: ~50ms
    - Email exato: ~10ms
    - Busca genérica: ~1-5s
    """
    start_time = time.time()

    try:
        client = ElasticsearchClient.get_client()

        # Constrói query otimizada
        es_query, detected_type, timeout_sec = build_optimized_query(
            request.query, request.mode
        )

        # Executa count (mais rápido que search)
        response = await client.count(
            index=INDEX_NAME,
            body={"query": es_query}
        )

        count = response["count"]
        search_time = int((time.time() - start_time) * 1000)

        # Estima tempo de carregamento baseado no tipo
        if detected_type in ["email_exact", "email_domain", "url_domain"]:
            estimated = "<1s"
        elif count > 100000:
            estimated = "30-60s"
        elif count > 10000:
            estimated = "5-15s"
        else:
            estimated = "1-5s"

        logger.info(f"📊 Count '{request.query}' [{detected_type}]: {count} em {search_time}ms")

        return CountResponse(
            count=count,
            query=request.query,
            mode=request.mode.value,
            detected_type=detected_type,
            search_time_ms=search_time,
            estimated_load_time=estimated
        )

    except Exception as e:
        logger.error(f"❌ Erro no count: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search-v2", response_model=SearchV2Response)
async def search_credentials_v2(request: SearchV2Request):
    """
    Busca otimizada com detecção automática do melhor tipo de query.

    Modos:
    - auto: Detecta automaticamente (recomendado)
    - email_domain: Busca por domínio de email (@empresa.com)
    - url_domain: Busca por domínio de URL (site.com)
    - email_exact: Busca email exato (joao@empresa.com)
    - contains: Busca genérica (pode ser lenta)

    Performance por tipo:
    - email_exact: ~10ms
    - email_domain/url_domain: ~100ms
    - contains/generic: 5-60s (limitado)
    """
    start_time = time.time()

    try:
        client = ElasticsearchClient.get_client()

        # Constrói query otimizada
        es_query, detected_type, timeout_sec = build_optimized_query(
            request.query, request.mode
        )

        offset = (request.page - 1) * request.page_size

        # Configurações baseadas no tipo de busca
        if detected_type == "generic":
            # Busca genérica: limita resultados e usa terminate_after
            track_total = 50000
            terminate_after = 50000
        else:
            # Buscas otimizadas: pode contar todos
            track_total = True
            terminate_after = None

        # Monta body da query
        body = {
            "query": es_query,
            "from": offset,
            "size": request.page_size,
            "sort": [
                {"_score": {"order": "desc"}},
                {"ingestao_timestamp": {"order": "desc", "unmapped_type": "date"}}
            ],
            "_source": [
                "usuario", "senha", "url", "dominio_email", "dominio_url",
                "complexidade_senha", "forca_senha", "tamanho_senha",
                "data_breach", "arquivo", "grupo_telegram", "padrao_detectado"
            ],
            "timeout": f"{timeout_sec}s",
            "track_total_hits": track_total
        }

        if terminate_after:
            body["terminate_after"] = terminate_after

        # Executa busca
        response = await client.search(index=INDEX_NAME, body=body)

        # Processa resultados
        timed_out = response.get("timed_out", False)
        total_hits = response["hits"]["total"]
        total = total_hits["value"] if isinstance(total_hits, dict) else total_hits

        results = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            results.append(CredentialResult(
                usuario=source.get("usuario", ""),
                senha=source.get("senha", ""),
                url=source.get("url"),
                dominio_email=source.get("dominio_email"),
                dominio_url=source.get("dominio_url"),
                complexidade_senha=source.get("complexidade_senha"),
                forca_senha=source.get("forca_senha"),
                tamanho_senha=source.get("tamanho_senha"),
                data_breach=source.get("data_breach"),
                arquivo=source.get("arquivo"),
                grupo_telegram=source.get("grupo_telegram"),
                padrao_detectado=source.get("padrao_detectado")
            ))

        search_time = int((time.time() - start_time) * 1000)
        total_pages = (total + request.page_size - 1) // request.page_size if total > 0 else 1

        logger.info(f"🔍 Search-v2 '{request.query}' [{detected_type}]: {total} resultados em {search_time}ms")

        return SearchV2Response(
            total=total,
            page=request.page,
            page_size=request.page_size,
            total_pages=total_pages,
            results=results,
            query=request.query,
            mode=request.mode.value,
            detected_type=detected_type,
            search_time_ms=search_time,
            timed_out=timed_out
        )

    except Exception as e:
        logger.error(f"❌ Erro no search-v2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/by-domain/{domain}")
async def search_by_domain_fast(
    domain: str = Path(..., min_length=3, description="Domínio para buscar"),
    domain_type: str = Query(default="email", description="Tipo: email ou url"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200)
):
    """
    Busca otimizada por domínio específico (term query - muito rápida).

    Exemplos:
    - /by-domain/riachuelo.com.br?domain_type=email
    - /by-domain/facebook.com?domain_type=url

    Performance: ~100ms para qualquer quantidade de resultados
    """
    start_time = time.time()

    try:
        client = ElasticsearchClient.get_client()

        domain_lower = domain.lower().lstrip('@')
        field = "dominio_email" if domain_type == "email" else "dominio_url"
        offset = (page - 1) * page_size

        # Term query - muito rápida
        query = {"term": {field: domain_lower}}

        response = await client.search(
            index=INDEX_NAME,
            body={
                "query": query,
                "from": offset,
                "size": page_size,
                "sort": [
                    {"ingestao_timestamp": {"order": "desc", "unmapped_type": "date"}}
                ],
                "_source": [
                    "usuario", "senha", "url", "dominio_email", "dominio_url",
                    "complexidade_senha", "forca_senha", "data_breach", "arquivo"
                ],
                "track_total_hits": True
            }
        )

        total = response["hits"]["total"]["value"]
        results = []

        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            results.append({
                "usuario": source.get("usuario", ""),
                "senha": source.get("senha", ""),
                "url": source.get("url"),
                "dominio_email": source.get("dominio_email"),
                "dominio_url": source.get("dominio_url"),
                "complexidade_senha": source.get("complexidade_senha"),
                "forca_senha": source.get("forca_senha"),
                "data_breach": source.get("data_breach"),
                "arquivo": source.get("arquivo")
            })

        search_time = int((time.time() - start_time) * 1000)

        logger.info(f"⚡ By-domain '{domain}' [{domain_type}]: {total} em {search_time}ms")

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
            "results": results,
            "domain": domain,
            "domain_type": domain_type,
            "search_time_ms": search_time
        }

    except Exception as e:
        logger.error(f"❌ Erro no by-domain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# ENDPOINTS LEGACY (mantidos para compatibilidade)
# ============================================================

@router.get("/search", response_model=SearchResponse)
async def search_credentials(
    q: str = Query(..., min_length=3, description="Termo de busca (min 3 caracteres)"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    domain_filter: Optional[str] = Query(default=None, description="Filtrar por domínio"),
    complexity_filter: Optional[str] = Query(default=None, description="Filtrar por complexidade"),
    search_type: str = Query(default="wildcard", description="Tipo: wildcard (padrão) ou prefix (rápido)"),
    field: str = Query(default="all", description="Campo: all, usuario, dominio_email, dominio_url")
):
    """
    Busca credenciais no Data Lake (230M+ documentos).

    Tipos de busca:
    - wildcard: Busca completa (ex: "riachuelo" encontra "joao@riachuelo.com.br") - 30-60s
    - prefix: Busca rápida por prefixo (ex: "john" encontra "john@email.com") - ~1s

    Campos:
    - all: Busca em todos os campos
    - usuario: Apenas no campo de usuário/email (mais rápido)
    - dominio_email: Apenas no domínio do email
    - dominio_url: Apenas no domínio da URL
    """
    import time
    start_time = time.time()

    try:
        client = ElasticsearchClient.get_client()

        # Calcula offset
        offset = (page - 1) * page_size
        q_lower = q.lower()

        # Define campos baseado no parâmetro field
        if field == "usuario":
            search_fields = ["usuario"]
        elif field == "dominio_email":
            search_fields = ["dominio_email"]
        elif field == "dominio_url":
            search_fields = ["dominio_url"]
        else:  # all
            search_fields = ["usuario", "dominio_email", "dominio_url"]

        # Escolhe estratégia de busca baseada no tipo
        if search_type == "wildcard":
            # Busca wildcard - LENTA mas mais flexível
            should_clauses = [
                {"wildcard": {f: {"value": f"*{q_lower}*", "case_insensitive": True}}}
                for f in search_fields
            ]
        else:
            # Busca prefix - RÁPIDA (padrão)
            should_clauses = []
            for f in search_fields:
                # Term exato (muito rápido)
                should_clauses.append({"term": {f: {"value": q_lower, "boost": 10}}})
                # Prefix (rápido)
                should_clauses.append({"prefix": {f: {"value": q_lower, "boost": 3}}})

        must_clauses = [
            {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }
        ]

        # Filtros opcionais
        if domain_filter:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"dominio_email": domain_filter.lower()}},
                        {"term": {"dominio_url": domain_filter.lower()}}
                    ],
                    "minimum_should_match": 1
                }
            })

        if complexity_filter:
            must_clauses.append({"term": {"complexidade_senha": complexity_filter}})

        query = {
            "bool": {
                "must": must_clauses
            }
        }

        # Executa busca com timeout
        response = await client.search(
            index=INDEX_NAME,
            body={
                "query": query,
                "from": offset,
                "size": page_size,
                "sort": [
                    {"ingestao_timestamp": {"order": "desc", "unmapped_type": "date"}},
                    "_score"
                ],
                "_source": [
                    "usuario", "senha", "url", "dominio_email", "dominio_url",
                    "complexidade_senha", "forca_senha", "tamanho_senha",
                    "data_breach", "arquivo", "grupo_telegram", "padrao_detectado"
                ],
                "timeout": "120s",  # 2 minutos para buscas wildcard em 230M docs
                "track_total_hits": 10000  # Limita contagem para performance
            }
        )

        # Processa resultados
        total = response["hits"]["total"]["value"]
        results = []

        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            results.append(CredentialResult(
                usuario=source.get("usuario", ""),
                senha=source.get("senha", ""),
                url=source.get("url"),
                dominio_email=source.get("dominio_email"),
                dominio_url=source.get("dominio_url"),
                complexidade_senha=source.get("complexidade_senha"),
                forca_senha=source.get("forca_senha"),
                tamanho_senha=source.get("tamanho_senha"),
                data_breach=source.get("data_breach"),
                arquivo=source.get("arquivo"),
                grupo_telegram=source.get("grupo_telegram"),
                padrao_detectado=source.get("padrao_detectado")
            ))

        search_time = int((time.time() - start_time) * 1000)
        total_pages = (total + page_size - 1) // page_size

        logger.info(f"🔍 Busca '{q}': {total} resultados em {search_time}ms")

        return SearchResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            results=results,
            query=q,
            search_time_ms=search_time
        )

    except Exception as e:
        logger.error(f"❌ Erro na busca: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Statistics Endpoint
# ============================================================

@router.get("/stats", response_model=DataLakeStats)
async def get_datalake_stats():
    """Retorna estatísticas do Data Lake de credenciais"""
    try:
        client = ElasticsearchClient.get_client()

        # Total de credenciais
        count_response = await client.count(index=INDEX_NAME)
        total = count_response["count"]

        # Agregações
        agg_response = await client.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "aggs": {
                    "unique_email_domains": {
                        "cardinality": {"field": "dominio_email"}
                    },
                    "unique_url_domains": {
                        "cardinality": {"field": "dominio_url"}
                    },
                    "by_complexity": {
                        "terms": {"field": "complexidade_senha", "size": 10}
                    },
                    "by_pattern": {
                        "terms": {"field": "padrao_detectado", "size": 10}
                    },
                    "avg_strength": {
                        "avg": {"field": "forca_senha"}
                    },
                    "recent_7d": {
                        "filter": {
                            "range": {
                                "ingestao_timestamp": {
                                    "gte": "now-7d/d"
                                }
                            }
                        }
                    }
                }
            }
        )

        aggs = agg_response["aggregations"]

        # Processa complexidade
        by_complexity = {}
        for bucket in aggs["by_complexity"]["buckets"]:
            by_complexity[bucket["key"]] = bucket["doc_count"]

        # Processa padrões
        by_pattern = {}
        for bucket in aggs["by_pattern"]["buckets"]:
            by_pattern[bucket["key"]] = bucket["doc_count"]

        return DataLakeStats(
            total_credentials=total,
            unique_domains=aggs["unique_url_domains"]["value"],
            unique_email_domains=aggs["unique_email_domains"]["value"],
            by_complexity=by_complexity,
            by_pattern=by_pattern,
            recent_ingestions=aggs["recent_7d"]["doc_count"],
            avg_password_strength=round(aggs["avg_strength"]["value"] or 0, 1)
        )

    except Exception as e:
        logger.error(f"❌ Erro ao obter stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Timeline Endpoint
# ============================================================

@router.get("/timeline")
async def get_breach_timeline(
    months: int = Query(default=12, ge=1, le=24)
):
    """Retorna timeline de vazamentos por mês (usando data_breach)"""
    try:
        client = ElasticsearchClient.get_client()

        response = await client.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "query": {
                    "range": {
                        "data_breach": {
                            "gte": f"now-{months}M/M"
                        }
                    }
                },
                "aggs": {
                    "timeline": {
                        "date_histogram": {
                            "field": "data_breach",
                            "calendar_interval": "month",
                            "format": "yyyy-MM"
                        }
                    }
                }
            }
        )

        timeline = []
        for bucket in response["aggregations"]["timeline"]["buckets"]:
            timeline.append({
                "date": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })

        return {"timeline": timeline, "months": months}

    except Exception as e:
        logger.error(f"❌ Erro ao obter timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Top Domains Endpoint
# ============================================================

@router.get("/top-domains")
async def get_top_domains(
    domain_type: str = Query(default="email", description="Tipo: email ou url"),
    limit: int = Query(default=20, ge=5, le=100)
):
    """Retorna os domínios mais frequentes"""
    try:
        client = ElasticsearchClient.get_client()

        field = "dominio_email" if domain_type == "email" else "dominio_url"

        response = await client.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "aggs": {
                    "top_domains": {
                        "terms": {
                            "field": field,
                            "size": limit
                        }
                    }
                }
            }
        )

        domains = []
        for bucket in response["aggregations"]["top_domains"]["buckets"]:
            domains.append({
                "domain": bucket["key"],
                "count": bucket["doc_count"]
            })

        return {"domains": domains, "type": domain_type}

    except Exception as e:
        logger.error(f"❌ Erro ao obter top domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Search by Domain Endpoint
# ============================================================

@router.get("/by-domain")
async def search_by_domain(
    domain: str = Query(..., min_length=3, description="Domínio para buscar"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200)
):
    """Busca credenciais de um domínio específico"""
    import time
    start_time = time.time()

    try:
        client = ElasticsearchClient.get_client()

        offset = (page - 1) * page_size

        # Busca em ambos os campos de domínio
        query = {
            "bool": {
                "should": [
                    {"term": {"dominio_email": domain.lower()}},
                    {"term": {"dominio_url": domain.lower()}},
                    {"wildcard": {"dominio_email": f"*{domain.lower()}*"}},
                    {"wildcard": {"dominio_url": f"*{domain.lower()}*"}}
                ],
                "minimum_should_match": 1
            }
        }

        response = await client.search(
            index=INDEX_NAME,
            body={
                "query": query,
                "from": offset,
                "size": page_size,
                "sort": [
                    {"ingestao_timestamp": {"order": "desc", "unmapped_type": "date"}}
                ],
                "_source": [
                    "usuario", "senha", "url", "dominio_email", "dominio_url",
                    "complexidade_senha", "forca_senha", "data_breach", "arquivo"
                ]
            }
        )

        total = response["hits"]["total"]["value"]
        results = []

        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            results.append({
                "usuario": source.get("usuario", ""),
                "senha": source.get("senha", ""),
                "url": source.get("url"),
                "dominio_email": source.get("dominio_email"),
                "dominio_url": source.get("dominio_url"),
                "complexidade_senha": source.get("complexidade_senha"),
                "forca_senha": source.get("forca_senha"),
                "data_breach": source.get("data_breach"),
                "arquivo": source.get("arquivo")
            })

        search_time = int((time.time() - start_time) * 1000)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
            "results": results,
            "domain": domain,
            "search_time_ms": search_time
        }

    except Exception as e:
        logger.error(f"❌ Erro na busca por domínio: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Top Sources (Arquivos/Grupos) Endpoint
# ============================================================

@router.get("/top-sources")
async def get_top_sources(
    source_type: str = Query(default="arquivo", description="Tipo: arquivo ou grupo_telegram"),
    limit: int = Query(default=20, ge=5, le=100)
):
    """Retorna as fontes mais frequentes"""
    try:
        client = ElasticsearchClient.get_client()

        field = "arquivo" if source_type == "arquivo" else "grupo_telegram"

        response = await client.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "aggs": {
                    "top_sources": {
                        "terms": {
                            "field": field,
                            "size": limit
                        }
                    }
                }
            }
        )

        sources = []
        for bucket in response["aggregations"]["top_sources"]["buckets"]:
            sources.append({
                "source": bucket["key"],
                "count": bucket["doc_count"]
            })

        return {"sources": sources, "type": source_type}

    except Exception as e:
        logger.error(f"❌ Erro ao obter top sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))
