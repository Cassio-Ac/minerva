"""
CPF (Cadastro de Pessoas Físicas) Schemas
Módulo para consulta de dados de CPF
"""
from typing import Optional, List
from datetime import date
from pydantic import BaseModel


class CPFEntry(BaseModel):
    """Single CPF entry from Elasticsearch"""
    cpf: str
    nome: str
    sexo: str
    nasc: Optional[date] = None


class CPFSearchRequest(BaseModel):
    """Request model for CPF search"""
    query: Optional[str] = None  # Busca geral (CPF ou nome)
    cpf: Optional[str] = None  # Busca específica por CPF
    nome: Optional[str] = None  # Busca específica por nome
    sexo: Optional[str] = None  # Filtro por sexo (M, F, I)
    nasc_from: Optional[date] = None  # Data de nascimento inicial
    nasc_to: Optional[date] = None  # Data de nascimento final
    idade_min: Optional[int] = None  # Idade mínima
    idade_max: Optional[int] = None  # Idade máxima
    limit: int = 50
    offset: int = 0
    sort_by: str = "nome.keyword"
    sort_order: str = "asc"


class CPFSearchResponse(BaseModel):
    """Response model for CPF search"""
    total: int
    results: List[CPFEntry]
    facets: Optional[dict] = None
    took_ms: int


class CPFStats(BaseModel):
    """CPF statistics"""
    total_records: int
    by_sexo: dict
    by_decade: List[dict]
    by_age_range: List[dict]
    timeline: List[dict]


class CPFChatRequest(BaseModel):
    """Request model for CPF chat"""
    query: str
    max_context: int = 10


class CPFChatResponse(BaseModel):
    """Response model for CPF chat"""
    answer: str
    context_used: int
