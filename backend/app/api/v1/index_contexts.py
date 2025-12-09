"""
Index Contexts API Endpoints
Gerenciar contextos de índices Elasticsearch
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging
import uuid

from app.db.database import get_db
from app.models.index_context import IndexContext

router = APIRouter()
logger = logging.getLogger(__name__)


class IndexContextCreate(BaseModel):
    """Schema para criar contexto de índice"""
    es_server_id: str
    index_pattern: str
    description: Optional[str] = None
    business_context: Optional[str] = None
    tips: Optional[str] = None
    field_descriptions: Optional[Dict[str, str]] = None
    query_examples: Optional[List[Dict[str, str]]] = None
    is_active: bool = True


class IndexContextUpdate(BaseModel):
    """Schema para atualizar contexto de índice"""
    description: Optional[str] = None
    business_context: Optional[str] = None
    tips: Optional[str] = None
    field_descriptions: Optional[Dict[str, str]] = None
    query_examples: Optional[List[Dict[str, str]]] = None
    is_active: Optional[bool] = None


class IndexContextResponse(BaseModel):
    """Schema de resposta"""
    id: str
    es_server_id: str
    index_pattern: str
    description: Optional[str]
    business_context: Optional[str]
    tips: Optional[str]
    field_descriptions: Dict[str, str]
    query_examples: List[Dict[str, str]]
    is_active: bool
    created_at: str
    updated_at: str


@router.get("/", response_model=List[IndexContextResponse])
async def list_index_contexts(
    es_server_id: Optional[str] = None,
    index_pattern: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Lista todos os contextos de índice

    Query params:
    - es_server_id: Filtrar por servidor ES
    - index_pattern: Filtrar por padrão de índice
    - is_active: Filtrar por status ativo
    """
    logger.info(f"Listing index contexts (es_server={es_server_id}, pattern={index_pattern})")

    try:
        query = select(IndexContext)

        # Filtros
        if es_server_id:
            query = query.where(IndexContext.es_server_id == es_server_id)
        if index_pattern:
            query = query.where(IndexContext.index_pattern.ilike(f"%{index_pattern}%"))
        if is_active is not None:
            query = query.where(IndexContext.is_active == is_active)

        result = await db.execute(query)
        contexts = result.scalars().all()

        return [context.to_dict() for context in contexts]

    except Exception as e:
        logger.error(f"Error listing index contexts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{context_id}", response_model=IndexContextResponse)
async def get_index_context(context_id: str, db: AsyncSession = Depends(get_db)):
    """
    Obtém contexto de índice por ID
    """
    logger.info(f"Getting index context: {context_id}")

    try:
        result = await db.execute(
            select(IndexContext).where(IndexContext.id == context_id)
        )
        context = result.scalar_one_or_none()

        if not context:
            raise HTTPException(status_code=404, detail=f"Index context {context_id} not found")

        return context.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting index context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=IndexContextResponse, status_code=201)
async def create_index_context(data: IndexContextCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria novo contexto de índice
    """
    logger.info(f"Creating index context for pattern: {data.index_pattern}")

    try:
        # Verificar se já existe contexto para esse índice
        result = await db.execute(
            select(IndexContext).where(
                IndexContext.es_server_id == data.es_server_id,
                IndexContext.index_pattern == data.index_pattern
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Context for index pattern '{data.index_pattern}' already exists"
            )

        # Criar contexto
        context = IndexContext(
            id=str(uuid.uuid4()),
            **data.dict()
        )

        db.add(context)
        await db.commit()
        await db.refresh(context)

        logger.info(f"✅ Index context created: {context.id}")
        return context.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating index context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{context_id}", response_model=IndexContextResponse)
async def update_index_context(
    context_id: str,
    data: IndexContextUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Atualiza contexto de índice
    """
    logger.info(f"Updating index context: {context_id}")

    try:
        # Buscar contexto
        result = await db.execute(
            select(IndexContext).where(IndexContext.id == context_id)
        )
        context = result.scalar_one_or_none()

        if not context:
            raise HTTPException(status_code=404, detail=f"Index context {context_id} not found")

        # Atualizar campos fornecidos
        update_data = data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(context, field, value)

        await db.commit()
        await db.refresh(context)

        logger.info(f"✅ Index context updated: {context_id}")
        return context.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating index context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{context_id}", status_code=204)
async def delete_index_context(context_id: str, db: AsyncSession = Depends(get_db)):
    """
    Deleta contexto de índice
    """
    logger.info(f"Deleting index context: {context_id}")

    try:
        # Buscar contexto
        result = await db.execute(
            select(IndexContext).where(IndexContext.id == context_id)
        )
        context = result.scalar_one_or_none()

        if not context:
            raise HTTPException(status_code=404, detail=f"Index context {context_id} not found")

        # Deletar
        await db.delete(context)
        await db.commit()

        logger.info(f"✅ Index context deleted: {context_id}")
        return None

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting index context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/by-pattern/{index_pattern}", response_model=Optional[IndexContextResponse])
async def get_context_by_pattern(
    index_pattern: str,
    es_server_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Busca contexto por padrão de índice

    Útil para o chat buscar contexto quando usuário menciona um índice
    """
    logger.info(f"Finding context for pattern: {index_pattern}")

    try:
        query = select(IndexContext).where(
            IndexContext.index_pattern == index_pattern,
            IndexContext.is_active == True
        )

        if es_server_id:
            query = query.where(IndexContext.es_server_id == es_server_id)

        result = await db.execute(query)
        context = result.scalar_one_or_none()

        if not context:
            return None

        return context.to_dict()

    except Exception as e:
        logger.error(f"Error finding context by pattern: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{context_id}/llm-context")
async def get_llm_formatted_context(context_id: str, db: AsyncSession = Depends(get_db)):
    """
    Retorna contexto formatado para LLM

    Útil para preview de como será enviado à LLM
    """
    logger.info(f"Getting LLM formatted context: {context_id}")

    try:
        result = await db.execute(
            select(IndexContext).where(IndexContext.id == context_id)
        )
        context = result.scalar_one_or_none()

        if not context:
            raise HTTPException(status_code=404, detail=f"Index context {context_id} not found")

        return {
            "context_id": context.id,
            "index_pattern": context.index_pattern,
            "formatted_context": context.get_llm_context()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting LLM context: {e}")
        raise HTTPException(status_code=500, detail=str(e))
