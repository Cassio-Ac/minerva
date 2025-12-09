"""
Knowledge Documents API Endpoints
Gerenciar documentos de conhecimento
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
import logging
import uuid

from app.db.database import get_db
from app.models.knowledge_document import KnowledgeDocument

router = APIRouter()
logger = logging.getLogger(__name__)


class KnowledgeDocCreate(BaseModel):
    """Schema para criar documento"""
    title: str
    content: str
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    related_indices: Optional[List[str]] = None
    priority: int = 0
    is_active: bool = True


class KnowledgeDocUpdate(BaseModel):
    """Schema para atualizar documento"""
    title: Optional[str] = None
    content: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    related_indices: Optional[List[str]] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None


class KnowledgeDocResponse(BaseModel):
    """Schema de resposta"""
    id: str
    title: str
    content: str
    category: Optional[str]
    tags: List[str]
    related_indices: List[str]
    priority: int
    is_active: bool
    created_at: str
    updated_at: str


@router.get("/", response_model=List[KnowledgeDocResponse])
async def list_knowledge_docs(
    category: Optional[str] = None,
    tag: Optional[str] = None,
    index_pattern: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Lista documentos de conhecimento

    Query params:
    - category: Filtrar por categoria
    - tag: Filtrar por tag
    - index_pattern: Filtrar por índice relacionado
    - is_active: Filtrar por status ativo
    """
    logger.info(f"Listing knowledge docs (category={category}, tag={tag})")

    try:
        query = select(KnowledgeDocument).order_by(
            KnowledgeDocument.priority.desc(),
            KnowledgeDocument.created_at.desc()
        )

        # Filtros
        if category:
            query = query.where(KnowledgeDocument.category == category)

        if is_active is not None:
            query = query.where(KnowledgeDocument.is_active == is_active)

        # Executar query
        result = await db.execute(query)
        docs = result.scalars().all()

        # Filtros que precisam ser aplicados em Python (ARRAY fields)
        if tag:
            docs = [doc for doc in docs if doc.tags and tag in doc.tags]

        if index_pattern:
            docs = [doc for doc in docs if doc.matches_indices([index_pattern])]

        return [doc.to_dict() for doc in docs]

    except Exception as e:
        logger.error(f"Error listing knowledge docs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{doc_id}", response_model=KnowledgeDocResponse)
async def get_knowledge_doc(doc_id: str, db: AsyncSession = Depends(get_db)):
    """
    Obtém documento por ID
    """
    logger.info(f"Getting knowledge doc: {doc_id}")

    try:
        result = await db.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        )
        doc = result.scalar_one_or_none()

        if not doc:
            raise HTTPException(status_code=404, detail=f"Knowledge document {doc_id} not found")

        return doc.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting knowledge doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=KnowledgeDocResponse, status_code=201)
async def create_knowledge_doc(data: KnowledgeDocCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria novo documento de conhecimento
    """
    logger.info(f"Creating knowledge doc: {data.title}")

    try:
        # Criar documento
        doc = KnowledgeDocument(
            id=str(uuid.uuid4()),
            **data.dict()
        )

        db.add(doc)
        await db.commit()
        await db.refresh(doc)

        logger.info(f"✅ Knowledge doc created: {doc.id}")
        return doc.to_dict()

    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating knowledge doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{doc_id}", response_model=KnowledgeDocResponse)
async def update_knowledge_doc(
    doc_id: str,
    data: KnowledgeDocUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Atualiza documento de conhecimento
    """
    logger.info(f"Updating knowledge doc: {doc_id}")

    try:
        # Buscar documento
        result = await db.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        )
        doc = result.scalar_one_or_none()

        if not doc:
            raise HTTPException(status_code=404, detail=f"Knowledge document {doc_id} not found")

        # Atualizar campos fornecidos
        update_data = data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(doc, field, value)

        await db.commit()
        await db.refresh(doc)

        logger.info(f"✅ Knowledge doc updated: {doc_id}")
        return doc.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating knowledge doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{doc_id}", status_code=204)
async def delete_knowledge_doc(doc_id: str, db: AsyncSession = Depends(get_db)):
    """
    Deleta documento de conhecimento
    """
    logger.info(f"Deleting knowledge doc: {doc_id}")

    try:
        # Buscar documento
        result = await db.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        )
        doc = result.scalar_one_or_none()

        if not doc:
            raise HTTPException(status_code=404, detail=f"Knowledge document {doc_id} not found")

        # Deletar
        await db.delete(doc)
        await db.commit()

        logger.info(f"✅ Knowledge doc deleted: {doc_id}")
        return None

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting knowledge doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories/list")
async def list_categories(db: AsyncSession = Depends(get_db)):
    """
    Lista todas as categorias únicas
    """
    logger.info("Listing knowledge doc categories")

    try:
        result = await db.execute(
            select(KnowledgeDocument.category)
            .distinct()
            .where(KnowledgeDocument.category.isnot(None))
        )
        categories = [row[0] for row in result.all()]

        return {"categories": sorted(categories)}

    except Exception as e:
        logger.error(f"Error listing categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tags/list")
async def list_tags(db: AsyncSession = Depends(get_db)):
    """
    Lista todas as tags únicas
    """
    logger.info("Listing knowledge doc tags")

    try:
        result = await db.execute(
            select(KnowledgeDocument.tags).where(KnowledgeDocument.tags.isnot(None))
        )

        # Flatten all tags
        all_tags = set()
        for row in result.all():
            if row[0]:
                all_tags.update(row[0])

        return {"tags": sorted(list(all_tags))}

    except Exception as e:
        logger.error(f"Error listing tags: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search")
async def search_knowledge_docs(
    query: str,
    category: Optional[str] = None,
    limit: int = 10,
    db: AsyncSession = Depends(get_db)
):
    """
    Busca documentos por texto (título ou conteúdo)

    Útil para RAG - encontrar documentos relevantes para uma pergunta
    """
    logger.info(f"Searching knowledge docs: {query}")

    try:
        # Busca básica por ILIKE (pode ser melhorado com full-text search)
        search_query = select(KnowledgeDocument).where(
            KnowledgeDocument.is_active == True,
            or_(
                KnowledgeDocument.title.ilike(f"%{query}%"),
                KnowledgeDocument.content.ilike(f"%{query}%")
            )
        ).order_by(
            KnowledgeDocument.priority.desc()
        ).limit(limit)

        if category:
            search_query = search_query.where(KnowledgeDocument.category == category)

        result = await db.execute(search_query)
        docs = result.scalars().all()

        return {
            "query": query,
            "count": len(docs),
            "results": [
                {
                    "id": doc.id,
                    "title": doc.title,
                    "excerpt": doc.get_excerpt(200),
                    "category": doc.category,
                    "tags": doc.tags or [],
                    "priority": doc.priority
                }
                for doc in docs
            ]
        }

    except Exception as e:
        logger.error(f"Error searching knowledge docs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{doc_id}/llm-context")
async def get_llm_formatted_doc(
    doc_id: str,
    max_length: int = 1000,
    db: AsyncSession = Depends(get_db)
):
    """
    Retorna documento formatado para LLM

    Útil para preview de como será enviado à LLM
    """
    logger.info(f"Getting LLM formatted doc: {doc_id}")

    try:
        result = await db.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        )
        doc = result.scalar_one_or_none()

        if not doc:
            raise HTTPException(status_code=404, detail=f"Knowledge document {doc_id} not found")

        return {
            "doc_id": doc.id,
            "title": doc.title,
            "formatted_context": doc.get_llm_context(max_length)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting LLM doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))
