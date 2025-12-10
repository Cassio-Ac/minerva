"""
API Endpoints para Consulta Externa de Credenciais

Endpoints:
- POST /credentials/query - Executa consulta externa
- GET /credentials/query/{id} - Obtém resultado de consulta
- GET /credentials/query/{id}/html - Obtém HTML renderizado
- GET /credentials/query/{id}/download - Baixa arquivo resultado
- GET /credentials/history - Lista histórico de consultas
- GET /credentials/stats - Estatísticas do módulo
- GET /credentials/bots - Lista bots disponíveis
- GET /credentials/session - Info da sessão Telegram
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.database import AsyncSessionLocal
from app.credentials.services.telegram_bot_service import telegram_bot_service
from app.credentials.services.query_type_detector import detect_query_type, QueryTypeDetector
from app.credentials.models.external_query import ExternalQuery
from app.schemas.credentials import (
    ExternalQueryRequest,
    ExternalQueryResponse,
    ExternalQueryHistory,
    ExternalQueryHistoryItem,
    CredentialsStats,
    HTMLResultResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["Credentials"])


# ============================================================
# Query Endpoints
# ============================================================

@router.post("/query", response_model=ExternalQueryResponse)
async def execute_external_query(
    request: ExternalQueryRequest,
    background_tasks: BackgroundTasks
):
    """
    Executa uma consulta externa a um bot de leak.
    O tipo de consulta (email, cpf, phone, etc.) é detectado automaticamente.

    - **query_value**: Valor a consultar (tipo detectado automaticamente)
    - **auto_download**: Se True, baixa o resultado automaticamente
    """
    import uuid

    query_id = uuid.uuid4()

    # Detecta automaticamente o tipo de consulta
    detected_type, normalized_value = detect_query_type(request.query_value)
    type_display = QueryTypeDetector.get_display_type(detected_type)

    logger.info(f"🔍 Nova consulta: [{detected_type}] {normalized_value[:30]}...")

    try:
        # Executa a consulta no bot (usa valor normalizado)
        result = await telegram_bot_service.query_bot(
            query_value=normalized_value,
            bot_key="database_lookup",
            auto_download=request.auto_download
        )

        # Prepara URLs se houver arquivos
        html_url = None
        download_url = None

        if result.get("html_path"):
            html_url = f"/api/v1/credentials/query/{query_id}/html"
            download_url = f"/api/v1/credentials/query/{query_id}/download"

        # Salva no banco de dados (em background para não travar a resposta)
        async def save_query():
            async with AsyncSessionLocal() as session:
                query_record = ExternalQuery(
                    id=query_id,
                    query_type=detected_type,
                    query_value=normalized_value,
                    bot_id="6574456300",
                    bot_name=result.get("bot_name", "Database Lookup"),
                    found=result.get("found", False),
                    result_count=result.get("result_count", 0),
                    result_preview=result.get("result_preview"),
                    result_html_path=result.get("html_path"),
                    result_file_path=result.get("file_path"),
                    raw_response=result,
                    status="completed" if result.get("success") else "error",
                    error_message=result.get("error"),
                    telegram_account="angello",
                    created_at=datetime.utcnow()
                )
                session.add(query_record)
                await session.commit()
                logger.info(f"✅ Consulta salva: {query_id}")

        background_tasks.add_task(save_query)

        return ExternalQueryResponse(
            id=query_id,
            query_type=detected_type,
            query_type_display=type_display,
            query_value=normalized_value,
            bot_name=result.get("bot_name", "Database Lookup"),
            found=result.get("found", False),
            result_count=result.get("result_count", 0),
            result_preview=result.get("result_preview"),
            html_url=html_url,
            download_url=download_url,
            status="completed" if result.get("success") else "error",
            error_message=result.get("error"),
            created_at=datetime.utcnow()
        )

    except Exception as e:
        logger.error(f"❌ Erro na consulta: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/query/{query_id}", response_model=ExternalQueryResponse)
async def get_query_result(query_id: UUID):
    """Obtém o resultado de uma consulta específica"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ExternalQuery).where(ExternalQuery.id == query_id)
        )
        query = result.scalar_one_or_none()

        if not query:
            raise HTTPException(status_code=404, detail="Consulta não encontrada")

        html_url = None
        download_url = None

        if query.result_html_path:
            html_url = f"/api/v1/credentials/query/{query_id}/html"
            download_url = f"/api/v1/credentials/query/{query_id}/download"

        return ExternalQueryResponse(
            id=query.id,
            query_type=query.query_type,
            query_value=query.query_value,
            bot_name=query.bot_name or "Database Lookup",
            found=query.found,
            result_count=query.result_count,
            result_preview=query.result_preview,
            html_url=html_url,
            download_url=download_url,
            status=query.status,
            error_message=query.error_message,
            created_at=query.created_at
        )


@router.get("/query/{query_id}/html", response_class=HTMLResponse)
async def get_query_html(query_id: UUID):
    """
    Retorna o HTML do resultado para renderização.
    O conteúdo é retornado diretamente para ser exibido na página.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ExternalQuery).where(ExternalQuery.id == query_id)
        )
        query = result.scalar_one_or_none()

        if not query:
            raise HTTPException(status_code=404, detail="Consulta não encontrada")

        if not query.result_html_path:
            raise HTTPException(status_code=404, detail="Nenhum HTML disponível")

        html_path = Path(query.result_html_path)
        if not html_path.exists():
            raise HTTPException(status_code=404, detail="Arquivo HTML não encontrado")

        # Lê o conteúdo HTML
        html_content = html_path.read_text(encoding='utf-8', errors='ignore')

        return HTMLResponse(content=html_content)


@router.get("/query/{query_id}/download")
async def download_query_result(query_id: UUID):
    """
    Baixa o arquivo de resultado da consulta.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ExternalQuery).where(ExternalQuery.id == query_id)
        )
        query = result.scalar_one_or_none()

        if not query:
            raise HTTPException(status_code=404, detail="Consulta não encontrada")

        file_path = query.result_html_path or query.result_file_path
        if not file_path:
            raise HTTPException(status_code=404, detail="Nenhum arquivo disponível")

        path = Path(file_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Arquivo não encontrado")

        return FileResponse(
            path=str(path),
            filename=path.name,
            media_type="application/octet-stream"
        )


# ============================================================
# History & Stats Endpoints
# ============================================================

@router.get("/history", response_model=ExternalQueryHistory)
async def get_query_history(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
    query_type: Optional[str] = None,
    found_only: bool = False
):
    """Lista histórico de consultas com filtros"""
    from datetime import timedelta

    RETENTION_DAYS = 7

    async with AsyncSessionLocal() as session:
        # Base query
        stmt = select(ExternalQuery)

        # Filtros
        if query_type:
            stmt = stmt.where(ExternalQuery.query_type == query_type)
        if found_only:
            stmt = stmt.where(ExternalQuery.found == True)

        # Ordenação e paginação
        stmt = stmt.order_by(desc(ExternalQuery.created_at)).offset(offset).limit(limit)

        result = await session.execute(stmt)
        queries = result.scalars().all()

        # Total count
        count_stmt = select(func.count(ExternalQuery.id))
        if query_type:
            count_stmt = count_stmt.where(ExternalQuery.query_type == query_type)
        if found_only:
            count_stmt = count_stmt.where(ExternalQuery.found == True)

        total_result = await session.execute(count_stmt)
        total = total_result.scalar() or 0

        # Processa cada query para verificar disponibilidade do HTML
        history_items = []
        now = datetime.utcnow()

        for q in queries:
            # Verifica se o HTML ainda existe
            html_available = False
            if q.result_html_path and q.status != 'expired':
                html_path = Path(q.result_html_path)
                html_available = html_path.exists()

            # Calcula dias restantes
            days_old = (now - q.created_at).days
            days_remaining = max(0, RETENTION_DAYS - days_old)

            history_items.append(ExternalQueryHistoryItem(
                id=q.id,
                query_type=q.query_type,
                query_value=q.query_value,
                bot_name=q.bot_name,
                found=q.found,
                result_count=q.result_count,
                status=q.status,
                created_at=q.created_at,
                created_by=q.created_by,
                html_available=html_available,
                days_remaining=days_remaining
            ))

        return ExternalQueryHistory(
            total=total,
            queries=history_items
        )


@router.get("/stats", response_model=CredentialsStats)
async def get_credentials_stats():
    """Retorna estatísticas do módulo Credentials"""
    from datetime import date

    async with AsyncSessionLocal() as session:
        # Total de consultas
        total_result = await session.execute(
            select(func.count(ExternalQuery.id))
        )
        total_queries = total_result.scalar() or 0

        # Consultas hoje
        today = date.today()
        today_result = await session.execute(
            select(func.count(ExternalQuery.id)).where(
                func.date(ExternalQuery.created_at) == today
            )
        )
        queries_today = today_result.scalar() or 0

        # Consultas com resultados
        found_result = await session.execute(
            select(func.count(ExternalQuery.id)).where(ExternalQuery.found == True)
        )
        queries_with_results = found_result.scalar() or 0

        # Taxa de sucesso
        success_rate = (queries_with_results / total_queries * 100) if total_queries > 0 else 0

        # Top query types
        types_result = await session.execute(
            select(ExternalQuery.query_type, func.count(ExternalQuery.id))
            .group_by(ExternalQuery.query_type)
        )
        top_query_types = {row[0]: row[1] for row in types_result.fetchall()}

        # Consultas recentes
        recent_result = await session.execute(
            select(ExternalQuery)
            .order_by(desc(ExternalQuery.created_at))
            .limit(10)
        )
        recent_queries = recent_result.scalars().all()

        # Processa consultas recentes com info de disponibilidade
        RETENTION_DAYS = 7
        now = datetime.utcnow()
        recent_items = []

        for q in recent_queries:
            html_available = False
            if q.result_html_path and q.status != 'expired':
                html_path = Path(q.result_html_path)
                html_available = html_path.exists()

            days_old = (now - q.created_at).days
            days_remaining = max(0, RETENTION_DAYS - days_old)

            recent_items.append(ExternalQueryHistoryItem(
                id=q.id,
                query_type=q.query_type,
                query_value=q.query_value,
                bot_name=q.bot_name,
                found=q.found,
                result_count=q.result_count,
                status=q.status,
                created_at=q.created_at,
                created_by=q.created_by,
                html_available=html_available,
                days_remaining=days_remaining
            ))

        return CredentialsStats(
            total_queries=total_queries,
            queries_today=queries_today,
            queries_with_results=queries_with_results,
            success_rate=round(success_rate, 1),
            top_query_types=top_query_types,
            recent_queries=recent_items
        )


# ============================================================
# Configuration Endpoints
# ============================================================

@router.get("/bots")
async def get_available_bots():
    """Lista bots disponíveis para consulta"""
    return {
        "bots": telegram_bot_service.get_available_bots()
    }


@router.get("/session")
async def get_session_info():
    """Retorna informações sobre a sessão Telegram atual"""
    return telegram_bot_service.get_session_info()
