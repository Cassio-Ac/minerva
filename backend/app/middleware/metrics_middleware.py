"""
Middleware para coleta automática de métricas do sistema
"""

import time
import logging
from typing import Callable, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import AsyncSessionLocal
from app.services.metrics_service import MetricsService
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware para coletar métricas de cada requisição HTTP
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Ignorar requisições de health check e WebSocket
        if request.url.path in ["/health", "/", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        if request.url.path.startswith("/socket.io"):
            return await call_next(request)

        # Extrair user_id do token JWT no Authorization header
        user_id = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            try:
                payload = AuthService.decode_access_token(token)
                if payload:
                    user_id = payload.get("sub")  # sub contém o username
            except Exception:
                pass  # Ignorar erros de token inválido

        # Medir tempo de resposta
        start_time = time.time()

        # Processar requisição
        response = None
        error = None
        status_code = 200

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as e:
            error = e
            status_code = 500
            raise
        finally:
            # Calcular tempo de resposta
            response_time = (time.time() - start_time) * 1000  # ms

            # Coletar métricas de forma assíncrona (não bloquear resposta)
            try:
                async with AsyncSessionLocal() as db:
                    # Preparar labels base
                    base_labels = {
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": status_code
                    }
                    if user_id:
                        base_labels["user_id"] = str(user_id)

                    # Métrica de uso (request count)
                    await MetricsService.record_metric(
                        db=db,
                        metric_type="usage",
                        metric_name="request_count",
                        value=1,
                        unit="requests",
                        labels=base_labels.copy()
                    )

                    # Métrica de performance (response time)
                    await MetricsService.record_metric(
                        db=db,
                        metric_type="performance",
                        metric_name="response_time",
                        value=response_time,
                        unit="ms",
                        labels=base_labels.copy()
                    )

                    # Métrica de erro (se houver)
                    if error or status_code >= 400:
                        error_labels = base_labels.copy()
                        error_labels["error"] = str(error) if error else None
                        await MetricsService.record_metric(
                            db=db,
                            metric_type="error",
                            metric_name="error_count",
                            value=1,
                            unit="errors",
                            labels=error_labels
                        )

                    logger.debug(f"📊 Metrics recorded: {request.method} {request.url.path} - {response_time:.2f}ms")
            except Exception as e:
                # Não deixar erro na coleta de métricas afetar a resposta
                logger.error(f"❌ Error recording metrics: {e}")
