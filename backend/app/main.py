"""
Dashboard AI v2.0 - FastAPI Application
Main entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import socketio
import logging

from app.core.config import settings
from app.api.v1 import widgets, chat, elasticsearch_api, es_servers, llm_providers, mcp_servers, mcp_execute
from app.api.v1 import dashboards_sql, conversations  # SQL versions
from app.api.v1 import index_contexts, knowledge_docs  # Knowledge system
from app.api.v1 import downloads  # Downloads
from app.api.v1 import auth, users  # Authentication & User management
from app.api.v1 import auth_sso, sso_providers, audit_logs  # SSO authentication & audit
from app.api.v1 import dashboard_permissions  # Dashboard permissions
from app.api.v1 import index_mcp_config  # Index MCP configuration
from app.api.v1 import cache  # Cache management
from app.api.v1 import metrics  # System metrics
from app.api.v1 import export  # Export (PDF/PNG)
from app.api.v1 import admin  # Admin endpoints
from app.api.v1 import csv_upload, index_access  # CSV upload and index access management
from app.api.v1 import rss, caveiratech, malpedia_library  # RSS feeds & CaveiraTech & Malpedia Library
from app.api.v1 import breaches  # Data Breaches & Leaks
from app.api.v1 import cves  # CVE Detection
from app.api.v1 import cpf  # CPF Lookup
from app.api.v1 import telegram, telegram_blacklist  # Telegram Intelligence
from app.cti.api import actors as cti_actors, families as cti_families, techniques as cti_techniques, enrichment as cti_enrichment, misp_feeds, ioc_enrichment, galaxy as cti_galaxy, otx_keys, otx_pulses, yara_rules  # CTI Module (isolated)
from app.credentials.api import external_query as credentials_external_query  # Credentials Module
from app.credentials.api import datalake as credentials_datalake  # Credentials Data Lake
from app.websocket import sio
from app.middleware.metrics_middleware import MetricsMiddleware

# Configurar logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Criar aplicação FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Sistema de Dashboards Interativos com IA para Elasticsearch",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Montar Socket.IO no FastAPI
socket_app = socketio.ASGIApp(
    sio,
    other_asgi_app=app,
    socketio_path="/socket.io"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Adicionar middleware de métricas
app.add_middleware(MetricsMiddleware)

# Incluir routers (usando versões SQL para dashboards e conversations)
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(auth_sso.router, prefix="/api/v1", tags=["sso-auth"])
app.include_router(sso_providers.router, prefix="/api/v1", tags=["sso-providers"])
app.include_router(audit_logs.router, prefix="/api/v1", tags=["audit-logs"])
app.include_router(users.router, prefix="/api/v1/users", tags=["user-management"])
app.include_router(dashboards_sql.router, prefix="/api/v1/dashboards", tags=["dashboards"])
app.include_router(widgets.router, prefix="/api/v1/widgets", tags=["widgets"])
app.include_router(chat.router, prefix="/api/v1/chat", tags=["chat"])
app.include_router(conversations.router, prefix="/api/v1/conversations", tags=["conversations"])
app.include_router(elasticsearch_api.router, prefix="/api/v1/elasticsearch", tags=["elasticsearch"])
app.include_router(es_servers.router, prefix="/api/v1/es-servers", tags=["es-servers"])
app.include_router(llm_providers.router, prefix="/api/v1/llm-providers", tags=["llm-providers"])
app.include_router(mcp_servers.router, prefix="/api/v1/mcp-servers", tags=["mcp-servers"])
app.include_router(mcp_execute.router, prefix="/api/v1/mcp", tags=["mcp-execution"])
app.include_router(index_contexts.router, prefix="/api/v1/index-contexts", tags=["knowledge"])
app.include_router(knowledge_docs.router, prefix="/api/v1/knowledge-docs", tags=["knowledge"])
app.include_router(downloads.router, prefix="/api/v1/downloads", tags=["downloads"])
app.include_router(dashboard_permissions.router, prefix="/api/v1/dashboard-permissions", tags=["dashboard-permissions"])
app.include_router(index_mcp_config.router, prefix="/api/v1/index-mcp-config", tags=["mcp-config"])
app.include_router(cache.router, prefix="/api/v1/cache", tags=["cache"])
app.include_router(metrics.router, prefix="/api/v1/metrics", tags=["metrics"])
app.include_router(export.router, prefix="/api/v1/export", tags=["export"])
app.include_router(admin.router, prefix="/api/v1", tags=["admin"])
app.include_router(csv_upload.router, prefix="/api/v1", tags=["csv-upload"])
app.include_router(index_access.router, prefix="/api/v1", tags=["index-access"])
app.include_router(rss.router, prefix="/api/v1", tags=["rss"])
app.include_router(caveiratech.router, prefix="/api/v1", tags=["caveiratech"])
app.include_router(malpedia_library.router, prefix="/api/v1", tags=["malpedia-library"])
app.include_router(breaches.router, prefix="/api/v1", tags=["breaches"])
app.include_router(cves.router, prefix="/api/v1", tags=["cves"])
app.include_router(cpf.router, prefix="/api/v1", tags=["cpf"])
app.include_router(telegram.router, prefix="/api/v1", tags=["telegram"])
app.include_router(telegram_blacklist.router, prefix="/api/v1", tags=["telegram"])

# CTI Module (Cyber Threat Intelligence) - Modular & Isolated
app.include_router(cti_actors.router, prefix="/api/v1/cti", tags=["CTI"])
app.include_router(cti_families.router, prefix="/api/v1/cti", tags=["CTI"])
app.include_router(cti_techniques.router, prefix="/api/v1/cti", tags=["CTI"])
app.include_router(cti_enrichment.router, prefix="/api/v1/cti", tags=["CTI Enrichment"])
app.include_router(misp_feeds.router, prefix="/api/v1/cti", tags=["CTI - MISP"])
app.include_router(ioc_enrichment.router, prefix="/api/v1/cti", tags=["CTI - IOC Enrichment"])
app.include_router(cti_galaxy.router, prefix="/api/v1/cti", tags=["CTI - MISP Galaxy"])
app.include_router(otx_keys.router, prefix="/api/v1/cti/otx", tags=["CTI - OTX"])
app.include_router(otx_pulses.router, prefix="/api/v1/cti/otx", tags=["CTI - OTX Pulses"])
app.include_router(yara_rules.router, prefix="/api/v1/cti/yara", tags=["CTI - YARA Rules"])

# Credentials Module (Leaked Credentials Lookup)
app.include_router(credentials_external_query.router, prefix="/api/v1", tags=["Credentials"])
app.include_router(credentials_datalake.router, prefix="/api/v1", tags=["Credentials - Data Lake"])

# Mount static files (profile photos, downloads, etc)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
async def startup_event():
    """Inicialização da aplicação"""
    logger.info(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # ========== 1. Inicializar PostgreSQL (metadados do sistema) ==========
    from app.db.database import test_connection, init_db

    try:
        # Testar conexão
        if await test_connection():
            logger.info("✅ PostgreSQL connected")
            # Criar tabelas (em produção, use Alembic migrations!)
            # await init_db()  # Commented: using Alembic migrations instead
            logger.info("✅ SQL Database tables managed by Alembic")
        else:
            logger.error("❌ PostgreSQL connection failed - app cannot start!")
            raise Exception("PostgreSQL is required")
    except Exception as e:
        logger.error(f"❌ Error initializing PostgreSQL: {e}")
        raise  # App não inicia sem banco SQL

    # ========== 2. Inicializar Elasticsearch (dados de negócio) ==========
    from app.db.elasticsearch import ElasticsearchClient

    try:
        # Conectar ao ES (usa config ou localhost)
        es_url = settings.ES_URL or "http://localhost:9200"
        ElasticsearchClient.initialize(
            url=es_url,
            username=settings.ES_USERNAME,
            password=settings.ES_PASSWORD
        )

        # Testar conexão
        if await ElasticsearchClient.ping():
            logger.info(f"✅ Elasticsearch connected: {es_url}")
            # Nota: Não criamos mais índices de metadados no ES!
        else:
            logger.warning("⚠️ Elasticsearch not available - data queries will not work")

    except Exception as e:
        logger.error(f"❌ Error initializing Elasticsearch: {e}")
        logger.warning("⚠️ Starting without Elasticsearch connection")

    # ========== 3. Inicializar cleanup de downloads ==========
    from app.api.v1.downloads import cleanup_old_files
    import asyncio

    async def periodic_cleanup():
        """Executa cleanup a cada 6 horas"""
        while True:
            try:
                logger.info("🧹 Starting periodic downloads cleanup...")
                await cleanup_old_files()
                # Aguardar 6 horas (21600 segundos)
                await asyncio.sleep(21600)
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")
                # Em caso de erro, tentar novamente em 1 hora
                await asyncio.sleep(3600)

    # Iniciar cleanup em background
    asyncio.create_task(periodic_cleanup())
    logger.info("✅ Periodic downloads cleanup scheduled (every 6 hours)")

    # ========== 3.5. Inicializar cleanup de credenciais ==========
    from app.credentials.services.cleanup_service import cleanup_expired_credentials

    async def periodic_credentials_cleanup():
        """Executa cleanup de credenciais a cada 6 horas"""
        while True:
            try:
                await cleanup_expired_credentials()
                # Aguardar 6 horas
                await asyncio.sleep(21600)
            except Exception as e:
                logger.error(f"Error in credentials cleanup: {e}")
                await asyncio.sleep(3600)

    asyncio.create_task(periodic_credentials_cleanup())
    logger.info("✅ Credentials cleanup scheduled (every 6 hours, retention: 7 days)")

    # ========== 4. Inicializar AD Sync Scheduler ==========
    from app.services.ad_sync_scheduler import get_ad_sync_scheduler

    try:
        # Iniciar scheduler (sincroniza a cada 6 horas)
        ad_scheduler = get_ad_sync_scheduler(interval_hours=6)
        ad_scheduler.start()
        logger.info("✅ AD Sync Scheduler started (every 6 hours)")
    except Exception as e:
        logger.error(f"❌ Error starting AD Sync Scheduler: {e}")
        logger.warning("⚠️ Starting without AD sync automation")

    # TODO: Inicializar Redis (se habilitado)
    # TODO: Inicializar LLM client

    logger.info(f"✅ Application started on {settings.HOST}:{settings.PORT}")


@app.on_event("shutdown")
async def shutdown_event():
    """Encerramento da aplicação"""
    logger.info("🛑 Shutting down application...")

    # Parar AD Sync Scheduler
    from app.services.ad_sync_scheduler import get_ad_sync_scheduler
    try:
        ad_scheduler = get_ad_sync_scheduler()
        await ad_scheduler.stop()
        logger.info("✅ AD Sync Scheduler stopped")
    except Exception as e:
        logger.error(f"Error stopping AD Sync Scheduler: {e}")

    # Fechar conexão PostgreSQL
    from app.db.database import close_db
    await close_db()

    # Fechar conexão Elasticsearch
    from app.db.elasticsearch import ElasticsearchClient
    await ElasticsearchClient.close()

    # TODO: Fechar Redis

    logger.info("✅ Application shutdown complete")


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check detalhado"""
    health_status = {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "services": {
            "elasticsearch": "checking...",  # TODO: verificar conexão
            "redis": "checking..." if settings.REDIS_ENABLED else "disabled"
        }
    }

    # TODO: Verificar conexões reais
    # try:
    #     es_client.ping()
    #     health_status["services"]["elasticsearch"] = "healthy"
    # except:
    #     health_status["services"]["elasticsearch"] = "unhealthy"

    return health_status


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handler global de exceções"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc) if settings.DEBUG else "An error occurred"
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:socket_app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
