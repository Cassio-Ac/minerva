"""
Configurações da aplicação
Carrega variáveis de ambiente via Pydantic Settings
"""

from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    """Configurações da aplicação"""

    # Application
    APP_NAME: str = "Dashboard AI"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = True
    SECRET_KEY: str = "dev-secret-key"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5174", "http://localhost:5180", "http://localhost:3000"]

    # Elasticsearch (opcional - pode ser configurado via UI)
    # Suporte para múltiplos servidores via página de Configurações
    ES_URL: Optional[str] = None  # Não obrigatório no startup
    ES_USERNAME: Optional[str] = None
    ES_PASSWORD: Optional[str] = None
    ES_TIMEOUT: int = 30
    ES_MAX_RETRIES: int = 3

    # Redis (opcional)
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_ENABLED: bool = False

    # LLM (Claude via Databricks)
    DATABRICKS_HOST: str = ""
    DATABRICKS_URL: Optional[str] = None  # Alias para DATABRICKS_HOST
    DATABRICKS_TOKEN: str = ""
    DATABRICKS_MODEL: Optional[str] = None  # Alias para LLM_MODEL
    LLM_MODEL: str = "databricks-meta-llama-3-1-70b-instruct"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 4000

    # JWT
    JWT_SECRET_KEY: str = "jwt-secret-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # External API Keys
    OTX_API_KEY: Optional[str] = None  # AlienVault OTX
    OPENAI_API_KEY: Optional[str] = None  # OpenAI

    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "allow"  # Permitir campos extras temporariamente
    }


# Singleton instance
settings = Settings()
