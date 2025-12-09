"""
LLM Factory
Creates LLM client instances based on provider configuration
"""

import logging
from typing import Optional, Dict, Any, Union
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.llm_clients import AnthropicClient, OpenAIClient, DatabricksClient
from app.services.llm_provider_service import get_llm_provider_service

logger = logging.getLogger(__name__)


LLMClient = Union[AnthropicClient, OpenAIClient, DatabricksClient]


class LLMFactory:
    """Factory for creating LLM client instances"""

    @staticmethod
    async def create_client_from_provider_id(
        db: AsyncSession,
        provider_id: str
    ) -> Optional[LLMClient]:
        """
        Create LLM client from provider ID

        Args:
            db: Database session
            provider_id: LLM provider ID

        Returns:
            LLM client instance or None
        """
        provider_service = get_llm_provider_service(db)
        provider_data = await provider_service.get_provider_with_decrypted_key(provider_id)

        if not provider_data:
            logger.error(f"❌ Provider {provider_id} not found")
            return None

        return LLMFactory.create_client_from_config(provider_data)

    @staticmethod
    async def create_client_from_default(db: AsyncSession) -> Optional[LLMClient]:
        """
        Create LLM client from default provider

        Args:
            db: Database session

        Returns:
            LLM client instance or None
        """
        provider_service = get_llm_provider_service(db)
        provider_data = await provider_service.get_default_provider_with_key()

        if not provider_data:
            logger.error("❌ No default provider configured")
            return None

        return LLMFactory.create_client_from_config(provider_data)

    @staticmethod
    def create_client_from_config(provider_data: Dict[str, Any]) -> Optional[LLMClient]:
        """
        Create LLM client from provider configuration

        Args:
            provider_data: Provider configuration dict (must include decrypted api_key)

        Returns:
            LLM client instance or None
        """
        provider_type = provider_data.get("provider_type")
        api_key = provider_data.get("api_key")
        model_name = provider_data.get("model_name")
        temperature = provider_data.get("temperature", 0.1)
        max_tokens = provider_data.get("max_tokens", 4000)
        api_base_url = provider_data.get("api_base_url")
        extra_config = provider_data.get("extra_config")

        if not all([provider_type, api_key, model_name]):
            logger.error("❌ Invalid provider configuration: missing required fields")
            return None

        try:
            if provider_type == "anthropic":
                client = AnthropicClient(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    api_base_url=api_base_url,
                    extra_config=extra_config,
                )
                logger.info(f"✅ Created Anthropic client: {model_name}")
                return client

            elif provider_type == "openai":
                client = OpenAIClient(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    api_base_url=api_base_url,
                    extra_config=extra_config,
                )
                logger.info(f"✅ Created OpenAI client: {model_name}")
                return client

            elif provider_type == "databricks":
                if not api_base_url:
                    logger.error("❌ Databricks requires api_base_url")
                    return None

                client = DatabricksClient(
                    api_key=api_key,
                    model_name=model_name,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    api_base_url=api_base_url,
                    extra_config=extra_config,
                )
                logger.info(f"✅ Created Databricks client: {model_name}")
                return client

            else:
                logger.error(f"❌ Unknown provider type: {provider_type}")
                return None

        except Exception as e:
            logger.error(f"❌ Error creating LLM client: {e}")
            return None

    @staticmethod
    def create_client_from_env() -> Optional[LLMClient]:
        """
        Create LLM client from environment variables (legacy support)

        This is for backward compatibility with existing .env configuration

        Returns:
            LLM client instance or None
        """
        try:
            from app.core.config import settings

            # Check if OpenAI is configured
            openai_key = getattr(settings, 'OPENAI_API_KEY', None)
            openai_model = getattr(settings, 'OPENAI_MODEL', None)
            llm_provider = getattr(settings, 'LLM_PROVIDER', None)

            # Priority 1: OpenAI if explicitly set as LLM_PROVIDER
            if llm_provider == 'openai' and openai_key:
                client = OpenAIClient(
                    api_key=openai_key,
                    model_name=openai_model or 'gpt-4o-mini',
                    temperature=settings.LLM_TEMPERATURE,
                    max_tokens=settings.LLM_MAX_TOKENS,
                )
                logger.info(f"✅ Created OpenAI client from env: {openai_model or 'gpt-4o-mini'}")
                return client

            # Priority 2: Databricks (backward compatibility)
            databricks_url = settings.DATABRICKS_URL or settings.DATABRICKS_HOST
            databricks_token = settings.DATABRICKS_TOKEN
            model_name = settings.DATABRICKS_MODEL or settings.LLM_MODEL

            if databricks_url and databricks_token:
                client = DatabricksClient(
                    api_key=databricks_token,
                    model_name=model_name,
                    temperature=settings.LLM_TEMPERATURE,
                    max_tokens=settings.LLM_MAX_TOKENS,
                    api_base_url=databricks_url,
                )
                logger.info(f"✅ Created Databricks client from env: {model_name}")
                return client

            logger.warning("⚠️ No LLM provider configured in .env")
            return None

        except Exception as e:
            logger.error(f"❌ Error creating LLM client from env: {e}")
            return None
