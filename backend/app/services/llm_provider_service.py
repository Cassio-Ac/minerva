"""
LLM Provider Service
Handles CRUD operations for LLM provider configurations
"""

import logging
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update

from app.models.llm_provider import LLMProvider
from app.services.encryption_service import get_encryption_service

logger = logging.getLogger(__name__)


class LLMProviderService:
    """Service for managing LLM provider configurations"""

    def __init__(self, db: AsyncSession):
        """
        Initialize the service

        Args:
            db: Async database session
        """
        self.db = db
        self.encryption_service = get_encryption_service()

    async def create_provider(
        self,
        name: str,
        provider_type: str,
        model_name: str,
        api_key: str,
        api_base_url: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        is_active: bool = True,
        is_default: bool = False,
        extra_config: Optional[Dict[str, Any]] = None,
    ) -> LLMProvider:
        """Create a new LLM provider configuration"""
        # Encrypt the API key
        encrypted_key = self.encryption_service.encrypt(api_key)

        # If this should be the default, unset other defaults
        if is_default:
            await self._unset_all_defaults()

        # Create the provider
        provider = LLMProvider(
            name=name,
            provider_type=provider_type,
            model_name=model_name,
            api_key_encrypted=encrypted_key,
            api_base_url=api_base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            is_active=is_active,
            is_default=is_default,
            extra_config=extra_config,
        )

        self.db.add(provider)
        await self.db.commit()
        await self.db.refresh(provider)

        logger.info(f"✅ Created LLM provider: {name} ({provider_type}/{model_name})")
        return provider

    async def get_provider(self, provider_id: str) -> Optional[LLMProvider]:
        """Get a provider by ID"""
        result = await self.db.execute(
            select(LLMProvider).where(LLMProvider.id == provider_id)
        )
        return result.scalar_one_or_none()

    async def get_provider_with_decrypted_key(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """Get a provider by ID with decrypted API key"""
        provider = await self.get_provider(provider_id)
        if not provider:
            return None

        return self._provider_to_dict_with_key(provider)

    async def list_providers(
        self,
        provider_type: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[LLMProvider]:
        """List all providers with optional filters"""
        query = select(LLMProvider)

        if provider_type is not None:
            query = query.where(LLMProvider.provider_type == provider_type)

        if is_active is not None:
            query = query.where(LLMProvider.is_active == is_active)

        query = query.order_by(LLMProvider.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_default_provider(self) -> Optional[LLMProvider]:
        """Get the default provider"""
        result = await self.db.execute(
            select(LLMProvider).where(
                and_(LLMProvider.is_default == True, LLMProvider.is_active == True)
            )
        )
        return result.scalar_one_or_none()

    async def get_default_provider_with_key(self) -> Optional[Dict[str, Any]]:
        """Get the default provider with decrypted API key"""
        provider = await self.get_default_provider()
        if not provider:
            return None

        return self._provider_to_dict_with_key(provider)

    async def update_provider(
        self,
        provider_id: str,
        name: Optional[str] = None,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base_url: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        is_active: Optional[bool] = None,
        is_default: Optional[bool] = None,
        extra_config: Optional[Dict[str, Any]] = None,
    ) -> Optional[LLMProvider]:
        """Update a provider configuration"""
        provider = await self.get_provider(provider_id)
        if not provider:
            return None

        # Update fields if provided
        if name is not None:
            provider.name = name

        if model_name is not None:
            provider.model_name = model_name

        if api_key is not None:
            provider.api_key_encrypted = self.encryption_service.encrypt(api_key)

        if api_base_url is not None:
            provider.api_base_url = api_base_url

        if temperature is not None:
            provider.temperature = temperature

        if max_tokens is not None:
            provider.max_tokens = max_tokens

        if is_active is not None:
            provider.is_active = is_active

        if is_default is not None and is_default:
            await self._unset_all_defaults()
            provider.is_default = True
        elif is_default is not None:
            provider.is_default = False

        if extra_config is not None:
            provider.extra_config = extra_config

        await self.db.commit()
        await self.db.refresh(provider)

        logger.info(f"✅ Updated LLM provider: {provider.name}")
        return provider

    async def delete_provider(self, provider_id: str) -> bool:
        """Delete a provider"""
        provider = await self.get_provider(provider_id)
        if not provider:
            return False

        await self.db.delete(provider)
        await self.db.commit()

        logger.info(f"🗑️ Deleted LLM provider: {provider.name}")
        return True

    async def set_default_provider(self, provider_id: str) -> Optional[LLMProvider]:
        """Set a provider as the default"""
        return await self.update_provider(provider_id, is_default=True)

    async def _unset_all_defaults(self):
        """Unset all default flags"""
        await self.db.execute(
            update(LLMProvider)
            .where(LLMProvider.is_default == True)
            .values(is_default=False)
        )

    def _provider_to_dict_with_key(self, provider: LLMProvider) -> Dict[str, Any]:
        """Convert provider to dict with decrypted API key"""
        decrypted_key = self.encryption_service.decrypt(provider.api_key_encrypted)

        return {
            "id": provider.id,
            "name": provider.name,
            "provider_type": provider.provider_type,
            "model_name": provider.model_name,
            "api_key": decrypted_key,  # Decrypted!
            "api_base_url": provider.api_base_url,
            "temperature": provider.temperature,
            "max_tokens": provider.max_tokens,
            "is_active": provider.is_active,
            "is_default": provider.is_default,
            "extra_config": provider.extra_config,
            "created_at": provider.created_at,
            "updated_at": provider.updated_at,
        }


def get_llm_provider_service(db: AsyncSession) -> LLMProviderService:
    """Get LLM provider service instance"""
    return LLMProviderService(db)
