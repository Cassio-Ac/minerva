"""
LLM Provider API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel

from app.db.database import get_db
from app.services.llm_provider_service import get_llm_provider_service
from app.services.llm_factory import LLMFactory
from app.models.llm_provider import LLMProvider

router = APIRouter()


# Pydantic models for request/response
class LLMProviderCreate(BaseModel):
    """Request model for creating LLM provider"""
    name: str
    provider_type: str  # 'anthropic', 'openai', 'databricks'
    model_name: str
    api_key: str
    api_base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4000
    is_active: bool = True
    is_default: bool = False
    extra_config: Optional[dict] = None


class LLMProviderUpdate(BaseModel):
    """Request model for updating LLM provider"""
    name: Optional[str] = None
    model_name: Optional[str] = None
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None
    extra_config: Optional[dict] = None


class LLMProviderResponse(BaseModel):
    """Response model for LLM provider (without API key)"""
    id: str
    name: str
    provider_type: str
    model_name: str
    api_base_url: Optional[str]
    temperature: float
    max_tokens: int
    is_active: bool
    is_default: bool
    extra_config: Optional[dict]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.post("/", response_model=LLMProviderResponse)
async def create_provider(
    provider: LLMProviderCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new LLM provider configuration
    """
    service = get_llm_provider_service(db)

    created = await service.create_provider(
        name=provider.name,
        provider_type=provider.provider_type,
        model_name=provider.model_name,
        api_key=provider.api_key,
        api_base_url=provider.api_base_url,
        temperature=provider.temperature,
        max_tokens=provider.max_tokens,
        is_active=provider.is_active,
        is_default=provider.is_default,
        extra_config=provider.extra_config,
    )

    return LLMProviderResponse(
        id=str(created.id),
        name=created.name,
        provider_type=created.provider_type,
        model_name=created.model_name,
        api_base_url=created.api_base_url,
        temperature=created.temperature,
        max_tokens=created.max_tokens,
        is_active=created.is_active,
        is_default=created.is_default,
        extra_config=created.extra_config,
        created_at=created.created_at.isoformat(),
        updated_at=created.updated_at.isoformat(),
    )


@router.get("/", response_model=List[LLMProviderResponse])
async def list_providers(
    provider_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List all LLM providers with optional filters
    """
    service = get_llm_provider_service(db)
    providers = await service.list_providers(provider_type=provider_type, is_active=is_active)

    return [
        LLMProviderResponse(
            id=str(p.id),
            name=p.name,
            provider_type=p.provider_type,
            model_name=p.model_name,
            api_base_url=p.api_base_url,
            temperature=p.temperature,
            max_tokens=p.max_tokens,
            is_active=p.is_active,
            is_default=p.is_default,
            extra_config=p.extra_config,
            created_at=p.created_at.isoformat(),
            updated_at=p.updated_at.isoformat(),
        )
        for p in providers
    ]


@router.get("/default", response_model=LLMProviderResponse)
async def get_default_provider(db: AsyncSession = Depends(get_db)):
    """
    Get the default LLM provider
    """
    service = get_llm_provider_service(db)
    provider = await service.get_default_provider()

    if not provider:
        raise HTTPException(status_code=404, detail="No default provider configured")

    return LLMProviderResponse(
        id=str(provider.id),
        name=provider.name,
        provider_type=provider.provider_type,
        model_name=provider.model_name,
        api_base_url=provider.api_base_url,
        temperature=provider.temperature,
        max_tokens=provider.max_tokens,
        is_active=provider.is_active,
        is_default=provider.is_default,
        extra_config=provider.extra_config,
        created_at=provider.created_at.isoformat(),
        updated_at=provider.updated_at.isoformat(),
    )


@router.get("/diagnostic")
async def run_diagnostic(db: AsyncSession = Depends(get_db)):
    """
    Run comprehensive diagnostics on LLM providers

    Tests:
    - Lists all configured providers
    - Checks default provider
    - Tests client creation
    - Tests API connectivity

    Returns detailed diagnostic information
    """
    result = {
        "success": False,
        "providers": [],
        "default_provider": None,
        "client_test": None,
        "api_test": None,
        "errors": []
    }

    try:
        # Step 1: List all providers
        service = get_llm_provider_service(db)
        providers = await service.list_providers()

        result["providers"] = [
            {
                "name": p.name,
                "provider_type": p.provider_type,
                "model_name": p.model_name,
                "is_active": p.is_active,
                "is_default": p.is_default,
                "temperature": p.temperature,
                "max_tokens": p.max_tokens,
                "has_base_url": bool(p.api_base_url)
            }
            for p in providers
        ]

        if not providers:
            result["errors"].append("No providers configured")
            return result

        # Step 2: Get default provider
        default_provider = await service.get_default_provider_with_key()

        if not default_provider:
            result["errors"].append("No default provider set")
            return result

        result["default_provider"] = {
            "name": default_provider["name"],
            "provider_type": default_provider["provider_type"],
            "model_name": default_provider["model_name"],
            "has_api_key": bool(default_provider.get("api_key")),
            "api_key_length": len(default_provider.get("api_key", "")) if default_provider.get("api_key") else 0,
            "has_base_url": bool(default_provider.get("api_base_url"))
        }

        if not default_provider.get("api_key"):
            result["errors"].append("Default provider has no API key")
            return result

        # Step 3: Test client creation
        try:
            client = LLMFactory.create_client_from_config(default_provider)

            if not client:
                result["errors"].append("Failed to create LLM client")
                return result

            provider_info = client.get_provider_info()
            result["client_test"] = {
                "success": True,
                "provider_type": provider_info["provider_type"],
                "model_name": provider_info["model_name"],
                "supports_tools": provider_info.get("supports_tools", False),
                "supports_streaming": provider_info.get("supports_streaming", False)
            }

            # Step 4: Test basic API call
            try:
                test_messages = [{"role": "user", "content": "Say 'ok' in one word"}]
                response = await client.generate(
                    messages=test_messages,
                    temperature=0.1,
                    max_tokens=10
                )

                result["api_test"] = {
                    "success": True,
                    "response_content": response.get("content", "")[:100],
                    "model_used": response.get("model"),
                    "tokens_used": {
                        "input": response.get("usage", {}).get("input_tokens", 0),
                        "output": response.get("output_tokens", 0)
                    }
                }

                result["success"] = True

            except Exception as api_error:
                result["api_test"] = {
                    "success": False,
                    "error": str(api_error)
                }
                result["errors"].append(f"API test failed: {str(api_error)}")

        except Exception as client_error:
            result["client_test"] = {
                "success": False,
                "error": str(client_error)
            }
            result["errors"].append(f"Client creation failed: {str(client_error)}")

    except Exception as e:
        result["errors"].append(f"Fatal error: {str(e)}")

    return result


@router.get("/{provider_id}", response_model=LLMProviderResponse)
async def get_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific LLM provider by ID
    """
    service = get_llm_provider_service(db)
    provider = await service.get_provider(provider_id)

    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    return LLMProviderResponse(
        id=str(provider.id),
        name=provider.name,
        provider_type=provider.provider_type,
        model_name=provider.model_name,
        api_base_url=provider.api_base_url,
        temperature=provider.temperature,
        max_tokens=provider.max_tokens,
        is_active=provider.is_active,
        is_default=provider.is_default,
        extra_config=provider.extra_config,
        created_at=provider.created_at.isoformat(),
        updated_at=provider.updated_at.isoformat(),
    )


@router.put("/{provider_id}", response_model=LLMProviderResponse)
async def update_provider(
    provider_id: str,
    provider_update: LLMProviderUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update an existing LLM provider
    """
    service = get_llm_provider_service(db)

    updated = await service.update_provider(
        provider_id=provider_id,
        name=provider_update.name,
        model_name=provider_update.model_name,
        api_key=provider_update.api_key,
        api_base_url=provider_update.api_base_url,
        temperature=provider_update.temperature,
        max_tokens=provider_update.max_tokens,
        is_active=provider_update.is_active,
        is_default=provider_update.is_default,
        extra_config=provider_update.extra_config,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Provider not found")

    return LLMProviderResponse(
        id=str(updated.id),
        name=updated.name,
        provider_type=updated.provider_type,
        model_name=updated.model_name,
        api_base_url=updated.api_base_url,
        temperature=updated.temperature,
        max_tokens=updated.max_tokens,
        is_active=updated.is_active,
        is_default=updated.is_default,
        extra_config=updated.extra_config,
        created_at=updated.created_at.isoformat(),
        updated_at=updated.updated_at.isoformat(),
    )


@router.post("/{provider_id}/set-default", response_model=LLMProviderResponse)
async def set_default_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Set a provider as the default
    """
    service = get_llm_provider_service(db)
    updated = await service.set_default_provider(provider_id)

    if not updated:
        raise HTTPException(status_code=404, detail="Provider not found")

    return LLMProviderResponse(
        id=str(updated.id),
        name=updated.name,
        provider_type=updated.provider_type,
        model_name=updated.model_name,
        api_base_url=updated.api_base_url,
        temperature=updated.temperature,
        max_tokens=updated.max_tokens,
        is_active=updated.is_active,
        is_default=updated.is_default,
        extra_config=updated.extra_config,
        created_at=updated.created_at.isoformat(),
        updated_at=updated.updated_at.isoformat(),
    )


@router.delete("/{provider_id}")
async def delete_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an LLM provider
    """
    service = get_llm_provider_service(db)
    success = await service.delete_provider(provider_id)

    if not success:
        raise HTTPException(status_code=404, detail="Provider not found")

    return {"message": "Provider deleted successfully"}


@router.get("/models/suggestions")
async def get_model_suggestions():
    """
    Get suggested model names for each provider type
    """
    return {
        "anthropic": [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ],
        "openai": [
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo",
            "gpt-4o",
        ],
        "databricks": [
            "databricks-claude-3-7-sonnet",
            "databricks-claude-3-5-sonnet",
            "databricks-meta-llama-3-1-405b-instruct",
        ],
    }
