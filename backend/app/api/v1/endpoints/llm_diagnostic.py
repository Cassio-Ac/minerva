"""
LLM Provider Diagnostic Endpoint
Test and verify LLM provider configuration
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from app.db.database import get_db
from app.services.llm_provider_service import get_llm_provider_service
from app.services.llm_factory import LLMFactory

router = APIRouter()


@router.get("/diagnostic", response_model=Dict[str, Any])
async def run_llm_diagnostic(db: AsyncSession = Depends(get_db)):
    """
    Run comprehensive diagnostics on LLM providers

    Returns detailed information about:
    - All configured providers
    - Default provider status
    - Client creation test
    - API connectivity test
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
                "name": p["name"],
                "provider_type": p["provider_type"],
                "model_name": p["model_name"],
                "is_active": p["is_active"],
                "is_default": p["is_default"],
                "temperature": p.get("temperature"),
                "max_tokens": p.get("max_tokens"),
                "has_base_url": bool(p.get("api_base_url"))
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
                    "response_content": response.get("content", "")[:100],  # First 100 chars
                    "model_used": response.get("model"),
                    "tokens_used": {
                        "input": response.get("usage", {}).get("input_tokens", 0),
                        "output": response.get("usage", {}).get("output_tokens", 0)
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
