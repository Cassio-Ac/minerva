"""
Databricks LLM Client
Handles interactions with Databricks model serving endpoints
"""

import logging
from typing import Dict, Any, List, Optional, AsyncGenerator
import httpx
import json

logger = logging.getLogger(__name__)


class DatabricksClient:
    """Client for Databricks model serving"""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        api_base_url: Optional[str] = None,
        extra_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize Databricks client

        Args:
            api_key: Databricks token
            model_name: Model serving endpoint name
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            api_base_url: Databricks serving endpoint URL
            extra_config: Additional configuration
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_base_url = api_base_url
        self.api_key = api_key
        self.extra_config = extra_config or {}

        if not api_base_url:
            raise ValueError("api_base_url is required for Databricks client")

        logger.info(f"✅ Initialized Databricks client with endpoint {api_base_url}")

    async def generate(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a response from Databricks

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system message
            temperature: Override default temperature
            max_tokens: Override default max tokens
            tools: Optional list of tool definitions for Claude models

        Returns:
            Response dictionary with 'content', 'role'
        """
        try:
            # Prepare messages (include system if provided)
            api_messages = []
            if system:
                api_messages.append({"role": "system", "content": system})
            api_messages.extend(messages)

            # Prepare request payload
            payload = {
                "messages": api_messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            }

            # Add tools if provided (for Claude models)
            if tools:
                payload["tools"] = tools

            # Headers
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            # Make API call
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    self.api_base_url,
                    headers=headers,
                    json=payload
                )
                response.raise_for_status()
                result = response.json()

            # Extract content from response
            if "choices" in result and len(result["choices"]) > 0:
                message = result["choices"][0]["message"]
                content = message.get("content") or ""

                # Debug: log se content veio null
                if content == "" and message.get("content") is None:
                    logger.warning(f"⚠️ Databricks returned null content. Message: {message}")
            else:
                raise ValueError(f"Unexpected response from Databricks: {result}")

            # Format response
            output = {
                "role": "assistant",
                "content": content,
                "model": self.model_name,
            }

            # Add tool_calls if present
            if "tool_calls" in message:
                output["tool_calls"] = message["tool_calls"]

            # Add usage info if available
            if "usage" in result:
                output["usage"] = {
                    "input_tokens": result["usage"].get("prompt_tokens", 0),
                    "output_tokens": result["usage"].get("completion_tokens", 0),
                }

            logger.info(f"✅ Generated response from Databricks ({len(content)} chars)")
            return output

        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Databricks API error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Databricks error: {e}")
            raise

    async def stream_generate(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncGenerator[str, None]:
        """
        Stream a response from Databricks

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system message
            temperature: Override default temperature
            max_tokens: Override default max tokens
            tools: Optional list of tool definitions

        Yields:
            Content chunks as they arrive
        """
        try:
            # Prepare messages
            api_messages = []
            if system:
                api_messages.append({"role": "system", "content": system})
            api_messages.extend(messages)

            # Prepare request payload with streaming enabled
            payload = {
                "messages": api_messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
                "stream": True,
            }

            # Headers
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            # Stream API call
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST",
                    self.api_base_url,
                    headers=headers,
                    json=payload
                ) as response:
                    response.raise_for_status()

                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data = line[6:]  # Remove "data: " prefix
                            if data == "[DONE]":
                                break

                            try:
                                chunk = json.loads(data)
                                if "choices" in chunk and len(chunk["choices"]) > 0:
                                    delta = chunk["choices"][0].get("delta", {})
                                    if "content" in delta:
                                        yield delta["content"]
                            except json.JSONDecodeError:
                                continue

            logger.info("✅ Completed streaming response from Databricks")

        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Databricks streaming error: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"❌ Databricks streaming error: {e}")
            raise

    def get_provider_info(self) -> Dict[str, Any]:
        """
        Get information about this provider

        Returns:
            Dictionary with provider details
        """
        return {
            "provider_type": "databricks",
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "supports_tools": False,  # Databricks doesn't support tool calling
            "supports_streaming": True,
        }
