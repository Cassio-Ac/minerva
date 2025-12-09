"""
Anthropic Claude LLM Client
Handles interactions with Anthropic's Claude API
"""

import logging
from typing import Dict, Any, List, Optional, AsyncGenerator
from anthropic import AsyncAnthropic
import json

logger = logging.getLogger(__name__)


class AnthropicClient:
    """Client for Anthropic Claude API"""

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
        Initialize Anthropic client

        Args:
            api_key: Anthropic API key
            model_name: Model name (e.g., 'claude-3-5-sonnet-20241022')
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            api_base_url: Optional custom base URL
            extra_config: Additional configuration
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.extra_config = extra_config or {}

        # Initialize Anthropic client
        client_kwargs = {"api_key": api_key}
        if api_base_url:
            client_kwargs["base_url"] = api_base_url

        self.client = AsyncAnthropic(**client_kwargs)

        logger.info(f"✅ Initialized Anthropic client with model {model_name}")

    async def generate(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a response from Claude

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system message
            temperature: Override default temperature
            max_tokens: Override default max tokens
            tools: Optional list of tool definitions

        Returns:
            Response dictionary with 'content', 'role', and optionally 'tool_calls'
        """
        try:
            # Prepare request parameters
            request_params = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            }

            if system:
                request_params["system"] = system

            if tools:
                request_params["tools"] = tools

            # Make API call
            response = await self.client.messages.create(**request_params)

            # Format response
            result = {
                "role": "assistant",
                "content": "",
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
            }

            # Extract content and tool calls
            for block in response.content:
                if block.type == "text":
                    result["content"] += block.text
                elif block.type == "tool_use":
                    if "tool_calls" not in result:
                        result["tool_calls"] = []
                    result["tool_calls"].append({
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

            logger.info(f"✅ Generated response from Anthropic ({response.usage.output_tokens} tokens)")
            return result

        except Exception as e:
            logger.error(f"❌ Anthropic API error: {e}")
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
        Stream a response from Claude

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
            # Prepare request parameters
            request_params = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
                "stream": True,
            }

            if system:
                request_params["system"] = system

            if tools:
                request_params["tools"] = tools

            # Stream API call
            async with self.client.messages.stream(**request_params) as stream:
                async for text in stream.text_stream:
                    yield text

            logger.info("✅ Completed streaming response from Anthropic")

        except Exception as e:
            logger.error(f"❌ Anthropic streaming error: {e}")
            raise

    def get_provider_info(self) -> Dict[str, Any]:
        """
        Get information about this provider

        Returns:
            Dictionary with provider details
        """
        return {
            "provider_type": "anthropic",
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "supports_tools": True,
            "supports_streaming": True,
        }
