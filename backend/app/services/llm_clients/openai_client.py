"""
OpenAI LLM Client
Handles interactions with OpenAI's API (GPT models)
"""

import logging
from typing import Dict, Any, List, Optional, AsyncGenerator
from openai import AsyncOpenAI
import json

logger = logging.getLogger(__name__)


class OpenAIClient:
    """Client for OpenAI API"""

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
        Initialize OpenAI client

        Args:
            api_key: OpenAI API key
            model_name: Model name (e.g., 'gpt-4', 'gpt-3.5-turbo')
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            api_base_url: Optional custom base URL
            extra_config: Additional configuration
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.extra_config = extra_config or {}

        # Initialize OpenAI client
        client_kwargs = {"api_key": api_key}
        if api_base_url:
            client_kwargs["base_url"] = api_base_url

        self.client = AsyncOpenAI(**client_kwargs)

        logger.info(f"✅ Initialized OpenAI client with model {model_name}")

    async def generate(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a response from OpenAI

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system message
            temperature: Override default temperature
            max_tokens: Override default max tokens
            tools: Optional list of tool definitions (OpenAI functions format)

        Returns:
            Response dictionary with 'content', 'role', and optionally 'tool_calls'
        """
        try:
            # Prepare messages (OpenAI includes system in messages)
            api_messages = []
            if system:
                api_messages.append({"role": "system", "content": system})
            api_messages.extend(messages)

            # Prepare request parameters
            request_params = {
                "model": self.model_name,
                "messages": api_messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            }

            if tools:
                # Convert to OpenAI functions format if needed
                request_params["tools"] = [
                    {"type": "function", "function": tool} if "function" not in tool else tool
                    for tool in tools
                ]
                request_params["tool_choice"] = "auto"

            # Make API call
            response = await self.client.chat.completions.create(**request_params)

            # Format response
            choice = response.choices[0]
            result = {
                "role": "assistant",
                "content": choice.message.content or "",
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.prompt_tokens,
                    "output_tokens": response.usage.completion_tokens,
                },
            }

            # Extract tool calls if present
            if choice.message.tool_calls:
                result["tool_calls"] = []
                for tool_call in choice.message.tool_calls:
                    result["tool_calls"].append({
                        "id": tool_call.id,
                        "name": tool_call.function.name,
                        "input": json.loads(tool_call.function.arguments),
                    })

            logger.info(f"✅ Generated response from OpenAI ({response.usage.completion_tokens} tokens)")
            return result

        except Exception as e:
            logger.error(f"❌ OpenAI API error: {e}")
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
        Stream a response from OpenAI

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

            # Prepare request parameters
            request_params = {
                "model": self.model_name,
                "messages": api_messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
                "stream": True,
            }

            if tools:
                request_params["tools"] = [
                    {"type": "function", "function": tool} if "function" not in tool else tool
                    for tool in tools
                ]
                request_params["tool_choice"] = "auto"

            # Stream API call
            stream = await self.client.chat.completions.create(**request_params)

            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

            logger.info("✅ Completed streaming response from OpenAI")

        except Exception as e:
            logger.error(f"❌ OpenAI streaming error: {e}")
            raise

    def get_provider_info(self) -> Dict[str, Any]:
        """
        Get information about this provider

        Returns:
            Dictionary with provider details
        """
        return {
            "provider_type": "openai",
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "supports_tools": True,
            "supports_streaming": True,
        }
