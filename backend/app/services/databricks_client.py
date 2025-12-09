"""
Cliente customizado para Databricks usando API HTTP direta
"""
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from typing import Any, Dict, List, Optional
import httpx
import logging

logger = logging.getLogger(__name__)


class DatabricksChatClient(BaseChatModel):
    """
    Cliente customizado para Databricks que usa a API HTTP direta
    Implementa interface LangChain para compatibilidade
    """

    databricks_url: str
    databricks_token: str
    model_name: str = "databricks-claude-3-7-sonnet"
    temperature: float = 0.1
    max_tokens: int = 4096

    class Config:
        """Configuração do Pydantic"""
        arbitrary_types_allowed = True

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> ChatResult:
        """
        Gera resposta usando a API Databricks

        Args:
            messages: Lista de mensagens (System, Human, AI)
            stop: Sequências de parada opcionais

        Returns:
            ChatResult com a resposta do modelo
        """
        # Converte mensagens para formato OpenAI
        formatted_messages = []
        for msg in messages:
            if isinstance(msg, SystemMessage):
                formatted_messages.append({"role": "system", "content": msg.content})
            elif isinstance(msg, HumanMessage):
                formatted_messages.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                formatted_messages.append({"role": "assistant", "content": msg.content})

        # Monta payload
        payload = {
            "messages": formatted_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if stop:
            payload["stop"] = stop

        # Faz requisição
        headers = {
            "Authorization": f"Bearer {self.databricks_token}",
            "Content-Type": "application/json"
        }

        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    self.databricks_url,
                    headers=headers,
                    json=payload
                )
                response.raise_for_status()
                result = response.json()

            # Extrai resposta
            if "choices" in result and len(result["choices"]) > 0:
                content = result["choices"][0]["message"]["content"]
            else:
                raise ValueError(f"Resposta inesperada da API: {result}")

            # Cria resultado
            message = AIMessage(content=content)
            generation = ChatGeneration(message=message)

            logger.info(f"✅ Databricks response received ({len(content)} chars)")
            return ChatResult(generations=[generation])

        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Databricks API error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error calling Databricks: {e}")
            raise

    @property
    def _llm_type(self) -> str:
        """Retorna o tipo do LLM"""
        return "databricks-chat"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        """Retorna parâmetros de identificação"""
        return {
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
