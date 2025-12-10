"""
Telegram Bot Service - Consulta de credenciais vazadas via bots do Telegram

Este serviço gerencia a interação com bots de leak no Telegram,
enviando consultas e processando as respostas.

Configuração:
- Sessão salva em: app/credentials/sessions/
- Variáveis de ambiente:
    TELEGRAM_API_ID
    TELEGRAM_API_HASH
    TELEGRAM_PHONE
    TELEGRAM_SESSION_NAME
"""

import os
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List
from telethon import TelegramClient
from telethon.tl.types import Message

from app.core.config import settings

logger = logging.getLogger(__name__)


class TelegramBotService:
    """
    Serviço para interagir com bots de leak no Telegram.

    Bots suportados:
    - Database Lookup (6574456300): Consulta de emails, CPFs, etc.
    """

    # Configuração dos bots conhecidos
    KNOWN_BOTS = {
        "database_lookup": {
            "id": 6574456300,
            "name": "Database Lookup",
            "description": "Bot para consulta de credenciais vazadas",
            "supported_types": ["email", "cpf", "phone", "domain", "username", "ip"]
        }
    }

    # Diretório base para sessões e downloads
    BASE_DIR = Path(__file__).parent.parent
    SESSIONS_DIR = BASE_DIR / "sessions"
    DOWNLOADS_DIR = BASE_DIR.parent.parent / "downloads" / "credentials"

    def __init__(self):
        """Inicializa o serviço com as configurações do ambiente"""
        # Configurações do Telegram (podem ser sobrescritas pelo .env)
        self.api_id = getattr(settings, 'TELEGRAM_API_ID', None) or 29746479
        self.api_hash = getattr(settings, 'TELEGRAM_API_HASH', None) or 'e9c6d52ad31d7233a2f9f323d5d0f500'
        self.phone = getattr(settings, 'TELEGRAM_PHONE', None) or '+5551981184847'
        self.session_name = getattr(settings, 'TELEGRAM_SESSION_NAME', None) or 'session_angello'

        # Caminho completo da sessão
        self.session_path = str(self.SESSIONS_DIR / self.session_name)

        # Criar diretório de downloads se não existir
        self.DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

        # Cliente será inicializado sob demanda
        self._client: Optional[TelegramClient] = None

        logger.info(f"📱 TelegramBotService inicializado")
        logger.info(f"   Session: {self.session_path}")
        logger.info(f"   Downloads: {self.DOWNLOADS_DIR}")

    async def _get_client(self) -> TelegramClient:
        """Obtém ou cria o cliente Telegram"""
        if self._client is None or not self._client.is_connected():
            self._client = TelegramClient(
                self.session_path,
                self.api_id,
                self.api_hash
            )
            await self._client.start(phone=self.phone)
            logger.info("✅ Cliente Telegram conectado")
        return self._client

    async def disconnect(self):
        """Desconecta o cliente Telegram"""
        if self._client and self._client.is_connected():
            await self._client.disconnect()
            logger.info("🔌 Cliente Telegram desconectado")

    async def query_bot(
        self,
        query_value: str,
        bot_key: str = "database_lookup",
        auto_download: bool = True,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Envia uma consulta para um bot de leak e aguarda a resposta.

        Args:
            query_value: Valor a consultar (email, CPF, etc.)
            bot_key: Chave do bot em KNOWN_BOTS
            auto_download: Se True, clica no botão Download automaticamente
            timeout: Tempo máximo de espera em segundos

        Returns:
            Dict com o resultado da consulta
        """
        if bot_key not in self.KNOWN_BOTS:
            return {
                "success": False,
                "error": f"Bot desconhecido: {bot_key}",
                "found": False,
                "results": []
            }

        bot_config = self.KNOWN_BOTS[bot_key]
        bot_id = bot_config["id"]

        try:
            client = await self._get_client()

            logger.info(f"🔍 Consultando '{query_value}' no bot {bot_config['name']}")

            # Envia a mensagem para o bot
            sent_message = await client.send_message(bot_id, query_value)
            sent_id = sent_message.id

            logger.info(f"📤 Mensagem enviada (ID: {sent_id})")

            # Aguarda resposta do bot
            await asyncio.sleep(5)

            # Captura mensagens após a enviada
            messages = await client.get_messages(bot_id, limit=20)

            responses = []
            message_with_buttons = None
            found = False

            for msg in reversed(messages):
                if msg.id > sent_id and not msg.out:
                    response_data = {
                        "id": msg.id,
                        "timestamp": msg.date.isoformat(),
                        "text": msg.text or "",
                        "has_buttons": bool(msg.buttons),
                        "has_file": bool(msg.file),
                        "buttons": []
                    }

                    # Verifica se tem botões
                    if msg.buttons:
                        message_with_buttons = msg
                        for row in msg.buttons:
                            for button in row:
                                response_data["buttons"].append(button.text)

                    # Verifica se encontrou resultados
                    if msg.text:
                        text_lower = msg.text.lower()
                        if "found" in text_lower or "resultado" in text_lower or "records" in text_lower:
                            found = True

                    responses.append(response_data)

            result = {
                "success": True,
                "found": found,
                "bot_name": bot_config["name"],
                "query_value": query_value,
                "responses": responses,
                "result_count": len(responses),
                "result_preview": responses[0]["text"][:500] if responses else None,
                "html_path": None,
                "file_path": None,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Se auto_download e tem botão Download, clica
            if auto_download and message_with_buttons:
                download_result = await self._click_download(
                    client, bot_id, message_with_buttons, query_value
                )
                result.update(download_result)

            return result

        except Exception as e:
            logger.error(f"❌ Erro na consulta: {e}")
            return {
                "success": False,
                "error": str(e),
                "found": False,
                "results": []
            }

    async def _click_download(
        self,
        client: TelegramClient,
        bot_id: int,
        message: Message,
        query_value: str
    ) -> Dict[str, Any]:
        """
        Clica no botão Download e baixa o arquivo resultante.

        Args:
            client: Cliente Telegram conectado
            bot_id: ID do bot
            message: Mensagem com os botões
            query_value: Valor da consulta (para nomear o arquivo)

        Returns:
            Dict com informações do download
        """
        result = {
            "download_clicked": False,
            "html_path": None,
            "file_path": None
        }

        try:
            # Procura o botão Download
            for row in message.buttons:
                for button in row:
                    if "download" in button.text.lower():
                        logger.info(f"🔽 Clicando no botão '{button.text}'...")
                        await button.click()
                        result["download_clicked"] = True

                        # Aguarda resposta
                        await asyncio.sleep(5)

                        # Captura novas mensagens
                        new_messages = await client.get_messages(bot_id, limit=10)

                        for new_msg in reversed(new_messages):
                            if new_msg.id > message.id and not new_msg.out:
                                # Se tem arquivo, baixa
                                if new_msg.file:
                                    # Gera nome único para o arquivo
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    safe_query = "".join(c if c.isalnum() else "_" for c in query_value[:30])

                                    # Define extensão
                                    original_name = new_msg.file.name or "result"
                                    ext = Path(original_name).suffix or ".html"

                                    file_name = f"{safe_query}_{timestamp}{ext}"
                                    file_path = self.DOWNLOADS_DIR / file_name

                                    # Baixa o arquivo
                                    downloaded_path = await client.download_media(
                                        new_msg,
                                        file=str(file_path)
                                    )

                                    logger.info(f"✅ Arquivo baixado: {downloaded_path}")

                                    if ext.lower() in [".html", ".htm"]:
                                        result["html_path"] = str(downloaded_path)
                                    else:
                                        result["file_path"] = str(downloaded_path)

                        break

        except Exception as e:
            logger.error(f"❌ Erro no download: {e}")
            result["download_error"] = str(e)

        return result

    def get_available_bots(self) -> List[Dict[str, Any]]:
        """Retorna lista de bots disponíveis"""
        return [
            {
                "key": key,
                **config
            }
            for key, config in self.KNOWN_BOTS.items()
        ]

    def get_session_info(self) -> Dict[str, Any]:
        """Retorna informações sobre a sessão atual"""
        session_file = Path(f"{self.session_path}.session")
        return {
            "session_name": self.session_name,
            "session_exists": session_file.exists(),
            "phone": self.phone[:6] + "****" + self.phone[-2:],  # Mascara o telefone
            "downloads_dir": str(self.DOWNLOADS_DIR)
        }


# Singleton instance
telegram_bot_service = TelegramBotService()
