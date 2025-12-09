"""
MCP Executor Service
Executa servidores MCP (STDIO, HTTP, SSE) e gerencia comunicação
"""

import asyncio
import json
import logging
import httpx
import os
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.mcp_server import MCPServer, MCPType

logger = logging.getLogger(__name__)


class MCPExecutor:
    """
    Executor para servidores MCP

    Suporta:
    - STDIO: Spawna processo e comunica via stdin/stdout
    - HTTP: Faz requests HTTP para servidor MCP
    - SSE: Conecta via Server-Sent Events
    """

    def __init__(self):
        self.active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def execute_stdio_mcp(
        self,
        server: MCPServer,
        method: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executa MCP via STDIO

        Args:
            server: Configuração do servidor MCP
            method: Método MCP a chamar (e.g., "tools/list", "tools/call")
            params: Parâmetros do método

        Returns:
            Resposta do MCP server
        """
        logger.info(f"Executing STDIO MCP: {server.name} - {method}")

        try:
            # Preparar comando e argumentos
            command = server.command
            args = server.args or []

            # Preparar ambiente (herdar variáveis do sistema + adicionar customizadas)
            env = os.environ.copy()
            if server.env:
                env.update(server.env)

            # Spawnar processo
            process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            # Enviar initialize primeiro (protocolo MCP)
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "dashboard-ai",
                        "version": "1.0.0"
                    }
                }
            }

            init_bytes = (json.dumps(init_request) + "\n").encode('utf-8')
            process.stdin.write(init_bytes)
            await process.stdin.drain()

            # Preparar mensagem JSON-RPC real
            request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": method,
                "params": params
            }

            # Enviar request via stdin
            request_bytes = (json.dumps(request) + "\n").encode('utf-8')
            process.stdin.write(request_bytes)
            await process.stdin.drain()
            process.stdin.close()

            # Ler resposta via stdout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30.0
            )

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown error"
                raise Exception(f"MCP process failed: {error_msg}")

            # Parse respostas JSON-RPC (podem vir múltiplas linhas)
            response_lines = stdout.decode('utf-8').strip().split('\n')
            # Pegar a última resposta (que é a do nosso método, não do initialize)
            response_text = response_lines[-1] if response_lines else "{}"
            response = json.loads(response_text)

            if "error" in response:
                raise Exception(f"MCP error: {response['error']}")

            logger.info(f"✅ STDIO MCP {server.name} executed successfully")
            return response.get("result", {})

        except asyncio.TimeoutError:
            logger.error(f"❌ STDIO MCP {server.name} timeout")
            raise Exception(f"MCP server {server.name} timeout")

        except Exception as e:
            logger.error(f"❌ Error executing STDIO MCP {server.name}: {e}")
            raise

    async def execute_http_mcp(
        self,
        server: MCPServer,
        method: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executa MCP via HTTP

        Args:
            server: Configuração do servidor MCP
            method: Método MCP a chamar
            params: Parâmetros do método

        Returns:
            Resposta do MCP server
        """
        logger.info(f"Executing HTTP MCP: {server.name} - {method}")

        try:
            # Preparar request JSON-RPC
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            }

            # Fazer POST request
            response = await self.http_client.post(
                server.url,
                json=request,
                headers={"Content-Type": "application/json"}
            )

            response.raise_for_status()

            # Parse resposta
            data = response.json()

            if "error" in data:
                raise Exception(f"MCP error: {data['error']}")

            logger.info(f"✅ HTTP MCP {server.name} executed successfully")
            return data.get("result", {})

        except httpx.HTTPError as e:
            logger.error(f"❌ HTTP error for MCP {server.name}: {e}")
            raise Exception(f"HTTP MCP error: {e}")

        except Exception as e:
            logger.error(f"❌ Error executing HTTP MCP {server.name}: {e}")
            raise

    async def execute_sse_mcp(
        self,
        server: MCPServer,
        method: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executa MCP via SSE

        Args:
            server: Configuração do servidor MCP
            method: Método MCP a chamar
            params: Parâmetros do método

        Returns:
            Resposta do MCP server
        """
        logger.info(f"Executing SSE MCP: {server.name} - {method}")

        try:
            # SSE geralmente usa GET com EventSource
            # Para simplificar, usamos HTTP POST similar ao HTTP MCP
            # Em produção, seria necessário implementar cliente SSE completo

            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            }

            async with self.http_client.stream("POST", server.url, json=request) as response:
                response.raise_for_status()

                # Ler eventos SSE
                result = {}
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data:
                            result = data["result"]
                        elif "error" in data:
                            raise Exception(f"MCP error: {data['error']}")

                logger.info(f"✅ SSE MCP {server.name} executed successfully")
                return result

        except Exception as e:
            logger.error(f"❌ Error executing SSE MCP {server.name}: {e}")
            raise

    async def execute(
        self,
        server: MCPServer,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executa MCP baseado no tipo

        Args:
            server: Configuração do servidor MCP
            method: Método MCP a chamar
            params: Parâmetros do método

        Returns:
            Resposta do MCP server
        """
        if not server.is_active:
            raise Exception(f"MCP server {server.name} is not active")

        params = params or {}

        if server.type == MCPType.STDIO.value or server.type == "stdio":
            return await self.execute_stdio_mcp(server, method, params)
        elif server.type == MCPType.HTTP.value or server.type == "http":
            return await self.execute_http_mcp(server, method, params)
        elif server.type == MCPType.SSE.value or server.type == "sse":
            return await self.execute_sse_mcp(server, method, params)
        else:
            raise Exception(f"Unknown MCP type: {server.type}")

    async def list_tools(self, server: MCPServer) -> List[Dict[str, Any]]:
        """
        Lista ferramentas disponíveis em um servidor MCP

        Args:
            server: Configuração do servidor MCP

        Returns:
            Lista de ferramentas disponíveis
        """
        result = await self.execute(server, "tools/list", {})
        return result.get("tools", [])

    async def call_tool(
        self,
        server: MCPServer,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Any:
        """
        Chama uma ferramenta específica em um servidor MCP

        Args:
            server: Configuração do servidor MCP
            tool_name: Nome da ferramenta a chamar
            arguments: Argumentos da ferramenta

        Returns:
            Resultado da execução da ferramenta
        """
        result = await self.execute(
            server,
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments
            }
        )
        return result.get("content", [])

    async def close(self):
        """Fecha conexões e processos ativos"""
        await self.http_client.aclose()

        for process_id, process in self.active_processes.items():
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()
            except Exception as e:
                logger.error(f"Error closing process {process_id}: {e}")


# Singleton instance
_executor: Optional[MCPExecutor] = None


def get_mcp_executor() -> MCPExecutor:
    """Retorna instância singleton do executor"""
    global _executor
    if _executor is None:
        _executor = MCPExecutor()
    return _executor


async def get_mcp_server_by_id(db: AsyncSession, server_id: str) -> MCPServer:
    """
    Busca servidor MCP por ID

    Args:
        db: Sessão do banco de dados
        server_id: ID do servidor

    Returns:
        Servidor MCP

    Raises:
        Exception: Se servidor não encontrado
    """
    result = await db.execute(
        select(MCPServer).where(MCPServer.id == server_id)
    )
    server = result.scalar_one_or_none()

    if not server:
        raise Exception(f"MCP server {server_id} not found")

    return server
