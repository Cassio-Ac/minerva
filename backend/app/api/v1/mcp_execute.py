"""
MCP Execution API Endpoints
Endpoints para executar ferramentas MCP
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.database import get_db
from app.services.mcp_executor import get_mcp_executor, get_mcp_server_by_id

router = APIRouter()
logger = logging.getLogger(__name__)


class MCPToolCallRequest(BaseModel):
    """Request para chamar ferramenta MCP"""
    server_id: str
    tool_name: str
    arguments: Dict[str, Any] = {}


class MCPToolListResponse(BaseModel):
    """Response com lista de ferramentas"""
    server_id: str
    server_name: str
    tools: List[Dict[str, Any]]


class MCPToolCallResponse(BaseModel):
    """Response de execução de ferramenta"""
    server_id: str
    tool_name: str
    result: Any


@router.get("/{server_id}/tools", response_model=MCPToolListResponse)
async def list_mcp_tools(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Lista ferramentas disponíveis em um servidor MCP

    - **server_id**: ID do servidor MCP
    """
    logger.info(f"Listing tools for MCP server: {server_id}")

    try:
        # Buscar servidor
        server = await get_mcp_server_by_id(db, server_id)

        # Obter executor
        executor = get_mcp_executor()

        # Listar ferramentas
        tools = await executor.list_tools(server)

        return MCPToolListResponse(
            server_id=server.id,
            server_name=server.name,
            tools=tools
        )

    except Exception as e:
        logger.error(f"Error listing MCP tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute", response_model=MCPToolCallResponse)
async def execute_mcp_tool(request: MCPToolCallRequest, db: AsyncSession = Depends(get_db)):
    """
    Executa uma ferramenta MCP

    - **server_id**: ID do servidor MCP
    - **tool_name**: Nome da ferramenta a executar
    - **arguments**: Argumentos da ferramenta
    """
    logger.info(
        f"Executing MCP tool: {request.tool_name} "
        f"on server {request.server_id}"
    )

    try:
        # Buscar servidor
        server = await get_mcp_server_by_id(db, request.server_id)

        # Obter executor
        executor = get_mcp_executor()

        # Executar ferramenta
        result = await executor.call_tool(
            server,
            request.tool_name,
            request.arguments
        )

        return MCPToolCallResponse(
            server_id=server.id,
            tool_name=request.tool_name,
            result=result
        )

    except Exception as e:
        logger.error(f"Error executing MCP tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/test/{server_id}")
async def test_mcp_server(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Testa conexão com servidor MCP

    - **server_id**: ID do servidor MCP

    Returns:
        Status da conexão e informações básicas
    """
    logger.info(f"Testing MCP server: {server_id}")

    try:
        # Buscar servidor
        server = await get_mcp_server_by_id(db, server_id)

        # Obter executor
        executor = get_mcp_executor()

        # Tentar listar ferramentas (teste de conexão)
        tools = await executor.list_tools(server)

        return {
            "status": "success",
            "server_id": server.id,
            "server_name": server.name,
            "server_type": server.type,
            "tools_count": len(tools),
            "message": f"Successfully connected to {server.name}. Found {len(tools)} tools."
        }

    except Exception as e:
        logger.error(f"Error testing MCP server: {e}")
        return {
            "status": "error",
            "server_id": server_id,
            "error": str(e),
            "message": f"Failed to connect to MCP server: {str(e)}"
        }
