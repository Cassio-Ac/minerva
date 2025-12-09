"""
MCP Servers API Endpoints
CRUD para gerenciar servidores Model Context Protocol
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging
import uuid

from app.db.database import get_db
from app.models.mcp_server import MCPServer, MCPType

router = APIRouter()
logger = logging.getLogger(__name__)


class MCPServerCreate(BaseModel):
    """Request para criar servidor MCP"""
    name: str
    type: MCPType
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    url: Optional[str] = None
    description: Optional[str] = None


class MCPServerUpdate(BaseModel):
    """Request para atualizar servidor MCP"""
    name: Optional[str] = None
    type: Optional[MCPType] = None
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    url: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class MCPServerResponse(BaseModel):
    """Response de servidor MCP"""
    id: str
    name: str
    type: str
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    url: Optional[str] = None
    description: Optional[str] = None
    is_active: bool
    created_at: str
    updated_at: str


@router.get("/", response_model=List[MCPServerResponse])
async def list_mcp_servers(db: AsyncSession = Depends(get_db)):
    """
    Lista todos os servidores MCP
    """
    try:
        result = await db.execute(
            select(MCPServer).order_by(MCPServer.created_at.desc())
        )
        servers = result.scalars().all()

        return [MCPServerResponse(**server.to_dict()) for server in servers]

    except Exception as e:
        logger.error(f"Error listing MCP servers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{server_id}", response_model=MCPServerResponse)
async def get_mcp_server(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Busca servidor MCP por ID
    """
    try:
        result = await db.execute(
            select(MCPServer).where(MCPServer.id == server_id)
        )
        server = result.scalar_one_or_none()

        if not server:
            raise HTTPException(status_code=404, detail="MCP server not found")

        return MCPServerResponse(**server.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting MCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=MCPServerResponse)
async def create_mcp_server(data: MCPServerCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria novo servidor MCP

    Validações:
    - STDIO: requer command
    - HTTP/SSE: requer url
    """
    try:
        # Validar configuração por tipo
        if data.type == MCPType.STDIO:
            if not data.command:
                raise HTTPException(
                    status_code=400,
                    detail="STDIO servers require 'command' field"
                )
        elif data.type in [MCPType.HTTP, MCPType.SSE]:
            if not data.url:
                raise HTTPException(
                    status_code=400,
                    detail=f"{data.type.value.upper()} servers require 'url' field"
                )

        # Verificar se já existe servidor com esse nome
        result = await db.execute(
            select(MCPServer).where(MCPServer.name == data.name)
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"MCP server with name '{data.name}' already exists"
            )

        # Criar servidor
        server = MCPServer(
            id=str(uuid.uuid4()),
            name=data.name,
            type=data.type,
            command=data.command,
            args=data.args,
            env=data.env,
            url=data.url,
            description=data.description,
            is_active=True,
        )

        db.add(server)
        await db.commit()
        await db.refresh(server)

        logger.info(f"Created MCP server: {server.name} ({server.type})")
        return MCPServerResponse(**server.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating MCP server: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{server_id}", response_model=MCPServerResponse)
async def update_mcp_server(
    server_id: str,
    data: MCPServerUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Atualiza servidor MCP
    """
    try:
        # Buscar servidor
        result = await db.execute(
            select(MCPServer).where(MCPServer.id == server_id)
        )
        server = result.scalar_one_or_none()

        if not server:
            raise HTTPException(status_code=404, detail="MCP server not found")

        # Atualizar campos fornecidos
        update_data = data.dict(exclude_unset=True)

        for key, value in update_data.items():
            setattr(server, key, value)

        await db.commit()
        await db.refresh(server)

        logger.info(f"Updated MCP server: {server.name}")
        return MCPServerResponse(**server.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating MCP server: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{server_id}")
async def delete_mcp_server(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Remove servidor MCP
    """
    try:
        # Buscar servidor
        result = await db.execute(
            select(MCPServer).where(MCPServer.id == server_id)
        )
        server = result.scalar_one_or_none()

        if not server:
            raise HTTPException(status_code=404, detail="MCP server not found")

        await db.delete(server)
        await db.commit()

        logger.info(f"Deleted MCP server: {server.name}")
        return {"message": f"MCP server '{server.name}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting MCP server: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
