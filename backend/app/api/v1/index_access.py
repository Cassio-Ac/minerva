"""
Index Access Management API
Endpoints para gerenciar acesso de usuários OPERATOR a índices do Elasticsearch
"""
import logging
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, get_db
from app.models.user import User
from app.services.index_authorization_service import get_index_authorization_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/index-access", tags=["index-access"])


# Schemas
class IndexAccessCreate(BaseModel):
    """Schema para criar acesso a índice"""
    user_id: str = Field(..., description="ID do usuário OPERATOR")
    es_server_id: str = Field(..., description="ID do servidor Elasticsearch")
    index_name: str = Field(..., description="Nome do índice (pode usar wildcard: logs-*)")
    can_read: bool = Field(True, description="Permissão de leitura")
    can_write: bool = Field(False, description="Permissão de escrita (CSV upload)")
    can_create: bool = Field(False, description="Permissão de criar novos índices")


class IndexAccessUpdate(BaseModel):
    """Schema para atualizar acesso a índice"""
    can_read: Optional[bool] = Field(None, description="Nova permissão de leitura")
    can_write: Optional[bool] = Field(None, description="Nova permissão de escrita")
    can_create: Optional[bool] = Field(None, description="Nova permissão de criar")


class IndexAccessResponse(BaseModel):
    """Schema de resposta de acesso a índice"""
    id: str
    user_id: str
    es_server_id: str
    index_name: str
    can_read: bool
    can_write: bool
    can_create: bool
    created_at: str
    updated_at: str
    created_by_id: Optional[str]


# Endpoints
@router.post("/", response_model=IndexAccessResponse, status_code=status.HTTP_201_CREATED)
async def create_index_access(
    access_data: IndexAccessCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Concede acesso a um índice para um usuário OPERATOR

    **Permissões:** Somente ADMIN pode conceder acessos

    **Wildcards:** O campo `index_name` suporta wildcards:
    - `logs-*` = match logs-2024, logs-prod, etc.
    - `gvuln*` = match gvuln_v1, gvuln-test, etc.
    - `*` = match todos os índices (não recomendado para OPERATOR)
    """
    # Verificar permissão (só ADMIN pode gerenciar acessos)
    if not current_user.can_manage_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only ADMIN users can manage index access"
        )

    try:
        auth_service = get_index_authorization_service(db)

        # Criar acesso
        access = auth_service.grant_index_access(
            user_id=access_data.user_id,
            es_server_id=access_data.es_server_id,
            index_name=access_data.index_name,
            can_read=access_data.can_read,
            can_write=access_data.can_write,
            can_create=access_data.can_create,
            created_by_id=str(current_user.id)
        )

        return IndexAccessResponse(**access.to_dict())

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"❌ Error creating index access: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/user/{user_id}", response_model=List[IndexAccessResponse])
async def list_user_index_accesses(
    user_id: str,
    es_server_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista todos os acessos a índices de um usuário

    **Permissões:**
    - ADMIN: Pode listar acessos de qualquer usuário
    - Outros: Só podem ver seus próprios acessos

    **Query Parameters:**
    - es_server_id: Filtrar por servidor específico (opcional)
    """
    # Verificar permissão
    if not current_user.can_manage_users and str(current_user.id) != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own index accesses"
        )

    try:
        auth_service = get_index_authorization_service(db)
        accesses = auth_service.list_user_accesses(
            user_id=user_id,
            es_server_id=es_server_id
        )

        return [IndexAccessResponse(**access.to_dict()) for access in accesses]

    except Exception as e:
        logger.error(f"❌ Error listing index accesses: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/my-accesses", response_model=List[IndexAccessResponse])
async def list_my_index_accesses(
    es_server_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista acessos a índices do usuário atual

    **Query Parameters:**
    - es_server_id: Filtrar por servidor específico (opcional)
    """
    try:
        auth_service = get_index_authorization_service(db)
        accesses = auth_service.list_user_accesses(
            user_id=str(current_user.id),
            es_server_id=es_server_id
        )

        return [IndexAccessResponse(**access.to_dict()) for access in accesses]

    except Exception as e:
        logger.error(f"❌ Error listing my index accesses: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.patch("/{access_id}", response_model=IndexAccessResponse)
async def update_index_access(
    access_id: str,
    update_data: IndexAccessUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atualiza permissões de um acesso existente

    **Permissões:** Somente ADMIN pode atualizar acessos
    """
    # Verificar permissão
    if not current_user.can_manage_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only ADMIN users can update index access"
        )

    try:
        auth_service = get_index_authorization_service(db)

        # Atualizar acesso
        access = auth_service.update_index_access(
            access_id=access_id,
            can_read=update_data.can_read,
            can_write=update_data.can_write,
            can_create=update_data.can_create
        )

        if not access:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Index access {access_id} not found"
            )

        return IndexAccessResponse(**access.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error updating index access: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.delete("/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_index_access(
    access_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Remove acesso a um índice

    **Permissões:** Somente ADMIN pode remover acessos
    """
    # Verificar permissão
    if not current_user.can_manage_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only ADMIN users can delete index access"
        )

    try:
        auth_service = get_index_authorization_service(db)

        # Remover acesso
        success = auth_service.revoke_index_access(access_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Index access {access_id} not found"
            )

        return None

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error deleting index access: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.post("/check-access")
async def check_index_access(
    index_name: str,
    es_server_id: str,
    action: str = "read",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifica se usuário atual tem acesso a um índice específico

    **Query Parameters:**
    - index_name: Nome do índice
    - es_server_id: ID do servidor Elasticsearch
    - action: Tipo de ação (read, write, create)

    **Response:**
    - has_access: Se usuário tem acesso
    - role: Role do usuário
    - reason: Razão do acesso (ou negação)
    """
    try:
        auth_service = get_index_authorization_service(db)

        has_access = auth_service.can_access_index(
            user=current_user,
            index_name=index_name,
            es_server_id=es_server_id,
            action=action
        )

        # Determinar razão
        if has_access:
            if current_user.role.value in ['admin', 'power']:
                reason = f"{current_user.role.value.upper()} role has unrestricted access"
            else:
                reason = f"User has explicit {action} permission for this index"
        else:
            if current_user.role.value == 'reader':
                reason = "READER role cannot access indices directly"
            else:
                reason = f"User does not have {action} permission for this index"

        return {
            "has_access": has_access,
            "role": current_user.role.value,
            "action": action,
            "index_name": index_name,
            "es_server_id": es_server_id,
            "reason": reason
        }

    except Exception as e:
        logger.error(f"❌ Error checking index access: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )
