"""
CSV Upload API
Endpoints para upload de arquivos CSV para o Elasticsearch
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, get_db
from app.models.user import User
from app.services.csv_upload_service import get_csv_upload_service
from app.services.index_authorization_service import get_index_authorization_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/csv-upload", tags=["csv-upload"])


@router.post("/")
async def upload_csv(
    file: UploadFile = File(..., description="Arquivo CSV a ser enviado"),
    index_name: str = Form(..., description="Nome do índice de destino"),
    es_server_id: str = Form(..., description="ID do servidor Elasticsearch"),
    force_create: bool = Form(False, description="Forçar criação do índice se já existir"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload de arquivo CSV para o Elasticsearch

    **Permissões:**
    - ADMIN: Pode fazer upload para qualquer índice/servidor
    - POWER: Pode fazer upload para qualquer índice/servidor
    - OPERATOR: Só pode fazer upload para índices que tem permissão

    **Comportamento:**
    1. Se o índice não existe: cria automaticamente com mapping inferido
    2. Se o índice existe: valida compatibilidade (smart mapping)
    3. Se incompatível: retorna erro com detalhes

    **Formato do CSV:**
    - Deve ter cabeçalho na primeira linha
    - Campos vazios são ignorados
    - Tipos são inferidos automaticamente (string, int, float, boolean)
    """
    try:
        # 1. Verificar se usuário pode fazer upload de CSV
        if not current_user.can_upload_csv:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User role does not have permission to upload CSV files"
            )

        # 2. Verificar se usuário tem permissão para escrever neste índice
        auth_service = get_index_authorization_service(db)

        # Para criar índice novo, precisa de permissão "create"
        # Para índice existente, precisa de permissão "write"
        # Vamos verificar primeiro se tem permissão de create (que permite ambos)
        can_create = auth_service.can_access_index(
            user=current_user,
            index_name=index_name,
            es_server_id=es_server_id,
            action="create"
        )

        can_write = auth_service.can_access_index(
            user=current_user,
            index_name=index_name,
            es_server_id=es_server_id,
            action="write"
        )

        if not (can_create or can_write):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User does not have permission to upload to index '{index_name}' "
                       f"on server '{es_server_id}'"
            )

        # 3. Validar arquivo CSV
        if not file.filename.endswith('.csv'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be a CSV file (.csv extension)"
            )

        # 4. Ler conteúdo do arquivo
        logger.info(
            f"📤 User {current_user.username} uploading CSV '{file.filename}' "
            f"to index '{index_name}' on server '{es_server_id}'"
        )

        file_content = await file.read()

        if not file_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSV file is empty"
            )

        # 5. Processar e fazer upload
        csv_service = get_csv_upload_service()
        result = await csv_service.process_and_upload_csv(
            file_content=file_content,
            index_name=index_name,
            es_server_id=es_server_id,
            user_id=str(current_user.id),
            force_create=force_create
        )

        # 6. Se criou índice novo e usuário é OPERATOR, garantir que tem acesso
        if result.get("created_index") and current_user.has_index_restrictions:
            # Verificar se já tem acesso
            existing_accesses = auth_service.list_user_accesses(
                user_id=str(current_user.id),
                es_server_id=es_server_id
            )

            # Se não tem acesso explícito a este índice, criar
            has_access = any(
                access.matches_index(index_name) for access in existing_accesses
            )

            if not has_access:
                logger.info(
                    f"🔐 Auto-granting access to new index '{index_name}' "
                    f"for OPERATOR user {current_user.username}"
                )
                auth_service.grant_index_access(
                    user_id=str(current_user.id),
                    es_server_id=es_server_id,
                    index_name=index_name,
                    can_read=True,
                    can_write=True,
                    can_create=True,
                    created_by_id=str(current_user.id)
                )

        # 7. Retornar resultado
        if result["success"]:
            logger.info(
                f"✅ CSV upload successful: {result['documents_indexed']}/{result['documents_processed']} "
                f"documents indexed to '{index_name}'"
            )
            return {
                "success": True,
                "message": result.get("message", "CSV uploaded successfully"),
                "index_name": result["index_name"],
                "documents_processed": result["documents_processed"],
                "documents_indexed": result["documents_indexed"],
                "created_index": result["created_index"],
                "errors": result.get("errors", []),
                "mapping": result.get("mapping")
            }
        else:
            logger.error(f"❌ CSV upload failed: {result.get('message')}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Failed to upload CSV"),
                headers={"X-Upload-Errors": str(result.get("errors", []))}
            )

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"❌ Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"❌ Unexpected error during CSV upload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/my-upload-permissions")
async def get_my_upload_permissions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna informações sobre permissões de upload do usuário atual

    **Response:**
    - can_upload: Se usuário pode fazer upload de CSV
    - has_restrictions: Se usuário tem restrições de índice
    - accessible_servers: Lista de servidores que pode acessar
    - accessible_indices: Lista de padrões de índices que pode acessar
    """
    auth_service = get_index_authorization_service(db)

    # Obter informações básicas
    can_upload = current_user.can_upload_csv
    has_restrictions = current_user.has_index_restrictions

    # Para OPERATOR, listar acessos
    accessible_servers = []
    accessible_indices = []

    if has_restrictions:
        # Servidor atribuído
        if current_user.assigned_es_server_id:
            accessible_servers = [str(current_user.assigned_es_server_id)]

        # Listar todos os acessos
        accesses = auth_service.list_user_accesses(user_id=str(current_user.id))
        accessible_indices = [
            {
                "index_pattern": access.index_name,
                "es_server_id": str(access.es_server_id),
                "can_read": access.can_read,
                "can_write": access.can_write,
                "can_create": access.can_create
            }
            for access in accesses
        ]

    return {
        "can_upload": can_upload,
        "has_restrictions": has_restrictions,
        "role": current_user.role.value,
        "accessible_servers": accessible_servers,
        "accessible_indices": accessible_indices,
        "message": (
            "No restrictions - can upload to any index" if not has_restrictions
            else f"Restricted to {len(accessible_indices)} index patterns"
        )
    }
