"""
Index Authorization Service
Gerencia autorização de acesso a índices do Elasticsearch para usuários OPERATOR
"""
import logging
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.user import User, UserRole
from app.models.user_index_access import UserIndexAccess

logger = logging.getLogger(__name__)


class IndexAuthorizationService:
    """Service para verificar e gerenciar autorização de acesso a índices"""

    def __init__(self, db: Session):
        self.db = db

    def can_access_index(
        self,
        user: User,
        index_name: str,
        es_server_id: str,
        action: str = "read"
    ) -> bool:
        """
        Verifica se usuário pode acessar um índice específico

        Args:
            user: Usuário a verificar
            index_name: Nome do índice
            es_server_id: ID do servidor Elasticsearch
            action: Tipo de ação ("read", "write", "create")

        Returns:
            True se usuário pode acessar o índice
        """
        # ADMIN e POWER têm acesso irrestrito
        if user.role in [UserRole.ADMIN, UserRole.POWER]:
            return True

        # READER não tem acesso a índices (só dashboards compartilhados)
        if user.role == UserRole.READER:
            return False

        # OPERATOR: verificar permissões específicas
        if user.role == UserRole.OPERATOR:
            # Verificar se servidor está correto (se assigned_es_server_id está definido)
            if user.assigned_es_server_id and str(user.assigned_es_server_id) != str(es_server_id):
                logger.warning(
                    f"User {user.username} attempted to access server {es_server_id} "
                    f"but is restricted to {user.assigned_es_server_id}"
                )
                return False

            # Buscar permissões de acesso
            accesses = self.db.query(UserIndexAccess).filter(
                and_(
                    UserIndexAccess.user_id == user.id,
                    UserIndexAccess.es_server_id == es_server_id
                )
            ).all()

            # Verificar se algum acesso match com o índice
            for access in accesses:
                if access.matches_index(index_name):
                    # Verificar permissão específica
                    if action == "read" and access.can_read:
                        return True
                    elif action == "write" and access.can_write:
                        return True
                    elif action == "create" and access.can_create:
                        return True

            logger.warning(
                f"User {user.username} (OPERATOR) attempted to {action} index {index_name} "
                f"without proper permissions"
            )
            return False

        # Caso padrão: negar acesso
        return False

    def get_accessible_indices(
        self,
        user: User,
        es_server_id: str,
        action: str = "read"
    ) -> List[str]:
        """
        Retorna lista de padrões de índices que o usuário pode acessar

        Args:
            user: Usuário
            es_server_id: ID do servidor Elasticsearch
            action: Tipo de ação ("read", "write", "create")

        Returns:
            Lista de padrões de índices (pode incluir wildcards)
        """
        # ADMIN e POWER têm acesso a tudo
        if user.role in [UserRole.ADMIN, UserRole.POWER]:
            return ["*"]  # Wildcard para todos os índices

        # READER não tem acesso
        if user.role == UserRole.READER:
            return []

        # OPERATOR: retornar índices específicos
        if user.role == UserRole.OPERATOR:
            # Verificar servidor
            if user.assigned_es_server_id and str(user.assigned_es_server_id) != str(es_server_id):
                return []

            # Buscar permissões
            accesses = self.db.query(UserIndexAccess).filter(
                and_(
                    UserIndexAccess.user_id == user.id,
                    UserIndexAccess.es_server_id == es_server_id
                )
            ).all()

            # Filtrar por tipo de ação
            indices = []
            for access in accesses:
                if action == "read" and access.can_read:
                    indices.append(access.index_name)
                elif action == "write" and access.can_write:
                    indices.append(access.index_name)
                elif action == "create" and access.can_create:
                    indices.append(access.index_name)

            return indices

        return []

    def grant_index_access(
        self,
        user_id: str,
        es_server_id: str,
        index_name: str,
        can_read: bool = True,
        can_write: bool = False,
        can_create: bool = False,
        created_by_id: Optional[str] = None
    ) -> UserIndexAccess:
        """
        Concede acesso a um índice para um usuário

        Args:
            user_id: ID do usuário
            es_server_id: ID do servidor Elasticsearch
            index_name: Nome do índice (pode usar wildcard)
            can_read: Permissão de leitura
            can_write: Permissão de escrita
            can_create: Permissão de criar índice
            created_by_id: ID do usuário que está concedendo o acesso

        Returns:
            UserIndexAccess criado

        Raises:
            ValueError: Se acesso já existe ou se usuário não é OPERATOR
        """
        # Verificar se usuário é OPERATOR
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found")

        if user.role != UserRole.OPERATOR:
            raise ValueError(f"Can only grant index access to OPERATOR users")

        # Verificar se acesso já existe
        existing = self.db.query(UserIndexAccess).filter(
            and_(
                UserIndexAccess.user_id == user_id,
                UserIndexAccess.es_server_id == es_server_id,
                UserIndexAccess.index_name == index_name
            )
        ).first()

        if existing:
            raise ValueError(
                f"Access already exists for user {user_id} to index {index_name}"
            )

        # Criar novo acesso
        access = UserIndexAccess(
            user_id=user_id,
            es_server_id=es_server_id,
            index_name=index_name,
            can_read=can_read,
            can_write=can_write,
            can_create=can_create,
            created_by_id=created_by_id
        )

        self.db.add(access)
        self.db.commit()
        self.db.refresh(access)

        logger.info(
            f"✅ Granted access to index {index_name} for user {user.username} "
            f"(read={can_read}, write={can_write}, create={can_create})"
        )

        return access

    def revoke_index_access(
        self,
        access_id: str
    ) -> bool:
        """
        Remove acesso a um índice

        Args:
            access_id: ID do acesso a remover

        Returns:
            True se removido com sucesso
        """
        access = self.db.query(UserIndexAccess).filter(
            UserIndexAccess.id == access_id
        ).first()

        if not access:
            return False

        self.db.delete(access)
        self.db.commit()

        logger.info(f"✅ Revoked access {access_id}")
        return True

    def update_index_access(
        self,
        access_id: str,
        can_read: Optional[bool] = None,
        can_write: Optional[bool] = None,
        can_create: Optional[bool] = None
    ) -> Optional[UserIndexAccess]:
        """
        Atualiza permissões de um acesso existente

        Args:
            access_id: ID do acesso
            can_read: Nova permissão de leitura (None = não mudar)
            can_write: Nova permissão de escrita (None = não mudar)
            can_create: Nova permissão de criar (None = não mudar)

        Returns:
            UserIndexAccess atualizado ou None se não encontrado
        """
        access = self.db.query(UserIndexAccess).filter(
            UserIndexAccess.id == access_id
        ).first()

        if not access:
            return None

        # Atualizar campos se fornecidos
        if can_read is not None:
            access.can_read = can_read
        if can_write is not None:
            access.can_write = can_write
        if can_create is not None:
            access.can_create = can_create

        self.db.commit()
        self.db.refresh(access)

        logger.info(f"✅ Updated access {access_id}")
        return access

    def list_user_accesses(
        self,
        user_id: str,
        es_server_id: Optional[str] = None
    ) -> List[UserIndexAccess]:
        """
        Lista todos os acessos de um usuário

        Args:
            user_id: ID do usuário
            es_server_id: Filtrar por servidor (opcional)

        Returns:
            Lista de acessos do usuário
        """
        query = self.db.query(UserIndexAccess).filter(
            UserIndexAccess.user_id == user_id
        )

        if es_server_id:
            query = query.filter(UserIndexAccess.es_server_id == es_server_id)

        return query.all()


def get_index_authorization_service(db: Session) -> IndexAuthorizationService:
    """Factory para criar instância do service"""
    return IndexAuthorizationService(db)
