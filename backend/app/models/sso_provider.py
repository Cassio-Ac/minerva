"""
SSO Provider Model
Armazena configurações de provedores de SSO (Microsoft Entra ID, Google, Okta, etc)
"""
import uuid
import json
from datetime import datetime
from sqlalchemy import Column, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.services.encryption_service import EncryptionService


class SSOProvider(Base):
    """Modelo para provedores SSO (Microsoft Entra ID, Google, Okta, etc)"""

    __tablename__ = "sso_providers"
    __table_args__ = {'extend_existing': True}

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Basic info
    name = Column(String(100), nullable=False)  # Ex: "Microsoft Entra ID - Empresa X"
    provider_type = Column(String(50), nullable=False)  # 'entra_id', 'google', 'okta'

    # OAuth2/OIDC Configuration
    client_id = Column(String(255), nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)
    tenant_id = Column(String(255), nullable=True)  # Para Entra ID
    authority_url = Column(Text, nullable=True)
    redirect_uri = Column(Text, nullable=False)

    # Scopes (JSON array as string)
    scopes = Column(Text, nullable=True)

    # Role Mapping (JSONB)
    role_mapping = Column(JSONB, nullable=True)
    default_role = Column(String(50), default='reader')

    # Settings
    is_active = Column(Boolean, default=True, nullable=False)
    auto_provision = Column(Boolean, default=True, nullable=False)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    # created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<SSOProvider {self.name} ({self.provider_type})>"

    def to_dict(self):
        """Converte para dicionário (sem secrets)"""
        return {
            "id": str(self.id),
            "name": self.name,
            "provider_type": self.provider_type,
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "authority_url": self.authority_url,
            "redirect_uri": self.redirect_uri,
            "scopes": self.get_scopes_list(),
            "role_mapping": self.role_mapping,
            "default_role": self.default_role,
            "is_active": self.is_active,
            "auto_provision": self.auto_provision,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def get_scopes_list(self) -> list:
        """Retorna scopes como lista"""
        if not self.scopes:
            return []
        try:
            return json.loads(self.scopes)
        except:
            return self.scopes.split(",") if self.scopes else []

    def set_scopes_list(self, scopes: list):
        """Define scopes a partir de lista"""
        self.scopes = json.dumps(scopes)

    def get_client_secret(self) -> str:
        """Descriptografa e retorna client secret"""
        encryption_service = EncryptionService()
        return encryption_service.decrypt(self.client_secret_encrypted)

    def set_client_secret(self, client_secret: str):
        """Criptografa e armazena client secret"""
        encryption_service = EncryptionService()
        self.client_secret_encrypted = encryption_service.encrypt(client_secret)

    def get_authorize_url(self, state: str, nonce: str) -> str:
        """
        Gera URL de autorização para o provider

        Args:
            state: State parameter para CSRF protection
            nonce: Nonce para ID token validation

        Returns:
            URL completa para redirect do usuário
        """
        if self.provider_type == "entra_id":
            # Microsoft Entra ID (Azure AD)
            base_url = self.authority_url or f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
            scopes_str = " ".join(self.get_scopes_list())

            params = [
                f"client_id={self.client_id}",
                f"response_type=code",
                f"redirect_uri={self.redirect_uri}",
                f"response_mode=query",
                f"scope={scopes_str}",
                f"state={state}",
                f"nonce={nonce}",
                f"prompt=select_account",  # Força seleção de conta
            ]

            return f"{base_url}?{'&'.join(params)}"

        elif self.provider_type == "google":
            # Google OAuth2
            base_url = "https://accounts.google.com/o/oauth2/v2/auth"
            scopes_str = " ".join(self.get_scopes_list())

            params = [
                f"client_id={self.client_id}",
                f"response_type=code",
                f"redirect_uri={self.redirect_uri}",
                f"scope={scopes_str}",
                f"state={state}",
                f"access_type=offline",
            ]

            return f"{base_url}?{'&'.join(params)}"

        else:
            raise ValueError(f"Unsupported provider type: {self.provider_type}")

    def get_token_url(self) -> str:
        """Retorna URL para trocar code por token"""
        if self.provider_type == "entra_id":
            return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        elif self.provider_type == "google":
            return "https://oauth2.googleapis.com/token"
        else:
            raise ValueError(f"Unsupported provider type: {self.provider_type}")

    def get_userinfo_url(self) -> str:
        """Retorna URL para buscar informações do usuário"""
        if self.provider_type == "entra_id":
            return "https://graph.microsoft.com/v1.0/me"
        elif self.provider_type == "google":
            return "https://www.googleapis.com/oauth2/v2/userinfo"
        else:
            raise ValueError(f"Unsupported provider type: {self.provider_type}")
