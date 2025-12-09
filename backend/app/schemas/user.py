"""
User Schemas
Pydantic models for API request/response validation
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, validator
from app.models.user import UserRole


# ====================== REQUEST SCHEMAS =======================

class UserCreate(BaseModel):
    """Schema for creating a new user"""
    username: str = Field(..., min_length=3, max_length=50, description="Username (3-50 chars)")
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, max_length=100, description="Password (min 8 chars)")
    full_name: Optional[str] = Field(None, max_length=255, description="Full name")
    role: UserRole = Field(default=UserRole.READER, description="User role")
    assigned_es_server_id: Optional[str] = Field(None, description="Elasticsearch server ID (for OPERATOR role)")

    @validator('username')
    def username_alphanumeric(cls, v):
        """Validate username is alphanumeric with underscores and dashes"""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must contain only letters, numbers, underscores, and dashes')
        return v.lower()


class UserUpdate(BaseModel):
    """Schema for updating user information"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    assigned_es_server_id: Optional[str] = Field(None, description="Elasticsearch server ID (for OPERATOR role)")


class UserChangePassword(BaseModel):
    """Schema for changing password"""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password (min 8 chars)")


class UserLogin(BaseModel):
    """Schema for user login"""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="Password")


# ====================== RESPONSE SCHEMAS =======================

class UserResponse(BaseModel):
    """Schema for user response (safe - no password)"""
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_superuser: bool
    created_at: str
    updated_at: str
    last_login: Optional[str]
    assigned_es_server_id: Optional[str] = Field(None, description="Elasticsearch server ID (for OPERATOR role)")

    # Profile photo fields
    profile_photo_url: Optional[str] = Field(None, description="URL da foto de perfil (relativa)")
    photo_source: Optional[str] = Field(None, description="Fonte da foto: 'entra_id', 'upload', 'gravatar', 'default'")
    photo_updated_at: Optional[str] = Field(None, description="Data da última atualização da foto")

    # Permissions (computed)
    can_manage_users: bool = Field(..., description="Can manage other users")
    can_use_llm: bool = Field(..., description="Can use LLM features")
    can_create_dashboards: bool = Field(..., description="Can create dashboards")
    can_upload_csv: bool = Field(..., description="Can upload CSV files")
    has_index_restrictions: bool = Field(..., description="Has index-level restrictions")
    can_configure_system: bool = Field(..., description="Can configure system")

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema for user list response"""
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: str
    last_login: Optional[str]

    class Config:
        from_attributes = True


class Token(BaseModel):
    """Schema for authentication token"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    """Schema for token data (decoded JWT)"""
    user_id: str
    username: str
    role: str
    exp: Optional[datetime] = None
