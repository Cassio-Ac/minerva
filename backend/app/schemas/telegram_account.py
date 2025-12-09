"""
Telegram Account Schemas
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from uuid import UUID


class TelegramAccountBase(BaseModel):
    """Base schema for Telegram Account"""
    name: str = Field(..., min_length=1, max_length=100, description="Nome amigável da conta")
    api_id: int = Field(..., description="API ID do Telegram")
    api_hash: str = Field(..., min_length=32, max_length=32, description="API Hash do Telegram")
    phone: str = Field(..., pattern=r"^\+\d{10,15}$", description="Número de telefone com código do país (ex: +5585997783113)")
    session_name: str = Field(..., min_length=1, max_length=100, description="Nome do arquivo de sessão (ex: session_paloma)")
    is_active: bool = Field(default=True, description="Se a conta está ativa")


class TelegramAccountCreate(TelegramAccountBase):
    """Schema for creating a new Telegram Account"""
    pass


class TelegramAccountUpdate(BaseModel):
    """Schema for updating a Telegram Account"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    api_id: Optional[int] = None
    api_hash: Optional[str] = Field(None, min_length=32, max_length=32)
    phone: Optional[str] = Field(None, pattern=r"^\+\d{10,15}$")
    session_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None


class TelegramAccountResponse(BaseModel):
    """Schema for Telegram Account response (sem campos criptografados)"""
    id: UUID
    name: str
    phone_masked: str  # Telefone mascarado (ex: +55***********13)
    session_name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TelegramAccountDetail(TelegramAccountResponse):
    """Schema for detailed Telegram Account (usado apenas para exportação)"""
    api_id: int
    api_hash: str
    phone: str

    class Config:
        from_attributes = True
