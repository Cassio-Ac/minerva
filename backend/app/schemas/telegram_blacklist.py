"""
Telegram Blacklist Schemas
Pydantic models for Telegram message blacklist API
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID


# ==================== Request Schemas ====================

class TelegramBlacklistCreateRequest(BaseModel):
    """Request to create a new blacklist entry"""
    pattern: str = Field(..., min_length=1, max_length=500, description="String pattern to filter from results")
    description: Optional[str] = Field(None, max_length=1000, description="Description of why this is blacklisted")
    is_regex: bool = Field(default=False, description="Whether the pattern is a regular expression")
    case_sensitive: bool = Field(default=False, description="Whether matching should be case sensitive")
    is_active: bool = Field(default=True, description="Whether this filter is active")


class TelegramBlacklistUpdateRequest(BaseModel):
    """Request to update a blacklist entry"""
    pattern: Optional[str] = Field(None, min_length=1, max_length=500, description="String pattern")
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    is_regex: Optional[bool] = Field(None, description="Whether the pattern is regex")
    case_sensitive: Optional[bool] = Field(None, description="Whether matching is case sensitive")
    is_active: Optional[bool] = Field(None, description="Whether this filter is active")


# ==================== Response Schemas ====================

class TelegramBlacklistResponse(BaseModel):
    """Response with blacklist entry details"""
    id: UUID
    pattern: str
    description: Optional[str]
    is_regex: bool
    case_sensitive: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID]

    class Config:
        from_attributes = True


class TelegramBlacklistListResponse(BaseModel):
    """Response with list of blacklist entries"""
    total: int
    items: list[TelegramBlacklistResponse]
