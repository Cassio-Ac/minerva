"""
Actor Schemas - Threat Actor data models
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ActorBase(BaseModel):
    """Base schema for threat actor"""
    name: str = Field(..., description="Actor name")
    aka: Optional[List[str]] = Field(None, description="Alternative names/aliases")
    explicacao: Optional[str] = Field(None, description="Actor description/explanation")
    familias_relacionadas: Optional[List[str]] = Field(None, description="Related malware families")
    url: Optional[str] = Field(None, description="Malpedia URL")


class ActorReference(BaseModel):
    """Reference/source for actor information"""
    desc: str = Field(..., description="Reference description")
    url: str = Field(..., description="Reference URL")


class ActorResponse(ActorBase):
    """Actor response with references"""
    referencias: Optional[List[ActorReference]] = Field(None, description="References")

    class Config:
        from_attributes = True


class ActorDetailResponse(ActorResponse):
    """Detailed actor response with enriched data"""
    total_families: int = Field(0, description="Number of related families")
    total_techniques: int = Field(0, description="Number of ATT&CK techniques used")
    techniques: Optional[List[str]] = Field(None, description="List of technique IDs (e.g., T1485)")


class ActorListResponse(BaseModel):
    """Response for actor list endpoint"""
    total: int = Field(..., description="Total number of actors")
    actors: List[ActorResponse] = Field(..., description="List of actors")
    page: Optional[int] = Field(1, description="Current page number")
    page_size: Optional[int] = Field(20, description="Items per page")
