"""
Family Schemas - Malware Family data models
"""

from typing import List, Optional
from datetime import date
from pydantic import BaseModel, Field


class YaraRule(BaseModel):
    """YARA rule for malware detection"""
    nome: str = Field(..., description="Rule name")
    url: str = Field(..., description="Rule download URL")
    conteudo: Optional[str] = Field(None, description="Rule content")


class FamilyReference(BaseModel):
    """Reference/source for family information"""
    desc: str = Field(..., description="Reference description")
    url: str = Field(..., description="Reference URL")


class FamilyBase(BaseModel):
    """Base schema for malware family"""
    name: str = Field(..., description="Family name")
    os: Optional[str] = Field(None, description="Target operating system")
    aka: Optional[List[str]] = Field(None, description="Alternative names")
    descricao: Optional[str] = Field(None, description="Family description")
    url: Optional[str] = Field(None, description="Malpedia URL")
    status: Optional[str] = Field(None, description="Sample status")
    update: Optional[date] = Field(None, description="Last update date")


class FamilyResponse(FamilyBase):
    """Family response with references and YARA rules"""
    referencias: Optional[List[FamilyReference]] = Field(None, description="References")
    yara_rules: Optional[List[YaraRule]] = Field(None, description="YARA rules")
    actors: Optional[List[str]] = Field(None, description="Associated actors")

    class Config:
        from_attributes = True


class AttackTechnique(BaseModel):
    """MITRE ATT&CK Technique"""
    technique_id: str = Field(..., description="Technique ID (e.g., T1485)")
    technique_name: str = Field(..., description="Technique name")
    tactic: str = Field(..., description="Tactic name")
    tactic_id: str = Field(..., description="Tactic ID (e.g., TA0040)")
    url: str = Field(..., description="ATT&CK URL")
    subtechnique_of: Optional[str] = Field(None, description="Parent technique ID if subtechnique")


class FamilyDetailResponse(FamilyResponse):
    """Detailed family response with enriched ATT&CK data"""
    techniques: Optional[List[AttackTechnique]] = Field(None, description="ATT&CK techniques")
    total_techniques: int = Field(0, description="Number of techniques")


class FamilyListResponse(BaseModel):
    """Response for family list endpoint"""
    total: int = Field(..., description="Total number of families")
    families: List[FamilyResponse] = Field(..., description="List of families")
    page: Optional[int] = Field(1, description="Current page number")
    page_size: Optional[int] = Field(20, description="Items per page")


class FamilyFilterRequest(BaseModel):
    """Request for filtering families"""
    os: Optional[List[str]] = Field(None, description="Filter by OS (e.g., Windows, Linux)")
    actors: Optional[List[str]] = Field(None, description="Filter by actor names")
    tags: Optional[List[str]] = Field(None, description="Filter by tags (e.g., ransomware, wiper)")
    search: Optional[str] = Field(None, description="Search query")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")
