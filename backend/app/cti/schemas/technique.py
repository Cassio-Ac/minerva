"""
Technique Schemas - MITRE ATT&CK Technique data models
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class TacticInfo(BaseModel):
    """MITRE ATT&CK Tactic information"""
    tactic_id: str = Field(..., description="Tactic ID (e.g., TA0001)")
    tactic_name: str = Field(..., description="Tactic name (e.g., Initial Access)")
    url: str = Field(..., description="ATT&CK tactic URL")


class MitigationInfo(BaseModel):
    """Mitigation information"""
    mitigation_id: str = Field(..., description="Mitigation ID (e.g., M1053)")
    name: str = Field(..., description="Mitigation name")
    description: str = Field(..., description="Mitigation description")
    url: str = Field(..., description="ATT&CK mitigation URL")


class TechniqueBase(BaseModel):
    """Base schema for ATT&CK technique"""
    technique_id: str = Field(..., description="Technique ID (e.g., T1485)")
    technique_name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    url: str = Field(..., description="ATT&CK technique URL")
    tactics: List[TacticInfo] = Field(..., description="Associated tactics")
    platforms: List[str] = Field(..., description="Platforms (e.g., Windows, Linux)")
    is_subtechnique: bool = Field(False, description="Whether this is a subtechnique")
    parent_technique: Optional[str] = Field(None, description="Parent technique ID if subtechnique")


class TechniqueResponse(TechniqueBase):
    """Technique response with additional data"""
    mitigations: Optional[List[MitigationInfo]] = Field(None, description="Mitigations")
    detection: Optional[str] = Field(None, description="Detection guidance")
    data_sources: Optional[List[str]] = Field(None, description="Data sources for detection")

    class Config:
        from_attributes = True


class TechniqueDetailResponse(TechniqueResponse):
    """Detailed technique response with usage information"""
    used_by_families: Optional[List[str]] = Field(None, description="Malware families using this technique")
    used_by_actors: Optional[List[str]] = Field(None, description="Threat actors using this technique")
    total_families: int = Field(0, description="Number of families using this")
    total_actors: int = Field(0, description="Number of actors using this")


class TechniqueListResponse(BaseModel):
    """Response for technique list endpoint"""
    total: int = Field(..., description="Total number of techniques")
    techniques: List[Dict[str, Any]] = Field(..., description="List of techniques")

    class Config:
        extra = "allow"


class TechniqueMatrixResponse(BaseModel):
    """Response for ATT&CK matrix visualization"""
    tactics: List[Dict[str, Any]] = Field(..., description="All tactics in order")
    techniques: List[Dict[str, Any]] = Field(..., description="All techniques")
    matrix: Dict[str, List[str]] = Field(
        ...,
        description="Matrix structure: {tactic_id: [technique_ids]}"
    )

    class Config:
        extra = "allow"


class TechniqueHighlightRequest(BaseModel):
    """Request to highlight techniques based on selection"""
    actors: Optional[List[str]] = Field(None, description="Selected actor names")
    families: Optional[List[str]] = Field(None, description="Selected family names")
    mode: str = Field("union", description="Highlight mode: 'union' or 'intersection'")


class TechniqueHighlightResponse(BaseModel):
    """Response with highlighted techniques"""
    highlighted_techniques: List[str] = Field(..., description="List of technique IDs to highlight")
    technique_details: Dict[str, Any] = Field(default_factory=dict, description="Details for each highlighted technique")
    message: Optional[str] = Field(None, description="Optional message (e.g., enrichment not available)")

    class Config:
        extra = "allow"
