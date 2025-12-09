"""
MISP Galaxy Cluster Model
Armazena clusters de threat intelligence (threat actors, malware, tools)
"""
from sqlalchemy import Column, String, Integer, Text, DateTime, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.db.database import Base


class GalaxyCluster(Base):
    """
    MISP Galaxy Cluster

    Representa um cluster do MISP Galaxy (threat actor, malware, tool, etc)
    """
    __tablename__ = "galaxy_clusters"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Identificação
    galaxy_type = Column(String(50), nullable=False, index=True)  # 'threat-actor', 'malpedia', 'tool'
    uuid_galaxy = Column(String(100), unique=True, nullable=False, index=True)  # UUID do cluster MISP
    value = Column(String(500), nullable=False, index=True)  # Nome (APT1, WannaCry, etc)
    description = Column(Text)

    # Metadados comuns
    country = Column(String(2), index=True)  # ISO code (CN, RU, US, etc)
    attribution_confidence = Column(Integer)  # 0-100
    synonyms = Column(JSON)  # Array de strings
    refs = Column(JSON)  # Array de URLs

    # Threat Actor específicos
    suspected_state_sponsor = Column(String(100))
    suspected_victims = Column(JSON)  # Array de países/organizações
    target_category = Column(JSON)  # Array de categorias (Government, Private sector)
    type_of_incident = Column(JSON)  # Array de tipos (Espionage, DDoS, etc)
    targeted_sector = Column(JSON)  # Array de setores industriais
    motive = Column(Text)

    # Malware específicos
    malware_type = Column(String(50))  # RAT, Trojan, Ransomware, etc

    # Metadados completos em JSON (para campos customizados)
    raw_meta = Column(JSON)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Índices compostos
    __table_args__ = (
        Index('idx_galaxy_type_value', 'galaxy_type', 'value'),
        Index('idx_galaxy_country_type', 'country', 'galaxy_type'),
    )

    def __repr__(self):
        return f"<GalaxyCluster {self.galaxy_type}:{self.value}>"

    def to_dict(self):
        """Serializa para dicionário"""
        return {
            "id": str(self.id),
            "galaxy_type": self.galaxy_type,
            "uuid_galaxy": self.uuid_galaxy,
            "value": self.value,
            "description": self.description,
            "country": self.country,
            "attribution_confidence": self.attribution_confidence,
            "synonyms": self.synonyms,
            "refs": self.refs,
            "suspected_state_sponsor": self.suspected_state_sponsor,
            "suspected_victims": self.suspected_victims,
            "target_category": self.target_category,
            "type_of_incident": self.type_of_incident,
            "targeted_sector": self.targeted_sector,
            "motive": self.motive,
            "malware_type": self.malware_type,
            "raw_meta": self.raw_meta,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class GalaxyRelationship(Base):
    """
    Relacionamentos entre clusters MISP Galaxy

    Ex: APT28 'uses' X-Agent malware
    """
    __tablename__ = "galaxy_relationships"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Relacionamento
    source_cluster_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    dest_cluster_uuid = Column(String(100), nullable=False, index=True)  # UUID do cluster destino
    relationship_type = Column(String(50), nullable=False, index=True)  # 'similar', 'uses', 'targets', 'derives-from'
    tags = Column(JSON)  # estimative-language, etc

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Índices compostos
    __table_args__ = (
        Index('idx_relationship_source_dest', 'source_cluster_id', 'dest_cluster_uuid'),
        Index('idx_relationship_type_source', 'relationship_type', 'source_cluster_id'),
    )

    def __repr__(self):
        return f"<GalaxyRelationship {self.source_cluster_id} {self.relationship_type} {self.dest_cluster_uuid}>"

    def to_dict(self):
        """Serializa para dicionário"""
        return {
            "id": str(self.id),
            "source_cluster_id": str(self.source_cluster_id),
            "dest_cluster_uuid": self.dest_cluster_uuid,
            "relationship_type": self.relationship_type,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
