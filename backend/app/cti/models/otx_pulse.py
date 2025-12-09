"""
OTX Pulse Model

Model para armazenar OTX Pulses sincronizados
"""
from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime, JSON, ForeignKey, Index, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from app.db.database import Base
import uuid
from datetime import datetime


class OTXPulse(Base):
    """
    OTX Pulse - Threat Intelligence from AlienVault OTX

    Represents a single pulse (threat report) from OTX
    """
    __tablename__ = "otx_pulses"

    # Primary fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pulse_id = Column(String(100), unique=True, nullable=False, index=True)  # OTX pulse ID
    name = Column(String(500), nullable=False)
    description = Column(Text)
    author_name = Column(String(200))

    # Pulse metadata
    created = Column(DateTime)  # When pulse was created in OTX
    modified = Column(DateTime)  # Last modified in OTX
    revision = Column(Integer, default=1)

    # Threat info
    tlp = Column(String(20))  # white, green, amber, red
    adversary = Column(String(200))
    targeted_countries = Column(ARRAY(String), default=[])
    industries = Column(ARRAY(String), default=[])
    tags = Column(ARRAY(String), default=[])
    references = Column(ARRAY(String), default=[])

    # Indicators count
    indicator_count = Column(Integer, default=0)

    # Attack patterns
    attack_ids = Column(ARRAY(String), default=[])  # MITRE ATT&CK IDs
    malware_families = Column(ARRAY(String), default=[])

    # Raw data
    raw_data = Column(JSON)  # Full OTX pulse JSON

    # Sync metadata
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    synced_by_key_id = Column(UUID(as_uuid=True), ForeignKey("otx_api_keys.id"))

    # MISP integration
    exported_to_misp = Column(Boolean, default=False, nullable=False)
    misp_event_id = Column(String(100))  # MISP event UUID
    exported_to_misp_at = Column(DateTime)

    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes for performance
    __table_args__ = (
        Index('ix_otx_pulses_created', 'created'),
        Index('ix_otx_pulses_synced_at', 'synced_at'),
        Index('ix_otx_pulses_exported_to_misp', 'exported_to_misp'),
        Index('ix_otx_pulses_tags', 'tags', postgresql_using='gin'),
        Index('ix_otx_pulses_attack_ids', 'attack_ids', postgresql_using='gin'),
    )

    def __repr__(self):
        return f"<OTXPulse {self.name} ({self.pulse_id})>"


class OTXPulseIndicator(Base):
    """
    OTX Pulse Indicator - IOCs from a pulse

    Represents individual indicators (IOCs) extracted from pulses
    """
    __tablename__ = "otx_pulse_indicators"

    # Primary fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pulse_id = Column(UUID(as_uuid=True), ForeignKey("otx_pulses.id", ondelete="CASCADE"), nullable=False, index=True)

    # Indicator data
    indicator = Column(String(500), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)  # IPv4, domain, URL, FileHash-SHA256, etc
    title = Column(String(500))
    description = Column(Text)

    # Context
    is_active = Column(Boolean, default=True, nullable=False)
    role = Column(String(50))  # malware, C2, phishing, etc

    # Enrichment data (from OTX)
    otx_enrichment = Column(JSON)  # Store full OTX enrichment data
    enriched_at = Column(DateTime)

    # MISP integration
    exported_to_misp = Column(Boolean, default=False, nullable=False)
    misp_attribute_id = Column(String(100))

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        Index('ix_otx_pulse_indicators_type_indicator', 'type', 'indicator'),
        Index('ix_otx_pulse_indicators_enriched', 'enriched_at'),
    )

    def __repr__(self):
        return f"<OTXPulseIndicator {self.type}: {self.indicator}>"


class OTXSyncHistory(Base):
    """
    OTX Sync History - Track synchronization jobs

    Records each sync operation for monitoring and debugging
    """
    __tablename__ = "otx_sync_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Sync metadata
    sync_type = Column(String(50), nullable=False)  # pulse_sync, bulk_enrichment, misp_export
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)

    # Stats
    pulses_fetched = Column(Integer, default=0)
    pulses_new = Column(Integer, default=0)
    pulses_updated = Column(Integer, default=0)
    indicators_processed = Column(Integer, default=0)
    indicators_enriched = Column(Integer, default=0)

    # Status
    status = Column(String(20), nullable=False, default="running")  # running, completed, failed
    error_message = Column(Text)

    # Key used
    api_key_id = Column(UUID(as_uuid=True), ForeignKey("otx_api_keys.id"))

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<OTXSyncHistory {self.sync_type} ({self.status})>"
