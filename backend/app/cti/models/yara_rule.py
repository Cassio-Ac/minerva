"""
YARA Rule Model

Model para armazenar regras YARA do Neo23x0 Signature Base e outras fontes
"""
from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime, JSON, Index, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from app.db.database import Base
import uuid
from datetime import datetime


class YaraRule(Base):
    """
    YARA Rule - Detection signatures for malware and threats

    Stores individual YARA rules parsed from signature files
    """
    __tablename__ = "yara_rules"

    # Primary fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_name = Column(String(255), nullable=False, index=True)
    rule_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 of rule content

    # Source info
    source = Column(String(50), nullable=False, index=True)  # signature_base, malpedia, custom
    source_file = Column(String(255), nullable=False)  # Original filename
    source_url = Column(String(500))  # GitHub raw URL

    # Category/Classification
    category = Column(String(50), index=True)  # apt, crime, gen, mal, expl, etc
    threat_name = Column(String(255))  # Malware/threat name
    threat_actor = Column(String(255))  # APT name if applicable

    # Rule content
    rule_content = Column(Text, nullable=False)  # Full YARA rule text

    # Metadata extracted from rule
    description = Column(Text)
    author = Column(String(255))
    reference = Column(ARRAY(String), default=[])  # URLs
    date = Column(String(50))  # Date string from rule
    version = Column(String(50))

    # Tags and classification
    tags = Column(ARRAY(String), default=[])  # YARA rule tags
    mitre_attack = Column(ARRAY(String), default=[])  # ATT&CK techniques

    # Detection info
    severity = Column(String(20))  # critical, high, medium, low, info
    false_positive_risk = Column(String(20))  # high, medium, low

    # Strings and conditions (for search/analysis)
    strings_count = Column(Integer, default=0)
    condition_summary = Column(String(500))  # Simplified condition

    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_validated = Column(Boolean, default=False)  # Passed yara compilation test
    validation_error = Column(Text)

    # Sync metadata
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_updated = Column(DateTime)  # When rule was updated upstream

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes for performance
    __table_args__ = (
        Index('ix_yara_rules_source_category', 'source', 'category'),
        Index('ix_yara_rules_threat', 'threat_name', 'threat_actor'),
        Index('ix_yara_rules_tags', 'tags', postgresql_using='gin'),
        Index('ix_yara_rules_mitre', 'mitre_attack', postgresql_using='gin'),
        Index('ix_yara_rules_synced_at', 'synced_at'),
    )

    def __repr__(self):
        return f"<YaraRule {self.rule_name} ({self.source})>"


class YaraSyncHistory(Base):
    """
    YARA Sync History - Track synchronization jobs
    """
    __tablename__ = "yara_sync_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Sync metadata
    source = Column(String(50), nullable=False)  # signature_base, malpedia
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)

    # Stats
    files_processed = Column(Integer, default=0)
    rules_total = Column(Integer, default=0)
    rules_new = Column(Integer, default=0)
    rules_updated = Column(Integer, default=0)
    rules_unchanged = Column(Integer, default=0)
    rules_failed = Column(Integer, default=0)

    # Status
    status = Column(String(20), nullable=False, default="running")  # running, completed, failed
    error_message = Column(Text)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<YaraSyncHistory {self.source} ({self.status})>"


class SignatureBaseIOC(Base):
    """
    Signature Base IOCs - C2, hashes, filenames from Neo23x0
    """
    __tablename__ = "signature_base_iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # IOC data
    value = Column(String(500), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)  # c2, hash, filename, keyword

    # Context
    description = Column(Text)
    source_file = Column(String(100))  # c2-iocs.txt, hash-iocs.txt, etc

    # Hash-specific fields
    hash_type = Column(String(20))  # md5, sha1, sha256

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Sync metadata
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Unique constraint on value+type
    __table_args__ = (
        Index('ix_signature_base_iocs_type_value', 'type', 'value'),
        Index('ix_signature_base_iocs_hash_type', 'hash_type'),
    )

    def __repr__(self):
        return f"<SignatureBaseIOC {self.type}: {self.value[:50]}>"
