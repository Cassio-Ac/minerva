"""
Unified IOC Source Adapters

Adapters transform source-specific data formats to the unified IOC format.
Each source has its own adapter that handles normalization and field mapping.

To add a new source:
1. Create a new adapter class inheriting from BaseIOCAdapter
2. Implement the transform() method
3. Register in the ADAPTERS dict at the bottom
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


class BaseIOCAdapter(ABC):
    """Base adapter for IOC sources"""

    source_name: str = "unknown"
    source_reputation: float = 0.5

    @abstractmethod
    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform source-specific data to unified format.

        Args:
            raw_data: Raw data from the source

        Returns:
            Unified IOC format dict with standardized fields
        """
        pass

    def transform_batch(self, items: List[Dict]) -> List[Dict]:
        """Transform batch of items, skipping invalid ones"""
        results = []
        for item in items:
            if item:
                try:
                    transformed = self.transform(item)
                    if transformed and transformed.get("value"):
                        results.append(transformed)
                except Exception:
                    continue
        return results

    def _normalize_confidence(self, confidence: Any) -> float:
        """Normalize confidence to float 0.0-1.0"""
        if confidence is None:
            return 0.6  # Default medium

        if isinstance(confidence, (int, float)):
            if confidence > 1:
                return min(1.0, confidence / 100)  # Assume 0-100 scale
            return float(confidence)

        if isinstance(confidence, str):
            return {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.9,
                "critical": 1.0
            }.get(confidence.lower(), 0.6)

        return 0.6


class MISPIOCAdapter(BaseIOCAdapter):
    """Adapter for MISP IOCs (from misp_iocs table)"""

    source_name = "misp"
    source_reputation = 0.75

    # MISP type to normalized type mapping
    TYPE_MAP = {
        # IP types
        "ip-dst": "ip",
        "ip-src": "ip",
        "ip-dst|port": "ip",
        "ip-src|port": "ip",

        # Domain types
        "domain": "domain",
        "domain|ip": "domain",
        "hostname": "domain",
        "hostname|port": "domain",

        # URL types
        "url": "url",
        "uri": "url",
        "link": "url",

        # Hash types
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "sha512": "hash",
        "sha224": "hash",
        "sha384": "hash",
        "ssdeep": "hash",
        "imphash": "hash",
        "pehash": "hash",
        "tlsh": "hash",
        "authentihash": "hash",
        "filename|md5": "hash",
        "filename|sha1": "hash",
        "filename|sha256": "hash",

        # Email types
        "email": "email",
        "email-src": "email",
        "email-dst": "email",
        "email-subject": "email",
        "email-attachment": "email",

        # SSL/Certificate
        "x509-fingerprint-sha1": "hash",
        "x509-fingerprint-sha256": "hash",
        "x509-fingerprint-md5": "hash",
    }

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform MISP IOC to unified format"""
        ioc_type = raw_data.get("ioc_type", "").lower()
        ioc_subtype = raw_data.get("ioc_subtype", "")

        # Normalize type
        normalized_type = self.TYPE_MAP.get(ioc_subtype, ioc_type)
        if not normalized_type:
            normalized_type = self.TYPE_MAP.get(ioc_type, "other")

        return {
            "value": raw_data.get("ioc_value"),
            "type": normalized_type,
            "subtype": ioc_subtype or ioc_type,
            "source_id": str(raw_data.get("id", "")),
            "source_ref": str(raw_data.get("feed_id", "")),
            "confidence": self._normalize_confidence(raw_data.get("confidence")),
            "reputation": self.source_reputation,
            "context": raw_data.get("context"),
            "malware_family": raw_data.get("malware_family"),
            "threat_actor": raw_data.get("threat_actor"),
            "threat_type": None,
            "tags": raw_data.get("tags") or [],
            "tlp": raw_data.get("tlp", "white"),
            "first_seen": self._format_date(raw_data.get("first_seen")),
            "to_ids": raw_data.get("to_ids", False),
            "attack_ids": [],
            "references": [],
            "targeted_countries": [],
            "industries": [],
            "campaigns": [],
            "raw_data": None  # Don't store raw for MISP (already in PG)
        }

    def _format_date(self, date_val: Any) -> Optional[str]:
        """Format date to ISO string"""
        if date_val is None:
            return None
        if isinstance(date_val, str):
            return date_val
        if isinstance(date_val, datetime):
            return date_val.isoformat()
        return None


class OTXIOCAdapter(BaseIOCAdapter):
    """Adapter for OTX Pulse Indicators"""

    source_name = "otx"
    source_reputation = 0.70

    # OTX type to normalized type mapping
    TYPE_MAP = {
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "uri": "url",
        "filehash-md5": "hash",
        "filehash-sha1": "hash",
        "filehash-sha256": "hash",
        "filehash-sha512": "hash",
        "filehash-pehash": "hash",
        "filehash-imphash": "hash",
        "email": "email",
        "cve": "other",
        "mutex": "other",
        "yara": "other",
    }

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform OTX indicator to unified format.

        Note: OTX data may come from either:
        - Indicator level (from otx_pulse_indicators table)
        - Pulse level (from otx_pulses table with indicators)
        """
        indicator_type = raw_data.get("type", "").lower()
        normalized_type = self.TYPE_MAP.get(indicator_type, "other")

        # Handle indicator value (may be in different fields)
        value = raw_data.get("indicator") or raw_data.get("value")

        # Extract pulse-level data if present
        pulse_data = raw_data.get("pulse", {})

        return {
            "value": value,
            "type": normalized_type,
            "subtype": indicator_type,
            "source_id": str(raw_data.get("id", "")),
            "source_ref": raw_data.get("pulse_id") or pulse_data.get("pulse_id"),
            "confidence": 0.7,  # OTX default confidence
            "reputation": self.source_reputation,
            "context": raw_data.get("description") or raw_data.get("title"),
            "malware_family": self._extract_malware_family(raw_data, pulse_data),
            "threat_actor": raw_data.get("adversary") or pulse_data.get("adversary"),
            "threat_type": raw_data.get("role"),  # C2, malware, phishing, etc.
            "tags": raw_data.get("tags") or pulse_data.get("tags") or [],
            "tlp": raw_data.get("tlp") or pulse_data.get("tlp") or "white",
            "first_seen": self._format_date(
                raw_data.get("created") or pulse_data.get("created")
            ),
            "to_ids": True,
            "attack_ids": raw_data.get("attack_ids") or pulse_data.get("attack_ids") or [],
            "references": raw_data.get("references") or pulse_data.get("references") or [],
            "targeted_countries": (
                raw_data.get("targeted_countries") or
                pulse_data.get("targeted_countries") or []
            ),
            "industries": (
                raw_data.get("industries") or
                pulse_data.get("industries") or []
            ),
            "campaigns": [],
            "raw_data": raw_data.get("otx_enrichment")  # Store enrichment if present
        }

    def _extract_malware_family(
        self,
        raw_data: Dict[str, Any],
        pulse_data: Dict[str, Any]
    ) -> Optional[str]:
        """Extract malware family from data"""
        # Check direct field
        if raw_data.get("malware_family"):
            return raw_data["malware_family"]

        # Check pulse malware_families array
        families = pulse_data.get("malware_families", [])
        if families:
            return families[0] if isinstance(families, list) else families

        return None

    def _format_date(self, date_val: Any) -> Optional[str]:
        """Format date to ISO string"""
        if date_val is None:
            return None
        if isinstance(date_val, str):
            return date_val
        if isinstance(date_val, datetime):
            return date_val.isoformat()
        return None


class ThreatFoxAdapter(BaseIOCAdapter):
    """Adapter for ThreatFox IOCs (abuse.ch)"""

    source_name = "threatfox"
    source_reputation = 0.90

    TYPE_MAP = {
        "ip:port": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash",
        "sha256_hash": "hash",
    }

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform ThreatFox IOC to unified format"""
        ioc_type = raw_data.get("ioc_type", "").lower()
        normalized_type = self.TYPE_MAP.get(ioc_type, "other")

        return {
            "value": raw_data.get("ioc") or raw_data.get("value"),
            "type": normalized_type,
            "subtype": ioc_type,
            "source_id": str(raw_data.get("id", "")),
            "source_ref": str(raw_data.get("threat_id", "")),
            "confidence": 0.9,  # ThreatFox is high quality
            "reputation": self.source_reputation,
            "context": raw_data.get("threat_type_desc"),
            "malware_family": raw_data.get("malware"),
            "threat_actor": None,
            "threat_type": raw_data.get("threat_type"),
            "tags": raw_data.get("tags") or [],
            "tlp": "white",
            "first_seen": raw_data.get("first_seen"),
            "to_ids": True,
            "attack_ids": [],
            "references": [raw_data.get("reference")] if raw_data.get("reference") else [],
            "targeted_countries": [],
            "industries": [],
            "campaigns": [],
            "raw_data": None
        }


class URLHausAdapter(BaseIOCAdapter):
    """Adapter for URLhaus IOCs (abuse.ch)"""

    source_name = "urlhaus"
    source_reputation = 0.85

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform URLhaus IOC to unified format"""
        return {
            "value": raw_data.get("url") or raw_data.get("value"),
            "type": "url",
            "subtype": "malware_url",
            "source_id": str(raw_data.get("id", "")),
            "source_ref": str(raw_data.get("urlhaus_reference", "")),
            "confidence": 0.85,
            "reputation": self.source_reputation,
            "context": raw_data.get("threat"),
            "malware_family": raw_data.get("payload"),
            "threat_actor": None,
            "threat_type": "malware_delivery",
            "tags": raw_data.get("tags") or [],
            "tlp": "white",
            "first_seen": raw_data.get("date_added"),
            "to_ids": True,
            "attack_ids": [],
            "references": [],
            "targeted_countries": [],
            "industries": [],
            "campaigns": [],
            "raw_data": None
        }


class VirusTotalAdapter(BaseIOCAdapter):
    """Adapter for VirusTotal IOCs (future integration)"""

    source_name = "virustotal"
    source_reputation = 0.95

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform VirusTotal IOC to unified format"""
        ioc_type = raw_data.get("type", "").lower()

        return {
            "value": raw_data.get("id") or raw_data.get("value"),
            "type": ioc_type if ioc_type in ["ip", "domain", "url", "hash"] else "other",
            "subtype": raw_data.get("type"),
            "source_id": raw_data.get("id"),
            "source_ref": None,
            "confidence": self._calculate_vt_confidence(raw_data),
            "reputation": self.source_reputation,
            "context": raw_data.get("meaningful_name"),
            "malware_family": self._extract_vt_family(raw_data),
            "threat_actor": None,
            "threat_type": "malware" if raw_data.get("last_analysis_stats", {}).get("malicious", 0) > 0 else None,
            "tags": raw_data.get("tags") or [],
            "tlp": "white",
            "first_seen": raw_data.get("first_submission_date"),
            "to_ids": True,
            "attack_ids": [],
            "references": [],
            "targeted_countries": [],
            "industries": [],
            "campaigns": [],
            "raw_data": raw_data.get("last_analysis_stats")
        }

    def _calculate_vt_confidence(self, raw_data: Dict[str, Any]) -> float:
        """Calculate confidence based on VT detection ratio"""
        stats = raw_data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        if malicious == 0:
            return 0.3

        ratio = malicious / total
        return min(0.95, 0.5 + (ratio * 0.45))

    def _extract_vt_family(self, raw_data: Dict[str, Any]) -> Optional[str]:
        """Extract malware family from VT results"""
        popular_threat = raw_data.get("popular_threat_classification", {})
        family = popular_threat.get("popular_threat_name", [])
        if family:
            return family[0].get("value") if isinstance(family[0], dict) else family[0]
        return None


class AbuseIPDBAdapter(BaseIOCAdapter):
    """Adapter for AbuseIPDB IOCs (future integration)"""

    source_name = "abuseipdb"
    source_reputation = 0.85

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform AbuseIPDB IOC to unified format"""
        abuse_score = raw_data.get("abuseConfidenceScore", 0)

        return {
            "value": raw_data.get("ipAddress") or raw_data.get("value"),
            "type": "ip",
            "subtype": "ip-dst",
            "source_id": raw_data.get("ipAddress"),
            "source_ref": None,
            "confidence": min(0.95, abuse_score / 100),
            "reputation": self.source_reputation,
            "context": f"Reports: {raw_data.get('totalReports', 0)}, ISP: {raw_data.get('isp', 'Unknown')}",
            "malware_family": None,
            "threat_actor": None,
            "threat_type": self._map_abuse_categories(raw_data.get("categories", [])),
            "tags": self._categories_to_tags(raw_data.get("categories", [])),
            "tlp": "white",
            "first_seen": raw_data.get("lastReportedAt"),
            "to_ids": abuse_score >= 50,
            "attack_ids": [],
            "references": [],
            "targeted_countries": [],
            "industries": [],
            "campaigns": [],
            "raw_data": None
        }

    def _map_abuse_categories(self, categories: List[int]) -> Optional[str]:
        """Map AbuseIPDB category codes to threat types"""
        category_map = {
            1: "dns_compromise",
            2: "dns_poisoning",
            3: "fraud_voip",
            4: "ddos",
            5: "ftp_brute_force",
            6: "ping_of_death",
            7: "phishing",
            9: "open_proxy",
            10: "web_spam",
            11: "email_spam",
            14: "port_scan",
            15: "hacking",
            18: "brute_force",
            19: "bad_web_bot",
            20: "exploited_host",
            21: "web_app_attack",
            22: "ssh",
            23: "iot_targeted",
        }
        for cat in categories:
            if cat in category_map:
                return category_map[cat]
        return None

    def _categories_to_tags(self, categories: List[int]) -> List[str]:
        """Convert category codes to tags"""
        category_names = {
            4: "ddos",
            7: "phishing",
            14: "port-scan",
            15: "hacking",
            18: "brute-force",
            22: "ssh-attack",
        }
        return [category_names[c] for c in categories if c in category_names]


class ShodanAdapter(BaseIOCAdapter):
    """Adapter for Shodan IOCs (future integration)"""

    source_name = "shodan"
    source_reputation = 0.80

    def transform(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Shodan IOC to unified format"""
        return {
            "value": raw_data.get("ip_str") or raw_data.get("value"),
            "type": "ip",
            "subtype": "ip-dst",
            "source_id": raw_data.get("ip_str"),
            "source_ref": None,
            "confidence": 0.7,
            "reputation": self.source_reputation,
            "context": f"Org: {raw_data.get('org', 'Unknown')}, Ports: {raw_data.get('ports', [])}",
            "malware_family": None,
            "threat_actor": None,
            "threat_type": "exposed_service",
            "tags": raw_data.get("tags") or [],
            "tlp": "white",
            "first_seen": raw_data.get("last_update"),
            "to_ids": False,
            "attack_ids": [],
            "references": [],
            "targeted_countries": [raw_data.get("country_code")] if raw_data.get("country_code") else [],
            "industries": [],
            "campaigns": [],
            "raw_data": {
                "ports": raw_data.get("ports"),
                "vulns": raw_data.get("vulns"),
            } if raw_data.get("vulns") else None
        }


# ============ ADAPTER REGISTRY ============

ADAPTERS: Dict[str, BaseIOCAdapter] = {
    "misp": MISPIOCAdapter(),
    "otx": OTXIOCAdapter(),
    "threatfox": ThreatFoxAdapter(),
    "urlhaus": URLHausAdapter(),
    "virustotal": VirusTotalAdapter(),
    "abuseipdb": AbuseIPDBAdapter(),
    "shodan": ShodanAdapter(),
}


def get_adapter(source_name: str) -> BaseIOCAdapter:
    """
    Get adapter for a source.

    Args:
        source_name: Name of the source (misp, otx, etc.)

    Returns:
        Adapter instance for the source
    """
    adapter = ADAPTERS.get(source_name.lower())
    if adapter:
        return adapter

    # Return MISP adapter as fallback (most generic)
    return ADAPTERS["misp"]


def list_adapters() -> List[Dict[str, Any]]:
    """List all available adapters with their metadata"""
    return [
        {
            "name": name,
            "source_name": adapter.source_name,
            "reputation": adapter.source_reputation,
        }
        for name, adapter in ADAPTERS.items()
    ]
