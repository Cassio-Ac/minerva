"""
AlienVault OTX Service

Service para buscar IOCs no AlienVault OTX (Open Threat Exchange)
"""
import requests
import logging
from typing import Dict, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


class OTXService:
    """Service para buscar IOCs no AlienVault OTX"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OTX_API_KEY
        if not self.api_key:
            logger.warning("⚠️ OTX API key not configured")

    def search_indicator(self, indicator: str, indicator_type: str = "general") -> Dict:
        """
        Buscar indicador no OTX

        Args:
            indicator: O valor do indicador (IP, domain, URL, hash)
            indicator_type: Tipo (IPv4, domain, url, file_hash, hostname)

        Returns:
            Dict com informações do OTX ou indicando não encontrado
        """
        if not self.api_key:
            return {
                "found": False,
                "message": "OTX API key not configured",
                "pulses": 0
            }

        # Detect indicator type
        ioc_type = self._detect_indicator_type(indicator)

        try:
            # OTX API endpoint for indicator lookup
            url = f"{self.BASE_URL}/indicators/{ioc_type}/{indicator}/general"

            headers = {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json"
            }

            logger.info(f"🔍 Searching OTX for {ioc_type}: {indicator}")
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                return {
                    "found": False,
                    "message": "Indicator not found in OTX",
                    "pulses": 0
                }

            if response.status_code != 200:
                logger.error(f"❌ OTX API error: {response.status_code}")
                return {
                    "found": False,
                    "message": f"OTX API error: {response.status_code}",
                    "pulses": 0
                }

            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count == 0:
                return {
                    "found": False,
                    "message": "Indicator not found in any OTX pulses",
                    "pulses": 0
                }

            # Extract useful information
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])

            # Get tags and malware families from pulses
            all_tags = set()
            malware_families = set()

            for pulse in pulses[:10]:  # First 10 pulses
                tags = pulse.get("tags", [])
                all_tags.update(tags)

                # Extract malware families from tags
                for tag in tags:
                    if "malware" in tag.lower() or "apt" in tag.lower():
                        malware_families.add(tag)

            result = {
                "found": True,
                "pulses": pulse_count,
                "tags": list(all_tags)[:20],  # Top 20 tags
                "malware_families": list(malware_families) if malware_families else None,
                "pulse_names": [p.get("name") for p in pulses[:5]],  # First 5 pulse names
                "message": f"Found in {pulse_count} OTX pulses"
            }

            logger.info(f"✅ Found in OTX: {pulse_count} pulses")
            return result

        except requests.Timeout:
            logger.error("❌ OTX API timeout")
            return {
                "found": False,
                "message": "OTX API timeout",
                "pulses": 0
            }
        except Exception as e:
            logger.error(f"❌ Error searching OTX: {e}")
            return {
                "found": False,
                "message": f"Error: {str(e)}",
                "pulses": 0
            }

    def _detect_indicator_type(self, indicator: str) -> str:
        """
        Detecta o tipo de indicador automaticamente

        Args:
            indicator: O valor do indicador

        Returns:
            Tipo do indicador para OTX API (IPv4, domain, url, hostname, file)
        """
        import re

        # URL
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"

        # IPv4
        ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ipv4_pattern, indicator):
            return "IPv4"

        # IPv6
        if ":" in indicator and len(indicator) > 15:
            return "IPv6"

        # File hash (MD5, SHA1, SHA256)
        if len(indicator) == 32:  # MD5
            return "file"
        if len(indicator) == 40:  # SHA1
            return "file"
        if len(indicator) == 64:  # SHA256
            return "file"

        # Domain/Hostname
        if "." in indicator and not indicator.startswith("http"):
            return "domain"

        # Default to hostname
        return "hostname"
