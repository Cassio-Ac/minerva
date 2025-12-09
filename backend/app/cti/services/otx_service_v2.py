"""
OTX Service V2 - Using OTXv2 SDK with Key Rotation

Service completo para buscar IOCs no AlienVault OTX usando SDK oficial
com suporte a múltiplas chaves e rotação automática
"""
from OTXv2 import OTXv2, IndicatorTypes
import logging
from typing import Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.cti.services.otx_key_manager import OTXKeyManager
from app.cti.models.otx_api_key import OTXAPIKey
import re

logger = logging.getLogger(__name__)


class OTXServiceV2:
    """Service para buscar IOCs no AlienVault OTX usando SDK oficial"""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.key_manager = OTXKeyManager(session)

    def _detect_indicator_type(self, indicator: str) -> IndicatorTypes:
        """
        Detecta o tipo de indicador automaticamente

        Args:
            indicator: O valor do indicador

        Returns:
            IndicatorTypes enum
        """
        # URL
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return IndicatorTypes.URL

        # IPv4
        ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ipv4_pattern, indicator):
            return IndicatorTypes.IPv4

        # IPv6
        if ":" in indicator and len(indicator) > 15:
            return IndicatorTypes.IPv6

        # File hash
        if len(indicator) == 32:  # MD5
            return IndicatorTypes.FILE_HASH_MD5
        if len(indicator) == 40:  # SHA1
            return IndicatorTypes.FILE_HASH_SHA1
        if len(indicator) == 64:  # SHA256
            return IndicatorTypes.FILE_HASH_SHA256

        # Domain/Hostname
        if "." in indicator and not indicator.startswith("http"):
            return IndicatorTypes.DOMAIN

        # Default to hostname
        return IndicatorTypes.HOSTNAME

    async def enrich_indicator(self, indicator: str) -> Dict:
        """
        Enriquecimento completo de um indicador usando OTX

        Busca em múltiplos endpoints:
        - general: Info básica + pulse count
        - reputation: Reputation score
        - geo: Geographic data
        - malware: Malware families
        - passive_dns: Historical DNS (IPs/domains)
        - url_list: URLs relacionadas

        Args:
            indicator: O valor do indicador (IP, domain, URL, hash)

        Returns:
            Dict com informações completas do OTX
        """
        # Detectar tipo
        ioc_type = self._detect_indicator_type(indicator)

        logger.info(f"🔍 Enriching {ioc_type}: {indicator}")

        # Obter chave disponível
        key = await self.key_manager.get_available_key()

        if not key:
            return {
                "found": False,
                "message": "No OTX API keys available",
                "error": "all_keys_exhausted"
            }

        try:
            # Criar cliente OTX
            otx = OTXv2(key.api_key)

            # Buscar dados de diferentes endpoints
            results = {}

            # 1. General (sempre)
            try:
                general = otx.get_indicator_details_by_section(ioc_type, indicator, 'general')
                results['general'] = general
            except Exception as e:
                logger.error(f"Error fetching general: {e}")
                results['general'] = None

            # 2. Reputation
            try:
                reputation = otx.get_indicator_details_by_section(ioc_type, indicator, 'reputation')
                results['reputation'] = reputation
            except Exception as e:
                logger.debug(f"Error fetching reputation: {e}")
                results['reputation'] = None

            # 3. Geo (IPs, domains, hostnames)
            if ioc_type in [IndicatorTypes.IPv4, IndicatorTypes.IPv6, IndicatorTypes.DOMAIN, IndicatorTypes.HOSTNAME]:
                try:
                    geo = otx.get_indicator_details_by_section(ioc_type, indicator, 'geo')
                    results['geo'] = geo
                except Exception as e:
                    logger.debug(f"Error fetching geo: {e}")
                    results['geo'] = None

            # 4. Malware
            try:
                malware = otx.get_indicator_details_by_section(ioc_type, indicator, 'malware')
                results['malware'] = malware
            except Exception as e:
                logger.debug(f"Error fetching malware: {e}")
                results['malware'] = None

            # 5. Passive DNS (IPs, domains)
            if ioc_type in [IndicatorTypes.IPv4, IndicatorTypes.IPv6, IndicatorTypes.DOMAIN]:
                try:
                    passive_dns = otx.get_indicator_details_by_section(ioc_type, indicator, 'passive_dns')
                    results['passive_dns'] = passive_dns
                except Exception as e:
                    logger.debug(f"Error fetching passive_dns: {e}")
                    results['passive_dns'] = None

            # 6. URL List
            try:
                url_list = otx.get_indicator_details_by_section(ioc_type, indicator, 'url_list')
                results['url_list'] = url_list
            except Exception as e:
                logger.debug(f"Error fetching url_list: {e}")
                results['url_list'] = None

            # 7. WHOIS (domains, hostnames)
            if ioc_type in [IndicatorTypes.DOMAIN, IndicatorTypes.HOSTNAME]:
                try:
                    whois = otx.get_indicator_details_by_section(ioc_type, indicator, 'whois')
                    results['whois'] = whois
                except Exception as e:
                    logger.debug(f"Error fetching whois: {e}")
                    results['whois'] = None

            # Consolidar resultados
            consolidated = self._consolidate_results(results, indicator, str(ioc_type))

            # Registrar uso da chave
            await self.key_manager.record_request(key, success=True)

            logger.info(f"✅ Enriched {indicator}: {consolidated.get('pulse_count', 0)} pulses")

            return consolidated

        except Exception as e:
            logger.error(f"❌ Error enriching indicator: {e}")

            # Verificar se é rate limit
            if "429" in str(e) or "rate" in str(e).lower():
                await self.key_manager.record_rate_limit_error(key)
            else:
                await self.key_manager.record_request(key, success=False)

            return {
                "found": False,
                "message": f"Error: {str(e)}",
                "error": "api_error"
            }

    def _consolidate_results(self, results: Dict, indicator: str, ioc_type: str) -> Dict:
        """
        Consolida resultados de múltiplos endpoints

        Args:
            results: Dict com resultados de cada endpoint
            indicator: Valor do indicador
            ioc_type: Tipo do indicador

        Returns:
            Dict consolidado
        """
        general = results.get('general', {})
        reputation = results.get('reputation', {})
        geo = results.get('geo', {})
        malware = results.get('malware', {})
        passive_dns = results.get('passive_dns', {})
        url_list = results.get('url_list', {})
        whois = results.get('whois', {})

        # Pulse info
        pulse_info = general.get('pulse_info', {}) if general else {}
        pulse_count = pulse_info.get('count', 0)

        if pulse_count == 0:
            return {
                "found": False,
                "indicator": indicator,
                "type": ioc_type,
                "message": "Not found in any OTX pulses"
            }

        # Extract pulse data
        pulses = pulse_info.get('pulses', [])

        tags = set()
        malware_families = set()
        adversaries = set()
        attack_ids = set()

        for pulse in pulses[:20]:  # First 20 pulses
            tags.update(pulse.get('tags', []))
            malware_families.update(pulse.get('malware_families', []))
            if pulse.get('adversary'):
                adversaries.add(pulse['adversary'])
            attack_ids.update(pulse.get('attack_ids', []))

        # Build consolidated response
        return {
            "found": True,
            "indicator": indicator,
            "type": ioc_type,
            "pulse_count": pulse_count,

            # Reputation
            "reputation": {
                "threat_score": reputation.get('threat_score', 0) if reputation else 0,
                "reputation_score": reputation.get('reputation', 0) if reputation else 0,
            },

            # Geographic data
            "geo": {
                "country": geo.get('country_name') if geo else None,
                "city": geo.get('city') if geo else None,
                "asn": geo.get('asn') if geo else None,
                "org": geo.get('organization') if geo else None,
                "continent": geo.get('continent_code') if geo else None,
            } if geo else None,

            # Malware
            "malware": {
                "families": list(malware_families) if malware_families else [],
                "samples": malware.get('data', [])[:5] if malware else []
            },

            # Threat intelligence
            "threat_intel": {
                "tags": list(tags)[:30],
                "adversaries": list(adversaries),
                "attack_ids": list(attack_ids),
            },

            # Passive DNS
            "passive_dns": {
                "count": len(passive_dns.get('passive_dns', [])) if passive_dns else 0,
                "records": passive_dns.get('passive_dns', [])[:10] if passive_dns else []
            } if passive_dns else None,

            # URLs
            "url_list": {
                "count": len(url_list.get('url_list', [])) if url_list else 0,
                "urls": url_list.get('url_list', [])[:10] if url_list else []
            } if url_list else None,

            # WHOIS
            "whois": whois if whois else None,

            # Pulse names
            "pulse_names": [p['name'] for p in pulses[:5]]
        }

    async def get_key_stats(self) -> Dict:
        """
        Retorna estatísticas de uso das chaves OTX

        Returns:
            Dict com estatísticas
        """
        return await self.key_manager.get_key_stats()
