"""
IOC Enrichment Service

Enriquece IOCs (Indicators of Compromise) usando LLM e integrações externas.

Strategy:
1. Analisa IOC e seu contexto (feed, tags, malware family)
2. Usa LLM para inferir contexto adicional e threat intelligence
3. Mapeia para MITRE ATT&CK techniques quando possível
4. Retorna IOC enriquecido com metadata adicional

Author: Claude + Angello Cassio
Date: 2025-11-21
"""

import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from .attack_service import get_attack_service

logger = logging.getLogger(__name__)


class IOCEnrichmentService:
    """
    Service to enrich IOCs using LLM and MITRE ATT&CK
    """

    def __init__(self):
        self.attack_service = get_attack_service()

    def _build_ioc_enrichment_prompt(self, ioc_data: Dict[str, Any]) -> str:
        """
        Constrói prompt para LLM analisar e enriquecer IOC

        Args:
            ioc_data: Dados do IOC

        Returns:
            Prompt formatado
        """
        ioc_type = ioc_data.get('type', 'unknown')
        ioc_value = ioc_data.get('value', '')
        ioc_subtype = ioc_data.get('subtype', '')
        context = ioc_data.get('context', 'No context available')
        tags = ioc_data.get('tags', [])
        malware_family = ioc_data.get('malware_family')
        threat_actor = ioc_data.get('threat_actor')
        feed_source = ioc_data.get('feed_source', 'Unknown')

        # Get common MITRE ATT&CK techniques
        self.attack_service._ensure_loaded()
        all_techniques = self.attack_service._attack_data.get_techniques(remove_revoked_deprecated=True)

        # Create list of common techniques for C2, malware delivery, etc
        techniques_list = []
        relevant_keywords = ['command', 'control', 'c2', 'malware', 'phishing', 'execution', 'persistence']

        for tech in all_techniques[:200]:
            tech_id = None
            tech_name = getattr(tech, 'name', 'Unknown')

            # Filter relevant techniques
            if any(keyword in tech_name.lower() for keyword in relevant_keywords):
                if hasattr(tech, 'external_references'):
                    for ref in tech.external_references:
                        if ref.source_name == 'mitre-attack' and hasattr(ref, 'external_id'):
                            tech_id = ref.external_id
                            break

                if tech_id:
                    techniques_list.append(f"- {tech_id}: {tech_name}")

        techniques_reference = "\n".join(techniques_list[:30])  # Top 30 relevant techniques

        prompt = f"""Você é um especialista em CTI (Cyber Threat Intelligence) e análise de IOCs.

**TAREFA:**
Analise o IOC (Indicator of Compromise) abaixo e forneça contexto de threat intelligence.

**IOC DETAILS:**
- Tipo: {ioc_type} ({ioc_subtype})
- Valor: {ioc_value[:100]}{'...' if len(ioc_value) > 100 else ''}
- Contexto: {context}
- Tags: {', '.join(tags[:10]) if tags else 'None'}
- Malware Family: {malware_family if malware_family else 'Unknown'}
- Threat Actor: {threat_actor if threat_actor else 'Unknown'}
- Fonte: {feed_source}

**INSTRUÇÕES:**
1. Analise o tipo de IOC e seu contexto
2. Determine o propósito provável deste IOC (C2, phishing, malware delivery, etc.)
3. Sugira técnicas MITRE ATT&CK que PROVAVELMENTE estão associadas a este IOC
4. Avalie o nível de severidade (critical/high/medium/low)
5. Forneça recomendações de detecção

**TIPOS DE IOC E TÉCNICAS COMUNS:**
- **IPs maliciosos**: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)
- **URLs de phishing**: T1566 (Phishing), T1204 (User Execution)
- **Domínios C2**: T1071.001 (Web Protocols), T1095 (Non-Application Layer Protocol)
- **SSL fingerprints**: T1573.002 (Asymmetric Cryptography), T1071.001 (Web Protocols)
- **Hashes de malware**: T1204 (User Execution), T1027 (Obfuscated Files)

**TÉCNICAS MITRE ATT&CK RELEVANTES:**
{techniques_reference}

**FORMATO DE RESPOSTA:**
Retorne APENAS um JSON no seguinte formato (sem markdown, sem explicações):

{{
    "threat_type": "c2" | "phishing" | "malware_delivery" | "data_exfiltration" | "reconnaissance" | "other",
    "severity": "critical" | "high" | "medium" | "low",
    "techniques": ["T1071.001", "T1573.002", ...],
    "tactics": ["command-and-control", "initial-access", ...],
    "summary": "Breve resumo (1-2 linhas) do que este IOC representa",
    "detection_methods": ["método 1", "método 2", ...],
    "confidence": "high" | "medium" | "low"
}}

**REGRAS:**
- Retorne entre 2 a 8 técnicas (não mais)
- Use APENAS IDs válidos do MITRE ATT&CK (formato: T####.###)
- Tactics deve ser slug format (lowercase com hífen)
- detection_methods: 2-5 métodos práticos de detecção
- Confidence "high" se houver malware_family ou threat_actor conhecido
- Confidence "medium" para IOCs com bom contexto
- Confidence "low" para IOCs genéricos

Retorne APENAS o JSON, sem texto adicional."""

        return prompt

    async def enrich_ioc_with_llm(
        self,
        ioc_data: Dict[str, Any],
        llm_provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enriquece IOC usando LLM

        Args:
            ioc_data: Dados do IOC
            llm_provider: Provider LLM a usar (opcional, usa default)

        Returns:
            {
                "threat_type": "c2|phishing|...",
                "severity": "critical|high|medium|low",
                "techniques": ["T1071.001", ...],
                "tactics": ["command-and-control", ...],
                "summary": "...",
                "detection_methods": ["..."],
                "confidence": "high|medium|low",
                "llm_used": "provider/model",
                "enriched_at": "timestamp"
            }
        """
        logger.info(f"🔍 Enriching IOC: {ioc_data.get('type')}/{ioc_data.get('value', '')[:50]}")

        # Build prompt
        prompt = self._build_ioc_enrichment_prompt(ioc_data)

        # Call LLM
        try:
            # Import here to avoid circular dependency
            from app.services.llm_factory import LLMFactory
            from app.db.database import AsyncSessionLocal

            llm_client = None

            # Try database providers first
            try:
                async with AsyncSessionLocal() as db:
                    if llm_provider:
                        llm_client = await LLMFactory.create_client_from_provider_id(db, llm_provider)
                    else:
                        # Use default provider
                        llm_client = await LLMFactory.create_client_from_default(db)
            except Exception as db_error:
                logger.warning(f"⚠️ Failed to load LLM from database: {db_error}")
                logger.info("📝 Falling back to env configuration")

            # Fallback to env if database failed
            if not llm_client:
                logger.info("📝 Trying env configuration")
                llm_client = LLMFactory.create_client_from_env()

            if not llm_client:
                raise Exception("No LLM provider available (database and env failed)")

            provider_info = llm_client.get_provider_info()
            logger.info(f"🤖 Using LLM: {provider_info['provider_type']}/{provider_info['model_name']}")

            # Call LLM
            response = await llm_client.generate(
                messages=[
                    {"role": "user", "content": prompt}
                ],
                system=None,
                tools=None
            )

            content = response.get("content", "").strip()
            logger.debug(f"📥 LLM Response ({len(content)} chars): {content[:200]}")

            # Parse response
            result = self._parse_llm_response(content)
            result["llm_used"] = f"{provider_info['provider_type']}/{provider_info['model_name']}"
            result["enriched_at"] = datetime.utcnow().isoformat()

            # Validate techniques
            if "techniques" in result:
                result["techniques"] = self._validate_techniques(result["techniques"])

            logger.info(f"✅ IOC enriched: threat_type={result.get('threat_type')}, "
                       f"severity={result.get('severity')}, "
                       f"techniques={len(result.get('techniques', []))}")

            return result

        except Exception as e:
            logger.error(f"❌ Error enriching IOC: {e}")
            return {
                "threat_type": "unknown",
                "severity": "medium",
                "techniques": [],
                "tactics": [],
                "summary": f"Enrichment failed: {str(e)}",
                "detection_methods": [],
                "confidence": "none",
                "llm_used": None,
                "enriched_at": datetime.utcnow().isoformat(),
                "error": str(e)
            }

    def _parse_llm_response(self, content: str) -> Dict[str, Any]:
        """
        Parse LLM response JSON

        Args:
            content: LLM response content

        Returns:
            Parsed dict
        """
        try:
            # Try to find JSON in response
            content = content.strip()

            # Remove markdown code blocks if present
            if content.startswith('```'):
                lines = content.split('\n')
                content = '\n'.join(lines[1:-1])

            # Try direct JSON parse
            result = json.loads(content)
            return result

        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Response content: {content[:500]}")

            # Return minimal valid structure
            return {
                "threat_type": "unknown",
                "severity": "medium",
                "techniques": [],
                "tactics": [],
                "summary": "Failed to parse LLM response",
                "detection_methods": [],
                "confidence": "none"
            }

    def _validate_techniques(self, techniques: List[str]) -> List[str]:
        """
        Valida se técnicas existem no MITRE ATT&CK

        Args:
            techniques: Lista de IDs de técnicas

        Returns:
            Lista de técnicas válidas
        """
        valid_techniques = []

        self.attack_service._ensure_loaded()
        all_techniques = self.attack_service._attack_data.get_techniques(remove_revoked_deprecated=True)

        # Create set of valid IDs
        valid_ids = set()
        for tech in all_techniques:
            if hasattr(tech, 'external_references'):
                for ref in tech.external_references:
                    if ref.source_name == 'mitre-attack' and hasattr(ref, 'external_id'):
                        valid_ids.add(ref.external_id)

        # Validate each technique
        for tech_id in techniques:
            if tech_id in valid_ids:
                valid_techniques.append(tech_id)
            else:
                logger.warning(f"⚠️ Invalid MITRE ATT&CK technique ID: {tech_id}")

        return valid_techniques

    async def enrich_iocs_batch(
        self,
        iocs: List[Dict[str, Any]],
        llm_provider: Optional[str] = None,
        max_iocs: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Enriquece múltiplos IOCs em batch

        Args:
            iocs: Lista de IOCs para enriquecer
            llm_provider: Provider LLM (opcional)
            max_iocs: Número máximo de IOCs para processar

        Returns:
            Lista de IOCs enriquecidos
        """
        logger.info(f"📦 Batch enriching {min(len(iocs), max_iocs)} IOCs...")

        enriched_iocs = []

        for ioc in iocs[:max_iocs]:
            try:
                enrichment = await self.enrich_ioc_with_llm(ioc, llm_provider)

                # Merge enrichment into IOC
                enriched_ioc = {**ioc, "enrichment": enrichment}
                enriched_iocs.append(enriched_ioc)

            except Exception as e:
                logger.error(f"❌ Error enriching IOC {ioc.get('value', 'unknown')}: {e}")
                enriched_iocs.append({
                    **ioc,
                    "enrichment": {
                        "error": str(e),
                        "enriched_at": datetime.utcnow().isoformat()
                    }
                })

        logger.info(f"✅ Batch enrichment complete: {len(enriched_iocs)} IOCs processed")
        return enriched_iocs


# Singleton instance
_ioc_enrichment_service = None


def get_ioc_enrichment_service() -> IOCEnrichmentService:
    """Get singleton IOCEnrichmentService instance"""
    global _ioc_enrichment_service
    if _ioc_enrichment_service is None:
        _ioc_enrichment_service = IOCEnrichmentService()
    return _ioc_enrichment_service
