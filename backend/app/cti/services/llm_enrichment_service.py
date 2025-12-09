"""
LLM-Based CTI Enrichment Service

Usa LLM para inferir técnicas MITRE ATT&CK para atores que não têm
match direto no framework oficial.

Strategy:
1. Busca descrição e informações do ator no Malpedia
2. Usa LLM para inferir técnicas baseado no perfil do ator
3. Salva no cache de enrichment para uso futuro

Author: Claude + Angello Cassio
Date: 2025-11-20
"""

import logging
import json
from typing import List, Dict, Any, Optional
from elasticsearch import AsyncElasticsearch

from app.db.elasticsearch import get_es_client
from .attack_service import get_attack_service

logger = logging.getLogger(__name__)


class LLMEnrichmentService:
    """
    Service to enrich actors using LLM inference
    """

    def __init__(self):
        self.attack_service = get_attack_service()
        self.es_client: Optional[AsyncElasticsearch] = None

    async def _get_es_client(self):
        """Get Elasticsearch client"""
        if self.es_client is None:
            self.es_client = await get_es_client()
        return self.es_client

    async def _get_actor_details(self, actor_name: str) -> Optional[Dict[str, Any]]:
        """
        Busca detalhes completos do ator no Malpedia

        Args:
            actor_name: Nome do ator

        Returns:
            Documento completo do ator ou None
        """
        try:
            es = await self._get_es_client()

            result = await es.search(
                index="malpedia_actors",
                body={
                    "query": {
                        "term": {
                            "name.keyword": actor_name
                        }
                    }
                },
                size=1
            )

            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_source']
            else:
                logger.warning(f"⚠️ Actor not found in Malpedia: {actor_name}")
                return None

        except Exception as e:
            logger.error(f"❌ Error fetching actor details: {e}")
            return None

    def _build_enrichment_prompt(self, actor_data: Dict[str, Any]) -> str:
        """
        Constrói prompt para LLM inferir técnicas

        Args:
            actor_data: Dados do ator do Malpedia

        Returns:
            Prompt formatado
        """
        actor_name = actor_data.get('name', 'Unknown')
        aka = actor_data.get('aka', [])
        description = actor_data.get('explicacao', 'No description available')
        families = actor_data.get('familias_relacionadas', [])
        references = actor_data.get('referencias', [])

        # Lista de todas as técnicas disponíveis
        self.attack_service._ensure_loaded()
        all_techniques = self.attack_service._attack_data.get_techniques(remove_revoked_deprecated=True)

        # Criar lista resumida de técnicas (ID + nome)
        techniques_list = []
        for tech in all_techniques[:100]:  # Limitar a 100 técnicas mais comuns
            tech_id = None
            tech_name = getattr(tech, 'name', 'Unknown')

            if hasattr(tech, 'external_references'):
                for ref in tech.external_references:
                    if ref.source_name == 'mitre-attack' and hasattr(ref, 'external_id'):
                        tech_id = ref.external_id
                        break

            if tech_id:
                techniques_list.append(f"- {tech_id}: {tech_name}")

        techniques_reference = "\n".join(techniques_list[:50])  # Top 50 técnicas

        prompt = f"""Você é um especialista em CTI (Cyber Threat Intelligence) e MITRE ATT&CK framework.

**TAREFA:**
Analise o perfil do threat actor abaixo e identifique as técnicas MITRE ATT&CK que este ator PROVAVELMENTE utiliza.

**THREAT ACTOR:**
- Nome: {actor_name}
- Aliases: {', '.join(aka) if aka else 'None'}
- Descrição: {description}
- Malware Families: {', '.join(families[:10]) if families else 'None'}
- Referências: {len(references)} fontes disponíveis

**INSTRUÇÕES:**
1. Baseie-se na descrição, aliases e malware families para inferir as TTPs (Tactics, Techniques, Procedures)
2. Considere o perfil do ator (APT vs Cybercrime, alvos típicos, motivações)
3. Retorne APENAS técnicas que fazem sentido para este ator específico
4. Seja conservador - é melhor retornar menos técnicas certas do que muitas erradas
5. Foque em técnicas comuns do tipo de ator (ex: APTs usam T1566 Phishing, T1059 Command Scripting, etc.)

**TÉCNICAS MITRE ATT&CK COMUNS (REFERÊNCIA):**
{techniques_reference}

**FORMATO DE RESPOSTA:**
Retorne APENAS um JSON no seguinte formato (sem markdown, sem explicações):

{{
    "techniques": ["T1566.001", "T1059.001", "T1027", ...],
    "confidence": "high" | "medium" | "low",
    "reasoning": "Breve explicação de 1-2 linhas do porquê dessas técnicas"
}}

**REGRAS:**
- Retorne entre 5 a 15 técnicas (não menos, não mais)
- Use APENAS IDs válidos do MITRE ATT&CK (formato: T####.###)
- Confidence "high" apenas se houver descrição detalhada
- Confidence "medium" para perfis parciais
- Confidence "low" para atores com pouca informação

Retorne APENAS o JSON, sem texto adicional."""

        return prompt

    async def infer_techniques_with_llm(
        self,
        actor_name: str,
        llm_provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Infere técnicas usando LLM

        Args:
            actor_name: Nome do ator
            llm_provider: Provider LLM a usar (opcional, usa default)

        Returns:
            {
                "techniques": ["T1566.001", ...],
                "confidence": "high|medium|low",
                "reasoning": "...",
                "llm_used": "provider/model"
            }
        """
        logger.info(f"🤖 Using LLM to infer techniques for: {actor_name}")

        # 1. Buscar dados do ator
        actor_data = await self._get_actor_details(actor_name)
        if not actor_data:
            logger.error(f"❌ Cannot infer techniques - actor not found: {actor_name}")
            return {
                "techniques": [],
                "confidence": "none",
                "reasoning": "Actor not found in Malpedia database",
                "llm_used": None
            }

        # 2. Construir prompt
        prompt = self._build_enrichment_prompt(actor_data)

        # 3. Chamar LLM
        try:
            # Import aqui para evitar circular dependency
            from app.services.llm_factory import LLMFactory
            from app.db.database import AsyncSessionLocal

            llm_client = None

            # Try database providers first (with error handling for decryption)
            try:
                async with AsyncSessionLocal() as db:
                    # Criar client LLM
                    if llm_provider:
                        llm_client = await LLMFactory.create_client_from_provider_id(db, llm_provider)
                    else:
                        # Usar provider padrão
                        llm_client = await LLMFactory.create_client_from_default(db)
            except Exception as db_error:
                logger.warning(f"⚠️ Failed to load LLM from database: {db_error}")
                logger.info("📝 Falling back to env configuration")

            # Fallback para env se não conseguiu do banco
            if not llm_client:
                logger.info("📝 Trying env configuration")
                llm_client = LLMFactory.create_client_from_env()

            if not llm_client:
                raise Exception("No LLM provider available (database and env failed)")

            provider_info = llm_client.get_provider_info()
            logger.info(f"🤖 Using LLM: {provider_info['provider_type']}/{provider_info['model_name']}")

            # Chamar LLM
            response = await llm_client.generate(
                messages=[
                    {"role": "user", "content": prompt}
                ],
                system=None,
                tools=None
            )

            content = response.get("content", "").strip()
            logger.info(f"📥 LLM Response ({len(content)} chars)")

            # 4. Parsear resposta
            result = self._parse_llm_response(content)
            result["llm_used"] = f"{provider_info['provider_type']}/{provider_info['model_name']}"

            # 5. Validar técnicas
            result["techniques"] = self._validate_techniques(result.get("techniques", []))

            logger.info(f"✅ LLM inferred {len(result['techniques'])} techniques (confidence: {result.get('confidence')})")
            logger.info(f"   Reasoning: {result.get('reasoning', 'N/A')[:100]}")

            return result

        except Exception as e:
            logger.error(f"❌ Error calling LLM: {e}")
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return {
                "techniques": [],
                "confidence": "error",
                "reasoning": f"LLM call failed: {str(e)}",
                "llm_used": None
            }

    def _parse_llm_response(self, content: str) -> Dict[str, Any]:
        """
        Parseia resposta JSON do LLM

        Args:
            content: Resposta do LLM

        Returns:
            Dicionário parseado
        """
        import re

        # Remove markdown code blocks
        if "```json" in content:
            content = re.sub(r'```json\s*', '', content)
            content = re.sub(r'```\s*$', '', content)
        elif "```" in content:
            content = re.sub(r'```\s*', '', content)

        content = content.strip()

        # Find JSON
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON parse error: {e}")
                logger.error(f"   Content: {content[:200]}")

        # Fallback
        return {
            "techniques": [],
            "confidence": "error",
            "reasoning": "Failed to parse LLM response"
        }

    def _validate_techniques(self, techniques: List[str]) -> List[str]:
        """
        Valida técnicas contra MITRE ATT&CK

        Args:
            techniques: Lista de IDs de técnicas

        Returns:
            Lista de técnicas válidas
        """
        validated = []

        for tech_id in techniques:
            # Verifica se existe no MITRE ATT&CK
            tech = self.attack_service.get_technique(tech_id)
            if tech:
                validated.append(tech_id)
            else:
                logger.warning(f"⚠️ Invalid technique ID (not in MITRE): {tech_id}")

        return validated


# Singleton
_llm_enrichment_service: Optional[LLMEnrichmentService] = None


def get_llm_enrichment_service() -> LLMEnrichmentService:
    """Get singleton instance"""
    global _llm_enrichment_service
    if _llm_enrichment_service is None:
        _llm_enrichment_service = LLMEnrichmentService()
    return _llm_enrichment_service
