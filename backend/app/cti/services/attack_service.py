"""
MITRE ATT&CK Service

Carrega e fornece acesso aos dados do MITRE ATT&CK Framework usando a biblioteca
mitreattack-python que baixa dados STIX diretamente do repositório oficial.

Cache: Dados são carregados na memória na primeira chamada e reutilizados.
"""

import logging
import requests
import tempfile
import json
from typing import List, Dict, Any, Optional
from functools import lru_cache

# MITRE ATT&CK Python library
from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)


class AttackService:
    """
    Service para acessar dados do MITRE ATT&CK Framework

    Utiliza mitreattack-python para carregar dados STIX do repositório oficial.
    Dados são cacheados em memória após o primeiro carregamento.
    """

    def __init__(self):
        """Initialize service"""
        self._attack_data: Optional[MitreAttackData] = None
        self._loaded = False

    def _ensure_loaded(self):
        """Carrega dados ATT&CK se ainda não foram carregados"""
        if not self._loaded:
            logger.info("📥 Loading MITRE ATT&CK data from official STIX repository...")
            try:
                # Baixa os dados STIX do GitHub
                stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                logger.info(f"   Downloading from: {stix_url}")

                response = requests.get(stix_url, timeout=30)
                response.raise_for_status()

                # Salva em arquivo temporário (a biblioteca precisa de um arquivo)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                    json.dump(response.json(), tmp)
                    tmp_path = tmp.name

                # Carrega os dados STIX do arquivo temporário
                self._attack_data = MitreAttackData(tmp_path)
                self._loaded = True

                # Remove arquivo temporário
                import os
                os.unlink(tmp_path)

                # Log statistics
                techniques = self._attack_data.get_techniques(remove_revoked_deprecated=True)
                tactics = self._attack_data.get_tactics(remove_revoked_deprecated=True)

                logger.info(f"✅ MITRE ATT&CK data loaded successfully")
                logger.info(f"   - Techniques: {len(techniques)}")
                logger.info(f"   - Tactics: {len(tactics)}")

            except Exception as e:
                logger.error(f"❌ Error loading MITRE ATT&CK data: {e}")
                raise

    # ==================== TACTICS ====================

    def get_tactics(self) -> List[Dict[str, Any]]:
        """
        Get all tactics (high-level adversary goals)

        Returns:
            List of tactics with:
            - tactic_id: External ID (e.g., "TA0001")
            - name: Tactic name (e.g., "Initial Access")
            - description: Tactic description
            - url: MITRE ATT&CK URL
        """
        self._ensure_loaded()

        tactics = self._attack_data.get_tactics(remove_revoked_deprecated=True)

        result = []
        for tactic in tactics:
            # Extrair external_id
            tactic_id = None
            if hasattr(tactic, 'external_references'):
                for ref in tactic.external_references:
                    if ref.source_name == "mitre-attack":
                        tactic_id = ref.external_id
                        break

            result.append({
                "tactic_id": tactic_id,
                "name": tactic.name,
                "description": tactic.description if hasattr(tactic, 'description') else None,
                "url": f"https://attack.mitre.org/tactics/{tactic_id}/" if tactic_id else None
            })

        logger.info(f"📊 Retrieved {len(result)} tactics")
        return sorted(result, key=lambda x: x["tactic_id"] or "")

    # ==================== TECHNIQUES ====================

    def get_techniques(
        self,
        include_subtechniques: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get all techniques

        Args:
            include_subtechniques: Include sub-techniques (e.g., T1566.001)

        Returns:
            List of techniques with:
            - technique_id: External ID (e.g., "T1566")
            - name: Technique name
            - description: Description
            - tactics: List of tactic names this technique belongs to
            - url: MITRE ATT&CK URL
            - is_subtechnique: Boolean
            - parent_id: Parent technique ID (if sub-technique)
        """
        self._ensure_loaded()

        techniques = self._attack_data.get_techniques(
            remove_revoked_deprecated=True,
            include_subtechniques=include_subtechniques
        )

        result = []
        for tech in techniques:
            # Extrair external_id
            tech_id = None
            if hasattr(tech, 'external_references'):
                for ref in tech.external_references:
                    if ref.source_name == "mitre-attack":
                        tech_id = ref.external_id
                        break

            # Extrair tactics (kill chain phases)
            tactic_names = []
            if hasattr(tech, 'kill_chain_phases'):
                for phase in tech.kill_chain_phases:
                    if phase.kill_chain_name == "mitre-attack":
                        # Converter phase name para tactic name
                        # Ex: "initial-access" -> "Initial Access"
                        tactic_name = phase.phase_name.replace("-", " ").title()
                        tactic_names.append(tactic_name)

            # Verificar se é sub-technique
            is_subtechnique = "." in (tech_id or "")
            parent_id = tech_id.split(".")[0] if is_subtechnique else None

            result.append({
                "technique_id": tech_id,
                "name": tech.name,
                "description": tech.description if hasattr(tech, 'description') else None,
                "tactics": tactic_names,
                "url": f"https://attack.mitre.org/techniques/{tech_id}/" if tech_id else None,
                "is_subtechnique": is_subtechnique,
                "parent_id": parent_id
            })

        logger.info(f"📊 Retrieved {len(result)} techniques (subtechniques: {include_subtechniques})")
        return sorted(result, key=lambda x: x["technique_id"] or "")

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific technique by ID

        Args:
            technique_id: Technique ID (e.g., "T1566" or "T1566.001")

        Returns:
            Technique details or None if not found
        """
        techniques = self.get_techniques(include_subtechniques=True)

        for tech in techniques:
            if tech["technique_id"] == technique_id:
                logger.info(f"✅ Found technique: {technique_id}")
                return tech

        logger.warning(f"⚠️ Technique not found: {technique_id}")
        return None

    # ==================== MATRIX STRUCTURE ====================

    def get_matrix(self) -> Dict[str, Any]:
        """
        Get ATT&CK matrix structure (tactics × techniques)

        Returns:
            {
                "tactics": [list of tactics],
                "techniques": [list of techniques],
                "matrix": {
                    "tactic_id": [list of technique_ids]
                }
            }
        """
        self._ensure_loaded()

        tactics = self.get_tactics()
        techniques = self.get_techniques(include_subtechniques=False)  # Only parent techniques

        # Build matrix mapping
        matrix = {}
        for tactic in tactics:
            tactic_name = tactic["name"]
            # Find techniques for this tactic
            tactic_techniques = [
                tech["technique_id"]
                for tech in techniques
                if tactic_name in tech["tactics"]
            ]
            matrix[tactic["tactic_id"]] = tactic_techniques

        result = {
            "tactics": tactics,
            "techniques": techniques,
            "matrix": matrix
        }

        logger.info(f"📊 Matrix: {len(tactics)} tactics × ~{len(techniques)} techniques")
        return result

    # ==================== MITIGATIONS ====================

    def get_mitigations(self, technique_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get mitigations (all or for specific technique)

        Args:
            technique_id: Optional technique ID to filter mitigations

        Returns:
            List of mitigations
        """
        self._ensure_loaded()

        mitigations = self._attack_data.get_mitigations(remove_revoked_deprecated=True)

        result = []
        for mitigation in mitigations:
            # Extrair external_id
            mitigation_id = None
            if hasattr(mitigation, 'external_references'):
                for ref in mitigation.external_references:
                    if ref.source_name == "mitre-attack":
                        mitigation_id = ref.external_id
                        break

            result.append({
                "mitigation_id": mitigation_id,
                "name": mitigation.name,
                "description": mitigation.description if hasattr(mitigation, 'description') else None,
                "url": f"https://attack.mitre.org/mitigations/{mitigation_id}/" if mitigation_id else None
            })

        logger.info(f"📊 Retrieved {len(result)} mitigations")
        return result

    # ==================== STATISTICS ====================

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about ATT&CK data

        Returns:
            Statistics dictionary
        """
        self._ensure_loaded()

        tactics = self.get_tactics()
        techniques = self.get_techniques(include_subtechniques=False)
        subtechniques = self.get_techniques(include_subtechniques=True)
        mitigations = self.get_mitigations()

        num_subtechniques = len(subtechniques) - len(techniques)

        stats = {
            "total_tactics": len(tactics),
            "total_techniques": len(techniques),
            "total_subtechniques": num_subtechniques,
            "total_mitigations": len(mitigations),
            "matrix_size": f"{len(tactics)} × {len(techniques)}"
        }

        logger.info(f"📊 ATT&CK Stats: {stats}")
        return stats


# Singleton instance
_attack_service: Optional[AttackService] = None


def get_attack_service() -> AttackService:
    """Get singleton instance of AttackService"""
    global _attack_service
    if _attack_service is None:
        _attack_service = AttackService()
    return _attack_service
