"""
OTX to MISP Exporter Service

Exporta OTX Pulses como eventos MISP
"""
from pymisp import PyMISP, MISPEvent, MISPAttribute
import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime
from app.cti.models.otx_pulse import OTXPulse, OTXPulseIndicator
import os

logger = logging.getLogger(__name__)


class OTXMISPExporter:
    """Service para exportar OTX Pulses para MISP"""

    # Mapeamento de tipos OTX -> MISP
    TYPE_MAPPING = {
        'IPv4': 'ip-dst',
        'IPv6': 'ip-dst',
        'domain': 'domain',
        'hostname': 'hostname',
        'URL': 'url',
        'URI': 'url',
        'FileHash-MD5': 'md5',
        'FileHash-SHA1': 'sha1',
        'FileHash-SHA256': 'sha256',
        'email': 'email-src',
        'YARA': 'yara',
        'Mutex': 'mutex',
        'CVE': 'vulnerability'
    }

    def __init__(self, session: AsyncSession, misp_url: str = None, misp_key: str = None):
        self.session = session
        self.misp_url = misp_url or os.getenv('MISP_URL')
        self.misp_key = misp_key or os.getenv('MISP_KEY')

        if not self.misp_url or not self.misp_key:
            logger.warning("⚠️ MISP credentials not configured")
            self.misp = None
        else:
            try:
                self.misp = PyMISP(self.misp_url, self.misp_key, ssl=False)
                logger.info(f"✅ Connected to MISP: {self.misp_url}")
            except Exception as e:
                logger.error(f"❌ Failed to connect to MISP: {e}")
                self.misp = None

    async def export_pulse_to_misp(self, pulse_id: str) -> Dict:
        """
        Exporta um pulse OTX para MISP como evento

        Args:
            pulse_id: UUID do pulse no banco

        Returns:
            Dict com resultado da exportação
        """
        if not self.misp:
            return {
                "success": False,
                "message": "MISP not configured"
            }

        # Buscar pulse
        stmt = select(OTXPulse).where(OTXPulse.id == pulse_id)
        result = await self.session.execute(stmt)
        pulse = result.scalar_one_or_none()

        if not pulse:
            return {
                "success": False,
                "message": f"Pulse {pulse_id} not found"
            }

        if pulse.exported_to_misp:
            return {
                "success": False,
                "message": f"Pulse already exported to MISP (event {pulse.misp_event_id})"
            }

        logger.info(f"📤 Exporting pulse to MISP: {pulse.name}")

        try:
            # Criar evento MISP
            event = MISPEvent()
            event.info = pulse.name
            event.distribution = 3  # All communities
            event.threat_level_id = 2  # Medium
            event.analysis = 2  # Completed

            # Tags
            if pulse.tags:
                for tag in pulse.tags[:10]:  # Limite de 10 tags
                    event.add_tag(f"otx:{tag}")

            # Tag OTX source
            event.add_tag("tlp:white" if pulse.tlp == "white" else f"tlp:{pulse.tlp or 'white'}")
            event.add_tag("osint:source-type=\"otx\"")

            # Adversary
            if pulse.adversary:
                event.add_tag(f"adversary:{pulse.adversary}")

            # Buscar indicators
            indicators_stmt = select(OTXPulseIndicator).where(OTXPulseIndicator.pulse_id == pulse_id)
            indicators_result = await self.session.execute(indicators_stmt)
            indicators = indicators_result.scalars().all()

            logger.info(f"📋 Adding {len(indicators)} indicators to MISP event")

            # Adicionar attributes (indicators)
            for indicator in indicators:
                misp_type = self.TYPE_MAPPING.get(indicator.type, 'other')

                if misp_type == 'other':
                    logger.debug(f"⚠️ Unknown type: {indicator.type}, skipping")
                    continue

                attr = MISPAttribute()
                attr.type = misp_type
                attr.value = indicator.indicator
                attr.comment = indicator.description or f"From OTX pulse: {pulse.name}"
                attr.to_ids = True  # Para detecção
                attr.distribution = 3  # All communities

                event.add_attribute(**attr)

            # Adicionar referências
            if pulse.references:
                for ref in pulse.references[:5]:  # Limite de 5 refs
                    event.add_attribute('link', ref, comment="OTX Reference")

            # Criar evento no MISP
            misp_event = self.misp.add_event(event, pythonify=True)

            if not misp_event or not hasattr(misp_event, 'id'):
                raise Exception("Failed to create MISP event")

            logger.info(f"✅ MISP event created: {misp_event.id}")

            # Atualizar pulse no banco
            pulse.exported_to_misp = True
            pulse.misp_event_id = str(misp_event.id)
            pulse.exported_to_misp_at = datetime.utcnow()

            # Atualizar indicators
            for indicator in indicators:
                indicator.exported_to_misp = True

            await self.session.commit()

            return {
                "success": True,
                "misp_event_id": str(misp_event.id),
                "misp_event_uuid": str(misp_event.uuid),
                "indicators_exported": len(indicators),
                "message": f"Pulse exported successfully to MISP event {misp_event.id}"
            }

        except Exception as e:
            logger.error(f"❌ Failed to export pulse to MISP: {e}")
            await self.session.rollback()
            return {
                "success": False,
                "message": f"Export failed: {str(e)}"
            }

    async def export_pending_pulses(self, limit: int = 10) -> Dict:
        """
        Exporta pulses pendentes para MISP em batch

        Args:
            limit: Número máximo de pulses para exportar

        Returns:
            Dict com estatísticas
        """
        if not self.misp:
            return {
                "success": False,
                "message": "MISP not configured"
            }

        logger.info(f"📤 Exporting pending pulses to MISP (limit={limit})")

        # Buscar pulses não exportados
        stmt = select(OTXPulse).where(
            and_(
                OTXPulse.exported_to_misp == False,
                OTXPulse.is_active == True
            )
        ).order_by(OTXPulse.synced_at.desc()).limit(limit)

        result = await self.session.execute(stmt)
        pulses = result.scalars().all()

        logger.info(f"📋 Found {len(pulses)} pulses to export")

        stats = {
            "total_pulses": len(pulses),
            "exported": 0,
            "failed": 0,
            "errors": []
        }

        for pulse in pulses:
            try:
                result = await self.export_pulse_to_misp(str(pulse.id))
                if result['success']:
                    stats['exported'] += 1
                else:
                    stats['failed'] += 1
                    stats['errors'].append(f"{pulse.name}: {result['message']}")

            except Exception as e:
                logger.error(f"❌ Error exporting pulse {pulse.name}: {e}")
                stats['failed'] += 1
                stats['errors'].append(str(e))

        logger.info(f"✅ Export completed: {stats['exported']} exported, {stats['failed']} failed")

        return {
            "success": True,
            **stats
        }

    async def get_export_stats(self) -> Dict:
        """
        Estatísticas de export para MISP

        Returns:
            Dict com estatísticas
        """
        from sqlalchemy import func

        # Total de pulses
        total_stmt = select(func.count(OTXPulse.id))
        total = await self.session.scalar(total_stmt)

        # Exportados
        exported_stmt = select(func.count(OTXPulse.id)).where(OTXPulse.exported_to_misp == True)
        exported = await self.session.scalar(exported_stmt)

        # Pending
        pending = (total or 0) - (exported or 0)

        return {
            "total_pulses": total or 0,
            "exported_to_misp": exported or 0,
            "pending_export": pending,
            "misp_configured": self.misp is not None
        }
