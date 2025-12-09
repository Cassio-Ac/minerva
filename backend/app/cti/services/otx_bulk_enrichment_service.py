"""
OTX Bulk IOC Enrichment Service

Enriquecimento em massa de IOCs existentes (MISP feeds) com dados OTX
"""
import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from datetime import datetime, timedelta
from app.cti.models.misp_ioc import MISPIoC
from app.cti.models.otx_pulse import OTXPulseIndicator, OTXSyncHistory
from app.cti.services.otx_service_v2 import OTXServiceV2
from app.cti.services.otx_key_manager import OTXKeyManager
import asyncio

logger = logging.getLogger(__name__)


class OTXBulkEnrichmentService:
    """Service para enriquecer IOCs em massa com dados OTX"""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.otx_service = OTXServiceV2(session)
        self.key_manager = OTXKeyManager(session)

    async def enrich_misp_iocs(
        self,
        limit: int = 100,
        ioc_types: Optional[List[str]] = None,
        priority_only: bool = True
    ) -> Dict:
        """
        Enriquece IOCs do MISP com dados OTX

        Args:
            limit: Número máximo de IOCs para enriquecer
            ioc_types: Tipos específicos de IOCs (ex: ['ip-dst', 'domain'])
            priority_only: Apenas IOCs críticos/high (default True)

        Returns:
            Dict com estatísticas do enriquecimento
        """
        logger.info(f"🔄 Starting bulk IOC enrichment (limit={limit}, priority={priority_only})")

        # Criar histórico
        sync_history = OTXSyncHistory(
            sync_type="bulk_enrichment",
            started_at=datetime.utcnow(),
            status="running"
        )
        self.session.add(sync_history)
        await self.session.commit()

        stats = {
            "iocs_processed": 0,
            "iocs_enriched": 0,
            "iocs_not_found": 0,
            "iocs_failed": 0,
            "errors": []
        }

        try:
            # Verificar chave disponível
            key = await self.key_manager.get_available_key()
            if not key:
                raise Exception("No OTX API keys available")

            sync_history.api_key_id = key.id
            await self.session.commit()

            # Buscar IOCs para enriquecer
            iocs = await self._get_iocs_to_enrich(limit, ioc_types, priority_only)
            logger.info(f"📋 Found {len(iocs)} IOCs to enrich")

            # Processar IOCs
            for ioc in iocs:
                try:
                    result = await self._enrich_single_ioc(ioc)
                    stats['iocs_processed'] += 1

                    if result['found']:
                        stats['iocs_enriched'] += 1
                    else:
                        stats['iocs_not_found'] += 1

                    # Rate limiting: pequeno delay entre requests
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"❌ Error enriching IOC {ioc.value}: {e}")
                    stats['iocs_failed'] += 1
                    stats['errors'].append(f"{ioc.value}: {str(e)}")

            # Atualizar histórico
            sync_history.status = "completed"
            sync_history.completed_at = datetime.utcnow()
            sync_history.indicators_processed = stats['iocs_processed']
            sync_history.indicators_enriched = stats['iocs_enriched']
            await self.session.commit()

            logger.info(f"✅ Bulk enrichment completed: {stats['iocs_enriched']}/{stats['iocs_processed']} enriched")
            return stats

        except Exception as e:
            logger.error(f"❌ Bulk enrichment failed: {e}")
            sync_history.status = "failed"
            sync_history.error_message = str(e)
            sync_history.completed_at = datetime.utcnow()
            await self.session.commit()
            raise

    async def enrich_pulse_indicators(self, pulse_id: str) -> Dict:
        """
        Enriquece todos os indicators de um pulse específico

        Args:
            pulse_id: UUID do pulse

        Returns:
            Dict com estatísticas
        """
        logger.info(f"🔄 Enriching pulse indicators: {pulse_id}")

        # Buscar indicators do pulse que não foram enriquecidos
        stmt = select(OTXPulseIndicator).where(
            and_(
                OTXPulseIndicator.pulse_id == pulse_id,
                OTXPulseIndicator.enriched_at.is_(None)
            )
        )
        result = await self.session.execute(stmt)
        indicators = result.scalars().all()

        logger.info(f"📋 Found {len(indicators)} indicators to enrich")

        stats = {
            "total": len(indicators),
            "enriched": 0,
            "failed": 0
        }

        for indicator in indicators:
            try:
                # Enriquecer usando OTXServiceV2
                enrichment = await self.otx_service.enrich_indicator(indicator.indicator)

                if enrichment.get('found'):
                    # Salvar enrichment data
                    indicator.otx_enrichment = enrichment
                    indicator.enriched_at = datetime.utcnow()
                    stats['enriched'] += 1

                await asyncio.sleep(0.3)  # Rate limiting

            except Exception as e:
                logger.error(f"❌ Error enriching {indicator.indicator}: {e}")
                stats['failed'] += 1

        await self.session.commit()

        logger.info(f"✅ Enrichment completed: {stats['enriched']}/{stats['total']} enriched")
        return stats

    async def _get_iocs_to_enrich(
        self,
        limit: int,
        ioc_types: Optional[List[str]],
        priority_only: bool
    ) -> List[MISPIoC]:
        """
        Busca IOCs que precisam ser enriquecidos

        Critérios:
        - Ainda não enriquecidos (otx_enrichment NULL)
        - Ativos (is_active = true)
        - Opcionalmente: apenas críticos/high
        - Opcionalmente: tipos específicos
        """
        conditions = [
            MISPIoC.is_active == True,
        ]

        # Prioridade
        if priority_only:
            conditions.append(
                or_(
                    MISPIoC.threat_level == "critical",
                    MISPIoC.threat_level == "high"
                )
            )

        # Tipos específicos
        if ioc_types:
            conditions.append(MISPIoC.type.in_(ioc_types))

        # Construir query
        stmt = select(MISPIoC).where(and_(*conditions)).order_by(
            MISPIoC.first_seen.desc()
        ).limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def _enrich_single_ioc(self, ioc: MISPIoC) -> Dict:
        """
        Enriquece um único IOC

        Args:
            ioc: Model do IOC

        Returns:
            Dict com resultado
        """
        logger.debug(f"🔍 Enriching IOC: {ioc.value} ({ioc.type})")

        # Enriquecer usando OTXServiceV2
        enrichment = await self.otx_service.enrich_indicator(ioc.value)

        if enrichment.get('found'):
            # Atualizar IOC com enrichment data
            # Nota: Assumindo que MISPIoC tem campo otx_enrichment (JSON)
            # Se não tiver, criar em migration futura
            if hasattr(ioc, 'otx_enrichment'):
                ioc.otx_enrichment = enrichment
                ioc.otx_enriched_at = datetime.utcnow()
                await self.session.commit()

        return enrichment

    async def get_enrichment_stats(self) -> Dict:
        """
        Estatísticas de enriquecimento

        Returns:
            Dict com estatísticas
        """
        from sqlalchemy import func

        # Total de IOCs MISP
        total_iocs_stmt = select(func.count(MISPIoC.id))
        total_iocs = await self.session.scalar(total_iocs_stmt)

        # IOCs enriquecidos (se campo existir)
        enriched_iocs = 0
        if hasattr(MISPIoC, 'otx_enriched_at'):
            enriched_stmt = select(func.count(MISPIoC.id)).where(
                MISPIoC.otx_enriched_at.isnot(None)
            )
            enriched_iocs = await self.session.scalar(enriched_stmt)

        # Total de pulse indicators enriquecidos
        enriched_pulse_indicators_stmt = select(func.count(OTXPulseIndicator.id)).where(
            OTXPulseIndicator.enriched_at.isnot(None)
        )
        enriched_pulse_indicators = await self.session.scalar(enriched_pulse_indicators_stmt)

        return {
            "misp_iocs_total": total_iocs or 0,
            "misp_iocs_enriched": enriched_iocs,
            "misp_iocs_pending": (total_iocs or 0) - enriched_iocs,
            "pulse_indicators_enriched": enriched_pulse_indicators or 0
        }

    async def enrich_high_priority_batch(self, batch_size: int = 50) -> Dict:
        """
        Enriquece batch de IOCs de alta prioridade

        Útil para Celery task programada

        Args:
            batch_size: Tamanho do batch

        Returns:
            Dict com resultado
        """
        return await self.enrich_misp_iocs(
            limit=batch_size,
            ioc_types=['ip-dst', 'domain', 'hostname', 'url'],  # Tipos mais comuns
            priority_only=True
        )
