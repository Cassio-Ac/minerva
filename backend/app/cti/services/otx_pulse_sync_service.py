"""
OTX Pulse Sync Service

Service para sincronizar OTX Pulses automaticamente para o banco de dados
Suporta sync de pulses subscritos e pulses por tags/adversaries

Usa API REST direta ao inves de OTXv2 SDK (que e muito lento por fazer paginacao excessiva)
"""
import requests
import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime
from app.cti.models.otx_pulse import OTXPulse, OTXPulseIndicator, OTXSyncHistory
from app.cti.models.otx_api_key import OTXAPIKey
from app.cti.services.otx_key_manager import OTXKeyManager

logger = logging.getLogger(__name__)

# OTX API Base URL
OTX_API_BASE = "https://otx.alienvault.com/api/v1"


class OTXPulseSyncService:
    """Service para sincronizar OTX Pulses"""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.key_manager = OTXKeyManager(session)

    async def sync_subscribed_pulses(self, limit: int = 50) -> Dict:
        """
        Sincroniza pulses dos feeds subscritos no OTX

        Args:
            limit: Número máximo de pulses para buscar (default 50)

        Returns:
            Dict com estatísticas da sincronização
        """
        logger.info(f"🔄 Starting OTX pulse sync (limit={limit})")

        # Criar histórico de sync
        sync_history = OTXSyncHistory(
            sync_type="pulse_sync",
            started_at=datetime.utcnow(),
            status="running"
        )
        self.session.add(sync_history)
        await self.session.commit()

        stats = {
            "pulses_fetched": 0,
            "pulses_new": 0,
            "pulses_updated": 0,
            "indicators_processed": 0,
            "errors": []
        }

        try:
            # Obter chave OTX
            key = await self.key_manager.get_available_key()
            if not key:
                raise Exception("No OTX API keys available")

            sync_history.api_key_id = key.id
            await self.session.commit()

            # Buscar pulses via API REST direta (mais rapido que SDK)
            logger.info("📥 Fetching subscribed pulses from OTX API...")
            headers = {"X-OTX-API-KEY": key.api_key}

            response = requests.get(
                f"{OTX_API_BASE}/pulses/subscribed",
                headers=headers,
                params={"limit": limit, "page": 1},
                timeout=60
            )
            response.raise_for_status()
            pulses_data = response.json()

            if not pulses_data or 'results' not in pulses_data:
                logger.warning("⚠️ No pulses returned from OTX")
                sync_history.status = "completed"
                sync_history.completed_at = datetime.utcnow()
                await self.session.commit()
                return stats

            pulses = pulses_data.get('results', [])
            stats['pulses_fetched'] = len(pulses)
            logger.info(f"✅ Fetched {len(pulses)} pulses from OTX")

            # Processar cada pulse
            for pulse_data in pulses:
                try:
                    result = await self._process_pulse(pulse_data, key.id)
                    if result['is_new']:
                        stats['pulses_new'] += 1
                    else:
                        stats['pulses_updated'] += 1
                    stats['indicators_processed'] += result['indicators_count']

                except Exception as e:
                    logger.error(f"❌ Error processing pulse {pulse_data.get('id')}: {e}")
                    stats['errors'].append(str(e))

            # Registrar uso da chave
            await self.key_manager.record_request(key, success=True)

            # Atualizar histórico
            sync_history.status = "completed"
            sync_history.completed_at = datetime.utcnow()
            sync_history.pulses_fetched = stats['pulses_fetched']
            sync_history.pulses_new = stats['pulses_new']
            sync_history.pulses_updated = stats['pulses_updated']
            sync_history.indicators_processed = stats['indicators_processed']
            await self.session.commit()

            logger.info(f"✅ Sync completed: {stats['pulses_new']} new, {stats['pulses_updated']} updated")
            return stats

        except Exception as e:
            logger.error(f"❌ Sync failed: {e}")
            sync_history.status = "failed"
            sync_history.error_message = str(e)
            sync_history.completed_at = datetime.utcnow()
            await self.session.commit()
            raise

    async def sync_pulses_by_search(self, query: str, limit: int = 20) -> Dict:
        """
        Buscar e sincronizar pulses por query (tags, adversary, malware, etc)

        Args:
            query: Termo de busca (ex: "apt29", "ransomware", "phishing")
            limit: Número máximo de pulses

        Returns:
            Dict com estatísticas
        """
        logger.info(f"🔍 Searching OTX pulses: '{query}' (limit={limit})")

        # Criar histórico
        sync_history = OTXSyncHistory(
            sync_type=f"pulse_search:{query}",
            started_at=datetime.utcnow(),
            status="running"
        )
        self.session.add(sync_history)
        await self.session.commit()

        stats = {
            "pulses_fetched": 0,
            "pulses_new": 0,
            "pulses_updated": 0,
            "indicators_processed": 0,
            "errors": []
        }

        try:
            # Obter chave
            key = await self.key_manager.get_available_key()
            if not key:
                raise Exception("No OTX API keys available")

            sync_history.api_key_id = key.id
            await self.session.commit()

            # Buscar pulses via API REST
            logger.info(f"📥 Searching OTX for: {query}")
            headers = {"X-OTX-API-KEY": key.api_key}

            response = requests.get(
                f"{OTX_API_BASE}/search/pulses",
                headers=headers,
                params={"q": query, "limit": limit, "page": 1},
                timeout=60
            )
            response.raise_for_status()
            search_results = response.json()

            if not search_results or 'results' not in search_results:
                logger.warning(f"⚠️ No results for query: {query}")
                sync_history.status = "completed"
                sync_history.completed_at = datetime.utcnow()
                await self.session.commit()
                return stats

            pulses = search_results.get('results', [])
            stats['pulses_fetched'] = len(pulses)
            logger.info(f"✅ Found {len(pulses)} pulses")

            # Processar pulses
            for pulse_data in pulses:
                try:
                    # Buscar detalhes completos do pulse via REST
                    pulse_id = pulse_data.get('id')
                    pulse_resp = requests.get(
                        f"{OTX_API_BASE}/pulses/{pulse_id}",
                        headers=headers,
                        timeout=30
                    )
                    pulse_resp.raise_for_status()
                    full_pulse = pulse_resp.json()

                    result = await self._process_pulse(full_pulse, key.id)
                    if result['is_new']:
                        stats['pulses_new'] += 1
                    else:
                        stats['pulses_updated'] += 1
                    stats['indicators_processed'] += result['indicators_count']

                except Exception as e:
                    logger.error(f"❌ Error processing pulse: {e}")
                    stats['errors'].append(str(e))

            # Registrar uso
            await self.key_manager.record_request(key, success=True)

            # Atualizar histórico
            sync_history.status = "completed"
            sync_history.completed_at = datetime.utcnow()
            sync_history.pulses_fetched = stats['pulses_fetched']
            sync_history.pulses_new = stats['pulses_new']
            sync_history.pulses_updated = stats['pulses_updated']
            sync_history.indicators_processed = stats['indicators_processed']
            await self.session.commit()

            logger.info(f"✅ Search sync completed: {stats['pulses_new']} new, {stats['pulses_updated']} updated")
            return stats

        except Exception as e:
            logger.error(f"❌ Search sync failed: {e}")
            sync_history.status = "failed"
            sync_history.error_message = str(e)
            sync_history.completed_at = datetime.utcnow()
            await self.session.commit()
            raise

    async def _process_pulse(self, pulse_data: Dict, key_id: str) -> Dict:
        """
        Processa um pulse individual e salva no banco

        Args:
            pulse_data: Dados do pulse do OTX
            key_id: ID da chave OTX usada

        Returns:
            Dict com resultado: {'is_new': bool, 'indicators_count': int}
        """
        pulse_id = pulse_data.get('id')

        # Verificar se pulse já existe
        stmt = select(OTXPulse).where(OTXPulse.pulse_id == pulse_id)
        result = await self.session.execute(stmt)
        existing_pulse = result.scalar_one_or_none()

        indicators = pulse_data.get('indicators', [])
        indicators_count = len(indicators)

        if existing_pulse:
            # Atualizar pulse existente
            logger.debug(f"📝 Updating pulse: {pulse_data.get('name')}")
            existing_pulse.name = pulse_data.get('name')
            existing_pulse.description = pulse_data.get('description')
            existing_pulse.modified = datetime.fromisoformat(pulse_data.get('modified').replace('Z', '+00:00')) if pulse_data.get('modified') else None
            existing_pulse.revision = pulse_data.get('revision', 1)
            existing_pulse.tags = pulse_data.get('tags', [])
            existing_pulse.references = pulse_data.get('references', [])
            existing_pulse.attack_ids = pulse_data.get('attack_ids', [])
            existing_pulse.malware_families = pulse_data.get('malware_families', [])
            existing_pulse.targeted_countries = pulse_data.get('targeted_countries', [])
            existing_pulse.industries = pulse_data.get('industries', [])
            existing_pulse.indicator_count = indicators_count
            existing_pulse.raw_data = pulse_data
            existing_pulse.synced_at = datetime.utcnow()
            existing_pulse.synced_by_key_id = key_id
            existing_pulse.updated_at = datetime.utcnow()

            pulse_db = existing_pulse
            is_new = False

        else:
            # Criar novo pulse
            logger.debug(f"➕ Creating new pulse: {pulse_data.get('name')}")

            created_date = pulse_data.get('created')
            modified_date = pulse_data.get('modified')

            pulse_db = OTXPulse(
                pulse_id=pulse_id,
                name=pulse_data.get('name'),
                description=pulse_data.get('description'),
                author_name=pulse_data.get('author_name') or pulse_data.get('author', {}).get('username'),
                created=datetime.fromisoformat(created_date.replace('Z', '+00:00')) if created_date else None,
                modified=datetime.fromisoformat(modified_date.replace('Z', '+00:00')) if modified_date else None,
                revision=pulse_data.get('revision', 1),
                tlp=pulse_data.get('TLP', 'white'),
                adversary=pulse_data.get('adversary'),
                targeted_countries=pulse_data.get('targeted_countries', []),
                industries=pulse_data.get('industries', []),
                tags=pulse_data.get('tags', []),
                references=pulse_data.get('references', []),
                indicator_count=indicators_count,
                attack_ids=pulse_data.get('attack_ids', []),
                malware_families=pulse_data.get('malware_families', []),
                raw_data=pulse_data,
                synced_at=datetime.utcnow(),
                synced_by_key_id=key_id
            )
            self.session.add(pulse_db)
            is_new = True

        await self.session.flush()  # Get pulse_db.id

        # Processar indicators
        if indicators:
            await self._process_indicators(pulse_db.id, indicators)

        await self.session.commit()

        return {
            'is_new': is_new,
            'indicators_count': indicators_count
        }

    async def _process_indicators(self, pulse_id: str, indicators: List[Dict]) -> None:
        """
        Processa indicators de um pulse

        Args:
            pulse_id: UUID do pulse no banco
            indicators: Lista de indicators do OTX
        """
        for indicator_data in indicators:
            indicator_value = indicator_data.get('indicator')
            indicator_type = indicator_data.get('type')

            if not indicator_value or not indicator_type:
                continue

            # Verificar se indicador já existe para este pulse
            stmt = select(OTXPulseIndicator).where(
                and_(
                    OTXPulseIndicator.pulse_id == pulse_id,
                    OTXPulseIndicator.indicator == indicator_value
                )
            )
            result = await self.session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                # Criar novo indicator
                indicator_db = OTXPulseIndicator(
                    pulse_id=pulse_id,
                    indicator=indicator_value,
                    type=indicator_type,
                    title=indicator_data.get('title'),
                    description=indicator_data.get('description'),
                    role=indicator_data.get('role'),
                    is_active=indicator_data.get('is_active', True)
                )
                self.session.add(indicator_db)

    async def get_sync_history(self, limit: int = 10) -> List[Dict]:
        """
        Obter histórico de sincronizações

        Args:
            limit: Número de registros para retornar

        Returns:
            Lista de sync histories
        """
        stmt = select(OTXSyncHistory).order_by(OTXSyncHistory.started_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        histories = result.scalars().all()

        return [
            {
                "id": str(h.id),
                "sync_type": h.sync_type,
                "started_at": h.started_at.isoformat() if h.started_at else None,
                "completed_at": h.completed_at.isoformat() if h.completed_at else None,
                "status": h.status,
                "pulses_fetched": h.pulses_fetched,
                "pulses_new": h.pulses_new,
                "pulses_updated": h.pulses_updated,
                "indicators_processed": h.indicators_processed,
                "error_message": h.error_message
            }
            for h in histories
        ]

    async def get_pulse_stats(self) -> Dict:
        """
        Estatísticas gerais dos pulses sincronizados

        Returns:
            Dict com estatísticas
        """
        from sqlalchemy import func

        # Total de pulses
        total_pulses_stmt = select(func.count(OTXPulse.id))
        total_pulses = await self.session.scalar(total_pulses_stmt)

        # Total de indicators
        total_indicators_stmt = select(func.count(OTXPulseIndicator.id))
        total_indicators = await self.session.scalar(total_indicators_stmt)

        # Pulses exportados para MISP
        exported_stmt = select(func.count(OTXPulse.id)).where(OTXPulse.exported_to_misp == True)
        exported_to_misp = await self.session.scalar(exported_stmt)

        # Últimos pulses
        recent_stmt = select(OTXPulse).order_by(OTXPulse.synced_at.desc()).limit(5)
        result = await self.session.execute(recent_stmt)
        recent_pulses = result.scalars().all()

        return {
            "total_pulses": total_pulses or 0,
            "total_indicators": total_indicators or 0,
            "exported_to_misp": exported_to_misp or 0,
            "pending_export": (total_pulses or 0) - (exported_to_misp or 0),
            "recent_pulses": [
                {
                    "id": str(p.id),
                    "pulse_id": p.pulse_id,
                    "name": p.name,
                    "author": p.author_name,
                    "tags": p.tags,
                    "indicator_count": p.indicator_count,
                    "synced_at": p.synced_at.isoformat() if p.synced_at else None
                }
                for p in recent_pulses
            ]
        }
