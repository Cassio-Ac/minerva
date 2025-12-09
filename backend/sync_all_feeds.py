#!/usr/bin/env python3
"""
Script completo para sincronizar todos os feeds MISP pendentes
Implementa parsers para: Feodo, Malware Bazaar, PhishTank, FireHOL, DigitalSide
"""
import asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.core.config import settings
from app.cti.models.misp_feed import MISPFeed
from app.cti.models.misp_ioc import MISPIoC
from datetime import datetime
import logging
import uuid
import csv
from io import StringIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def parse_feodo_csv(url: str, feed_name: str, limit: int = 500):
    """Parser para Feodo IP Blocklist (CSV)"""
    logger.info(f"📥 Downloading Feodo feed from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()

        iocs = []
        lines = response.text.strip().split('\n')

        for line in lines:
            # Skip comments and headers
            if line.startswith('#') or line.startswith('first_seen'):
                continue

            if not line.strip():
                continue

            try:
                # CSV format: first_seen,dst_ip,dst_port,c2_status,last_online,malware
                parts = line.split(',')
                if len(parts) >= 6:
                    ip = parts[1].strip()
                    port = parts[2].strip()
                    malware = parts[5].strip() if len(parts) > 5 else "unknown"

                    iocs.append({
                        "value": ip,
                        "ioc_type": "ip",
                        "source": feed_name,
                        "tags": ["botnet", "c2", malware.lower(), "feodo"],
                        "confidence": 90,
                        "description": f"Feodo botnet C2 IP (port {port}, malware: {malware})"
                    })
            except Exception as e:
                logger.debug(f"Error parsing line: {line[:100]}: {e}")
                continue

        logger.info(f"✅ Parsed {len(iocs)} IOCs from Feodo feed")
        return iocs[:limit]


async def parse_malware_bazaar_md5(url: str, feed_name: str, limit: int = 500):
    """Parser para Malware Bazaar MD5 hashes (TXT)"""
    logger.info(f"📥 Downloading Malware Bazaar from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()

        iocs = []
        lines = response.text.strip().split('\n')

        for line in lines:
            # Skip comments
            if line.startswith('#') or not line.strip():
                continue

            hash_value = line.strip()

            # Validate MD5 format (32 hex chars)
            if len(hash_value) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
                iocs.append({
                    "value": hash_value.lower(),
                    "ioc_type": "hash-md5",
                    "source": feed_name,
                    "tags": ["malware", "hash", "bazaar"],
                    "confidence": 95,
                    "description": "Malware sample hash from MalwareBazaar"
                })

        logger.info(f"✅ Parsed {len(iocs)} IOCs from Malware Bazaar")
        return iocs[:limit]


async def parse_phishtank_csv(url: str, feed_name: str, limit: int = 500):
    """Parser para PhishTank Online Valid (CSV)"""
    logger.info(f"📥 Downloading PhishTank from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()

        iocs = []
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)

        for row in reader:
            try:
                url_value = row.get('url', '').strip()
                target = row.get('target', '').strip()

                if url_value:
                    iocs.append({
                        "value": url_value,
                        "ioc_type": "url",
                        "source": feed_name,
                        "tags": ["phishing", target.lower() if target else "generic"],
                        "confidence": 85,
                        "description": f"Phishing URL targeting {target}" if target else "Phishing URL"
                    })
            except Exception as e:
                logger.debug(f"Error parsing PhishTank row: {e}")
                continue

        logger.info(f"✅ Parsed {len(iocs)} IOCs from PhishTank")
        return iocs[:limit]


async def parse_firehol_netset(url: str, feed_name: str, limit: int = 500):
    """Parser para FireHOL Level 1 (netset format)"""
    logger.info(f"📥 Downloading FireHOL from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()

        iocs = []
        lines = response.text.strip().split('\n')

        for line in lines:
            # Skip comments
            if line.startswith('#') or not line.strip():
                continue

            # Can be IP or CIDR
            ip_or_cidr = line.strip()

            # Basic validation
            if '/' in ip_or_cidr or '.' in ip_or_cidr:
                iocs.append({
                    "value": ip_or_cidr,
                    "ioc_type": "ip" if '/' not in ip_or_cidr else "cidr",
                    "source": feed_name,
                    "tags": ["firehol", "malicious-ip", "blocklist"],
                    "confidence": 80,
                    "description": "Malicious IP/range from FireHOL Level 1"
                })

        logger.info(f"✅ Parsed {len(iocs)} IOCs from FireHOL")
        return iocs[:limit]


async def parse_digitalside_misp(url: str, feed_name: str, limit: int = 100):
    """Parser para DigitalSide MISP feed (manifest + events)"""
    logger.info(f"📥 Downloading DigitalSide MISP manifest from {url}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Download manifest
        manifest_url = f"{url}/manifest.json"
        response = await client.get(manifest_url)
        response.raise_for_status()
        manifest = response.json()

        logger.info(f"✅ Manifest downloaded: {len(manifest)} events available")

        iocs = []

        # Process events (limited)
        for idx, event_uuid in enumerate(list(manifest.keys())[:limit]):
            try:
                event_url = f"{url}/{event_uuid}.json"
                logger.debug(f"[{idx+1}/{min(limit, len(manifest))}] Downloading event {event_uuid}")

                event_resp = await client.get(event_url, timeout=30.0)
                event_resp.raise_for_status()
                event_data = event_resp.json()

                event = event_data.get("Event", {})

                # Extract IOCs from attributes
                for attr in event.get("Attribute", []):
                    attr_type = attr.get("type")
                    attr_value = attr.get("value", "").strip()

                    # Map MISP types to our types
                    type_mapping = {
                        "ip-dst": "ip",
                        "ip-src": "ip",
                        "domain": "domain",
                        "hostname": "domain",
                        "url": "url",
                        "md5": "hash-md5",
                        "sha1": "hash-sha1",
                        "sha256": "hash-sha256",
                        "email": "email",
                    }

                    if attr_type in type_mapping and attr_value:
                        iocs.append({
                            "value": attr_value,
                            "ioc_type": type_mapping[attr_type],
                            "source": feed_name,
                            "tags": ["digitalside", "misp", attr_type],
                            "confidence": 85,
                            "description": f"IOC from DigitalSide MISP event {event_uuid[:8]}"
                        })

            except Exception as e:
                logger.warning(f"Error processing event {event_uuid}: {e}")
                continue

        logger.info(f"✅ Parsed {len(iocs)} IOCs from DigitalSide MISP")
        return iocs


async def import_iocs_to_db(session: AsyncSession, iocs: list, feed_id: uuid.UUID):
    """Import IOCs to database with upsert"""
    if not iocs:
        return 0

    imported = 0

    for ioc_data in iocs:
        try:
            stmt = pg_insert(MISPIoC).values(
                id=uuid.uuid4(),
                value=ioc_data["value"],
                ioc_type=ioc_data["ioc_type"],
                source=ioc_data["source"],
                tags=ioc_data.get("tags", []),
                confidence=ioc_data.get("confidence", 50),
                description=ioc_data.get("description"),
                feed_id=feed_id,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )

            # Upsert: update last_seen if exists
            stmt = stmt.on_conflict_do_update(
                index_elements=["value", "ioc_type"],
                set_={"last_seen": datetime.utcnow()}
            )

            await session.execute(stmt)
            imported += 1

        except Exception as e:
            logger.debug(f"Error importing IOC {ioc_data.get('value', 'unknown')}: {e}")
            continue

    await session.commit()
    return imported


async def sync_all_pending_feeds():
    """Sincronizar todos os feeds pendentes"""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Feed configurations
    feed_parsers = {
        "Feodo IP Blocklist": parse_feodo_csv,
        "Malware Bazaar (MD5)": parse_malware_bazaar_md5,
        "PhishTank Online Valid": parse_phishtank_csv,
        "FireHOL Level 1": parse_firehol_netset,
        "DigitalSide Threat-Intel": parse_digitalside_misp,
    }

    print("🚀 SINCRONIZAÇÃO COMPLETA DE FEEDS MISP")
    print("=" * 100)

    async with async_session() as session:
        # Get pending feeds
        result = await session.execute(
            select(MISPFeed).where(MISPFeed.last_sync_at == None)
        )
        pending_feeds = result.scalars().all()

        print(f"\n📊 Encontrados {len(pending_feeds)} feeds pendentes:")
        for feed in pending_feeds:
            print(f"   • {feed.name}")

        total_imported = 0
        successful = 0
        failed = 0

        for i, feed in enumerate(pending_feeds, 1):
            parser = feed_parsers.get(feed.name)

            if not parser:
                print(f"\n[{i}/{len(pending_feeds)}] ⚠️ {feed.name}")
                print(f"             Parser não implementado, pulando...")
                failed += 1
                continue

            print(f"\n[{i}/{len(pending_feeds)}] 🔄 {feed.name}")
            print(f"             URL: {feed.url[:70]}...")

            try:
                # Parse IOCs
                iocs = await parser(feed.url, feed.name)

                if iocs:
                    # Import to database
                    imported_count = await import_iocs_to_db(session, iocs, feed.id)

                    # Update feed
                    feed.last_sync_at = datetime.utcnow()
                    feed.total_iocs_imported = imported_count
                    await session.commit()

                    total_imported += imported_count
                    successful += 1
                    print(f"             ✅ {imported_count} IOCs importados")
                else:
                    print(f"             ⚠️ Nenhum IOC encontrado")
                    failed += 1

            except Exception as e:
                failed += 1
                print(f"             ❌ Erro: {str(e)[:100]}")
                logger.error(f"Error syncing {feed.name}: {e}", exc_info=True)

        print(f"\n{'=' * 100}")
        print(f"📊 RESULTADO FINAL:")
        print(f"   ✅ Sucesso: {successful}/{len(pending_feeds)}")
        print(f"   ❌ Falhas: {failed}/{len(pending_feeds)}")
        print(f"   📦 Total IOCs importados: {total_imported:,}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(sync_all_pending_feeds())
