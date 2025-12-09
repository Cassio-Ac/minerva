"""
Populate RSS database with comprehensive feed list from ADINT project
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import select, text
from app.db.database import AsyncSessionLocal
from app.models.rss import RSSCategory, RSSSource, RSSSettings


async def populate_all_feeds():
    """Populate RSS database with comprehensive feed list"""
    print("🚀 Populating comprehensive RSS feeds...\n")

    async with AsyncSessionLocal() as db:
        # Get admin user ID
        result = await db.execute(text("SELECT id FROM users WHERE username = 'admin' LIMIT 1"))
        admin_user_row = result.first()

        if not admin_user_row:
            print("❌ Admin user not found")
            return

        admin_user_id = str(admin_user_row[0])
        print(f"✅ Found admin user ID: {admin_user_id}\n")

        # Define categories and their feeds
        feeds_data = {
            "Inteligência Artificial": [
                ("OpenAI News", "https://openai.com/news/rss.xml"),
                ("Google DeepMind Blog", "https://deepmind.com/blog/feed/basic"),
                ("Google Research Blog", "https://blog.research.google/atom.xml"),
                ("Hugging Face Blog", "https://huggingface.co/blog/feed.xml"),
                ("NVIDIA Developer Blog", "https://developer.nvidia.com/blog/feed/"),
                ("MIT Technology Review", "https://www.technologyreview.com/feed/"),
                ("arXiv AI (cs.AI)", "https://export.arxiv.org/rss/cs.AI"),
            ],
            "Segurança da Informação": [
                ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
                ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
                ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
                ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
                ("Dark Reading", "https://www.darkreading.com/rss.xml"),
                ("Threatpost", "https://threatpost.com/feed/"),
                ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
                ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
                ("Ars Technica Security", "https://arstechnica.com/tag/security/feed/"),
                ("The Register Security", "https://www.theregister.com/security/headlines.atom"),
            ],
            "Inteligência de Ameaças": [
                ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
                ("CISA ICS Advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
                ("CISA ICS Medical", "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"),
                ("US-CERT Activity", "https://www.cisa.gov/ncas/current-activity.xml"),
                ("US-CERT Alerts", "https://www.cisa.gov/ncas/alerts.xml"),
                ("US-CERT Analysis", "https://www.cisa.gov/ncas/analysis-reports.xml"),
                ("NVD Recent CVEs", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"),
                ("abuse.ch", "https://abuse.ch/feed/"),
                ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest"),
            ],
            "Vendors e Pesquisa": [
                ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
                ("Cisco Talos", "https://blog.talosintelligence.com/feed/"),
                ("Microsoft MSRC", "https://msrc.microsoft.com/blog/feed/"),
                ("Elastic Security Labs", "https://www.elastic.co/security-labs/feed/"),
                ("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
                ("Proofpoint", "https://www.proofpoint.com/us/blog/feed"),
                ("Google Cloud Blog", "https://cloudblog.withgoogle.com/rss"),
                ("Rapid7 Blog", "https://blog.rapid7.com/rss/"),
                ("Qualys Security", "https://blog.qualys.com/feed"),
                ("Tenable Blog", "https://www.tenable.com/blog/feed"),
            ],
            "Tecnologia": [
                ("TechCrunch", "https://techcrunch.com/feed/"),
                ("Ars Technica", "http://feeds.arstechnica.com/arstechnica/index"),
            ],
        }

        categories = {}

        # Create/get categories
        for category_name in feeds_data.keys():
            result = await db.execute(
                select(RSSCategory).where(RSSCategory.name == category_name)
            )
            category = result.scalar_one_or_none()

            if not category:
                category = RSSCategory(
                    name=category_name,
                    description=f"Feeds relacionados a {category_name}"
                )
                db.add(category)
                await db.flush()
                print(f"✅ Created category: {category_name}")
            else:
                print(f"ℹ️  Category exists: {category_name}")

            categories[category_name] = category

        # Create RSS sources
        total_added = 0
        total_existing = 0

        for category_name, feeds in feeds_data.items():
            print(f"\n📁 Category: {category_name}")
            category = categories[category_name]

            for feed_name, feed_url in feeds:
                # Check if exists
                result = await db.execute(
                    select(RSSSource).where(RSSSource.url == feed_url)
                )
                source = result.scalar_one_or_none()

                if not source:
                    source = RSSSource(
                        name=feed_name,
                        url=feed_url,
                        category_id=category.id,
                        is_active=True,
                        created_by=admin_user_id
                    )
                    db.add(source)
                    print(f"   ✅ Added: {feed_name}")
                    total_added += 1
                else:
                    print(f"   ℹ️  Exists: {feed_name}")
                    total_existing += 1

        await db.commit()

        print(f"\n✅ Database populated successfully!")
        print(f"\n📊 Summary:")
        print(f"   Categories: {len(categories)}")
        print(f"   Feeds added: {total_added}")
        print(f"   Feeds existing: {total_existing}")
        print(f"   Total feeds: {total_added + total_existing}")


if __name__ == "__main__":
    asyncio.run(populate_all_feeds())
