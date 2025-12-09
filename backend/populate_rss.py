"""
Populate RSS database with sample categories and feeds
"""

import asyncio
import sys
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import select, text
from app.db.database import AsyncSessionLocal
from app.models.rss import RSSCategory, RSSSource, RSSSettings


async def populate_rss():
    """Populate RSS database with sample data"""
    async with AsyncSessionLocal() as db:
        # Get admin user ID using raw SQL
        result = await db.execute(text("SELECT id FROM users WHERE username = 'admin' LIMIT 1"))
        admin_user_row = result.first()

        if not admin_user_row:
            print("❌ Admin user not found")
            return

        admin_user_id = str(admin_user_row[0])
        print(f"✅ Found admin user ID: {admin_user_id}")

        # Create categories
        categories_data = [
            {"name": "Segurança da Informação", "description": "Notícias sobre segurança cibernética, vulnerabilidades e ameaças"},
            {"name": "Tecnologia", "description": "Notícias gerais sobre tecnologia e inovação"},
            {"name": "Inteligência de Ameaças", "description": "Feeds especializados em threat intelligence"},
        ]

        categories = {}
        for cat_data in categories_data:
            # Check if exists
            result = await db.execute(select(RSSCategory).where(RSSCategory.name == cat_data["name"]))
            category = result.scalar_one_or_none()

            if not category:
                category = RSSCategory(
                    name=cat_data["name"],
                    description=cat_data["description"]
                )
                db.add(category)
                await db.flush()
                print(f"✅ Created category: {category.name}")
            else:
                print(f"ℹ️  Category already exists: {category.name}")

            categories[cat_data["name"]] = category

        # Create RSS sources
        sources_data = [
            {
                "name": "The Hacker News",
                "url": "https://feeds.feedburner.com/TheHackersNews",
                "category": "Segurança da Informação",
                "is_active": True
            },
            {
                "name": "Krebs on Security",
                "url": "https://krebsonsecurity.com/feed/",
                "category": "Segurança da Informação",
                "is_active": True
            },
            {
                "name": "Bleeping Computer",
                "url": "https://www.bleepingcomputer.com/feed/",
                "category": "Segurança da Informação",
                "is_active": True
            },
            {
                "name": "TechCrunch",
                "url": "https://techcrunch.com/feed/",
                "category": "Tecnologia",
                "is_active": True
            },
            {
                "name": "Ars Technica",
                "url": "http://feeds.arstechnica.com/arstechnica/index",
                "category": "Tecnologia",
                "is_active": True
            },
        ]

        for source_data in sources_data:
            # Check if exists
            result = await db.execute(select(RSSSource).where(RSSSource.url == source_data["url"]))
            source = result.scalar_one_or_none()

            if not source:
                category = categories[source_data["category"]]
                source = RSSSource(
                    name=source_data["name"],
                    url=source_data["url"],
                    category_id=category.id,
                    is_active=source_data["is_active"],
                    created_by=admin_user_id
                )
                db.add(source)
                print(f"✅ Created source: {source.name}")
            else:
                print(f"ℹ️  Source already exists: {source.name}")

        # Create/update settings
        result = await db.execute(select(RSSSettings))
        settings = result.scalar_one_or_none()

        if not settings:
            settings = RSSSettings(
                collection_interval_hours=4,
                max_articles_per_feed=50,
                article_retention_days=90,
                enable_sentiment_analysis=False,
                auto_categorize=True
            )
            db.add(settings)
            print("✅ Created RSS settings")
        else:
            print("ℹ️  RSS settings already exist")

        await db.commit()
        print("\n✅ Database populated successfully!")

        # Show summary
        result = await db.execute(select(RSSCategory))
        categories_count = len(result.scalars().all())

        result = await db.execute(select(RSSSource))
        sources_count = len(result.scalars().all())

        print(f"\n📊 Summary:")
        print(f"   Categories: {categories_count}")
        print(f"   RSS Sources: {sources_count}")


if __name__ == "__main__":
    print("🚀 Populating RSS database...\n")
    asyncio.run(populate_rss())
