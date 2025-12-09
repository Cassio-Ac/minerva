"""
Import RSS feeds from YAML file
Adds missing feeds to the database
"""

import yaml
import requests
import sys

# API config
API_BASE = "http://localhost:8001/api/v1/rss"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYzQ3OTcyNi0xZDQwLTRhNzctOTVkMC1hMjgyNTI4ZjVhYWMiLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzYzNDA2MzExfQ.bIwY9FOGtIm6PrkCvK-FH4Pd5lWXPcFMdQeYml7tOz0"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Category mapping
CATEGORY_MAP = {
    "AI": "Inteligência Artificial",
    "Cybersecurity (News/Análises)": "Segurança da Informação",
    "Threat Intel / CVEs / IOCs": "Inteligência de Ameaças",
    "Vendors/Research (Threat Intel)": "Threat Intelligence"
}


def get_or_create_category(category_name):
    """Get existing category or create new one"""
    # Get all categories
    response = requests.get(f"{API_BASE}/categories", headers=HEADERS)
    categories = response.json()

    # Find by name
    for cat in categories:
        if cat["name"] == category_name:
            print(f"  ✓ Category '{category_name}' exists (ID: {cat['id']})")
            return cat["id"]

    # Create new
    data = {
        "name": category_name,
        "description": f"Category for {category_name}",
        "is_active": True
    }
    response = requests.post(f"{API_BASE}/categories", headers=HEADERS, json=data)
    if response.status_code == 201:
        cat = response.json()
        print(f"  ✅ Created category '{category_name}' (ID: {cat['id']})")
        return cat["id"]
    else:
        print(f"  ❌ Failed to create category: {response.text}")
        return None


def get_existing_sources():
    """Get all existing RSS sources"""
    response = requests.get(f"{API_BASE}/sources?limit=1000", headers=HEADERS)
    sources = response.json()

    # Create URL set for quick lookup
    existing_urls = {s["url"] for s in sources}
    print(f"📊 Found {len(existing_urls)} existing sources")
    return existing_urls


def import_feeds(yaml_path):
    """Import feeds from YAML file"""
    print(f"📖 Reading feeds from {yaml_path}")

    with open(yaml_path, 'r', encoding='utf-8') as f:
        feeds = yaml.safe_load(f)

    existing = get_existing_sources()

    added = 0
    skipped = 0
    failed = 0

    for category_key, category_feeds in feeds.items():
        print(f"\n📂 Category: {category_key}")

        # Map category name
        category_name = CATEGORY_MAP.get(category_key, category_key)
        category_id = get_or_create_category(category_name)

        if not category_id:
            print(f"  ⏭️  Skipping category (could not get/create ID)")
            continue

        # Add feeds
        for feed_name, feed_url in category_feeds.items():
            if feed_url in existing:
                print(f"  ⏭️  {feed_name}: already exists")
                skipped += 1
                continue

            # Create source
            data = {
                "name": feed_name,
                "url": feed_url,
                "category_id": category_id,
                "is_active": True,
                "refresh_interval_hours": 6
            }

            response = requests.post(f"{API_BASE}/sources", headers=HEADERS, json=data)
            if response.status_code == 201:
                print(f"  ✅ {feed_name}")
                added += 1
            else:
                print(f"  ❌ {feed_name}: {response.status_code} - {response.text[:100]}")
                failed += 1

    print(f"\n{'='*60}")
    print(f"📊 Summary:")
    print(f"  ✅ Added: {added}")
    print(f"  ⏭️  Skipped: {skipped}")
    print(f"  ❌ Failed: {failed}")
    print(f"{'='*60}")


if __name__ == "__main__":
    yaml_path = "/Users/angellocassio/Documents/ADINT/CURSO/clean_adint/FEED/feeds.yaml"
    import_feeds(yaml_path)
