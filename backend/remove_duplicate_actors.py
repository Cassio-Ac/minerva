"""
Remove Duplicate Actors from Elasticsearch

This script identifies and removes duplicate threat actors from the malpedia_actors index.
Keeps only the most recent version of each actor (by update timestamp).
"""

import asyncio
from collections import defaultdict
from app.db.elasticsearch import ElasticsearchClient
from app.core.config import settings


async def remove_duplicate_actors():
    """Remove duplicate actors, keeping only the most recent version."""

    # Get Elasticsearch client
    es = ElasticsearchClient.get_client()

    print("🔍 Searching for duplicate actors in malpedia_actors index...")

    # Get all actors
    response = await es.search(
        index="malpedia_actors",
        body={
            "size": 10000,
            "query": {"match_all": {}},
            "_source": ["name", "familias_relacionadas"]
        }
    )

    total_actors = response['hits']['total']['value']
    print(f"📊 Total actors found: {total_actors}")

    # Group actors by name
    actors_by_name = defaultdict(list)
    for hit in response['hits']['hits']:
        actor_name = hit['_source']['name']
        actors_by_name[actor_name].append({
            'id': hit['_id'],
            'name': actor_name,
            'families': len(hit['_source'].get('familias_relacionadas', []))
        })

    # Find duplicates
    duplicates = {name: actors for name, actors in actors_by_name.items() if len(actors) > 1}

    if not duplicates:
        print("✅ No duplicates found!")
        return

    print(f"\n⚠️  Found {len(duplicates)} actors with duplicates:")

    to_delete = []
    for actor_name, versions in duplicates.items():
        print(f"\n  • {actor_name}: {len(versions)} versions")

        # Sort by number of families (descending)
        versions_sorted = sorted(
            versions,
            key=lambda x: x['families'],
            reverse=True
        )

        # Keep the first (with most families)
        keep = versions_sorted[0]
        delete_versions = versions_sorted[1:]

        print(f"    ✓ Keeping: ID={keep['id']}, families={keep['families']}")

        for version in delete_versions:
            print(f"    ✗ Deleting: ID={version['id']}, families={version['families']}")
            to_delete.append(version['id'])

    if to_delete:
        print(f"\n🗑️  Deleting {len(to_delete)} duplicate documents...")

        # Delete in batches
        batch_size = 100
        deleted_count = 0

        for i in range(0, len(to_delete), batch_size):
            batch = to_delete[i:i + batch_size]

            # Build bulk delete operations
            bulk_body = []
            for doc_id in batch:
                bulk_body.append({"delete": {"_index": "malpedia_actors", "_id": doc_id}})

            # Execute bulk delete
            result = await es.bulk(body=bulk_body, refresh=True)

            if result.get('errors'):
                print(f"    ⚠️  Some deletions failed in batch {i // batch_size + 1}")
            else:
                deleted_count += len(batch)
                print(f"    ✓ Deleted batch {i // batch_size + 1}/{(len(to_delete) + batch_size - 1) // batch_size}")

        print(f"\n✅ Successfully deleted {deleted_count} duplicate documents!")

        # Verify
        response_after = await es.search(
            index="malpedia_actors",
            body={
                "size": 0,
                "aggs": {
                    "duplicate_names": {
                        "terms": {
                            "field": "name.keyword",
                            "min_doc_count": 2,
                            "size": 1000
                        }
                    }
                }
            }
        )

        remaining_duplicates = len(response_after['aggregations']['duplicate_names']['buckets'])

        if remaining_duplicates > 0:
            print(f"\n⚠️  Still {remaining_duplicates} actors with duplicates remaining")
        else:
            print("\n✅ All duplicates removed!")
    else:
        print("\n✅ No documents to delete")


if __name__ == "__main__":
    asyncio.run(remove_duplicate_actors())
