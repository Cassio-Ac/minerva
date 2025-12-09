#!/usr/bin/env python3
"""
Script para executar enrichment em BATCH de todos os actors do Malpedia

Execução:
    PYTHONPATH=/Users/angellocassio/Documents/intelligence-platform/backend python3 enrich_all_actors.py

O que faz:
1. Busca TODOS os actors do Malpedia no Elasticsearch
2. Para cada actor, tenta mapear para MITRE ATT&CK
3. Salva resultado em arquivo JSON com estatísticas
"""

import asyncio
import json
from datetime import datetime
from elasticsearch import AsyncElasticsearch
from app.cti.services.enrichment_service import EnrichmentService
from app.core.config import settings

async def enrich_all_actors():
    """Enriquece todos os actors do Malpedia com técnicas do MITRE ATT&CK"""

    # Connect to Elasticsearch
    print("📡 Conectando ao Elasticsearch...")
    es = AsyncElasticsearch(
        [settings.ES_URL or "http://localhost:9200"],
        basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD) if settings.ES_USERNAME else None,
        verify_certs=False,
        request_timeout=30
    )

    # Get ALL actors from Malpedia
    print("📥 Buscando todos os actors do Malpedia...")
    result = await es.search(
        index="malpedia_actors",
        body={
            "query": {"match_all": {}},
            "size": 10000  # Get all actors
        }
    )

    actors = [hit['_source'] for hit in result['hits']['hits']]
    print(f"✅ Encontrados {len(actors)} actors\n")

    # Initialize enrichment service
    enrichment_service = EnrichmentService()

    # Results
    enrichment_results = {
        "timestamp": datetime.now().isoformat(),
        "total_actors": len(actors),
        "enriched_actors": [],
        "not_mapped": [],
        "statistics": {
            "total_mapped": 0,
            "total_not_mapped": 0,
            "total_techniques": 0
        }
    }

    print("🔄 Processando actors...\n")

    for i, actor in enumerate(actors, 1):
        actor_name = actor['name']
        print(f"[{i}/{len(actors)}] Processing: {actor_name}", end="")

        try:
            # Get techniques for this actor
            techniques = await enrichment_service.get_techniques_for_actor(actor_name)

            if techniques:
                print(f" ✅ {len(techniques)} techniques")
                enrichment_results["enriched_actors"].append({
                    "name": actor_name,
                    "aka": actor.get('aka', []),
                    "techniques_count": len(techniques),
                    "techniques": techniques
                })
                enrichment_results["statistics"]["total_mapped"] += 1
                enrichment_results["statistics"]["total_techniques"] += len(techniques)
            else:
                print(f" ⚠️  No MITRE mapping")
                enrichment_results["not_mapped"].append({
                    "name": actor_name,
                    "aka": actor.get('aka', [])
                })
                enrichment_results["statistics"]["total_not_mapped"] += 1

        except Exception as e:
            print(f" ❌ Error: {e}")
            enrichment_results["not_mapped"].append({
                "name": actor_name,
                "aka": actor.get('aka', []),
                "error": str(e)
            })
            enrichment_results["statistics"]["total_not_mapped"] += 1

    # Save results
    output_file = "enrichment_results.json"
    with open(output_file, 'w') as f:
        json.dump(enrichment_results, f, indent=2)

    print(f"\n📊 Estatísticas:")
    print(f"   Total de actors: {enrichment_results['total_actors']}")
    print(f"   Mapeados com MITRE: {enrichment_results['statistics']['total_mapped']}")
    print(f"   Não mapeados: {enrichment_results['statistics']['total_not_mapped']}")
    print(f"   Total de técnicas: {enrichment_results['statistics']['total_techniques']}")
    print(f"   Cobertura: {enrichment_results['statistics']['total_mapped'] / enrichment_results['total_actors'] * 100:.1f}%")
    print(f"\n💾 Resultados salvos em: {output_file}")

    # Close ES connection
    await es.close()

if __name__ == "__main__":
    asyncio.run(enrich_all_actors())
