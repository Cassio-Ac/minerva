#!/usr/bin/env python3
"""
Analisa clusters do MISP Galaxy e cria documentação
"""
import json
from collections import defaultdict

def analyze_cluster(filepath: str, cluster_type: str):
    """Analisa um cluster MISP Galaxy"""
    with open(filepath) as f:
        data = json.load(f)

    print(f"\n{'='*60}")
    print(f"📊 {cluster_type.upper()}")
    print(f"{'='*60}\n")

    # Metadata
    print(f"Nome: {data.get('name', 'N/A')}")
    print(f"Tipo: {data.get('type', 'N/A')}")
    print(f"Descrição: {data.get('description', 'N/A')}")
    print(f"Versão: {data.get('version', 'N/A')}")
    print(f"UUID: {data.get('uuid', 'N/A')}")
    print(f"Total de valores: {len(data.get('values', []))}\n")

    # Analisa valores
    values = data.get('values', [])
    if not values:
        return

    # Campos disponíveis
    all_fields = set()
    meta_fields = defaultdict(int)

    for value in values:
        all_fields.update(value.keys())
        meta = value.get('meta', {})
        for key in meta.keys():
            meta_fields[key] += 1

    print("🔑 Campos principais:")
    for field in sorted(all_fields):
        print(f"  - {field}")

    print("\n📋 Metadados disponíveis (frequência):")
    for field, count in sorted(meta_fields.items(), key=lambda x: -x[1])[:15]:
        pct = (count / len(values)) * 100
        print(f"  - {field}: {count}/{len(values)} ({pct:.1f}%)")

    # Exemplos
    print("\n📝 Exemplos:")
    for i, value in enumerate(values[:3]):
        print(f"\n{i+1}. {value.get('value', 'N/A')}")
        if 'description' in value:
            desc = value['description'][:200] + "..." if len(value['description']) > 200 else value['description']
            print(f"   Descrição: {desc}")

        meta = value.get('meta', {})
        if 'synonyms' in meta:
            print(f"   Sinônimos: {', '.join(meta['synonyms'][:3])}")
        if 'country' in meta:
            print(f"   País: {meta['country']}")
        if 'refs' in meta:
            print(f"   Referências: {len(meta['refs'])} links")

if __name__ == '__main__':
    analyze_cluster('/tmp/threat-actor.json', 'Threat Actors')
    analyze_cluster('/tmp/malpedia.json', 'Malpedia (Malware)')
    analyze_cluster('/tmp/tool.json', 'Tools')

    print(f"\n{'='*60}")
    print("✅ Análise completa!")
    print(f"{'='*60}\n")
