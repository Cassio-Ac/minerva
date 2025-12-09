#!/usr/bin/env python3
"""
MALPEDIA PIPELINE - Coleta BibTeX + Enriquecimento com LLM

Pipeline completo para processar biblioteca Malpedia:
1. Baixa BibTeX do Malpedia (17.595 entries)
2. Indexa no Elasticsearch (rss-articles)
3. Enriquece com LLM:
   - Resumos gerados (2-3 frases)
   - Menções a atores de ameaça (APTs)
   - Menções a famílias de malware

Processa em batches de 50 com checkpoint para retomar.

Conecta ao Elasticsearch EXTERNO em localhost:9200 (projeto BHACK_2025)
que contém os índices:
  - malpedia_actors (864 docs)
  - malpedia_families (3,578 docs)
  - rss-articles (target para enriquecimento)
"""
import asyncio
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Adiciona backend ao path
sys.path.insert(0, str(Path(__file__).parent))

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from app.services.llm_factory import LLMFactory
from app.core.config import settings


# ============================================================================
# CONFIGURAÇÃO
# ============================================================================
# Elasticsearch EXTERNO (projeto BHACK_2025)
# Usa host.docker.internal quando rodando de dentro do Docker (macOS/Windows)
# ou localhost quando rodando no host
ES_URL = os.environ.get("MALPEDIA_ES_URL", "http://host.docker.internal:9200")
ES_USER = os.environ.get("MALPEDIA_ES_USER", None)
ES_PASS = os.environ.get("MALPEDIA_ES_PASS", None)

INDEX_RSS = "rss-articles"
INDEX_ACTORS = "malpedia_actors"
INDEX_FAMILIES = "malpedia_families"

BATCH_SIZE = 50  # Processar 50 artigos por vez
CHECKPOINT_FILE = "malpedia_enrichment_checkpoint.json"
ENRICHMENT_LOG = "malpedia_enrichment_log.jsonl"

# ============================================================================
# CLIENTE ELASTICSEARCH
# ============================================================================
es = Elasticsearch([ES_URL], request_timeout=30)


# ============================================================================
# FUNÇÕES DE CHECKPOINT
# ============================================================================
def load_checkpoint() -> Dict[str, Any]:
    """Carrega checkpoint do último processamento"""
    if Path(CHECKPOINT_FILE).exists():
        with open(CHECKPOINT_FILE, 'r') as f:
            return json.load(f)
    return {
        "last_processed_index": 0,
        "total_processed": 0,
        "total_enriched": 0,
        "total_errors": 0,
        "started_at": None,
        "last_update": None
    }


def save_checkpoint(checkpoint: Dict[str, Any]):
    """Salva checkpoint"""
    checkpoint["last_update"] = datetime.now().isoformat()
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(checkpoint, f, indent=2)


def log_enrichment(article_id: str, status: str, data: Dict[str, Any]):
    """Loga resultado do enriquecimento"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "article_id": article_id,
        "status": status,
        "data": data
    }
    with open(ENRICHMENT_LOG, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')


# ============================================================================
# BUSCAR DADOS DE REFERÊNCIA
# ============================================================================
def get_all_actors() -> List[Dict[str, Any]]:
    """Busca todos os atores do Elasticsearch"""
    print("📊 Buscando atores...")

    result = es.search(
        index=INDEX_ACTORS,
        body={
            "size": 1000,
            "_source": ["name", "aka"]
        },
        scroll='2m'
    )

    actors = []
    scroll_id = result['_scroll_id']
    hits = result['hits']['hits']

    while hits:
        for hit in hits:
            source = hit['_source']
            actors.append({
                "id": hit['_id'],
                "name": source.get('name', ''),
                "aka": source.get('aka', [])
            })

        result = es.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = result['_scroll_id']
        hits = result['hits']['hits']

    es.clear_scroll(scroll_id=scroll_id)

    print(f"   ✓ {len(actors)} atores carregados")
    return actors


def get_all_families() -> List[Dict[str, Any]]:
    """Busca todas as famílias do Elasticsearch"""
    print("📊 Buscando famílias de malware...")

    result = es.search(
        index=INDEX_FAMILIES,
        body={
            "size": 5000,
            "_source": ["name", "aka", "os"]
        },
        scroll='2m'
    )

    families = []
    scroll_id = result['_scroll_id']
    hits = result['hits']['hits']

    while hits:
        for hit in hits:
            source = hit['_source']
            families.append({
                "id": hit['_id'],
                "name": source.get('name', ''),
                "aka": source.get('aka', []),
                "os": source.get('os', '')
            })

        result = es.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = result['_scroll_id']
        hits = result['hits']['hits']

    es.clear_scroll(scroll_id=scroll_id)

    print(f"   ✓ {len(families)} famílias carregadas")
    return families


# ============================================================================
# BUSCAR ARTIGOS MALPEDIA LIBRARY
# ============================================================================
def get_malpedia_articles(from_index: int, size: int) -> List[Dict[str, Any]]:
    """Busca artigos da Malpedia Library"""
    result = es.search(
        index=INDEX_RSS,
        body={
            "query": {
                "term": {
                    "feed_name": "Malpedia Library"
                }
            },
            "from": from_index,
            "size": size,
            "sort": [{"published": "desc"}]
        }
    )

    articles = []
    for hit in result['hits']['hits']:
        articles.append({
            "_id": hit['_id'],
            "_source": hit['_source']
        })

    return articles


def count_malpedia_articles() -> int:
    """Conta total de artigos Malpedia Library"""
    result = es.count(
        index=INDEX_RSS,
        body={
            "query": {
                "term": {
                    "feed_name": "Malpedia Library"
                }
            }
        }
    )
    return result['count']


# ============================================================================
# ENRIQUECIMENTO COM LLM
# ============================================================================
async def enrich_article_with_llm(
    article: Dict[str, Any],
    actors: List[Dict[str, Any]],
    families: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Usa LLM para enriquecer artigo com:
    - Resumo gerado
    - Menções de atores
    - Menções de famílias
    """

    source = article['_source']
    title = source.get('title', '')
    author = source.get('author', '')
    link = source.get('link', '')

    # Cria lista de nomes de atores e famílias para o prompt
    actor_names = []
    for actor in actors[:200]:  # Limita a 200 mais relevantes
        actor_names.append(actor['name'])
        if actor.get('aka'):
            actor_names.extend(actor['aka'][:3])

    family_names = []
    for family in families[:500]:  # Limita a 500 mais relevantes
        family_names.append(family['name'])
        if family.get('aka'):
            aka_list = family['aka'] if isinstance(family['aka'], list) else []
            family_names.extend(aka_list[:2])

    # Remove duplicatas e ordena
    actor_names = sorted(list(set([a for a in actor_names if a])))[:300]
    family_names = sorted(list(set([f for f in family_names if f])))[:600]

    prompt = f"""Analise o artigo de threat intelligence abaixo e extraia:

1. RESUMO: Crie um resumo técnico de 2-3 frases sobre o artigo
2. ATORES: Liste APENAS os atores/APTs mencionados no título ou que você reconheça
3. FAMÍLIAS: Liste APENAS as famílias de malware mencionadas no título ou que você reconheça

**ARTIGO:**
Título: {title}
Autor: {author}
Link: {link}

**REFERÊNCIA DE ATORES CONHECIDOS (use apenas se mencionados):**
{', '.join(actor_names[:100])}

**REFERÊNCIA DE FAMÍLIAS CONHECIDAS (use apenas se mencionadas):**
{', '.join(family_names[:150])}

**IMPORTANTE:**
- Para ATORES e FAMÍLIAS: liste APENAS se houver menção explícita ou forte indicação no título
- Use os nomes exatos da lista de referência quando possível
- Se não tiver certeza, deixe a lista vazia
- Seja conservador, é melhor não mencionar do que mencionar incorretamente

Responda APENAS em JSON:
{{
  "summary": "resumo aqui",
  "actors_mentioned": ["actor1", "actor2"],
  "families_mentioned": ["family1", "family2"]
}}"""

    try:
        # Chama LLM
        llm_client = LLMFactory.create_client_from_env()
        if not llm_client:
            raise Exception("LLM client not configured")

        # Chama o método generate com mensagens no formato correto
        response = await llm_client.generate(
            messages=[{"role": "user", "content": prompt}]
        )

        # Extrai JSON da resposta
        response_text = response.get('content', '') if isinstance(response, dict) else str(response)

        # Tenta extrair JSON
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1

        if json_start >= 0 and json_end > json_start:
            json_str = response_text[json_start:json_end]
            enrichment = json.loads(json_str)

            return {
                "enriched_summary": enrichment.get("summary", ""),
                "actors_mentioned": enrichment.get("actors_mentioned", []),
                "families_mentioned": enrichment.get("families_mentioned", []),
                "enriched_at": datetime.now().isoformat(),
                "enrichment_version": "1.0"
            }
        else:
            print(f"   ⚠️  Resposta LLM não contém JSON válido")
            return None

    except Exception as e:
        print(f"   ❌ Erro ao processar artigo {article['_id']}: {e}")
        return None


# ============================================================================
# ATUALIZAÇÃO NO ELASTICSEARCH
# ============================================================================
def update_articles_bulk(updates: List[Dict[str, Any]]):
    """Atualiza artigos em bulk no Elasticsearch"""
    actions = []

    for update in updates:
        actions.append({
            "_op_type": "update",
            "_index": INDEX_RSS,
            "_id": update["_id"],
            "doc": update["enrichment"]
        })

    if actions:
        success, failed = bulk(es, actions, raise_on_error=False)
        return success, failed
    return 0, 0


# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================
async def enrich_all_articles():
    """Processa todos os artigos da Malpedia Library"""

    print("=" * 70)
    print("🚀 ENRIQUECIMENTO DE ARTIGOS MALPEDIA LIBRARY")
    print("=" * 70)

    # Carrega checkpoint
    checkpoint = load_checkpoint()

    if checkpoint["started_at"]:
        print(f"\n📂 Retomando do checkpoint:")
        print(f"   Último índice: {checkpoint['last_processed_index']}")
        print(f"   Processados: {checkpoint['total_processed']}")
        print(f"   Enriquecidos: {checkpoint['total_enriched']}")
        print(f"   Erros: {checkpoint['total_errors']}")
    else:
        checkpoint["started_at"] = datetime.now().isoformat()
        print("\n✨ Iniciando novo processamento")

    # Conta total de artigos
    total_articles = count_malpedia_articles()
    print(f"\n📊 Total de artigos: {total_articles:,}")

    # Carrega dados de referência
    actors = get_all_actors()
    families = get_all_families()

    # Inicializa LLM
    print("\n🤖 Inicializando LLM...")
    llm_client = LLMFactory.create_client_from_env()
    if not llm_client:
        print("   ❌ Erro: LLM não configurado. Verifique variáveis DATABRICKS_URL e DATABRICKS_TOKEN no .env")
        return

    print(f"   ✓ LLM configurado com sucesso")

    # Processa em batches
    from_index = checkpoint["last_processed_index"]

    print(f"\n🔄 Processando em batches de {BATCH_SIZE} artigos...")
    print(f"   Começando do índice {from_index}")

    while from_index < total_articles:
        batch_start = datetime.now()

        # Busca batch
        articles = get_malpedia_articles(from_index, BATCH_SIZE)

        if not articles:
            break

        print(f"\n📦 Batch {from_index // BATCH_SIZE + 1} ({from_index + 1} - {from_index + len(articles)})")

        # Processa cada artigo
        updates = []
        batch_enriched = 0
        batch_errors = 0

        for idx, article in enumerate(articles):
            article_id = article['_id']
            print(f"   [{idx + 1}/{len(articles)}] {article_id[:20]}...", end=" ")

            # Verifica se já foi enriquecido
            if article['_source'].get('enriched_at'):
                print("SKIP (já enriquecido)")
                continue

            # Enriquece
            enrichment = await enrich_article_with_llm(article, actors, families)

            if enrichment:
                updates.append({
                    "_id": article_id,
                    "enrichment": enrichment
                })
                batch_enriched += 1
                print(f"OK ({len(enrichment.get('actors_mentioned', []))} atores, {len(enrichment.get('families_mentioned', []))} famílias)")

                # Loga
                log_enrichment(article_id, "success", enrichment)
            else:
                batch_errors += 1
                print("ERRO")
                log_enrichment(article_id, "error", {})

        # Atualiza Elasticsearch
        if updates:
            print(f"\n   💾 Salvando {len(updates)} artigos no Elasticsearch...")
            success, failed = update_articles_bulk(updates)
            print(f"      ✓ {success} atualizados, {failed} falhas")

        # Atualiza checkpoint
        checkpoint["last_processed_index"] = from_index + len(articles)
        checkpoint["total_processed"] += len(articles)
        checkpoint["total_enriched"] += batch_enriched
        checkpoint["total_errors"] += batch_errors
        save_checkpoint(checkpoint)

        # Stats do batch
        batch_duration = (datetime.now() - batch_start).total_seconds()
        articles_per_sec = len(articles) / batch_duration if batch_duration > 0 else 0

        print(f"\n   ⏱️  Tempo: {batch_duration:.1f}s ({articles_per_sec:.2f} artigos/s)")
        print(f"   📈 Progresso: {checkpoint['total_processed']}/{total_articles} ({checkpoint['total_processed']/total_articles*100:.1f}%)")

        # Avança
        from_index += len(articles)

        # Pausa entre batches
        await asyncio.sleep(1)

    # Finaliza
    print("\n" + "=" * 70)
    print("✅ PROCESSAMENTO CONCLUÍDO")
    print("=" * 70)
    print(f"Total processado: {checkpoint['total_processed']}")
    print(f"Total enriquecido: {checkpoint['total_enriched']}")
    print(f"Total erros: {checkpoint['total_errors']}")
    print(f"Taxa de sucesso: {checkpoint['total_enriched']/checkpoint['total_processed']*100:.1f}%")
    print(f"\nCheckpoint salvo em: {CHECKPOINT_FILE}")
    print(f"Log completo em: {ENRICHMENT_LOG}")


# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    asyncio.run(enrich_all_articles())
