"""
Malpedia Synchronization Service

Serviço para sincronização incremental de dados do Malpedia.
Detecta mudanças via content_hash e atualiza apenas documentos novos ou modificados.

Author: Angello Cassio
Date: 2025-11-19
"""

import hashlib
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from bs4 import BeautifulSoup
import requests

from app.db.elasticsearch import get_es_client
from app.core.config import settings

logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============

BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IntelligencePlatform/1.0)"}

# Elasticsearch indices
INDEX_ACTORS = "malpedia_actors"
INDEX_FAMILIES = "malpedia_families"


# ============= HASH UTILITIES =============

def calculate_content_hash(doc: Dict[str, Any]) -> str:
    """
    Calcula hash MD5 do conteúdo do documento

    Args:
        doc: Documento para calcular hash

    Returns:
        Hash MD5 em hexadecimal
    """
    # Remove metadados que não afetam o conteúdo
    content = {k: v for k, v in doc.items() if k not in ["content_hash", "last_updated", "created_at"]}

    # Serializa de forma determinística
    content_str = json.dumps(content, sort_keys=True, ensure_ascii=False)

    return hashlib.md5(content_str.encode()).hexdigest()


# ============= ACTORS COLLECTION =============

def extract_actor_names_and_links(html: str) -> List[Dict[str, str]]:
    """
    Extrai lista de atores da página principal

    Args:
        html: HTML da página de atores

    Returns:
        Lista de dicionários com name e url
    """
    soup = BeautifulSoup(html, "html.parser")
    actors = []

    for tr in soup.find_all("tr", class_="clickable-row"):
        actor_link = tr.get("data-href", "")
        common_name_tag = tr.find("td", class_="common_name")

        if actor_link and common_name_tag:
            actors.append({
                "name": common_name_tag.get_text(strip=True),
                "url": BASE_URL + actor_link
            })

    return actors


def parse_actor_page(html: str) -> Dict[str, Any]:
    """
    Extrai dados detalhados de um ator

    Args:
        html: HTML da página do ator

    Returns:
        Dicionário com dados do ator
    """
    soup = BeautifulSoup(html, "html.parser")

    # === AKA (aliases) ===
    aka = None
    aka_tag = soup.find("div", string=lambda s: s and s.strip().startswith("aka:"))
    h2 = soup.find("h2")

    if not aka_tag:
        if h2:
            next_div = h2.find_next_sibling("div")
            if next_div and "aka:" in next_div.text:
                aka = [a.strip() for a in next_div.text.replace("aka:", "").split(",") if a.strip()]
    else:
        aka = [a.strip() for a in aka_tag.text.replace("aka:", "").split(",") if a.strip()]

    # === Explicação (descrição) ===
    explicacao = None
    if h2:
        exp_p = h2.find_next_sibling("p")
        if exp_p:
            explicacao = exp_p.text.strip()

    # === Famílias relacionadas ===
    familialist = []
    h5_fam = soup.find("h5", string=lambda s: s and "Associated Families" in s)
    if h5_fam:
        badges = h5_fam.find_next_sibling("div")
        if badges:
            familialist = [
                span.text.strip()
                for span in badges.find_all("span", class_="badge-custom")
                if span.text.strip()
            ]

    # === Referências ===
    refs = []
    h5_refs = soup.find("h5", string=lambda s: s and "References" in s)
    if h5_refs:
        # Tabela (formato mais comum)
        table = h5_refs.find_next_sibling("table")
        if table:
            for tr in table.find_all("tr", class_="clickable-row"):
                url = tr.get("data-href", None)
                title = ""
                td = tr.find("td")
                if td:
                    span_title = td.find("span", class_="title mono-font")
                    if span_title:
                        title = span_title.get_text(strip=True)
                    elif td.find("a"):
                        title = td.find("a").get_text(strip=True)
                    else:
                        title = td.get_text(strip=True)
                refs.append({"desc": title, "url": url})
        # Fallback: UL/LI
        else:
            ul = h5_refs.find_next_sibling("ul")
            if ul:
                for li in ul.find_all("li"):
                    a = li.find("a")
                    if a and a.has_attr("href"):
                        refs.append({"desc": a.text.strip(), "url": a["href"]})
                    elif li.text.strip():
                        refs.append({"desc": li.text.strip(), "url": None})

    return {
        "aka": aka,
        "explicacao": explicacao,
        "familias_relacionadas": familialist,
        "referencias": refs
    }


async def fetch_actor_details(actor_name: str, actor_url: str) -> Optional[Dict[str, Any]]:
    """
    Baixa e parseia detalhes de um ator

    Args:
        actor_name: Nome do ator
        actor_url: URL da página do ator

    Returns:
        Dicionário com dados completos do ator ou None em erro
    """
    try:
        logger.info(f"Fetching actor: {actor_name}")
        resp = requests.get(actor_url, headers=HEADERS, timeout=30)

        if resp.status_code != 200:
            logger.error(f"HTTP {resp.status_code} for {actor_name}")
            return None

        enrichment = parse_actor_page(resp.text)

        # Combina dados básicos + enriquecimento
        actor_data = {
            "name": actor_name,
            "url": actor_url,
            **enrichment
        }

        # Adiciona metadados
        actor_data["content_hash"] = calculate_content_hash(actor_data)
        actor_data["last_updated"] = datetime.utcnow().isoformat()

        return actor_data

    except Exception as e:
        logger.error(f"Error fetching {actor_name}: {e}")
        return None


# ============= CHANGE DETECTION =============

async def detect_actor_changes(actor_data: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Detecta se um ator mudou

    Args:
        actor_data: Dados do ator do Malpedia

    Returns:
        Tupla (change_type, existing_doc)
        - change_type: "new", "updated", "unchanged"
        - existing_doc: Documento existente no ES ou None
    """
    es = await get_es_client()
    actor_name = actor_data["name"]

    try:
        # Busca documento existente
        result = await es.search(
            index=INDEX_ACTORS,
            body={
                "query": {"term": {"name.keyword": actor_name}},
                "size": 1
            }
        )

        if result["hits"]["total"]["value"] == 0:
            return "new", None

        # Documento existe - compara hash
        existing_doc = result["hits"]["hits"][0]["_source"]
        old_hash = existing_doc.get("content_hash")
        new_hash = actor_data["content_hash"]

        if old_hash != new_hash:
            return "updated", existing_doc

        return "unchanged", existing_doc

    except Exception as e:
        logger.error(f"Error detecting changes for {actor_name}: {e}")
        # Assume novo em caso de erro
        return "new", None


# ============= ELASTICSEARCH SYNC =============

async def sync_actor_to_es(actor_data: Dict[str, Any], change_type: str) -> bool:
    """
    Sincroniza um ator para o Elasticsearch

    Args:
        actor_data: Dados do ator
        change_type: Tipo de mudança (new, updated, unchanged)

    Returns:
        True se sincronizado com sucesso
    """
    if change_type == "unchanged":
        logger.debug(f"⏭️ {actor_data['name']}: sem mudanças")
        return True

    es = await get_es_client()
    actor_name = actor_data["name"]

    try:
        if change_type == "new":
            actor_data["created_at"] = datetime.utcnow().isoformat()
            logger.info(f"➕ {actor_name}: NOVO")
        else:
            logger.info(f"🔄 {actor_name}: ATUALIZADO")

        # Upsert (index com mesmo ID sobrescreve)
        await es.index(
            index=INDEX_ACTORS,
            id=actor_name,
            body=actor_data
        )

        return True

    except Exception as e:
        logger.error(f"Error syncing {actor_name} to ES: {e}")
        return False


# ============= MAIN SYNC FUNCTION =============

async def sync_all_actors() -> Dict[str, Any]:
    """
    Sincroniza todos os atores do Malpedia de forma incremental

    Returns:
        Estatísticas da sincronização
    """
    logger.info("="*80)
    logger.info("🚀 MALPEDIA ACTORS SYNC - Starting")
    logger.info("="*80)

    start_time = time.time()

    # === FASE 1: Baixar lista de atores ===
    logger.info("\n📥 PHASE 1: Fetching actors list...")

    try:
        resp = requests.get(f"{BASE_URL}/actors", headers=HEADERS)
        resp.raise_for_status()
        actors_list = extract_actor_names_and_links(resp.text)
        logger.info(f"✅ Found {len(actors_list)} actors")
    except Exception as e:
        logger.error(f"❌ Failed to fetch actors list: {e}")
        return {"error": str(e)}

    # === FASE 2: Processar cada ator ===
    logger.info("\n🔄 PHASE 2: Processing actors...")

    stats = {
        "total": len(actors_list),
        "new": [],
        "updated": [],
        "unchanged": 0,
        "errors": []
    }

    for idx, actor_info in enumerate(actors_list, 1):
        actor_name = actor_info["name"]
        actor_url = actor_info["url"]

        logger.info(f"\n[{idx}/{stats['total']}] {actor_name}")

        # Fetch details
        actor_data = await fetch_actor_details(actor_name, actor_url)
        if not actor_data:
            stats["errors"].append(actor_name)
            continue

        # Detect changes
        change_type, _ = await detect_actor_changes(actor_data)

        # Sync to Elasticsearch
        success = await sync_actor_to_es(actor_data, change_type)

        if success:
            if change_type == "new":
                stats["new"].append(actor_name)
            elif change_type == "updated":
                stats["updated"].append(actor_name)
            else:
                stats["unchanged"] += 1
        else:
            stats["errors"].append(actor_name)

        # Rate limiting (gentil com o servidor)
        if idx < stats["total"]:
            await asyncio.sleep(0.5)

    # === FINAL STATS ===
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    logger.info("\n" + "="*80)
    logger.info("✅ MALPEDIA ACTORS SYNC - Completed!")
    logger.info("="*80)
    logger.info(f"\n📊 Summary:")
    logger.info(f"   Total actors:    {stats['total']}")
    logger.info(f"   New:             {len(stats['new'])}")
    logger.info(f"   Updated:         {len(stats['updated'])}")
    logger.info(f"   Unchanged:       {stats['unchanged']}")
    logger.info(f"   Errors:          {len(stats['errors'])}")
    logger.info(f"\n⏱️  Time: {minutes}min {seconds}s")
    logger.info("="*80)

    return stats


# ============= FAMILIES COLLECTION =============

def extract_family_names_and_links(html: str) -> List[Dict[str, str]]:
    """
    Extrai lista de famílias da página principal

    Args:
        html: HTML da página de famílias

    Returns:
        Lista de dicionários com name e url
    """
    soup = BeautifulSoup(html, "html.parser")
    families = []

    for tr in soup.find_all("tr", class_="clickable-row"):
        family_link = tr.get("data-href", "")
        common_name_tag = tr.find("td", class_="common_name")

        if family_link and common_name_tag:
            # Extract nome técnico do link (ex: /details/win.vidar -> win.vidar)
            tech_name = family_link.replace("/details/", "")

            families.append({
                "name": tech_name,
                "common_name": common_name_tag.get_text(strip=True),
                "url": BASE_URL + family_link
            })

    return families


def parse_family_page(html: str) -> Dict[str, Any]:
    """
    Extrai dados detalhados de uma família

    Args:
        html: HTML da página da família

    Returns:
        Dicionário com dados da família
    """
    soup = BeautifulSoup(html, "html.parser")

    # === Nome técnico (do title ou h2) ===
    tech_name = None
    mono_font = soup.find("span", class_="mono-font")
    if mono_font:
        tech_name = mono_font.text.strip()

    # === Common Name (do h2) ===
    common_name = None
    h2 = soup.find("h2")
    if h2:
        # Remove ícones e botões
        for tag in h2.find_all(["i", "button"]):
            tag.decompose()
        common_name = h2.text.strip()

    # === Descrição ===
    description = None
    # Procura meta description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        description = meta_desc.get("content", "").strip()

    # === Aliases (nomes alternativos) ===
    aliases = []
    # Procura no campo hidden alt_names da tabela
    for tr in soup.find_all("tr", class_="clickable-row"):
        alt_names_td = tr.find("td", class_="alt_names", hidden=True)
        if alt_names_td and tech_name and tech_name in str(tr):
            import ast
            try:
                aliases = ast.literal_eval(alt_names_td.text.strip())
            except:
                pass
            break

    # === Sistema Operacional ===
    os_info = None
    os_icons = {
        "fa-windows": "Windows",
        "fa-apple": "MacOS",
        "fa-linux": "Linux",
        "fa-android": "Android",
        "fa-python": "Python",
        "fa-js": "JavaScript"
    }

    for icon_class, os_name in os_icons.items():
        if soup.find("i", class_=icon_class):
            os_info = os_name
            break

    # === Atores relacionados ===
    related_actors = []
    # Procura no campo hidden actors da tabela
    for tr in soup.find_all("tr", class_="clickable-row"):
        actors_td = tr.find("td", class_="actors", hidden=True)
        if actors_td and tech_name and tech_name in str(tr):
            import ast
            try:
                related_actors = ast.literal_eval(actors_td.text.strip())
            except:
                pass
            break

    # === Last Updated ===
    last_updated = None
    for tr in soup.find_all("tr", class_="clickable-row"):
        if tech_name and tech_name in str(tr):
            updated_td = tr.find("td", class_="entry_updated")
            if updated_td:
                last_updated = updated_td.text.strip()
            break

    return {
        "name": tech_name,
        "common_name": common_name or tech_name,
        "description": description,
        "aliases": aliases if aliases else None,
        "os": os_info,
        "related_actors": related_actors if related_actors else None,
        "last_updated": last_updated
    }


async def fetch_family_details(family_name: str, family_url: str) -> Optional[Dict[str, Any]]:
    """
    Faz scraping dos detalhes de uma família

    Args:
        family_name: Nome técnico da família
        family_url: URL da página da família

    Returns:
        Dicionário com dados da família ou None se erro
    """
    try:
        logger.info(f"Fetching family: {family_name}")

        resp = requests.get(family_url, headers=HEADERS)
        resp.raise_for_status()

        family_data = parse_family_page(resp.text)

        # Adiciona metadados
        family_data["url"] = family_url
        family_data["last_updated"] = datetime.utcnow().isoformat()

        # Calcula hash do conteúdo
        family_data["content_hash"] = calculate_content_hash(family_data)

        return family_data

    except Exception as e:
        logger.error(f"Error fetching {family_name}: {e}")
        return None


# ============= FAMILIES CHANGE DETECTION =============

async def detect_family_changes(family_data: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Detecta se uma família mudou

    Args:
        family_data: Dados da família do Malpedia

    Returns:
        Tupla (change_type, existing_doc)
        - change_type: "new", "updated", "unchanged"
        - existing_doc: Documento existente no ES ou None
    """
    es = await get_es_client()
    family_name = family_data["name"]

    try:
        # Busca documento existente
        result = await es.search(
            index=INDEX_FAMILIES,
            body={
                "query": {"term": {"name.keyword": family_name}},
                "size": 1
            }
        )

        if result["hits"]["total"]["value"] == 0:
            return "new", None

        # Documento existe - compara hash
        existing_doc = result["hits"]["hits"][0]["_source"]
        old_hash = existing_doc.get("content_hash")
        new_hash = family_data["content_hash"]

        if old_hash != new_hash:
            return "updated", existing_doc

        return "unchanged", existing_doc

    except Exception as e:
        logger.error(f"Error detecting changes for {family_name}: {e}")
        # Assume novo em caso de erro
        return "new", None


# ============= FAMILIES ELASTICSEARCH SYNC =============

async def sync_family_to_es(family_data: Dict[str, Any], change_type: str) -> bool:
    """
    Sincroniza uma família para o Elasticsearch

    Args:
        family_data: Dados da família
        change_type: Tipo de mudança (new, updated, unchanged)

    Returns:
        True se sincronizado com sucesso
    """
    if change_type == "unchanged":
        logger.debug(f"⏭️ {family_data['name']}: sem mudanças")
        return True

    es = await get_es_client()
    family_name = family_data["name"]

    try:
        if change_type == "new":
            family_data["created_at"] = datetime.utcnow().isoformat()
            logger.info(f"➕ {family_name}: NOVO")
        else:
            logger.info(f"🔄 {family_name}: ATUALIZADO")

        # Upsert (index com mesmo ID sobrescreve)
        await es.index(
            index=INDEX_FAMILIES,
            id=family_name,
            body=family_data
        )

        return True

    except Exception as e:
        logger.error(f"Error syncing {family_name} to ES: {e}")
        return False


# ============= FAMILIES MAIN SYNC FUNCTION =============

async def sync_all_families() -> Dict[str, Any]:
    """
    Sincroniza todas as famílias do Malpedia de forma incremental

    Returns:
        Estatísticas da sincronização
    """
    logger.info("="*80)
    logger.info("🚀 MALPEDIA FAMILIES SYNC - Starting")
    logger.info("="*80)

    start_time = time.time()

    # === FASE 1: Baixar lista de famílias (todas as páginas) ===
    logger.info("\n📥 PHASE 1: Fetching families list...")

    all_families = []
    page = 1
    max_pages = 50  # Limite de segurança

    try:
        while page <= max_pages:
            url = f"{BASE_URL}/families/{page}/" if page > 1 else f"{BASE_URL}/families"

            logger.info(f"   Fetching page {page}...")
            resp = requests.get(url, headers=HEADERS)
            resp.raise_for_status()

            families_on_page = extract_family_names_and_links(resp.text)

            if not families_on_page:
                logger.info(f"   No more families found on page {page}")
                break

            all_families.extend(families_on_page)
            logger.info(f"   Found {len(families_on_page)} families on page {page}")

            # Check if there's a next page
            if 'page-item"><a class="page-link" href="/families/' + str(page + 1) in resp.text:
                page += 1
                await asyncio.sleep(0.3)  # Rate limiting entre páginas
            else:
                break

        logger.info(f"✅ Found {len(all_families)} families across {page} page(s)")

    except Exception as e:
        logger.error(f"❌ Failed to fetch families list: {e}")
        return {"error": str(e)}

    # === FASE 2: Processar cada família ===
    logger.info("\n🔄 PHASE 2: Processing families...")

    stats = {
        "total": len(all_families),
        "new": [],
        "updated": [],
        "unchanged": 0,
        "errors": []
    }

    for idx, family_info in enumerate(all_families, 1):
        family_name = family_info["name"]
        family_url = family_info["url"]

        logger.info(f"\n[{idx}/{stats['total']}] {family_name}")

        # Fetch details
        family_data = await fetch_family_details(family_name, family_url)
        if not family_data:
            stats["errors"].append(family_name)
            continue

        # Detect changes
        change_type, _ = await detect_family_changes(family_data)

        # Sync to Elasticsearch
        success = await sync_family_to_es(family_data, change_type)

        if success:
            if change_type == "new":
                stats["new"].append(family_name)
            elif change_type == "updated":
                stats["updated"].append(family_name)
            else:
                stats["unchanged"] += 1
        else:
            stats["errors"].append(family_name)

        # Rate limiting (gentil com o servidor)
        if idx < stats["total"]:
            await asyncio.sleep(0.5)

    # === FINAL STATS ===
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    logger.info("\n" + "="*80)
    logger.info("✅ MALPEDIA FAMILIES SYNC - Completed!")
    logger.info("="*80)
    logger.info(f"\n📊 Summary:")
    logger.info(f"   Total families:  {stats['total']}")
    logger.info(f"   New:             {len(stats['new'])}")
    logger.info(f"   Updated:         {len(stats['updated'])}")
    logger.info(f"   Unchanged:       {stats['unchanged']}")
    logger.info(f"   Errors:          {len(stats['errors'])}")
    logger.info(f"\n⏱️  Time: {minutes}min {seconds}s")
    logger.info("="*80)

    return stats


# ============= ASYNCIO IMPORT =============

import asyncio
