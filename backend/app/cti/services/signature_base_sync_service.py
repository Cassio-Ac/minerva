"""
Signature Base Sync Service

Sincroniza regras YARA e IOCs do repositório Neo23x0/signature-base
https://github.com/Neo23x0/signature-base

Fontes:
- /yara/*.yar - Regras YARA (727+ arquivos)
- /iocs/c2-iocs.txt - C2 domains/IPs (~1800 IOCs)
- /iocs/hash-iocs.txt - Malicious hashes (~1500 hashes)
- /iocs/filename-iocs.txt - Malicious filenames
"""
import requests
import hashlib
import re
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

logger = logging.getLogger(__name__)

# GitHub API and Raw URLs
GITHUB_API = "https://api.github.com/repos/Neo23x0/signature-base/contents"
GITHUB_RAW = "https://raw.githubusercontent.com/Neo23x0/signature-base/master"

# Category mapping from filename prefix
CATEGORY_MAP = {
    "apt": "apt",
    "crime": "crime",
    "gen": "generic",
    "mal": "malware",
    "expl": "exploit",
    "exploit": "exploit",
    "vul": "vulnerability",
    "vuln": "vulnerability",
    "hktl": "hacktool",
    "spy": "spyware",
    "pua": "pua",
    "pup": "pup",
    "webshell": "webshell",
    "thor": "thor",
}


class SignatureBaseSyncService:
    """Service para sincronizar Signature Base do Neo23x0"""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.headers = {
            "User-Agent": "Minerva-Intelligence/1.0",
            "Accept": "application/vnd.github.v3+json"
        }

    async def sync_yara_rules(self, limit: Optional[int] = None) -> Dict:
        """
        Sincroniza regras YARA do Signature Base

        Args:
            limit: Limite de arquivos para processar (None = todos)

        Returns:
            Dict com estatísticas da sincronização
        """
        logger.info("=" * 80)
        logger.info("SIGNATURE BASE YARA SYNC - Starting")
        logger.info("=" * 80)

        # Criar histórico de sync
        sync_id = await self._create_sync_history("signature_base_yara")

        stats = {
            "files_processed": 0,
            "rules_total": 0,
            "rules_new": 0,
            "rules_updated": 0,
            "rules_unchanged": 0,
            "rules_failed": 0,
            "errors": []
        }

        try:
            # 1. Listar arquivos YARA
            logger.info("Fetching YARA file list from GitHub...")
            yara_files = await self._list_yara_files()

            if limit:
                yara_files = yara_files[:limit]

            logger.info(f"Found {len(yara_files)} YARA files to process")

            # 2. Processar cada arquivo
            for idx, file_info in enumerate(yara_files, 1):
                filename = file_info["name"]
                logger.info(f"[{idx}/{len(yara_files)}] Processing: {filename}")

                try:
                    # Baixar conteúdo do arquivo
                    content = await self._fetch_file_content(f"yara/{filename}")
                    if not content:
                        stats["errors"].append(f"Failed to fetch: {filename}")
                        continue

                    # Extrair regras individuais
                    rules = self._parse_yara_file(content, filename)
                    stats["files_processed"] += 1

                    # Processar cada regra
                    for rule in rules:
                        result = await self._process_yara_rule(rule)
                        stats["rules_total"] += 1

                        if result == "new":
                            stats["rules_new"] += 1
                        elif result == "updated":
                            stats["rules_updated"] += 1
                        elif result == "unchanged":
                            stats["rules_unchanged"] += 1
                        else:
                            stats["rules_failed"] += 1

                except Exception as e:
                    logger.error(f"Error processing {filename}: {e}")
                    stats["errors"].append(f"{filename}: {str(e)}")

            # 3. Atualizar histórico
            await self._update_sync_history(sync_id, stats, "completed")

            logger.info("=" * 80)
            logger.info("SIGNATURE BASE YARA SYNC - Completed!")
            logger.info(f"Files: {stats['files_processed']}, Rules: {stats['rules_total']}")
            logger.info(f"New: {stats['rules_new']}, Updated: {stats['rules_updated']}, Unchanged: {stats['rules_unchanged']}")
            logger.info("=" * 80)

            return stats

        except Exception as e:
            logger.error(f"Sync failed: {e}")
            await self._update_sync_history(sync_id, stats, "failed", str(e))
            raise

    async def sync_iocs(self) -> Dict:
        """
        Sincroniza IOCs (C2, hashes, filenames) do Signature Base

        Returns:
            Dict com estatísticas
        """
        logger.info("=" * 80)
        logger.info("SIGNATURE BASE IOC SYNC - Starting")
        logger.info("=" * 80)

        stats = {
            "c2_iocs": 0,
            "hash_iocs": 0,
            "filename_iocs": 0,
            "total": 0,
            "errors": []
        }

        try:
            # 1. Sincronizar C2 IOCs
            logger.info("Syncing C2 IOCs...")
            c2_count = await self._sync_c2_iocs()
            stats["c2_iocs"] = c2_count

            # 2. Sincronizar Hash IOCs
            logger.info("Syncing Hash IOCs...")
            hash_count = await self._sync_hash_iocs()
            stats["hash_iocs"] = hash_count

            # 3. Sincronizar Filename IOCs
            logger.info("Syncing Filename IOCs...")
            filename_count = await self._sync_filename_iocs()
            stats["filename_iocs"] = filename_count

            stats["total"] = c2_count + hash_count + filename_count

            logger.info("=" * 80)
            logger.info("SIGNATURE BASE IOC SYNC - Completed!")
            logger.info(f"C2: {c2_count}, Hashes: {hash_count}, Filenames: {filename_count}")
            logger.info("=" * 80)

            return stats

        except Exception as e:
            logger.error(f"IOC sync failed: {e}")
            stats["errors"].append(str(e))
            raise

    async def _list_yara_files(self) -> List[Dict]:
        """Lista arquivos YARA do GitHub"""
        try:
            response = requests.get(
                f"{GITHUB_API}/yara",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            files = response.json()

            # Filtrar apenas arquivos .yar
            yara_files = [f for f in files if f["name"].endswith(".yar")]
            return sorted(yara_files, key=lambda x: x["name"])

        except Exception as e:
            logger.error(f"Failed to list YARA files: {e}")
            return []

    async def _fetch_file_content(self, path: str) -> Optional[str]:
        """Baixa conteúdo de um arquivo do GitHub"""
        try:
            url = f"{GITHUB_RAW}/{path}"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to fetch {path}: {e}")
            return None

    def _parse_yara_file(self, content: str, filename: str) -> List[Dict]:
        """
        Extrai regras individuais de um arquivo YARA

        Args:
            content: Conteúdo do arquivo
            filename: Nome do arquivo

        Returns:
            Lista de dicionários com dados das regras
        """
        rules = []

        # Regex para capturar regras YARA completas
        # Formato: rule RuleName { ... }
        rule_pattern = re.compile(
            r'(?:private\s+)?rule\s+(\w+)(?:\s*:\s*([^\{]+))?\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            re.MULTILINE | re.DOTALL
        )

        # Determinar categoria do arquivo
        category = self._get_category(filename)

        for match in rule_pattern.finditer(content):
            rule_name = match.group(1)
            rule_tags = match.group(2).strip().split() if match.group(2) else []
            rule_body = match.group(3)

            # Reconstruir a regra completa
            full_rule = f"rule {rule_name}"
            if rule_tags:
                full_rule += f" : {' '.join(rule_tags)}"
            full_rule += " {" + rule_body + "}"

            # Extrair metadados
            metadata = self._extract_metadata(rule_body)

            # Contar strings
            strings_count = len(re.findall(r'\$\w+\s*=', rule_body))

            # Extrair condição (simplificada)
            condition_match = re.search(r'condition:\s*(.+?)(?:\s*\}|$)', rule_body, re.DOTALL)
            condition = condition_match.group(1).strip()[:500] if condition_match else ""

            # Calcular hash do conteúdo
            rule_hash = hashlib.sha256(full_rule.encode()).hexdigest()

            rules.append({
                "rule_name": rule_name,
                "rule_hash": rule_hash,
                "source": "signature_base",
                "source_file": filename,
                "source_url": f"{GITHUB_RAW}/yara/{filename}",
                "category": category,
                "rule_content": full_rule,
                "tags": rule_tags,
                "strings_count": strings_count,
                "condition_summary": condition,
                **metadata
            })

        return rules

    def _get_category(self, filename: str) -> str:
        """Determina categoria baseado no prefixo do arquivo"""
        prefix = filename.split("_")[0].lower()
        return CATEGORY_MAP.get(prefix, "other")

    def _extract_metadata(self, rule_body: str) -> Dict:
        """Extrai metadados da seção meta de uma regra YARA"""
        metadata = {
            "description": None,
            "author": None,
            "reference": [],
            "date": None,
            "version": None,
            "threat_name": None,
            "threat_actor": None,
            "mitre_attack": [],
            "severity": None,
            "false_positive_risk": None,
        }

        # Extrair seção meta
        meta_match = re.search(r'meta:\s*(.+?)(?:strings:|condition:)', rule_body, re.DOTALL)
        if not meta_match:
            return metadata

        meta_section = meta_match.group(1)

        # Extrair campos específicos
        patterns = {
            "description": r'description\s*=\s*"([^"]*)"',
            "author": r'author\s*=\s*"([^"]*)"',
            "date": r'date\s*=\s*"([^"]*)"',
            "version": r'version\s*=\s*"([^"]*)"',
            "threat_name": r'(?:malware|family|threat)\s*=\s*"([^"]*)"',
            "threat_actor": r'(?:actor|apt|group)\s*=\s*"([^"]*)"',
            "severity": r'(?:severity|score)\s*=\s*"?(\w+)"?',
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, meta_section, re.IGNORECASE)
            if match:
                metadata[field] = match.group(1)

        # Extrair múltiplas referências
        ref_matches = re.findall(r'reference\s*=\s*"([^"]*)"', meta_section, re.IGNORECASE)
        metadata["reference"] = ref_matches

        # Extrair MITRE ATT&CK IDs
        mitre_matches = re.findall(r'(T\d{4}(?:\.\d{3})?)', meta_section)
        metadata["mitre_attack"] = list(set(mitre_matches))

        return metadata

    async def _process_yara_rule(self, rule: Dict) -> str:
        """
        Processa uma regra YARA individual

        Args:
            rule: Dicionário com dados da regra

        Returns:
            "new", "updated", "unchanged", ou "failed"
        """
        try:
            # Verificar se regra já existe
            result = await self.session.execute(
                text("SELECT rule_hash FROM yara_rules WHERE rule_hash = :hash"),
                {"hash": rule["rule_hash"]}
            )
            existing = result.fetchone()

            if existing:
                return "unchanged"

            # Verificar se existe regra com mesmo nome (atualização)
            result = await self.session.execute(
                text("SELECT id FROM yara_rules WHERE rule_name = :name AND source = :source"),
                {"name": rule["rule_name"], "source": rule["source"]}
            )
            existing_by_name = result.fetchone()

            if existing_by_name:
                # Atualizar regra existente
                await self.session.execute(
                    text("""
                        UPDATE yara_rules SET
                            rule_hash = :rule_hash,
                            source_file = :source_file,
                            source_url = :source_url,
                            category = :category,
                            rule_content = :rule_content,
                            description = :description,
                            author = :author,
                            reference = :reference,
                            date = :date,
                            version = :version,
                            tags = :tags,
                            mitre_attack = :mitre_attack,
                            threat_name = :threat_name,
                            threat_actor = :threat_actor,
                            severity = :severity,
                            strings_count = :strings_count,
                            condition_summary = :condition_summary,
                            synced_at = :synced_at,
                            updated_at = :updated_at
                        WHERE rule_name = :rule_name AND source = :source
                    """),
                    {
                        **rule,
                        "synced_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow(),
                    }
                )
                await self.session.commit()
                return "updated"

            # Inserir nova regra
            await self.session.execute(
                text("""
                    INSERT INTO yara_rules (
                        rule_name, rule_hash, source, source_file, source_url,
                        category, rule_content, description, author, reference,
                        date, version, tags, mitre_attack, threat_name,
                        threat_actor, severity, strings_count, condition_summary,
                        synced_at, created_at, updated_at
                    ) VALUES (
                        :rule_name, :rule_hash, :source, :source_file, :source_url,
                        :category, :rule_content, :description, :author, :reference,
                        :date, :version, :tags, :mitre_attack, :threat_name,
                        :threat_actor, :severity, :strings_count, :condition_summary,
                        :synced_at, :created_at, :updated_at
                    )
                """),
                {
                    **rule,
                    "synced_at": datetime.utcnow(),
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                }
            )
            await self.session.commit()
            return "new"

        except Exception as e:
            logger.error(f"Failed to process rule {rule['rule_name']}: {e}")
            await self.session.rollback()
            return "failed"

    async def _sync_c2_iocs(self) -> int:
        """Sincroniza IOCs de C2"""
        content = await self._fetch_file_content("iocs/c2-iocs.txt")
        if not content:
            logger.error("Failed to fetch C2 IOCs content")
            return 0

        logger.info(f"Fetched C2 IOCs content: {len(content)} bytes")

        count = 0
        skipped = 0
        errors = 0
        current_description = None

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Linhas com # no início são descrições para os IOCs seguintes
            if line.startswith("#"):
                # Captura descrição (sem o # inicial)
                desc_text = line.lstrip("#").strip()
                if desc_text and not desc_text.startswith("FORMAT") and not desc_text.startswith("LOKI"):
                    current_description = desc_text
                continue

            # Linha é um IOC (domain ou IP)
            value = line.strip()
            if not value:
                continue

            try:
                # Check if exists
                result = await self.session.execute(
                    text("SELECT id FROM signature_base_iocs WHERE value = :value AND type = 'c2'"),
                    {"value": value}
                )
                if result.fetchone():
                    skipped += 1
                    continue

                # Insert
                await self.session.execute(
                    text("""
                        INSERT INTO signature_base_iocs (value, type, description, source_file, synced_at, created_at)
                        VALUES (:value, 'c2', :description, 'c2-iocs.txt', :now, :now)
                    """),
                    {"value": value, "description": current_description, "now": datetime.utcnow()}
                )
                count += 1

                # Commit in batches to avoid transaction issues
                if count % 100 == 0:
                    await self.session.commit()

            except Exception as e:
                errors += 1
                await self.session.rollback()
                if errors <= 5:
                    logger.warning(f"Error inserting C2 IOC {value}: {e}")

        await self.session.commit()
        logger.info(f"C2 IOCs: {count} new, {skipped} skipped, {errors} errors")
        return count

    async def _sync_hash_iocs(self) -> int:
        """Sincroniza IOCs de hashes"""
        content = await self._fetch_file_content("iocs/hash-iocs.txt")
        if not content:
            logger.warning("Failed to fetch hash-iocs.txt")
            return 0

        count = 0
        skipped = 0
        errors = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Formato: hash;description
            parts = line.split(";", 1)
            value = parts[0].strip()
            description = parts[1].strip() if len(parts) > 1 else None

            if not value:
                continue

            # Verificar se é um hash válido (somente hex)
            if not all(c in '0123456789abcdefABCDEF' for c in value):
                continue

            # Determinar tipo de hash
            hash_type = None
            if len(value) == 32:
                hash_type = "md5"
            elif len(value) == 40:
                hash_type = "sha1"
            elif len(value) == 64:
                hash_type = "sha256"
            else:
                continue  # Hash de tamanho inválido

            try:
                result = await self.session.execute(
                    text("SELECT id FROM signature_base_iocs WHERE value = :value AND type = 'hash'"),
                    {"value": value.lower()}
                )
                if result.fetchone():
                    skipped += 1
                    continue

                await self.session.execute(
                    text("""
                        INSERT INTO signature_base_iocs (value, type, description, source_file, hash_type, synced_at, created_at)
                        VALUES (:value, 'hash', :description, 'hash-iocs.txt', :hash_type, :now, :now)
                    """),
                    {"value": value.lower(), "description": description, "hash_type": hash_type, "now": datetime.utcnow()}
                )
                count += 1

                if count % 100 == 0:
                    await self.session.commit()

            except Exception as e:
                errors += 1
                await self.session.rollback()
                if errors <= 5:
                    logger.warning(f"Error inserting hash IOC {value}: {e}")

        await self.session.commit()
        logger.info(f"Hash IOCs: {count} new, {skipped} skipped, {errors} errors")
        return count

    async def _sync_filename_iocs(self) -> int:
        """Sincroniza IOCs de filenames (regex patterns)"""
        content = await self._fetch_file_content("iocs/filename-iocs.txt")
        if not content:
            logger.warning("Failed to fetch filename-iocs.txt")
            return 0

        count = 0
        skipped = 0
        errors = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Formato: REGEX;SCORE[;FALSE_POSITIVE_EXCLUSION]
            parts = line.split(";")
            value = parts[0].strip()
            score = parts[1].strip() if len(parts) > 1 else None
            description = f"Score: {score}" if score else None

            if not value:
                continue

            try:
                result = await self.session.execute(
                    text("SELECT id FROM signature_base_iocs WHERE value = :value AND type = 'filename'"),
                    {"value": value}
                )
                if result.fetchone():
                    skipped += 1
                    continue

                await self.session.execute(
                    text("""
                        INSERT INTO signature_base_iocs (value, type, description, source_file, synced_at, created_at)
                        VALUES (:value, 'filename', :description, 'filename-iocs.txt', :now, :now)
                    """),
                    {"value": value, "description": description, "now": datetime.utcnow()}
                )
                count += 1

                if count % 100 == 0:
                    await self.session.commit()

            except Exception as e:
                errors += 1
                await self.session.rollback()
                if errors <= 5:
                    logger.warning(f"Error inserting filename IOC {value}: {e}")

        await self.session.commit()
        logger.info(f"Filename IOCs: {count} new, {skipped} skipped, {errors} errors")
        return count

    async def _create_sync_history(self, source: str) -> str:
        """Cria registro de histórico de sync"""
        result = await self.session.execute(
            text("""
                INSERT INTO yara_sync_history (source, started_at, status, created_at)
                VALUES (:source, :now, 'running', :now)
                RETURNING id
            """),
            {"source": source, "now": datetime.utcnow()}
        )
        await self.session.commit()
        row = result.fetchone()
        return str(row[0])

    async def _update_sync_history(self, sync_id: str, stats: Dict, status: str, error: str = None):
        """Atualiza registro de histórico de sync"""
        await self.session.execute(
            text("""
                UPDATE yara_sync_history SET
                    completed_at = :now,
                    files_processed = :files_processed,
                    rules_total = :rules_total,
                    rules_new = :rules_new,
                    rules_updated = :rules_updated,
                    rules_unchanged = :rules_unchanged,
                    rules_failed = :rules_failed,
                    status = :status,
                    error_message = :error
                WHERE id = :id
            """),
            {
                "id": sync_id,
                "now": datetime.utcnow(),
                "files_processed": stats.get("files_processed", 0),
                "rules_total": stats.get("rules_total", 0),
                "rules_new": stats.get("rules_new", 0),
                "rules_updated": stats.get("rules_updated", 0),
                "rules_unchanged": stats.get("rules_unchanged", 0),
                "rules_failed": stats.get("rules_failed", 0),
                "status": status,
                "error": error,
            }
        )
        await self.session.commit()

    async def get_stats(self) -> Dict:
        """Retorna estatísticas das regras YARA"""
        result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) as total_rules,
                    COUNT(DISTINCT source_file) as total_files,
                    COUNT(*) FILTER (WHERE category = 'apt') as apt_rules,
                    COUNT(*) FILTER (WHERE category = 'crime') as crime_rules,
                    COUNT(*) FILTER (WHERE category = 'generic') as generic_rules,
                    COUNT(*) FILTER (WHERE category = 'malware') as malware_rules,
                    COUNT(*) FILTER (WHERE category = 'exploit') as exploit_rules
                FROM yara_rules
                WHERE source = 'signature_base'
            """)
        )
        row = result.fetchone()

        ioc_result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (WHERE type = 'c2') as c2_count,
                    COUNT(*) FILTER (WHERE type = 'hash') as hash_count,
                    COUNT(*) FILTER (WHERE type = 'filename') as filename_count
                FROM signature_base_iocs
            """)
        )
        ioc_row = ioc_result.fetchone()

        return {
            "yara_rules": {
                "total": row[0] if row else 0,
                "files": row[1] if row else 0,
                "by_category": {
                    "apt": row[2] if row else 0,
                    "crime": row[3] if row else 0,
                    "generic": row[4] if row else 0,
                    "malware": row[5] if row else 0,
                    "exploit": row[6] if row else 0,
                }
            },
            "iocs": {
                "c2": ioc_row[0] if ioc_row else 0,
                "hashes": ioc_row[1] if ioc_row else 0,
                "filenames": ioc_row[2] if ioc_row else 0,
            }
        }
