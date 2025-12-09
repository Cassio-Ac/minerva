"""
CPF Search Service using Elasticsearch
"""
from datetime import datetime, date
from typing import Optional
from elasticsearch import Elasticsearch


class CPFSearchService:
    def __init__(self, es_client: Elasticsearch, index_name: str = "cpf"):
        self.es = es_client
        self.index_name = index_name

    def search_cpf(
        self,
        query: Optional[str] = None,
        cpf: Optional[str] = None,
        nome: Optional[str] = None,
        sexo: Optional[str] = None,
        nasc_from: Optional[date] = None,
        nasc_to: Optional[date] = None,
        idade_min: Optional[int] = None,
        idade_max: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "nome.keyword",
        sort_order: str = "asc",
    ):
        """
        Search CPF records with filters and facets
        """
        must_clauses = []
        filter_clauses = []

        # Busca geral (CPF ou nome)
        if query:
            # Remove pontuação do CPF se houver
            clean_query = query.replace(".", "").replace("-", "").strip()

            # Se parece ser um CPF (só números)
            if clean_query.isdigit():
                must_clauses.append({
                    "term": {"cpf": clean_query}
                })
            else:
                # Busca por nome
                must_clauses.append({
                    "match": {
                        "nome": {
                            "query": query,
                            "operator": "and"
                        }
                    }
                })

        # Busca específica por CPF
        if cpf:
            clean_cpf = cpf.replace(".", "").replace("-", "").strip()
            filter_clauses.append({"term": {"cpf": clean_cpf}})

        # Busca específica por nome
        if nome:
            must_clauses.append({
                "match": {
                    "nome": {
                        "query": nome,
                        "operator": "and"
                    }
                }
            })

        # Filtro por sexo
        if sexo:
            filter_clauses.append({"term": {"sexo": sexo.upper()}})

        # Filtro por data de nascimento
        if nasc_from or nasc_to:
            date_range = {}
            if nasc_from:
                date_range["gte"] = nasc_from.strftime('%Y-%m-%d')
            if nasc_to:
                date_range["lte"] = nasc_to.strftime('%Y-%m-%d')
            filter_clauses.append({"range": {"nasc": date_range}})

        # Filtro por idade (converte para data de nascimento)
        if idade_min is not None or idade_max is not None:
            today = datetime.now()
            age_range = {}
            if idade_max is not None:
                # Idade máxima = data de nascimento mínima
                min_birth = date(today.year - idade_max - 1, today.month, today.day)
                age_range["gte"] = min_birth.strftime('%Y-%m-%d')
            if idade_min is not None:
                # Idade mínima = data de nascimento máxima
                max_birth = date(today.year - idade_min, today.month, today.day)
                age_range["lte"] = max_birth.strftime('%Y-%m-%d')
            filter_clauses.append({"range": {"nasc": age_range}})

        # Build search body
        body = {
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}],
                    "filter": filter_clauses,
                }
            },
            "from": offset,
            "size": limit,
            "sort": [{sort_by: {"order": sort_order}}],
            # Aggregations for facets
            "aggs": {
                "by_sexo": {"terms": {"field": "sexo", "size": 5}},
                "by_decade": {
                    "date_histogram": {
                        "field": "nasc",
                        "calendar_interval": "year",
                        "format": "yyyy",
                        "min_doc_count": 1000,
                    }
                },
            },
        }

        # Execute search
        result = self.es.search(index=self.index_name, body=body)

        # Parse results
        records = []
        for hit in result["hits"]["hits"]:
            source = hit["_source"]
            records.append({
                "cpf": source.get("cpf", ""),
                "nome": source.get("nome", ""),
                "sexo": source.get("sexo", ""),
                "nasc": source.get("nasc"),
            })

        # Parse facets
        facets = {
            "sexo": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_sexo"]["buckets"]
            ],
            "timeline": [
                {"date": b["key_as_string"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_decade"]["buckets"]
            ],
        }

        return {
            "total": result["hits"]["total"]["value"],
            "results": records,
            "facets": facets,
            "took_ms": result["took"],
        }

    def get_by_cpf(self, cpf: str):
        """
        Get a single record by CPF
        """
        clean_cpf = cpf.replace(".", "").replace("-", "").strip()

        try:
            result = self.es.get(index=self.index_name, id=clean_cpf)
            source = result["_source"]
            return {
                "cpf": source.get("cpf", ""),
                "nome": source.get("nome", ""),
                "sexo": source.get("sexo", ""),
                "nasc": source.get("nasc"),
            }
        except Exception:
            return None

    def get_stats(self):
        """
        Get global CPF statistics
        """
        # Total count
        total = self.es.count(index=self.index_name)["count"]

        # Aggregations
        aggs_result = self.es.search(
            index=self.index_name,
            body={
                "size": 0,
                "aggs": {
                    "by_sexo": {"terms": {"field": "sexo", "size": 10}},
                    "by_decade": {
                        "date_histogram": {
                            "field": "nasc",
                            "calendar_interval": "year",
                            "format": "yyyy",
                            "min_doc_count": 100000,
                        }
                    },
                    "age_ranges": {
                        "range": {
                            "field": "nasc",
                            "ranges": [
                                {"key": "0-17", "from": f"{datetime.now().year - 17}-01-01"},
                                {"key": "18-25", "from": f"{datetime.now().year - 25}-01-01", "to": f"{datetime.now().year - 18}-01-01"},
                                {"key": "26-35", "from": f"{datetime.now().year - 35}-01-01", "to": f"{datetime.now().year - 26}-01-01"},
                                {"key": "36-45", "from": f"{datetime.now().year - 45}-01-01", "to": f"{datetime.now().year - 36}-01-01"},
                                {"key": "46-55", "from": f"{datetime.now().year - 55}-01-01", "to": f"{datetime.now().year - 46}-01-01"},
                                {"key": "56-65", "from": f"{datetime.now().year - 65}-01-01", "to": f"{datetime.now().year - 56}-01-01"},
                                {"key": "65+", "to": f"{datetime.now().year - 65}-01-01"},
                            ]
                        }
                    },
                },
            },
        )

        sexo_counts = {
            b["key"]: b["doc_count"]
            for b in aggs_result["aggregations"]["by_sexo"]["buckets"]
        }

        by_decade = [
            {"year": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs_result["aggregations"]["by_decade"]["buckets"]
        ]

        by_age_range = [
            {"range": b["key"], "count": b["doc_count"]}
            for b in aggs_result["aggregations"]["age_ranges"]["buckets"]
        ]

        # Timeline para os últimos anos de nascimento
        timeline = [
            {"date": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs_result["aggregations"]["by_decade"]["buckets"][-50:]
        ]

        return {
            "total_records": total,
            "by_sexo": sexo_counts,
            "by_decade": by_decade,
            "by_age_range": by_age_range,
            "timeline": timeline,
        }
