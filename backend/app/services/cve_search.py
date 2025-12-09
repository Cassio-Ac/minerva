"""
CVE Search Service using Elasticsearch
"""
from datetime import datetime, timedelta
from typing import Optional, List
from elasticsearch import Elasticsearch


class CVESearchService:
    def __init__(self, es_client: Elasticsearch, index_name: str = "cvedetector_v2"):
        self.es = es_client
        self.index_name = index_name

    def search_cves(
        self,
        query: Optional[str] = None,
        sources: Optional[List[str]] = None,
        types: Optional[List[str]] = None,
        severity_levels: Optional[List[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "date",
        sort_order: str = "desc",
    ):
        """
        Search CVEs with filters and facets
        """
        # Build query
        must_clauses = []
        filter_clauses = []

        # Text search
        if query:
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": ["cve_title^3", "cve_content", "cve_id^2"],
                    "type": "best_fields",
                }
            })

        # Filters
        if sources:
            filter_clauses.append({"terms": {"cve_source": sources}})
        if types:
            filter_clauses.append({"terms": {"cve_type": types}})
        if severity_levels:
            filter_clauses.append({"terms": {"cve_severity_level": severity_levels}})
        if date_from:
            filter_clauses.append({"range": {"date": {"gte": date_from.strftime('%Y-%m-%d')}}})
        if date_to:
            filter_clauses.append({"range": {"date": {"lte": date_to.strftime('%Y-%m-%d')}}})

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
                "by_source": {"terms": {"field": "cve_source", "size": 50}},
                "by_type": {"terms": {"field": "cve_type", "size": 20}},
                "by_severity": {"terms": {"field": "cve_severity_level", "size": 10}},
                "by_date": {
                    "date_histogram": {
                        "field": "date",
                        "calendar_interval": "day",
                        "format": "yyyy-MM-dd",
                    }
                },
            },
        }

        # Execute search
        result = self.es.search(index=self.index_name, body=body)

        # Parse results
        cves = []
        for hit in result["hits"]["hits"]:
            source = hit["_source"]
            cves.append({
                "id": source["id"],
                "date": source["date"],
                "cve_id": source["cve_id"],
                "cve_title": source["cve_title"],
                "cve_content": source["cve_content"],
                "cve_source": source["cve_source"],
                "cve_type": source["cve_type"],
                "cve_severity_level": source["cve_severity_level"],
                "cve_severity_score": source["cve_severity_score"],
            })

        # Parse facets
        facets = {
            "sources": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_source"]["buckets"]
            ],
            "types": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_type"]["buckets"]
            ],
            "severity_levels": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_severity"]["buckets"]
            ],
            "timeline": [
                {"date": b["key_as_string"], "count": b["doc_count"]}
                for b in result["aggregations"]["by_date"]["buckets"]
            ],
        }

        return {
            "total": result["hits"]["total"]["value"],
            "cves": cves,
            "facets": facets,
            "took_ms": result["took"],
        }

    def get_stats(self):
        """
        Get global CVE statistics
        """
        now = datetime.now()
        today_start = datetime(now.year, now.month, now.day)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        # Count queries - use date format yyyy-MM-dd only
        total = self.es.count(index=self.index_name)["count"]

        today = self.es.count(
            index=self.index_name,
            body={"query": {"range": {"date": {"gte": today_start.strftime('%Y-%m-%d')}}}},
        )["count"]

        this_week = self.es.count(
            index=self.index_name,
            body={"query": {"range": {"date": {"gte": week_start.strftime('%Y-%m-%d')}}}},
        )["count"]

        this_month = self.es.count(
            index=self.index_name,
            body={"query": {"range": {"date": {"gte": month_start.strftime('%Y-%m-%d')}}}},
        )["count"]

        # Aggregations
        aggs_result = self.es.search(
            index=self.index_name,
            body={
                "size": 0,
                "aggs": {
                    "by_severity": {"terms": {"field": "cve_severity_level", "size": 20}},
                    "by_source": {"terms": {"field": "cve_source", "size": 50}},
                    "timeline": {
                        "date_histogram": {
                            "field": "date",
                            "calendar_interval": "day",
                            "format": "yyyy-MM-dd",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": (now - timedelta(days=30)).strftime('%Y-%m-%d'),
                                "max": now.strftime('%Y-%m-%d'),
                            },
                        }
                    },
                },
            },
        )

        severity_counts = {
            b["key"]: b["doc_count"]
            for b in aggs_result["aggregations"]["by_severity"]["buckets"]
        }

        source_counts = {
            b["key"]: b["doc_count"]
            for b in aggs_result["aggregations"]["by_source"]["buckets"]
        }

        top_sources = [
            {"name": b["key"], "count": b["doc_count"]}
            for b in aggs_result["aggregations"]["by_source"]["buckets"][:10]
        ]

        timeline = [
            {"date": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs_result["aggregations"]["timeline"]["buckets"]
        ]

        return {
            "total_cves": total,
            "cves_today": today,
            "cves_this_week": this_week,
            "cves_this_month": this_month,
            "cves_by_severity": severity_counts,
            "cves_by_source": source_counts,
            "top_sources": top_sources,
            "timeline": timeline,
        }
