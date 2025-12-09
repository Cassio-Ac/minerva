"""
CVE Chat Service with RAG (Retrieval-Augmented Generation)
"""
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from app.schemas.cve import CVEChatRequest, CVEChatResponse
from app.services.llm_service_v2 import LLMServiceV2


class CVEChatService:
    def __init__(
        self,
        es_client: Elasticsearch,
        llm_service: LLMServiceV2,
        index_name: str = "cvedetector_v2",
    ):
        self.es = es_client
        self.llm_service = llm_service
        self.index_name = index_name

    async def chat(self, request: CVEChatRequest) -> CVEChatResponse:
        """
        Chat with CVE data using RAG
        """
        # Search relevant CVEs
        cves = self._search_relevant_cves(
            query=request.query,
            severity_level=request.severity_level,
            source=request.source,
            days=request.days,
            limit=request.max_context,
        )

        if not cves:
            return CVEChatResponse(
                answer="Não encontrei CVEs relevantes para sua consulta. Tente ajustar os filtros ou reformular a pergunta.",
                context_used=0,
            )

        # Build context from CVEs
        context = self._build_context(cves)

        # Generate LLM response
        system_prompt = """Você é um assistente especializado em segurança da informação e vulnerabilidades (CVEs).

Sua função é analisar e responder perguntas sobre vulnerabilidades de software com base nos dados de CVE fornecidos.

Diretrizes:
- Seja preciso e técnico nas suas respostas
- Sempre cite os CVE-IDs relevantes (ex: CVE-2024-1234)
- Mencione níveis de severidade (CRITICAL, HIGH, MEDIUM, LOW)
- Explique o impacto e riscos quando relevante
- Se houver múltiplas vulnerabilidades similares, resuma os padrões comuns
- Forneça recomendações práticas quando apropriado
- Responda em português brasileiro
"""

        user_prompt = f"""Contexto de CVEs relevantes:

{context}

Pergunta do usuário: {request.query}

Por favor, analise os CVEs acima e responda a pergunta do usuário de forma clara e objetiva."""

        answer = await self.llm_service.generate_completion(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3,
        )

        return CVEChatResponse(
            answer=answer,
            context_used=len(cves),
        )

    def _search_relevant_cves(
        self,
        query: str,
        severity_level: str = None,
        source: str = None,
        days: int = 30,
        limit: int = 10,
    ):
        """
        Search for relevant CVEs using Elasticsearch
        """
        # Build query
        must_clauses = [
            {
                "multi_match": {
                    "query": query,
                    "fields": ["cve_title^3", "cve_content", "cve_id^2"],
                    "type": "best_fields",
                }
            }
        ]

        filter_clauses = []

        # Date filter
        date_from = datetime.now() - timedelta(days=days)
        filter_clauses.append({"range": {"date": {"gte": date_from.isoformat()}}})

        # Severity filter
        if severity_level:
            filter_clauses.append({"term": {"cve_severity_level": severity_level}})

        # Source filter
        if source:
            filter_clauses.append({"term": {"cve_source": source}})

        # Search
        result = self.es.search(
            index=self.index_name,
            body={
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "filter": filter_clauses,
                    }
                },
                "size": limit,
                "sort": [{"date": {"order": "desc"}}],
            },
        )

        # Parse results
        cves = []
        for hit in result["hits"]["hits"]:
            source = hit["_source"]
            cves.append(
                {
                    "cve_id": source["cve_id"],
                    "cve_title": source["cve_title"],
                    "cve_content": source["cve_content"],
                    "cve_severity_level": source["cve_severity_level"],
                    "cve_severity_score": source["cve_severity_score"],
                    "cve_source": source["cve_source"],
                    "date": source["date"],
                }
            )

        return cves

    def _build_context(self, cves):
        """
        Build context string from CVEs for LLM
        """
        context_parts = []

        for i, cve in enumerate(cves, 1):
            context_parts.append(
                f"""--- CVE #{i} ---
CVE ID: {cve['cve_id']}
Título: {cve['cve_title']}
Severidade: {cve['cve_severity_level']} (Score: {cve['cve_severity_score']})
Fonte: {cve['cve_source']}
Data: {cve['date']}
Descrição: {cve['cve_content'][:500]}...
"""
            )

        return "\n\n".join(context_parts)
