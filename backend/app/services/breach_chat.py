"""
Breach Chat Service with RAG
Chat about data breaches using retrieval augmented generation
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from elasticsearch import Elasticsearch

from app.schemas.breach import BreachChatRequest, BreachChatResponse, BreachEntry

logger = logging.getLogger(__name__)


class BreachChatService:
    """Chat service for breach data using RAG"""

    def __init__(self, es_client: Elasticsearch, llm_service, index_name: str = "breachdetect_v3"):
        self.es = es_client
        self.llm_service = llm_service
        self.index_name = index_name

    async def chat(self, request: BreachChatRequest) -> BreachChatResponse:
        """
        Answer questions about breaches using RAG

        1. Retrieve relevant breaches from Elasticsearch
        2. Format as context
        3. Generate answer using LLM
        """
        logger.info(f"💬 Breach chat: {request.query[:50]}...")

        # Build search query
        must_clauses = [{
            "multi_match": {
                "query": request.query,
                "fields": ["breach_content^3", "breach_author^2", "breach_source"],
                "type": "best_fields"
            }
        }]

        filter_clauses = []

        # Date filter
        date_from = datetime.now(timezone.utc) - timedelta(days=request.days)
        filter_clauses.append({
            "range": {"date": {"gte": date_from.isoformat()}}
        })

        # Type filter
        if request.breach_type:
            filter_clauses.append({"term": {"breach_type": request.breach_type}})

        # Source filter
        if request.source:
            filter_clauses.append({"term": {"breach_source.keyword": request.source}})

        # Execute search
        search_body = {
            "query": {
                "bool": {
                    "must": must_clauses,
                    "filter": filter_clauses
                }
            },
            "size": request.max_context,
            "sort": [{"date": {"order": "desc"}}]
        }

        try:
            response = self.es.search(index=self.index_name, body=search_body)
            hits = response["hits"]["hits"]

            # Parse breaches
            breaches = [BreachEntry(**hit["_source"]) for hit in hits]

            if not breaches:
                return BreachChatResponse(
                    answer="Não encontrei vazamentos de dados relevantes para sua pergunta nos últimos {} dias.".format(request.days),
                    context_used=0,
                    sources=[],
                    query=request.query
                )

            # Build context for LLM
            context = self._build_context(breaches)

            # Generate answer
            system_prompt = """Você é um assistente especializado em segurança da informação e vazamentos de dados.
Analise os vazamentos de dados fornecidos e responda à pergunta do usuário de forma clara e objetiva.
Cite fontes quando relevante e mantenha o foco em informações de inteligência de ameaças."""

            user_prompt = f"""Baseado nos seguintes vazamentos de dados recentes:

{context}

Pergunta do usuário: {request.query}

Responda de forma clara e objetiva, citando os vazamentos relevantes."""

            answer = await self.llm_service.generate_completion(
                prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=0.3,
                max_tokens=1000
            )

            logger.info(f"✅ Generated answer: {len(answer)} chars from {len(breaches)} breaches")

            return BreachChatResponse(
                answer=answer,
                context_used=len(breaches),
                sources=breaches,
                query=request.query
            )

        except Exception as e:
            logger.error(f"❌ Breach chat error: {e}")
            raise

    def _build_context(self, breaches: list[BreachEntry]) -> str:
        """Build context string from breaches"""
        context_parts = []

        for i, breach in enumerate(breaches, 1):
            date_str = breach.date.strftime("%d/%m/%Y %H:%M")
            author = breach.breach_author if breach.breach_author else "Desconhecido"

            context_parts.append(
                f"[{i}] {date_str}\n"
                f"Fonte: {breach.breach_source}\n"
                f"Tipo: {breach.breach_type}\n"
                f"Autor: {author}\n"
                f"Conteúdo: {breach.breach_content}\n"
            )

        return "\n".join(context_parts)
