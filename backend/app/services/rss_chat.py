"""
RSS Chat Service with RAG - Conversational Version
Chat interface for querying RSS articles using LLM with context retrieval
Now with conversation history and Elasticsearch mapping knowledge
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from elasticsearch import Elasticsearch

from app.services.rss_elasticsearch import RSSElasticsearchService
from app.schemas.rss import RSSArticle, RSSChatRequest, RSSChatResponse, ChatMessage

logger = logging.getLogger(__name__)


class RSSChatService:
    """
    RSS Chat Service with RAG (Retrieval Augmented Generation)
    Conversational AI that knows about RSS article structure and can help users explore news
    """

    def __init__(self, es_client: Elasticsearch, llm_service, index_alias: str = "rss-articles"):
        self.es_service = RSSElasticsearchService(es_client, index_alias)
        self.llm_service = llm_service
        self.index_alias = index_alias

    async def chat(self, request: RSSChatRequest) -> RSSChatResponse:
        """
        Answer user question using conversational RAG over RSS articles

        Args:
            request: Chat request with query, filters, and conversation history

        Returns:
            Chat response with answer and sources
        """
        logger.info(f"💬 RSS Chat query: {request.query[:100]}...")

        # Ensure LLM client is initialized
        if not self.llm_service.llm_client:
            logger.error("❌ LLM client not initialized")
            return RSSChatResponse(
                answer="Erro: LLM não configurado. Configure um provider LLM nas configurações.",
                sources=[],
                query=request.query,
                context_used=0,
                model_used="none",
            )

        # Step 1: Get Elasticsearch mapping knowledge base
        knowledge_base = await self._get_knowledge_base()

        # Step 2: Build system prompt with index knowledge
        system_prompt = self._build_system_prompt(knowledge_base)

        # Step 3: Build conversation messages
        messages = self._build_messages(request)

        # Step 4: Call LLM to understand user intent and search
        try:
            # First LLM call: understand intent and potentially search
            llm_response = await self.llm_service.llm_client.generate(
                messages=messages,
                system=system_prompt,
                max_tokens=2000,
                temperature=0.7,
            )

            answer_text = llm_response.get('response', llm_response.get('content', ''))

            # Step 5: Check if we should search for articles
            # Search if: user asked for specific information, news, or articles
            should_search = self._should_search_articles(request.query, request.context)

            sources = []
            if should_search:
                logger.info("🔍 Searching for relevant articles...")
                articles = await self._retrieve_relevant_articles(request)

                if articles:
                    sources = articles
                    # Build enhanced prompt with article context
                    enhanced_messages = messages + [
                        {"role": "assistant", "content": answer_text},
                        {"role": "user", "content": self._format_articles_for_llm(articles)}
                    ]

                    # Second LLM call with article context
                    enhanced_response = await self.llm_service.llm_client.generate(
                        messages=enhanced_messages,
                        system=system_prompt,
                        max_tokens=2000,
                        temperature=0.7,
                    )

                    answer_text = enhanced_response.get('response', enhanced_response.get('content', ''))

            # Get model info
            provider_info = self.llm_service.llm_client.get_provider_info()
            model_used = provider_info.get('model', provider_info.get('model_name', 'unknown'))

            return RSSChatResponse(
                answer=answer_text,
                sources=sources,
                query=request.query,
                context_used=len(sources),
                model_used=model_used,
            )

        except Exception as e:
            logger.error(f"❌ LLM generation error: {e}")
            return RSSChatResponse(
                answer=f"Erro ao gerar resposta: {str(e)}",
                sources=[],
                query=request.query,
                context_used=0,
                model_used="error",
            )

    def _should_search_articles(self, query: str, context: Optional[List[ChatMessage]]) -> bool:
        """
        Determine if we should search for articles based on query

        Args:
            query: User query
            context: Conversation history

        Returns:
            True if should search articles
        """
        # Keywords that indicate user wants articles/news
        search_keywords = [
            'notícia', 'noticia', 'news', 'artigo', 'article',
            'quais', 'what', 'mostre', 'show', 'liste', 'list',
            'encontre', 'find', 'busque', 'search', 'procure',
            'principais', 'main', 'recente', 'recent', 'último', 'last',
            'sobre', 'about', 'acerca',
        ]

        query_lower = query.lower()
        return any(kw in query_lower for kw in search_keywords)

    async def _get_knowledge_base(self) -> str:
        """
        Get Elasticsearch mapping knowledge base for RSS articles index

        Returns:
            Formatted knowledge base string
        """
        try:
            # Get ES mapping
            mapping_info = self.es_service.es.indices.get_mapping(index=self.index_alias)

            # Extract properties
            index_name = list(mapping_info.keys())[0]
            properties = mapping_info[index_name]['mappings']['properties']

            # Build knowledge base
            kb = "# Estrutura do Índice RSS Articles\n\n"
            kb += "O índice 'rss-articles' contém artigos de fontes RSS com os seguintes campos:\n\n"

            # Group by type
            text_fields = []
            keyword_fields = []
            date_fields = []
            other_fields = []

            for field, config in properties.items():
                field_type = config.get('type', 'unknown')
                if field_type == 'text':
                    text_fields.append(field)
                elif field_type == 'keyword':
                    keyword_fields.append(field)
                elif field_type == 'date':
                    date_fields.append(field)
                else:
                    other_fields.append((field, field_type))

            if text_fields:
                kb += "**Campos de texto (pesquisáveis):**\n"
                kb += ", ".join(f"`{f}`" for f in text_fields) + "\n\n"

            if keyword_fields:
                kb += "**Campos categóricos (para filtros):**\n"
                kb += ", ".join(f"`{f}`" for f in keyword_fields) + "\n\n"

            if date_fields:
                kb += "**Campos de data:**\n"
                kb += ", ".join(f"`{f}`" for f in date_fields) + "\n\n"

            kb += "\n**Campos principais:**\n"
            kb += "- `title`: Título do artigo (text)\n"
            kb += "- `summary`: Resumo do artigo (text)\n"
            kb += "- `link`: URL do artigo (keyword)\n"
            kb += "- `published`: Data de publicação (date)\n"
            kb += "- `feed_name`: Nome da fonte RSS (keyword)\n"
            kb += "- `category`: Categoria da notícia (keyword)\n"
            kb += "- `tags`: Tags do artigo (keyword array)\n"
            kb += "- `author`: Autor do artigo (keyword)\n"

            return kb

        except Exception as e:
            logger.warning(f"⚠️ Could not get ES mapping: {e}")
            return "Índice RSS articles com artigos de fontes RSS."

    def _build_system_prompt(self, knowledge_base: str) -> str:
        """
        Build system prompt with index knowledge

        Args:
            knowledge_base: Elasticsearch mapping knowledge

        Returns:
            System prompt
        """
        prompt = f"""Você é um assistente de inteligência especializado em análise de notícias de segurança cibernética, tecnologia e inteligência artificial.

{knowledge_base}

Você tem acesso a artigos RSS coletados de diversas fontes confiáveis nas áreas de:
- Inteligência Artificial (OpenAI, Google, Hugging Face, NVIDIA, MIT, arXiv)
- Segurança da Informação (The Hacker News, Krebs, BleepingComputer, Schneier, SANS, etc.)
- Inteligência de Ameaças (CISA, NVD, abuse.ch, Malpedia)
- Threat Intelligence (Palo Alto Unit 42, Cisco Talos, Microsoft MSRC, CrowdStrike, etc.)

## Suas Capacidades:

1. **Conversação Natural**: Você pode conversar naturalmente com o usuário sobre notícias e tendências.

2. **Busca Contextual**: Quando o usuário perguntar sobre notícias específicas, você pode buscar e analisar artigos relevantes.

3. **Análise e Insights**: Você pode identificar padrões, tendências e fornecer análises aprofundadas.

4. **Recomendações**: Você pode sugerir artigos relacionados e tópicos de interesse.

## Diretrizes:

- Seja conversacional e amigável, mas profissional
- Cite as fontes quando usar informações específicas de artigos
- Se não tiver informação nos artigos, diga claramente
- Ofereça explorar tópicos relacionados quando relevante
- Use markdown para formatação (títulos, listas, negrito)
- Responda SEMPRE em português brasileiro
- Quando mostrar múltiplas informações, estruture com títulos e listas
- Seja proativo em sugerir buscas ou análises adicionais

Se o usuário não especificar datas, assuma notícias recentes (última semana).
"""
        return prompt

    def _build_messages(self, request: RSSChatRequest) -> List[Dict[str, str]]:
        """
        Build conversation messages for LLM

        Args:
            request: Chat request

        Returns:
            List of message dicts
        """
        messages = []

        # Add conversation history
        if request.context:
            for msg in request.context[-5:]:  # Last 5 messages for context
                messages.append({
                    "role": msg.role,
                    "content": msg.content
                })

        # Add current query
        messages.append({
            "role": "user",
            "content": request.query
        })

        return messages

    def _format_articles_for_llm(self, articles: List[RSSArticle]) -> str:
        """
        Format articles as additional context for LLM

        Args:
            articles: Retrieved articles

        Returns:
            Formatted string
        """
        context = "Com base nos artigos abaixo, forneça uma resposta mais detalhada e precisa:\n\n"

        for i, article in enumerate(articles, 1):
            date_str = article.published.strftime("%d/%m/%Y")
            context += f"**Artigo {i}**\n"
            context += f"- Título: {article.title}\n"
            context += f"- Fonte: {article.feed_name} ({article.category})\n"
            context += f"- Data: {date_str}\n"
            context += f"- Resumo: {article.summary[:300]}...\n"
            context += f"- Link: {article.link}\n\n"

        return context

    async def _retrieve_relevant_articles(self, request: RSSChatRequest) -> List[RSSArticle]:
        """
        Retrieve relevant articles from Elasticsearch based on query and filters

        Args:
            request: Chat request

        Returns:
            List of relevant articles
        """
        try:
            # Search with user query and filters
            import asyncio
            result = await asyncio.to_thread(
                self.es_service.search_articles,
                query=request.query,
                categories=request.categories,
                date_from=request.date_from,
                date_to=request.date_to,
                limit=request.max_context_articles,
                offset=0,
                sort_by="published",
                sort_order="desc",
            )

            # Convert to RSSArticle objects
            articles = []
            for art_dict in result.get('articles', []):
                try:
                    article = RSSArticle(
                        content_hash=art_dict.get('content_hash', ''),
                        title=art_dict.get('title', ''),
                        link=art_dict.get('link', ''),
                        published=datetime.fromisoformat(art_dict['published'].replace('Z', '+00:00')),
                        summary=art_dict.get('summary', ''),
                        author=art_dict.get('author'),
                        tags=art_dict.get('tags', []),
                        feed_name=art_dict.get('feed_name', ''),
                        category=art_dict.get('category', ''),
                        feed_title=art_dict.get('feed_title'),
                        feed_description=art_dict.get('feed_description'),
                        feed_link=art_dict.get('feed_link'),
                        feed_updated=art_dict.get('feed_updated'),
                        collected_at=datetime.fromisoformat(art_dict['collected_at'].replace('Z', '+00:00')),
                        source_type=art_dict.get('source_type', 'rss_feed'),
                        sentiment=art_dict.get('sentiment'),
                        entities=art_dict.get('entities'),
                        keywords=art_dict.get('keywords'),
                    )
                    articles.append(article)
                except Exception as e:
                    logger.warning(f"⚠️ Error parsing article: {e}")
                    continue

            logger.info(f"📚 Retrieved {len(articles)} relevant articles")
            return articles

        except Exception as e:
            logger.error(f"❌ Error retrieving articles: {e}")
            return []
