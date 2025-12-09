"""
LLM Service
Processa mensagens do usuário com LLM (Claude via Databricks)
"""

from typing import Optional, Dict, Any, List
import logging
import json
import os

logger = logging.getLogger(__name__)


class LLMService:
    """Service para processamento com LLM"""

    def __init__(self, use_real_llm: bool = True):
        """
        Inicializa o service

        Args:
            use_real_llm: Se True, tenta usar Databricks. Se False ou falhar, usa mock.
        """
        self.llm_client = None
        self.llm_available = False

        if use_real_llm:
            try:
                self._initialize_databricks()
            except Exception as e:
                logger.warning(f"⚠️ Could not initialize Databricks LLM: {e}")
                logger.info("📝 Falling back to mock responses")

    def _initialize_databricks(self):
        """Inicializa cliente Databricks"""
        from app.core.config import settings

        databricks_url = settings.DATABRICKS_URL or settings.DATABRICKS_HOST
        databricks_token = settings.DATABRICKS_TOKEN
        model_name = settings.DATABRICKS_MODEL or settings.LLM_MODEL

        if not databricks_url or not databricks_token:
            raise ValueError("DATABRICKS_URL and DATABRICKS_TOKEN must be set in .env")

        from app.services.databricks_client import DatabricksChatClient

        self.llm_client = DatabricksChatClient(
            databricks_url=databricks_url,
            databricks_token=databricks_token,
            model_name=model_name,
            temperature=settings.LLM_TEMPERATURE,
            max_tokens=settings.LLM_MAX_TOKENS
        )

        self.llm_available = True
        logger.info(f"✅ Databricks LLM initialized: {model_name}")


    async def process_message(
        self,
        message: str,
        index: str,
        server_id: Optional[str] = None,
        time_range: Optional[Dict] = None,
        context: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Processa mensagem do usuário e retorna widget spec

        Args:
            message: Mensagem do usuário
            index: Índice Elasticsearch
            server_id: ID do servidor ES (opcional)
            time_range: Período temporal para filtro (opcional)
            context: Histórico de mensagens (opcional)

        Returns:
            {
                "explanation": str,
                "visualization_type": str,
                "query": dict,
                "needs_clarification": bool,
                "widget": dict
            }
        """
        logger.info(
            f"Processing message: {message} (index: {index}, "
            f"server: {server_id or 'default'}, time_range: {time_range}, "
            f"llm_available: {self.llm_available})"
        )

        # SEMPRE usa LLM real quando disponível (para todas as mensagens)
        if self.llm_available and self.llm_client:
            try:
                logger.info("🎯 Using Databricks LLM for all message processing")
                return await self._process_with_real_llm(message, index, server_id, time_range, context)
            except Exception as e:
                logger.error(f"❌ Error with real LLM, falling back to mock: {e}")
                # Continua para processamento mock em caso de erro

        # Fallback: processamento mock (só se LLM não disponível ou falhar)
        logger.warning("📝 Using mock processing (LLM not available or failed)")
        message_lower = message.lower()

        # Primeiro, detectar se é uma mensagem conversacional (não precisa de widget)
        if self._is_conversational(message_lower):
            response = self._generate_conversational_response(message_lower)
            return {
                "explanation": response,
                "visualization_type": None,
                "query": None,
                "needs_clarification": False,
                "widget": None
            }

        # Detectar se é uma pergunta geral (não sobre visualização)
        if self._is_general_question(message_lower):
            response = self._answer_general_question(message_lower)
            return {
                "explanation": response,
                "visualization_type": None,
                "query": None,
                "needs_clarification": False,
                "widget": None
            }

        # Detectar se realmente quer uma visualização
        if not self._wants_visualization(message_lower):
            return {
                "explanation": "Posso ajudar com visualizações de dados! Me diga o que você gostaria de ver:\n\n• Gráfico de pizza para distribuições\n• Gráfico de barras para comparações\n• Gráfico de linhas para tendências\n• Métrica para valores únicos\n\nExemplo: 'mostre um gráfico de pizza' ou 'quero ver o total'",
                "visualization_type": None,
                "query": None,
                "needs_clarification": True,
                "widget": None
            }

        # Detectar tipo de visualização
        viz_type = self._detect_visualization_type(message_lower)

        # Gerar query mock
        query = self._generate_mock_query(message_lower, viz_type)

        # Gerar dados mock
        widget_data = self._generate_mock_data(viz_type)

        result = {
            "explanation": f"Criei uma visualização do tipo {viz_type} para mostrar {message}",
            "visualization_type": viz_type,
            "query": query,
            "needs_clarification": False,
            "widget": {
                "title": self._generate_title(message),
                "type": viz_type,
                "data": {
                    "query": query,
                    "results": {},
                    "config": widget_data
                }
            }
        }

        logger.info(f"✅ Generated {viz_type} visualization")
        return result

    async def _process_with_real_llm(
        self,
        message: str,
        index: str,
        server_id: Optional[str] = None,
        time_range: Optional[Dict] = None,
        context: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Processa mensagem usando Databricks LLM real

        Args:
            message: Mensagem do usuário
            index: Índice Elasticsearch
            server_id: ID do servidor ES (opcional)
            time_range: Período temporal para filtro (opcional)
            context: Histórico de mensagens

        Returns:
            Dicionário com resposta processada
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        # Gerar base de conhecimento completa do índice
        from app.services.index_mapping_service import get_mapping_service
        mapping_service = get_mapping_service()
        knowledge_base = await mapping_service.generate_knowledge_base(index)

        # Build system prompt
        from datetime import datetime
        now = datetime.now()
        data_hoje = now.strftime("%d/%m/%Y")
        dia_semana = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"][now.weekday()]
        hora_atual = now.strftime("%H:%M")

        # Formatar time_range se fornecido
        time_range_info = ""
        if time_range:
            time_range_dict = time_range if isinstance(time_range, dict) else time_range.dict()
            time_range_info = f"""
**PERÍODO TEMPORAL SELECIONADO:**
- Tipo: {time_range_dict.get('type', 'preset')}
- Período: {time_range_dict.get('label', 'Não definido')}
- De: {time_range_dict.get('from') or time_range_dict.get('from_', 'now-30d')}
- Até: {time_range_dict.get('to', 'now')}

**⚠️ CRÍTICO - FILTRO TEMPORAL OBRIGATÓRIO:**
- TODA query DEVE incluir filtro temporal em um campo DATE
- Escolha o campo DATE mais apropriado da base de conhecimento acima
- Use EXATAMENTE estes valores:
  - gte: {time_range_dict.get('from') or time_range_dict.get('from_', 'now-30d')}
  - lte: {time_range_dict.get('to', 'now')}

**Como escolher o campo de data:**
- Procure na base de conhecimento por campos tipo DATE
- Use o campo mais relevante (ex: @timestamp, data_criacao, scan_date, etc)
- Se o índice não tiver campo de data, NÃO adicione o filtro temporal

**Estrutura OBRIGATÓRIA da query (se houver campo DATE):**
{{
  "size": 0,
  "query": {{
    "bool": {{
      "filter": [
        {{
          "range": {{
            "CAMPO_DATE_AQUI": {{
              "gte": "{time_range_dict.get('from') or time_range_dict.get('from_', 'now-30d')}",
              "lte": "{time_range_dict.get('to', 'now')}"
            }}
          }}
        }}
      ]
    }}
  }},
  "aggs": {{ ... suas agregações aqui ... }}
}}

IMPORTANTE: Substitua "CAMPO_DATE_AQUI" pelo campo DATE real do índice!
"""
        else:
            time_range_info = """
**PERÍODO TEMPORAL:**
- Nenhum período específico selecionado
- Use "now-30d" a "now" como padrão se precisar filtrar por data
"""

        system_prompt = f"""Você é Claude (Sonnet 4.5), um assistente conversacional especializado em análise de dados do Elasticsearch.

**CONTEXTO ATUAL:**
- Data de hoje: {dia_semana}-feira, {data_hoje}
- Hora atual: {hora_atual}
- Índice Elasticsearch em uso: **{index}**
{time_range_info}
**BASE DE CONHECIMENTO DO ÍNDICE:**
{knowledge_base}

**SUA PERSONALIDADE:**
- Seja conversacional, amigável e natural
- Responda perguntas gerais (data, hora, saudações, dúvidas)
- Use emojis ocasionalmente para dar personalidade
- Seja proativo e ofereça ajuda

**SUAS CAPACIDADES:**
1. **Conversar naturalmente** sobre qualquer assunto
2. **Responder perguntas** sobre data, hora, seus recursos
3. **Criar visualizações de dados** do Elasticsearch quando solicitado
4. **Explicar** como funciona a análise de dados

**IMPORTANTE:**
- Para saudações, perguntas gerais ou conversas, responda naturalmente SEM criar visualizações
- Só crie visualizações quando o usuário explicitamente pedir para ver/mostrar/criar gráficos ou dados

Para pedidos de visualização, retorne JSON no formato:
{{
    "needs_visualization": true,
    "visualization_type": "pie" | "bar" | "line" | "metric",
    "title": "Título Profissional do Widget",
    "query": {{ ... elasticsearch query ... }},
    "explanation": "Explicação em português do que foi criado"
}}

**REGRAS PARA TÍTULOS DOS WIDGETS:**
- Crie títulos PROFISSIONAIS, CONCISOS e DESCRITIVOS
- Use português formal e claro
- Evite artigos no início ("o", "a", "os", "as")
- Exemplos CORRETOS:
  * "Distribuição por Categoria"
  * "Top 10 Domínios Mais Acessados"
  * "Evolução Temporal de Acessos"
  * "Total de Vulnerabilidades"
  * "Vulnerabilidades por Severidade"
- Exemplos INCORRETOS:
  * "mostre um gráfico de pizza" ❌
  * "gráfico com categorias" ❌
  * "total" ❌ (muito genérico)

Para perguntas gerais, retorne JSON:
{{
    "needs_visualization": false,
    "explanation": "Sua resposta aqui"
}}

**Tipos de visualização disponíveis:**
- **pie**: Gráficos de pizza para distribuições percentuais
- **bar**: Gráficos de barras para comparações entre categorias
- **line**: Gráficos de linhas para tendências temporais
- **area**: Gráficos de área para volumes ao longo do tempo
- **metric**: Métrica única (contagem total, soma, etc)
- **table**: Tabela para visualizar dados detalhados em formato tabular
- **scatter**: Gráfico de dispersão para correlações

**Exemplos de queries Elasticsearch COM FILTRO TEMPORAL:**
(Use o campo DATE apropriado do índice, não necessariamente @timestamp)

1. Total de documentos (metric) - COM FILTRO TEMPORAL:
{{
  "query": {{
    "bool": {{
      "filter": [
        {{"range": {{"<campo_date_do_indice>": {{"gte": "now-30d", "lte": "now"}}}}}}
      ]
    }}
  }}
}}

2. Distribuição por campo (pie/bar) - COM FILTRO TEMPORAL:
{{
  "size": 0,
  "query": {{
    "bool": {{
      "filter": [
        {{"range": {{"<campo_date_do_indice>": {{"gte": "now-7d", "lte": "now"}}}}}}
      ]
    }}
  }},
  "aggs": {{"result": {{"terms": {{"field": "campo.keyword", "size": 10}}}}}}
}}

3. Histograma temporal (line/area) - COM FILTRO TEMPORAL:
{{
  "size": 0,
  "query": {{
    "bool": {{
      "filter": [
        {{"range": {{"<campo_date_do_indice>": {{"gte": "now-30d", "lte": "now"}}}}}}
      ]
    }}
  }},
  "aggs": {{"result": {{"date_histogram": {{"field": "<campo_date_do_indice>", "calendar_interval": "day"}}}}}}
}}

4. Tabela com documentos (table) - COM FILTRO TEMPORAL:
{{
  "size": 10,
  "query": {{
    "bool": {{
      "filter": [
        {{"range": {{"<campo_date_do_indice>": {{"gte": "now-24h", "lte": "now"}}}}}}
      ]
    }}
  }}
}}

**IMPORTANTE - REGRAS PARA CRIAÇÃO DE QUERIES:**
- ⚠️ **FILTRO TEMPORAL É OBRIGATÓRIO**: Toda query DEVE ter filtro no campo DATE apropriado usando os valores fornecidos
- **USE APENAS OS CAMPOS** listados na base de conhecimento acima
- **RESPEITE A AGREGABILIDADE**: Use apenas campos marcados com ✓ AGREGÁVEL para agregações
- **CAMPOS TEXT**: Para campos text, siga as instruções 💡 (geralmente usar .keyword)
- **CAMPOS KEYWORD**: Use diretamente para agregações (já são keyword)
- **CAMPOS DATE**: Use para date_histogram com calendar_interval adequado
- **CAMPOS NUMÉRICOS**: Use para métricas (sum, avg, min, max, stats)
- SEMPRE use "result" como nome da agregação principal
- Retorne APENAS o JSON, sem markdown
- Seja conversacional e amigável"""

        # Adicionar contexto se houver
        if context and len(context) > 0:
            context_str = "\n\n**Histórico recente:**\n"
            for msg in context[-3:]:  # Últimas 3 mensagens
                # Suporta tanto dict quanto objeto Pydantic
                if isinstance(msg, dict):
                    role = "Usuário" if msg.get("role") == "user" else "Assistente"
                    content = msg.get("content", "")
                else:
                    # Objeto Pydantic ChatMessage
                    role = "Usuário" if msg.role == "user" else "Assistente"
                    content = msg.content
                context_str += f"- {role}: {content}\n"
            system_prompt += context_str

        # Chamar LLM
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=message)
        ]

        logger.info("🤖 Calling Databricks LLM...")
        response = self.llm_client.invoke(messages)
        content = response.content.strip()

        logger.info(f"📥 LLM Response ({len(content)} chars)")

        # Parse JSON response
        result = self._parse_llm_json_response(content)

        # Converter para formato esperado
        if result.get("needs_visualization"):
            viz_type = result.get("visualization_type", "pie")
            query = result.get("query", {})

            # Executar query no Elasticsearch para obter dados reais
            widget_data = {}
            try:
                from app.services.elasticsearch_service import get_es_service
                es_service = get_es_service()

                logger.info(f"🔍 Executing ES query to get real data...")
                es_results = await es_service.execute_query(index, query)

                # Formatar dados para o widget
                widget_data = {
                    "data": es_results.get("data", [])
                }

                logger.info(f"✅ Got {len(es_results.get('data', []))} data points from ES")

            except Exception as e:
                logger.error(f"❌ Error executing ES query: {e}")
                # Em caso de erro, usar dados vazios
                widget_data = {"data": []}

            # Usar título da LLM se disponível, senão gerar
            widget_title = result.get("title") or self._generate_title(message)

            return {
                "explanation": result.get("explanation", "Visualização criada"),
                "visualization_type": viz_type,
                "query": query,
                "needs_clarification": False,
                "widget": {
                    "title": widget_title,
                    "type": viz_type,
                    "data": {
                        "query": query,
                        "results": es_results if 'es_results' in locals() else {},
                        "config": widget_data
                    }
                }
            }
        else:
            # Resposta conversacional
            return {
                "explanation": result.get("explanation", ""),
                "visualization_type": None,
                "query": None,
                "needs_clarification": False,
                "widget": None
            }

    def _parse_llm_json_response(self, content: str) -> Dict[str, Any]:
        """
        Parse da resposta JSON do LLM

        Args:
            content: Resposta do LLM

        Returns:
            Dicionário parseado
        """
        import re

        # Remove markdown code blocks se houver
        if "```json" in content:
            content = re.sub(r'```json\s*', '', content)
            content = re.sub(r'```\s*$', '', content)
        elif "```" in content:
            content = re.sub(r'```\s*', '', content)

        content = content.strip()

        # Procura por JSON
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON parse error: {e}")
                logger.error(f"Content: {json_str[:200]}...")

        # Se não conseguiu parsear, retorna resposta conversacional
        return {
            "needs_visualization": False,
            "explanation": content
        }

    async def _get_index_fields(self, index: str) -> str:
        """
        Busca os campos disponíveis no índice Elasticsearch

        Args:
            index: Nome do índice

        Returns:
            String formatada com os campos
        """
        try:
            from app.services.elasticsearch_service import get_es_service
            es_service = get_es_service()

            mapping = await es_service.get_index_mapping(index)

            # Extrair campos do mapping
            fields = []
            if index in mapping:
                properties = mapping[index].get("mappings", {}).get("properties", {})

                for field_name, field_props in properties.items():
                    field_type = field_props.get("type", "unknown")
                    fields.append(f"- **{field_name}** ({field_type})")

            if fields:
                return "\n".join(fields)
            else:
                return "Nenhum campo encontrado (índice vazio ou sem mapping)"

        except Exception as e:
            logger.warning(f"Could not fetch index mapping: {e}")
            return "Campos não disponíveis (use nomes comuns como 'source', 'type', etc)"

    def _is_conversational(self, message: str) -> bool:
        """Detecta se é uma mensagem conversacional (saudação, agradecimento, etc)"""
        conversational_patterns = [
            # Saudações (palavra completa ou no início)
            (r'\boi\b', r'^oi\s'),
            (r'\bolá\b', r'^olá\s', r'\bola\b', r'^ola\s'),
            (r'\bhey\b', r'\bhi\b', r'\bhello\b'),
            # Agradecimentos
            (r'\bobrigad[oa]\b', r'\bvaleu\b', r'\bthanks\b', r'\bthank you\b'),
            # Despedidas
            (r'\btchau\b', r'\baté logo\b', r'\baté mais\b', r'\bbye\b', r'\bgoodbye\b'),
            # Perguntas gerais
            (r'\btudo bem\b', r'\bcomo vai\b', r'\be ai\b', r'\be aí\b'),
            # Confirmações simples (apenas palavra sozinha)
            (r'^\s*ok\s*$', r'^\s*beleza\s*$', r'^\s*legal\s*$', r'^\s*show\s*$', r'^\s*boa\s*$')
        ]

        import re

        # Verificar se a mensagem é muito curta (até 3 palavras)
        if len(message.split()) <= 3:
            for patterns in conversational_patterns:
                for pattern in patterns if isinstance(patterns, tuple) else (patterns,):
                    if re.search(pattern, message, re.IGNORECASE):
                        return True

        return False

    def _generate_conversational_response(self, message: str) -> str:
        """Gera resposta conversacional apropriada"""
        # Saudações
        if any(word in message for word in ["oi", "olá", "ola", "hey", "hi", "hello"]):
            return "Olá! Como posso ajudar você a visualizar seus dados? Você pode me pedir para criar gráficos de pizza, barras, linhas ou mostrar métricas. 😊"

        # Agradecimentos
        if any(word in message for word in ["obrigado", "obrigada", "valeu", "thanks"]):
            return "De nada! Estou aqui para ajudar com suas visualizações. Precisa de mais alguma coisa?"

        # Despedidas
        if any(word in message for word in ["tchau", "até logo", "até mais", "bye"]):
            return "Até logo! Volte sempre que precisar criar visualizações! 👋"

        # Perguntas sobre estado
        if any(word in message for word in ["tudo bem", "como vai"]):
            return "Tudo ótimo! Pronto para criar visualizações incríveis para você. O que gostaria de ver?"

        # Confirmações
        if any(word in message for word in ["ok", "beleza", "legal", "show", "boa"]):
            return "Ótimo! Se precisar de mais alguma visualização, é só pedir!"

        # Default
        return "Estou aqui para ajudar! Me diga o que você gostaria de visualizar."

    def _is_general_question(self, message: str) -> bool:
        """Detecta se é uma pergunta geral (não sobre visualização)"""
        import re

        general_patterns = [
            # Perguntas sobre data/hora
            r'\b(que|qual).*\b(dia|data)\b',
            r'\b(que|qual).*\bhora[s]?\b',
            r'\bhora[s]?\s+(são|sao|é|e)\b',
            r'\bhoje\b', r'\bhj\b', r'\bagora\b',
            # Perguntas sobre o assistente
            r'\b(quem|o que|que).*\b(você|vc|voce)\b',
            r'\bvocê (é|e)\b', r'\bvc (é|e)\b',
            # Pedidos de ajuda
            r'\b(ajuda|help|como.*funciona|o que.*fazer)\b',
            r'\b(pode|consegue|sabe).*fazer\b',
            # Perguntas sobre capacidades
            r'\bque.*posso\b', r'\bo que.*posso\b',
        ]

        for pattern in general_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return True

        return False

    def _answer_general_question(self, message: str) -> str:
        """Responde perguntas gerais"""
        from datetime import datetime
        import re

        # Perguntas sobre capacidades (verificar primeiro, antes de "o que")
        if re.search(r'\b(o que|que).*\b(pode[s]?|consegue[s]?|sabe[s]?).*\bfazer\b', message, re.IGNORECASE):
            return """Posso fazer várias coisas! 🚀

✅ Criar visualizações interativas (pizza, barras, linhas, métricas)
✅ Gerar queries Elasticsearch automaticamente
✅ Responder perguntas sobre data, hora
✅ Ajudar com dúvidas sobre o dashboard

Quer criar alguma visualização?"""

        # Perguntas sobre data/hora
        if re.search(r'\b(que|qual).*\b(dia|data)\b|\bhoje\b|\bhj\b', message, re.IGNORECASE):
            now = datetime.now()
            data_formatada = now.strftime("%d/%m/%Y")
            dia_semana = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"][now.weekday()]
            return f"Hoje é {dia_semana}-feira, {data_formatada}. 📅\n\nPosso criar alguma visualização para você?"

        if re.search(r'\b(que|qual).*\bhora[s]?\b|\bhora[s]?\s+(são|sao|é|e)\b|\bagora\b', message, re.IGNORECASE):
            now = datetime.now()
            hora_formatada = now.strftime("%H:%M")
            return f"Agora são {hora_formatada}. ⏰\n\nQuer visualizar algum dado?"

        # Pedidos de ajuda
        if re.search(r'\bajuda\b|\bhelp\b|\bcomo.*funciona\b', message, re.IGNORECASE):
            return """Posso ajudar você a criar visualizações! Aqui estão alguns exemplos:

📊 **Gráficos disponíveis:**
• Pizza - "mostre a distribuição por categoria"
• Barras - "compare os valores por região"
• Linhas - "mostre a tendência ao longo do tempo"
• Métrica - "qual o total de registros"

💡 **Dicas:**
• Use linguagem natural
• Seja específico sobre o que quer ver
• Posso também responder perguntas gerais!

O que gostaria de visualizar?"""

        # Perguntas sobre o assistente
        if re.search(r'\b(quem|o que).*\b(você|vc)\b|\bvocê (é|e)\b', message, re.IGNORECASE):
            return "Sou um assistente de visualização de dados! 🤖\n\nPosso criar gráficos e dashboards interativos a partir dos seus dados no Elasticsearch. Basta me dizer o que você quer ver!"

        # Default para outras perguntas
        return "Interessante pergunta! Minha especialidade é criar visualizações de dados. 📊\n\nQue tal me dizer o que você gostaria de visualizar?"

    def _wants_visualization(self, message: str) -> bool:
        """Detecta se o usuário realmente quer criar uma visualização"""
        visualization_keywords = [
            # Verbos de ação
            "mostre", "mostra", "exiba", "exibir", "crie", "criar", "gere", "gerar",
            "faça", "fazer", "quero", "preciso", "gostaria",
            # Tipos de gráfico
            "gráfico", "grafico", "chart", "visualização", "visualizacao",
            "pizza", "pie", "barra", "bar", "linha", "line", "métrica", "metric",
            # Análises
            "total", "soma", "count", "média", "media", "distribuição", "distribuicao",
            "comparar", "comparação", "comparacao", "tendência", "tendencia",
            "evolução", "evolucao", "ranking", "top"
        ]

        return any(keyword in message for keyword in visualization_keywords)

    def _detect_visualization_type(self, message: str) -> str:
        """Detecta tipo de visualização baseado na mensagem"""
        if any(word in message for word in ["pizza", "distribuição", "porcentagem", "pie"]):
            return "pie"
        elif any(word in message for word in ["barra", "comparar", "ranking", "top", "bar"]):
            return "bar"
        elif any(word in message for word in ["linha", "tendência", "tempo", "evolução", "line"]):
            return "line"
        elif any(word in message for word in ["total", "soma", "count", "métrica", "metric"]):
            return "metric"
        else:
            # Default: pie
            return "pie"

    def _generate_mock_query(self, message: str, viz_type: str) -> Dict[str, Any]:
        """Gera query Elasticsearch mock"""
        if viz_type == "metric":
            return {
                "size": 0,
                "aggs": {
                    "total": {
                        "value_count": {"field": "_id"}
                    }
                }
            }
        else:
            return {
                "size": 0,
                "aggs": {
                    "data": {
                        "terms": {
                            "field": "category.keyword",
                            "size": 10
                        }
                    }
                }
            }

    def _generate_mock_data(self, viz_type: str) -> Dict[str, Any]:
        """Gera dados mock para visualização"""
        if viz_type == "metric":
            return {
                "data": [
                    {"label": "Total", "value": 1234}
                ]
            }
        elif viz_type == "pie":
            return {
                "data": [
                    {"label": "Categoria A", "value": 35},
                    {"label": "Categoria B", "value": 25},
                    {"label": "Categoria C", "value": 20},
                    {"label": "Categoria D", "value": 15},
                    {"label": "Outros", "value": 5}
                ]
            }
        elif viz_type == "bar":
            return {
                "data": [
                    {"label": "Jan", "value": 120},
                    {"label": "Fev", "value": 150},
                    {"label": "Mar", "value": 180},
                    {"label": "Abr", "value": 160},
                    {"label": "Mai", "value": 200}
                ]
            }
        elif viz_type == "line":
            return {
                "data": [
                    {"label": "Seg", "value": 30},
                    {"label": "Ter", "value": 45},
                    {"label": "Qua", "value": 38},
                    {"label": "Qui", "value": 52},
                    {"label": "Sex", "value": 48},
                    {"label": "Sáb", "value": 35},
                    {"label": "Dom", "value": 25}
                ]
            }
        else:
            return {"data": []}

    def _generate_title(self, message: str) -> str:
        """Gera título baseado na mensagem"""
        # Capitalizar primeira letra de cada palavra
        return message.strip().capitalize()


# Singleton instance
_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """Retorna instância do service"""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service
