"""
LLM Service
Processa mensagens do usuário com LLM (Claude via Databricks)
"""

from typing import Optional, Dict, Any, List
import logging
import json

logger = logging.getLogger(__name__)


class LLMService:
    """Service para processamento com LLM"""

    def __init__(self):
        # TODO: Inicializar LangChain + Databricks
        # Por enquanto, vamos usar processamento mock
        self.llm_available = False

    async def process_message(
        self,
        message: str,
        index: str,
        context: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Processa mensagem do usuário e retorna widget spec

        Args:
            message: Mensagem do usuário
            index: Índice Elasticsearch
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
        logger.info(f"Processing message: {message} (index: {index})")

        # Por enquanto, retorna mock baseado em palavras-chave
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
