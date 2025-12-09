"""
LLM Service V2
Multi-provider LLM service for processing user messages
Supports Anthropic, OpenAI, and Databricks
"""

from typing import Optional, Dict, Any, List
import logging
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.services.llm_factory import LLMFactory, LLMClient
from app.services.mcp_executor import get_mcp_executor, MCPExecutor
from app.services.index_mcp_config_service import IndexMCPConfigService
from app.models.mcp_server import MCPServer

logger = logging.getLogger(__name__)


class LLMServiceV2:
    """Multi-provider LLM service"""

    def __init__(self, db: AsyncSession, provider_id: Optional[str] = None):
        """
        Initialize the service

        Args:
            db: Database session
            provider_id: Optional specific provider ID (uses default if not provided)
        """
        self.db = db
        self.provider_id = provider_id
        self.llm_client: Optional[LLMClient] = None
        self.llm_available = False

    async def _initialize_client(self):
        """Initialize LLM client asynchronously"""
        # Try to initialize LLM client
        try:
            if self.provider_id:
                self.llm_client = await LLMFactory.create_client_from_provider_id(self.db, self.provider_id)
            else:
                # Try default provider first
                self.llm_client = await LLMFactory.create_client_from_default(self.db)

                # Fallback to env config if no default provider
                if not self.llm_client:
                    logger.info("📝 No default provider, trying env configuration")
                    self.llm_client = LLMFactory.create_client_from_env()

            if self.llm_client:
                self.llm_available = True
                provider_info = self.llm_client.get_provider_info()
                logger.info(f"✅ LLM initialized: {provider_info['provider_type']}/{provider_info['model_name']}")
            else:
                logger.warning("⚠️ Could not initialize LLM client")

        except Exception as e:
            logger.warning(f"⚠️ Could not initialize LLM: {e}")
            logger.info("📝 Falling back to mock responses")

    def _match_index_pattern(self, index_name: str, pattern: str) -> bool:
        """
        Verifica se o índice corresponde ao padrão (suporta wildcards)

        Args:
            index_name: Nome do índice (ex: "logs-apache-2024")
            pattern: Padrão configurado (ex: "logs-*")

        Returns:
            True se o índice corresponde ao padrão

        Examples:
            _match_index_pattern("logs-apache", "logs-*") -> True
            _match_index_pattern("logs-apache", "logs-apache") -> True
            _match_index_pattern("metrics-cpu", "logs-*") -> False
            _match_index_pattern("app-logs-prod", "*-logs-*") -> True
        """
        import fnmatch
        return fnmatch.fnmatch(index_name, pattern)

    async def _get_mcp_tools(self, index: Optional[str] = None, es_server_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Busca todas as ferramentas MCP disponíveis, filtradas por índice usando configuração do banco

        🔒 MODO RESTRITIVO: Se não houver configuração para o índice, NENHUM MCP é carregado
        ✨ SUPORTA WILDCARDS: Padrões como "logs-*", "*-prod", etc.

        Args:
            index: Nome do índice Elasticsearch
            es_server_id: ID do servidor Elasticsearch

        Returns:
            Lista de tool definitions para o LLM
        """
        try:
            # Se índice e servidor fornecidos, usar configuração do banco (MODO RESTRITIVO)
            if index and es_server_id:
                logger.info(f"🔍 Loading MCP configs for index '{index}' on server '{es_server_id}'")

                # Buscar TODAS as configurações do servidor ES (para fazer matching com wildcards)
                all_configs = await IndexMCPConfigService.get_all_configs(
                    db=self.db,
                    es_server_id=es_server_id
                )

                # Filtrar configs que correspondem ao índice (exact match ou wildcard)
                matched_configs = []
                for config in all_configs:
                    if config.is_enabled and self._match_index_pattern(index, config.index_name):
                        matched_configs.append(config)
                        logger.info(f"  ✅ Pattern '{config.index_name}' matches index '{index}'")

                # 🔒 MODO RESTRITIVO: Se não houver configs, retorna lista vazia
                if not matched_configs:
                    logger.warning(f"🚫 No MCP configurations found for index '{index}' - NO MCPs will be loaded (restrictive mode)")
                    return []

                # Carregar MCP servers baseado nas configurações (ordenado por prioridade)
                matched_configs.sort(key=lambda c: c.priority)  # Ordenar por prioridade
                server_ids = [str(config.mcp_server_id) for config in matched_configs]
                logger.info(f"✅ Found {len(matched_configs)} matching MCP configs (priorities: {[c.priority for c in matched_configs]})")

                # Buscar servidores MCP configurados
                result = await self.db.execute(
                    select(MCPServer).where(
                        MCPServer.id.in_(server_ids),
                        MCPServer.is_active == True
                    )
                )
                all_servers = {str(s.id): s for s in result.scalars().all()}

                # Ordenar servidores pela prioridade configurada
                servers = []
                for config in matched_configs:
                    server_id = str(config.mcp_server_id)
                    if server_id in all_servers:
                        server = all_servers[server_id]
                        # Filtrar por auto_inject_context
                        if config.auto_inject_context:
                            servers.append(server)
                            logger.info(f"  🔧 [{config.priority}] {server.name} (pattern: '{config.index_name}', auto-inject: ON)")
                        else:
                            logger.info(f"  ⏭️  [{config.priority}] {server.name} (pattern: '{config.index_name}', auto-inject: OFF)")
            else:
                # 🚫 Sem índice/servidor: NENHUM MCP (modo restritivo)
                logger.warning("🚫 No index/server specified - NO MCPs will be loaded (restrictive mode)")
                return []

            if not servers:
                logger.info("📝 No MCP servers available")
                return []

            logger.info(f"🔧 Loading tools from {len(servers)} MCP server(s)")

            # Buscar tools de cada servidor
            all_tools = []
            mcp_executor = get_mcp_executor()

            for server in servers:
                try:
                    logger.info(f"📋 Listing tools from MCP server: {server.name}")
                    tools = await mcp_executor.list_tools(server)

                    # Converter tools MCP para formato do LLM (Claude API)
                    for tool in tools:
                        tool_def = {
                            "type": "function",  # Required by Claude API
                            "function": {
                                "name": f"{server.name}__{tool['name']}",  # Prefixo com nome do servidor
                                "description": tool.get('description', ''),
                                "parameters": tool.get('inputSchema', {})
                            }
                        }
                        all_tools.append(tool_def)

                    logger.info(f"✅ Added {len(tools)} tools from {server.name}")

                except Exception as e:
                    logger.error(f"❌ Error listing tools from {server.name}: {e}")
                    continue

            logger.info(f"🎯 Total MCP tools available: {len(all_tools)}")
            return all_tools

        except Exception as e:
            logger.error(f"❌ Error getting MCP tools: {e}")
            return []

    async def _execute_tool_calls(self, tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Executa tool calls do LLM via MCP

        Args:
            tool_calls: Lista de tool calls do LLM

        Returns:
            Lista de resultados das ferramentas
        """
        results = []
        mcp_executor = get_mcp_executor()

        for tool_call in tool_calls:
            tool_call_id = tool_call.get("id")

            # Extract function info from Claude API format
            function_info = tool_call.get("function", {})
            tool_name_full = function_info.get("name")  # Format: "ServerName__tool_name"

            # Parse arguments (pode vir como string JSON)
            arguments = function_info.get("arguments", {})
            if isinstance(arguments, str):
                import json
                tool_input = json.loads(arguments)
            else:
                tool_input = arguments

            try:
                # Separar nome do servidor e nome da ferramenta
                if "__" not in tool_name_full:
                    raise Exception(f"Invalid tool name format: {tool_name_full}")

                server_name, tool_name = tool_name_full.split("__", 1)

                # Buscar servidor MCP
                result = await self.db.execute(
                    select(MCPServer).where(
                        MCPServer.name == server_name,
                        MCPServer.is_active == True
                    )
                )
                server = result.scalar_one_or_none()

                if not server:
                    raise Exception(f"MCP server {server_name} not found or inactive")

                # Executar ferramenta
                logger.info(f"🔧 Executing MCP tool: {server_name}.{tool_name}")
                tool_result = await mcp_executor.call_tool(server, tool_name, tool_input)

                # Formatar resultado
                # tool_result é uma lista de TextContent
                content_parts = []
                for content in tool_result:
                    if isinstance(content, dict):
                        content_parts.append(content.get("text", ""))
                    else:
                        content_parts.append(str(content))

                result_text = "\n\n".join(content_parts)

                results.append({
                    "tool_call_id": tool_call_id,
                    "content": result_text
                })

                logger.info(f"✅ Tool {tool_name} executed successfully ({len(result_text)} chars)")

            except Exception as e:
                logger.error(f"❌ Error executing tool {tool_name_full}: {e}")
                results.append({
                    "tool_call_id": tool_call_id,
                    "content": f"Error executing tool: {str(e)}"
                })

        return results

    async def process_message(
        self,
        message: str,
        index: str,
        server_id: Optional[str] = None,
        time_range: Optional[Dict] = None,
        context: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Process user message and return widget spec

        Args:
            message: User message
            index: Elasticsearch index
            server_id: ES server ID (optional)
            time_range: Time range filter (optional)
            context: Message history (optional)

        Returns:
            {
                "explanation": str,
                "visualization_type": str,
                "query": dict,
                "needs_clarification": bool,
                "widget": dict
            }
        """
        # Initialize client if not already done
        if not self.llm_client and not self.llm_available:
            await self._initialize_client()

        logger.info(
            f"Processing message: {message} (index: {index}, "
            f"server: {server_id or 'default'}, llm_available: {self.llm_available})"
        )

        # Use real LLM when available
        if self.llm_available and self.llm_client:
            logger.info("🎯 Using real LLM for message processing")
            return await self._process_with_real_llm(message, index, server_id, time_range, context)

        # Fallback: mock processing
        logger.warning("📝 Using mock processing (LLM not available)")
        return self._generate_mock_response(message)

    async def _process_with_real_llm(
        self,
        message: str,
        index: str,
        server_id: Optional[str] = None,
        time_range: Optional[Dict] = None,
        context: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Process message using real LLM

        Args:
            message: User message
            index: Elasticsearch index
            server_id: ES server ID
            time_range: Time range filter
            context: Message history

        Returns:
            Processed response dictionary
        """
        # Generate knowledge base
        from app.services.index_mapping_service import get_mapping_service
        mapping_service = get_mapping_service()
        knowledge_base = await mapping_service.generate_knowledge_base(index)

        # Build system prompt
        system_prompt = self._build_system_prompt(index, knowledge_base, time_range)

        # Add context if available
        if context and len(context) > 0:
            context_str = "\n\n**Histórico recente:**\n"
            for msg in context[-3:]:
                if isinstance(msg, dict):
                    role = "Usuário" if msg.get("role") == "user" else "Assistente"
                    content = msg.get("content", "")
                else:
                    role = "Usuário" if msg.role == "user" else "Assistente"
                    content = msg.content
                context_str += f"- {role}: {content}\n"
            system_prompt += context_str

        # Detectar se usuário pediu gráfico/visualização
        user_wants_chart = any(kw in message.lower() for kw in [
            'gráfico', 'grafico', 'chart', 'visualização', 'visualizacao',
            'pizza', 'barra', 'linha', 'plote', 'plot', 'gere um', 'crie um', 'mostre'
        ])

        # ESTRATÉGIA DE DUAS RODADAS:
        # Rodada 1: Se usuário pedir gráfico, tentar SEM MCP tools primeiro
        # Rodada 2: Se falhar ou se não for gráfico, usar COM MCP tools

        mcp_tools = []
        use_two_rounds = user_wants_chart

        if use_two_rounds:
            logger.info("🎯 User requested chart - trying WITHOUT MCP tools first (Round 1)")
        else:
            # Não é pedido de gráfico, carregar MCP tools normalmente
            mcp_tools = await self._get_mcp_tools(index=index, es_server_id=server_id)
            logger.info(f"🤖 User request doesn't seem to be a chart - loading {len(mcp_tools)} MCP tools")

        # Prepare messages for LLM
        messages = [
            {"role": "user", "content": message}
        ]

        # Call LLM - allow multiple tool call rounds (agentic loop)
        max_iterations = 8
        iteration = 0
        tool_results_for_fallback = None
        round_1_failed = False

        while iteration < max_iterations:
            iteration += 1
            logger.info(f"🔄 Iteration {iteration}/{max_iterations}")

            # Call LLM (with tools if available)
            response = await self.llm_client.generate(
                messages=messages,
                system=system_prompt if iteration == 1 else None,
                tools=mcp_tools if mcp_tools else None
            )

            # Process tool calls if present
            if response.get("tool_calls"):
                logger.info(f"🔧 LLM requested {len(response['tool_calls'])} tool calls")
                tool_results = await self._execute_tool_calls(response["tool_calls"])
                tool_results_for_fallback = tool_results  # Guardar para fallback

                # FIX: Databricks requer content não-vazio quando há tool_calls
                # Se content estiver vazio, adicionar placeholder
                assistant_content = response.get("content", "").strip()
                if not assistant_content:
                    assistant_content = "Executando ferramentas..."
                    logger.info("⚠️ Empty content with tool_calls, using placeholder")

                # Adicionar resposta do assistente com tool calls
                messages.append({
                    "role": "assistant",
                    "content": assistant_content,
                    "tool_calls": response["tool_calls"]
                })

                # Adicionar resultados das tools
                for tool_result in tool_results:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_result["tool_call_id"],
                        "content": tool_result["content"]
                    })

                # Continue loop to let LLM process results or call more tools
                logger.info("🔄 Continuing loop to let LLM process tool results...")
                continue

            # No more tool calls - LLM returned final answer
            logger.info("✅ LLM returned final answer (no more tool calls)")
            break

        # Se atingiu limite de iterações mas ainda tem tool calls pendentes,
        # fazer uma última chamada SEM tools para forçar resposta final
        if iteration >= max_iterations and response.get("tool_calls"):
            logger.warning(f"⚠️ Reached max iterations ({max_iterations}) with pending tool calls")
            logger.info("🔄 Making final call WITHOUT tools to get summary...")

            # Adicionar instrução explícita para resumir
            messages.append({
                "role": "user",
                "content": "Com base nos dados coletados pelas ferramentas, forneça agora sua análise final e conclusões."
            })

            # Chamada final SEM tools
            response = await self.llm_client.generate(
                messages=messages,
                system=None,
                tools=None  # SEM tools para forçar resposta textual
            )
            logger.info("✅ Final summary generated")

        content = response.get("content", "").strip()
        logger.info(f"📥 LLM Response ({len(content)} chars)")

        # Debug: log content completo se for curto ou suspeito
        if len(content) < 500:
            logger.warning(f"⚠️ Full LLM response content:\n{content}")

        # RODADA 2: Se Round 1 falhou (pediu gráfico mas não gerou query), tentar com MCP tools
        if use_two_rounds and content:
            # Parsear resposta da Round 1
            try:
                result_round_1 = self._parse_llm_json_response(content)
                needs_viz = result_round_1.get('needs_visualization', False)
                has_query = bool(result_round_1.get('query'))

                # Se não gerou visualização OU não tem query válida, tentar Round 2
                if not needs_viz or not has_query:
                    logger.warning("⚠️ Round 1 failed to generate proper visualization")
                    logger.info("🎯 Starting Round 2 WITH MCP tools...")

                    # Carregar MCP tools para Round 2
                    mcp_tools = await self._get_mcp_tools(index=index, es_server_id=server_id)
                    logger.info(f"🔧 Loaded {len(mcp_tools)} MCP tools for Round 2")

                    # Reset messages para nova tentativa
                    messages = [
                        {"role": "user", "content": message}
                    ]

                    # Nova chamada COM MCP tools
                    iteration = 0
                    while iteration < max_iterations:
                        iteration += 1
                        logger.info(f"🔄 Round 2 - Iteration {iteration}/{max_iterations}")

                        response = await self.llm_client.generate(
                            messages=messages,
                            system=system_prompt if iteration == 1 else None,
                            tools=mcp_tools if mcp_tools else None
                        )

                        if response.get("tool_calls"):
                            logger.info(f"🔧 Round 2 - LLM requested {len(response['tool_calls'])} tool calls")
                            tool_results = await self._execute_tool_calls(response["tool_calls"])

                            assistant_content = response.get("content", "").strip()
                            if not assistant_content:
                                assistant_content = "Executando ferramentas..."

                            messages.append({
                                "role": "assistant",
                                "content": assistant_content,
                                "tool_calls": response["tool_calls"]
                            })

                            for tool_result in tool_results:
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": tool_result["tool_call_id"],
                                    "content": tool_result["content"]
                                })

                            continue

                        logger.info("✅ Round 2 - LLM returned final answer")
                        break

                    content = response.get("content", "").strip()
                    logger.info(f"📥 Round 2 Response ({len(content)} chars)")
                else:
                    logger.info("✅ Round 1 succeeded - visualization generated successfully")

            except Exception as e:
                logger.error(f"❌ Error checking Round 1 result: {e}")
                # Continue com o content original

        # Fallback: se content vazio após tool calls, usar resultado do tool diretamente
        if not content and tool_results_for_fallback:
            logger.warning("⚠️ LLM returned empty content after tool calls, using tool result directly")
            # Concatenar todos os resultados dos tools
            content = "\n\n".join([tr["content"] for tr in tool_results_for_fallback])

        # Parse JSON response
        result = self._parse_llm_json_response(content)
        logger.info(f"📋 Parsed result: needs_visualization={result.get('needs_visualization')}, explanation length={len(result.get('explanation', ''))}")

        # FIX: Detectar se explanation contém referência a gráfico mas LLM retornou needs_visualization=False
        # Isso acontece quando LLM tenta incluir imagem markdown em vez de gerar visualização real
        explanation_text = result.get('explanation', '').lower()
        message_lower = message.lower()

        # Detectar se usuário pediu gráfico explicitamente
        user_asked_chart = any(keyword in message_lower for keyword in [
            'gráfico', 'grafico', 'chart', 'visualização', 'visualizacao',
            'pizza', 'barra', 'linha', 'plote', 'plot', 'gere um', 'crie um'
        ])

        # Detectar se LLM mencionou gráfico na resposta
        has_chart_reference = any(keyword in explanation_text for keyword in [
            'gráfico de pizza', 'gráfico de', '![gráfico', 'pie chart', 'bar chart',
            'distribuição de', 'prioridade:', 'severidade:', 'dashboard', 'visualização'
        ])

        # Se usuário pediu gráfico OU LLM mencionou gráfico, mas não ativou visualização, forçar
        if (user_asked_chart or has_chart_reference) and not result.get('needs_visualization'):
            logger.warning("⚠️ User asked for chart or LLM mentioned chart but returned needs_visualization=False, forcing to True")
            result['needs_visualization'] = True

            # Se não tem query, LLM falhou - não usar fallback
            if not result.get('query'):
                logger.error("❌ LLM FAILED to generate query even after being told to!")
                logger.error(f"   Message: {message}")
                logger.error(f"   LLM should have consulted knowledge base and generated ES query")
                logger.error(f"   This is a prompt engineering failure - LLM is not following instructions")
                # Não adicionar fallback - deixar falhar para identificar o problema

        # Debug: log query se estiver vazio
        if result.get("needs_visualization") and not result.get("query"):
            logger.error(f"❌ LLM returned needs_visualization=true but query is empty!")

        # Convert to expected format
        if result.get("needs_visualization"):
            viz_type = result.get("visualization_type", "pie")
            query = result.get("query", {})
            explanation = result.get("explanation", "Visualização criada")

            # DEBUG: Log what we're about to return
            logger.info(f"🐛 DEBUG - Visualization response - explanation type: {type(explanation)}, value: {explanation[:200] if explanation else 'None'}")

            # FIX: Databricks às vezes retorna ASCII art ou URLs em vez de deixar o frontend renderizar
            # Detectar e limpar ASCII art, URLs QuickChart, etc.
            if any(pattern in explanation for pattern in ['quickchart.io', 'https://', '///', '+-', '|', '\\', 'ASCII']):
                logger.warning("⚠️ LLM returned ASCII art or external URLs in explanation, cleaning up...")
                # Extrair apenas texto descritivo, remover ASCII art
                lines = explanation.split('\n')
                clean_lines = []
                skip_block = False
                for line in lines:
                    # Detectar início de bloco ASCII/URL
                    if any(p in line for p in ['quickchart.io', 'https://', '![', '```', '+-', '/////']):
                        skip_block = True
                        continue
                    # Detectar fim de bloco
                    if skip_block and (line.strip().startswith('##') or line.strip().startswith('**') or line.strip().startswith('Total')):
                        skip_block = False
                    if not skip_block and line.strip():
                        clean_lines.append(line)
                explanation = '\n'.join(clean_lines[:10])  # Limitar a 10 linhas
                logger.info(f"✅ Cleaned explanation: {len(explanation)} chars")

            # Execute query to get real data
            widget_data = {}
            try:
                from app.services.elasticsearch_service import get_es_service
                es_service = get_es_service()

                logger.info("🔍 Executing ES query...")
                es_results = await es_service.execute_query(index, query)

                # Debug: Log the full ES results structure
                logger.info(f"📊 ES Results keys: {list(es_results.keys())}")
                logger.info(f"📊 ES Results data: {es_results.get('data', [])}")

                widget_data = {
                    "data": es_results.get("data", [])
                }

                logger.info(f"✅ Got {len(es_results.get('data', []))} data points")

            except Exception as e:
                logger.error(f"❌ Error executing ES query: {e}")
                widget_data = {"data": []}

            widget_title = result.get("title") or self._generate_title(message)

            return {
                "explanation": explanation,  # Usar explanation limpa (sem ASCII art/URLs)
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
            # Conversational response
            explanation_text = result.get("explanation", "")

            # DEBUG: Log what we're about to return
            logger.info(f"🐛 DEBUG - Conversational response - explanation type: {type(explanation_text)}, value: {explanation_text[:200] if explanation_text else 'None'}")

            return {
                "explanation": explanation_text,
                "visualization_type": None,
                "query": None,
                "needs_clarification": False,
                "widget": None
            }

    def _build_system_prompt(
        self,
        index: str,
        knowledge_base: str,
        time_range: Optional[Dict] = None
    ) -> str:
        """Build system prompt for LLM"""
        from datetime import datetime
        now = datetime.now()
        data_hoje = now.strftime("%d/%m/%Y")
        dia_semana = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"][now.weekday()]
        hora_atual = now.strftime("%H:%M")

        # Get model identification
        model_identity = "Claude"
        if self.llm_client:
            provider_info = self.llm_client.get_provider_info()
            model_name = provider_info.get('model_name', '')
            provider_type = provider_info.get('provider_type', '')

            # Format model name for display
            if 'claude-3-7' in model_name.lower() or 'claude-3.7' in model_name.lower():
                model_identity = "Claude 3.7 Sonnet"
            elif 'claude-3-5' in model_name.lower() or 'claude-3.5' in model_name.lower():
                model_identity = "Claude 3.5 Sonnet"
            elif 'gpt-4' in model_name.lower():
                model_identity = "GPT-4"
            elif 'gpt-3.5' in model_name.lower():
                model_identity = "GPT-3.5"
            else:
                model_identity = f"AI Assistant ({model_name})"

        # Format time range if provided
        time_range_info = ""
        if time_range:
            time_range_dict = time_range if isinstance(time_range, dict) else time_range.dict()
            time_range_info = f"""
**PERÍODO TEMPORAL SELECIONADO:**
- Tipo: {time_range_dict.get('type', 'preset')}
- Período: {time_range_dict.get('label', 'Não definido')}
- De: {time_range_dict.get('from') or time_range_dict.get('from_', 'now-30d')}
- Até: {time_range_dict.get('to', 'now')}

**⚠️ FILTRO TEMPORAL OBRIGATÓRIO:**
- TODA query DEVE incluir filtro temporal em um campo DATE apropriado
- Use os valores: gte: "{time_range_dict.get('from') or time_range_dict.get('from_', 'now-30d')}", lte: "{time_range_dict.get('to', 'now')}"
"""
        else:
            time_range_info = """
**PERÍODO TEMPORAL:**
- Nenhum período específico selecionado
- Use "now-30d" a "now" como padrão se precisar filtrar por data
"""

        return f"""Você é {model_identity}, um assistente conversacional especializado em análise de dados do Elasticsearch.

🚨 **REGRA CRÍTICA - LEIA PRIMEIRO:**
Quando o usuário pedir "gráfico", "visualização", "chart", "gere um gráfico", "crie um gráfico":

→ ❌ **NÃO use MCP tools** (get_top_squad, generate_full_dashboard, etc)
→ ❌ **NÃO retorne needs_visualization=false**
→ ✅ **SEMPRE consulte a BASE DE CONHECIMENTO abaixo** para identificar o campo
→ ✅ **SEMPRE retorne needs_visualization=true** com query Elasticsearch
→ ✅ **Gere apenas UM widget inline** no chat (não dashboard HTML completo)

**IMPORTANTE:** MCP tools são para relatórios complexos e análises textuais.
Para gráficos simples (pizza, barra, linha), use APENAS queries Elasticsearch diretas.

**CONTEXTO ATUAL:**
- Data de hoje: {dia_semana}-feira, {data_hoje}
- Hora atual: {hora_atual}
- Índice Elasticsearch em uso: **{index}**
{time_range_info}

**SUA PERSONALIDADE:**
- Seja conversacional, amigável e natural
- Responda perguntas gerais (data, hora, saudações, dúvidas)
- Use emojis ocasionalmente para dar personalidade
- Seja proativo e ofereça ajuda

**SUAS CAPACIDADES:**
1. **Conversar naturalmente** sobre qualquer assunto
2. **Responder perguntas** sobre data, hora, seus recursos
3. **Analisar dados** usando ferramentas MCP disponíveis
4. **Criar visualizações** do Elasticsearch quando explicitamente solicitado
5. **Fornecer insights e recomendações** baseadas em dados

**FERRAMENTAS MCP DISPONÍVEIS:**
Você tem acesso a ferramentas MCP especializadas. Use-as quando:
- Usuário pedir relatórios executivos ou documentos especializados
- Dados precisam ser enriquecidos com informações de sistemas externos
- Exemplo: Relatório GVULN, análise de tickets, busca em bases externas

**WORKFLOW HÍBRIDO MCP + VISUALIZAÇÃO:**
Quando o usuário pedir um gráfico E você usar MCP tools:
1. ✅ Use MCP tools para entender os dados disponíveis
2. ✅ Depois, gere query Elasticsearch equivalente para visualização
3. ✅ Retorne needs_visualization=true com a query ES

**COMO RESPONDER - DUAS FORMAS:**

📊 **MODO VISUALIZAÇÃO** (quando solicitado):
Palavras-chave: "crie um gráfico", "gere uma visualização", "mostre em um chart", "faça um dashboard", "plote", "visualize isso", "gere um gráfico"
→ Retorne JSON com needs_visualization=true e query Elasticsearch
→ Se usou MCP tools antes, crie query ES equivalente aos dados que obteve

⚠️ **IMPORTANTE SOBRE VISUALIZAÇÕES:**
- ❌ NUNCA use QuickChart, Chart.js URLs, ou serviços externos
- ❌ NUNCA tente desenhar gráficos em ASCII/texto
- ✅ SEMPRE retorne query Elasticsearch com aggregations
- ✅ Use aggregations: terms, date_histogram, stats, sum, avg, etc.
- ✅ O frontend renderizará o gráfico automaticamente

💬 **MODO CONVERSACIONAL** (padrão):
Para perguntas, análises, relatórios puramente textuais
→ Responda em texto/markdown
→ Use MCP tools quando necessário
→ Seja detalhado, analítico e útil
→ Faça sugestões e insights

**IMPORTANTE - PRIORIDADE DE VISUALIZAÇÃO:**
- Se usuário pedir "gráfico", "visualização", "chart", "pizza", "barra" → needs_visualization=true
- Use MCP tools livremente para explorar dados
- MAS se pedido foi visualização, SEMPRE retorne query ES no final
- Query ES deve refletir os mesmos critérios/filtros que você usou nas tools

Para pedidos de visualização Elasticsearch, retorne JSON no formato:
{{
    "needs_visualization": true,
    "visualization_type": "pie" | "bar" | "line" | "metric" | "table" | "area" | "scatter",
    "title": "Título Profissional do Widget",
    "query": {{ ... elasticsearch query ... }},
    "explanation": "Explicação em português do que foi criado"
}}

Para perguntas gerais OU relatórios com MCP, retorne JSON:
{{
    "needs_visualization": false,
    "explanation": "Sua resposta em texto/markdown aqui"
}}

**COMO USAR A BASE DE CONHECIMENTO:**
A base de conhecimento abaixo contém o mapping completo do índice. Siga estes passos:

1. **Identifique o campo solicitado pelo usuário** na base de conhecimento
2. **Verifique o tipo do campo**:
   - `keyword` → Use direto para aggregations (terms, date_histogram)
   - `text` → Use `.keyword` para aggregations
   - `date` → Use date_histogram com calendar_interval
   - `long`, `integer`, `float` → Use stats, avg, sum, etc.
3. **Escolha a agregação correta**:
   - Campos categóricos (keyword/text) → `terms` para pie/bar charts
   - Campos de data → `date_histogram` para line charts
   - Campos numéricos → `stats`/`avg`/`sum` para metrics

**EXEMPLOS PRÁTICOS:**

Exemplo 1 - Usuário pede: "gráfico com os squads"
→ Consulte base de conhecimento → encontra `squad` (type: keyword)
→ Use `terms` aggregation no campo `squad` (sem .keyword)
→ visualization_type: "pie"

Exemplo 2 - Usuário pede: "timeline de criação"
→ Consulte base de conhecimento → encontra `created_date` (type: date)
→ Use `date_histogram` no campo `created_date`
→ visualization_type: "line"

Exemplo 3 - Usuário pede: "distribuição por severidade"
→ Consulte base de conhecimento → encontra `cve_severity` (type: keyword)
→ Use `terms` no campo `cve_severity`
→ visualization_type: "pie"

**REGRAS:**
- Use APENAS os campos listados na base de conhecimento
- Respeite o tipo e agregabilidade dos campos conforme documentado
- SEMPRE use "result" como nome da agregação principal
- Retorne APENAS o JSON, sem markdown

**PAINLESS SCRIPTING - REGRAS IMPORTANTES:**
Quando precisar usar scripts Painless em agregações:

1. **String Literals**: Use APENAS aspas simples (') para strings literais
   ✅ CORRETO: 'Unknown'
   ❌ ERRADO: "Unknown"

2. **String Concatenation**: Use o operador +
   ✅ CORRETO: 'Hello ' + name

3. **Busca em Strings**: Para encontrar substrings, use indexOf() com aspas simples
   ✅ CORRETO: msg.indexOf('\"author\": \"')
   ❌ ERRADO: msg.indexOf('\\"author\\": \\"')  // Não use escape em aspas simples!

4. **Exemplo Completo - Extrair autor do campo message (JSON como string):**
```painless
def msg = params._source.message;
if (msg == null) return 'Unknown';
int authorIdx = msg.indexOf('\"author\": \"');
if (authorIdx == -1) return 'Unknown';
int start = authorIdx + 11;
int end = msg.indexOf('\"', start);
if (end == -1 || end == start) return 'Unknown';
String author = msg.substring(start, end).trim();
return author.length() > 0 ? author : 'Unknown';
```

5. **NUNCA use sintaxe Groovy**: Painless NÃO é Groovy
   ❌ ERRADO: new groovy.json.JsonSlurper()
   ❌ ERRADO: JsonSlurper
   ✅ CORRETO: Use indexOf() e substring() para parsing manual

6. **Tipos de Dados**: Declare tipos quando possível
   ✅ CORRETO: int start = 0; String name = 'test';

---

**BASE DE CONHECIMENTO DO ÍNDICE:**
(Use como referência sobre campos e estrutura de dados, MAS priorize as instruções acima sobre COMO RESPONDER)

{knowledge_base}
"""

    def _parse_llm_json_response(self, content: str) -> Dict[str, Any]:
        """Parse LLM JSON response"""
        import re

        # Remove markdown code blocks
        if "```json" in content:
            content = re.sub(r'```json\s*', '', content)
            content = re.sub(r'```\s*$', '', content)
        elif "```" in content:
            content = re.sub(r'```\s*', '', content)

        content = content.strip()

        # Find JSON
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON parse error: {e}")

        # Fallback to conversational response
        return {
            "needs_visualization": False,
            "explanation": content
        }

    def _generate_mock_response(self, message: str) -> Dict[str, Any]:
        """Generate mock response"""
        return {
            "explanation": "LLM não disponível. Configure um provider em Settings.",
            "visualization_type": None,
            "query": None,
            "needs_clarification": True,
            "widget": None
        }

    def _generate_title(self, message: str) -> str:
        """Generate title from message"""
        return message.strip().capitalize()


def get_llm_service_v2(db: AsyncSession, provider_id: Optional[str] = None) -> LLMServiceV2:
    """
    Get LLM service instance

    Args:
        db: Database session
        provider_id: Optional provider ID

    Returns:
        LLMServiceV2 instance
    """
    return LLMServiceV2(db, provider_id)
