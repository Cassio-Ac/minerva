# Sistema de MCP por Índice

## Visão Geral

O sistema de **MCP (Model Context Protocol) por Índice** permite configurar quais servidores MCP devem ser usados para cada índice do Elasticsearch. Isso resolve o problema de confusão do LLM sobre quais ferramentas usar, garantindo que apenas ferramentas relevantes sejam oferecidas baseado no contexto do índice selecionado.

### 🔒 Modo Restritivo

**IMPORTANTE**: O sistema opera em **modo restritivo** - se não houver configuração para um índice, **NENHUM MCP** será carregado. Isso garante controle total sobre quais ferramentas são disponibilizadas para cada índice.

### ✨ Suporte a Wildcards

O sistema suporta padrões com wildcards (`*`) para agrupar múltiplos índices:
- `logs-*` → Todos os índices que começam com "logs-" (ex: logs-apache, logs-nginx, logs-app)
- `*-prod` → Todos os índices que terminam com "-prod" (ex: api-prod, db-prod)
- `*-logs-*` → Qualquer índice que contenha "-logs-" no nome

## Arquitetura

### 1. Model (`IndexMCPConfig`)

**Arquivo**: `backend/app/models/index_mcp_config.py`

```python
class IndexMCPConfig(Base):
    __tablename__ = "index_mcp_config"

    # Identificação
    id: UUID

    # Associação (qual MCP para qual índice)
    es_server_id: UUID              # Servidor Elasticsearch
    index_name: str                 # Nome do índice (ex: "vazamentos", "logs-apache")
    mcp_server_id: UUID             # Servidor MCP a ser usado

    # Configuração
    priority: int = 10              # Menor número = maior prioridade
    is_enabled: bool = True         # Ativo/Inativo
    auto_inject_context: bool = True # Auto-injetar no contexto do LLM
    config: JSONB = {}              # Configurações específicas (JSON)

    # Auditoria
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[UUID]
```

**Campos Principais**:
- `es_server_id` + `index_name` + `mcp_server_id`: Tripla que define a associação
- `priority`: Ordem de apresentação ao LLM (1 = primeiro, 10 = último)
- `auto_inject_context`: Se `True`, o MCP é automaticamente incluído no contexto do LLM quando o índice é selecionado
- `config`: Campo JSONB para configurações adicionais específicas do MCP

### 2. Service Layer (`IndexMCPConfigService`)

**Arquivo**: `backend/app/services/index_mcp_config_service.py`

**Métodos Principais**:

```python
# Criar configuração
await IndexMCPConfigService.create_config(
    db=db,
    es_server_id="uuid-do-servidor-es",
    index_name="vazamentos",
    mcp_server_id="uuid-do-mcp",
    priority=10,
    is_enabled=True,
    auto_inject_context=True
)

# Buscar MCPs para um índice (ordenados por prioridade)
configs = await IndexMCPConfigService.get_configs_by_index(
    db=db,
    es_server_id="uuid-do-servidor-es",
    index_name="vazamentos",
    enabled_only=True  # Apenas ativos
)

# Obter lista de MCP IDs habilitados
mcp_ids = await IndexMCPConfigService.get_mcp_servers_for_index(
    db=db,
    es_server_id="uuid-do-servidor-es",
    index_name="vazamentos"
)
```

### 3. API Endpoints (`/api/v1/index-mcp-config`)

**Arquivo**: `backend/app/api/v1/index_mcp_config.py`

**Endpoints Disponíveis**:

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/` | Criar nova configuração |
| `GET` | `/` | Listar todas configurações |
| `GET` | `/index/{es_server_id}/{index_name}` | Buscar configs de um índice |
| `GET` | `/{config_id}` | Buscar config por ID |
| `PATCH` | `/{config_id}` | Atualizar configuração |
| `DELETE` | `/{config_id}` | Deletar configuração |
| `DELETE` | `/index/{es_server_id}/{index_name}` | Deletar todas configs de um índice |
| `GET` | `/index/{es_server_id}/{index_name}/mcp-servers` | Listar MCP IDs habilitados |

**Exemplo de uso**:

```bash
# Criar configuração
curl -X POST http://localhost:8000/api/v1/index-mcp-config/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "es_server_id": "uuid-do-servidor-es",
    "index_name": "vazamentos",
    "mcp_server_id": "uuid-do-mcp-gvuln",
    "priority": 5,
    "is_enabled": true,
    "auto_inject_context": true
  }'

# Listar MCPs para um índice
curl http://localhost:8000/api/v1/index-mcp-config/index/{es_server_id}/{index_name}?enabled_only=true
```

### 4. Frontend Component (`IndexMCPConfigManager`)

**Arquivo**: `frontend/src/components/IndexMCPConfigManager.tsx`

**Funcionalidades**:
- ✅ Listagem de configurações agrupadas por índice
- ✅ Formulário para adicionar nova configuração
- ✅ Toggle ativar/desativar configuração
- ✅ Deletar configuração
- ✅ Indicadores visuais de prioridade
- ✅ Badge de status (ativo/inativo, auto-inject)

**Interface**:
```typescript
interface IndexMCPConfig {
  id: string;
  es_server_id: string;
  index_name: string;
  mcp_server_id: string;
  priority: number;
  is_enabled: boolean;
  auto_inject_context: boolean;
  config: Record<string, any> | null;
}
```

### 5. Integração com LLM Service (`LLMServiceV2`)

**Arquivo**: `backend/app/services/llm_service_v2.py`

**Fluxo de Integração**:

```python
async def _get_mcp_tools(
    self,
    index: Optional[str] = None,
    es_server_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Busca ferramentas MCP filtradas pelo índice

    FLUXO:
    1. Se index + es_server_id fornecidos:
       - Buscar configurações do banco (IndexMCPConfigService)
       - Filtrar apenas configs com is_enabled=True
       - Ordenar por prioridade
       - Filtrar por auto_inject_context=True
       - Carregar apenas esses MCPs

    2. Fallback (sem index/server):
       - Carregar todos MCPs ativos

    3. Para cada MCP:
       - Listar ferramentas via MCP executor
       - Converter para formato Claude API
       - Adicionar prefixo server_name__ ao nome da ferramenta
    """

    # 1. Buscar configurações do banco
    if index and es_server_id:
        configs = await IndexMCPConfigService.get_configs_by_index(
            db=self.db,
            es_server_id=es_server_id,
            index_name=index,
            enabled_only=True
        )

        # 2. Carregar servidores MCP
        server_ids = [str(config.mcp_server_id) for config in configs]

        # 3. Filtrar por auto_inject_context
        servers = []
        for config in configs:
            if config.auto_inject_context:
                servers.append(get_mcp_server(config.mcp_server_id))
```

**Chamada no `process_message`**:

```python
async def _process_with_real_llm(
    self, message: str, index: str, server_id: Optional[str] = None, ...
):
    # 1. Gerar knowledge base do índice
    knowledge_base = await mapping_service.generate_knowledge_base(index)

    # 2. Construir system prompt
    system_prompt = self._build_system_prompt(index, knowledge_base, ...)

    # 3. 🎯 BUSCAR MCPs FILTRADOS PELO ÍNDICE
    mcp_tools = await self._get_mcp_tools(
        index=index,
        es_server_id=server_id
    )

    # 4. Chamar LLM com ferramentas específicas
    response = await self.llm_client.generate(
        messages=messages,
        system=system_prompt,
        tools=mcp_tools  # ✅ Apenas MCPs configurados para este índice!
    )
```

## Fluxo Completo de Uso

### 1. Configuração (Admin)

1. Acessar **Settings** → **MCP por Índice**
2. Clicar em **"➕ Adicionar Configuração"**
3. Preencher:
   - **Servidor Elasticsearch**: Selecionar servidor
   - **Nome do Índice**: Ex: `vazamentos`
   - **MCP Server**: Selecionar MCP (ex: `GVULN MCP`)
   - **Prioridade**: 1-100 (menor = maior prioridade)
   - **Ativo**: ✅ Habilitado
   - **Auto-inject no contexto do LLM**: ✅ Habilitado
4. Salvar

### 2. Uso Automático (Chat)

Quando o usuário seleciona um índice no chat:

```
Usuário: [Seleciona índice "vazamentos" + servidor ES]
Usuário: "Liste os últimos 10 vazamentos críticos"

SISTEMA:
1. ✅ Identifica: index="vazamentos", es_server_id="uuid-123"
2. 🔍 Busca configurações: IndexMCPConfigService.get_configs_by_index()
3. 📋 Encontra:
   - [Priority 5] GVULN MCP (auto_inject=True, enabled=True)
4. 🔧 Carrega ferramentas do GVULN MCP:
   - list_recent_leaks
   - get_leak_details
   - search_by_category
5. 🤖 Envia para LLM com:
   - Knowledge base do índice "vazamentos"
   - Ferramentas do GVULN MCP
   - Mensagem do usuário

LLM: [Usa ferramenta list_recent_leaks automaticamente]
LLM: [Retorna análise dos 10 vazamentos mais recentes]
```

### 3. Cenários de Uso

#### Cenário 1: MCP Hardcoded para Índice Específico

**Problema**: MCP `gvuln_mcp` tem índice hardcoded `vazamentos`

**Solução**:
```sql
INSERT INTO index_mcp_config (
    es_server_id, index_name, mcp_server_id,
    priority, is_enabled, auto_inject_context
) VALUES (
    'uuid-servidor-es', 'vazamentos', 'uuid-gvuln-mcp',
    1, true, true
);
```

**Resultado**: Quando usuário selecionar `vazamentos`, o GVULN MCP será automaticamente disponibilizado.

#### Cenário 2: Múltiplos MCPs para um Índice

**Exemplo**: Índice `logs-apache` usa 2 MCPs:
- `LogAnalyzer MCP` (priority=1) - análise de logs
- `SecurityScanner MCP` (priority=5) - análise de segurança

```typescript
// Config 1
{
  index_name: "logs-apache",
  mcp_server_id: "uuid-log-analyzer",
  priority: 1,  // Primeira ferramenta oferecida
  auto_inject_context: true
}

// Config 2
{
  index_name: "logs-apache",
  mcp_server_id: "uuid-security-scanner",
  priority: 5,  // Segunda ferramenta oferecida
  auto_inject_context: true
}
```

**Resultado**: LLM terá acesso a ferramentas de ambos os MCPs, ordenadas por prioridade.

#### Cenário 3: Desabilitar MCP Temporariamente

```bash
# Desabilitar GVULN MCP para índice "vazamentos"
curl -X PATCH http://localhost:8000/api/v1/index-mcp-config/{config_id} \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_enabled": false}'
```

**Resultado**: MCP não será mais oferecido ao LLM para este índice.

#### Cenário 4: Modo Manual (sem auto-inject)

```typescript
{
  index_name: "vazamentos",
  mcp_server_id: "uuid-gvuln-mcp",
  priority: 10,
  is_enabled: true,
  auto_inject_context: false  // ❌ NÃO injetar automaticamente
}
```

**Resultado**: MCP está configurado mas não será automaticamente oferecido ao LLM. Pode ser usado em lógicas especiais futuras.

## Benefícios

### 1. Elimina Confusão do LLM
- ✅ LLM recebe apenas ferramentas relevantes ao índice
- ✅ Reduz tokens no prompt (menos ferramentas)
- ✅ Melhora precisão das respostas

### 2. Flexibilidade
- ✅ Admin pode configurar MCPs sem alterar código
- ✅ Pode desabilitar temporariamente sem deletar
- ✅ Suporta múltiplos MCPs por índice

### 3. Manutenibilidade
- ✅ Configuração no banco (não hardcoded)
- ✅ Histórico de alterações
- ✅ Fácil debug (logs mostram MCPs carregados)

### 4. Escalabilidade
- ✅ Adicionar novos MCPs sem alterar código
- ✅ Priorização customizável
- ✅ Config JSONB para extensões futuras

## Logs e Debug

O sistema gera logs detalhados:

```
🔍 Loading MCP configs for index 'vazamentos' on server 'uuid-123'
✅ Found 2 MCP configs (priorities: [1, 5])
  🔧 [1] GVULN MCP (auto-inject enabled)
  🔧 [5] SecurityScanner MCP (auto-inject enabled)
🔧 Loading tools from 2 MCP server(s)
📋 Listing tools from MCP server: GVULN MCP
✅ Added 5 tools from GVULN MCP
📋 Listing tools from MCP server: SecurityScanner MCP
✅ Added 3 tools from SecurityScanner MCP
🎯 Total MCP tools available: 8
🤖 Calling LLM with 8 MCP tools...
```

## Troubleshooting

### Problema: MCPs não aparecem no chat

**Checklist**:
1. ✅ MCP está configurado para o índice? (`/api/v1/index-mcp-config/`)
2. ✅ `is_enabled = true`?
3. ✅ `auto_inject_context = true`?
4. ✅ MCP Server está ativo? (`/api/v1/mcp-servers/`)
5. ✅ Logs mostram MCPs sendo carregados? (docker logs)

### Problema: LLM não usa ferramentas

**Possíveis causas**:
1. ❌ Ferramentas não retornam dados (problema no MCP)
2. ❌ System prompt não incentiva uso de ferramentas
3. ❌ LLM não entende quando usar (melhorar descrição da ferramenta)

### Problema: Múltiplos MCPs conflitantes

**Solução**: Usar `priority` para definir ordem:
- MCPs mais específicos = prioridade menor (1-5)
- MCPs genéricos = prioridade maior (6-10)

## Migração Alembic

Tabela criada pela migration:

```bash
alembic revision -m "add_index_mcp_config"
alembic upgrade head
```

**Migration file**: `backend/alembic/versions/XXXXXX_add_index_mcp_config.py`

## Roadmap Futuro

### Funcionalidades Planejadas:
- [ ] Auto-detecção de índice compatível com MCP
- [ ] Sugestões de MCPs baseado em tipo de dados do índice
- [ ] Testes A/B de diferentes configs
- [ ] Analytics: quais MCPs mais usados por índice
- [ ] Configuração por pattern (ex: `logs-*` usa LogAnalyzer MCP)

## Conclusão

O sistema de **MCP por Índice** é essencial para garantir que o LLM use as ferramentas corretas no contexto certo. Ele:

1. ✅ **Resolve confusão**: LLM não precisa decidir entre 50 ferramentas
2. ✅ **Facilita manutenção**: Admins configuram sem alterar código
3. ✅ **Melhora performance**: Menos tokens no prompt
4. ✅ **Flexível**: Suporta cenários complexos (múltiplos MCPs, priorização, etc.)

**Próximos passos**: Testar com diferentes índices e MCPs, ajustar prioridades baseado em feedback real de uso.
