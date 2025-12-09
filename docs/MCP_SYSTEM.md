# Sistema de Model Context Protocol (MCP)

## Visão Geral

O Dashboard AI v2.0 agora suporta integração completa com servidores MCP (Model Context Protocol), permitindo expandir as capacidades da IA com ferramentas externas como acesso a filesystem, GitHub, PostgreSQL e muito mais.

## Arquitetura

### Componentes

1. **Backend (FastAPI)**
   - Model: `MCPServer` (app/models/mcp_server.py)
   - API: `/api/v1/mcp-servers` e `/api/v1/mcp`
   - Executor: `MCPExecutor` (app/services/mcp_executor.py)

2. **Frontend (React + TypeScript)**
   - Component: `MCPManager` (frontend/src/components/MCPManager.tsx)
   - Settings Page: Nova aba "MCP Servers"

3. **Docker**
   - Node.js 20.x instalado no backend container
   - Volume `/mcp-data` para dados compartilhados
   - MCPs pré-instalados: filesystem, github, postgres

### Tipos de MCP Suportados

#### 1. STDIO (Standard Input/Output)
- Executa MCPs como subprocessos
- Comunicação via stdin/stdout usando JSON-RPC 2.0
- Exemplo: filesystem MCP via npx

#### 2. HTTP (REST API)
- MCPs expostos como servidores HTTP
- Comunicação via POST requests JSON-RPC
- Exemplo: MCP server rodando em http://localhost:3000

#### 3. SSE (Server-Sent Events)
- MCPs com streaming de eventos
- Útil para operações de longa duração
- Comunicação bidirecional

## Instalação

### MCPs Pré-instalados (Docker)

O Dockerfile já inclui:

**Python-based:**
- `mcp-server-git` - Operações Git
- `httpx` - Cliente HTTP

**Node.js-based:**
- `@modelcontextprotocol/server-filesystem` - Operações de arquivo
- `@modelcontextprotocol/server-github` - Integração GitHub
- `@modelcontextprotocol/server-postgres` - Acesso PostgreSQL

### Adicionar Novos MCPs

#### Via Frontend (Settings → MCP Servers)

1. Clique em "Add MCP Server"
2. Preencha os campos:
   - **Name**: Nome único do servidor
   - **Type**: STDIO, HTTP ou SSE
   - **Description**: Descrição opcional

**Para STDIO:**
- **Command**: Comando executável (ex: `npx`, `python3`, `node`)
- **Args**: Argumentos do comando (ex: `["-y", "@modelcontextprotocol/server-filesystem", "/mcp-data"]`)
- **Env**: Variáveis de ambiente (JSON)

**Para HTTP/SSE:**
- **URL**: Endpoint do servidor MCP (ex: `http://localhost:3000`)

#### Via API (cURL)

```bash
curl -X POST http://localhost:8000/api/v1/mcp-servers/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "filesystem-prod",
    "type": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
    "description": "Production filesystem access",
    "is_active": true
  }'
```

## API Endpoints

### Gerenciamento de Servidores

#### Listar Servidores
```bash
GET /api/v1/mcp-servers/
```

#### Criar Servidor
```bash
POST /api/v1/mcp-servers/
Content-Type: application/json

{
  "name": "my-mcp",
  "type": "stdio",
  "command": "npx",
  "args": [...],
  "description": "...",
  "is_active": true
}
```

#### Obter Servidor
```bash
GET /api/v1/mcp-servers/{server_id}
```

#### Atualizar Servidor
```bash
PATCH /api/v1/mcp-servers/{server_id}
Content-Type: application/json

{
  "is_active": false
}
```

#### Deletar Servidor
```bash
DELETE /api/v1/mcp-servers/{server_id}
```

### Execução de Ferramentas

#### Listar Ferramentas Disponíveis
```bash
GET /api/v1/mcp/{server_id}/tools
```

Resposta:
```json
{
  "server_id": "...",
  "server_name": "filesystem-test",
  "tools": [
    {
      "name": "read_file",
      "description": "Read file contents",
      "inputSchema": {...}
    },
    ...
  ]
}
```

#### Executar Ferramenta
```bash
POST /api/v1/mcp/execute
Content-Type: application/json

{
  "server_id": "...",
  "tool_name": "read_file",
  "arguments": {
    "path": "/mcp-data/test.txt"
  }
}
```

Resposta:
```json
{
  "server_id": "...",
  "tool_name": "read_file",
  "result": [
    {
      "type": "text",
      "text": "File contents here..."
    }
  ]
}
```

#### Testar Conexão
```bash
GET /api/v1/mcp/test/{server_id}
```

Resposta:
```json
{
  "status": "success",
  "server_id": "...",
  "server_name": "filesystem-test",
  "server_type": "stdio",
  "tools_count": 14,
  "message": "Successfully connected to filesystem-test. Found 14 tools."
}
```

## Exemplos de Uso

### 1. Filesystem MCP

**Criar servidor:**
```json
{
  "name": "filesystem-data",
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/mcp-data"],
  "description": "Access to /mcp-data directory"
}
```

**Ferramentas disponíveis:**
- `read_text_file` - Ler arquivo texto
- `write_file` - Escrever arquivo
- `list_directory` - Listar diretório
- `search_files` - Buscar arquivos
- `get_file_info` - Metadados do arquivo
- E mais 9 ferramentas...

**Exemplo de uso:**
```bash
# Escrever arquivo
POST /api/v1/mcp/execute
{
  "server_id": "...",
  "tool_name": "write_file",
  "arguments": {
    "path": "/mcp-data/config.json",
    "content": "{\"env\": \"production\"}"
  }
}

# Ler arquivo
POST /api/v1/mcp/execute
{
  "server_id": "...",
  "tool_name": "read_text_file",
  "arguments": {
    "path": "/mcp-data/config.json"
  }
}
```

### 2. GitHub MCP

**Criar servidor:**
```json
{
  "name": "github-integration",
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-github"],
  "env": {
    "GITHUB_TOKEN": "ghp_your_token_here"
  },
  "description": "GitHub API integration"
}
```

**Ferramentas típicas:**
- `create_or_update_file` - Criar/atualizar arquivo no repo
- `search_repositories` - Buscar repositórios
- `create_issue` - Criar issue
- `create_pull_request` - Criar PR
- `get_file_contents` - Ler arquivo do repo

### 3. PostgreSQL MCP

**Criar servidor:**
```json
{
  "name": "postgres-analytics",
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-postgres"],
  "env": {
    "POSTGRES_CONNECTION_STRING": "postgresql://user:pass@host:5432/db"
  },
  "description": "PostgreSQL analytics database"
}
```

**Ferramentas típicas:**
- `query` - Executar SQL query
- `list_tables` - Listar tabelas
- `describe_table` - Descrever schema de tabela

### 4. Custom HTTP MCP

**Criar servidor:**
```json
{
  "name": "custom-api",
  "type": "http",
  "url": "http://my-mcp-server:3000/mcp",
  "description": "Custom MCP server"
}
```

## Integração com Chat IA

Os MCPs podem ser integrados ao chat do Dashboard AI para expandir as capacidades do LLM:

1. **Auto-discovery**: LLM pode listar MCPs disponíveis
2. **Tool calling**: LLM pode chamar ferramentas MCP durante conversa
3. **Context enrichment**: MCPs fornecem contexto adicional (arquivos, dados, etc.)

**Fluxo de exemplo:**
```
User: "Analise os logs de erro de ontem"

LLM: [Chama filesystem MCP]
  → read_text_file("/mcp-data/logs/error-2025-11-07.log")

MCP: [Retorna conteúdo]
  → "2025-11-07 10:30:15 ERROR: Database connection timeout..."

LLM: [Analisa e responde]
  → "Encontrei 15 erros de timeout no banco de dados ontem..."
```

## Segurança

### Filesystem MCP
- **Sandbox**: MCPs só acessam diretórios permitidos
- **No sistema**: `/mcp-data` é um volume Docker isolado
- **Validação**: Todos os paths são validados antes da execução

### API Keys e Credenciais
- **Environment variables**: Use `env` field para passar credenciais
- **Nunca em logs**: Credenciais nunca aparecem em logs
- **PostgreSQL**: Armazene API keys criptografadas se necessário

### Execução
- **Timeout**: MCPs têm timeout de 30s por padrão
- **Isolamento**: Cada execução é um processo separado
- **Error handling**: Erros são capturados e logados

## Troubleshooting

### MCP não encontrado
```
Error: mcp-server-xxx not found
```
**Solução**: Reconstruir container Docker
```bash
docker compose build backend
docker compose up -d backend
```

### Timeout na execução
```
Error: MCP server timeout
```
**Solução**: Aumentar timeout em `mcp_executor.py` ou verificar comando/args

### Permission denied
```
Error: EACCES permission denied
```
**Solução**:
- Verificar permissões do diretório
- Usar volume Docker correto
- Verificar usuário do container

### JSON-RPC error
```
Error: MCP error: {"code": -32600, "message": "Invalid Request"}
```
**Solução**: Verificar formato dos argumentos da ferramenta

## Desenvolvimento

### Adicionar Novo MCP ao Docker

1. Editar `backend/Dockerfile`:
```dockerfile
# Python MCP
RUN pip install --no-cache-dir mcp-server-custom

# Node.js MCP
RUN npm install -g @org/mcp-server-custom
```

2. Rebuild:
```bash
docker compose build backend
docker compose up -d backend
```

### Criar MCP Customizado

Consulte documentação oficial: https://modelcontextprotocol.io

**Estrutura básica (Node.js):**
```javascript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';

const server = new Server({
  name: 'my-custom-mcp',
  version: '1.0.0'
});

server.setRequestHandler('tools/list', async () => ({
  tools: [
    {
      name: 'my_tool',
      description: 'My custom tool',
      inputSchema: {...}
    }
  ]
}));

server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;
  // Execute tool logic
  return { content: [...] };
});
```

## Limitações Atuais

1. **Concorrência**: MCPs STDIO executam 1 por vez (podem ser paralelizados se necessário)
2. **Streaming**: SSE ainda não totalmente implementado
3. **Caching**: Resultados não são cacheados (pode ser adicionado com Redis)
4. **Rate limiting**: Sem rate limiting por servidor (pode ser necessário)

## Roadmap

- [ ] Cache de resultados MCP com Redis
- [ ] Rate limiting por servidor MCP
- [ ] Logs estruturados de execução
- [ ] Métricas (tempo de execução, taxa de erro)
- [ ] UI para visualizar logs de execução
- [ ] Suporte a prompts MCP
- [ ] Suporte a resources MCP
- [ ] Auto-restart de MCPs falhados
- [ ] Health checks periódicos

## Referências

- [MCP Specification](https://modelcontextprotocol.io)
- [MCP SDK](https://github.com/modelcontextprotocol/sdk)
- [Official MCP Servers](https://github.com/modelcontextprotocol/servers)
