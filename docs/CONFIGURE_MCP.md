# 🚀 Guia Completo: Configurar MCP RSS News com Claude Desktop

## 📋 Sumário

1. [Por que MCP?](#por-que-mcp)
2. [Pré-requisitos](#pré-requisitos)
3. [Instalação](#instalação)
4. [Configuração Claude Desktop](#configuração-claude-desktop)
5. [Testando](#testando)
6. [Troubleshooting](#troubleshooting)

---

## 🎯 Por que MCP?

### Problema Atual (RAG tradicional):
```
User: "Quais notícias de IA de hoje?"
  ↓
Backend: Busca ES → Monta contexto → Envia para LLM
  ↓
LLM: Processa contexto limitado → Responde
```

❌ **Limitações:**
- Context window de ~200k tokens
- LLM não pode refinar busca
- Lógica hard-coded
- Uma busca por vez

### Solução MCP:
```
User: "Quais notícias de IA de hoje?"
  ↓
LLM: Decide chamar search_rss_news(query="IA", days=1)
  ↓
Tool: Acessa ES diretamente → Retorna dados estruturados
  ↓
LLM: Analisa → Se necessário, chama mais tools
  ↓
User: Recebe resposta contextualizada
```

✅ **Vantagens:**
- Sem limite de context (ferramentas retornam dados estruturados)
- LLM controla a busca (pode refinar automaticamente)
- Múltiplas queries em paralelo
- Escalável infinitamente

---

## 📦 Pré-requisitos

### 1. Elasticsearch Rodando
```bash
curl http://localhost:9200/rss-articles/_count
# Deve retornar: {"count": 800, ...}
```

### 2. Python 3.11+
```bash
python3 --version
# Python 3.11.x ou superior
```

### 3. Claude Desktop Instalado
- Download: https://claude.ai/download
- Versão: 0.7.0 ou superior (suporte MCP)

---

## 🔧 Instalação

### Passo 1: Instalar Dependências MCP

```bash
cd /Users/angellocassio/Documents/intelligence-platform/backend

# Criar virtual environment (opcional mas recomendado)
python3 -m venv venv_mcp
source venv_mcp/bin/activate  # macOS/Linux
# ou
venv_mcp\Scripts\activate  # Windows

# Instalar dependências
pip install mcp requests python-dateutil elasticsearch
```

### Passo 2: Testar Servidor MCP

```bash
python3 mcp_rss_server.py
```

Você deve ver:
```
✅ Conectado ao Elasticsearch: localhost:9200
   Version: 9.0.0
   Índice 'rss-articles': 800 documentos
🚀 Iniciando MCP RSS News Intelligence Server...
🛠️ Ferramentas disponíveis:
  - ping: Health check
  - search_rss_news: Busca notícias com filtros avançados
  ...
```

Pressione `Ctrl+C` para parar.

---

## ⚙️ Configuração Claude Desktop

### Passo 1: Localizar Arquivo de Configuração

**macOS:**
```bash
mkdir -p ~/Library/Application\ Support/Claude/
touch ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Windows:**
```powershell
New-Item -ItemType Directory -Path "$env:APPDATA\Claude" -Force
New-Item -ItemType File -Path "$env:APPDATA\Claude\claude_desktop_config.json" -Force
```

### Passo 2: Editar Configuração

Abra o arquivo `claude_desktop_config.json` e adicione:

```json
{
  "mcpServers": {
    "rss-news-intelligence": {
      "command": "python3",
      "args": [
        "/Users/angellocassio/Documents/intelligence-platform/backend/mcp_rss_server.py"
      ],
      "env": {
        "ES_HOST": "localhost",
        "ES_PORT": "9200"
      }
    }
  }
}
```

**⚠️ IMPORTANTE:**
- Use o caminho **completo** para `mcp_rss_server.py`
- Se estiver usando virtual environment, use o caminho completo do Python:
  ```json
  "command": "/Users/angellocassio/Documents/intelligence-platform/backend/venv_mcp/bin/python3"
  ```

### Passo 3: Reiniciar Claude Desktop

1. **Feche completamente** o Claude Desktop (Cmd+Q no macOS)
2. Abra novamente

### Passo 4: Verificar Conexão

No Claude Desktop, você deve ver:
- 🔌 Ícone de "plugs" no canto inferior (indicando MCP ativo)
- Ao clicar, deve mostrar "rss-news-intelligence" com status "connected"

---

## 🧪 Testando

### Teste 1: Health Check

No Claude Desktop, pergunte:
```
Você tem acesso às ferramentas MCP de notícias RSS?
```

O Claude deve listar as ferramentas disponíveis.

### Teste 2: Busca Simples

```
Quais são as últimas 5 notícias de Inteligência Artificial?
```

O Claude deve chamar `get_latest_news(category="Inteligência Artificial", limit=5)`.

### Teste 3: Busca com Filtros

```
Mostre notícias sobre ransomware dos últimos 3 dias
```

O Claude deve chamar `search_rss_news(query="ransomware", days=3)`.

### Teste 4: Estatísticas

```
Quais foram as estatísticas de notícias esta semana?
```

O Claude deve chamar `get_rss_stats(days=7)`.

### Teste 5: Análise Complexa

```
Compare o volume de notícias de IA vs Segurança nos últimos 30 dias
```

O Claude deve:
1. Chamar `get_rss_stats(days=30)` para visão geral
2. Chamar `search_rss_news(categories=["Inteligência Artificial"], days=30)`
3. Chamar `search_rss_news(categories=["Segurança da Informação"], days=30)`
4. Analisar e comparar

---

## 🐛 Troubleshooting

### Problema: Claude não encontra o servidor MCP

**Sintomas:**
- Claude diz "Não tenho acesso a ferramentas MCP"
- Ícone de plug não aparece

**Soluções:**

1. **Verificar logs do MCP:**

   macOS:
   ```bash
   tail -f ~/Library/Logs/Claude/mcp*.log
   ```

   Windows:
   ```powershell
   Get-Content -Path "$env:APPDATA\Claude\mcp*.log" -Wait
   ```

2. **Verificar permissões:**
   ```bash
   chmod +x /Users/angellocassio/Documents/intelligence-platform/backend/mcp_rss_server.py
   ```

3. **Testar Python path:**
   ```bash
   which python3
   # Use este path exato no claude_desktop_config.json
   ```

4. **Verificar se ES está acessível:**
   ```bash
   curl http://localhost:9200/rss-articles/_count
   ```

### Problema: Erro "ModuleNotFoundError: No module named 'mcp'"

**Solução:**
```bash
# Ative o virtual environment correto
source /Users/angellocassio/Documents/intelligence-platform/backend/venv_mcp/bin/activate

# Reinstale dependências
pip install mcp requests python-dateutil elasticsearch

# Use o path completo do Python no config
which python3
# Copie esse path para claude_desktop_config.json
```

### Problema: Elasticsearch connection refused

**Sintomas:**
```
❌ Erro de conexão com ES: Connection refused
```

**Soluções:**

1. **Verificar se ES está rodando:**
   ```bash
   docker compose ps | grep elasticsearch
   # ou
   brew services list | grep elasticsearch
   ```

2. **Verificar porta:**
   ```bash
   lsof -i :9200
   ```

3. **Se ES está em Docker, usar `host.docker.internal`:**
   ```json
   "env": {
     "ES_HOST": "host.docker.internal",
     "ES_PORT": "9200"
   }
   ```

### Problema: Ferramentas funcionam mas retornam erro

**Debug:**
```bash
# Rodar MCP server manualmente com logs
python3 mcp_rss_server.py 2> /tmp/mcp_debug.log

# Em outra janela, trigger a query no Claude Desktop

# Ver logs
cat /tmp/mcp_debug.log
```

### Problema: Claude diz "Tool returned empty results"

**Causas possíveis:**
1. Índice RSS vazio - verificar: `curl http://localhost:9200/rss-articles/_count`
2. Query muito específica - tentar query mais ampla
3. Date filter muito restrito - aumentar `days`

**Teste direto:**
```python
python3
>>> from mcp_rss_server import search_rss_news, get_rss_stats
>>> print(get_rss_stats(days=30))
>>> print(search_rss_news(query="AI", days=7))
```

---

## 📊 Exemplos Avançados

### Análise de Tendências
```
Quais tópicos estão em alta no último mês? Me dê um ranking.
```

Claude deve chamar `analyze_trending_topics(days=30)` e formatar os resultados.

### Comparação Temporal
```
Compare as notícias de hoje com as de ontem
```

Claude deve:
1. Chamar `get_news_by_date(date="2025-11-15")`
2. Chamar `get_news_by_date(date="2025-11-14")`
3. Comparar e analisar diferenças

### Análise por Fonte
```
Qual fonte publica mais sobre vulnerabilidades?
```

Claude deve:
1. Chamar `get_sources_summary()` para ver todas as fontes
2. Chamar `search_rss_news(query="vulnerabilidade OR vulnerability", days=30)`
3. Agrupar por fonte e rankear

### Deep Dive em Tópico
```
Me dê um relatório completo sobre ransomware nos últimos 15 dias
```

Claude deve:
1. Chamar `search_rss_news(query="ransomware", days=15, limit=50)`
2. Chamar `analyze_trending_topics(days=15)` para ver tags relacionadas
3. Compilar relatório executivo

---

## 🎯 Próximos Passos

### Integração com Frontend (Futuro)

Duas opções:

**Opção 1: Claude Desktop como Interface Principal**
- Usuários usam Claude Desktop diretamente
- Frontend atual vira "manager" de configurações RSS
- Vantagem: Melhor UX, capacidades completas da LLM

**Opção 2: MCP via API (Wrapper)**
- Criar endpoint `/api/v1/mcp/chat` que:
  1. Recebe query do frontend
  2. Chama MCP server internamente
  3. Retorna resposta formatada
- Vantagem: Mantém interface web atual

### Adicionando Mais Ferramentas

Para adicionar novas capabilities:

1. Editar `mcp_rss_server.py`
2. Adicionar função com `@mcp.tool()`:
   ```python
   @mcp.tool()
   def my_new_tool(param: str) -> Dict[str, Any]:
       """Documentação que a LLM lerá"""
       # Implementação
       return {"result": "data"}
   ```
3. Reiniciar Claude Desktop

### Monitoramento

Adicionar telemetria no MCP server:
```python
import time

@mcp.tool()
def search_rss_news(...):
    start_time = time.time()
    result = # ... implementação
    duration = time.time() - start_time
    logger.info(f"search_rss_news took {duration:.2f}s")
    return result
```

---

## 📚 Recursos

- [MCP Documentation](https://modelcontextprotocol.io/)
- [Claude Desktop MCP Guide](https://docs.anthropic.com/claude/docs/model-context-protocol)
- [FastMCP GitHub](https://github.com/jlowin/fastmcp)
- [Intelligence Platform Backend](./backend/)

---

## ✅ Checklist de Configuração

- [ ] Python 3.11+ instalado
- [ ] Elasticsearch rodando e acessível
- [ ] Dependências MCP instaladas (`pip install mcp...`)
- [ ] MCP server testado manualmente (roda sem erros)
- [ ] `claude_desktop_config.json` criado com path correto
- [ ] Claude Desktop reiniciado
- [ ] Ícone de plug aparece no Claude Desktop
- [ ] Teste básico funcionou ("Quais as últimas notícias?")
- [ ] Ferramentas listadas corretamente ao perguntar

---

## 🆘 Suporte

Se encontrar problemas:

1. Verificar logs: `~/Library/Logs/Claude/mcp*.log` (macOS)
2. Testar MCP server standalone: `python3 mcp_rss_server.py`
3. Verificar ES: `curl localhost:9200/rss-articles/_count`
4. Criar issue no repositório com logs completos

**Informações úteis para debug:**
- Sistema operacional
- Versão do Python: `python3 --version`
- Versão do Claude Desktop
- Conteúdo de `claude_desktop_config.json`
- Logs do MCP server
- Output de `curl localhost:9200/rss-articles/_count`
