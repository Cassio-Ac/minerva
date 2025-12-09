# 🚀 MCP RSS News Intelligence Server

Servidor MCP (Model Context Protocol) que permite que LLMs acessem diretamente o Elasticsearch de notícias RSS através de ferramentas especializadas.

## 🎯 Por que MCP é melhor que RAG tradicional?

### ❌ Abordagem RAG Antiga (problema atual):
1. Backend faz busca no Elasticsearch
2. Backend monta contexto manualmente
3. Backend envia contexto massivo para LLM
4. LLM processa e responde
5. **Problemas**:
   - Context window limitado
   - LLM não pode refinar busca
   - Lógica hard-coded no backend

### ✅ Abordagem MCP (nova):
1. User pergunta: "Quais as notícias de IA de hoje?"
2. LLM decide chamar: `search_rss_news(query="inteligência artificial", days=1)`
3. Tool retorna dados estruturados do ES
4. LLM processa e pode chamar mais tools se necessário
5. **Vantagens**:
   - ✅ LLM controla a busca
   - ✅ Múltiplas queries automáticas
   - ✅ Dados estruturados
   - ✅ Escalável

## 🛠️ Ferramentas Disponíveis

### 1. `search_rss_news`
Busca avançada de notícias com filtros

**Parâmetros:**
- `query` (str): Texto para buscar
- `categories` (List[str]): Filtrar por categorias
- `sources` (List[str]): Filtrar por fontes
- `days` (int): Últimos N dias (padrão: 7)
- `limit` (int): Máximo de resultados (padrão: 20)

**Exemplo de uso pela LLM:**
```
User: "Quais são as últimas notícias sobre IA?"
LLM chama: search_rss_news(query="inteligência artificial", days=3)
```

### 2. `get_rss_stats`
Estatísticas de notícias coletadas

**Parâmetros:**
- `days` (int): Período em dias (padrão: 30)

**Retorna:**
- Total de artigos
- Distribuição por categoria
- Top fontes
- Timeline diária

### 3. `get_latest_news`
Últimas notícias, opcionalmente por categoria

**Parâmetros:**
- `category` (str): Categoria opcional
- `limit` (int): Número de notícias (padrão: 10)

### 4. `get_news_by_date`
Notícias de data específica

**Parâmetros:**
- `date` (str): Data YYYY-MM-DD
- `category` (str): Categoria opcional

### 5. `get_sources_summary`
Resumo de fontes RSS

**Retorna:**
- Lista de fontes com contagem
- Categorias disponíveis

### 6. `analyze_trending_topics`
Tópicos em alta baseado em tags

**Parâmetros:**
- `days` (int): Período (padrão: 7)
- `top_n` (int): Número de tópicos (padrão: 20)

## 📦 Instalação

### 1. Instalar dependências
```bash
pip install mcp requests python-dateutil elasticsearch
```

### 2. Configurar variáveis de ambiente (opcional)
```bash
export ES_HOST=localhost
export ES_PORT=9200
```

### 3. Testar o servidor
```bash
cd /Users/angellocassio/Documents/intelligence-platform/backend
python mcp_rss_server.py
```

## 🔧 Integração com Claude Desktop

### 1. Localizar arquivo de configuração
**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

### 2. Adicionar configuração MCP

Edite o arquivo `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rss-news": {
      "command": "python",
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

### 3. Reiniciar Claude Desktop

Após salvar a configuração, reinicie o Claude Desktop. O servidor MCP será iniciado automaticamente quando você abrir o Claude.

### 4. Verificar funcionamento

No Claude Desktop, pergunte:
- "Quais são as últimas notícias de IA?"
- "Me mostre estatísticas de notícias da última semana"
- "Quais foram as notícias mais importantes ontem?"

O Claude irá automaticamente chamar as ferramentas MCP apropriadas!

## 🐛 Troubleshooting

### Logs do MCP Server

Os logs vão para `stderr`. Para debugar:

```bash
python mcp_rss_server.py 2> mcp_rss.log
```

### Verificar conectividade ES

```bash
curl http://localhost:9200/rss-articles/_count
```

Deve retornar o número de documentos no índice.

### Testar tool manualmente

O MCP Server usa stdio, mas você pode testar as funções diretamente:

```python
python
>>> from mcp_rss_server import search_rss_news
>>> result = search_rss_news(query="AI", days=3)
>>> print(result)
```

## 🔄 Integração com Backend Atual

### Opção 1: Substituir endpoint `/chat` (recomendado)

Atualizar o frontend para usar Claude Desktop com MCP ao invés do endpoint REST.

**Vantagens:**
- LLM acessa ES diretamente
- Sem context window limitations
- LLM pode refinar queries
- Melhor para conversas longas

### Opção 2: Híbrido

Manter endpoint `/chat` para usuários web, mas adicionar botão "Abrir no Claude Desktop" que deeplinks para o MCP.

### Opção 3: MCP via API

Criar wrapper API que chama o MCP server internamente (mais complexo, menos eficiente).

## 📊 Exemplos de Queries

### Análise Comparativa
```
User: "Compare notícias de IA vs Segurança desta semana"
LLM:
1. Chama: search_rss_news(categories=["Inteligência Artificial"], days=7)
2. Chama: search_rss_news(categories=["Segurança da Informação"], days=7)
3. Analisa e compara os resultados
```

### Trend Analysis
```
User: "Quais tópicos estão em alta nos últimos 30 dias?"
LLM:
1. Chama: analyze_trending_topics(days=30)
2. Chama: get_rss_stats(days=30) para contexto
3. Apresenta análise
```

### Deep Dive
```
User: "Me conte sobre as principais notícias de ransomware da semana passada"
LLM:
1. Chama: search_rss_news(query="ransomware", days=7, limit=30)
2. Analisa resultados
3. Se necessário, chama: search_rss_news com query refinada
4. Apresenta resumo executivo
```

## 🎯 Roadmap

### Fase 1 (Atual)
- ✅ Ferramentas básicas de busca
- ✅ Estatísticas
- ✅ Análise de trending topics

### Fase 2
- [ ] Ferramentas de análise de sentimento
- [ ] Entity extraction
- [ ] Cross-reference de notícias
- [ ] Detecção de notícias duplicadas

### Fase 3
- [ ] Multi-índice support (RSS + outros)
- [ ] Alertas personalizados
- [ ] Export de relatórios
- [ ] Integração com vectorstore

## 📚 Referências

- [MCP Documentation](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Claude Desktop MCP](https://docs.anthropic.com/claude/docs/model-context-protocol)
- [Elasticsearch Python Client](https://elasticsearch-py.readthedocs.io/)

## 🤝 Contribuindo

Para adicionar novas ferramentas MCP:

1. Adicionar função com decorator `@mcp.tool()`
2. Documentar parâmetros e uso
3. Testar localmente
4. Atualizar este README

Exemplo:
```python
@mcp.tool()
def my_new_tool(param: str) -> Dict[str, Any]:
    """
    Descrição da ferramenta

    Args:
        param: Descrição do parâmetro

    Returns:
        Descrição do retorno
    """
    # Implementação
    return {"result": "data"}
```

## 📝 License

MIT License - veja LICENSE file
