# ✅ Integração GVULN MCP - Completa

## Resumo

O servidor MCP GVULN foi **integrado com sucesso** ao dashboard usando a **Opção 1 (STDIO)**. O servidor agora está disponível dentro do container Docker do backend e pode ser configurado via interface web.

## O que foi implementado

### 1. **Dockerfile Backend** - Atualizado
- ✅ Adicionadas dependências Python: `mcp` e `plotly`
- ✅ Criado diretório `/app/mcp/gvuln_mcp/` no container
- ✅ Copiados arquivos do servidor MCP

### 2. **Script MCP GVULN** - Adaptado
- ✅ Shebang alterado de path específico para `#!/usr/bin/env python3`
- ✅ Configuração via variáveis de ambiente (`ES_URL`, `ES_IDX`)
- ✅ Logs de inicialização para debug
- ✅ Permissão de execução configurada

### 3. **Container Docker** - Rebuildo
- ✅ Backend rebuildo com novas dependências
- ✅ Container recriado com nova imagem
- ✅ Verificado: MCP e Plotly instalados corretamente
- ✅ Script executável e funcionando

## Como configurar via UI

### Passo 1: Acessar Settings → MCP Servers

1. Abra o dashboard no navegador
2. Vá para **Settings** (Configurações)
3. Clique na aba **MCP Servers**
4. Clique no botão **"Adicionar Servidor MCP"**

### Passo 2: Preencher o formulário

Configure o servidor MCP com os seguintes dados:

| Campo | Valor |
|-------|-------|
| **Nome** | `GVULN` |
| **Tipo** | `stdio` |
| **Comando** | `/app/mcp/gvuln_mcp/mcp_gvuln_server.py` |
| **Argumentos** | (deixar vazio) |
| **Variáveis de Ambiente** | Ver abaixo |

**Variáveis de Ambiente (clique em "Adicionar Variável"):**

```
ES_URL=http://host.docker.internal:9200
ES_IDX=tickets_enviados_jira
```

**Ou, se o Elasticsearch estiver em outro servidor:**

```
ES_URL=http://SEU_SERVIDOR_ELASTICSEARCH:9200
ES_IDX=tickets_enviados_jira
```

### Passo 3: Salvar e ativar

1. Clique em **"Salvar"**
2. Verifique se o servidor aparece na lista
3. Marque como **ativo** (checkbox `is_active`)
4. O servidor estará disponível para uso

## Ferramentas disponíveis

O servidor GVULN MCP possui **13 ferramentas** para análise de vulnerabilidades:

### Ferramentas de Overview

| Ferramenta | Descrição |
|------------|-----------|
| `health_check` | Verifica conectividade com Elasticsearch |
| `get_top_squad` | Top 10 squads com mais tickets |
| `get_top_remediation` | Top 15 remediações que resolvem mais tickets |
| `get_tickets_by_priority` | Distribuição por prioridade (P1, P2, P3, P4) |
| `get_tickets_by_severity` | Distribuição por severidade (CRITICAL, HIGH, MEDIUM, LOW) |

### Ferramentas de Assets

| Ferramenta | Descrição |
|------------|-----------|
| `get_most_critical_asset` | Ativo mais crítico (CVSS + EPSS) |
| `get_asset_with_most_tickets` | Top 10 ativos com mais tickets |
| `get_asset_with_most_vulnerabilities` | Top 10 ativos com mais vulnerabilidades |
| `search_tickets_by_hostname` | Buscar tickets de um hostname específico |

### Ferramentas de Análise

| Ferramenta | Descrição |
|------------|-----------|
| `get_cisa_kev_tickets` | Tickets com CVEs no CISA KEV (exploited) |
| `get_action_plan_for_remediation` | Plano de ação para remediação específica |
| `get_squad_summary` | Resumo completo de um squad |
| `generate_full_dashboard` | Dashboard completo com 15+ visualizações |

## Testando o servidor

### Teste 1: Health Check

Após configurar, teste via chat:

```
Use o GVULN para verificar a saúde do servidor
```

**Resposta esperada:**
```
✅ Conectado ao Elasticsearch: http://host.docker.internal:9200
✅ Índice: tickets_enviados_jira
✅ Status: OK
```

### Teste 2: Top Squads

```
Mostre os top 10 squads com mais tickets de vulnerabilidade
```

**Resposta esperada:**
```
🏆 Top 10 Squads por Número de Tickets:

Squad_Infra_Basica  │ ████████████████████████████████ 45,123 (34.2%)
Squad_Cloud         │ ████████████████████ 32,456 (24.6%)
Squad_Database      │ ████████████████ 28,789 (21.8%)
...
```

### Teste 3: Distribuição de Severidade

```
Como estão distribuídos os tickets por severidade?
```

**Resposta esperada:**
```
🎯 Distribuição de Tickets por Severidade:

┌────────────────────────────────────────────────────────────┐
│ CRITICAL        ████████ 12,345 (5.2%)                     │
│ HIGH            ██████████████████████ 56,789 (24.1%)      │
│ MEDIUM          ████████████████████████████ 78,901 (33.5%)│
│ LOW             ██████████████████████████████ 87,234 (37.1%)│
└────────────────────────────────────────────────────────────┘

TOTAL: 235,269 tickets
```

## Estrutura de arquivos

```
/app/mcp/gvuln_mcp/
├── mcp_gvuln_server.py   # Servidor MCP principal (executável)
└── README.md             # Documentação original do GVULN
```

## Variáveis de ambiente suportadas

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `ES_URL` | URL do Elasticsearch | `http://localhost:9200` |
| `ES_IDX` | Nome do índice | `tickets_enviados_jira` |

## Características técnicas

- **Protocolo**: STDIO (stdin/stdout)
- **Linguagem**: Python 3.11
- **Dependências**: `mcp`, `requests`, `plotly`
- **Gráficos**: ASCII art + Plotly HTML (opcional)
- **Timeout**: 30 segundos por query
- **Máximo de documentos**: 1000 por busca (configurável)

## Logs e debug

### Ver logs do servidor MCP

```bash
docker logs dashboard-ai-backend 2>&1 | grep "GVULN MCP"
```

**Saída esperada:**
```
[GVULN MCP] Iniciando servidor...
[GVULN MCP] Elasticsearch URL: http://host.docker.internal:9200
[GVULN MCP] Índice: tickets_enviados_jira
```

### Testar execução manual

Entre no container e execute o servidor:

```bash
docker exec -it dashboard-ai-backend bash
cd /app/mcp/gvuln_mcp
./mcp_gvuln_server.py
```

O servidor ficará aguardando input no stdin (protocolo MCP).

## Troubleshooting

### Erro: "Connection refused" ao Elasticsearch

**Problema**: O container não consegue conectar ao Elasticsearch.

**Solução**: Verifique a variável `ES_URL`:

- Se Elasticsearch está na **mesma máquina** (localhost): use `http://host.docker.internal:9200`
- Se está em **servidor remoto**: use `http://IP_DO_SERVIDOR:9200`
- Se está em **outro container Docker**: use `http://nome-do-container:9200`

### Erro: "Index not found"

**Problema**: O índice `tickets_enviados_jira` não existe.

**Solução**:
1. Verifique se o índice existe no Elasticsearch
2. Ajuste a variável `ES_IDX` para o nome correto do índice
3. Se necessário, restaure o índice do backup disponível em `/Users/angellocassio/Downloads/gvuln_atual/gvuln_mcp/backup_tickets_enviados_jira_*`

### Erro: "Tool execution failed"

**Problema**: Ferramenta retorna erro genérico.

**Solução**:
1. Verifique logs do backend: `docker logs dashboard-ai-backend`
2. Teste health_check primeiro para verificar conectividade
3. Verifique se o índice tem os campos esperados

### Erro: "Permission denied" ao executar script

**Problema**: Script não tem permissão de execução.

**Solução**:
```bash
docker exec dashboard-ai-backend chmod +x /app/mcp/gvuln_mcp/mcp_gvuln_server.py
```

## Próximos passos (Opcional)

### 1. Adicionar mais MCP servers

Você pode adicionar outros servidores MCP da mesma forma:

1. Copie o código para `/app/mcp/<nome-do-servidor>/`
2. Configure via Settings → MCP Servers
3. Teste via chat

### 2. Conectar a outras bases de dados

O GVULN pode ser adaptado para outros índices:

```
ES_URL=http://host.docker.internal:9200
ES_IDX=seu-outro-indice
```

### 3. Criar dashboards personalizados

Use a ferramenta `generate_full_dashboard` para gerar visualizações:

```
Gere um dashboard completo das vulnerabilidades dos últimos 30 dias
```

## Integração com Knowledge Base

Você pode criar documentos de conhecimento que explicam como usar o GVULN:

**Exemplo de Knowledge Document:**

```markdown
Título: Como Analisar Vulnerabilidades com GVULN
Categoria: troubleshooting
Tags: vulnerabilities, gvuln, security

# Análise de Vulnerabilidades GVULN

O servidor MCP GVULN permite analisar tickets de vulnerabilidades.

## Principais ferramentas:

1. **health_check** - Verificar conectividade
2. **get_top_squad** - Ver squads com mais trabalho
3. **get_tickets_by_severity** - Ver distribuição de criticidade
4. **get_most_critical_asset** - Encontrar ativo mais crítico

## Exemplo de análise:

1. Verificar saúde: "Use GVULN para health check"
2. Ver distribuição: "Mostre distribuição por severidade"
3. Identificar prioridades: "Quais são os ativos mais críticos?"
```

## Conclusão

🎉 **O servidor MCP GVULN está totalmente integrado e pronto para uso!**

**Configuração necessária:**
1. Adicionar servidor via Settings → MCP Servers
2. Configurar variáveis `ES_URL` e `ES_IDX`
3. Ativar o servidor

**Uso:**
- Via chat: "Use o GVULN para..."
- 13 ferramentas disponíveis
- Gráficos ASCII e Plotly
- Análise completa de vulnerabilidades

**Suporte:**
- Logs: `docker logs dashboard-ai-backend`
- Teste manual: `docker exec -it dashboard-ai-backend /app/mcp/gvuln_mcp/mcp_gvuln_server.py`
- Documentação: Este arquivo e `/app/mcp/gvuln_mcp/README.md`
