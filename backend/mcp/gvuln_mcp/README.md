# MCP GVULN - Servidor MCP para Análise de Vulnerabilidades

Servidor MCP (Model Context Protocol) para análise de vulnerabilidades do índice `tickets_enviados_jira` no Elasticsearch.

## 🚀 Instalação

### 1. Dependências

```bash
cd /Users/60004239/Documents/GVULN_MCP
source venv/bin/activate
pip install mcp requests
```

### 2. Configuração no Goose

O servidor já está configurado em `~/.config/goose/config.yaml`:

```yaml
gvuln:
  enabled: true
  type: stdio
  name: gvuln
  description: 'Análise de vulnerabilidades do GVULN - tickets_enviados_jira'
  cmd: /Users/60004239/Documents/GVULN_MCP/mcp_gvuln_server.py
  args: []
  envs:
    ES_URL: http://localhost:9200
    ES_IDX: tickets_enviados_jira
  env_keys: []
  timeout: 300
```

### 3. Reiniciar o Goose

Após adicionar a configuração, reinicie o Goose Desktop para carregar o novo servidor MCP.

---

## 🛠️ Ferramentas Disponíveis

### 1. **health_check**
Verifica conectividade com Elasticsearch

**Exemplo de uso no Goose:**
```
Verifique a saúde do servidor GVULN
```

---

### 2. **get_top_squad**
Retorna os top 10 squads com mais tickets

**Exemplo de uso no Goose:**
```
Mostre os top 10 squads com mais tickets
Quais squads têm mais trabalho?
```

**Saída esperada:**
```
🏆 Top 10 Squads por Número de Tickets:

1. Squad_Infra_Basica: 45,123 tickets
2. Squad_Cloud: 32,456 tickets
3. Squad_Database: 28,789 tickets
...
```

---

### 3. **get_top_remediation**
Retorna as top 15 remediações que resolvem mais tickets

**Exemplo de uso no Goose:**
```
Quais são as remediações mais importantes?
Mostre as remediações que resolvem mais tickets
```

**Saída esperada:**
```
🔧 Top 15 Remediações por Número de Tickets:

1. Update Windows Server 2019: 5,678 tickets
2. Update RHEL 8 kernel: 4,321 tickets
...
```

---

### 4. **get_most_critical_asset**
Retorna o ativo mais crítico baseado em CVSS e EPSS

**Exemplo de uso no Goose:**
```
Qual é o ativo mais crítico?
Mostre o servidor com maior risco
```

**Saída esperada:**
```
🔴 Ativo Mais Crítico:

Hostname: RVACQARNCH01.riachuelo.net
IP Local: 192.168.252.132
IP Externo: 179.190.55.69
CVSS Score: 9.8
EPSS Score: 0.95
Severidade: CRITICAL
Prioridade: P1
Título: Critical RCE vulnerability...
```

---

### 5. **get_asset_with_most_tickets**
Retorna os top 10 ativos com mais tickets

**Exemplo de uso no Goose:**
```
Quais ativos têm mais tickets?
Mostre os servidores com mais vulnerabilidades abertas
```

---

### 6. **get_asset_with_most_vulnerabilities**
Retorna os top 10 ativos com mais vulnerabilidades

**Exemplo de uso no Goose:**
```
Quais ativos têm mais vulnerabilidades?
Mostre os servidores mais vulneráveis
```

---

### 7. **get_tickets_by_priority**
Distribuição de tickets por prioridade (P1, P2, P3, P4)

**Exemplo de uso no Goose:**
```
Como estão distribuídos os tickets por prioridade?
Mostre a distribuição de prioridades
```

**Saída esperada:**
```
📊 Distribuição de Tickets por Prioridade:

P1: 5,234 tickets (2.2%)
P2: 45,678 tickets (19.6%)
P3: 123,456 tickets (53.0%)
P4: 58,774 tickets (25.2%)
```

---

### 8. **get_tickets_by_severity**
Distribuição de tickets por severidade (CRITICAL, HIGH, MEDIUM, LOW)

**Exemplo de uso no Goose:**
```
Como estão distribuídos os tickets por severidade?
Quantos tickets críticos temos?
```

---

### 9. **get_cisa_kev_tickets**
Tickets com CVEs no CISA KEV (Known Exploited Vulnerabilities)

**Exemplo de uso no Goose:**
```
Mostre os tickets com CVEs no CISA KEV
Quais vulnerabilidades estão sendo exploradas ativamente?
```

**Saída esperada:**
```
🚨 Tickets com CVEs no CISA KEV (15 encontrados):

1. RVACQARNCH01.riachuelo.net - CVE-2024-1234 (CRITICAL, CVSS: 9.8)
2. RVACPR0005 - CVE-2024-5678 (HIGH, CVSS: 8.1)
...
```

---

### 10. **get_action_plan_for_remediation**
Gera plano de ação para uma remediação específica

**Parâmetros:**
- `remediation_title` (string): Título da remediação

**Exemplo de uso no Goose:**
```
Me dê um plano de ação para a remediação "Update Windows Server 2019"
Como aplicar o patch "Update RHEL 8 kernel"?
```

**Saída esperada:**
```
📋 Plano de Ação para Remediação:

Título: Update Windows Server 2019
Ação: Install KB5012345
Referência: KB5012345
Prioridade: P2
Severidade Máxima: HIGH
Descrição CVE: Remote code execution vulnerability...
```

---

### 11. **search_tickets_by_hostname**
Busca tickets de um hostname específico

**Parâmetros:**
- `hostname` (string): Nome do host

**Exemplo de uso no Goose:**
```
Busque tickets do hostname RVACQARNCH01.riachuelo.net
Quais vulnerabilidades o servidor RVACPR0005 tem?
```

**Saída esperada:**
```
🔍 Tickets para RVACQARNCH01.riachuelo.net (12 encontrados):

1. HGDV-399812 - Fechado (P2, HIGH)
   CVEs: 4
   Remediação: Update redhat_el8 glibc...

2. HGDV-399813 - Aberto (P1, CRITICAL)
   CVEs: 2
   Remediação: Update kernel...
```

---

### 12. **get_squad_summary**
Resumo completo de um squad específico

**Parâmetros:**
- `squad` (string): Nome do squad

**Exemplo de uso no Goose:**
```
Me dê um resumo do Squad_Infra_Basica
Como está o Squad_Cloud?
```

**Saída esperada:**
```
📊 Resumo do Squad: Squad_Infra_Basica

Total de Tickets: 45,123

Por Prioridade:
  P1: 1,234 (2.7%)
  P2: 8,765 (19.4%)
  P3: 25,432 (56.4%)
  P4: 9,692 (21.5%)

Por Severidade:
  CRITICAL: 567 (1.3%)
  HIGH: 12,345 (27.4%)
  MEDIUM: 23,456 (52.0%)
  LOW: 8,755 (19.4%)

Por Status:
  Aberto: 15,678 (34.7%)
  Fechado: 29,445 (65.3%)
```

---

## 📊 Exemplos de Uso Avançado

### Análise de Risco

```
Quais são os 5 ativos mais críticos e quantos tickets cada um tem?
```

### Planejamento de Patches

```
Quais remediações resolvem mais de 1000 tickets?
Me dê o plano de ação para cada uma delas
```

### Monitoramento de Squads

```
Compare os squads Squad_Infra_Basica e Squad_Cloud
Qual squad tem mais tickets críticos?
```

### Análise de CVEs

```
Mostre todos os tickets com CVEs no CISA KEV
Qual é o ativo mais crítico entre eles?
```

---

## 🔧 Troubleshooting

### Erro: "Tool not found"

Verifique se o servidor está habilitado no config.yaml:
```bash
cat ~/.config/goose/config.yaml | grep -A 15 "gvuln:"
```

### Erro: "Connection refused"

Verifique se o Elasticsearch está rodando:
```bash
curl http://localhost:9200/_cluster/health?pretty
```

### Erro: "No module named 'mcp'"

Reinstale as dependências:
```bash
cd /Users/60004239/Documents/GVULN_MCP
source venv/bin/activate
pip install mcp requests
```

### Ver logs do servidor

Os logs aparecem no console do Goose. Para debug avançado:
```bash
cd /Users/60004239/Documents/GVULN_MCP
source venv/bin/activate
python mcp_gvuln_server.py 2> debug.log
```

---

## 📚 Arquivos do Projeto

```
GVULN_MCP/
├── venv/                           # Ambiente virtual Python
├── mcp_gvuln_server.py            # Servidor MCP principal
├── mcp_gvuln_integrated.py        # Versão antiga com gráficos
├── backup_elasticsearch_index.py  # Script de backup do ES
├── restore_to_local_elk.py        # Script de restauração
├── goose_mcp_config.md            # Documentação de configuração
├── README.md                      # Este arquivo
└── backup_tickets_enviados_jira_20251029_152935/  # Backup do índice
```

---

## 🎯 Próximos Passos

1. **Adicionar mais ferramentas**:
   - Análise temporal (tickets nos últimos 7/30 dias)
   - Exportação de relatórios
   - Comparação entre squads
   - Análise de tendências

2. **Melhorar visualizações**:
   - Gerar gráficos inline
   - Exportar para PDF
   - Dashboards interativos

3. **Integração com Jira**:
   - Criar tickets automaticamente
   - Atualizar status
   - Adicionar comentários

---

## 📞 Suporte

Para dúvidas ou problemas:
1. Verifique os logs do Goose
2. Teste o servidor manualmente
3. Verifique a conectividade com o Elasticsearch

---

**Versão**: 1.0.0  
**Data**: 2025-10-29  
**Autor**: GVULN Team
