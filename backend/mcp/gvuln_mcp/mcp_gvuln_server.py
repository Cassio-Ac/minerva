#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP Server - GVULN (Python 3.10+)
Servidor MCP para análise de vulnerabilidades do índice tickets_enviados_jira

Requisitos:
  pip install mcp requests plotly

Uso:
  python mcp_gvuln_server.py

Configuração via variáveis de ambiente:
  ES_URL: URL do Elasticsearch (default: http://localhost:9200)
  ES_IDX: Nome do índice (default: tickets_enviados_jira)
"""
import sys
import json
import asyncio
from typing import Any, Dict, List
import requests
import os
from datetime import datetime

# Importar MCP SDK
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
except ImportError:
    print("Erro: Instale o MCP SDK: pip install mcp", file=sys.stderr)
    sys.exit(1)

# Importar Plotly
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("Aviso: Plotly não instalado. Apenas gráficos ASCII estarão disponíveis.", file=sys.stderr)

# ===================== CONFIG ============================
# Configuração via variáveis de ambiente com fallback
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_IDX = os.getenv("ES_IDX", "tickets_enviados_jira")
HEADERS = {"Content-Type": "application/json"}
TIMEOUT = 30

# Log de configuração
print(f"[GVULN MCP] Iniciando servidor...", file=sys.stderr)
print(f"[GVULN MCP] Elasticsearch URL: {ES_URL}", file=sys.stderr)
print(f"[GVULN MCP] Índice: {ES_IDX}", file=sys.stderr)

# ===================== UTILS ================================
def search_es(index: str, query: Dict[str, Any], size: int = 1000) -> Dict[str, Any]:
    """Busca documentos no Elasticsearch"""
    try:
        url = f"{ES_URL}/{index}/_search"
        query_copy = dict(query)
        query_copy['size'] = size
        response = requests.post(url, headers=HEADERS, json=query_copy, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"hits": {"hits": []}, "error": str(e)}

def agg_es(index: str, agg_query: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    """Executa agregações no Elasticsearch"""
    try:
        url = f"{ES_URL}/{index}/_search"
        query_copy = dict(agg_query)
        query_copy['size'] = size
        response = requests.post(url, headers=HEADERS, json=query_copy, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"aggregations": {}, "error": str(e)}

def create_bar_chart(data: List[tuple], max_width: int = 50, show_values: bool = True) -> str:
    """
    Cria um gráfico de barras em ASCII art
    
    Args:
        data: Lista de tuplas (label, value)
        max_width: Largura máxima das barras
        show_values: Se deve mostrar os valores numéricos
    
    Returns:
        String com o gráfico em ASCII
    """
    if not data:
        return "Sem dados para exibir"
    
    max_value = max(v for _, v in data)
    if max_value == 0:
        return "Todos os valores são zero"
    
    chart = []
    max_label_len = max(len(str(label)) for label, _ in data)
    
    for label, value in data:
        # Calcular tamanho da barra
        bar_length = int((value / max_value) * max_width)
        bar = "█" * bar_length
        
        # Formatar label
        label_str = str(label).ljust(max_label_len)
        
        # Adicionar valor se solicitado
        if show_values:
            value_str = f"{value:,}"
            chart.append(f"{label_str} │ {bar} {value_str}")
        else:
            chart.append(f"{label_str} │ {bar}")
    
    return "\n".join(chart)

def create_pie_chart(data: List[tuple], width: int = 60) -> str:
    """
    Cria um gráfico de pizza em ASCII art (representação textual)
    
    Args:
        data: Lista de tuplas (label, value)
        width: Largura da visualização
    
    Returns:
        String com o gráfico em ASCII
    """
    if not data:
        return "Sem dados para exibir"
    
    total = sum(v for _, v in data)
    if total == 0:
        return "Todos os valores são zero"
    
    chart = []
    chart.append("┌" + "─" * (width - 2) + "┐")
    
    for label, value in data:
        percentage = (value / total) * 100
        bar_length = int((percentage / 100) * (width - 20))
        bar = "█" * bar_length
        
        label_str = str(label)[:15].ljust(15)
        value_str = f"{value:,}".rjust(8)
        pct_str = f"{percentage:5.1f}%"
        
        chart.append(f"│ {label_str} {bar} {value_str} {pct_str} │")
    
    chart.append("└" + "─" * (width - 2) + "┘")
    
    return "\n".join(chart)

def create_horizontal_bar_chart(data: List[tuple], max_width: int = 40) -> str:
    """
    Cria um gráfico de barras horizontais com percentuais
    
    Args:
        data: Lista de tuplas (label, value)
        max_width: Largura máxima das barras
    
    Returns:
        String com o gráfico em ASCII
    """
    if not data:
        return "Sem dados para exibir"
    
    total = sum(v for _, v in data)
    if total == 0:
        return "Todos os valores são zero"
    
    max_value = max(v for _, v in data)
    max_label_len = max(len(str(label)) for label, _ in data)
    
    chart = []
    for label, value in data:
        percentage = (value / total) * 100
        bar_length = int((value / max_value) * max_width)
        bar = "█" * bar_length
        
        label_str = str(label).ljust(max_label_len)
        value_str = f"{value:,}".rjust(10)
        pct_str = f"({percentage:5.1f}%)"
        
        chart.append(f"{label_str} │ {bar} {value_str} {pct_str}")
    
    return "\n".join(chart)

# ===================== PLOTLY FUNCTIONS =========================
def create_plotly_bar_chart(data: List[tuple], title: str, output_path: str) -> str:
    """
    Cria gráfico de barras horizontais com Plotly
    
    Args:
        data: Lista de tuplas (label, value)
        title: Título do gráfico
        output_path: Caminho para salvar o HTML
    
    Returns:
        Caminho do arquivo gerado
    """
    if not PLOTLY_AVAILABLE:
        return ""
    
    labels, values = zip(*data) if data else ([], [])
    total = sum(values)
    percentages = [(v/total)*100 for v in values] if total > 0 else []
    
    fig = go.Figure(data=[
        go.Bar(
            y=labels,
            x=values,
            orientation='h',
            marker=dict(
                color=values,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Tickets")
            ),
            text=[f'{v:,} ({p:.1f}%)' for v, p in zip(values, percentages)],
            textposition='outside',
            hovertemplate='<b>%{y}</b><br>Tickets: %{x:,}<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title={'text': title, 'x': 0.5, 'xanchor': 'center', 'font': {'size': 20}},
        xaxis_title="Número de Tickets",
        height=500,
        showlegend=False,
        plot_bgcolor='rgba(240,240,240,0.5)',
        margin=dict(l=200, r=100, t=80, b=60)
    )
    
    fig.write_html(output_path)
    return output_path

def create_plotly_pie_chart(data: List[tuple], title: str, output_path: str, 
                            color_map: Dict[str, str] = None) -> str:
    """
    Cria gráfico de pizza com Plotly
    
    Args:
        data: Lista de tuplas (label, value)
        title: Título do gráfico
        output_path: Caminho para salvar o HTML
        color_map: Dicionário de cores por label
    
    Returns:
        Caminho do arquivo gerado
    """
    if not PLOTLY_AVAILABLE:
        return ""
    
    labels, values = zip(*data) if data else ([], [])
    
    # Cores padrão ou customizadas
    if color_map:
        colors = [color_map.get(label, '#808080') for label in labels]
    else:
        colors = None
    
    fig = go.Figure(data=[
        go.Pie(
            labels=labels,
            values=values,
            hole=0.4,
            marker=dict(colors=colors, line=dict(color='white', width=2)) if colors else None,
            textinfo='label+percent',
            texttemplate='<b>%{label}</b><br>%{percent}',
            hovertemplate='<b>%{label}</b><br>Tickets: %{value:,}<br>%{percent}<extra></extra>'
        )
    ])
    
    total = sum(values)
    fig.update_layout(
        title={'text': title, 'x': 0.5, 'xanchor': 'center', 'font': {'size': 20}},
        height=600,
        showlegend=True,
        annotations=[
            dict(
                text=f'Total<br><b>{total:,}</b><br>tickets',
                x=0.5, y=0.5,
                font_size=16,
                showarrow=False
            )
        ]
    )
    
    fig.write_html(output_path)
    return output_path

# ===================== MCP SERVER ===========================
app = Server("gvuln-server")

@app.list_tools()
async def list_tools() -> List[Tool]:
    """Lista todas as ferramentas disponíveis"""
    return [
        Tool(
            name="health_check",
            description="Verifica conectividade com Elasticsearch",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_top_squad",
            description="Retorna o squad com mais tickets (top 10)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_top_remediation",
            description="Retorna as remediações que resolvem mais tickets (top 15)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_most_critical_asset",
            description="Retorna o ativo mais crítico baseado em CVSS e EPSS",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_asset_with_most_tickets",
            description="Retorna os ativos com mais tickets (top 10)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_asset_with_most_vulnerabilities",
            description="Retorna os ativos com mais vulnerabilidades (top 10)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_tickets_by_priority",
            description="Distribuição de tickets por prioridade (P1, P2, P3, P4)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_tickets_by_severity",
            description="Distribuição de tickets por severidade (CRITICAL, HIGH, MEDIUM, LOW)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_cisa_kev_tickets",
            description="Tickets com CVEs no CISA KEV (Known Exploited Vulnerabilities)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_action_plan_for_remediation",
            description="Gera plano de ação para uma remediação específica",
            inputSchema={
                "type": "object",
                "properties": {
                    "remediation_title": {
                        "type": "string",
                        "description": "Título da remediação"
                    }
                },
                "required": ["remediation_title"]
            }
        ),
        Tool(
            name="search_tickets_by_hostname",
            description="Busca tickets de um hostname específico",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Nome do host"
                    }
                },
                "required": ["hostname"]
            }
        ),
        Tool(
            name="get_squad_summary",
            description="Resumo completo de um squad específico",
            inputSchema={
                "type": "object",
                "properties": {
                    "squad": {
                        "type": "string",
                        "description": "Nome do squad"
                    }
                },
                "required": ["squad"]
            }
        ),
        Tool(
            name="generate_full_dashboard",
            description="Gera dashboard completo com 15+ visualizações (squads, remediações, severidade, CVSS, EPSS, timeline, heatmaps, etc)",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {
                        "type": "string",
                        "description": "Data inicial (YYYY-MM-DD) ou vazio para todo o período"
                    },
                    "end_date": {
                        "type": "string",
                        "description": "Data final (YYYY-MM-DD) ou vazio para todo o período"
                    },
                    "last_days": {
                        "type": "integer",
                        "description": "Últimos N dias (alternativa às datas específicas)"
                    }
                },
                "required": []
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Executa uma ferramenta específica"""
    
    if name == "health_check":
        try:
            response = requests.get(f"{ES_URL}/", timeout=5)
            response.raise_for_status()
            result = f"✅ Conectado ao Elasticsearch: {ES_URL}\n"
            result += f"✅ Índice: {ES_IDX}\n"
            result += f"✅ Status: OK"
            return [TextContent(type="text", text=result)]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Erro: {e}")]
    
    elif name == "get_top_squad":
        agg = {
            "aggs": {
                "by_squad": {
                    "terms": {"field": "squad", "size": 10}
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        squads = res.get("aggregations", {}).get("by_squad", {}).get("buckets", [])
        
        # Preparar dados para o gráfico
        chart_data = [(squad['key'], squad['doc_count']) for squad in squads]
        
        # ASCII preview
        result = "🏆 Top 10 Squads por Número de Tickets:\n\n"
        result += create_horizontal_bar_chart(chart_data, max_width=50)
        result += "\n\n📋 Detalhes:\n"
        for i, squad in enumerate(squads, 1):
            result += f"{i}. {squad['key']}: {squad['doc_count']:,} tickets\n"
        
        # Gerar gráfico Plotly
        if PLOTLY_AVAILABLE:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = "/tmp/gvuln_charts"
            os.makedirs(output_dir, exist_ok=True)
            output_path = f"{output_dir}/squads_{timestamp}.html"
            
            plotly_path = create_plotly_bar_chart(
                chart_data, 
                "🏆 Top 10 Squads por Número de Tickets",
                output_path
            )
            
            if plotly_path:
                result += f"\n\n📊 Gráfico interativo Plotly gerado!"
                result += f"\n🌐 Abrir: file://{plotly_path}"
                result += f"\n💡 Clique no link acima para visualizar no navegador"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_top_remediation":
        agg = {
            "aggs": {
                "by_remed": {
                    "terms": {"field": "remediation_title.keyword", "size": 15}
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        remeds = res.get("aggregations", {}).get("by_remed", {}).get("buckets", [])
        
        # Preparar dados para o gráfico (truncar títulos para visualização)
        chart_data = [(remed['key'][:30] + "..." if len(remed['key']) > 30 else remed['key'], 
                      remed['doc_count']) for remed in remeds]
        
        result = "🔧 Top 15 Remediações por Número de Tickets:\n\n"
        result += create_horizontal_bar_chart(chart_data, max_width=45)
        result += "\n\n📋 Detalhes Completos:\n"
        for i, remed in enumerate(remeds, 1):
            result += f"{i}. {remed['key'][:80]}...: {remed['doc_count']:,} tickets\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_most_critical_asset":
        query = {
            "sort": [
                {"MAX_BASE_SCORE": {"order": "desc"}},
                {"MAX_EPSS": {"order": "desc"}}
            ],
            "_source": ["hostname", "local_ip", "external_ip", "MAX_BASE_SCORE", 
                       "MAX_EPSS", "MAX_SEVERITY", "prioridade", "titulo_ticket"]
        }
        res = search_es(ES_IDX, query, size=1)
        hits = res.get("hits", {}).get("hits", [])
        
        if not hits:
            return [TextContent(type="text", text="❌ Nenhum ativo encontrado")]
        
        doc = hits[0]["_source"]
        result = f"🔴 Ativo Mais Crítico:\n\n"
        result += f"Hostname: {doc.get('hostname')}\n"
        result += f"IP Local: {doc.get('local_ip')}\n"
        result += f"IP Externo: {doc.get('external_ip')}\n"
        result += f"CVSS Score: {doc.get('MAX_BASE_SCORE')}\n"
        result += f"EPSS Score: {doc.get('MAX_EPSS')}\n"
        result += f"Severidade: {doc.get('MAX_SEVERITY')}\n"
        result += f"Prioridade: {doc.get('prioridade')}\n"
        result += f"Título: {doc.get('titulo_ticket', '')[:100]}...\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_asset_with_most_tickets":
        agg = {
            "aggs": {
                "by_host": {
                    "terms": {"field": "hostname", "size": 10}
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        hosts = res.get("aggregations", {}).get("by_host", {}).get("buckets", [])
        
        result = "💻 Top 10 Ativos com Mais Tickets:\n\n"
        for i, host in enumerate(hosts, 1):
            result += f"{i}. {host['key']}: {host['doc_count']:,} tickets\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_asset_with_most_vulnerabilities":
        # Nota: VULNERABILITY_COUNT não está populado nos documentos
        # Usando CVE_COUNT como alternativa
        agg = {
            "aggs": {
                "by_host": {
                    "terms": {"field": "hostname", "size": 10},
                    "aggs": {
                        "total_cves": {"sum": {"field": "CVE_COUNT"}},
                        "avg_severity": {"avg": {"field": "MAX_BASE_SCORE"}}
                    }
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        hosts = res.get("aggregations", {}).get("by_host", {}).get("buckets", [])
        
        result = "⚠️ Top 10 Ativos com Mais CVEs:\n\n"
        for i, host in enumerate(hosts, 1):
            cve_count = int(host.get("total_cves", {}).get("value", 0))
            avg_score = host.get("avg_severity", {}).get("value", 0)
            result += f"{i}. {host['key']}: {cve_count:,} CVEs (CVSS médio: {avg_score:.1f})\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_tickets_by_priority":
        agg = {
            "aggs": {
                "by_priority": {
                    "terms": {"field": "prioridade", "size": 10}
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        priorities = res.get("aggregations", {}).get("by_priority", {}).get("buckets", [])
        
        # Preparar dados para o gráfico
        chart_data = [(p['key'], p['doc_count']) for p in priorities]
        
        result = "📊 Distribuição de Tickets por Prioridade:\n\n"
        result += create_pie_chart(chart_data, width=70)
        result += "\n\n📋 Resumo:\n"
        total = sum(p['doc_count'] for p in priorities)
        for priority in priorities:
            pct = (priority['doc_count'] / total * 100) if total > 0 else 0
            result += f"  {priority['key']}: {priority['doc_count']:,} tickets ({pct:.1f}%)\n"
        result += f"\n  TOTAL: {total:,} tickets"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_tickets_by_severity":
        agg = {
            "aggs": {
                "by_severity": {
                    "terms": {"field": "MAX_SEVERITY", "size": 10}
                }
            }
        }
        res = agg_es(ES_IDX, agg)
        severities = res.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
        
        # Preparar dados para o gráfico
        chart_data = [(s['key'], s['doc_count']) for s in severities]
        
        # ASCII preview
        result = "🎯 Distribuição de Tickets por Severidade:\n\n"
        result += create_pie_chart(chart_data, width=70)
        result += "\n\n📋 Resumo:\n"
        total = sum(s['doc_count'] for s in severities)
        for severity in severities:
            pct = (severity['doc_count'] / total * 100) if total > 0 else 0
            emoji = "🔴" if severity['key'] in ['CRITICAL', 'HIGH'] else "🟠" if severity['key'] == 'MEDIUM' else "🟢"
            result += f"  {emoji} {severity['key']}: {severity['doc_count']:,} tickets ({pct:.1f}%)\n"
        result += f"\n  TOTAL: {total:,} tickets"
        
        # Gerar gráfico Plotly
        if PLOTLY_AVAILABLE:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = "/tmp/gvuln_charts"
            os.makedirs(output_dir, exist_ok=True)
            output_path = f"{output_dir}/severity_{timestamp}.html"
            
            # Mapa de cores por severidade
            color_map = {
                'CRITICAL': '#8B0000',
                'HIGH': '#DC143C',
                'MEDIUM': '#FF8C00',
                'LOW': '#32CD32',
                'UNKNOWN': '#808080'
            }
            
            plotly_path = create_plotly_pie_chart(
                chart_data,
                "🎯 Distribuição de Tickets por Severidade",
                output_path,
                color_map
            )
            
            if plotly_path:
                result += f"\n\n📊 Gráfico interativo Plotly gerado!"
                result += f"\n🌐 Abrir: file://{plotly_path}"
                result += f"\n💡 Clique no link acima para visualizar no navegador"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_cisa_kev_tickets":
        query = {
            "query": {
                "term": {"is_cisa_kev": True}
            },
            "_source": ["hostname", "cve_id", "cve_severity", "cve_base_score", "titulo_ticket"]
        }
        res = search_es(ES_IDX, query, size=50)
        hits = res.get("hits", {}).get("hits", [])
        
        result = f"🚨 Tickets com CVEs no CISA KEV ({len(hits)} encontrados):\n\n"
        for i, hit in enumerate(hits[:20], 1):
            doc = hit["_source"]
            result += f"{i}. {doc.get('hostname')} - {doc.get('cve_id')} "
            result += f"({doc.get('cve_severity')}, CVSS: {doc.get('cve_base_score')})\n"
        
        if len(hits) > 20:
            result += f"\n... e mais {len(hits) - 20} tickets"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_action_plan_for_remediation":
        remediation_title = arguments.get("remediation_title", "")
        query = {
            "query": {
                "match_phrase": {"remediation_title": remediation_title}
            },
            "_source": ["remediation_title", "remediation_action", "remediation_reference", 
                       "prioridade", "cve_description", "MAX_SEVERITY"]
        }
        res = search_es(ES_IDX, query, size=1)
        hits = res.get("hits", {}).get("hits", [])
        
        if not hits:
            return [TextContent(type="text", text=f"❌ Remediação '{remediation_title}' não encontrada")]
        
        doc = hits[0]["_source"]
        result = f"📋 Plano de Ação para Remediação:\n\n"
        result += f"Título: {doc.get('remediation_title')}\n"
        result += f"Ação: {doc.get('remediation_action')}\n"
        result += f"Referência: {doc.get('remediation_reference')}\n"
        result += f"Prioridade: {doc.get('prioridade')}\n"
        result += f"Severidade Máxima: {doc.get('MAX_SEVERITY')}\n"
        result += f"Descrição CVE: {doc.get('cve_description', '')[:200]}...\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "search_tickets_by_hostname":
        hostname = arguments.get("hostname", "")
        query = {
            "query": {
                "term": {"hostname": hostname}
            },
            "_source": ["ticket_id", "jira_key", "hostname", "prioridade", "status", 
                       "MAX_SEVERITY", "CVE_COUNT", "remediation_title"]
        }
        res = search_es(ES_IDX, query, size=50)
        hits = res.get("hits", {}).get("hits", [])
        
        result = f"🔍 Tickets para {hostname} ({len(hits)} encontrados):\n\n"
        for i, hit in enumerate(hits, 1):
            doc = hit["_source"]
            result += f"{i}. {doc.get('jira_key')} - {doc.get('status')} "
            result += f"({doc.get('prioridade')}, {doc.get('MAX_SEVERITY')})\n"
            result += f"   CVEs: {doc.get('CVE_COUNT')}\n"
            result += f"   Remediação: {doc.get('remediation_title', '')[:60]}...\n\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "get_squad_summary":
        squad = arguments.get("squad", "")
        query = {
            "query": {
                "term": {"squad": squad}
            }
        }
        res = search_es(ES_IDX, query, size=10000)
        hits = res.get("hits", {}).get("hits", [])
        
        # Calcular estatísticas
        total_tickets = len(hits)
        priorities = {}
        severities = {}
        statuses = {}
        
        for hit in hits:
            doc = hit["_source"]
            prio = doc.get("prioridade", "Unknown")
            sev = doc.get("MAX_SEVERITY", "Unknown")
            status = doc.get("status", "Unknown")
            
            priorities[prio] = priorities.get(prio, 0) + 1
            severities[sev] = severities.get(sev, 0) + 1
            statuses[status] = statuses.get(status, 0) + 1
        
        result = f"📊 Resumo do Squad: {squad}\n\n"
        result += f"Total de Tickets: {total_tickets:,}\n\n"
        
        result += "Por Prioridade:\n"
        for prio, count in sorted(priorities.items()):
            pct = (count / total_tickets * 100) if total_tickets > 0 else 0
            result += f"  {prio}: {count:,} ({pct:.1f}%)\n"
        
        result += "\nPor Severidade:\n"
        for sev, count in sorted(severities.items()):
            pct = (count / total_tickets * 100) if total_tickets > 0 else 0
            result += f"  {sev}: {count:,} ({pct:.1f}%)\n"
        
        result += "\nPor Status:\n"
        for status, count in sorted(statuses.items()):
            pct = (count / total_tickets * 100) if total_tickets > 0 else 0
            result += f"  {status}: {count:,} ({pct:.1f}%)\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "generate_full_dashboard":
        # Importar dashboard agent
        try:
            import subprocess
            from datetime import timedelta
            
            start_date = arguments.get("start_date")
            end_date = arguments.get("end_date")
            last_days = arguments.get("last_days")
            
            # Construir comando
            cmd = ["python", "dashboard_agent.py"]
            
            if last_days:
                cmd.extend(["--last-days", str(last_days)])
                period_str = f"últimos {last_days} dias"
            elif start_date or end_date:
                if start_date:
                    cmd.extend(["--start-date", start_date])
                if end_date:
                    cmd.extend(["--end-date", end_date])
                period_str = f"{start_date or 'início'} até {end_date or 'agora'}"
            else:
                period_str = "todo o período"
            
            result = f"🎨 Gerando dashboard completo do GVULN...\n"
            result += f"📅 Período: {period_str}\n\n"
            result += "📊 O dashboard inclui 15+ visualizações:\n"
            result += "  • Total de tickets e indicadores principais\n"
            result += "  • Distribuição por severidade e prioridade\n"
            result += "  • Top 10 squads, remediações e hosts\n"
            result += "  • Distribuições CVSS e EPSS\n"
            result += "  • Heatmap squad x severidade\n"
            result += "  • Timeline de criação de tickets\n"
            result += "  • Análise de CISA KEV\n"
            result += "  • E muito mais!\n\n"
            result += "⏳ Processando... (isso pode levar alguns segundos)\n\n"
            
            # Executar dashboard agent
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(__file__) or "."
            )
            
            if proc.returncode == 0:
                # Extrair caminho do arquivo gerado
                output_lines = proc.stdout.split('\n')
                file_path = None
                for line in output_lines:
                    if 'file://' in line:
                        file_path = line.split('file://')[1].strip()
                        break

                if file_path:
                    # Extrair nome do arquivo
                    file_name = os.path.basename(file_path)
                    # Gerar URL de download
                    download_url = f"http://localhost:8000/api/v1/downloads/{file_name}"

                    result += "✅ Dashboard gerado com sucesso!\n\n"
                    result += f"📥 **[Clique aqui para baixar o dashboard]({download_url})**\n\n"
                    result += "📊 O dashboard é totalmente interativo:\n"
                    result += "  • Hover para ver detalhes\n"
                    result += "  • Zoom e pan em gráficos\n"
                    result += "  • Exportar como PNG\n"
                    result += "  • Legenda clicável\n"
                else:
                    result += "✅ Dashboard gerado!\n"
                    result += proc.stdout
            else:
                result += f"❌ Erro ao gerar dashboard:\n{proc.stderr}"
            
            return [TextContent(type="text", text=result)]
            
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Erro ao gerar dashboard: {e}")]
    
    else:
        return [TextContent(type="text", text=f"❌ Ferramenta '{name}' não encontrada")]

# ===================== MAIN ===================================
async def main():
    """Inicia o servidor MCP"""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
