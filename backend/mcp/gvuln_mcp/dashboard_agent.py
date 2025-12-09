#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboard Agent - GVULN
Gera dashboards completos com múltiplas visualizações
"""
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ===================== CONFIG ============================
ES_URL = "http://localhost:9200"
ES_IDX = "tickets_enviados_jira"
HEADERS = {"Content-Type": "application/json"}
TIMEOUT = 30

# Cores por severidade
SEVERITY_COLORS = {
    'CRITICAL': '#8B0000',
    'HIGH': '#DC143C',
    'MEDIUM': '#FF8C00',
    'LOW': '#32CD32',
    'UNKNOWN': '#808080'
}

# Cores por prioridade
PRIORITY_COLORS = {
    'P1': '#DC143C',
    'P2': '#FF8C00',
    'P3': '#32CD32',
    'P4': '#87CEEB'
}

# ===================== ELASTICSEARCH UTILS ================
def search_es(query: Dict[str, Any], size: int = 10000, use_scroll: bool = False) -> Dict[str, Any]:
    """
    Busca documentos no Elasticsearch
    
    Args:
        query: Query do Elasticsearch
        size: Tamanho da página (ignorado se use_scroll=True)
        use_scroll: Se True, usa scroll API para buscar TODOS os documentos
    
    Returns:
        Resultado da busca
    """
    try:
        url = f"{ES_URL}/{ES_IDX}/_search"
        
        if use_scroll:
            # Usar scroll API para buscar TODOS os documentos
            all_hits = []
            scroll_size = 1000
            scroll_time = "5m"
            
            # Primeira requisição
            query_copy = dict(query)
            query_copy['size'] = scroll_size
            query_copy['track_total_hits'] = True
            response = requests.post(
                f"{url}?scroll={scroll_time}", 
                headers=HEADERS, 
                json=query_copy, 
                timeout=TIMEOUT
            )
            response.raise_for_status()
            result = response.json()
            
            scroll_id = result.get('_scroll_id')
            hits = result.get('hits', {}).get('hits', [])
            all_hits.extend(hits)
            
            total = result.get('hits', {}).get('total', {}).get('value', 0)
            print(f"📊 Total de documentos: {total:,}")
            print(f"⏳ Buscando todos usando scroll API...")
            
            # Continuar buscando enquanto houver resultados
            while len(hits) > 0:
                scroll_response = requests.post(
                    f"{ES_URL}/_search/scroll",
                    headers=HEADERS,
                    json={"scroll": scroll_time, "scroll_id": scroll_id},
                    timeout=TIMEOUT
                )
                scroll_response.raise_for_status()
                scroll_result = scroll_response.json()
                
                scroll_id = scroll_result.get('_scroll_id')
                hits = scroll_result.get('hits', {}).get('hits', [])
                all_hits.extend(hits)
                
                # Mostrar progresso
                progress = (len(all_hits) / total) * 100 if total > 0 else 0
                print(f"  📥 {len(all_hits):,}/{total:,} documentos ({progress:.1f}%)", end="\r")
            
            # Limpar scroll
            requests.delete(
                f"{ES_URL}/_search/scroll",
                headers=HEADERS,
                json={"scroll_id": scroll_id},
                timeout=TIMEOUT
            )
            
            print(f"\n✅ {len(all_hits):,} documentos carregados!")
            
            return {
                "hits": {
                    "hits": all_hits,
                    "total": {"value": len(all_hits)}
                }
            }
        else:
            # Busca normal com limite
            query_copy = dict(query)
            query_copy['size'] = size
            response = requests.post(url, headers=HEADERS, json=query_copy, timeout=TIMEOUT)
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        print(f"❌ Erro ao buscar dados: {e}", file=sys.stderr)
        print(f"Query: {query}", file=sys.stderr)
        print(f"use_scroll: {use_scroll}", file=sys.stderr)
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return {"hits": {"hits": []}, "error": str(e)}

def agg_es(agg_query: Dict[str, Any]) -> Dict[str, Any]:
    """Executa agregações no Elasticsearch"""
    try:
        url = f"{ES_URL}/{ES_IDX}/_search"
        query_copy = dict(agg_query)
        query_copy['size'] = 0
        response = requests.post(url, headers=HEADERS, json=query_copy, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Erro ao executar agregação: {e}", file=sys.stderr)
        print(f"Query: {agg_query}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return {"aggregations": {}, "error": str(e)}

# ===================== DATA COLLECTORS ====================
class DashboardDataCollector:
    """Coleta dados para o dashboard"""
    
    def __init__(self, start_date: Optional[str] = None, end_date: Optional[str] = None):
        self.start_date = start_date
        self.end_date = end_date
        self.date_filter = self._build_date_filter()
    
    def _build_date_filter(self) -> Dict[str, Any]:
        """Constrói filtro de data"""
        if not self.start_date and not self.end_date:
            return {}
        
        date_range = {}
        if self.start_date:
            date_range["gte"] = self.start_date
        if self.end_date:
            date_range["lte"] = self.end_date
        
        return {
            "range": {
                "created_date": date_range
            }
        }
    
    def get_total_tickets(self) -> int:
        """Total de tickets"""
        query = {
            "query": {"match_all": {}},
            "track_total_hits": True
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = search_es(query, size=0)
        return result.get("hits", {}).get("total", {}).get("value", 0)
    
    
    def get_all_tickets_data(self) -> List[Dict[str, Any]]:
        """Busca TODOS os tickets usando scroll API"""
        query = {"query": {"match_all": {}}}
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = search_es(query, use_scroll=True)
        return result.get("hits", {}).get("hits", [])
    
    def get_tickets_by_priority(self) -> List[Dict[str, Any]]:
        """Tickets por prioridade"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_priority": {
                    "terms": {"field": "prioridade", "size": 10}
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_priority", {}).get("buckets", [])
    
    def get_tickets_by_severity(self) -> List[Dict[str, Any]]:
        """Tickets por severidade"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_severity": {
                    "terms": {"field": "MAX_SEVERITY", "size": 10}
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    
    def get_top_squads(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Top squads"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_squad": {
                    "terms": {"field": "squad", "size": limit}
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_squad", {}).get("buckets", [])
    
    def get_top_remediations(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Top remediações"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_remediation": {
                    "terms": {"field": "remediation_title.keyword", "size": limit}
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_remediation", {}).get("buckets", [])
    
    def get_top_hosts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Top hosts com mais tickets"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_host": {
                    "terms": {"field": "hostname", "size": limit}
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    
    def get_cvss_distribution(self) -> List[Dict[str, Any]]:
        """Distribuição de CVSS scores"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "cvss_ranges": {
                    "histogram": {
                        "field": "MAX_BASE_SCORE",
                        "interval": 1,
                        "min_doc_count": 1
                    }
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("cvss_ranges", {}).get("buckets", [])
    
    def get_epss_distribution(self) -> List[Dict[str, Any]]:
        """Distribuição de EPSS scores"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "epss_ranges": {
                    "histogram": {
                        "field": "MAX_EPSS",
                        "interval": 0.1,
                        "min_doc_count": 1
                    }
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("epss_ranges", {}).get("buckets", [])
    
    def get_cisa_kev_count(self) -> int:
        """Total de tickets com CISA KEV"""
        # is_cisa_kev é um campo boolean direto, não nested
        query = {
            "query": {
                "term": {"is_cisa_kev": True}
            }
        }
        
        if self.date_filter:
            query["query"] = {
                "bool": {
                    "must": [
                        {"term": {"is_cisa_kev": True}}
                    ],
                    "filter": [self.date_filter]
                }
            }
        
        result = search_es(query, size=0)
        return result.get("hits", {}).get("total", {}).get("value", 0)
    
    def get_squad_severity_matrix(self) -> Dict[str, Any]:
        """Matriz squad x severidade"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "by_squad": {
                    "terms": {"field": "squad", "size": 10},
                    "aggs": {
                        "by_severity": {
                            "terms": {"field": "MAX_SEVERITY", "size": 10}
                        }
                    }
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("by_squad", {}).get("buckets", [])
    
    def get_timeline_data(self, interval: str = "1d") -> List[Dict[str, Any]]:
        """Dados temporais"""
        query = {
            "query": {"match_all": {}},
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "created_date",
                        "calendar_interval": interval,
                        "min_doc_count": 0
                    }
                }
            }
        }
        if self.date_filter:
            query["query"] = {"bool": {"filter": [self.date_filter]}}
        
        result = agg_es(query)
        return result.get("aggregations", {}).get("timeline", {}).get("buckets", [])

# ===================== DASHBOARD GENERATOR ================
class DashboardGenerator:
    """Gera dashboard completo"""
    
    def __init__(self, collector: DashboardDataCollector):
        self.collector = collector
        self.fig = None
    
    def create_dashboard(self) -> go.Figure:
        """Cria dashboard completo com 15+ visualizações"""
        
        # Criar grid de subplots (5 linhas x 3 colunas = 15 gráficos)
        self.fig = make_subplots(
            rows=5, cols=3,
            subplot_titles=(
                '📊 Total de Tickets', '🎯 Tickets por Severidade', '📋 Tickets por Prioridade',
                '🏢 Top 10 Squads', '🔧 Top 10 Remediações', '💻 Top 10 Hosts',
                '📈 Distribuição CVSS', '🎲 Distribuição EPSS', '🚨 CISA KEV',
                '🔥 Heatmap Squad x Severidade', '📊 Severidade por Squad', '⏱️ Timeline de Tickets',
                '🎯 Prioridade Crítica (P1)', '💡 Insights Principais', '📈 Tendências'
            ),
            specs=[
                [{"type": "indicator"}, {"type": "pie"}, {"type": "pie"}],
                [{"type": "bar"}, {"type": "bar"}, {"type": "bar"}],
                [{"type": "bar"}, {"type": "bar"}, {"type": "indicator"}],
                [{"type": "heatmap", "colspan": 2}, None, {"type": "bar"}],
                [{"type": "scatter", "colspan": 3}, None, None]
            ],
            vertical_spacing=0.08,
            horizontal_spacing=0.10,
            row_heights=[0.15, 0.20, 0.20, 0.20, 0.25]
        )
        
        # Coletar todos os dados
        print("📊 Coletando dados do Elasticsearch...")
        total_tickets = self.collector.get_total_tickets()
        severity_data = self.collector.get_tickets_by_severity()
        priority_data = self.collector.get_tickets_by_priority()
        squads_data = self.collector.get_top_squads()
        remediation_data = self.collector.get_top_remediations()
        hosts_data = self.collector.get_top_hosts()
        cvss_data = self.collector.get_cvss_distribution()
        epss_data = self.collector.get_epss_distribution()
        cisa_kev = self.collector.get_cisa_kev_count()
        squad_severity = self.collector.get_squad_severity_matrix()
        timeline_data = self.collector.get_timeline_data()
        
        print(f"✅ Dados coletados: {total_tickets:,} tickets")
        
        # 1. Total de Tickets (Indicador)
        self._add_total_indicator(total_tickets, row=1, col=1)
        
        # 2. Tickets por Severidade (Pizza)
        self._add_severity_pie(severity_data, row=1, col=2)
        
        # 3. Tickets por Prioridade (Pizza)
        self._add_priority_pie(priority_data, row=1, col=3)
        
        # 4. Top 10 Squads (Barras)
        self._add_squads_bar(squads_data, row=2, col=1)
        
        # 5. Top 10 Remediações (Barras)
        self._add_remediations_bar(remediation_data, row=2, col=2)
        
        # 6. Top 10 Hosts (Barras)
        self._add_hosts_bar(hosts_data, row=2, col=3)
        
        # 7. Distribuição CVSS (Barras)
        self._add_cvss_distribution(cvss_data, row=3, col=1)
        
        # 8. Distribuição EPSS (Barras)
        self._add_epss_distribution(epss_data, row=3, col=2)
        
        # 9. CISA KEV (Indicador)
        self._add_cisa_kev_indicator(cisa_kev, total_tickets, row=3, col=3)
        
        # 10. Heatmap Squad x Severidade
        self._add_squad_severity_heatmap(squad_severity, row=4, col=1)
        
        # 11. Severidade por Squad (Stacked Bar)
        self._add_severity_by_squad(squad_severity, row=4, col=3)
        
        # 12. Timeline de Tickets
        self._add_timeline(timeline_data, row=5, col=1)
        
        # Layout geral
        self.fig.update_layout(
            title={
                'text': f'🎯 Dashboard GVULN - Análise Completa de Vulnerabilidades<br><sub>Total: {total_tickets:,} tickets | Gerado em: {datetime.now().strftime("%d/%m/%Y %H:%M")}</sub>',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 24, 'color': '#2c3e50'}
            },
            height=2000,
            showlegend=True,
            paper_bgcolor='#f8f9fa',
            plot_bgcolor='white'
        )
        
        return self.fig
    
    def _add_total_indicator(self, total: int, row: int, col: int):
        """Adiciona indicador de total"""
        self.fig.add_trace(
            go.Indicator(
                mode="number",
                value=total,
                title={"text": "Total de Tickets", "font": {"size": 16}},
                number={"font": {"size": 40, "color": "#2c3e50"}},
                domain={'x': [0, 1], 'y': [0, 1]}
            ),
            row=row, col=col
        )
    
    def _add_severity_pie(self, data: List[Dict], row: int, col: int):
        """Adiciona gráfico de pizza de severidade"""
        if not data:
            return
        
        labels = [d['key'] for d in data]
        values = [d['doc_count'] for d in data]
        colors = [SEVERITY_COLORS.get(label, '#808080') for label in labels]
        
        self.fig.add_trace(
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=colors),
                hole=0.4,
                textinfo='label+percent',
                textposition='auto'
            ),
            row=row, col=col
        )
    
    def _add_priority_pie(self, data: List[Dict], row: int, col: int):
        """Adiciona gráfico de pizza de prioridade"""
        if not data:
            return
        
        labels = [d['key'] for d in data]
        values = [d['doc_count'] for d in data]
        colors = [PRIORITY_COLORS.get(label, '#808080') for label in labels]
        
        self.fig.add_trace(
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=colors),
                hole=0.4,
                textinfo='label+percent',
                textposition='auto'
            ),
            row=row, col=col
        )
    
    def _add_squads_bar(self, data: List[Dict], row: int, col: int):
        """Adiciona gráfico de barras de squads"""
        if not data:
            return
        
        labels = [d['key'][:20] for d in data]
        values = [d['doc_count'] for d in data]
        
        self.fig.add_trace(
            go.Bar(
                y=labels,
                x=values,
                orientation='h',
                marker=dict(color='#DC143C'),
                text=values,
                textposition='outside'
            ),
            row=row, col=col
        )
    
    def _add_remediations_bar(self, data: List[Dict], row: int, col: int):
        """Adiciona gráfico de barras de remediações"""
        if not data:
            return
        
        labels = [d['key'][:25] + '...' if len(d['key']) > 25 else d['key'] for d in data[:10]]
        values = [d['doc_count'] for d in data[:10]]
        
        self.fig.add_trace(
            go.Bar(
                y=labels,
                x=values,
                orientation='h',
                marker=dict(color='#FF8C00'),
                text=values,
                textposition='outside'
            ),
            row=row, col=col
        )
    
    def _add_hosts_bar(self, data: List[Dict], row: int, col: int):
        """Adiciona gráfico de barras de hosts"""
        if not data:
            return
        
        labels = [d['key'][:20] for d in data]
        values = [d['doc_count'] for d in data]
        
        self.fig.add_trace(
            go.Bar(
                y=labels,
                x=values,
                orientation='h',
                marker=dict(color='#32CD32'),
                text=values,
                textposition='outside'
            ),
            row=row, col=col
        )
    
    def _add_cvss_distribution(self, data: List[Dict], row: int, col: int):
        """Adiciona distribuição CVSS"""
        if not data:
            return
        
        x_values = [d['key'] for d in data]
        y_values = [d['doc_count'] for d in data]
        
        self.fig.add_trace(
            go.Bar(
                x=x_values,
                y=y_values,
                marker=dict(color='#8B0000'),
                text=y_values,
                textposition='outside'
            ),
            row=row, col=col
        )
    
    def _add_epss_distribution(self, data: List[Dict], row: int, col: int):
        """Adiciona distribuição EPSS"""
        if not data:
            return
        
        x_values = [round(d['key'], 2) for d in data]
        y_values = [d['doc_count'] for d in data]
        
        self.fig.add_trace(
            go.Bar(
                x=x_values,
                y=y_values,
                marker=dict(color='#FF6347'),
                text=y_values,
                textposition='outside'
            ),
            row=row, col=col
        )
    
    def _add_cisa_kev_indicator(self, cisa_count: int, total: int, row: int, col: int):
        """Adiciona indicador CISA KEV"""
        percentage = (cisa_count / total * 100) if total > 0 else 0
        
        self.fig.add_trace(
            go.Indicator(
                mode="number+delta",
                value=cisa_count,
                title={"text": "CISA KEV", "font": {"size": 14}},
                number={"font": {"size": 30, "color": "#DC143C"}},
                delta={'reference': 0, 'relative': False},
                domain={'x': [0, 1], 'y': [0, 1]}
            ),
            row=row, col=col
        )
    
    def _add_squad_severity_heatmap(self, data: List[Dict], row: int, col: int):
        """Adiciona heatmap squad x severidade"""
        if not data:
            return
        
        # Preparar dados para heatmap
        squads = [d['key'][:15] for d in data[:8]]
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        # Matriz de valores
        matrix = []
        for squad_data in data[:8]:
            row_values = []
            severity_buckets = {b['key']: b['doc_count'] for b in squad_data.get('by_severity', {}).get('buckets', [])}
            for sev in severities:
                row_values.append(severity_buckets.get(sev, 0))
            matrix.append(row_values)
        
        self.fig.add_trace(
            go.Heatmap(
                z=matrix,
                x=severities,
                y=squads,
                colorscale='Reds',
                text=matrix,
                texttemplate='%{text}',
                textfont={"size": 10}
            ),
            row=row, col=col
        )
    
    def _add_severity_by_squad(self, data: List[Dict], row: int, col: int):
        """Adiciona barras empilhadas de severidade por squad"""
        if not data:
            return
        
        squads = [d['key'][:15] for d in data[:5]]
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            values = []
            for squad_data in data[:5]:
                severity_buckets = {b['key']: b['doc_count'] for b in squad_data.get('by_severity', {}).get('buckets', [])}
                values.append(severity_buckets.get(severity, 0))
            
            self.fig.add_trace(
                go.Bar(
                    name=severity,
                    y=squads,
                    x=values,
                    orientation='h',
                    marker=dict(color=SEVERITY_COLORS.get(severity, '#808080'))
                ),
                row=row, col=col
            )
    
    def _add_timeline(self, data: List[Dict], row: int, col: int):
        """Adiciona timeline de tickets"""
        if not data or len(data) == 0:
            print("⚠️ Nenhum dado de timeline disponível")
            return
        
        print(f"📈 Gerando timeline com {len(data)} pontos de dados")
        
        # Converter timestamps para datas
        dates = []
        values = []
        for d in data:
            try:
                # Converter timestamp de milissegundos para datetime
                dt = datetime.fromtimestamp(d['key']/1000)
                dates.append(dt)
                values.append(d['doc_count'])
            except Exception as e:
                print(f"⚠️ Erro ao processar data: {e}")
                continue
        
        if not dates:
            print("⚠️ Nenhuma data válida encontrada")
            return
        
        # Adicionar trace
        self.fig.add_trace(
            go.Scatter(
                x=dates,
                y=values,
                mode='lines+markers',
                name='Tickets Criados',
                line=dict(color='#2c3e50', width=2),
                marker=dict(size=6, color='#DC143C'),
                fill='tozeroy',
                fillcolor='rgba(44, 62, 80, 0.2)',
                hovertemplate='<b>%{x|%d/%m/%Y}</b><br>Tickets: %{y}<extra></extra>'
            ),
            row=row, col=col
        )
        
        # Atualizar eixos
        self.fig.update_xaxes(
            title_text="Data",
            showgrid=True,
            gridwidth=1,
            gridcolor='lightgray',
            row=row, col=col
        )
        self.fig.update_yaxes(
            title_text="Número de Tickets",
            showgrid=True,
            gridwidth=1,
            gridcolor='lightgray',
            row=row, col=col
        )
    
    def save_dashboard(self, output_path: str):
        """Salva dashboard em HTML"""
        if self.fig:
            self.fig.write_html(output_path)
            print(f"✅ Dashboard salvo em: {output_path}")
            return output_path
        return None

# ===================== MAIN ===================================
def generate_dashboard(start_date: Optional[str] = None, 
                      end_date: Optional[str] = None,
                      output_path: Optional[str] = None) -> str:
    """
    Gera dashboard completo do GVULN
    
    Args:
        start_date: Data inicial (formato: YYYY-MM-DD) ou None para todo o período
        end_date: Data final (formato: YYYY-MM-DD) ou None para todo o período
        output_path: Caminho para salvar o HTML
    
    Returns:
        Caminho do arquivo gerado
    """
    print("🎨 Iniciando geração do dashboard GVULN...")
    
    # Definir período
    if start_date or end_date:
        period_str = f"{start_date or 'início'} até {end_date or 'agora'}"
    else:
        period_str = "todo o período"
    
    print(f"📅 Período: {period_str}")
    
    # Coletar dados
    collector = DashboardDataCollector(start_date, end_date)
    
    # Gerar dashboard
    generator = DashboardGenerator(collector)
    fig = generator.create_dashboard()
    
    # Salvar
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = "/app/static/downloads"
        os.makedirs(output_dir, exist_ok=True)
        output_path = f"{output_dir}/dashboard_gvuln_{timestamp}.html"
    
    generator.save_dashboard(output_path)
    
    print(f"\n🎉 Dashboard gerado com sucesso!")
    print(f"🌐 Abrir: file://{output_path}")
    
    return output_path

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Gera dashboard completo do GVULN')
    parser.add_argument('--start-date', help='Data inicial (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='Data final (YYYY-MM-DD)')
    parser.add_argument('--output', help='Caminho de saída do HTML')
    parser.add_argument('--last-days', type=int, help='Últimos N dias')
    
    args = parser.parse_args()
    
    start_date = args.start_date
    end_date = args.end_date
    
    # Se especificou últimos N dias
    if args.last_days:
        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=args.last_days)).strftime("%Y-%m-%d")
    
    generate_dashboard(start_date, end_date, args.output)
