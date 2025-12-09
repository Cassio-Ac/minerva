"""
Export Service
Service para exportar dashboards em PDF e PNG
"""

import os
import io
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from PIL import Image
import plotly.graph_objects as go
import plotly.io as pio

logger = logging.getLogger(__name__)

# Configure Kaleido to use Chromium
pio.kaleido.scope.chromium_args = tuple([
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-gpu"
])

# Try to set Chromium path
if os.path.exists("/usr/bin/chromium"):
    os.environ["CHROME_PATH"] = "/usr/bin/chromium"
    logger.info("✅ Chromium found at /usr/bin/chromium")


class ExportService:
    """Service para exportar dashboards"""

    @staticmethod
    async def export_dashboard_pdf(
        dashboard: Dict[str, Any],
        widgets: list[Dict[str, Any]],
        output_path: Optional[str] = None
    ) -> str:
        """
        Exporta dashboard para PDF

        Args:
            dashboard: Dados do dashboard
            widgets: Lista de widgets do dashboard
            output_path: Caminho para salvar PDF (opcional)

        Returns:
            Caminho do arquivo PDF gerado
        """
        try:
            # Preparar caminho de saída
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"dashboard_{dashboard.get('id', 'export')}_{timestamp}.pdf"
                output_path = os.path.join("/app/static/downloads", filename)

            # Criar diretório se não existir
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # Criar PDF
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=30,
                leftMargin=30,
                topMargin=30,
                bottomMargin=30
            )

            # Preparar estilos
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=30,
                alignment=TA_CENTER
            )

            subtitle_style = ParagraphStyle(
                'CustomSubtitle',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#6b7280'),
                spaceAfter=20,
                alignment=TA_CENTER
            )

            widget_title_style = ParagraphStyle(
                'WidgetTitle',
                parent=styles['Heading3'],
                fontSize=12,
                textColor=colors.HexColor('#374151'),
                spaceAfter=10
            )

            # Construir conteúdo
            story = []

            # Título do Dashboard
            title = Paragraph(dashboard.get('title', 'Dashboard'), title_style)
            story.append(title)

            # Descrição
            if dashboard.get('description'):
                desc = Paragraph(dashboard.get('description', ''), subtitle_style)
                story.append(desc)

            # Data de exportação
            export_date = Paragraph(
                f"Exportado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                subtitle_style
            )
            story.append(export_date)
            story.append(Spacer(1, 20))

            # Adicionar widgets
            for idx, widget in enumerate(widgets):
                # Título do widget
                widget_name = Paragraph(
                    f"Widget: {widget.get('title', f'Widget {idx+1}')}",
                    widget_title_style
                )
                story.append(widget_name)

                # Tipo do widget
                widget_type = widget.get('type', 'unknown')
                type_text = Paragraph(
                    f"Tipo: {widget_type.upper()}",
                    styles['Normal']
                )
                story.append(type_text)
                story.append(Spacer(1, 10))

                # Dados do widget (se disponível)
                widget_data = widget.get('data')

                if widget_type == 'metric':
                    # Widget tipo METRIC: renderizar como texto grande
                    if widget_data and 'data' in widget_data and isinstance(widget_data['data'], list) and len(widget_data['data']) > 0:
                        # Pegar o primeiro valor
                        metric_value = widget_data['data'][0].get('value', 0)
                        metric_label = widget_data['data'][0].get('label', 'Valor')

                        # Criar estilo para métrica
                        metric_style = ParagraphStyle(
                            'MetricValue',
                            parent=styles['Heading1'],
                            fontSize=48,
                            textColor=colors.HexColor('#1f2937'),
                            alignment=TA_CENTER,
                            spaceAfter=10
                        )

                        metric_label_style = ParagraphStyle(
                            'MetricLabel',
                            parent=styles['Normal'],
                            fontSize=14,
                            textColor=colors.HexColor('#6b7280'),
                            alignment=TA_CENTER,
                            spaceAfter=20
                        )

                        # Renderizar valor
                        value_text = Paragraph(f"<b>{metric_value:,}</b>", metric_style)
                        story.append(value_text)

                        # Renderizar label se disponível
                        if metric_label and metric_label != str(metric_value):
                            label_text = Paragraph(metric_label, metric_label_style)
                            story.append(label_text)
                    else:
                        metric_text = Paragraph(
                            f"<i>Métrica: dados não disponíveis</i>",
                            styles['Normal']
                        )
                        story.append(metric_text)

                elif widget_data:
                    try:
                        # Tentar renderizar gráfico Plotly como imagem
                        if widget_type in ['line', 'bar', 'pie', 'area', 'scatter', 'table']:
                            img_bytes = ExportService._render_plotly_to_image(
                                widget_data,
                                widget_type,
                                widget.get('config', {})
                            )
                            if img_bytes:
                                img = RLImage(img_bytes, width=500, height=300)
                                story.append(img)
                            else:
                                # Sem dados para renderizar
                                no_data_text = Paragraph(
                                    f"<i>Gráfico sem dados. Visualize o dashboard para gerar os dados.</i>",
                                    styles['Italic']
                                )
                                story.append(no_data_text)
                    except Exception as e:
                        logger.warning(f"Error rendering widget {widget.get('id')}: {e}")
                        error_text = Paragraph(
                            f"<i>Erro ao renderizar gráfico: {str(e)[:100]}</i>",
                            styles['Italic']
                        )
                        story.append(error_text)
                else:
                    # Outros tipos sem dados
                    no_data_text = Paragraph(
                        f"<i>Dados não disponíveis. Visualize o dashboard para gerar os dados.</i>",
                        styles['Italic']
                    )
                    story.append(no_data_text)

                story.append(Spacer(1, 20))

                # Page break entre widgets (opcional)
                if idx < len(widgets) - 1:
                    story.append(PageBreak())

            # Gerar PDF
            doc.build(story)

            logger.info(f"✅ PDF exported successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"❌ Error exporting dashboard to PDF: {e}")
            raise

    @staticmethod
    def _render_plotly_to_image(
        data: Dict[str, Any],
        chart_type: str,
        config: Dict[str, Any] = {}
    ) -> Optional[io.BytesIO]:
        """
        Renderiza gráfico Plotly como imagem PNG a partir de resultados do Elasticsearch

        Args:
            data: Resultados do Elasticsearch (aggregations)
            chart_type: Tipo do gráfico (line, bar, pie, area, scatter)
            config: Configuração adicional do Plotly

        Returns:
            BytesIO com imagem PNG ou None
        """
        try:
            # Verificar se há dados
            if not data:
                logger.warning("No data provided for chart rendering")
                return None

            # Log dos dados recebidos para debug
            logger.info(f"📊 Chart data received: {json.dumps(data, indent=2)[:500]}")

            # Criar figura Plotly baseado no tipo
            fig = go.Figure()

            # Extrair dados dos resultados do Elasticsearch
            # Formato esperado: {"aggregations": {"buckets": [...]}} ou dados diretos

            # Tentar diferentes formatos de dados
            if 'data' in data and isinstance(data['data'], list):
                # Formato processado do elasticsearch_service: [{"label": "x", "value": y}]
                data_list = data['data']

                if not data_list:
                    logger.warning("Data list is empty")
                    return None

                # Extrair labels e values
                labels = [item.get('label', '') for item in data_list]
                values = [item.get('value', 0) for item in data_list]

                logger.info(f"📊 Extracted {len(labels)} data points")

                if chart_type == 'pie':
                    fig.add_trace(go.Pie(labels=labels, values=values))
                elif chart_type == 'bar':
                    fig.add_trace(go.Bar(x=labels, y=values))
                elif chart_type in ['line', 'area']:
                    mode = 'lines+markers' if chart_type == 'line' else 'lines'
                    fill = 'tozeroy' if chart_type == 'area' else None
                    fig.add_trace(go.Scatter(
                        x=labels,
                        y=values,
                        mode=mode,
                        fill=fill
                    ))
                elif chart_type == 'scatter':
                    fig.add_trace(go.Scatter(
                        x=labels,
                        y=values,
                        mode='markers'
                    ))

            elif 'aggregations' in data:
                # Formato Elasticsearch com aggregations
                aggs = data['aggregations']
                # Pegar primeira aggregation
                first_agg_key = list(aggs.keys())[0] if aggs else None
                if first_agg_key:
                    buckets = aggs[first_agg_key].get('buckets', [])

                    if not buckets:
                        return None

                    # Extrair labels e values
                    labels = [bucket.get('key', '') for bucket in buckets]
                    values = [bucket.get('doc_count', 0) for bucket in buckets]

                    if chart_type == 'pie':
                        fig.add_trace(go.Pie(labels=labels, values=values))
                    elif chart_type == 'bar':
                        fig.add_trace(go.Bar(x=labels, y=values))
                    elif chart_type in ['line', 'area']:
                        mode = 'lines+markers' if chart_type == 'line' else 'lines'
                        fill = 'tozeroy' if chart_type == 'area' else None
                        fig.add_trace(go.Scatter(
                            x=labels,
                            y=values,
                            mode=mode,
                            fill=fill
                        ))
                    elif chart_type == 'scatter':
                        fig.add_trace(go.Scatter(
                            x=labels,
                            y=values,
                            mode='markers'
                        ))

            elif 'data' in data and isinstance(data['data'], dict):
                # Formato Plotly direto
                for trace in data.get('data', []):
                    if chart_type == 'line':
                        fig.add_trace(go.Scatter(
                            x=trace.get('x', []),
                            y=trace.get('y', []),
                            name=trace.get('name', ''),
                            mode='lines+markers'
                        ))
                    elif chart_type == 'bar':
                        fig.add_trace(go.Bar(
                            x=trace.get('x', []),
                            y=trace.get('y', []),
                            name=trace.get('name', '')
                        ))
                    elif chart_type == 'pie':
                        fig.add_trace(go.Pie(
                            labels=trace.get('labels', []),
                            values=trace.get('values', [])
                        ))
                    elif chart_type in ['area', 'scatter']:
                        mode = 'lines' if chart_type == 'area' else 'markers'
                        fill = 'tozeroy' if chart_type == 'area' else None
                        fig.add_trace(go.Scatter(
                            x=trace.get('x', []),
                            y=trace.get('y', []),
                            name=trace.get('name', ''),
                            mode=mode,
                            fill=fill
                        ))
            else:
                logger.warning(f"Unknown data format: {data.keys()}")
                return None

            # Verificar se figura tem traces
            if not fig.data:
                logger.warning("No traces added to figure")
                return None

            # Configurar layout
            layout = data.get('layout', {})
            fig.update_layout(
                title=layout.get('title', ''),
                width=800,
                height=500,
                showlegend=True,
                template='plotly_white'
            )

            # Converter para imagem PNG
            img_bytes = pio.to_image(fig, format='png', width=800, height=500)
            return io.BytesIO(img_bytes)

        except Exception as e:
            logger.warning(f"Error rendering Plotly chart: {e}")
            return None

    @staticmethod
    async def export_dashboard_png(
        dashboard_id: str,
        dashboard_url: str,
        output_path: Optional[str] = None,
        width: int = 1920,
        height: int = 1080
    ) -> str:
        """
        Exporta dashboard como screenshot PNG usando Playwright

        Args:
            dashboard_id: ID do dashboard
            dashboard_url: URL do dashboard
            output_path: Caminho para salvar PNG (opcional)
            width: Largura da screenshot
            height: Altura da screenshot

        Returns:
            Caminho do arquivo PNG gerado
        """
        try:
            from playwright.async_api import async_playwright

            # Preparar caminho de saída
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"dashboard_{dashboard_id}_{timestamp}.png"
                output_path = os.path.join("/app/static/downloads", filename)

            # Criar diretório se não existir
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # Capturar screenshot com Playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={'width': width, 'height': height})

                # Navegar para URL
                await page.goto(dashboard_url, wait_until='networkidle')

                # Aguardar carregamento de gráficos
                await page.wait_for_timeout(2000)

                # Tirar screenshot
                await page.screenshot(path=output_path, full_page=True)

                await browser.close()

            logger.info(f"✅ PNG screenshot saved: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"❌ Error capturing dashboard screenshot: {e}")
            raise
