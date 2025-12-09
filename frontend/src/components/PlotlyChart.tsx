/**
 * PlotlyChart Component
 * Renderiza visualizações usando Plotly.js
 */

import React from 'react';
import Plot from 'react-plotly.js';
import type { VisualizationType } from '@types/widget';
import { useSettingsStore } from '@stores/settingsStore';

interface PlotlyChartProps {
  type: VisualizationType;
  data: any;
  title?: string;
  config?: any;
}

export const PlotlyChart: React.FC<PlotlyChartProps> = ({
  type,
  data,
  title,
  config = {},
}) => {
  const { currentColors } = useSettingsStore();

  // Helper para detectar se um label é timestamp e formatar como data
  const formatLabel = (label: any) => {
    // Se for número muito grande (timestamp em ms), converter para data
    if (typeof label === 'number' && label > 1000000000000) {
      return new Date(label).toLocaleDateString('pt-BR');
    }
    // Se for string que parece timestamp, converter
    if (typeof label === 'string' && !isNaN(Number(label)) && Number(label) > 1000000000000) {
      return new Date(Number(label)).toLocaleDateString('pt-BR');
    }
    return label;
  };

  // Processar dados baseado no tipo
  const getPlotlyData = () => {
    if (!data || !data.data) {
      return [];
    }

    switch (type) {
      case 'pie':
        return [
          {
            type: 'pie',
            labels: data.data.map((d: any) => formatLabel(d.label)),
            values: data.data.map((d: any) => d.value),
            marker: {
              colors: config.colors || [
                currentColors.accent.primary,
                '#36A2EB',
                '#FFCE56',
                '#4BC0C0',
                '#9966FF',
                '#FF9F40',
              ],
            },
            textfont: {
              color: currentColors.text.inverse,
              size: 12,
            },
          },
        ];

      case 'bar':
        return [
          {
            type: 'bar',
            x: data.data.map((d: any) => formatLabel(d.label)),
            y: data.data.map((d: any) => d.value),
            marker: {
              color: config.colors?.[0] || currentColors.accent.primary,
            },
            text: data.data.map((d: any) => d.value),
            textposition: 'outside',
            textfont: {
              color: currentColors.text.primary,
            },
          },
        ];

      case 'line':
        return [
          {
            type: 'scatter',
            mode: 'lines+markers',
            x: data.data.map((d: any) => formatLabel(d.label)),
            y: data.data.map((d: any) => d.value),
            line: {
              color: config.colors?.[0] || currentColors.accent.primary,
              width: 2,
            },
            marker: {
              color: config.colors?.[0] || currentColors.accent.primary,
              size: 6,
            },
          },
        ];

      case 'metric':
        // Para métricas, vamos usar um indicador
        const value = data.data[0]?.value || 0;
        return [
          {
            type: 'indicator',
            mode: 'number+delta',
            value: value,
            number: { font: { size: 60 } },
            domain: { x: [0, 1], y: [0, 1] },
          },
        ];

      case 'table':
        // Para tabelas, usar Plotly table
        if (!data.data || data.data.length === 0) {
          return [];
        }

        // Extrair colunas dos dados
        const firstRow = data.data[0];
        const columns = Object.keys(firstRow);

        return [
          {
            type: 'table',
            header: {
              values: columns.map((col) => `<b>${col}</b>`),
              align: 'left',
              fill: { color: '#4F46E5' },
              font: { color: 'white', size: 14 },
            },
            cells: {
              values: columns.map((col) => data.data.map((row: any) => row[col])),
              align: 'left',
              fill: { color: ['#F9FAFB', '#FFFFFF'] },
              font: { size: 12 },
            },
          },
        ];

      case 'area':
        // Gráfico de área (similar ao line mas preenchido)
        return [
          {
            type: 'scatter',
            mode: 'lines',
            fill: 'tozeroy',
            x: data.data.map((d: any) => formatLabel(d.label)),
            y: data.data.map((d: any) => d.value),
            line: {
              color: config.colors?.[0] || currentColors.accent.primary,
              width: 2,
            },
            fillcolor: config.colors?.[0]
              ? `${config.colors[0]}33`
              : `${currentColors.accent.primary}33`,
          },
        ];

      case 'scatter':
        // Gráfico de dispersão
        return [
          {
            type: 'scatter',
            mode: 'markers',
            x: data.data.map((d: any) => d.x || d.label),
            y: data.data.map((d: any) => d.y || d.value),
            marker: {
              size: data.data.map((d: any) => d.size || 10),
              color: config.colors?.[0] || '#10B981',
            },
          },
        ];

      default:
        return [];
    }
  };

  const layout = {
    title: title || '',
    autosize: true,
    margin: { l: 50, r: 40, t: 60, b: 80 },
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',
    font: {
      color: currentColors.text.primary,
      size: 12,
    },
    xaxis: {
      gridcolor: currentColors.border.default,
      tickfont: {
        color: currentColors.text.secondary,
        size: 11,
      },
      automargin: true,
    },
    yaxis: {
      gridcolor: currentColors.border.default,
      tickfont: {
        color: currentColors.text.secondary,
        size: 11,
      },
      automargin: true,
    },
    showlegend: false,
    ...config.layout,
  };

  const plotConfig = {
    responsive: true,
    displayModeBar: false,
    ...config.plotly,
  };

  return (
    <div className="w-full h-full">
      <Plot
        data={getPlotlyData()}
        layout={layout}
        config={plotConfig}
        style={{ width: '100%', height: '100%' }}
        useResizeHandler={true}
      />
    </div>
  );
};
