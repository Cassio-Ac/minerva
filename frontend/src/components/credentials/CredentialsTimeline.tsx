import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useSettingsStore } from '@stores/settingsStore';

interface TimelineData {
  date: string;
  count: number;
}

interface CredentialsTimelineProps {
  data: TimelineData[];
  title?: string;
}

const CredentialsTimeline: React.FC<CredentialsTimelineProps> = ({ data, title = 'Timeline de Vazamentos' }) => {
  const { theme, currentColors } = useSettingsStore();

  const chartColors = {
    light: {
      area: '#f97316',
      gradient1: '#f97316',
      gradient2: '#fed7aa',
      grid: '#e5e7eb',
      text: '#374151',
    },
    dark: {
      area: '#fb923c',
      gradient1: '#fb923c',
      gradient2: '#7c2d12',
      grid: '#374151',
      text: '#d1d5db',
    },
    monokai: {
      area: '#f97316',
      gradient1: '#f97316',
      gradient2: '#272822',
      grid: '#49483e',
      text: '#f8f8f2',
    },
    dracula: {
      area: '#ffb86c',
      gradient1: '#ffb86c',
      gradient2: '#6272a4',
      grid: '#44475a',
      text: '#f8f8f2',
    },
    nord: {
      area: '#d08770',
      gradient1: '#d08770',
      gradient2: '#5e81ac',
      grid: '#3b4252',
      text: '#d8dee9',
    },
    solarized: {
      area: '#cb4b16',
      gradient1: '#cb4b16',
      gradient2: '#073642',
      grid: '#073642',
      text: '#839496',
    },
  };

  const colors = chartColors[theme as keyof typeof chartColors] || chartColors.dark;

  // Format number for tooltip
  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toLocaleString('pt-BR');
  };

  return (
    <div
      className="rounded-lg shadow p-4"
      style={{
        backgroundColor: currentColors.bg.secondary,
        border: `1px solid ${currentColors.border.default}`,
      }}
    >
      <h3
        className="text-sm font-semibold mb-3"
        style={{ color: currentColors.text.primary }}
      >
        {title}
      </h3>
      <ResponsiveContainer width="100%" height={150}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorCredCount" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={colors.gradient1} stopOpacity={0.8} />
              <stop offset="95%" stopColor={colors.gradient2} stopOpacity={0.1} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} />
          <XAxis
            dataKey="date"
            stroke={colors.text}
            style={{ fontSize: '10px' }}
            tick={{ fontSize: 10 }}
          />
          <YAxis
            stroke={colors.text}
            style={{ fontSize: '10px' }}
            tick={{ fontSize: 10 }}
            tickFormatter={formatNumber}
            width={45}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: currentColors.bg.primary,
              border: `1px solid ${colors.grid}`,
              borderRadius: '6px',
              color: currentColors.text.primary,
              fontSize: '12px',
            }}
            labelStyle={{ color: currentColors.text.primary }}
            formatter={(value: number) => [formatNumber(value), 'Credenciais']}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke={colors.area}
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorCredCount)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default CredentialsTimeline;
