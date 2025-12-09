import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useSettingsStore } from '@stores/settingsStore';

interface TimelineData {
  date: string;
  count: number;
}

interface NewsTimelineProps {
  data: TimelineData[];
}

const NewsTimeline: React.FC<NewsTimelineProps> = ({ data }) => {
  const { theme, currentColors } = useSettingsStore();

  const chartColors = {
    light: {
      area: '#3b82f6',
      gradient1: '#3b82f6',
      gradient2: '#93c5fd',
      grid: '#e5e7eb',
      text: '#374151',
    },
    dark: {
      area: '#60a5fa',
      gradient1: '#60a5fa',
      gradient2: '#1e40af',
      grid: '#374151',
      text: '#d1d5db',
    },
    monokai: {
      area: '#a6e22e',
      gradient1: '#a6e22e',
      gradient2: '#272822',
      grid: '#49483e',
      text: '#f8f8f2',
    },
    dracula: {
      area: '#ff79c6',
      gradient1: '#ff79c6',
      gradient2: '#6272a4',
      grid: '#44475a',
      text: '#f8f8f2',
    },
    nord: {
      area: '#88c0d0',
      gradient1: '#88c0d0',
      gradient2: '#5e81ac',
      grid: '#3b4252',
      text: '#d8dee9',
    },
    solarized: {
      area: '#268bd2',
      gradient1: '#268bd2',
      gradient2: '#073642',
      grid: '#073642',
      text: '#839496',
    },
  };

  const colors = chartColors[theme as keyof typeof chartColors] || chartColors.light;

  return (
    <div
      className="rounded-lg shadow p-6"
      style={{
        backgroundColor: currentColors.bg.primary,
      }}
    >
      <h3
        className="text-lg font-semibold mb-4"
        style={{ color: currentColors.text.primary }}
      >
        Timeline de Notícias
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={colors.gradient1} stopOpacity={0.8} />
              <stop offset="95%" stopColor={colors.gradient2} stopOpacity={0.1} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} />
          <XAxis
            dataKey="date"
            stroke={colors.text}
            style={{ fontSize: '12px' }}
          />
          <YAxis
            stroke={colors.text}
            style={{ fontSize: '12px' }}
            domain={[0, 'dataMax + 5']}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: theme === 'dark' ? '#1f2937' : '#ffffff',
              border: `1px solid ${colors.grid}`,
              borderRadius: '0.5rem',
              color: colors.text,
            }}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke={colors.area}
            fillOpacity={1}
            fill="url(#colorCount)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default NewsTimeline;
