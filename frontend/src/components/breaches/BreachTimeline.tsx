import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useSettingsStore } from '@stores/settingsStore';

interface TimelineData {
  date: string;
  count: number;
}

interface BreachTimelineProps {
  data: TimelineData[];
}

const BreachTimeline: React.FC<BreachTimelineProps> = ({ data }) => {
  const { theme, currentColors } = useSettingsStore();

  const chartColors = {
    light: {
      area: '#ef4444',
      gradient1: '#ef4444',
      gradient2: '#fca5a5',
      grid: '#e5e7eb',
      text: '#374151',
    },
    dark: {
      area: '#f87171',
      gradient1: '#f87171',
      gradient2: '#991b1b',
      grid: '#374151',
      text: '#d1d5db',
    },
    monokai: {
      area: '#f92672',
      gradient1: '#f92672',
      gradient2: '#272822',
      grid: '#49483e',
      text: '#f8f8f2',
    },
    dracula: {
      area: '#ff5555',
      gradient1: '#ff5555',
      gradient2: '#6272a4',
      grid: '#44475a',
      text: '#f8f8f2',
    },
    nord: {
      area: '#bf616a',
      gradient1: '#bf616a',
      gradient2: '#5e81ac',
      grid: '#3b4252',
      text: '#d8dee9',
    },
    solarized: {
      area: '#dc322f',
      gradient1: '#dc322f',
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
        Timeline de Vazamentos
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorBreachCount" x1="0" y1="0" x2="0" y2="1">
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
              borderRadius: '6px',
              color: currentColors.text.primary,
            }}
            labelStyle={{ color: currentColors.text.primary }}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke={colors.area}
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorBreachCount)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default BreachTimeline;
