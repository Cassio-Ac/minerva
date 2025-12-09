/**
 * DashboardGrid Component
 * Grid com drag-and-drop usando react-grid-layout
 * Totalmente responsivo e elástico
 */

import React, { useMemo } from 'react';
import { Responsive, WidthProvider } from 'react-grid-layout';
import type { Layout, Layouts } from 'react-grid-layout';
import { WidgetCard } from './WidgetCard';
import { useDashboardStore } from '@stores/dashboardStore';
import { useSettingsStore } from '@stores/settingsStore';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface DashboardGridProps {
  cols?: number;
  rowHeight?: number;
}

export const DashboardGrid: React.FC<DashboardGridProps> = ({
  cols = 12,
  rowHeight = 60,
}) => {
  const { widgets, updateWidgetPosition, removeWidget } = useDashboardStore();
  const { currentColors } = useSettingsStore();

  // Layouts responsivos para diferentes breakpoints
  const layouts: Layouts = useMemo(() => {
    const baseLayout: Layout[] = widgets.map((widget) => ({
      i: widget.id,
      x: widget.position.x,
      y: widget.position.y,
      w: widget.position.w,
      h: widget.position.h,
      minW: 2,
      minH: 3,
    }));

    return {
      lg: baseLayout, // Large: 1200px+
      md: baseLayout, // Medium: 996px+
      sm: baseLayout.map(item => ({ ...item, w: Math.min(item.w, 6) })), // Small: 768px+ (max 6 cols)
      xs: baseLayout.map(item => ({ ...item, w: 4, x: 0 })), // Extra small: < 768px (stack)
    };
  }, [widgets]);

  // Handler quando layout muda (drag/resize)
  const handleLayoutChange = (newLayout: Layout[]) => {
    newLayout.forEach((item) => {
      const widget = widgets.find((w) => w.id === item.i);
      if (widget) {
        // Só atualizar se a posição mudou
        if (
          widget.position.x !== item.x ||
          widget.position.y !== item.y ||
          widget.position.w !== item.w ||
          widget.position.h !== item.h
        ) {
          updateWidgetPosition(item.i, {
            x: item.x,
            y: item.y,
            w: item.w,
            h: item.h,
          });
        }
      }
    });
  };

  if (widgets.length === 0) {
    return (
      <div className="flex items-center justify-center h-full min-h-96 rounded-lg border-2 border-dashed m-6" style={{
        backgroundColor: currentColors.bg.tertiary,
        borderColor: currentColors.border.default
      }}>
        <div className="text-center" style={{ color: currentColors.text.muted }}>
          <svg
            className="w-16 h-16 mx-auto mb-4 opacity-50"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"
            />
          </svg>
          <p className="text-lg font-medium mb-1">Nenhum widget ainda</p>
          <p className="text-sm">
            Use o chat para criar visualizações e começar seu dashboard
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-grid-container" style={{ backgroundColor: currentColors.bg.secondary }}>
      <ResponsiveGridLayout
        className="layout"
        layouts={layouts}
        breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480 }}
        cols={{ lg: 12, md: 10, sm: 6, xs: 4 }}
        rowHeight={rowHeight}
        onLayoutChange={handleLayoutChange}
        draggableHandle=".widget-header"
        compactType="vertical"
        preventCollision={false}
        isDraggable={true}
        isResizable={true}
        margin={[16, 16]}
        containerPadding={[24, 48]}
      >
        {widgets.map((widget) => (
          <div key={widget.id} className="grid-item">
            <WidgetCard widget={widget} onRemove={removeWidget} />
          </div>
        ))}
      </ResponsiveGridLayout>

      <style>{`
        .dashboard-grid-container {
          width: 100%;
          min-height: calc(100% + 48px);
          padding-bottom: 48px;
        }

        .layout {
          position: relative;
          width: 100% !important;
          min-height: 100%;
          padding-bottom: 24px;
        }

        .grid-item {
          background: transparent;
        }

        .react-grid-item {
          transition: all 200ms ease;
          transition-property: left, top, width, height;
        }

        .react-grid-item.react-grid-placeholder {
          background: #3b82f6;
          opacity: 0.2;
          transition-duration: 100ms;
          z-index: 2;
          border-radius: 8px;
        }

        .react-grid-item.resizing {
          transition: none;
          z-index: 100;
        }

        .react-grid-item.static {
          background: #ccc;
        }

        .react-grid-item .react-resizable-handle {
          position: absolute;
          width: 20px;
          height: 20px;
        }

        .react-grid-item .react-resizable-handle::after {
          content: "";
          position: absolute;
          right: 3px;
          bottom: 3px;
          width: 8px;
          height: 8px;
          border-right: 2px solid rgba(0, 0, 0, 0.4);
          border-bottom: 2px solid rgba(0, 0, 0, 0.4);
        }

        .widget-header {
          cursor: move;
          user-select: none;
        }

        .widget-header:active {
          cursor: grabbing;
        }
      `}</style>
    </div>
  );
};
