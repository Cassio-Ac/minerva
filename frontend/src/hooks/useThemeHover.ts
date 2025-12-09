/**
 * useThemeHover Hook
 * Provides reusable hover handlers for theme-aware components
 */

import React from 'react';
import { useSettingsStore } from '@stores/settingsStore';

export const useThemeHover = () => {
  const { currentColors } = useSettingsStore();

  const createHoverHandlers = (
    hoverBg: string,
    normalBg: string = 'transparent',
    hoverColor?: string,
    normalColor?: string
  ) => ({
    onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
      e.currentTarget.style.backgroundColor = hoverBg;
      if (hoverColor) e.currentTarget.style.color = hoverColor;
    },
    onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
      e.currentTarget.style.backgroundColor = normalBg;
      if (normalColor) e.currentTarget.style.color = normalColor;
    },
  });

  return { createHoverHandlers, currentColors };
};
