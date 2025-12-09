/**
 * Settings Store (Zustand)
 * Gerencia configurações globais: tema, preferências, etc.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type Theme = 'light' | 'dark' | 'monokai' | 'dracula' | 'nord' | 'solarized';

export interface ThemeColors {
  // Background colors
  bg: {
    primary: string;
    secondary: string;
    tertiary: string;
    hover: string;
  };
  // Text colors
  text: {
    primary: string;
    secondary: string;
    muted: string;
    inverse: string;
  };
  // Border colors
  border: {
    default: string;
    focus: string;
  };
  // Accent colors (buttons, links, etc)
  accent: {
    primary: string;
    primaryHover: string;
    secondary: string;
    secondaryHover: string;
    success: string;
    warning: string;
    error: string;
    info: string;
  };
  // Chart colors
  chart: string[];
}

// Definição de temas
export const themes: Record<Theme, ThemeColors> = {
  light: {
    bg: {
      primary: '#ffffff',
      secondary: '#f9fafb',
      tertiary: '#f3f4f6',
      hover: '#e5e7eb',
    },
    text: {
      primary: '#111827',
      secondary: '#374151',
      muted: '#6b7280',
      inverse: '#ffffff',
    },
    border: {
      default: '#e5e7eb',
      focus: '#3b82f6',
    },
    accent: {
      primary: '#3b82f6',
      primaryHover: '#2563eb',
      secondary: '#8b5cf6',
      secondaryHover: '#7c3aed',
      success: '#10b981',
      warning: '#f59e0b',
      error: '#ef4444',
      info: '#06b6d4',
    },
    chart: ['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899', '#f97316'],
  },
  dark: {
    bg: {
      primary: '#1f2937',
      secondary: '#111827',
      tertiary: '#374151',
      hover: '#4b5563',
    },
    text: {
      primary: '#f9fafb',
      secondary: '#e5e7eb',
      muted: '#9ca3af',
      inverse: '#111827',
    },
    border: {
      default: '#374151',
      focus: '#60a5fa',
    },
    accent: {
      primary: '#60a5fa',
      primaryHover: '#3b82f6',
      secondary: '#a78bfa',
      secondaryHover: '#8b5cf6',
      success: '#34d399',
      warning: '#fbbf24',
      error: '#f87171',
      info: '#22d3ee',
    },
    chart: ['#60a5fa', '#a78bfa', '#34d399', '#fbbf24', '#f87171', '#22d3ee', '#f472b6', '#fb923c'],
  },
  monokai: {
    bg: {
      primary: '#272822',
      secondary: '#1e1f1c',
      tertiary: '#3e3d32',
      hover: '#49483e',
    },
    text: {
      primary: '#f8f8f2',
      secondary: '#cfcfc2',
      muted: '#75715e',
      inverse: '#272822',
    },
    border: {
      default: '#3e3d32',
      focus: '#66d9ef',
    },
    accent: {
      primary: '#66d9ef',
      primaryHover: '#52c5df',
      secondary: '#ae81ff',
      secondaryHover: '#9567ee',
      success: '#a6e22e',
      warning: '#e6db74',
      error: '#f92672',
      info: '#66d9ef',
    },
    chart: ['#66d9ef', '#ae81ff', '#a6e22e', '#e6db74', '#f92672', '#fd971f', '#f8f8f2', '#75715e'],
  },
  dracula: {
    bg: {
      primary: '#282a36',
      secondary: '#1e1f29',
      tertiary: '#383a59',
      hover: '#44475a',
    },
    text: {
      primary: '#f8f8f2',
      secondary: '#d4d4d8',
      muted: '#6272a4',
      inverse: '#282a36',
    },
    border: {
      default: '#44475a',
      focus: '#8be9fd',
    },
    accent: {
      primary: '#8be9fd',
      primaryHover: '#6cd5e5',
      secondary: '#bd93f9',
      secondaryHover: '#a87de8',
      success: '#50fa7b',
      warning: '#f1fa8c',
      error: '#ff5555',
      info: '#8be9fd',
    },
    chart: ['#8be9fd', '#bd93f9', '#50fa7b', '#f1fa8c', '#ff5555', '#ff79c6', '#ffb86c', '#6272a4'],
  },
  nord: {
    bg: {
      primary: '#2e3440',
      secondary: '#3b4252',
      tertiary: '#434c5e',
      hover: '#4c566a',
    },
    text: {
      primary: '#eceff4',
      secondary: '#e5e9f0',
      muted: '#d8dee9',
      inverse: '#2e3440',
    },
    border: {
      default: '#4c566a',
      focus: '#88c0d0',
    },
    accent: {
      primary: '#88c0d0',
      primaryHover: '#6fb3c3',
      secondary: '#81a1c1',
      secondaryHover: '#6a8aad',
      success: '#a3be8c',
      warning: '#ebcb8b',
      error: '#bf616a',
      info: '#5e81ac',
    },
    chart: ['#88c0d0', '#81a1c1', '#a3be8c', '#ebcb8b', '#bf616a', '#d08770', '#b48ead', '#5e81ac'],
  },
  solarized: {
    bg: {
      primary: '#002b36',
      secondary: '#073642',
      tertiary: '#586e75',
      hover: '#657b83',
    },
    text: {
      primary: '#fdf6e3',
      secondary: '#eee8d5',
      muted: '#93a1a1',
      inverse: '#002b36',
    },
    border: {
      default: '#586e75',
      focus: '#268bd2',
    },
    accent: {
      primary: '#268bd2',
      primaryHover: '#1f7dbe',
      secondary: '#6c71c4',
      secondaryHover: '#5861b0',
      success: '#859900',
      warning: '#b58900',
      error: '#dc322f',
      info: '#2aa198',
    },
    chart: ['#268bd2', '#6c71c4', '#859900', '#b58900', '#dc322f', '#d33682', '#2aa198', '#cb4b16'],
  },
};

interface SettingsStore {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  currentColors: ThemeColors;
}

export const useSettingsStore = create<SettingsStore>()(
  persist(
    (set, get) => ({
      theme: 'light',
      currentColors: themes.light,

      setTheme: (theme: Theme) => {
        set({
          theme,
          currentColors: themes[theme],
        });
        console.log('🎨 Theme changed to:', theme);
      },
    }),
    {
      name: 'dashboard-settings',
    }
  )
);
