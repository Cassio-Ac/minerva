/**
 * Theme Styles Utility
 * Centralized theme-aware style generators
 */

import type { ThemeColors } from '@stores/settingsStore';

export const getThemeStyles = (currentColors: ThemeColors) => ({
  /**
   * Message bubble styles for chat
   */
  messageBubble: (isUserMessage: boolean) => ({
    backgroundColor: isUserMessage
      ? currentColors.accent.primary
      : currentColors.bg.primary,
    color: isUserMessage
      ? currentColors.text.inverse
      : currentColors.text.primary,
    borderWidth: '1px',
    borderStyle: 'solid' as const,
    borderColor: isUserMessage ? 'transparent' : currentColors.border.default,
  }),

  /**
   * Textarea/Input styles
   */
  textarea: {
    backgroundColor: currentColors.bg.secondary,
    borderWidth: '1px',
    borderStyle: 'solid' as const,
    borderColor: currentColors.border.default,
    color: currentColors.text.primary,
    outline: 'none',
  },

  /**
   * Border top separator
   */
  borderTop: {
    borderTopWidth: '1px',
    borderTopStyle: 'solid' as const,
    borderTopColor: currentColors.border.default,
  },

  /**
   * Card/Container with border
   */
  card: {
    backgroundColor: currentColors.bg.primary,
    borderWidth: '1px',
    borderStyle: 'solid' as const,
    borderColor: currentColors.border.default,
  },

  /**
   * Input field styles
   */
  input: {
    backgroundColor: currentColors.bg.secondary,
    color: currentColors.text.primary,
  },

  /**
   * Border styles
   */
  border: {
    borderColor: currentColors.border.default,
  },

  /**
   * Text styles
   */
  text: {
    color: currentColors.text.primary,
  },
});
