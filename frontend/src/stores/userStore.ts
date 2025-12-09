/**
 * User Store
 * Gerencia informações do usuário (temporário até implementar autenticação real)
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UserState {
  userId: string;
  userName: string;
  setUserName: (name: string) => void;
}

/**
 * Generate a unique user ID based on browser fingerprint
 * This is temporary until we implement real authentication
 */
function generateUserId(): string {
  // Check if we already have a user ID in localStorage
  const stored = localStorage.getItem('dashboard-user-id');
  if (stored) return stored;

  // Generate new ID based on timestamp + random
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  const userId = `user_${timestamp}_${random}`;

  // Store it
  localStorage.setItem('dashboard-user-id', userId);
  return userId;
}

/**
 * User store
 *
 * Manages temporary user identification until we implement proper authentication.
 * Currently uses browser-based IDs stored in localStorage.
 *
 * Future: Replace with JWT/OAuth based authentication system
 */
export const useUserStore = create<UserState>()(
  persist(
    (set) => ({
      // Generate or retrieve user ID
      userId: generateUserId(),

      // Default user name (can be customized)
      userName: 'Usuário',

      // Update user name
      setUserName: (name: string) => set({ userName: name }),
    }),
    {
      name: 'dashboard-user-storage',
    }
  )
);
