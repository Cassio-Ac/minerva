/**
 * Auth Store
 * Gerencia autenticação JWT, login/logout e estado do usuário
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const API_BASE = `${import.meta.env.VITE_API_URL || 'http://localhost:8002'}/api/v1`;

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: 'admin' | 'power' | 'operator' | 'reader';
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
  last_login: string | null;
  can_manage_users: boolean;
  can_use_llm: boolean;
  can_create_dashboards: boolean;
  can_upload_csv: boolean;
  has_index_restrictions: boolean;
  can_configure_system: boolean;
  profile_photo_url: string | null;
  photo_source: string | null;
  photo_updated_at: string | null;
}

interface AuthState {
  // State
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  loadUser: () => Promise<void>;
  clearError: () => void;
}

/**
 * Auth Store
 *
 * Manages JWT authentication with persistent storage.
 * Automatically loads user on init if token exists.
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      /**
       * Login with username/password
       */
      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null });

        try {
          const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
          });

          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Login failed');
          }

          const data = await response.json();

          set({
            user: data.user,
            token: data.access_token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          console.log('✅ Login successful:', data.user.username);
          return true;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Login failed';
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            isLoading: false,
            error: errorMessage,
          });
          console.error('❌ Login error:', errorMessage);
          return false;
        }
      },

      /**
       * Logout - clear all auth data
       */
      logout: () => {
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
        });
        console.log('👋 Logged out');
      },

      /**
       * Load user from token (refresh user data)
       */
      loadUser: async () => {
        const { token } = get();

        if (!token) {
          set({ isAuthenticated: false, user: null });
          return;
        }

        set({ isLoading: true });

        try {
          const response = await fetch(`${API_BASE}/auth/me`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error('Failed to load user');
          }

          const user = await response.json();

          set({
            user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          console.log('✅ User loaded:', user.username);
        } catch (error) {
          console.error('❌ Failed to load user:', error);
          // Token might be invalid/expired - clear auth
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            isLoading: false,
            error: 'Session expired',
          });
        }
      },

      /**
       * Clear error message
       */
      clearError: () => set({ error: null }),
    }),
    {
      name: 'dashboard-auth-storage',
      // Only persist token, will load user on init
      partialize: (state) => ({
        token: state.token,
      }),
    }
  )
);

// Auto-load user on store initialization if token exists
if (useAuthStore.getState().token) {
  useAuthStore.getState().loadUser();
}
