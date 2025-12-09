/**
 * Login Page
 * Authentication page with username/password login
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { useSettingsStore } from '../stores/settingsStore';
import { API_URL } from '../config/api';

interface SSOProvider {
  id: string;
  name: string;
  provider_type: string;
}

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { theme } = useSettingsStore();
  const { login, isAuthenticated, isLoading, error, clearError } = useAuthStore();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [ssoProviders, setSsoProviders] = useState<SSOProvider[]>([]);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  // SSO not used in this project (Intelligence Platform)
  // SSO is only available in Dashboard AI project

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    const success = await login(username, password);
    if (success) {
      navigate('/');
    }
  };

  // Theme colors
  const colors = {
    light: {
      bg: '#ffffff',
      cardBg: '#f8f9fa',
      text: '#1a1a1a',
      textSecondary: '#6c757d',
      border: '#dee2e6',
      inputBg: '#ffffff',
      inputBorder: '#ced4da',
      inputFocus: '#0d6efd',
      primary: '#0d6efd',
      primaryHover: '#0b5ed7',
      error: '#dc3545',
    },
    dark: {
      bg: '#1a1a1a',
      cardBg: '#2d2d2d',
      text: '#ffffff',
      textSecondary: '#adb5bd',
      border: '#404040',
      inputBg: '#3a3a3a',
      inputBorder: '#4a4a4a',
      inputFocus: '#0d6efd',
      primary: '#0d6efd',
      primaryHover: '#0b5ed7',
      error: '#dc3545',
    },
    monokai: {
      bg: '#272822',
      cardBg: '#3e3d32',
      text: '#f8f8f2',
      textSecondary: '#75715e',
      border: '#49483e',
      inputBg: '#3e3d32',
      inputBorder: '#49483e',
      inputFocus: '#66d9ef',
      primary: '#66d9ef',
      primaryHover: '#50c9df',
      error: '#f92672',
    },
    dracula: {
      bg: '#282a36',
      cardBg: '#44475a',
      text: '#f8f8f2',
      textSecondary: '#6272a4',
      border: '#44475a',
      inputBg: '#44475a',
      inputBorder: '#6272a4',
      inputFocus: '#bd93f9',
      primary: '#bd93f9',
      primaryHover: '#9d73d9',
      error: '#ff5555',
    },
    nord: {
      bg: '#2e3440',
      cardBg: '#3b4252',
      text: '#eceff4',
      textSecondary: '#d8dee9',
      border: '#4c566a',
      inputBg: '#3b4252',
      inputBorder: '#4c566a',
      inputFocus: '#88c0d0',
      primary: '#88c0d0',
      primaryHover: '#68a0b0',
      error: '#bf616a',
    },
    solarized: {
      bg: '#002b36',
      cardBg: '#073642',
      text: '#fdf6e3',
      textSecondary: '#93a1a1',
      border: '#586e75',
      inputBg: '#073642',
      inputBorder: '#586e75',
      inputFocus: '#268bd2',
      primary: '#268bd2',
      primaryHover: '#1671b2',
      error: '#dc322f',
    },
  };

  const currentColors = colors[theme as keyof typeof colors] || colors.light;

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: currentColors.bg,
        padding: '20px',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '400px',
          backgroundColor: currentColors.cardBg,
          borderRadius: '12px',
          padding: '40px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
          border: `1px solid ${currentColors.border}`,
        }}
      >
        {/* Logo/Title */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <h1
            style={{
              fontSize: '28px',
              fontWeight: '700',
              color: currentColors.text,
              marginBottom: '8px',
            }}
          >
            Minerva Intelligence Platform
          </h1>
          <p
            style={{
              fontSize: '14px',
              color: currentColors.textSecondary,
              margin: 0,
            }}
          >
            Faça login para continuar
          </p>
        </div>

        {/* Error Message */}
        {error && (
          <div
            style={{
              backgroundColor: `${currentColors.error}20`,
              border: `1px solid ${currentColors.error}`,
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '24px',
            }}
          >
            <p
              style={{
                color: currentColors.error,
                fontSize: '14px',
                margin: 0,
              }}
            >
              {error}
            </p>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          {/* Username Field */}
          <div style={{ marginBottom: '20px' }}>
            <label
              htmlFor="username"
              style={{
                display: 'block',
                fontSize: '14px',
                fontWeight: '500',
                color: currentColors.text,
                marginBottom: '8px',
              }}
            >
              Usuário
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Digite seu usuário"
              disabled={isLoading}
              required
              style={{
                width: '100%',
                padding: '12px',
                fontSize: '14px',
                backgroundColor: currentColors.inputBg,
                color: currentColors.text,
                border: `1px solid ${currentColors.inputBorder}`,
                borderRadius: '8px',
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e) => {
                e.target.style.borderColor = currentColors.inputFocus;
              }}
              onBlur={(e) => {
                e.target.style.borderColor = currentColors.inputBorder;
              }}
            />
          </div>

          {/* Password Field */}
          <div style={{ marginBottom: '24px' }}>
            <label
              htmlFor="password"
              style={{
                display: 'block',
                fontSize: '14px',
                fontWeight: '500',
                color: currentColors.text,
                marginBottom: '8px',
              }}
            >
              Senha
            </label>
            <div style={{ position: 'relative' }}>
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Digite sua senha"
                disabled={isLoading}
                required
                style={{
                  width: '100%',
                  padding: '12px',
                  paddingRight: '45px',
                  fontSize: '14px',
                  backgroundColor: currentColors.inputBg,
                  color: currentColors.text,
                  border: `1px solid ${currentColors.inputBorder}`,
                  borderRadius: '8px',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = currentColors.inputFocus;
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = currentColors.inputBorder;
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                disabled={isLoading}
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: currentColors.textSecondary,
                  cursor: 'pointer',
                  padding: '4px',
                  fontSize: '14px',
                }}
              >
                {showPassword ? '🙈' : '👁️'}
              </button>
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            style={{
              width: '100%',
              padding: '12px',
              fontSize: '16px',
              fontWeight: '600',
              color: '#ffffff',
              backgroundColor: currentColors.primary,
              border: 'none',
              borderRadius: '8px',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              opacity: isLoading ? 0.6 : 1,
              transition: 'all 0.2s',
            }}
            onMouseEnter={(e) => {
              if (!isLoading) {
                e.currentTarget.style.backgroundColor = currentColors.primaryHover;
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = currentColors.primary;
            }}
          >
            {isLoading ? 'Entrando...' : 'Entrar'}
          </button>
        </form>

        {/* SSO Login Options */}
        {ssoProviders.length > 0 && (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                margin: '24px 0',
                gap: '12px',
              }}
            >
              <div
                style={{
                  flex: 1,
                  height: '1px',
                  backgroundColor: currentColors.border,
                }}
              ></div>
              <span
                style={{
                  color: currentColors.textSecondary,
                  fontSize: '12px',
                  fontWeight: '500',
                }}
              >
                OU
              </span>
              <div
                style={{
                  flex: 1,
                  height: '1px',
                  backgroundColor: currentColors.border,
                }}
              ></div>
            </div>

            {ssoProviders.map((provider) =>
              provider.provider_type === 'entra_id' ? (
                <a
                  key={provider.id}
                  href={`${API_URL}/auth/sso/${provider.id}/login`}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '12px',
                    width: '100%',
                    padding: '12px',
                    backgroundColor: '#ffffff',
                    border: '1px solid #d1d5db',
                    borderRadius: '8px',
                    color: '#1f2937',
                    textDecoration: 'none',
                    fontSize: '14px',
                    fontWeight: '500',
                    transition: 'all 0.2s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#f9fafb';
                    e.currentTarget.style.borderColor = '#9ca3af';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = '#ffffff';
                    e.currentTarget.style.borderColor = '#d1d5db';
                  }}
                >
                  <svg
                    width="21"
                    height="21"
                    viewBox="0 0 21 21"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <rect x="1" y="1" width="9" height="9" fill="#f25022" />
                    <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
                    <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
                    <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
                  </svg>
                  Entrar com Microsoft
                </a>
              ) : null
            )}
          </>
        )}

        {/* Demo Credentials */}
        <div
          style={{
            marginTop: '24px',
            padding: '16px',
            backgroundColor: `${currentColors.primary}10`,
            border: `1px solid ${currentColors.primary}30`,
            borderRadius: '8px',
          }}
        >
          <p
            style={{
              fontSize: '12px',
              color: currentColors.textSecondary,
              margin: '0 0 8px 0',
              fontWeight: '600',
            }}
          >
            Credenciais de teste:
          </p>
          <p
            style={{
              fontSize: '12px',
              color: currentColors.text,
              margin: '0 0 4px 0',
              fontFamily: 'monospace',
            }}
          >
            <strong>Admin:</strong> admin / admin123
          </p>
          <p
            style={{
              fontSize: '12px',
              color: currentColors.text,
              margin: 0,
              fontFamily: 'monospace',
            }}
          >
            <strong>Power:</strong> angello / angello123
          </p>
        </div>
      </div>
    </div>
  );
};
