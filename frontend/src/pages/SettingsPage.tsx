/**
 * Settings Page
 * Página de configurações: temas, ES servers, preferências
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSettingsStore, Theme, themes } from '@stores/settingsStore';
import { ESServersManager } from '@pages/ESServersManager';
import { LLMProvidersManager } from '@components/LLMProvidersManager';
import { MCPManager } from '@components/MCPManager';
import { IndexMCPConfigManager } from '@components/IndexMCPConfigManager';
import { KnowledgeBase } from '@components/KnowledgeBase';
import { UserManager } from '@components/UserManager';
import { MetricsPanel } from '@components/MetricsPanel';
import { SSOProvidersManager } from '@components/SSOProvidersManager';
import { RSSManager } from '@components/RSSManager';

type Tab = 'appearance' | 'users' | 'sso' | 'llm' | 'elasticsearch' | 'mcp' | 'mcp-config' | 'knowledge' | 'rss' | 'metrics' | 'advanced';

export const SettingsPage: React.FC = () => {
  const navigate = useNavigate();
  const { theme, setTheme, currentColors } = useSettingsStore();
  const [activeTab, setActiveTab] = useState<Tab>('appearance');

  const themeOptions: { id: Theme; name: string; description: string }[] = [
    { id: 'light', name: 'Claro', description: 'Tema claro padrão' },
    { id: 'dark', name: 'Escuro', description: 'Tema escuro moderno' },
    { id: 'monokai', name: 'Monokai', description: 'Inspirado no editor Sublime Text' },
    { id: 'dracula', name: 'Dracula', description: 'Tema escuro vibrante' },
    { id: 'nord', name: 'Nord', description: 'Paleta ártica e elegante' },
    { id: 'solarized', name: 'Solarized Dark', description: 'Tema clássico para terminais' },
  ];

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{
        backgroundColor: currentColors.bg.secondary,
        color: currentColors.text.primary,
      }}
    >
      {/* Header */}
      <header
        className="border-b"
        style={{
          backgroundColor: currentColors.bg.primary,
          borderColor: currentColors.border.default,
        }}
      >
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                color: currentColors.text.secondary,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = currentColors.bg.hover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              <span className="font-medium">Menu</span>
            </button>

            <div
              className="h-8 w-px"
              style={{ backgroundColor: currentColors.border.default }}
            ></div>

            <div>
              <h1 className="text-2xl font-bold" style={{ color: currentColors.text.primary }}>
                Configurações
              </h1>
              <p className="text-sm" style={{ color: currentColors.text.muted }}>
                Personalize sua experiência
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        <div className="flex gap-8">
          {/* Sidebar */}
          <aside className="w-64 flex-shrink-0">
            <nav className="space-y-1">
              {[
                {
                  id: 'appearance' as Tab,
                  name: 'Aparência',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'users' as Tab,
                  name: 'Usuários',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'sso' as Tab,
                  name: 'SSO Providers',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'llm' as Tab,
                  name: 'LLM',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'elasticsearch' as Tab,
                  name: 'Elasticsearch',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'mcp' as Tab,
                  name: 'MCP Servers',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'mcp-config' as Tab,
                  name: 'MCP por Índice',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'knowledge' as Tab,
                  name: 'Knowledge Base',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'rss' as Tab,
                  name: 'RSS Feeds',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'metrics' as Tab,
                  name: 'Métricas do Sistema',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                      />
                    </svg>
                  ),
                },
                {
                  id: 'advanced' as Tab,
                  name: 'Avançado',
                  icon: (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                      />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                  ),
                },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors text-left"
                  style={{
                    backgroundColor: activeTab === tab.id ? currentColors.bg.tertiary : 'transparent',
                    color: activeTab === tab.id ? currentColors.text.primary : currentColors.text.secondary,
                  }}
                  onMouseEnter={(e) => {
                    if (activeTab !== tab.id) {
                      e.currentTarget.style.backgroundColor = currentColors.bg.hover;
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (activeTab !== tab.id) {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  {tab.icon}
                  <span className="font-medium">{tab.name}</span>
                </button>
              ))}
            </nav>
          </aside>

          {/* Content */}
          <main className="flex-1">
            {activeTab === 'appearance' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Aparência
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Escolha o tema que mais combina com você
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {themeOptions.map((themeOption) => {
                    const isActive = theme === themeOption.id;
                    const themeColors = themes[themeOption.id];

                    return (
                      <button
                        key={themeOption.id}
                        onClick={() => setTheme(themeOption.id)}
                        className="relative rounded-lg overflow-hidden border-2 transition-all hover:scale-105"
                        style={{
                          borderColor: isActive ? currentColors.accent.primary : currentColors.border.default,
                        }}
                      >
                        {/* Theme Preview */}
                        <div
                          className="p-4 h-32"
                          style={{
                            backgroundColor: themeColors.bg.primary,
                          }}
                        >
                          <div className="space-y-2">
                            <div
                              className="h-3 w-3/4 rounded"
                              style={{ backgroundColor: themeColors.text.primary }}
                            ></div>
                            <div
                              className="h-2 w-1/2 rounded"
                              style={{ backgroundColor: themeColors.text.secondary }}
                            ></div>
                            <div className="flex gap-2 mt-3">
                              {themeColors.chart.slice(0, 4).map((color, i) => (
                                <div
                                  key={i}
                                  className="h-8 w-8 rounded"
                                  style={{ backgroundColor: color }}
                                ></div>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Theme Info */}
                        <div
                          className="p-4 border-t"
                          style={{
                            backgroundColor: themeColors.bg.secondary,
                            borderColor: themeColors.border.default,
                          }}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <h3 className="font-semibold" style={{ color: themeColors.text.primary }}>
                              {themeOption.name}
                            </h3>
                            {isActive && (
                              <svg
                                className="w-5 h-5"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                                style={{ color: currentColors.accent.primary }}
                              >
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                            )}
                          </div>
                          <p className="text-sm" style={{ color: themeColors.text.muted }}>
                            {themeOption.description}
                          </p>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {activeTab === 'users' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Gerenciamento de Usuários
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Crie, edite e gerencie usuários do sistema
                </p>

                <UserManager />
              </div>
            )}

            {activeTab === 'sso' && (
              <div>
                <SSOProvidersManager />
              </div>
            )}

            {activeTab === 'llm' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Provedores LLM
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Configure os provedores de LLM para análise inteligente de dados
                </p>

                <LLMProvidersManager />
              </div>
            )}

            {activeTab === 'elasticsearch' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Servidores Elasticsearch
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Gerencie suas conexões com servidores Elasticsearch
                </p>

                {/* Embed ES Servers Manager */}
                <div className="rounded-lg border" style={{ borderColor: currentColors.border.default }}>
                  <ESServersManager embedded />
                </div>
              </div>
            )}

            {activeTab === 'mcp' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Servidores MCP
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Configure servidores Model Context Protocol para expandir as capacidades da IA
                </p>

                <MCPManager />
              </div>
            )}

            {activeTab === 'mcp-config' && <IndexMCPConfigManager />}

            {activeTab === 'knowledge' && <KnowledgeBase />}

            {activeTab === 'rss' && <RSSManager />}

            {activeTab === 'metrics' && <MetricsPanel />}

            {activeTab === 'advanced' && (
              <div>
                <h2 className="text-xl font-bold mb-2" style={{ color: currentColors.text.primary }}>
                  Configurações Avançadas
                </h2>
                <p className="mb-6" style={{ color: currentColors.text.muted }}>
                  Opções avançadas e experimentais
                </p>

                <div
                  className="rounded-lg p-6 border"
                  style={{
                    backgroundColor: currentColors.bg.primary,
                    borderColor: currentColors.border.default,
                  }}
                >
                  <p style={{ color: currentColors.text.secondary }}>
                    Mais configurações serão adicionadas em breve...
                  </p>
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};
