# Sistema de Temas - Dashboard AI v2

## Visão Geral

O Dashboard AI v2 possui um sistema completo de temas que permite aos usuários personalizar a aparência da interface. O sistema suporta 6 temas:

- **Light** - Tema claro padrão
- **Dark** - Tema escuro
- **Monokai** - Inspirado no tema Monokai do editor
- **Dracula** - Inspirado no tema Dracula
- **Nord** - Paleta de cores Nord
- **Solarized** - Tema Solarized Dark

## Arquitetura

### 1. Store de Configurações (`src/stores/settingsStore.ts`)

O sistema de temas é gerenciado através do Zustand com persistência no localStorage:

```typescript
import { useSettingsStore } from '@stores/settingsStore';

// Uso no componente
const { currentColors, theme, setTheme } = useSettingsStore();
```

#### Estrutura de Cores

Cada tema define cores para:

- **Background (`bg`)**: primary, secondary, tertiary, hover
- **Text (`text`)**: primary, secondary, muted, inverse
- **Border (`border`)**: default, focus
- **Accent (`accent`)**: primary, primaryHover, secondary, success, warning, error, info
- **Chart (`chart`)**: Array de cores para visualizações

### 2. Hook Customizado (`src/hooks/useThemeHover.ts`)

Hook para gerenciar estados de hover respeitando o tema atual:

```typescript
import { useThemeHover } from '@hooks/useThemeHover';

const { createHoverHandlers } = useThemeHover();

<button
  {...createHoverHandlers(
    currentColors.bg.hover,      // Cor ao passar o mouse
    'transparent',               // Cor normal
    currentColors.text.primary,  // Cor do texto ao hover (opcional)
    currentColors.text.secondary // Cor do texto normal (opcional)
  )}
>
  Botão
</button>
```

### 3. Utilitários de Estilo (`src/utils/themeStyles.ts`)

Funções auxiliares para estilos comuns:

```typescript
import { getThemeStyles } from '@utils/themeStyles';

const themeStyles = getThemeStyles(currentColors);

// Usar estilos pré-definidos
<div style={themeStyles.card}>Card com borda</div>
<div style={themeStyles.messageBubble(isUser)}>Mensagem</div>
<textarea style={themeStyles.textarea} />
<div style={themeStyles.borderTop}>Divisor superior</div>
```

## Guia de Implementação

### Padrão Básico

```typescript
import { useSettingsStore } from '@stores/settingsStore';
import { useThemeHover } from '@hooks/useThemeHover';
import { getThemeStyles } from '@utils/themeStyles';

export const MyComponent = () => {
  const { currentColors } = useSettingsStore();
  const { createHoverHandlers } = useThemeHover();
  const themeStyles = getThemeStyles(currentColors);

  return (
    <div style={{ backgroundColor: currentColors.bg.primary }}>
      {/* Conteúdo */}
    </div>
  );
};
```

### Botões com Hover

```typescript
// Botão primário
<button
  style={{
    backgroundColor: currentColors.accent.primary,
    color: currentColors.text.inverse
  }}
  {...createHoverHandlers(
    currentColors.accent.primaryHover,
    currentColors.accent.primary
  )}
>
  Ação Principal
</button>

// Botão secundário
<button
  style={{ color: currentColors.text.secondary }}
  {...createHoverHandlers(
    currentColors.bg.hover,
    'transparent',
    currentColors.text.primary,
    currentColors.text.secondary
  )}
>
  Ação Secundária
</button>
```

### Inputs e Textareas

```typescript
<textarea
  style={themeStyles.textarea}
  onFocus={(e) => {
    e.currentTarget.style.borderColor = currentColors.border.focus;
  }}
  onBlur={(e) => {
    e.currentTarget.style.borderColor = currentColors.border.default;
  }}
/>
```

### Cards e Containers

```typescript
// Card com borda
<div style={themeStyles.card}>
  Conteúdo do card
</div>

// Container com divisor superior
<div style={themeStyles.borderTop}>
  Conteúdo com linha superior
</div>
```

## Boas Práticas

### ✅ Fazer

- **Sempre** importar `currentColors` do `useSettingsStore`
- **Usar** os hooks e utilitários fornecidos para consistência
- **Testar** em todos os temas (especialmente Light e Dark)
- **Aplicar** estilos de tema em TODOS os elementos visuais
- **Usar** `createHoverHandlers` para estados de hover

### ❌ Evitar

- **NÃO** usar cores hardcoded do Tailwind (ex: `bg-white`, `text-gray-900`)
- **NÃO** criar handlers de hover inline sem o hook
- **NÃO** deixar elementos sem tematização
- **NÃO** usar cores fixas em novos componentes

## Componentes Tematizados

### Totalmente Implementados

- ✅ App.tsx
- ✅ DashboardEditor.tsx
- ✅ ChatPage.tsx
- ✅ SettingsPage.tsx
- ✅ ESServersManager.tsx
- ✅ Todos os componentes em `/src/components/`

## Estrutura de Arquivos

```
src/
├── stores/
│   └── settingsStore.ts       # Estado global de temas
├── hooks/
│   └── useThemeHover.ts       # Hook para hover states
├── utils/
│   └── themeStyles.ts         # Utilitários de estilo
├── styles/
│   └── index.css              # Estilos globais
└── pages/
    └── SettingsPage.tsx       # Página de configuração de temas
```

## Configuração de Path Aliases

O projeto está configurado para usar path aliases:

```typescript
// tsconfig.json
{
  "compilerOptions": {
    "paths": {
      "@hooks/*": ["src/hooks/*"],
      "@utils/*": ["src/utils/*"],
      "@stores/*": ["src/stores/*"],
      "@components/*": ["src/components/*"],
      // ...
    }
  }
}

// vite.config.ts
{
  resolve: {
    alias: {
      '@hooks': path.resolve(__dirname, './src/hooks'),
      '@utils': path.resolve(__dirname, './src/utils'),
      // ...
    }
  }
}
```

## Changelog

### v2.1.0 - Melhorias no Sistema de Temas

- ✨ Criado hook `useThemeHover` para gerenciar estados de hover
- ✨ Criado utilitário `getThemeStyles` para estilos comuns
- 🎨 Corrigidos problemas de tema na página de Chat
- ♻️ Refatorado código duplicado de hover handlers
- ⚡ Adicionado `useCallback` para otimizar performance
- 📝 Documentação completa do sistema de temas
- 🔧 Configurados path aliases `@hooks` e `@utils`

## Suporte

Para adicionar novos temas, edite `src/stores/settingsStore.ts` e adicione uma nova entrada no objeto `themes` seguindo a estrutura `ThemeColors`.

Para reportar problemas ou sugerir melhorias no sistema de temas, abra uma issue no repositório do projeto.
