# Grid Layout Responsiveness - Análise Técnica

## Problema Identificado

Quando o usuário redimensiona a janela do navegador (ex: abrindo o DevTools com F12), as posições dos widgets no dashboard são reconfiguradas, perdendo o layout que foi salvo.

## Causa Raiz

O sistema atual usa `react-grid-layout` com breakpoints responsivos que utilizam **diferentes números de colunas**:

```typescript
// DashboardGrid.tsx
breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480 }}
cols={{ lg: 12, md: 10, sm: 6, xs: 4 }}
```

### Como o Problema Ocorre

1. **Posicionamento Absoluto por Coluna**: As posições dos widgets são salvas como coordenadas absolutas (`x`, `y`, `w`, `h`) baseadas no número de colunas do grid
2. **Breakpoints Diferentes**: Cada tamanho de tela tem um número diferente de colunas
3. **Conversão Incorreta**: Quando a janela redimensiona:
   - O widget em `x: 8, w: 4` no breakpoint `lg` (12 colunas) está na posição relativa 66% da largura
   - Ao mudar para `md` (10 colunas), o mesmo `x: 8` representa 80% da largura
   - O layout fica completamente desconfigurando

### Exemplo Prático

```
Breakpoint LG (12 colunas):
┌─────────────────────────────────────┐
│         Widget A (x:8, w:4)         │  ← Ocupa colunas 8-12 (33% direita)
└─────────────────────────────────────┘

Breakpoint MD (10 colunas):
┌─────────────────────────────────────┐
│              Widget A (x:8, w:4)    │  ← Ocupa colunas 8-12 (mas só existem 10!)
└─────────────────────────────────────┘
                                          Widget sai da tela ou é reposicionado
```

## Código Atual

```typescript
// frontend/src/components/DashboardGrid.tsx - linhas 31-48
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
    lg: baseLayout,  // 12 colunas (1200px+)
    md: baseLayout,  // 10 colunas (996px+) ← PROBLEMA: usa mesmas posições
    sm: baseLayout.map(item => ({ ...item, w: Math.min(item.w, 6) })),  // 6 colunas
    xs: baseLayout.map(item => ({ ...item, w: 4, x: 0 })),  // 4 colunas
  };
}, [widgets]);
```

## Soluções Possíveis

### Opção 1: Grid Fixo (Recomendada) ⭐

**Usar o mesmo número de colunas para todos os breakpoints**

```typescript
breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480 }}
cols={{ lg: 12, md: 12, sm: 12, xs: 12 }}  // Todos usam 12 colunas

return {
  lg: baseLayout,
  md: baseLayout,  // Mesmo layout, sem transformações
  sm: baseLayout,  // Mesmo layout
  xs: baseLayout,  // Mesmo layout
};
```

**Vantagens:**
- ✅ Posições sempre consistentes
- ✅ Simples de implementar e manter
- ✅ Comportamento previsível
- ✅ Padrão usado por Grafana, Kibana, Tableau

**Desvantagens:**
- ❌ Em telas muito pequenas (mobile), pode requerer scroll horizontal
- ❌ Não otimizado para cada tamanho de tela

---

### Opção 2: Layouts Separados por Breakpoint

**Salvar um layout completo para cada breakpoint**

```typescript
// Estrutura no banco de dados
widget.position = {
  lg: { x: 0, y: 0, w: 4, h: 3 },
  md: { x: 0, y: 0, w: 5, h: 3 },
  sm: { x: 0, y: 0, w: 6, h: 3 },
  xs: { x: 0, y: 0, w: 4, h: 3 }
}
```

**Vantagens:**
- ✅ Totalmente responsivo
- ✅ Layout otimizado para cada tamanho

**Desvantagens:**
- ❌ Muito mais complexo de implementar
- ❌ Usuário precisa ajustar layout em cada breakpoint
- ❌ 4x mais dados para salvar e sincronizar
- ❌ Difícil manter consistência

---

### Opção 3: Grid Não-Responsivo com Scroll

**Usar `GridLayout` ao invés de `Responsive`**

```typescript
import { GridLayout } from 'react-grid-layout';

// Sempre 12 colunas, ajusta largura do container
<GridLayout
  cols={12}
  width={1200}  // Largura fixa
  // ... resto das props
/>
```

**Vantagens:**
- ✅ Posições totalmente consistentes
- ✅ Simples de implementar

**Desvantagens:**
- ❌ Requer scroll horizontal em telas pequenas
- ❌ Menos flexível

---

### Opção 4: Conversão Proporcional Dinâmica

**Salvar sempre em lg (12 colunas) e converter dinamicamente**

```typescript
const convertLayout = (baseLayout: Layout[], fromCols: number, toCols: number) => {
  return baseLayout.map(item => ({
    ...item,
    x: Math.round((item.x / fromCols) * toCols),
    w: Math.round((item.w / fromCols) * toCols)
  }));
};

return {
  lg: baseLayout,
  md: convertLayout(baseLayout, 12, 10),
  sm: convertLayout(baseLayout, 12, 6),
  xs: convertLayout(baseLayout, 12, 4)
};
```

**Vantagens:**
- ✅ Responsivo
- ✅ Uma única fonte de verdade (layout lg)

**Desvantagens:**
- ❌ Arredondamentos podem causar comportamentos estranhos
- ❌ Difícil debugar
- ❌ Pode ter colisões inesperadas

---

## Benchmarking - Como Outras Ferramentas Resolvem

### Grafana
- **Solução**: Grid fixo de 24 colunas
- Em mobile: scroll horizontal + zoom
- Prioriza consistência sobre responsividade

### Kibana
- **Solução**: Grid fixo de 12 colunas
- Em mobile: widgets empilham verticalmente (força `x: 0`)
- Salva apenas uma versão do layout

### Tableau
- **Solução**: Canvas fixo com zoom
- Dashboards são projetados para uma resolução específica
- Mobile: visualização somente leitura com scroll/zoom

### Google Data Studio
- **Solução**: Layouts separados para Desktop e Mobile
- Usuário precisa configurar dois layouts manualmente

---

## Decisão Atual

**Status**: Documentado para implementação futura

**Motivo**: Funcionalidade funciona adequadamente para uso em desktop. Se houver demanda dos usuários para melhor suporte mobile ou comportamento em múltiplos tamanhos de tela, implementaremos a **Opção 1 (Grid Fixo)** por ser a mais simples e seguir o padrão da indústria.

---

## Implementação Futura (Se Necessário)

### Passos para Implementar Opção 1

1. **Atualizar DashboardGrid.tsx**:
```typescript
// Linha 108 - Mudar de colunas variáveis para fixas
cols={{ lg: 12, md: 12, sm: 12, xs: 12 }}

// Linhas 42-47 - Usar mesmo layout para todos
return {
  lg: baseLayout,
  md: baseLayout,
  sm: baseLayout,
  xs: baseLayout
};
```

2. **Ajustar CSS para scroll horizontal em telas pequenas**:
```css
.dashboard-grid-container {
  overflow-x: auto;
  min-width: 768px; /* Largura mínima para manter usabilidade */
}
```

3. **Testar em diferentes resoluções**:
   - Desktop: 1920x1080
   - Laptop: 1366x768
   - Tablet: 768x1024
   - Mobile: 375x667

### Alternativa: Se Opção 2 For Necessária

Requer mudanças significativas:
- Migração do banco de dados (widget.position → widget.layouts)
- Atualizar tipos TypeScript
- Atualizar toda lógica de save/load
- Implementar UI para editar cada breakpoint
- Estimar: 2-3 dias de desenvolvimento

---

## Referências

- [react-grid-layout Documentation](https://github.com/react-grid-layout/react-grid-layout)
- [Responsive Breakpoints Best Practices](https://www.freecodecamp.org/news/the-100-correct-way-to-do-css-breakpoints-88d6a5ba1862/)
- Issue relacionada: [Posições desconfiguram ao redimensionar janela](https://github.com/react-grid-layout/react-grid-layout/issues/382)

---

**Última Atualização**: 2025-11-10
**Documentado por**: Claude Code
