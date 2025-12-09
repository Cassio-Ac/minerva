# 🎨 CTI Dashboard - UI/UX Mockup

**Data**: 2025-11-19
**Purpose**: Visual reference for implementation

---

## 📱 Page Layout - Full View

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║  🏠 Home  |  🔍 Search  |  📊 Dashboards  |  ⚙️ Settings     👤 Admin         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  🎯 CYBER THREAT INTELLIGENCE MONITORING                                      ║
║                                                                               ║
║  ┌─────────────────────────┐  ┌─────────────────────────────────────────┐   ║
║  │  THREAT ACTORS          │  │  MITRE ATT&CK MATRIX                    │   ║
║  │  ─────────────────────  │  │  ───────────────────────────────────── │   ║
║  │                         │  │                                         │   ║
║  │  🔍 Search actors...    │  │  [Initial Access] [Execution] [Persist] │   ║
║  │                         │  │  [Priv Esc] [Defense Evasion] [Cred]   │   ║
║  │  📊 Total: 864 actors   │  │  [Discovery] [Lateral] [Collection]    │   ║
║  │  📌 Selected: 1         │  │  [C2] [Exfil] [Impact]                 │   ║
║  │                         │  │                                         │   ║
║  │  ┌──────────────────┐  │  │  ╔════╦════╦════╦════╦════╦════╗       │   ║
║  │  │ □ APT1           │  │  │  ║ T1 ║ T2 ║ T3 ║ T4 ║ T5 ║ T6 ║       │   ║
║  │  │ □ APT28          │  │  │  ╠════╬════╬════╬════╬════╬════╣       │   ║
║  │  │ □ APT29          │  │  │  ║ ■  ║    ║ ■  ║    ║ ■  ║    ║  ←─┐  │   ║
║  │  │ □ Carbanak       │  │  │  ╠════╬════╬════╬════╬════╬════╣    │  │   ║
║  │  │ □ Lazarus        │  │  │  ║    ║ ■  ║    ║ ■  ║    ║    ║    │  │   ║
║  │  │ ☑ Sandworm  ──────────────→║ ■  ║ ■  ║ ■  ║ ■  ║ ■  ║ ■  ║    │  │   ║
║  │  │ □ TA505          │  │  │  ╠════╬════╬════╬════╬════╬════╣    │  │   ║
║  │  │ ...              │  │  │  ║    ║    ║    ║ ■  ║    ║    ║    │  │   ║
║  │  └──────────────────┘  │  │  ╚════╩════╩════╩════╩════╩════╝    │  │   ║
║  │                         │  │                                      │  │   ║
║  │  Filters:               │  │  Legend:                             │  │   ║
║  │  ☑ Active               │  │  ■ = Used by selection               │  │   ║
║  │  □ Historical           │  │  □ = Not used                        │  │   ║
║  │                         │  │                                      │  │   ║
║  │  Sort by:               │  │  Showing: 45/193 techniques          │  │   ║
║  │  ▼ Name (A-Z)          │  │                                      │  │   ║
║  └─────────────────────────┘  └──────────────────────────────────────┘   ║
║                                                      ┌──────────────────┐ ║
║  ┌─────────────────────────┐                        │ TECHNIQUE DETAIL │ ║
║  │  MALWARE FAMILIES       │                        │ ──────────────── │ ║
║  │  ─────────────────────  │                        │                  │ ║
║  │                         │                        │ T1485            │ ║
║  │  🔍 Search families...  │                        │ Data Destruction │ ║
║  │                         │                        │                  │ ║
║  │  📊 Total: 3,578        │                        │ Tactic: Impact   │ ║
║  │  📌 Selected: 2         │                        │                  │ ║
║  │                         │                        │ Description:     │ ║
║  │  Filter by OS:          │                        │ Adversaries may  │ ║
║  │  □ Windows (2,341)      │                        │ destroy data to  │ ║
║  │  □ Linux (487)          │                        │ disrupt systems. │ ║
║  │  □ Android (312)        │                        │                  │ ║
║  │  □ macOS (138)          │                        │ Used by:         │ ║
║  │                         │                        │ • IsaacWiper     │ ║
║  │  ┌──────────────────┐  │                        │ • CaddyWiper     │ ║
║  │  │ ☑ IsaacWiper     │  │                        │ • WhisperGate    │ ║
║  │  │ ☑ CaddyWiper     │  │                        │                  │ ║
║  │  │ □ Emotet         │  │                        │ Mitigations:     │ ║
║  │  │ □ TrickBot       │  │                        │ M1053: Backup    │ ║
║  │  │ □ Ryuk           │  │                        │                  │ ║
║  │  │ ...              │  │                        │ [View in ATT&CK] │ ║
║  │  └──────────────────┘  │                        └──────────────────┘ ║
║  │                         │                                             ║
║  │  Tags:                  │                                             ║
║  │  □ Ransomware           │                                             ║
║  │  □ Wiper                │                                             ║
║  │  □ Backdoor             │                                             ║
║  └─────────────────────────┘                                             ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🎨 Color Scheme

### Theme Support
- **Light Mode**: Clean whites, subtle grays
- **Dark Mode**: Dark backgrounds, neon highlights (current default)

### ATT&CK Matrix Colors

**Light Mode**:
```
Selected Technique:     #3B82F6 (Blue-500)
Hover:                  #60A5FA (Blue-400)
Not Used:               #E5E7EB (Gray-200)
Background:             #FFFFFF (White)
```

**Dark Mode** (Current):
```
Selected Technique:     #10B981 (Green-500)  ← Neon green
Hover:                  #34D399 (Green-400)
Not Used:               #374151 (Gray-700)
Background:             #1F2937 (Gray-800)
```

---

## 🖱️ Interaction Patterns

### Actor/Family Selection

**Single Select** (Click):
```
Before: □ Sandworm
After:  ☑ Sandworm
Result: Matrix highlights Sandworm's techniques
```

**Multi-Select** (Ctrl+Click):
```
Before: ☑ Sandworm
        □ APT28
After:  ☑ Sandworm
        ☑ APT28
Result: Matrix shows UNION of both actors' techniques
```

**Union vs Intersection Toggle**:
```
┌──────────────────────────┐
│ Show techniques:         │
│ ○ Used by ANY selection  │  ← Union (default)
│ ○ Used by ALL selections │  ← Intersection
└──────────────────────────┘
```

---

### Matrix Hover States

**Technique Hover**:
```
╔════════════════════════════════╗
║  T1485: Data Destruction       ║
║  ───────────────────────────── ║
║  Tactic: Impact                ║
║  Used by 3 selected families   ║
║                                ║
║  🖱️ Click for details          ║
╚════════════════════════════════╝
```

**Technique Click**:
- Opens detail panel on right
- Shows full description
- Lists using families/actors
- Links to ATT&CK page

---

### Search & Filter

**Actor Search**:
```
┌──────────────────────────┐
│ 🔍 Search actors...      │
├──────────────────────────┤
│ Results: 3               │
│                          │
│ □ APT28                  │
│ □ Sandworm               │
│ □ APT29                  │
└──────────────────────────┘
```

**Family Search with Filters**:
```
┌──────────────────────────┐
│ 🔍 Search families...    │
│                          │
│ Filter by OS:            │
│ ☑ Windows                │
│ □ Linux                  │
│                          │
│ Filter by Type:          │
│ □ Ransomware             │
│ ☑ Wiper                  │
│ □ Backdoor               │
├──────────────────────────┤
│ Results: 12              │
│                          │
│ □ IsaacWiper (Windows)   │
│ □ CaddyWiper (Windows)   │
│ ...                      │
└──────────────────────────┘
```

---

## 📊 Responsive Layout

### Desktop (> 1280px)

```
┌────────┬─────────────────┬──────────┐
│ Actors │  ATT&CK Matrix  │ Details  │
│  20%   │       50%       │   30%    │
└────────┴─────────────────┴──────────┘
┌────────────────────────────────────┐
│         Families (20%)             │
└────────────────────────────────────┘
```

### Tablet (768px - 1280px)

```
┌─────────────────┬──────────┐
│  ATT&CK Matrix  │ Details  │
│       60%       │   40%    │
└─────────────────┴──────────┘
┌────────┬────────┐
│ Actors │Families│
│  50%   │  50%   │
└────────┴────────┘
```

### Mobile (< 768px)

```
┌──────────────────┐
│  Tabs:           │
│  [Actors] [Fam]  │
└──────────────────┘
┌──────────────────┐
│  Selection List  │
└──────────────────┘
┌──────────────────┐
│  ATT&CK Matrix   │
│  (Scrollable)    │
└──────────────────┘
┌──────────────────┐
│  Details         │
│  (Drawer)        │
└──────────────────┘
```

---

## 🎬 User Flows

### Flow 1: Research Threat Actor

```
1. User opens CTI Dashboard
   ↓
2. Search "Sandworm" in actors
   ↓
3. Click checkbox to select
   ↓
4. Matrix highlights 45 techniques
   ↓
5. User sees tactics distribution:
   - Initial Access: 3 techniques
   - Execution: 8 techniques
   - Persistence: 5 techniques
   - Defense Evasion: 12 techniques
   - Credential Access: 4 techniques
   - Discovery: 6 techniques
   - Lateral Movement: 2 techniques
   - Collection: 3 techniques
   - C2: 1 technique
   - Impact: 1 technique
   ↓
6. User clicks "T1485 - Data Destruction"
   ↓
7. Details panel shows:
   - Full description
   - Families using it: IsaacWiper, CaddyWiper
   - Mitigations: M1053 (Backup)
   - Link to ATT&CK page
```

---

### Flow 2: Compare Multiple Families

```
1. User searches "wiper"
   ↓
2. Filter results:
   - ☑ Windows OS
   - ☑ Wiper tag
   ↓
3. Multi-select families:
   - ☑ IsaacWiper
   - ☑ CaddyWiper
   - ☑ WhisperGate
   ↓
4. Matrix shows UNION of techniques
   ↓
5. User toggles to INTERSECTION
   ↓
6. Matrix shows only common techniques:
   - T1485: Data Destruction
   - T1561: Disk Wipe
   ↓
7. User exports as ATT&CK Navigator layer
   ↓
8. Downloads JSON file for reporting
```

---

### Flow 3: Technique Lookup

```
1. User hovers over technique in matrix
   ↓
2. Tooltip shows:
   "T1485: Data Destruction
    Used by 3 selected families"
   ↓
3. User clicks technique
   ↓
4. Details panel opens on right
   ↓
5. User sees:
   - Full ATT&CK description
   - List of malware using it
   - Mitigations
   - Detection strategies
   ↓
6. User clicks "View in ATT&CK"
   ↓
7. Opens official ATT&CK page in new tab
```

---

## 🎨 Component Specifications

### Actor/Family Selection List

**Component**: `<SelectionList>`

**Props**:
```typescript
{
  items: Array<Actor | Family>,
  selected: Array<string>,
  onSelect: (id: string) => void,
  onSearch: (query: string) => void,
  filters: Array<Filter>
}
```

**Features**:
- ✅ Search input with debounce
- ✅ Checkbox multi-select
- ✅ Filter by attributes
- ✅ Sort options
- ✅ Virtualized scrolling (for performance)

---

### ATT&CK Matrix

**Component**: `<AttackMatrix>`

**Props**:
```typescript
{
  techniques: Array<Technique>,
  highlighted: Array<string>,
  onTechniqueClick: (id: string) => void,
  mode: 'union' | 'intersection'
}
```

**Features**:
- ✅ Grid layout (14 tactics × ~200 techniques)
- ✅ Hover tooltips
- ✅ Color-coded cells
- ✅ Collapse/expand tactics
- ✅ Responsive zoom

**Performance**:
- Use `react-window` for virtualization
- Lazy load technique details
- Debounce hover events

---

### Technique Details Panel

**Component**: `<TechniqueDetails>`

**Props**:
```typescript
{
  technique: Technique,
  relatedFamilies: Array<Family>,
  relatedActors: Array<Actor>
}
```

**Features**:
- ✅ Technique metadata
- ✅ Related families list
- ✅ Related actors list
- ✅ Mitigations
- ✅ External links

---

## 🚀 Export Features

### Export Options Menu

```
┌──────────────────────────┐
│  📥 Export               │
│  ──────────────────────  │
│  • ATT&CK Navigator JSON │
│  • CSV (Families)        │
│  • CSV (Techniques)      │
│  • PDF Report            │
│  • PNG (Matrix)          │
└──────────────────────────┘
```

### ATT&CK Navigator Export

**Output**:
```json
{
  "name": "Sandworm + IsaacWiper Techniques",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Generated from Intelligence Platform CTI Dashboard",
  "techniques": [
    {
      "techniqueID": "T1485",
      "tactic": "impact",
      "color": "#10B981",
      "comment": "Used by IsaacWiper, CaddyWiper",
      "enabled": true
    }
  ]
}
```

**Usage**: Import into official ATT&CK Navigator

---

## 📱 Mobile Considerations

### Touch Interactions

**Tap** = Click (single select)
**Long Press** = Context menu
**Swipe** = Navigate between panels

### Gestures

**Pinch to Zoom** (on matrix):
```
Two-finger pinch → Zoom in/out on ATT&CK matrix
```

**Swipe to Dismiss** (details panel):
```
Swipe right → Close technique details
```

### Mobile Menu

```
┌──────────────────────────┐
│  ☰ Menu                  │
├──────────────────────────┤
│  👥 Actors (2 selected)  │
│  🦠 Families (3 selected)│
│  📊 Matrix View          │
│  📋 Technique List       │
│  📥 Export               │
└──────────────────────────┘
```

---

## 🎨 Animation & Transitions

### Matrix Highlight Transition

```css
.technique-cell {
  transition: background-color 0.3s ease,
              transform 0.2s ease;
}

.technique-cell.highlighted {
  background-color: #10B981;
  transform: scale(1.05);
}
```

### Panel Slide-In

```css
.details-panel {
  animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}
```

### Selection Feedback

```
User clicks actor → Checkbox animates ✓
                 → Matrix cells fade in (stagger 50ms each)
                 → Counter updates with number animation
```

---

## ✨ Polish & UX Details

### Loading States

**Initial Load**:
```
┌──────────────────────────┐
│  🔄 Loading CTI Data...  │
│  ██████████░░░░░░░░ 60%  │
│                          │
│  • Actors loaded         │
│  • Families loaded       │
│  • Loading techniques... │
└──────────────────────────┘
```

**Technique Details Load**:
```
┌──────────────────────────┐
│  T1485                   │
│  Data Destruction        │
│  ──────────────────────  │
│  ⏳ Loading details...   │
└──────────────────────────┘
```

### Empty States

**No Selection**:
```
┌──────────────────────────┐
│  ATT&CK MATRIX           │
│  ──────────────────────  │
│                          │
│  👆 Select an actor or   │
│     family to highlight  │
│     their techniques     │
│                          │
└──────────────────────────┘
```

**No Search Results**:
```
┌──────────────────────────┐
│  🔍 Search: "xyz"        │
│  ──────────────────────  │
│  No results found        │
│                          │
│  Try:                    │
│  • Different spelling    │
│  • Fewer filters         │
│  • Browse all actors     │
└──────────────────────────┘
```

---

## 🎯 Success Criteria

**Dashboard is successful if**:
- Loads in < 2 seconds
- Matrix renders smoothly (60fps)
- Selection updates in < 100ms
- Intuitive for new users (< 30s to first interaction)
- Accessible (keyboard navigation, screen readers)

---

**Mockup ready for implementation! 🚀**

**Documented with ❤️ for ADINT**
