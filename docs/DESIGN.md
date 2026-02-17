# Design System Reference

Semantic design tokens for common.ink. All tokens are defined in the inline Tailwind config in `web/templates/base.html` and `web/templates/base_public.html`. Three themes exist: **default** (blue/sans), **academic** (terracotta/serif/square), **neonfizz** (purple/mono headings/pillowy).

## Theme Personalities

| | Default | Academic | Neonfizz |
|---|---------|----------|----------|
| **Vibe** | Clean, professional | Scholarly, traditional | Techy, playful |
| **Primary** | Blue #2563eb | Terracotta #ae5630 | Purple #7c3aed |
| **Headings** | System sans | Georgia/serif | SF Mono/monospace |
| **Body** | System sans | Georgia/serif | System UI |
| **Corners** | Medium (0.75rem cards) | Square (0.25rem cards, 0 buttons) | Pillowy (1.25rem cards) |
| **Shadows** | Standard elevation | Gentle, minimal | Discord-style flat layers |
| **Gray** | Cool neutral | Warm cream | Discord dark surfaces |

## Tokens

### Border Radius
| Token | Default | Academic | Neonfizz | Use for |
|-------|---------|----------|----------|---------|
| `rounded-card` | 0.75rem | 0.25rem | 1.25rem | Card containers, panels, alerts, dropdowns |
| `rounded-input` | 0.5rem | 0 | 0.75rem | Buttons, inputs, selects, textareas |
| `rounded-badge` | 9999px | 9999px | 9999px | Pills, badges, tags |

### Box Shadow
| Token | Use for |
|-------|---------|
| `shadow-card` | Card/panel surfaces |
| `shadow-card-hover` | Card hover states |
| `shadow-subtle` | Nav bars, light chrome |

### Font Family
| Token | Default | Academic | Neonfizz | Use for |
|-------|---------|----------|----------|---------|
| `font-display` | system sans | Georgia/serif | SF Mono/monospace | Headings (auto-applied via `@layer base`) |
| `font-body` | system sans | Georgia/serif | system-ui | Body text (applied on `<body>`) |

### Colors
| Token | Description |
|-------|-------------|
| `primary-{50-900}` | Brand color (blue/terracotta/purple per theme) |
| `success-{50-900}` | Success states |
| `error-{50-900}` | Error states |
| `warning-{50-900}` | Warning states |
| `gray-{50-900}` | Neutral surfaces (warm in academic, Discord dark in neonfizz) |

## Rules for New Code

1. **Cards/panels**: Use `rounded-card shadow-card`. Hover: `hover:shadow-card-hover`.
2. **Buttons/inputs**: Use `rounded-input`. Never `rounded-lg` or `rounded-md`.
3. **Badges/pills**: Use `rounded-badge`. Never `rounded-full` for non-circular elements.
4. **Alerts/banners**: Use `rounded-card` (they're container elements).
5. **Nav bar shadow**: Use `shadow-subtle`.
6. **Headings**: `font-display` is auto-applied to `h1-h6` via CSS. No class needed.
7. **Body text**: `font-body` is on `<body>`. No class needed.

## Do NOT Use
- `rounded-lg`, `rounded-xl`, `rounded-2xl` — use semantic tokens instead
- `rounded-md` — use `rounded-input`
- `shadow-sm`, `shadow-lg` — use `shadow-subtle` or `shadow-card`
- Stock Tailwind border-radius/shadow utilities on new elements

## Exceptions (keep stock utilities)
- `rounded-full` on truly circular elements (avatars, theme swatch dots)
- `rounded-lg` on nav link hover states (interactive, not containers)
- `rounded` (bare) on tiny inline controls (kbd hints, small icon buttons)

## Theme Switching
- Pure client-side via `localStorage`. Keys: `ci_theme` (default/academic/neonfizz), `ci_darkmode` (system/light/dark).
- Theme switch: sets `localStorage.ci_theme`, reloads page. Tailwind CDN re-processes with new config.
- Dark mode toggle: cycles system→light→dark, toggles `dark` class on `<html>`, no reload.
- Controls live in the top nav bar (base.html) or header (base_public.html).
- On mobile, the same controls DOM node is moved into the mobile menu via JS (no duplication).

## Theme Configs
Full theme objects are in `web/themes/theme-academic.js` and `web/themes/theme-neonfizz.js` (reference only — the live configs are inlined in the base templates).

Academic and neonfizz themes also override stock Tailwind values (`lg`, `xl`, `2xl` for borderRadius; `sm`, `lg` for boxShadow) so any remaining stock utility usage still gets themed.

---

## Per-Theme Visual Behaviors

### Architecture: `data-theme` + CSS Custom Properties + `@layer`

- `data-theme` attribute is set on `<html>` by the same IIFE that configures Tailwind.
- Theme-specific CSS lives in `@layer base` (heading treatments, body typography, custom properties) and `@layer components` (themed component classes).
- Templates use generic classes (`themed-card`, `themed-btn-primary`, etc.) -- no if/then branching in templates.

### CSS Custom Properties

| Property | Purpose | Default | Academic | Neonfizz |
|----------|---------|---------|----------|----------|
| `--ci-texture` | Page background pattern | dot grid | paper fiber hairlines | CRT scanlines |
| `--ci-texture-size` | Background-size | 20px 20px | 100% 100% | 100% 4px |
| `--ci-glow` | Card/button glow | none | none | purple glow |
| `--ci-glow-hover` | Intensified glow | none | none | stronger purple glow |
| `--ci-glow-focus` | Focus ring replacement | none | none | purple focus glow |

### Themed Component Classes

| Class | Purpose | Default | Academic | Neonfizz |
|-------|---------|---------|----------|----------|
| `themed-page` | On body; texture overlay via `::before` | dot grid bg | paper fiber bg | CRT scanline bg |
| `themed-card` | Card container | top-2 primary border, lift on hover | left-4 primary border, no shadow | glow on hover |
| `themed-btn-primary` | Primary CTA button | scale(1.02) on hover | standard | resting + hover glow |
| `themed-prose` | Prose content container | no change | max-w-3xl centered, first-paragraph indent | no change |
| `themed-hero-heading` | Landing hero h1 | no change | no change | gradient text fill |
| `themed-focus` | Interactive elements | no change | no change | glow focus ring |

### Per-Theme Base Styles

| Aspect | Default | Academic | Neonfizz |
|--------|---------|----------|----------|
| h1-h3 | tracking-tight | h2-h3: small-caps + tracking-widest; h1: tracking-wide | uppercase + tracking-tighter |
| Body | standard | line-height: 1.8 | standard |
| Dark mode | system/manual | system/manual | auto-dark (forced dark unless explicit override) |

### Empty States

Theme-specific text in notes list empty state, shown/hidden by JS checking `data-theme`.

### Theme Swatches

`w-5 h-5` with `title` tooltip.

### Footer

common.ink wordmark in display font, slightly different bg from page (`bg-gray-100`).

### Fade-in

Body starts `opacity: 0`, set to `1` on `DOMContentLoaded` to mask Tailwind CDN processing flash.
