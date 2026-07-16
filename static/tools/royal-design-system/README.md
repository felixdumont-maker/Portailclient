# Royal de Shawinigan — Design System

## Index of this folder

| Path | What's there |
| --- | --- |
| `README.md` | This file — context, content & visual foundations, iconography |
| `SKILL.md` | Agent-Skills front-matter so this folder works as a portable skill |
| `colors_and_type.css` | Single source of truth for color + type tokens — import this everywhere |
| `fonts/` | Bebas Neue + Plus Jakarta Sans (400/500/700), self-hosted woff2 |
| `assets/` | Logos & brand marks (see `assets/README.md` — placeholders flagged) |
| `preview/` | ~25 small HTML cards rendered in the Design System tab — one per token cluster |
| `ui_kits/social/` | 5 JSX recreations of the production templates + interactive `index.html` |

## Quick-start for agents

1. Read `SKILL.md` and the rest of this README.
2. Link `colors_and_type.css` into any HTML you produce — never hand-roll the palette.
3. For social graphics, copy the closest matching `ui_kits/social/R0X*.jsx` and edit the `defaults` data.
4. Always render at **1080×1080**, on `var(--royal-red)`, with the diagonal hatch overlay.
5. French copy, formal-sportif tone, no emoji, Cocktail Média credit in footer-right.

---



A design system for **Le Royal de Shawinigan**, a women's ball-hockey team competing in the **LNHBF** (Ligue Nationale Hockey Balle Féminin · Saison 2025–2026). The team plays out of **Centre Bionest** in Shawinigan, Québec. All marketing/social assets are produced by **Cocktail Média** (cocktailmedia.ca).

The system in this folder is built specifically for the team's **social-media graphics surface** — square, photo-driven, sports-poster aesthetics meant to be exported as static PNGs for Instagram, Facebook, etc.

---

## Sources

- **`template/`** — Local mounted folder (read-only). 7 reference HTML templates at 1080×1080:
  - `R01-gameday.html` — "SOIR DE MATCH" (next-game announcement)
  - `R02-joueuse.html` — Player spotlight card (with two layouts A/B + Tweaks panel)
  - `R03-resultat.html` — Single match result (win/loss)
  - `R04-horaire.html` — Weekly schedule (HORAIRE DE LA SEMAINE)
  - `R05-18avril-v3.html` — Concrete dated multi-result example
  - `R05-multi-resultats.html` — Generic multi-result template
  - `joueuse-sample.json` — Example data payload for R02
- **`felixdumont-maker/Claudedesign`** (GitHub) — currently empty / inaccessible (returns 409 from the GitHub API). Nothing to import.

The templates are data-driven: each accepts a base64-encoded JSON payload via `?data=` and renders against placeholders. Logos and photos are referenced from an external `Asset/` folder that is **not** present in `template/` itself — see *Caveats*.

---

## Index — what's in this folder

| Path | What it is |
| --- | --- |
| `README.md` | This file |
| `SKILL.md` | Agent-skill manifest (drop-in for Claude Code) |
| `colors_and_type.css` | All design tokens — colors, type scale, semantic classes |
| `assets/` | Brand visual assets (logos placeholder, sample partner marks) |
| `fonts/` | Webfonts → using Google Fonts CDN (no local TTFs needed) |
| `preview/` | Design system swatch / specimen cards for the review tab |
| `ui_kits/social/` | UI kit — the 5 social-graphic templates as JSX components |
| `ui_kits/social/index.html` | Interactive demo of all 5 templates |

---

## Brand at a glance

- **Voice:** French (Québécois). Confident, sporty, civic. Uppercase Bebas Neue does most of the emotional work.
- **Color:** A single saturated **crimson red `#d62127`** runs as full-bleed background on every artifact; everything else is white, transparent-white or transparent-black.
- **Type:** **Bebas Neue** (display, condensed, all-caps) + **Plus Jakarta Sans** (UI / labels / body).
- **Texture:** A subtle `-55°` diagonal hatch is laid over every red surface — this is the brand's silent signature.
- **Surface:** Always a 1080×1080 square. Photographic action-shot of a player typically sits center-bottom or full-bleed, faded into the red.

---

## Content fundamentals

**Language.** All copy is in **French (Québec)**. Numbers use comma decimals where applicable (`19h30` for time, `21–27 avr.` for date ranges with an en-dash).

**Tone.** Civic / community-team voice. **Not corporate, not slangy.** Fact-forward: matchup, date, location, score. No taglines, no hype copy, no exclamation marks. The team logo and the league label do the boasting.

**Person/POV.** Third-person and brand-voice — never "I" or "you". The team refers to itself as **"Le Royal"** or **"Le Royal de Shawinigan"** (full form in footers, short form in body). Players are referred to by `Prénom Nom` with the position (e.g. "Stéphanie Marchand · Défenseure · #23").

**Casing.**
- **ALL-CAPS BEBAS NEUE** for: hero titles, dates, times, team sigles (`RYL`, `MTL`), city names, day-of-week pills, status badges (`SOIR DE MATCH`, `VICTOIRE`, `DÉFAITE`).
- **Uppercase Plus Jakarta Sans (eyebrow)** for: league labels (`LNHBF · SAISON 2025–2026`), section labels (`DATE`, `HEURE`, `ARÉNA`), tags (`HOME`, `AWAY`).
- **Sentence case (body)** is rare — used only for the partner row label ("Nos partenaires") and the photo credit ("Photo : cocktailmedia.ca").

**Punctuation conventions.**
- Section labels separated by middle-dot: `LNHBF · Saison 2025–2026`
- Date ranges with en-dash: `21–27 AVR.`
- Times always two digits + lowercase `h`: `19h30`, `19h00`
- Date abbreviations all-caps with period: `SAM 26 AVR.`, `MAR 22 AVR.`
- Player stat lines: `2B 1A` (2 buts, 1 assist), `MJ · B · A · P` (matches/buts/assists/points)

**Vocabulary lexicon.**
| FR brand term | EN equivalent (do not use) | Notes |
| --- | --- | --- |
| **Joueuse** | player (f.) | Players are women — always feminine forms |
| **Défenseure** | defender (f.) | |
| **Gardienne** | goalie (f.) | |
| **Buteuse** | scorer (f.) | |
| **Soir de match** | game day | Always ALL-CAPS in pills |
| **Horaire de la semaine** | week schedule | Title block on R04 |
| **Résultats de la soirée** | tonight's results | Eyebrow on R05 |
| **Aréna** | venue / arena | |
| **Saison** | season | |
| **Nos partenaires** | our partners | Eyebrow above sponsor row |
| **Match régulier / Élim.** | regular / playoff | Match-context micro-copy |
| **Tirs au but** | shots on goal | |
| **Fusillade (FUS)** | shootout | Compact badge |

**Emoji & extras.** No emoji. No emoji-as-icon. No unicode dingbats — *except* the middle dot `·` (U+00B7) which is the brand's dedicated separator and shows up in nearly every label. Em-dashes (`—`) appear in long titles ("Ligue Nationale Hockey Balle Féminin —"). En-dashes (`–`) appear in numeric ranges only.

**Examples in the wild.**
- `LNHBF — Ligue Nationale Hockey Balle Féminin`
- `SAM 26 AVR. · 19H30 · CENTRE BIONEST`
- `Stéphanie Marchand · Défenseure · #23 — Dek Hockey Shawinigan`
- `Photo : cocktailmedia.ca`
- `Le Royal de Shawinigan · royalshawinigan.ca`

---

## Visual foundations

### Color
- **One** brand color: crimson red `#d62127` covers ~90% of every artifact as full-bleed background. The rest of the system is built on **transparent white** at five opacity steps (`0.55 / 0.45 / 0.30 / 0.20 / 0.10`) and **transparent black** (`0.22 / 0.30 / 0.45`) — see `colors_and_type.css`.
- **No gradients except photo-fades.** A photo is masked into the red via `linear-gradient(to top, #d62127 → transparent)`. There are zero brand-purple gradients, zero blue accents, zero "purple sunset" looks.
- **Win vs loss:** pure white score = win, `rgba(255,255,255,.20)` score = loss. No green/red status colors — saturation hierarchy alone signals outcome.

### Type
- **Display:** Bebas Neue. Always uppercase. Used at 22 / 26 / 28 / 30 / 38 / 50 / 52 / **100px** (giant scores).
- **Body / labels:** Plus Jakarta Sans, weights 500–800. Uppercase + extreme letterspacing (`0.18em`–`0.42em`) for eyebrows and labels. Lowercase only for actual prose (rare).
- **Hero text gets a hard 2px black shadow** — not blurred, just offset (`2px 2px 0 rgba(0,0,0,0.2)`). Gives a subtle "screenprint" / sports-poster feel.

### Backgrounds & textures
- Every red surface gets the **−55° diagonal hatch** (60px transparent + 60px `rgba(0,0,0,0.04)`). This single texture is the brand's silent signature — never skip it on a red surface.
- A **dark vignette corner** (`radial-gradient` at `bottom right`) anchors the gameday card.
- **Photos sit full-bleed or as banner crops**, then fade into the red. Action shots, color-graded warm. No B&W. The photo on R01 is a trapezoidal `clip-path: polygon(12% 0%, 88% 0%, 100% 100%, 0% 100%)` — that subtle taper is recurring.

### Cards & containers
- **Radii:** `20px` for primary match-result cards, `16px` for game cards in the schedule, `14px` for team logo boxes, `100px` for pills/badges.
- **Card surfaces** are translucent on red: `rgba(255,255,255,0.10)` neutral, `rgba(0,0,0,0.22)` "home" alt, `rgba(255,255,255,0.18)` featured.
- **Borders** are always white-translucent (`rgba(255,255,255,0.15)` typical). Logo placeholder boxes use **dashed 1.5px borders** at `0.30` opacity — kept in production as a deliberate "unsettled" aesthetic.
- **Glass strip:** R01's bottom info uses `rgba(0,0,0,0.30)` + `backdrop-filter: blur(12px)` + `1px rgba(255,255,255,0.15)` border. This is the only place blur appears.
- **No outer drop shadows.** Lift is achieved via the win-score `0 4px 16px rgba(0,0,0,0.30)` text-shadow only.

### Borders & dividers
- Hairline white separators at `rgba(255,255,255,0.20)` — always 1px or 2px, never thicker.
- Vertical 1px×32px dividers between info items in the gameday strip (`info-sep`).
- Horizontal 2px full-width dividers for major section breaks on R05.
- Left **6px accent bar** (`::before`) on result cards: white for win, `rgba(255,255,255,0.25)` for loss.

### Animation, hover, press
- The system is **export-only static rasters** — no motion in production. The only interactive surface is R02's Tweaks panel (color + layout + density), kept off-canvas during export (`body[data-playwright]` hides it).
- Hover/press patterns aren't part of the brand surface. For UI kit demos we use a soft `opacity: 0.85` on hover; no scale shrink, no color shifts.

### Layout
- **Canvas:** always 1080×1080. Templates auto-fit via JS `transform: scale()` against viewport.
- **Outer padding:** `44–56px` (mostly `56px` left/right).
- **Z-stacking:** background texture (`z-0`) → vignettes/photos (`z-2`) → photo-fade overlay (`z-3`) → all content (`z-5` to `z-10`).
- **Grid is implicit** — there's no formal column grid; layouts are flex compositions anchored to corners (`top-bar`, `bottom-info`).
- **Density** is tweakable on R02 only (`0.9 / 1.0 / 1.1` scale multiplier).

### Imagery
- Color: **warm**, slightly saturated, real action photos. No B&W, no grain filter, no duotone. When over the red, photos are darkened ~20% via overlay.
- Object-position: usually `center top` or `center 30%` so faces stay visible after fade-into-red.
- Logos render with `object-fit: contain` inside translucent boxes; partner logos may opt-out of white-filtering via `noFilter: true` in the data payload.

### Iconography
See **ICONOGRAPHY** below.

---

## Iconography

**The Royal de Shawinigan brand has no formal icon system.** This is intentional — the templates do their work via *typography, photography, color and the dot separator*. There are no inline UI icons (no chevrons, no info-circles, no calendar/clock glyphs); information that would normally be iconified is typeset instead (`DATE` / `HEURE` / `ARÉNA` as eyebrow labels above values).

**What does appear in the file system:**
- **Team logo** — referenced as `Asset/Logos/LogoLNHBF_Shawinigan.svg` and `assets/logo-royal.png` in different templates (the path varies — see *Caveats*). Placeholder boxes show a dashed white rectangle with the word "Logo Royal" while assets are missing.
- **Cocktail Média credit logo** — `Asset/Logos/icone blanc.png`. Small white mark, bottom-corner placement on R02.
- **Partner / sponsor logos** — `Asset/Logos/logo-white-lnhb_feminin_Prospect-White.png`, `LPS-BLANC.png`, `LOGO Royal Lepage MD Centre Cs.png`. Rendered in a horizontal row labeled "Nos partenaires"; some use `noFilter: true` to keep their original colors instead of being knocked out white.
- **Player photos** — e.g. `Asset/Photos/Stephanie Marchand.jpg`. Action shots, full-bleed.

**No icon font, no SVG sprite, no Lucide / Heroicons usage anywhere.** If a future surface (e.g. the team's website) needs UI icons, the closest match in stroke-weight / personality would be **Lucide** (1.5px stroke, geometric) — that would be a *substitution flag* and the team should approve before shipping.

**Emoji:** never used.

**Unicode glyphs in active use:**
- `·` (U+00B7, middle dot) — the brand's separator, used everywhere
- `—` (em-dash) — long titles
- `–` (en-dash) — numeric ranges only

In this design system folder, `assets/` contains generated **placeholder marks** for the team logo, partner logos and Cocktail Média mark — these are clearly labeled "PLACEHOLDER" so they can't be confused with real production assets. The user should drop in the real `Asset/` folder when handing this kit to a designer/developer.

---

## Caveats / open questions

- **Real logo + photo files are missing from `template/`.** The templates reference `Asset/Logos/...` and `assets/logo-royal.png` but neither folder is part of the mount. We've created clearly-labeled placeholders in `assets/` so layouts don't break visually. **Please attach the team's actual `Asset/` folder so we can swap them in.**
- **Path inconsistency.** R03 uses `assets/logo-royal.png` (lowercase, png), R02 uses `Asset/Logos/LogoLNHBF_Shawinigan.svg` (capitalized, svg). The production system will need one canonical path — flagging for resolution.
- **`Claudedesign` GitHub repo is currently empty / unreachable** (409 on the tree endpoint). Nothing imported from it.
- **Fonts:** the templates use **Bebas Neue** + **Plus Jakarta Sans** loaded from Google Fonts. No local TTF files were attached and Google Fonts is the canonical source for both — no substitution flag is needed, but if the brand later wants self-hosted webfonts, the existing references will need to be rewritten.
- **No website / app surface yet** — only the social-graphics surface is documented here. If a marketing site or fan-app is in scope, that's a separate UI kit to add later.
