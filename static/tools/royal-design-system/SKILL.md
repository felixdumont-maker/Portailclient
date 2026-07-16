---
name: royal-shawinigan-design
description: Use this skill to generate well-branded interfaces and assets for Le Royal de Shawinigan (women's ball-hockey team, LNHBF league), either for production or throwaway prototypes/mocks/social graphics. Contains essential design guidelines, colors, type, fonts, assets, and UI kit components for prototyping the team's social-media templates and any related collateral.
user-invocable: true
---

Read the README.md file within this skill, and explore the other available files.

Key files:
- `README.md` — full brand context, content fundamentals, visual foundations, iconography
- `colors_and_type.css` — single source of truth for color + type tokens (import this; don't reinvent)
- `fonts/` — Bebas Neue (display) + Plus Jakarta Sans (body), self-hosted
- `preview/` — small HTML cards demonstrating every token, component and pattern
- `ui_kits/social/` — five JSX templates that mirror the production templates in `template/`
- `assets/` — logos and brand marks (see `assets/README.md` for placeholder status)

If creating visual artifacts (slides, social posts, throwaway prototypes, etc.):
- Always start at 1080×1080 for social, with `background: var(--royal-red)` and the diagonal hatch overlay.
- Bebas Neue for ANY display copy (headlines, scores, dates, team names). All caps. Hard 2px black drop-shadow on red.
- Plus Jakarta Sans for everything else. Eyebrows are 12-13px, 700 weight, 0.22em letter-spacing, all caps.
- Copy is French, formal-sportif. Date format: `SAMEDI 18 AVRIL`. Time: `19 H 30`. Never use emoji.
- Always credit Cocktail Média in the footer-right at 11px, low-opacity white.
- If unsure, copy out the closest-matching JSX in `ui_kits/social/` and adapt it.

If working on production code, copy assets out and read the rules in README.md to become an expert in designing with this brand.

If the user invokes this skill without any other guidance, ask them what they want to build (gameday post? player card? recap? schedule? something new?), gather the data (teams, scores, dates, names), and output an HTML artifact OR production code, depending on the need.
