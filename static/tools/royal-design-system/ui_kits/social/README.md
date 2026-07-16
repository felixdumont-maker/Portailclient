# Social Graphics UI Kit — Royal de Shawinigan

Pixel-faithful recreations of the **5 production social-graphic templates** from `template/`. Each template renders at 1080×1080 (Instagram square).

| File | Source | Purpose |
| --- | --- | --- |
| `R01Gameday.jsx` | `R01-gameday.html` | Next-game announcement (SOIR DE MATCH) |
| `R02Joueuse.jsx` | `R02-joueuse.html` | Player spotlight (Layout A · Classic) |
| `R03Resultat.jsx` | `R03-resultat.html` | Single match result (win/loss) |
| `R04Horaire.jsx` | `R04-horaire.html` | Weekly schedule (HORAIRE DE LA SEMAINE) |
| `R05MultiResultats.jsx` | `R05-multi-resultats.html` | Two-match recap night |
| `index.html` | All five | Interactive switcher demo |

The components share a common pattern: all dimensions are absolute pixels against the 1080×1080 stage; layouts are flex/grid; type & color come from `../../colors_and_type.css`.

**Open `index.html`** to flip through the five templates.
