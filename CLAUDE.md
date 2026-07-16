# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Patching rules

- **Never rewrite `app.py` in full** unless explicitly asked — patch with targeted read/replace/write or the Edit tool.
- **Always verify syntax before rebuilding:** `python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"`
- **CSS changes** (`static/style.css`) require no Docker rebuild.
- **New Python modules:** add to `requirements.txt` and confirm the Dockerfile copies them.
- **Schema changes on existing tables:** never modify `init_db()` for existing tables — `CREATE TABLE IF NOT EXISTS` is a no-op on live DBs. Use `ALTER TABLE` directly via sqlite3.
- **Rebuilding the container:** always use `docker compose build portail && docker compose up -d portail` from `/opt/cocktailmedia/`. Never use `docker build -t portail` — it creates a separate image (`portail`) that is not used by the running container (`cocktailmedia-portail`). `docker compose up` without `--build` does not rebuild either.

## Running the app

```bash
# Development
python app.py

# Production (Docker)
docker build -t portail .
docker run -p 8000:8000 --env-file ../.env portail

# Production command (Gunicorn, 3 workers, gthread, 8 threads)
gunicorn -w 3 -k gthread --threads 8 -b 0.0.0.0:8000 app:app
```

The `.env` file lives **one directory above** the project root (`../env` relative to `app.py`). This is a PythonAnywhere deployment convention.

## Key environment variables

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing |
| `DB_PATH` | SQLite path (default: `instance/portail.db`) |
| `UPLOAD_ROOT` | File upload root (default: `./uploads`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth login |
| `GOOGLE_DRIVE_ROOT_FOLDER_ID` | Root Drive folder for client files |
| `MAIL_SERVER` / `MAIL_USERNAME` / `MAIL_PASSWORD` | Flask-Mail (Gmail SMTP) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Used only by `creation_base_de_donnees.py` to seed an admin |

## Architecture

`app.py` (~4500 lines) is the single-file Flask application. It owns all routes, the schema, the DB helpers, and all business logic. There is no blueprint splitting.

### Module breakdown

| File | Role |
|---|---|
| `app.py` | Flask app: routes, schema, business logic |
| `drive_service.py` | Google Drive API via Service Account (`service_account.json`) |
| `calendar_service.py` | Google Calendar API — production scheduling + séances/Meet events. Impersonates `felix.dumont@cocktailmedia.ca`. |
| `invoice_service.py` | PDF invoice generation (ReportLab) + invoice numbering |
| `billing_scheduler.py` | APScheduler jobs: closes open invoices and creates next-month invoices on the last day of the month at 17h00 Toronto time |
| `email_templates.py` | HTML email templates (all transactional emails) |
| `creation_base_de_donnees.py` | One-time DB initializer (standalone, `FORCE_RECREATE=True` by default — **do not run on production**) |

### Database

SQLite with WAL journal mode. Schema is auto-applied at startup via `init_db()` (called at module load, line 329). There is no migration framework — new columns must be added with `CREATE TABLE IF NOT EXISTS` or manual `ALTER TABLE` statements in `init_db()`.

**Core tables:** `clients`, `projets`, `services`, `checklistes`, `checklist_items`, `checklist_model_items`, `uploads`

**Feature tables:** `factures`, `facture_lignes`, `identite_visuelle`, `iv_logos`, `iv_fonts`, `iv_mockups`, `iv_declinaisons`, `iv_palettes`, `iv_svgs`, `decision_boards`, `decision_board_choices`, `roadmaps`, `roadmap_phases`, `roadmap_todos`, `roadmap_phase_notes`, `marketing_posts`, `notification_settings`

Many columns referenced in routes (e.g. `drive_folder_id`, `factures_folder_id`, `mode_facturation`, `id_service`, `item_type`, `file_category`, `drive_subfolders`) were added after the initial schema — `init_db()` uses `CREATE TABLE IF NOT EXISTS` idempotently but does **not** add missing columns to existing tables. Use `table_has_column()` (line 461) to guard against missing columns at runtime.

### Authentication & authorization

- `session['user_id']`, `session['is_admin']` drive access control
- Two decorators: `@login_required`, `@admin_required` (lines 423–437)
- Two auth methods: email/password + Google OAuth (Authlib)
- Email confirmation required before login (except Google OAuth users, who are auto-confirmed)
- `send_email_client()` silently drops emails for unconfirmed accounts

### Project lifecycle (statuts)

Projects move through these phases, with automated side-effects at each transition:

1. **Documents à donner** → initial state when service requires documents
2. **En attente de rendez-vous** → initial state when no documents required
3. **Documents reçus** → admin marks docs received
4. **Travaux en cours** → `start_work()` route: books a Calendar production block, generates invoice (per-project or adds line to monthly invoice), sends email with PDF attachment
5. **En révision** → admin marks for revision
6. **Travaux terminés** → `complete_project()` route

### Billing modes

Clients have `mode_facturation = 'projet' | 'mensuel'`:
- **projet**: invoice generated immediately when work starts (`creer_facture_projet`)
- **mensuel**: a line is added to the open monthly invoice (`ajouter_ligne_facture_mensuelle`); the scheduler closes and sends the invoice on the last day of the month

### Services configuration

`services` table controls project behaviour via columns:
- `documents_requis` — whether the project starts in "Documents à donner" or "En attente de rendez-vous"
- `duree_production_minutes` — duration booked in Calendar
- `delai_fixe_heures` — fixed delivery delay (used for immobilier: 48h, skips Calendar booking)
- `icon` — maps to `JOURS_PRODUCTION` dict in `calendar_service.py` for day-of-week scheduling
- `drive_subfolders` — pipe-separated `|` list of sub-folders auto-created in Drive on project creation
- `appel_exploratoire_requis`, `heure_seance_defaut`, `duree_seance_minutes`, `prix`, `localisation_requise`
- `checklist_model_items` — template items copied to `checklist_items` on project creation

### Google Drive integration

- Each client gets a Drive folder (`drive_folder_id`) and a `Factures` sub-folder (`factures_folder_id`) at registration
- Each project gets a Drive folder under the client folder; a `Dépôt de fichiers` sub-folder is created only if `documents_requis` is true
- All folders are made public (anyone with link can read)
- `drive_service.py` uses a Service Account (`service_account.json`) with full Drive scope

### API v1 (JSON)

Routes under `/api/v1/` serve a separate Next.js frontend (CORS configured for `192.168.10.10:3001` and `localhost:3001`). They share the same session cookie. The HTML routes and API routes coexist in the same Flask app.

### Jinja2 extras

Custom filters registered: `fromjson` / `from_json`, `mois_precedent`, `mois_suivant`, `jours_du_mois`. Globals injected: `normalize_status`, `status_badge_class`.

### Project status colors

`status_color()` (line 564) maps statut labels to CSS color names (`red`, `blue`, `orange`, `purple`, `green`, `grey`). `_PHASE_ALIAS` (line 536) normalizes variant spellings of phase names — always use `normalize_status()` before comparing statut strings.
