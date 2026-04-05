# app.py
import os
import re
import sqlite3
import pathlib
from functools import wraps
from typing import Tuple
import unicodedata
from rapidfuzz import fuzz

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# ── Chargement .env (PythonAnywhere : .env à la racine du projet) ──
from dotenv import load_dotenv
from pathlib import Path
ENV_PATH = (Path(__file__).resolve().parent / ".." / ".env").resolve()
load_dotenv(dotenv_path=ENV_PATH)
from drive_service import create_folder, upload_file, get_folder_link

# ───────────────────────────────────────────────────────────
# App init
# ───────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['PREFERRED_URL_SCHEME'] = 'https'  # à mettre APRÈS la création de app
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # derrière proxy (PA)

# ───────────────────────────────────────────────────────────
# Config (tirée du .env)
# ───────────────────────────────────────────────────────────
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME", ""))

    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    DB_PATH = os.getenv("DB_PATH", os.path.join(INSTANCE_DIR, "portail.db"))

    UPLOAD_ROOT = os.getenv("UPLOAD_ROOT", os.path.join(os.getcwd(), "uploads"))
    ALLOWED_EXTENSIONS = set(
        (os.getenv("ALLOWED_EXTENSIONS", "pdf,png,jpg,jpeg,webp,doc,docx,xls,xlsx,zip"))
        .replace(" ", "").split(",")
    )

app.config.from_object(Config)

# Ensure upload root exists
pathlib.Path(app.config["UPLOAD_ROOT"]).mkdir(parents=True, exist_ok=True)

bcrypt = Bcrypt(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# OAuth
oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# (optionnel) routes de debug
@app.route("/__env")
def __env():
    cid = os.getenv("GOOGLE_CLIENT_ID", "")
    csec = os.getenv("GOOGLE_CLIENT_SECRET", "")
    return jsonify({
        "GOOGLE_CLIENT_ID_loaded": bool(cid),
        "GOOGLE_CLIENT_ID_sample": (cid[:12] + "...") if cid else "",
        "GOOGLE_CLIENT_SECRET_loaded": bool(csec),
    })

@app.route("/__routes")
def __routes():
    return jsonify(sorted([(r.rule, r.endpoint) for r in app.url_map.iter_rules()]))

# ───────────────────────────────────────────────────────────
# Google OAuth Routes
# ───────────────────────────────────────────────────────────

@app.route("/login/google", endpoint="google_login")
def oauth_login_google():
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/google-callback", endpoint="google_callback")
def oauth_google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get("userinfo") or oauth.google.parse_id_token(token)

    email = (user_info.get("email") or "").strip().lower()
    nom   = user_info.get("name") or ""
    if not email:
        flash("Impossible de récupérer l'adresse email Google.", "error")
        return redirect(url_for("accueil"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM clients WHERE email = ?", (email,)).fetchone()
    if not user:
        conn.execute("""
            INSERT INTO clients (nom_complet, email, auth_provider, is_email_confirmed, is_admin)
            VALUES (?, ?, 'google', 1, 0)
        """, (nom or email.split("@")[0], email))
        conn.commit()
        user = conn.execute("SELECT * FROM clients WHERE email = ?", (email,)).fetchone()
    conn.close()

    session['user_id'] = user['id']
    session['user_name'] = user['nom_complet']
    session['is_admin'] = bool(user['is_admin'])

    flash("Connexion Google réussie!", "success")
    return redirect(url_for('admin_dashboard' if session['is_admin'] else 'dashboard'))


# ───────────────────────────────────────────────────────────
# DB helpers
# ───────────────────────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect(app.config["DB_PATH"], timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
    """Crée les tables manquantes et sème les valeurs par défaut essentielles."""
    schema_sql = """
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_complet TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        nom_entreprise TEXT,
        telephone TEXT,
        mot_de_passe_hash TEXT,
        auth_provider TEXT NOT NULL DEFAULT 'password',
        is_email_confirmed INTEGER NOT NULL DEFAULT 0,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS projets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_projet TEXT NOT NULL,
        statut TEXT DEFAULT 'Nouveau',
        lien_gdrive TEXT,
        id_client INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_client) REFERENCES clients(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_service TEXT NOT NULL UNIQUE,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS checklistes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_projet INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_projet) REFERENCES projets(id) ON DELETE CASCADE
    );

    /* Modèle (gabarit) d'items par service */
    CREATE TABLE IF NOT EXISTS checklist_model_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_service INTEGER NOT NULL,
        nom_item TEXT NOT NULL,
        requires_file INTEGER NOT NULL DEFAULT 0,
        is_required INTEGER NOT NULL DEFAULT 1,
        position INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_service) REFERENCES services(id) ON DELETE CASCADE
    );

    /* Items réels d'une checklist de projet */
    CREATE TABLE IF NOT EXISTS checklist_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_checklist INTEGER NOT NULL,
        nom_item TEXT NOT NULL,
        requires_file INTEGER NOT NULL DEFAULT 0,
        is_required INTEGER NOT NULL DEFAULT 1,
        est_coche INTEGER NOT NULL DEFAULT 0,
        file_path TEXT,
        important INTEGER NOT NULL DEFAULT 0,
        position INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_checklist) REFERENCES checklistes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_item INTEGER NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        uploaded_by TEXT NOT NULL CHECK (uploaded_by IN ('client','admin')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_item) REFERENCES checklist_items(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notification_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        admin_emails TEXT DEFAULT '',
        client_updates INTEGER NOT NULL DEFAULT 1,
        admin_updates INTEGER NOT NULL DEFAULT 1
    );

    /* Index utiles */
    CREATE INDEX IF NOT EXISTS idx_projets_client ON projets(id_client);
    CREATE INDEX IF NOT EXISTS idx_checklist_projet ON checklistes(id_projet);
    CREATE INDEX IF NOT EXISTS idx_items_checklist ON checklist_items(id_checklist);
    CREATE INDEX IF NOT EXISTS idx_model_items_service ON checklist_model_items(id_service);
    """
    conn = get_db_connection()
    try:
        conn.executescript(schema_sql)
        # Seed défaut notification_settings (id=1) si absent
        row = conn.execute("SELECT 1 FROM notification_settings WHERE id = 1").fetchone()
        if not row:
            conn.execute("""
                INSERT INTO notification_settings (id, admin_emails, client_updates, admin_updates)
                VALUES (1, '', 1, 1)
            """)
        conn.commit()
    finally:
        conn.close()

# Initialisation DB au démarrage du processus (Flask 3.x n’a plus before_first_request)
init_db()

# ───────────────────────────────────────────────────────────
# Utils / Security
# ───────────────────────────────────────────────────────────
def is_password_strong(password: str) -> bool:
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[!@#$%^&*]", password): return False
    return True
def normalize_company_name(name: str) -> str:
    if not name:
        return ""
    nfkd = unicodedata.normalize("NFKD", name.lower())
    ascii_str = "".join(c for c in nfkd if not unicodedata.combining(c))
    cleaned = re.sub(r"[^\w\s]", "", ascii_str)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = re.sub(r"s$", "", cleaned)
    return cleaned

def find_matching_company(nom_entreprise: str, conn: sqlite3.Connection, seuil: int = 85):
    needle = normalize_company_name(nom_entreprise)
    if not needle:
        return None
    rows = conn.execute(
        "SELECT id, nom_entreprise, drive_folder_id FROM clients WHERE nom_entreprise IS NOT NULL AND nom_entreprise != ''"
    ).fetchall()
    for row in rows:
        score = fuzz.ratio(needle, normalize_company_name(row["nom_entreprise"]))
        if score >= seuil:
            return row
    return None
def send_email(to_list, subject, body):
    if not to_list:
        return
    if isinstance(to_list, str):
        to_list = [to_list]
    try:
        msg = Message(
            subject,
            sender=app.config['MAIL_DEFAULT_SENDER'] or app.config['MAIL_USERNAME'],
            recipients=to_list
        )
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"[MAIL] Erreur d’envoi: {e}")

FILE_CATEGORIES = {
    'photo':     {'label': '📸 Photo',            'extensions': {'jpg','jpeg','png','heic','webp'}},
    'vecteur':   {'label': '🎨 Vecteur/Graphique', 'extensions': {'svg','ai','psd','png','eps'}},
    'video':     {'label': '🎬 Vidéo',             'extensions': {'mp4','mov','avi','mkv'}},
    'document':  {'label': '📄 Document',          'extensions': {'pdf','doc','docx','odt'}},
    'donnees':   {'label': '📊 Données',           'extensions': {'xls','xlsx','csv'}},
    'archive':   {'label': '📦 Archive',           'extensions': {'zip','rar'}},
    'autre':     {'label': '🔗 Autre',             'extensions': set()},
}

def allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".",1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def allowed_for_category(filename: str, category: str) -> bool:
    """Vérifie si l'extension du fichier correspond à la catégorie attendue."""
    if not filename or category not in FILE_CATEGORIES:
        return True  # Pas de restriction si catégorie inconnue
    cat = FILE_CATEGORIES[category]
    if not cat['extensions']:
        return True  # 'autre' = tout accepté
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in cat['extensions']

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('accueil'))
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not bool(session.get('is_admin', False)):
            return redirect(url_for('accueil'))
        return f(*args, **kwargs)
    return wrap

# ───────────────────────────────────────────────────────────
# Notifications settings
# ───────────────────────────────────────────────────────────
def get_notification_settings() -> dict:
    conn = get_db_connection()
    row = conn.execute("""
        SELECT admin_emails, client_updates, admin_updates
        FROM notification_settings WHERE id = 1
    """).fetchone()
    conn.close()
    if not row:
        return {"admin_emails": [], "client_updates": 1, "admin_updates": 1}
    admin_emails = [e.strip() for e in (row['admin_emails'] or '').split(',') if e.strip()]
    return {
        "admin_emails": admin_emails,
        "client_updates": int(row['client_updates'] or 1),
        "admin_updates": int(row['admin_updates'] or 1),
    }

# ───────────────────────────────────────────────────────────
# Readiness / Pastille
# ───────────────────────────────────────────────────────────
def table_has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return False
    return any(
        (row["name"] if hasattr(row, "keys") else row[1]) == column
        for row in info
    )

def compute_checklist_readiness(project_id: int) -> Tuple[bool, int, int]:
    """
    Retourne (is_ready, done_count, total_required)
    - is_ready == True si TOUS les items obligatoires sont cochés
      et, s'ils nécessitent un fichier, qu'un file_path est présent.
    """
    conn = get_db_connection()
    row = conn.execute("""
        SELECT ch.id AS id_checklist
        FROM checklistes ch WHERE ch.id_projet = ?
    """, (project_id,)).fetchone()

    if not row:
        conn.close()
        return (False, 0, 0)

    id_checklist = row['id_checklist'] if 'id_checklist' in row.keys() else row['id']
    has_required_column = table_has_column(conn, "checklist_items", "is_required")

    select_columns = "id, est_coche, requires_file, file_path"
    if has_required_column:
        select_columns += ", is_required"

    items = conn.execute(
        f"""
        SELECT {select_columns}
        FROM checklist_items
        WHERE id_checklist = ?
    """,
        (id_checklist,),
    ).fetchall()
    conn.close()

    total_required = 0
    done_required = 0
    for it in items:
        is_required = 1
        if has_required_column:
            is_required = int(it["is_required"] or 0)
        if is_required != 1:
            continue
        total_required += 1
        ok = int(it['est_coche'] or 0) == 1
        if int(it['requires_file'] or 0) == 1:
            ok = ok and bool(it['file_path'])
        if ok:
            done_required += 1

    return (done_required == total_required and total_required > 0, done_required, total_required)

def pastille_color(is_ready: bool) -> str:
    # Rouge si pas prêt, Orange si prêt
    return "orange" if is_ready else "red"

    # ───────────────────────────────────────────────────────────
# Phases Projet (4 statuts + couleurs) + helpers
# ───────────────────────────────────────────────────────────
PROJECT_PHASES = [
    ("Documents à donner", "red"),
    ("Documents reçus", "blue"),
    ("Travaux en cours", "orange"),
    ("Travaux terminés", "green"),
]

# Variantes acceptées → label normalisé
_PHASE_ALIAS = {
    "documents a donner": "Documents à donner",
    "document a donner": "Documents à donner",
    "doc a donner": "Documents à donner",
    "documents à donner": "Documents à donner",

    "documents reçus": "Documents reçus",
    "documents recus": "Documents reçus",
    "doc recu": "Documents reçus",
    "doc reçu": "Documents reçus",

    "travaux en cours": "Travaux en cours",
    "en cours": "Travaux en cours",

    "travaux terminés": "Travaux terminés",
    "travaux termines": "Travaux terminés",
    "terminé": "Travaux terminés",
    "termine": "Travaux terminés",
    "terminés": "Travaux terminés",
    "fini": "Travaux terminés",
}

def normalize_status(raw: str) -> str:
    if not raw:
        return "Documents à donner"
    key = raw.strip().lower()
    return _PHASE_ALIAS.get(key, raw.strip())

def status_color(status_label: str) -> str:
    """Couleur (red/blue/orange/green) selon la phase."""
    lab = normalize_status(status_label)
    for lbl, color in PROJECT_PHASES:
        if lab == lbl:
            return color
    return "red"

def status_badge_class(status_label: str) -> str:
    """Classe CSS badge en fonction de la couleur de phase."""
    color = status_color(status_label)
    return f"badge badge-{color}"

# Exposer les helpers aux templates
app.jinja_env.globals.update(
    normalize_status=normalize_status,
    status_badge_class=status_badge_class
)


# ───────────────────────────────────────────────────────────
# Routes Auth
# ───────────────────────────────────────────────────────────
@app.route('/')
def accueil():
    return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM clients WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and user['auth_provider'] == 'password' and bcrypt.check_password_hash(user['mot_de_passe_hash'], password):
            if not int(user['is_email_confirmed'] or 0):
                flash("Veuillez confirmer votre adresse email avant de vous connecter.", "error")
                return redirect(url_for('accueil'))
            session['user_id'] = user['id']
            session['user_name'] = user['nom_complet']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('admin_dashboard' if session['is_admin'] else 'dashboard'))

        flash("Email ou mot de passe incorrect.", "error")
        return redirect(url_for('accueil'))
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        nom = request.form.get('nom_complet','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        password2 = request.form.get('password2','')
        nom_entreprise = request.form.get('nom_entreprise','').strip()
        telephone = request.form.get('telephone','').strip()

        if not nom_entreprise:
            flash("Le nom d'entreprise est obligatoire. Pour un travailleur autonome, inscrivez votre nom complet.", "error")
            return redirect(url_for('register'))

        if password != password2:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return redirect(url_for('register'))
        if not is_password_strong(password):
            flash('Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        exists = conn.execute("SELECT 1 FROM clients WHERE email = ?", (email,)).fetchone()
        if exists:
            conn.close()
            flash("Cette adresse email est déjà utilisée.", "error")
            return redirect(url_for('register'))

        match = find_matching_company(nom_entreprise, conn)
        # S'assurer que le match a bien un dossier Drive existant
        drive_folder_id = match["drive_folder_id"] if match and match["drive_folder_id"] else None
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        conn.execute("""
            INSERT INTO clients (nom_complet, email, nom_entreprise, telephone, mot_de_passe_hash, auth_provider, is_email_confirmed, is_admin, drive_folder_id)
            VALUES (?, ?, ?, ?, ?, 'password', 0, 0, ?)
        """, (nom, email, nom_entreprise, telephone, hashed, drive_folder_id))
        conn.commit()

        if not drive_folder_id:
            try:
                new_folder_id = create_folder(
                    nom_entreprise,
                    parent_id=os.getenv('GOOGLE_DRIVE_ROOT_FOLDER_ID')
                )
                conn.execute("UPDATE clients SET drive_folder_id = ? WHERE email = ?", (new_folder_id, email))
                conn.commit()
                # Mettre à jour tous les autres comptes de la même entreprise sans dossier
                conn.execute("""
                    UPDATE clients SET drive_folder_id = ?
                    WHERE drive_folder_id IS NULL AND nom_entreprise = ? AND email != ?
                """, (new_folder_id, nom_entreprise, email))
                conn.commit()
            except Exception as e:
                print(f"[DRIVE] Création dossier client échouée: {e}")
        conn.close()

        try:
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            body = f"Bonjour {nom},\n\nMerci pour votre inscription ! Veuillez cliquer pour activer votre compte :\n{confirm_url}\n\nL'équipe Cocktail Média"
            send_email(email, "Confirmez votre compte - Portail Client", body)
        except Exception as e:
            print(f"[MAIL] Confirmation échouée: {e}")

        return render_template('register.html', show_success_popup=True)

    return render_template('register.html', show_success_popup=False)
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash("Le lien de confirmation est invalide ou a expiré.", "error")
        return redirect(url_for('accueil'))

    conn = get_db_connection()
    conn.execute("UPDATE clients SET is_email_confirmed = 1 WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    flash("Votre compte a été confirmé avec succès !", "success")
    return redirect(url_for('accueil'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('accueil'))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM clients WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user:
            try:
                token = s.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                body = (
                    f"Bonjour {user['nom_complet']},\n\n"
                    f"Pour réinitialiser votre mot de passe, cliquez (valide 1 heure) :\n{reset_url}\n\n"
                    f"Si vous n'avez pas demandé cette réinitialisation, ignorez cet email."
                )
                send_email(email, "Réinitialisation de votre mot de passe - Portail Client", body)
            except Exception as e:
                print(f"[MAIL] Reset échoué: {e}")
        flash("Si votre adresse email est dans notre système, vous recevrez un lien de réinitialisation.", "success")
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash("Le lien de réinitialisation est invalide ou a expiré.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password','')
        confirm_password = request.form.get('confirm_password','')
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return redirect(url_for('reset_password', token=token))
        if not is_password_strong(password):
            flash('Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.', 'error')
            return redirect(url_for('reset_password', token=token))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = get_db_connection()
        conn.execute("UPDATE clients SET mot_de_passe_hash = ? WHERE email = ?", (hashed, email))
        conn.commit()
        conn.close()
        flash('Votre mot de passe a été mis à jour avec succès !', 'success')
        return redirect(url_for('accueil'))
    return render_template('reset_password.html')

# ───────────────────────────────────────────────────────────
# Routes Client
# ───────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    user_id = session['user_id']
    conn = get_db_connection()
    projets_actifs = conn.execute("""
        SELECT p.*, s.icon as service_icon, s.nom_service as service_nom
        FROM projets p
        LEFT JOIN services s ON s.nom_service = SUBSTR(p.nom_projet, INSTR(p.nom_projet, ' — ') + 3)
        WHERE p.id_client = ? AND (p.is_archived = 0 OR p.is_archived IS NULL)
        ORDER BY p.created_at DESC
    """, (user_id,)).fetchall()
    projets_archives = conn.execute("""
        SELECT p.*, s.icon as service_icon, s.nom_service as service_nom
        FROM projets p
        LEFT JOIN services s ON s.nom_service = SUBSTR(p.nom_projet, INSTR(p.nom_projet, ' — ') + 3)
        WHERE p.id_client = ? AND p.is_archived = 1
        ORDER BY p.created_at DESC
    """, (user_id,)).fetchall()

    projets_with_pastille = []
    for p in projets:
        ready, done, total = compute_checklist_readiness(p['id'])
        projets_with_pastille.append(
            {"projet": p, "pastille": pastille_color(ready), "done": done, "total": total}
        )
    conn.close()
    return render_template('dashboard.html', projets=projets_with_pastille)

@app.route('/projet/<int:project_id>')
@login_required
def project_detail(project_id):
    conn = get_db_connection()
    projet = conn.execute("""
        SELECT p.*, s.icon as service_icon, s.nom_service as service_nom
        FROM projets p
        LEFT JOIN services s ON s.nom_service = SUBSTR(p.nom_projet, INSTR(p.nom_projet, ' — ') + 3)
        WHERE p.id = ?
    """, (project_id,)).fetchone()
    if not projet:
        conn.close()
        flash("Projet introuvable.", "error")
        return redirect(url_for('dashboard'))

    is_owner = (projet['id_client'] == session['user_id'])
    is_admin = bool(session.get('is_admin', False))
    if not (is_owner or is_admin):
        conn.close()
        flash("Accès non autorisé à ce projet.", "error")
        return redirect(url_for('dashboard'))

    checklist = conn.execute("SELECT * FROM checklistes WHERE id_projet = ?", (project_id,)).fetchone()
    items = []
    if checklist:
        items = conn.execute("""
            SELECT * FROM checklist_items
            WHERE id_checklist = ?
            ORDER BY id ASC
        """, (checklist['id'],)).fetchall()
    conn.close()

    ready, done, total = compute_checklist_readiness(project_id)
    color = pastille_color(ready)
    return render_template('project_detail.html',
                           projet=projet, checklist=checklist, items=items,
                           readiness={"ready": ready, "done": done, "total": total, "color": color})

@app.route('/item/toggle/<int:item_id>')
@login_required
def toggle_checklist_item(item_id):
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        return redirect(url_for('dashboard'))

    checklist = conn.execute("SELECT id_projet FROM checklistes WHERE id = ?", (item['id_checklist'],)).fetchone()
    projet = conn.execute("SELECT * FROM projets WHERE id = ?", (checklist['id_projet'],)).fetchone()
    client = conn.execute("SELECT * FROM clients WHERE id = ?", (projet['id_client'],)).fetchone()

    is_owner = (projet['id_client'] == session['user_id'])
    is_admin = bool(session.get('is_admin', False))
    if not (is_owner or is_admin):
        conn.close()
        flash("Action non autorisée.", "error")
        return redirect(url_for('dashboard'))

    requires_file = int(item['requires_file'] or 0) == 1
    has_file = bool(item['file_path'])
    current = int(item['est_coche'] or 0)
    new_status = 1 - current

    if requires_file and new_status == 1 and not has_file:
        conn.close()
        flash("Vous devez téléverser le fichier demandé avant de cocher cette tâche.", "error")
        return redirect(url_for('project_detail', project_id=projet['id']))

    conn.execute("UPDATE checklist_items SET est_coche = ? WHERE id = ?", (new_status, item_id))
    conn.commit()
    conn.close()

    if not is_admin and int(item['important'] or 0) == 1:
        settings = get_notification_settings()
        if settings["admin_updates"] == 1 and settings["admin_emails"]:
            status_txt = "complétée" if new_status == 1 else "décochée"
            subject = f"[Portail] {client['nom_complet']} a {status_txt} une tâche importante"
            body = (
                f"Client: {client['nom_complet']} ({client['email']})\n"
                f"Projet: {projet['nom_projet']} (ID {projet['id']})\n"
                f"Tâche: {item['nom_item']}\n"
                f"Statut: {status_txt}\n"
                f"Accéder: {url_for('project_detail', project_id=projet['id'], _external=True)}"
            )
            send_email(settings["admin_emails"], subject, body)

    return redirect(url_for('project_detail', project_id=projet['id']))

# ───────────────────────────────────────────────────────────
# Uploads de fichiers liés aux items
# ───────────────────────────────────────────────────────────
@app.route('/item/upload/<int:item_id>', methods=['POST'])
@login_required
def upload_item_file(item_id):
    file = request.files.get('document')
    if not file or file.filename == "":
        flash("Aucun fichier reçu.", "error")
        return redirect(request.referrer or url_for('dashboard'))
    if not allowed(file.filename):
        flash("Extension de fichier non autorisée.", "error")
        return redirect(request.referrer or url_for('dashboard'))

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        flash("Élément introuvable.", "error")
        return redirect(url_for('dashboard'))

    if item['file_category'] and not allowed_for_category(file.filename, item['file_category']):
        conn.close()
        cat_label = FILE_CATEGORIES.get(item['file_category'], {}).get('label', item['file_category'])
        flash(f"Ce champ attend un fichier de type : {cat_label}", "error")
        return redirect(request.referrer or url_for('dashboard'))

    checklist = conn.execute("SELECT id_projet FROM checklistes WHERE id = ?", (item['id_checklist'],)).fetchone()

    projet   = conn.execute("SELECT * FROM projets WHERE id = ?", (checklist['id_projet'],)).fetchone()

    is_owner = (projet['id_client'] == session['user_id'])
    is_admin = bool(session.get('is_admin', False))
    if not (is_owner or is_admin):
        conn.close()
        flash("Action non autorisée.", "error")
        return redirect(url_for('dashboard'))

    safe_name = secure_filename(file.filename)
    base_dir = os.path.join(app.config["UPLOAD_ROOT"], f"projet_{projet['id']}", f"item_{item_id}")
    pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
    save_path = os.path.join(base_dir, safe_name)

    file.save(save_path)

    # Upload vers Google Drive dans le dossier du projet
    drive_file_id = None
    try:
        # Utiliser le dossier "Dépôt de fichiers" si disponible, sinon le dossier projet
        target_folder_id = projet['depot_folder_id'] if projet['depot_folder_id'] else projet['drive_folder_id'] if projet['drive_folder_id'] else os.getenv('GOOGLE_DRIVE_ROOT_FOLDER_ID')
        drive_file_id, _ = upload_file(save_path, safe_name, target_folder_id)
    except Exception as e:
        print(f"[DRIVE] Upload fichier échoué: {e}")

    conn.execute("""
        INSERT INTO uploads (id_item, filename, filepath, uploaded_by)
        VALUES (?, ?, ?, ?)
    """, (item_id, safe_name, save_path, 'admin' if is_admin else 'client'))

    if int(item['requires_file'] or 0) == 1:
        conn.execute("UPDATE checklist_items SET file_path = ?, est_coche = 1 WHERE id = ?",
                     (save_path, item_id))
    else:
        conn.execute("UPDATE checklist_items SET file_path = ? WHERE id = ?", (save_path, item_id))

    conn.commit()
    conn.close()

    flash("Fichier téléversé.", "success")
    return redirect(url_for('project_detail', project_id=projet['id']))

@app.route('/item/file/<int:upload_id>')
@login_required
def download_uploaded_file(upload_id):
    conn = get_db_connection()
    up = conn.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not up:
        conn.close()
        flash("Fichier introuvable.", "error")
        return redirect(url_for('dashboard'))

    item = conn.execute("SELECT * FROM checklist_items WHERE id = ?", (up['id_item'],)).fetchone()
    checklist = conn.execute("SELECT id_projet FROM checklistes WHERE id = ?", (item['id_checklist'],)).fetchone()
    projet = conn.execute("SELECT * FROM projets WHERE id = ?", (checklist['id_projet'],)).fetchone()
    conn.close()

    is_owner = (projet['id_client'] == session['user_id'])
    is_admin = bool(session.get('is_admin', False))
    if not (is_owner or is_admin):
        flash("Accès non autorisé à ce fichier.", "error")
        return redirect(url_for('dashboard'))

    return send_file(up['filepath'], as_attachment=True, download_name=up['filename'])

# ───────────────────────────────────────────────────────────
# Profil / MDP
# ───────────────────────────────────────────────────────────
@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM clients WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user_id']
    nom = request.form.get('nom_complet','').strip()
    entreprise = request.form.get('nom_entreprise','')
    telephone = request.form.get('telephone','')

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM clients WHERE id = ?", (user_id,)).fetchone()
    if user['auth_provider'] == 'password':
        email = request.form.get('email','').strip().lower()
        conn.execute("""
            UPDATE clients SET nom_complet=?, nom_entreprise=?, telephone=?, email=? WHERE id=?
        """, (nom, entreprise, telephone, email, user_id))
    else:
        conn.execute("""
            UPDATE clients SET nom_complet=?, nom_entreprise=?, telephone=? WHERE id=?
        """, (nom, entreprise, telephone, user_id))
    conn.commit()
    conn.close()

    session['user_name'] = nom
    flash("Vos informations ont été mises à jour avec succès !", "success")
    return redirect(url_for('profile'))

@app.route('/update-password', methods=['POST'])
@login_required
def update_password():
    user_id = session['user_id']
    current = request.form.get('current_password','')
    new = request.form.get('new_password','')
    confirm = request.form.get('confirm_password','')

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM clients WHERE id = ?", (user_id,)).fetchone()

    if not bcrypt.check_password_hash(user['mot_de_passe_hash'], current):
        conn.close()
        flash("Le mot de passe actuel est incorrect.", "error")
        return redirect(url_for('profile'))

    if new != confirm:
        conn.close()
        flash("Les nouveaux mots de passe ne correspondent pas.", "error")
        return redirect(url_for('profile'))

    if not is_password_strong(new):
        conn.close()
        flash("Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.", "error")
        return redirect(url_for('profile'))

    hashed = bcrypt.generate_password_hash(new).decode('utf-8')
    conn.execute("UPDATE clients SET mot_de_passe_hash = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()

    flash("Votre mot de passe a été mis à jour avec succès !", "success")
    return redirect(url_for('profile'))

# ───────────────────────────────────────────────────────────
# Admin
# ───────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_dashboard():
    from datetime import date
    today = str(date.today())
    conn = get_db_connection()
    clients = conn.execute("SELECT id, nom_complet, email, nom_entreprise FROM clients").fetchall()
    projets = conn.execute("""
        SELECT p.id, p.nom_projet, p.statut, c.nom_complet AS nom_client
        FROM projets p JOIN clients c ON p.id_client = c.id
    """).fetchall()
    services = conn.execute("SELECT * FROM services ORDER BY nom_service").fetchall()
    services_localisation = {str(s['id']): bool(s['localisation_requise']) for s in services}
    conn.close()
    actifs_with_pastille = []
    for p in projets_actifs:
        ready, done, total = compute_checklist_readiness(p['id'])
        actifs_with_pastille.append(
            {"projet": p, "pastille": pastille_color(ready), "done": done, "total": total}
        )
    archives_with_pastille = []
    for p in projets_archives:
        ready, done, total = compute_checklist_readiness(p['id'])
        archives_with_pastille.append(
            {"projet": p, "pastille": pastille_color(ready), "done": done, "total": total}
        )
    conn.close()
    return render_template('dashboard.html', projets=actifs_with_pastille, projets_archives=archives_with_pastille)

        today=today,
        services_localisation=services_localisation,
                           clients=clients, projets=projets_with_pastille, services=services)

@app.route('/admin/add_client', methods=['POST'])
@admin_required
def add_client():
    nom = request.form.get('nom_complet','').strip()
    email = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    entreprise = request.form.get('nom_entreprise')

    if not is_password_strong(password):
        flash("Mot de passe trop faible.", "error")
        return redirect(url_for('admin_dashboard'))

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO clients (nom_complet, email, nom_entreprise, mot_de_passe_hash, auth_provider, is_email_confirmed, is_admin)
            VALUES (?, ?, ?, ?, 'password', 1, 0)
        """, (nom, email, entreprise, hashed))
        conn.commit()

        # Créer le dossier Drive du client
        try:
            dossier_nom = entreprise if entreprise else nom
            drive_folder_id = create_folder(
                dossier_nom,
                parent_id=os.getenv('GOOGLE_DRIVE_ROOT_FOLDER_ID')
            )
            conn.execute("UPDATE clients SET drive_folder_id=? WHERE email=?", (drive_folder_id, email))
            conn.commit()
        except Exception as e:
            print(f"[DRIVE] Création dossier client échouée: {e}")
        flash(f"Le client '{nom}' a été ajouté avec succès.", "success")
    except sqlite3.IntegrityError:
        flash(f"Erreur : L'email '{email}' existe déjà.", "error")
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_project', methods=['POST'])
@admin_required
def add_project():
    from datetime import date
    id_client = request.form.get('id_client')
    id_service = request.form.get('id_service')
    date_seance = request.form.get('date_seance') or str(date.today())
    localisation = request.form.get('localisation', '').strip() or None
    lien_gdrive = None
    conn_tmp = get_db_connection()
    service_row = conn_tmp.execute("SELECT nom_service, documents_requis FROM services WHERE id=?", (id_service,)).fetchone()
    conn_tmp.close()
    nom_service = service_row['nom_service'] if service_row else "Projet"
    localisation = request.form.get('localisation', '').strip() or None
    nom_projet = f"{date_seance} — {nom_service} — {localisation}" if localisation else f"{date_seance} — {nom_service}"    
    documents_requis = bool(service_row['documents_requis']) if service_row else True
    statut = "Documents à donner" if documents_requis else "En attente de rendez-vous"
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO projets (nom_projet, statut, lien_gdrive, id_client, localisation)
            VALUES (?, ?, ?, ?, ?)
        """, (nom_projet, statut, lien_gdrive, id_client, localisation))
        id_projet = cur.lastrowid


        if id_service:
            cur.execute("INSERT INTO checklistes (id_projet) VALUES (?)", (id_projet,))
            id_checklist = cur.lastrowid
            items_modele = conn.execute("""
                SELECT nom_item, requires_file, is_required, item_type, video_url, is_revision_item, file_category
                FROM checklist_model_items WHERE id_service = ?
            """, (id_service,)).fetchall()



            for m in items_modele:
                if not int(m['is_revision_item'] or 0):
                    cur.execute("""
                        INSERT INTO checklist_items (id_checklist, nom_item, requires_file, is_required, item_type, video_url, is_revision, file_category)
                        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                    """, (id_checklist, m['nom_item'], int(m['requires_file'] or 0), int(m['is_required'] or 1), m['item_type'] or 'document', m['video_url'], m['file_category'] or 'autre'))

        conn.commit()
        # Créer le dossier Drive du projet
        try:
            client = conn.execute("SELECT * FROM clients WHERE id=?", (id_client,)).fetchone()
            parent = client['drive_folder_id'] if client and client['drive_folder_id'] else os.getenv('GOOGLE_DRIVE_ROOT_FOLDER_ID')
            projet_folder_id = create_folder(nom_projet, parent_id=parent)
            # Créer le sous-dossier "Dépôt de fichiers" dans le dossier projet
            depot_folder_id = create_folder("Dépôt de fichiers", parent_id=projet_folder_id)
            lien_gdrive_new = get_folder_link(projet_folder_id)
            conn.execute("UPDATE projets SET lien_gdrive=?, drive_folder_id=?, depot_folder_id=? WHERE id=?", (lien_gdrive_new, projet_folder_id, depot_folder_id, id_projet))
            conn.commit()

        except Exception as drive_e:
            print(f"[DRIVE] Création dossier projet échouée: {drive_e}")
        flash(f"Le projet '{nom_projet}' a été ajouté avec succès.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Erreur lors de la création du projet : {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_client/<int:client_id>', methods=['GET','POST'])
@admin_required
def edit_client(client_id):
    conn = get_db_connection()
    if request.method == 'POST':
        nom = request.form.get('nom_complet','').strip()
        email = request.form.get('email','').strip().lower()
        entreprise = request.form.get('nom_entreprise','')
        conn.execute("UPDATE clients SET nom_complet=?, email=?, nom_entreprise=? WHERE id=?",
                     (nom, email, entreprise, client_id))
        conn.commit()
        conn.close()
        flash(f"Le client '{nom}' a été mis à jour.", "success")
        return redirect(url_for('admin_dashboard'))

    client = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    conn.close()
    if not client:
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_client.html', client=client)

@app.route('/admin/delete_client/<int:client_id>')
@admin_required
def delete_client(client_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    flash("Client supprimé.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_project/<int:project_id>', methods=['GET','POST'])
@admin_required
def edit_project(project_id):
    conn = get_db_connection()
    if request.method == 'POST':
        nom_projet = request.form.get('nom_projet','').strip()

        # Normaliser le statut (4 phases)
        statut_raw = request.form.get('statut','').strip()
        statut = normalize_status(statut_raw)

        lien_gdrive = request.form.get('lien_gdrive','')
        id_client = request.form.get('id_client')

        old = conn.execute("SELECT statut, id_client FROM projets WHERE id = ?", (project_id,)).fetchone()

        conn.execute("""
            UPDATE projets SET nom_projet=?, statut=?, lien_gdrive=?, id_client=? WHERE id=?
        """, (nom_projet, statut, lien_gdrive, id_client, project_id))
        conn.commit()

        # Notification client si passage à "Travaux terminés"
        try:
            if old and (old['statut'] != statut) and (normalize_status(statut) == "Travaux terminés"):
                settings = get_notification_settings()
                if settings["client_updates"] == 1:
                    client = conn.execute("SELECT nom_complet, email FROM clients WHERE id = ?", (id_client,)).fetchone()
                    subject = f"Votre projet « {nom_projet} » est terminé 🎉"
                    body = (
                        f"Bonjour {client['nom_complet']},\n\n"
                        f"Bonne nouvelle : votre projet « {nom_projet} » est maintenant au statut TERMINÉ.\n"
                        f"Vous pouvez le consulter ici : {url_for('project_detail', project_id=project_id, _external=True)}\n\n"
                        f"— L’équipe Cocktail Média"
                    )
                    send_email(client['email'], subject, body)
        except Exception as e:
            print(f"[MAIL] Notification client échouée: {e}")

        conn.close()
        flash(f"Le projet '{nom_projet}' a été mis à jour.", "success")
        return redirect(url_for('admin_dashboard'))

    projet = conn.execute("SELECT * FROM projets WHERE id = ?", (project_id,)).fetchone()
    clients = conn.execute("SELECT id, nom_complet FROM clients").fetchall()
    conn.close()
    if not projet:
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_project.html', projet=projet, clients=clients)

@app.route('/admin/delete_project/<int:project_id>')
@admin_required
def delete_project(project_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM projets WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    flash("Projet supprimé.", "success")
    return redirect(url_for('admin_dashboard'))

# Services & modèle checklist (admin)
@app.route('/admin/services')
@admin_required
def admin_services():
    conn = get_db_connection()
    les_services = conn.execute("SELECT * FROM services ORDER BY nom_service").fetchall()
    services_avec_items = []
    for service in les_services:
        items = conn.execute("""
            SELECT * FROM checklist_model_items
            WHERE id_service = ?
            ORDER BY is_revision_item ASC, id ASC
        """, (service['id'],)).fetchall()
        services_avec_items.append({'service': service, 'items': items})
    conn.close()
    return render_template('admin_services.html', services=services_avec_items, file_categories=FILE_CATEGORIES)

@app.route('/admin/add_service', methods=['POST'])
@admin_required
def add_service():
    nom_service = request.form.get('nom_service','').strip()
    description = request.form.get('description','')
    localisation_requise = int(request.form.get('localisation_requise', 0))
    documents_requis = int(request.form.get('documents_requis', 0))
    conn = get_db_connection()
    try:
        icon = request.form.get('icon', 'default')
        conn.execute("INSERT INTO services (nom_service, description, localisation_requise, documents_requis, icon) VALUES (?, ?, ?, ?, ?)", (nom_service, description, localisation_requise, documents_requis, icon))
        conn.commit()
        flash(f"Le service '{nom_service}' a été ajouté.", "success")
    except sqlite3.IntegrityError:
        flash(f"Erreur : Le service '{nom_service}' existe déjà.", "error")
    finally:
        conn.close()
    return redirect(url_for('admin_services'))

@app.route('/admin/delete_service/<int:service_id>')
@admin_required
def delete_service(service_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM checklist_model_items WHERE id_service = ?", (service_id,))
    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()
    flash("Service supprimé (et items de modèle associés).", "success")
    return redirect(url_for('admin_services'))

@app.route('/admin/add_checklist_item/<int:service_id>', methods=['POST'])
@admin_required
def add_checklist_item(service_id):
    nom_item = request.form.get('nom_item','').strip()
    is_required = int(request.form.get('is_required', 1))
    is_revision_item = int(request.form.get('is_revision_item', 0))
    video_url = request.form.get('video_url', '').strip() or None
    type_unified = request.form.get('type_unified', 'document')

    # Déduction item_type + file_category + requires_file selon choix unique
    TYPE_MAP = {
        'photo':     ('document', 'photo',    1),
        'vecteur':   ('document', 'vecteur',  1),
        'video_file':('document', 'video',    1),
        'document':  ('document', 'document', 1),
        'donnees':   ('document', 'donnees',  1),
        'archive':   ('document', 'archive',  1),
        'video_url': ('video',    'autre',    0),
        'autre':     ('document', 'autre',    0),
    }
    item_type, file_category, requires_file = TYPE_MAP.get(type_unified, ('document', 'autre', 0))
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO checklist_model_items (id_service, nom_item, requires_file, is_required, item_type, video_url, is_revision_item, file_category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (service_id, nom_item, requires_file, is_required, item_type, video_url, is_revision_item, file_category))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_services'))

@app.route('/admin/delete_checklist_item/<int:item_id>')
@admin_required
def delete_checklist_item(item_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM checklist_model_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_services'))

def update_project_status(project_id):
    """Met à jour le statut du projet selon l'état de la checklist."""
    conn = get_db_connection()
    projet = conn.execute("SELECT * FROM projets WHERE id=?", (project_id,)).fetchone()
    if not projet:
        conn.close()
        return
    checklist = conn.execute("SELECT id FROM checklistes WHERE id_projet=?", (project_id,)).fetchone()
    if not checklist:
        conn.close()
        return
    items = conn.execute("SELECT * FROM checklist_items WHERE id_checklist=?", (checklist['id'],)).fetchall()
    if not items:
        conn.close()
        return
    statut_actuel = projet['statut'].lower() if projet['statut'] else ''
    # Si déjà en révision ou complété, on ne touche pas au statut automatiquement
    if statut_actuel in ['en révision', 'complété', 'complete']:
        conn.close()
        return
    items_requis = [i for i in items if int(i['is_required'] or 0) == 1 and int(i['is_revision'] or 0) == 0]
    tous_coches = all(int(i['est_coche'] or 0) == 1 for i in items_requis)
    if tous_coches and items_requis:
        conn.execute("UPDATE projets SET statut='Travaux en cours' WHERE id=?", (project_id,))
        conn.commit()
    conn.close()

@app.route('/admin/projet/<int:project_id>/revision', methods=['POST'])
@admin_required
def start_revision(project_id):
    """Passe le projet en mode révision et ajoute des items de révision."""
    conn = get_db_connection()
    checklist = conn.execute("SELECT id FROM checklistes WHERE id_projet=?", (project_id,)).fetchone()
    if not checklist:
        conn.execute("INSERT INTO checklistes (id_projet) VALUES (?)", (project_id,))
        conn.commit()
        checklist = conn.execute("SELECT id FROM checklistes WHERE id_projet=?", (project_id,)).fetchone()
    # Ajouter les items modèle de révision du service
    projet_row = conn.execute("SELECT * FROM projets WHERE id=?", (project_id,)).fetchone()
    if projet_row:
        # Trouver le service via le nom du projet
        service_items_rev = []
        # Items manuels du formulaire
        items_revision = request.form.getlist('items_revision[]')
        for nom in items_revision:
            nom = nom.strip()
            if nom:
                conn.execute("""
                    INSERT INTO checklist_items (id_checklist, nom_item, requires_file, is_required, is_revision)
                    VALUES (?, ?, 0, 1, 1)
                """, (checklist['id'], nom))
    conn.execute("UPDATE projets SET statut='En révision' WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Projet passé en révision.", "success")
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/admin/projet/<int:project_id>/force_status', methods=['POST'])
@admin_required
def force_status(project_id):
    statut = request.form.get('statut', '').strip()
    if statut:
        conn = get_db_connection()
        conn.execute("UPDATE projets SET statut=? WHERE id=?", (statut, project_id))
        conn.commit()
        conn.close()
        flash(f"Statut mis à jour : {statut}", "success")
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/admin/projet/<int:project_id>/start', methods=['POST'])
@admin_required
def start_work(project_id):
    """Démarre les travaux manuellement (pour services sans documents requis)."""
    conn = get_db_connection()
    conn.execute("UPDATE projets SET statut='Travaux en cours' WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Travaux démarrés.", "success")
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/admin/projet/<int:project_id>/complete', methods=['POST'])
@admin_required
def complete_project(project_id):
    """Marque le projet comme complété."""
    conn = get_db_connection()
    conn.execute("UPDATE projets SET statut='Complété' WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Projet marqué comme complété.", "success")
    return redirect(url_for('project_detail', project_id=project_id))

# ───────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────

# ───────────────────────────────────────────────────────────
# Création manuelle d'un compte admin (exécuter une seule fois)
# ───────────────────────────────────────────────────────────
def create_admin():
    conn = get_db_connection()
    bcrypt = Bcrypt(app)
    email = "info@cocktailmedia.ca"
    password = "187132zZ!"
    nom = "Admin Cocktail Media"

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    exists = conn.execute("SELECT 1 FROM clients WHERE email = ?", (email,)).fetchone()
    if not exists:
        conn.execute("""
            INSERT INTO clients (nom_complet, email, mot_de_passe_hash, auth_provider, is_email_confirmed, is_admin)
            VALUES (?, ?, ?, 'password', 1, 1)
        """, (nom, email, hashed))
        conn.commit()
        print("✅ Compte admin créé avec succès.")
    else:
        print("⚠️ Ce compte existe déjà.")
    conn.close()

create_admin()

@app.route('/admin/projet/<int:project_id>/edit_items', methods=['POST'])
@admin_required
def edit_checklist_items(project_id):
    conn = get_db_connection()
    checklist = conn.execute("SELECT id FROM checklistes WHERE id_projet = ?", (project_id,)).fetchone()
    if not checklist:
        conn.close()
        flash("Checklist introuvable.", "error")
        return redirect(url_for('project_detail', project_id=project_id))

    item_ids = request.form.getlist('item_id[]')
    for iid in item_ids:
        nom = request.form.get(f'nom_{iid}', '').strip()
        type_unified = request.form.get(f'type_{iid}', 'document')
        is_required = 1 if request.form.get(f'required_{iid}') else 0

        TYPE_MAP = {
            'photo':      ('document', 'photo',    1),
            'vecteur':    ('document', 'vecteur',  1),
            'video_file': ('document', 'video',    1),
            'document':   ('document', 'document', 1),
            'donnees':    ('document', 'donnees',  1),
            'archive':    ('document', 'archive',  1),
            'video_url':  ('video',    'autre',    0),
            'autre':      ('document', 'autre',    0),
        }
        item_type, file_category, requires_file = TYPE_MAP.get(type_unified, ('document', 'autre', 0))

        if nom:
            conn.execute("""
                UPDATE checklist_items
                SET nom_item=?, item_type=?, file_category=?, requires_file=?, is_required=?
                WHERE id=? AND id_checklist=?
            """, (nom, item_type, file_category, requires_file, is_required, iid, checklist['id']))

    conn.commit()
    conn.close()
    flash("Items mis à jour.", "success")
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/admin/projet/<int:project_id>/archive', methods=['POST'])
@admin_required
def archive_project(project_id):
    conn = get_db_connection()
    conn.execute("UPDATE projets SET is_archived = 1 WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    flash("Projet archivé.", "success")
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/admin/projet/<int:project_id>/unarchive', methods=['POST'])
@admin_required
def unarchive_project(project_id):
    conn = get_db_connection()
    conn.execute("UPDATE projets SET is_archived = 0 WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    flash("Projet désarchivé.", "success")
    return redirect(url_for('project_detail', project_id=project_id))


if __name__ == '__main__':
    app.run(debug=True)
