import os
import sqlite3
import time

DB_PATH = os.getenv("DB_PATH", "portail.db")
FORCE_RECREATE = True  # True = supprime l'ancien fichier

# Optionnel: auto-créer un admin si tu exportes ces variables avant d'exécuter:
# export ADMIN_EMAIL="admin@cocktailmedia.ca"
# export ADMIN_PASSWORD="MotDePasseSolide!2025"
# export ADMIN_NAME="Administrateur"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_NAME = os.getenv("ADMIN_NAME", "Administrateur")

def drop_db_file():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def run_schema(conn):
    cur = conn.cursor()

    # --- Clients ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_complet         TEXT NOT NULL,
        email               TEXT NOT NULL UNIQUE,
        nom_entreprise      TEXT,
        telephone           TEXT,
        mot_de_passe_hash   TEXT,
        auth_provider       TEXT NOT NULL DEFAULT 'password' CHECK (auth_provider IN ('password','google')),
        is_email_confirmed  INTEGER NOT NULL DEFAULT 0,
        is_admin            INTEGER NOT NULL DEFAULT 0,
        created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);")
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_clients_updated
    AFTER UPDATE ON clients
    FOR EACH ROW BEGIN
        UPDATE clients SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
    """)

    # --- Projets ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS projets (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_projet   TEXT NOT NULL,
        statut       TEXT NOT NULL DEFAULT 'Nouveau',
        lien_gdrive  TEXT,
        id_client    INTEGER NOT NULL,
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_client) REFERENCES clients(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_projets_client ON projets(id_client);")
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_projets_updated
    AFTER UPDATE ON projets
    FOR EACH ROW BEGIN
        UPDATE projets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
    """)

    # --- Services (modèles) ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_service  TEXT NOT NULL UNIQUE,
        description  TEXT
    );
    """)

    # --- Modèle d'items par service ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS checklist_model_items (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        id_service    INTEGER NOT NULL,
        nom_item      TEXT NOT NULL,
        requires_file INTEGER NOT NULL DEFAULT 0,   -- 1 = un fichier obligatoire
        is_required   INTEGER NOT NULL DEFAULT 1,   -- 1 = item obligatoire
        FOREIGN KEY (id_service) REFERENCES services(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_model_items_service ON checklist_model_items(id_service);")

    # --- Checklist par projet (1:1) ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS checklistes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        id_projet  INTEGER NOT NULL UNIQUE,  -- 1 checklist par projet
        FOREIGN KEY (id_projet) REFERENCES projets(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checklistes_projet ON checklistes(id_projet);")

    # --- Items réels de checklist ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS checklist_items (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        id_checklist  INTEGER NOT NULL,
        nom_item      TEXT NOT NULL,
        est_coche     INTEGER NOT NULL DEFAULT 0,
        requires_file INTEGER NOT NULL DEFAULT 0,
        file_path     TEXT,
        important     INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (id_checklist) REFERENCES checklistes(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_items_checklist ON checklist_items(id_checklist);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_items_checked   ON checklist_items(est_coche);")

    # --- Uploads (historique des fichiers) ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        id_item     INTEGER NOT NULL,
        filename    TEXT NOT NULL,
        filepath    TEXT NOT NULL,
        uploaded_by TEXT NOT NULL CHECK (uploaded_by IN ('client','admin')),
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_item) REFERENCES checklist_items(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_uploads_item ON uploads(id_item);")

    # --- Paramètres notifications (singleton id=1) ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_settings (
        id              INTEGER PRIMARY KEY CHECK (id = 1),
        admin_emails    TEXT NOT NULL DEFAULT '',
        client_updates  INTEGER NOT NULL DEFAULT 1,
        admin_updates   INTEGER NOT NULL DEFAULT 1
    );
    """)
    cur.execute("INSERT OR IGNORE INTO notification_settings (id) VALUES (1);")

    conn.commit()

def insert_admin_if_needed(conn):
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("• Aucun admin ajouté (définis ADMIN_EMAIL et ADMIN_PASSWORD pour en créer un).")
        return
    import bcrypt
    cur = conn.cursor()
    email = ADMIN_EMAIL.strip().lower()
    name = ADMIN_NAME.strip() or "Administrateur"
    hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        cur.execute("""
            INSERT INTO clients (nom_complet, email, mot_de_passe_hash, auth_provider, is_email_confirmed, is_admin)
            VALUES (?, ?, ?, 'password', 1, 1)
        """, (name, email, hashed))
        conn.commit()
        print(f"• Admin créé : {email}")
    except sqlite3.IntegrityError:
        print(f"• Admin déjà présent : {email}")

def main():
    if FORCE_RECREATE:
        print(f"⚠️  Suppression de {DB_PATH} si existant…")
        drop_db_file()
        time.sleep(0.2)

    conn = connect()
    try:
        print("→ Création du schéma…")
        run_schema(conn)
        insert_admin_if_needed(conn)
        print(f"✅ Base initialisée : {DB_PATH}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()




