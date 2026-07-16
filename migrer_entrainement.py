#!/usr/bin/env python3
"""Migration — module Entraînement.

Ajoute (idempotent) :
  - clients.has_entrainement INTEGER DEFAULT 0   (jumelle de has_outils)
  - table entrainement_plans      (un plan = un cycle appartenant à un client, historisé)
  - table entrainement_progress   (suivi des cases coché par date réelle)

Usage:
    DB_PATH=/data/instance/portail.db python3 migrer_entrainement.py
Sur l'hôte:
    DB_PATH=/mnt/raid1/www/em/prod/data/instance/portail.db python3 migrer_entrainement.py
"""
import os
import sqlite3

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "instance", "portail.db"))


def column_exists(conn, table, column):
    return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})"))


def main():
    print(f"[migrate] DB = {DB_PATH}")
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    try:
        # 1) Colonne has_entrainement sur clients (SQLite n'a pas de ADD COLUMN IF NOT EXISTS)
        if not column_exists(conn, "clients", "has_entrainement"):
            conn.execute("ALTER TABLE clients ADD COLUMN has_entrainement INTEGER NOT NULL DEFAULT 0")
            print("[migrate] + clients.has_entrainement")
        else:
            print("[migrate] = clients.has_entrainement (déjà présent)")

        # 1b) Mode "entraînement seulement" : masque le portail entreprise (Accueil/Soumissions),
        #     atterrit directement sur la séance du jour.
        if not column_exists(conn, "clients", "entrainement_only"):
            conn.execute("ALTER TABLE clients ADD COLUMN entrainement_only INTEGER NOT NULL DEFAULT 0")
            print("[migrate] + clients.entrainement_only")
        else:
            print("[migrate] = clients.entrainement_only (déjà présent)")

        # 2) Table des plans (historisée, un seul actif à la fois par client)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entrainement_plans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id    INTEGER NOT NULL,
                titre        TEXT,
                note         TEXT,
                contenu_json TEXT NOT NULL DEFAULT '{}',
                actif        INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entr_plans_client ON entrainement_plans(client_id, actif)")
        print("[migrate] = entrainement_plans")

        # 3) Table du suivi (case cochée datée)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entrainement_progress (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id    INTEGER NOT NULL,
                plan_id      INTEGER NOT NULL,
                exercice_key TEXT NOT NULL,
                date         TEXT NOT NULL,
                done         INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (plan_id)   REFERENCES entrainement_plans(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
                UNIQUE (client_id, plan_id, exercice_key, date)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entr_prog_lookup ON entrainement_progress(client_id, plan_id, date)")
        print("[migrate] = entrainement_progress")

        print("[migrate] OK")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
