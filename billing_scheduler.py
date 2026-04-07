# billing_scheduler.py
"""
Scheduler facturation mensuelle — Cocktail Média
- Dernier jour du mois à 17h : ferme factures ouvertes + envoie + crée nouvelles
"""

import os
import sqlite3
import pathlib
from datetime import date, datetime
import calendar

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger


def get_db():
    db_path = os.getenv("DB_PATH", "/data/instance/portail.db")
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def est_dernier_jour_du_mois() -> bool:
    today = date.today()
    dernier = calendar.monthrange(today.year, today.month)[1]
    return today.day == dernier


def fermer_factures_ouvertes(app, mail):
    """Ferme toutes les factures ouvertes et les envoie aux clients."""
    from invoice_service import generer_pdf_facture
    from email_templates import email_nouvelle_facture
    from drive_service import upload_file
    from flask_mail import Message as MailMessage

    with app.app_context():
        conn = get_db()
        factures = conn.execute("""
            SELECT f.*, c.nom_complet, c.email, c.factures_folder_id,
                   c.adresse_facturation, c.ville_facturation, c.province_facturation,
                   c.code_postal_facturation, c.pays_facturation, c.telephone,
                   c.numero_tps, c.numero_tvq, c.nom_entreprise
            FROM factures f
            JOIN clients c ON c.id = f.id_client
            WHERE f.statut = 'ouverte'
        """).fetchall()

        today    = date.today()
        date_str = today.strftime("%Y-%m-%d")

        for facture in factures:
            try:
                lignes = conn.execute("""
                    SELECT * FROM facture_lignes
                    WHERE id_facture = ?
                    ORDER BY date_service
                """, (facture['id'],)).fetchall()

                if not lignes:
                    print(f"[SCHEDULER] Facture {facture['numero']} ignorée — aucune ligne")
                    continue

                # Calculer totaux
                sous_total = sum(float(l['total_ligne']) for l in lignes)
                tps  = round(sous_total * 0.05, 2)
                tvq  = round(sous_total * 0.09975, 2)
                total = round(sous_total + tps + tvq, 2)

                conn.execute("""
                    UPDATE factures SET sous_total=?, tps=?, tvq=?, total=? WHERE id=?
                """, (sous_total, tps, tvq, total, facture['id']))

                # Générer PDF
                upload_root  = os.getenv("UPLOAD_ROOT", "/data/uploads")
                factures_dir = os.path.join(upload_root, "factures", f"client_{facture['id_client']}")
                pathlib.Path(factures_dir).mkdir(parents=True, exist_ok=True)
                pdf_path = os.path.join(factures_dir, f"{facture['numero']}.pdf")

                client_dict = {
                    "nom_complet":          facture['nom_complet'],
                    "nom_entreprise":       facture['nom_entreprise'],
                    "email":                facture['email'],
                    "telephone":            facture['telephone'],
                    "adresse_facturation":  facture['adresse_facturation'],
                    "ville_facturation":    facture['ville_facturation'],
                    "province_facturation": facture['province_facturation'],
                    "code_postal_facturation": facture['code_postal_facturation'],
                    "pays_facturation":     facture['pays_facturation'] or 'Canada',
                    "numero_tps":           facture['numero_tps'],
                    "numero_tvq":           facture['numero_tvq'],
                }

                lignes_dict = [{
                    "description":   l['description'],
                    "date_service":  l['date_service'] or '',
                    "localisation":  l['localisation'] or '',
                    "quantite":      l['quantite'],
                    "prix_unitaire": l['prix_unitaire'],
                } for l in lignes]

                facture_dict = {
                    "numero":             facture['numero'],
                    "date_emission":      date_str,
                    "date_echeance":      "À la réception",
                    "exonere_taxes":      False,
                    "stripe_payment_url": facture['stripe_payment_url'],
                }

                generer_pdf_facture(facture_dict, lignes_dict, client_dict, pdf_path)

                # Upload Drive
                drive_file_id = None
                try:
                    if facture['factures_folder_id']:
                        drive_file_id, _ = upload_file(
                            pdf_path,
                            f"{facture['numero']}.pdf",
                            facture['factures_folder_id']
                        )
                except Exception as e:
                    print(f"[SCHEDULER] Drive upload échoué: {e}")

                # Mettre à jour DB
                conn.execute("""
                    UPDATE factures
                    SET statut='envoyee', date_emission=?, date_echeance='À la réception',
                        pdf_path=?, drive_file_id=?
                    WHERE id=?
                """, (date_str, pdf_path, drive_file_id, facture['id']))
                conn.commit()

                # Envoyer email
                try:
                    msg = MailMessage(
                        f"Votre facture {facture['numero']} — Cocktail Média",
                        sender=os.getenv("MAIL_DEFAULT_SENDER"),
                        recipients=[facture['email']]
                    )
                    msg.body = f"Bonjour {facture['nom_complet']}, veuillez trouver ci-joint votre facture {facture['numero']}."
                    msg.html = email_nouvelle_facture(facture['nom_complet'])
                    if os.path.exists(pdf_path):
                        with open(pdf_path, 'rb') as f:
                            msg.attach(f"{facture['numero']}.pdf", 'application/pdf', f.read())
                    mail.send(msg)
                    print(f"[SCHEDULER] Facture {facture['numero']} envoyée à {facture['email']}")
                except Exception as e:
                    print(f"[SCHEDULER] Email échoué: {e}")

            except Exception as e:
                print(f"[SCHEDULER] Erreur facture {facture['numero']}: {e}")

        conn.close()


def creer_factures_mensuelles(app):
    """Crée les factures ouvertes du mois suivant pour les clients mensuels."""
    from invoice_service import generer_numero_facture

    with app.app_context():
        conn = get_db()
        today      = date.today()
        # Mois suivant
        if today.month == 12:
            mois_suivant = date(today.year + 1, 1, 1)
        else:
            mois_suivant = date(today.year, today.month + 1, 1)
        periode = mois_suivant.strftime("%Y-%m")

        clients_mensuels = conn.execute("""
            SELECT * FROM clients
            WHERE mode_facturation = 'mensuel'
        """).fetchall()

        for client in clients_mensuels:
            # Vérifier si facture du mois suivant existe déjà
            existe = conn.execute("""
                SELECT 1 FROM factures
                WHERE id_client = ? AND periode_mois = ? AND statut = 'ouverte'
            """, (client['id'], periode)).fetchone()

            if existe:
                continue

            numero = generer_numero_facture(client['id'], conn)
            conn.execute("""
                INSERT INTO factures
                (numero, id_client, statut, type_facturation, periode_mois)
                VALUES (?, ?, 'ouverte', 'mensuel', ?)
            """, (numero, client['id'], periode))
            conn.commit()
            print(f"[SCHEDULER] Facture ouverte créée: {numero} pour {client['nom_complet']} — {periode}")

        conn.close()


def ajouter_ligne_facture_mensuelle(id_client: int, id_projet: int,
                                     description: str, date_service: str,
                                     localisation: str, prix: float, conn):
    """
    Appelée depuis start_work pour les clients mensuels.
    Ajoute une ligne à la facture ouverte du mois en cours.
    Crée la facture si elle n'existe pas encore.
    """
    from invoice_service import generer_numero_facture

    today   = date.today()
    periode = today.strftime("%Y-%m")

    facture = conn.execute("""
        SELECT id FROM factures
        WHERE id_client = ? AND periode_mois = ? AND statut = 'ouverte'
    """, (id_client, periode)).fetchone()

    if not facture:
        numero = generer_numero_facture(id_client, conn)
        conn.execute("""
            INSERT INTO factures
            (numero, id_client, statut, type_facturation, periode_mois, sous_total, tps, tvq, total)
            VALUES (?, ?, 'ouverte', 'mensuel', ?, 0, 0, 0, 0)
        """, (numero, id_client, periode))
        conn.commit()
        facture = conn.execute("""
            SELECT id FROM factures
            WHERE id_client = ? AND periode_mois = ? AND statut = 'ouverte'
        """, (id_client, periode)).fetchone()

    conn.execute("""
        INSERT INTO facture_lignes
        (id_facture, id_projet, description, date_service, localisation, quantite, prix_unitaire, total_ligne)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (facture['id'], id_projet, description, date_service, localisation, prix, prix))
    conn.commit()
    print(f"[SCHEDULER] Ligne ajoutée à facture mensuelle: {description} — {prix}$")


def init_scheduler(app, mail):
    """Initialise et démarre le scheduler APScheduler."""
    scheduler = BackgroundScheduler(timezone="America/Toronto")

    # Dernier jour du mois à 17h00
    scheduler.add_job(
        func=lambda: fermer_factures_ouvertes(app, mail),
        trigger=CronTrigger(hour=17, minute=0),
        id="fermer_factures",
        name="Fermer factures ouvertes fin de mois",
        replace_existing=True,
    )

    scheduler.add_job(
        func=lambda: creer_factures_mensuelles(app),
        trigger=CronTrigger(hour=17, minute=1),
        id="creer_factures_mensuelles",
        name="Créer factures mensuelles mois suivant",
        replace_existing=True,
    )

    scheduler.start()
    print("[SCHEDULER] Démarré — jobs: fermer_factures + creer_factures_mensuelles")
    return scheduler
