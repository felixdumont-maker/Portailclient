# billing_scheduler.py
"""
Scheduler facturation mensuelle — Cocktail Média
- Dernier jour ouvrable du mois à 17h : ferme les factures ouvertes ayant au moins
  une ligne et les envoie. La facture ouverte d'un client mensuel n'est créée qu'à
  la volée, à l'assignation de son premier projet du mois (voir ajouter_ligne_facture_mensuelle).
"""

import os
import fcntl
import sqlite3
import pathlib
import calendar
from datetime import date, datetime, timedelta

_scheduler_lock_fd = None  # garde le verrou ouvert pour la vie du process

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger


def get_db():
    db_path = os.getenv("DB_PATH", "/data/instance/portail.db")
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def dernier_jour_ouvrable_du_mois(reference: date | None = None) -> date:
    """Dernier jour ouvrable (lun-ven) du mois de `reference` (aujourd'hui par défaut).
       Ex.: si le 31 tombe un dimanche et le 30 un samedi, retourne le 29 (vendredi)."""
    ref = reference or date.today()
    dernier = calendar.monthrange(ref.year, ref.month)[1]
    d = date(ref.year, ref.month, dernier)
    while d.weekday() >= 5:  # 5=samedi, 6=dimanche
        d -= timedelta(days=1)
    return d


def est_dernier_jour_ouvrable_du_mois() -> bool:
    return date.today() == dernier_jour_ouvrable_du_mois()


def fermer_factures_ouvertes(app, mail):
    """Ferme toutes les factures ouvertes et les envoie aux clients."""
    if not est_dernier_jour_ouvrable_du_mois():
        return
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

    # Garde anti-doublon : évite une 2e ligne pour le même projet sur la facture ouverte du
    # mois (peut arriver si le déclencheur "travaux en cours" tourne deux fois pour le même
    # projet — ex. bouton dédié suivi d'un forçage de statut).
    deja = conn.execute(
        "SELECT id FROM facture_lignes WHERE id_facture = ? AND id_projet = ?",
        (facture['id'], id_projet)
    ).fetchone()
    if deja:
        print(f"[SCHEDULER] Ligne déjà présente pour ce projet sur la facture mensuelle, ignorée: {description}")
        return

    conn.execute("""
        INSERT INTO facture_lignes
        (id_facture, id_projet, description, date_service, localisation, quantite, prix_unitaire, total_ligne)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (facture['id'], id_projet, description, date_service, localisation, prix, prix))
    conn.commit()
    print(f"[SCHEDULER] Ligne ajoutée à facture mensuelle: {description} — {prix}$")


def sync_calendar_todos():
    """Sync bidirectionnelle : si un événement lié à un todo est déplacé/supprimé
       dans Google Agenda, on répercute sur le todo (date_echeance / déplanification)."""
    try:
        from calendar_service import get_event_datetime
    except Exception:
        return
    conn = get_db()
    todos = conn.execute(
        "SELECT id, date_echeance, calendar_event_id FROM todos_perso "
        "WHERE calendar_event_id IS NOT NULL AND calendar_event_id != '' AND est_coche=0"
    ).fetchall()
    modifs = 0
    for t in todos:
        res = get_event_datetime(t['calendar_event_id'])
        if res is None:
            continue  # erreur transitoire → on ne touche à rien
        if res == 'deleted':
            conn.execute("UPDATE todos_perso SET calendar_event_id=NULL WHERE id=?", (t['id'],))
            modifs += 1
            continue
        new_date, _heure = res
        if new_date and new_date != t['date_echeance']:
            conn.execute("UPDATE todos_perso SET date_echeance=? WHERE id=?", (new_date, t['id']))
            modifs += 1
    conn.close()
    if modifs:
        print(f"[CALENDAR-SYNC] {modifs} todo(s) mis à jour depuis l'agenda")


def envoyer_recap_todos(app, mail):
    """Récap matinal : tâches planifiées aujourd'hui + en retard + notifs non lues."""
    from flask_mail import Message as MailMessage
    destinataire = os.getenv("TODO_RECAP_EMAIL", "felix.dumont@cocktailmedia.ca")
    with app.app_context():
        conn = get_db()
        today = date.today().strftime("%Y-%m-%d")
        aujourdhui = conn.execute(
            "SELECT texte, projet_nom FROM todos_perso "
            "WHERE est_coche=0 AND COALESCE(is_titre,0)=0 AND date_echeance=? ORDER BY priorite", (today,)
        ).fetchall()
        retard = conn.execute(
            "SELECT texte, projet_nom, date_echeance FROM todos_perso "
            "WHERE est_coche=0 AND COALESCE(is_titre,0)=0 AND date_echeance IS NOT NULL AND date_echeance < ? "
            "ORDER BY date_echeance", (today,)
        ).fetchall()
        notifs = conn.execute("SELECT COUNT(*) FROM admin_notifications WHERE is_read=0").fetchone()[0]
        conn.close()
        if not aujourdhui and not retard and not notifs:
            return  # rien à signaler → pas d'email

        def li(rows, show_date=False):
            out = ""
            for r in rows:
                proj = f" — {r['projet_nom']}" if r['projet_nom'] else ""
                d = f" <span style='color:#888'>(échéance {r['date_echeance']})</span>" if show_date else ""
                out += f"<li style='margin:4px 0'>{r['texte']}{proj}{d}</li>"
            return out or "<li style='color:#888'><i>Aucune</i></li>"

        html = f"""<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#2b2b2b">
          <h2 style="color:#c0321a">📋 Ton récap du jour</h2>
          <p><b>Aujourd'hui ({len(aujourdhui)})</b></p><ul>{li(aujourdhui)}</ul>
          <p><b>En retard ({len(retard)})</b></p><ul>{li(retard, show_date=True)}</ul>
          <p style="margin-top:16px">🔔 <b>{notifs}</b> notification(s) non lue(s) sur le portail.</p>
        </div>"""
        try:
            msg = MailMessage(
                f"📋 Récap tâches — {len(aujourdhui)} aujourd'hui, {len(retard)} en retard",
                sender=os.getenv("MAIL_DEFAULT_SENDER"), recipients=[destinataire])
            msg.body = f"{len(aujourdhui)} tâche(s) aujourd'hui, {len(retard)} en retard, {notifs} notif(s) non lues."
            msg.html = html
            mail.send(msg)
            print(f"[SCHEDULER] Récap todos envoyé à {destinataire}")
        except Exception as e:
            print(f"[SCHEDULER] Récap todos échoué: {e}")


def init_scheduler(app, mail):
    """Initialise et démarre le scheduler APScheduler.
       Verrou fichier : un seul worker gunicorn exécute réellement les jobs (évite ×N)."""
    global _scheduler_lock_fd
    try:
        _scheduler_lock_fd = open('/tmp/portail_scheduler.lock', 'w')
        fcntl.flock(_scheduler_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("[SCHEDULER] Déjà actif dans un autre worker — pas de démarrage ici")
        return None
    scheduler = BackgroundScheduler(timezone="America/Toronto")

    # Dernier jour OUVRABLE du mois à 17h00 (bug corrigé le 2026-07-19 : le job
    # tournait tous les jours ; day='25-31' + la garde est_dernier_jour_ouvrable_du_mois()
    # limitent le déclenchement réel au vendredi si le 30/31 tombe un samedi/dimanche).
    # Pas de job de pré-création du mois suivant : la facture ouverte d'un client mensuel
    # ne doit exister qu'à partir de l'assignation de son premier projet du mois
    # (ajouter_ligne_facture_mensuelle la crée à la volée) — sinon des coquilles vides à 0$
    # s'accumulent pour les clients mensuels inactifs un mois donné (constaté le 2026-07-19).
    scheduler.add_job(
        func=lambda: fermer_factures_ouvertes(app, mail),
        trigger=CronTrigger(day='25-31', hour=17, minute=0),
        id="fermer_factures",
        name="Fermer factures ouvertes fin de mois",
        replace_existing=True,
    )

    # Récap des tâches chaque matin à 8h
    scheduler.add_job(
        func=lambda: envoyer_recap_todos(app, mail),
        trigger=CronTrigger(hour=8, minute=0),
        id="recap_todos",
        name="Récap tâches quotidien",
        replace_existing=True,
    )

    # Sync agenda → todos toutes les 10 minutes (déplacement/suppression d'événement)
    scheduler.add_job(
        func=sync_calendar_todos,
        trigger=IntervalTrigger(minutes=10),
        id="sync_calendar_todos",
        name="Sync agenda → todos",
        replace_existing=True,
    )

    # Ingestion Gmail des factures fournisseurs — toutes les 15 min.
    # Le job no-op proprement s'il n'y a aucune intégration Gmail active.
    _gmail_ready = bool(os.getenv("GOOGLE_CLIENT_ID", "").strip() and os.getenv("GOOGLE_CLIENT_SECRET", "").strip())
    if _gmail_ready:
        def _gmail_job():
            try:
                import app as _app
                with _app.app.app_context():
                    _app.sync_gmail_factures(_app.app)
            except Exception as e:
                print(f"[GMAIL] job planifié échoué: {e}")
        scheduler.add_job(
            func=_gmail_job,
            trigger=IntervalTrigger(minutes=15),
            id="sync_gmail_factures",
            name="Ingestion Gmail → factures à valider",
            replace_existing=True,
        )

    scheduler.start()
    print("[SCHEDULER] Démarré — jobs: fermer_factures"
          + (" + sync_gmail_factures" if _gmail_ready else ""))
    return scheduler
