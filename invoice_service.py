# invoice_service.py
"""
Génération de factures PDF — Cocktail Média
ReportLab + intégration Drive
"""

import os
import re
import sqlite3
import pathlib
from datetime import date, timedelta, datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER

# ── Constantes Cocktail Média ──────────────────────────────
TPS_RATE  = 0.05
TVQ_RATE  = 0.09975
COULEUR_ACCENT = colors.HexColor("#E83B14")
COULEUR_SOMBRE = colors.HexColor("#2B2B2B")
COULEUR_GRIS   = colors.HexColor("#F5F5F5")
COULEUR_BORDURE = colors.HexColor("#E0D9D3")

INFO_ENTREPRISE = {
    "nom":       "Cocktail Média",
    "adresse":   "1001 Rang Saint-Malo",
    "ville":     "Trois-Rivières, Québec  G8V 1X4",
    "pays":      "Canada",
    "email":     "marie-christine.blanchette@cocktailmedia.ca",
    "telephone": "(581) 802-5835",
    "tps":       "725896823 RT0001",
    "tvq":       "4027917505 TQ0001",
}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
LOGO_PATH  = os.path.join(STATIC_DIR, "logo-cocktailmedia-bloc.png")
LOGO_FOOTER_PATH = os.path.join(STATIC_DIR, "cocktailos-logo-noir.png")

# ── Numérotation intelligente ──────────────────────────────
def _generer_abreviation(nom_entreprise: str) -> str:
    """Génère 2-3 lettres depuis le nom d'entreprise."""
    if not nom_entreprise:
        return "CM"
    # Retirer mots génériques
    stop = {"inc", "ltee", "ltée", "enr", "et", "and", "the", "le", "la", "les", "de", "du"}
    mots = [m for m in re.sub(r"[^\w\s]", "", nom_entreprise).split() if m.lower() not in stop]
    if not mots:
        return nom_entreprise[:2].upper()
    if len(mots) == 1:
        return mots[0][:3].upper()
    # Initiales des 2-3 premiers mots
    return "".join(m[0] for m in mots[:3]).upper()


def _abrev_unique(abrev: str, id_client: int, conn: sqlite3.Connection) -> str:
    """S'assure que l'abréviation est unique à ce client. Sinon allonge."""
    # Vérifie si cette abrev est déjà utilisée par un AUTRE client
    row = conn.execute("""
        SELECT id_client FROM factures
        WHERE numero LIKE ? AND id_client != ?
        LIMIT 1
    """, (f"{abrev}-%", id_client)).fetchone()

    if not row:
        return abrev  # Libre ou déjà à ce client

    # Conflit — essayer avec une lettre de plus depuis le nom entreprise (ou nom complet si vide)
    client = conn.execute(
        "SELECT nom_entreprise, nom_complet FROM clients WHERE id = ?", (id_client,)
    ).fetchone()
    nom = (client["nom_entreprise"] or client["nom_complet"] or "") if client else ""
    mots = [m for m in re.sub(r"[^\w\s]", "", nom).split()]
    for length in range(len(abrev) + 1, 6):
        candidat = "".join(m[0] for m in mots)[:length].upper()
        if not candidat:
            continue
        r2 = conn.execute("""
            SELECT id_client FROM factures
            WHERE numero LIKE ? AND id_client != ?
            LIMIT 1
        """, (f"{candidat}-%", id_client)).fetchone()
        if not r2:
            return candidat
    # Fallback : abrev + id client
    return f"{abrev}{id_client}"


def generer_numero_facture(id_client: int, conn: sqlite3.Connection) -> str:
    """Génère le prochain numéro de facture pour ce client. Ex: MD-003"""
    client = conn.execute(
        "SELECT nom_entreprise, nom_complet FROM clients WHERE id = ?", (id_client,)
    ).fetchone()
    nom_entreprise = ((client["nom_entreprise"] or client["nom_complet"]) if client else "") or ""
    abrev = _generer_abreviation(nom_entreprise)
    abrev = _abrev_unique(abrev, id_client, conn)

    # Compter les factures existantes de ce client
    count = conn.execute(
        "SELECT COUNT(*) FROM factures WHERE id_client = ?", (id_client,)
    ).fetchone()[0]

    numero = f"{abrev}-{str(count + 1).zfill(3)}"

    # Garantir unicité globale (collision rare mais possible)
    while conn.execute(
        "SELECT 1 FROM factures WHERE numero = ?", (numero,)
    ).fetchone():
        count += 1
        numero = f"{abrev}-{str(count + 1).zfill(3)}"

    return numero


# ── Calcul taxes ──────────────────────────────────────────
def calculer_taxes(sous_total: float, exonere: bool = False):
    if exonere:
        return 0.0, 0.0, sous_total
    tps = round(sous_total * TPS_RATE, 2)
    tvq = round(sous_total * TVQ_RATE, 2)
    total = round(sous_total + tps + tvq, 2)
    return tps, tvq, total


# ── Génération PDF ────────────────────────────────────────
def generer_pdf_facture(facture: dict, lignes: list, client: dict, output_path: str):
    """
    facture : dict avec numero, date_emission, date_echeance, type_facturation
    lignes  : list de dict {description, date_service, localisation, prix_unitaire, quantite}
    client  : dict avec nom_complet, nom_entreprise, adresse_facturation, etc.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    story  = []

    # Styles custom
    s_normal  = ParagraphStyle("normal",  fontSize=9,  leading=13, textColor=COULEUR_SOMBRE)
    s_small   = ParagraphStyle("small",   fontSize=8,  leading=11, textColor=colors.HexColor("#666666"))
    s_bold    = ParagraphStyle("bold",    fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_title   = ParagraphStyle("title",   fontSize=22, leading=26, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_right   = ParagraphStyle("right",   fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, alignment=TA_RIGHT)
    s_accent  = ParagraphStyle("accent",  fontSize=9,  leading=13, textColor=COULEUR_ACCENT, fontName="Helvetica-Bold")

    # ── EN-TÊTE : Logo gauche | Titre droite ──────────────
    logo_cell = ""
    if os.path.exists(LOGO_PATH):
        try:
            logo_cell = Image(LOGO_PATH, width=1.8*inch, height=0.7*inch, kind='proportional')
        except Exception:
            logo_cell = Paragraph("<b>COCKTAIL MÉDIA</b>", s_bold)
    else:
        logo_cell = Paragraph("<b>COCKTAIL MÉDIA</b>", s_bold)

    titre_facture = Paragraph(f"FACTURE N° {facture['numero']}", s_title)
    meta_facture  = Paragraph(
        f"Date d'émission : {facture['date_emission']}<br/>"
        f"Échéance : {facture['date_echeance']}",
        s_right
    )

    entete = Table(
        [[logo_cell, [titre_facture, Spacer(1, 4), meta_facture]]],
        colWidths=[2.5*inch, 4.75*inch]
    )
    entete.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN",  (1, 0), (1, 0),  "RIGHT"),
    ]))
    story.append(entete)
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=COULEUR_ACCENT))
    story.append(Spacer(1, 16))

    # ── BLOC ÉMETTEUR | DESTINATAIRE ──────────────────────
    # Émetteur (Cocktail Média)
    emetteur_lines = [
        Paragraph(f"<b>{INFO_ENTREPRISE['nom']}</b>", s_bold),
        Paragraph(INFO_ENTREPRISE["adresse"], s_normal),
        Paragraph(INFO_ENTREPRISE["ville"],   s_normal),
        Paragraph(INFO_ENTREPRISE["pays"],    s_normal),
        Paragraph(INFO_ENTREPRISE["email"],   s_normal),
        Paragraph(f"Téléphone : {INFO_ENTREPRISE['telephone']}", s_normal),
        Spacer(1, 6),
        Paragraph(f"TPS/TVH : {INFO_ENTREPRISE['tps']}", s_small),
        Paragraph(f"TVQ : {INFO_ENTREPRISE['tvq']}",     s_small),
    ]

    # Destinataire (client)
    dest_nom       = client.get("nom_complet", "")
    dest_entreprise= client.get("nom_entreprise", "")
    dest_adresse   = client.get("adresse_facturation", "")
    dest_ville     = client.get("ville_facturation", "")
    dest_province  = client.get("province_facturation", "")
    dest_cp        = client.get("code_postal_facturation", "")
    dest_pays      = client.get("pays_facturation", "Canada")
    dest_email     = client.get("email", "")
    dest_tel       = client.get("telephone", "")
    dest_tps       = client.get("numero_tps", "")
    dest_tvq       = client.get("numero_tvq", "")

    ville_cp = " ".join(filter(None, [dest_ville, dest_province, dest_cp]))

    destinataire_lines = [
        Paragraph("<b>Facturer à :</b>", s_bold),
        Paragraph(f"<b>{dest_nom}</b>", s_bold),
    ]
    if dest_entreprise and dest_entreprise != dest_nom:
        destinataire_lines.append(Paragraph(dest_entreprise, s_normal))
    if dest_adresse:
        destinataire_lines.append(Paragraph(dest_adresse, s_normal))
    if ville_cp:
        destinataire_lines.append(Paragraph(ville_cp, s_normal))
    destinataire_lines.append(Paragraph(dest_pays, s_normal))

    infos_supp = []
    if dest_email:
        infos_supp.append(Paragraph(dest_email, s_normal))
    if dest_tel:
        infos_supp.append(Paragraph(f"Téléphone : {dest_tel}", s_normal))
    if dest_tps:
        infos_supp.append(Paragraph(f"TPS/TVH : {dest_tps}", s_small))
    if dest_tvq:
        infos_supp.append(Paragraph(f"TVQ : {dest_tvq}", s_small))

    bloc_adresses = Table(
        [[emetteur_lines, destinataire_lines, infos_supp]],
        colWidths=[2.4*inch, 2.4*inch, 2.45*inch]
    )
    bloc_adresses.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(bloc_adresses)
    story.append(Spacer(1, 20))

    # ── TABLEAU DES LIGNES ────────────────────────────────
    table_data = [[
        Paragraph("<b>Article ou service</b>", s_bold),
        Paragraph("<b>Qté</b>", s_bold),
        Paragraph("<b>Prix unitaire</b>", s_bold),
        Paragraph("<b>Total</b>", s_bold),
    ]]

    sous_total = 0.0
    for ligne in lignes:
        desc = ligne.get("description", "")
        date_svc = ligne.get("date_service", "")
        loc      = ligne.get("localisation", "")
        qte      = int(ligne.get("quantite", 1))
        prix_u   = float(ligne.get("prix_unitaire", 0))
        total_l  = round(qte * prix_u, 2)
        sous_total += total_l

        # Description avec date et localisation
        desc_parts = [f"<b>{desc}</b>"]
        if date_svc:
            desc_parts.append(date_svc)
        if loc:
            desc_parts.append(loc)
        desc_para = Paragraph("<br/>".join(desc_parts), s_normal)

        table_data.append([
            desc_para,
            Paragraph(str(qte), s_normal),
            Paragraph(f"{prix_u:,.2f} $CA", s_right),
            Paragraph(f"{total_l:,.2f} $CA", s_right),
        ])

    col_widths = [3.8*inch, 0.5*inch, 1.4*inch, 1.55*inch]
    tableau = Table(table_data, colWidths=col_widths, repeatRows=1)
    tableau.setStyle(TableStyle([
        # En-tête
        ("BACKGROUND",    (0, 0), (-1, 0), COULEUR_GRIS),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COULEUR_SOMBRE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING",    (0, 0), (-1, 0), 8),
        # Corps
        ("FONTSIZE",      (0, 1), (-1, -1), 9),
        ("TOPPADDING",    (0, 1), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        # Lignes horizontales
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, COULEUR_BORDURE),
        ("LINEBELOW",     (0, 0), (-1, 0),  1,   COULEUR_ACCENT),
    ]))
    story.append(tableau)
    story.append(Spacer(1, 16))

    # ── TOTAUX ────────────────────────────────────────────
    exonere = bool(facture.get("exonere_taxes", False))
    tps, tvq, total = calculer_taxes(sous_total, exonere)

    totaux_data = [
        ["", "Sous-total",          f"{sous_total:,.2f} $CA"],
    ]
    if not exonere:
        totaux_data += [
            ["", f"TPS ({TPS_RATE*100:.0f}%)",            f"{tps:,.2f} $CA"],
            ["", f"TVQ ({TVQ_RATE*100:.3f}%)",            f"{tvq:,.2f} $CA"],
            ["", "Total des taxes",  f"{tps+tvq:,.2f} $CA"],
        ]
    totaux_data += [
        ["", "TOTAL DE LA FACTURE", f"{total:,.2f} $CA"],
        ["", "Montant payé",        "0,00 $CA"],
        ["", "RESTE À PAYER",       f"{total:,.2f} $CA"],
    ]

    total_row_idx = len(totaux_data) - 1  # RESTE À PAYER

    totaux = Table(totaux_data, colWidths=[3.8*inch, 2.0*inch, 1.45*inch])
    totaux.setStyle(TableStyle([
        ("ALIGN",      (1, 0), (-1, -1), "RIGHT"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEABOVE",  (1, total_row_idx), (-1, total_row_idx), 1, COULEUR_ACCENT),
        ("FONTNAME",   (1, total_row_idx), (-1, total_row_idx), "Helvetica-Bold"),
        ("TEXTCOLOR",  (1, total_row_idx), (-1, total_row_idx), COULEUR_ACCENT),
        # Ligne TOTAL FACTURE aussi en gras
        ("FONTNAME",   (1, total_row_idx - 2), (-1, total_row_idx - 2), "Helvetica-Bold"),
    ]))
    story.append(totaux)
    story.append(Spacer(1, 24))

    # ── PAIEMENT ──────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=COULEUR_BORDURE))
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>MODE DE PAIEMENT</b>", s_accent))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Virement Interac : marie-christine.blanchette@cocktailmedia.ca",
        s_normal
    ))

    if facture.get("stripe_payment_url"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f'Paiement en ligne : <a href="{facture["stripe_payment_url"]}" color="#1473e6">'
            f'{facture["stripe_payment_url"]}</a>',
            s_normal
        ))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Merci de votre confiance. Pour toute question, contactez-nous à "
        "marie-christine.blanchette@cocktailmedia.ca",
        s_small
    ))

    # ── Pied de page — dessiné sur CHAQUE page via un callback canvas plutôt
    # qu'ajouté au flux de contenu (story) : sinon, sur une facture avec plusieurs
    # lignes, il se retrouve poussé sur une 2e page (ou nulle part si tout tient
    # sur une page) au lieu d'apparaître systématiquement en bas de chaque page.
    def _dessiner_pied_de_page(canvas, doc_):
        canvas.saveState()
        page_width = doc_.pagesize[0]
        margin = doc_.leftMargin
        y_ligne = 0.62 * inch

        canvas.setStrokeColor(COULEUR_BORDURE)
        canvas.setLineWidth(0.5)
        canvas.line(margin, y_ligne, page_width - margin, y_ligne)

        if os.path.exists(LOGO_FOOTER_PATH):
            logo_w, logo_h = 1.2 * inch, 0.45 * inch
            canvas.drawImage(
                LOGO_FOOTER_PATH,
                (page_width - logo_w) / 2, y_ligne + 8,
                width=logo_w, height=logo_h,
                preserveAspectRatio=True, mask='auto',
            )

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#AAAAAA"))
        canvas.drawCentredString(
            page_width / 2, y_ligne - 12,
            "1001 Rang Saint-Malo, Trois-Rivieres QC G8V 1X4 · (581) 802-5835 · cocktailmedia.ca",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_dessiner_pied_de_page, onLaterPages=_dessiner_pied_de_page)

# ── Fonction principale ───────────────────────────────────
def creer_facture_projet(id_projet: int, conn: sqlite3.Connection) -> dict | None:
    """
    Crée une facture PDF pour un projet (mode 'projet').
    Retourne le dict facture créé ou None si prix manquant.
    """
    projet = conn.execute("""
        SELECT p.*, s.nom_service, s.prix, s.exonere_taxes, s.localisation_requise
        FROM projets p
        LEFT JOIN services s ON s.id = p.id_service
        WHERE p.id = ?
    """, (id_projet,)).fetchone()

    if not projet:
        return None

    prix = float(projet["prix"] or 0)
    if prix <= 0:
        print(f"[INVOICE] Projet {id_projet} — prix non défini, facture ignorée.")
        return None

    existing = conn.execute(
        "SELECT f.id, f.numero FROM factures f JOIN facture_lignes fl ON fl.id_facture = f.id WHERE fl.id_projet = ?",
        (id_projet,)
    ).fetchone()
    if existing:
        print(f"[INVOICE] Projet {id_projet} — facture {existing['numero']} déjà existante, ignorée.")
        return None

    client = conn.execute(
        "SELECT * FROM clients WHERE id = ?", (projet["id_client"],)
    ).fetchone()

    # Numéro de facture
    numero = generer_numero_facture(client["id"], conn)

    # Dates
    today      = date.today()
    echeance   = today + timedelta(days=15)
    date_str   = today.strftime("%Y-%m-%d")
    ech_str    = echeance.strftime("%Y-%m-%d")

    # Taxes
    exonere = bool(projet["exonere_taxes"])
    tps, tvq, total = calculer_taxes(prix, exonere)

    # Insérer en DB
    conn.execute("""
        INSERT INTO factures
        (numero, id_client, statut, type_facturation, date_emission, date_echeance,
         sous_total, tps, tvq, total, periode_mois)
        VALUES (?, ?, 'envoyee', 'projet', ?, ?, ?, ?, ?, ?, ?)
    """, (numero, client["id"], date_str, ech_str, prix, tps, tvq, total,
          today.strftime("%Y-%m")))
    id_facture = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Localisation sur la ligne si requise
    loc = projet["localisation"] if projet["localisation_requise"] else None

    # Ligne de facture
    conn.execute("""
        INSERT INTO facture_lignes
        (id_facture, id_projet, description, date_service, localisation, quantite, prix_unitaire, total_ligne)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (id_facture, id_projet, projet["nom_service"] or projet["nom_projet"] or "Service",
          date_str, loc, prix, prix))

    conn.commit()

    # Générer PDF
    upload_root = os.getenv("UPLOAD_ROOT", "/data/uploads")
    factures_dir = os.path.join(upload_root, "factures", f"client_{client['id']}")
    pathlib.Path(factures_dir).mkdir(parents=True, exist_ok=True)
    pdf_path = os.path.join(factures_dir, f"{numero}.pdf")

    lignes = [{"description": projet["nom_service"] or projet["nom_projet"] or "Service",
               "date_service": today.strftime("%d %B %Y"),
               "localisation": loc,
               "quantite": 1,
               "prix_unitaire": prix}]

    facture_dict = {
        "numero": numero,
        "date_emission": date_str,
        "date_echeance": ech_str,
        "exonere_taxes": exonere,
        "stripe_payment_url": None,
    }

    generer_pdf_facture(facture_dict, lignes, dict(client), pdf_path)

    # Sauvegarder le chemin PDF en DB
    conn.execute("UPDATE factures SET pdf_path = ? WHERE id = ?", (pdf_path, id_facture))
    conn.commit()

    return {
        "id": id_facture,
        "numero": numero,
        "pdf_path": pdf_path,
        "total": total,
        "date_echeance": ech_str,
        "client": dict(client),
    }


# ── Génération PDF facture pigiste ────────────────────────
def generer_pdf_facture_pigiste(facture: dict, lignes: list, pigiste: dict, output_path: str):
    """
    Même mise en page que generer_pdf_facture.
    EMETTEUR = pigiste (qui facture Cocktail Média)
    DESTINATAIRE = Cocktail Média
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=1.35 * inch,
    )

    styles = getSampleStyleSheet()
    story  = []

    s_normal = ParagraphStyle("normal",  fontSize=9,  leading=13, textColor=COULEUR_SOMBRE)
    s_small  = ParagraphStyle("small",   fontSize=8,  leading=11, textColor=colors.HexColor("#666666"))
    s_bold   = ParagraphStyle("bold",    fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_title  = ParagraphStyle("title",   fontSize=22, leading=26, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_right  = ParagraphStyle("right",   fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, alignment=TA_RIGHT)
    s_accent = ParagraphStyle("accent",  fontSize=9,  leading=13, textColor=COULEUR_ACCENT, fontName="Helvetica-Bold")

    # ── EN-TÊTE ──────────────────────────────────────────
    logo_cell = ""
    if os.path.exists(LOGO_PATH):
        try:
            logo_cell = Image(LOGO_PATH, width=1.8*inch, height=0.7*inch, kind='proportional')
        except Exception:
            logo_cell = Paragraph("<b>COCKTAIL MÉDIA</b>", s_bold)
    else:
        logo_cell = Paragraph("<b>COCKTAIL MÉDIA</b>", s_bold)

    titre_facture = Paragraph(f"FACTURE N° {facture['numero']}", s_title)
    meta_facture  = Paragraph(
        f"Date d'émission : {facture['date_emission']}<br/>"
        f"Échéance : {facture['date_echeance']}",
        s_right
    )

    entete = Table(
        [[logo_cell, [titre_facture, Spacer(1, 4), meta_facture]]],
        colWidths=[2.5*inch, 4.75*inch]
    )
    entete.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN",  (1, 0), (1, 0),  "RIGHT"),
    ]))
    story.append(entete)
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=COULEUR_ACCENT))
    story.append(Spacer(1, 16))

    # ── ÉMETTEUR (pigiste) | DESTINATAIRE (Cocktail Média) ──
    pig_nom     = pigiste.get("nom_complet", "")
    pig_adresse = pigiste.get("adresse", "")
    pig_ville   = pigiste.get("ville", "")
    pig_province= pigiste.get("province", "")
    pig_cp      = pigiste.get("code_postal", "")
    pig_email   = pigiste.get("email", "")
    pig_tel     = pigiste.get("telephone", "")
    pig_tps     = pigiste.get("numero_tps", "")
    pig_tvq     = pigiste.get("numero_tvq", "")

    ville_cp_pig = " ".join(filter(None, [pig_ville, pig_province, pig_cp]))

    emetteur_lines = [
        Paragraph(f"<b>{pig_nom}</b>", s_bold),
    ]
    if pig_adresse:
        emetteur_lines.append(Paragraph(pig_adresse, s_normal))
    if ville_cp_pig:
        emetteur_lines.append(Paragraph(ville_cp_pig, s_normal))
    emetteur_lines.append(Paragraph("Canada", s_normal))
    if pig_email:
        emetteur_lines.append(Paragraph(pig_email, s_normal))
    if pig_tel:
        emetteur_lines.append(Paragraph(f"Téléphone : {pig_tel}", s_normal))
    if pig_tps:
        emetteur_lines.append(Spacer(1, 4))
        emetteur_lines.append(Paragraph(f"TPS/TVH : {pig_tps}", s_small))
    if pig_tvq:
        emetteur_lines.append(Paragraph(f"TVQ : {pig_tvq}", s_small))

    destinataire_lines = [
        Paragraph("<b>Facturer à :</b>", s_bold),
        Paragraph(f"<b>{INFO_ENTREPRISE['nom']}</b>", s_bold),
        Paragraph(INFO_ENTREPRISE["adresse"], s_normal),
        Paragraph(INFO_ENTREPRISE["ville"],   s_normal),
        Paragraph(INFO_ENTREPRISE["pays"],    s_normal),
        Paragraph(INFO_ENTREPRISE["email"],   s_normal),
        Paragraph(f"Téléphone : {INFO_ENTREPRISE['telephone']}", s_normal),
        Spacer(1, 4),
        Paragraph(f"TPS/TVH : {INFO_ENTREPRISE['tps']}", s_small),
        Paragraph(f"TVQ : {INFO_ENTREPRISE['tvq']}",     s_small),
    ]

    bloc_adresses = Table(
        [[emetteur_lines, destinataire_lines, []]],
        colWidths=[2.4*inch, 2.4*inch, 2.45*inch]
    )
    bloc_adresses.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(bloc_adresses)
    story.append(Spacer(1, 20))

    # ── TABLEAU DES LIGNES ────────────────────────────────
    table_data = [[
        Paragraph("<b>Article ou service</b>", s_bold),
        Paragraph("<b>Qté</b>", s_bold),
        Paragraph("<b>Taux</b>", s_bold),
        Paragraph("<b>Total</b>", s_bold),
    ]]

    sous_total = 0.0
    for ligne in lignes:
        desc        = ligne.get("description", "")
        qte         = float(ligne.get("quantite", 1))
        taux        = float(ligne.get("taux", 0))
        montant     = float(ligne.get("montant", round(qte * taux, 2)))
        sous_total += montant

        # Sous-lignes contextuelles : mandat, projet/client, dates
        desc_parts = [f"<b>{desc}</b>"]
        mandat_titre = ligne.get("mandat_titre", "")
        nom_projet   = ligne.get("nom_projet", "")
        nom_client   = ligne.get("nom_client", "")
        date_mandat  = ligne.get("date_mandat", "")

        if mandat_titre and mandat_titre != desc:
            desc_parts.append(f"Mandat : {mandat_titre}")
        if nom_projet:
            ctx = nom_projet
            if nom_client:
                ctx += f" — {nom_client}"
            desc_parts.append(ctx)
        if date_mandat:
            desc_parts.append(date_mandat)

        desc_para = Paragraph("<br/>".join(desc_parts), s_normal)

        table_data.append([
            desc_para,
            Paragraph(str(int(qte)) if qte == int(qte) else str(qte), s_normal),
            Paragraph(f"{taux:,.2f} $CA", s_right),
            Paragraph(f"{montant:,.2f} $CA", s_right),
        ])

    col_widths = [3.8*inch, 0.5*inch, 1.4*inch, 1.55*inch]
    tableau = Table(table_data, colWidths=col_widths, repeatRows=1)
    tableau.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COULEUR_GRIS),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COULEUR_SOMBRE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING",    (0, 0), (-1, 0), 8),
        ("FONTSIZE",      (0, 1), (-1, -1), 9),
        ("TOPPADDING",    (0, 1), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, COULEUR_BORDURE),
        ("LINEBELOW",     (0, 0), (-1, 0),  1,   COULEUR_ACCENT),
    ]))
    story.append(tableau)
    story.append(Spacer(1, 16))

    # ── TOTAUX ────────────────────────────────────────────
    tps  = float(facture.get("tps",  0))
    tvq  = float(facture.get("tvq",  0))
    total = float(facture.get("montant_total", sous_total + tps + tvq))

    totaux_data = [["", "Sous-total", f"{sous_total:,.2f} $CA"]]
    if tps > 0:
        totaux_data.append(["", f"TPS (5,0%)",          f"{tps:,.2f} $CA"])
    if tvq > 0:
        totaux_data.append(["", f"TVQ (9,975%)",         f"{tvq:,.2f} $CA"])
    if tps > 0 or tvq > 0:
        totaux_data.append(["", "Total des taxes",       f"{tps+tvq:,.2f} $CA"])
    totaux_data += [
        ["", "TOTAL DE LA FACTURE", f"{total:,.2f} $CA"],
        ["", "Montant payé",        "0,00 $CA"],
        ["", "RESTE À PAYER",       f"{total:,.2f} $CA"],
    ]

    total_row_idx = len(totaux_data) - 1

    totaux = Table(totaux_data, colWidths=[3.8*inch, 2.0*inch, 1.45*inch])
    totaux.setStyle(TableStyle([
        ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEABOVE",     (1, total_row_idx), (-1, total_row_idx), 1, COULEUR_ACCENT),
        ("FONTNAME",      (1, total_row_idx), (-1, total_row_idx), "Helvetica-Bold"),
        ("TEXTCOLOR",     (1, total_row_idx), (-1, total_row_idx), COULEUR_ACCENT),
        ("FONTNAME",      (1, total_row_idx - 2), (-1, total_row_idx - 2), "Helvetica-Bold"),
    ]))
    story.append(totaux)
    story.append(Spacer(1, 24))

    # ── PAIEMENT ──────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=COULEUR_BORDURE))
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>MODE DE PAIEMENT</b>", s_accent))
    story.append(Spacer(1, 6))
    if pig_email:
        story.append(Paragraph(f"Virement Interac : {pig_email}", s_normal))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Merci pour votre collaboration. Pour toute question, contactez "
        f"marie-christine.blanchette@cocktailmedia.ca",
        s_small
    ))

    # Pied de page — voir le commentaire équivalent dans generer_pdf_facture : dessiné
    # sur chaque page via un callback canvas, pas ajouté au flux (sinon poussé sur une 2e page).
    def _dessiner_pied_de_page(canvas, doc_):
        canvas.saveState()
        page_width = doc_.pagesize[0]
        margin = doc_.leftMargin
        y_ligne = 0.62 * inch

        canvas.setStrokeColor(COULEUR_BORDURE)
        canvas.setLineWidth(0.5)
        canvas.line(margin, y_ligne, page_width - margin, y_ligne)

        if os.path.exists(LOGO_FOOTER_PATH):
            logo_w, logo_h = 1.2 * inch, 0.45 * inch
            canvas.drawImage(
                LOGO_FOOTER_PATH,
                (page_width - logo_w) / 2, y_ligne + 8,
                width=logo_w, height=logo_h,
                preserveAspectRatio=True, mask='auto',
            )

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#AAAAAA"))
        canvas.drawCentredString(
            page_width / 2, y_ligne - 12,
            "1001 Rang Saint-Malo, Trois-Rivieres QC G8V 1X4 · (581) 802-5835 · cocktailmedia.ca",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_dessiner_pied_de_page, onLaterPages=_dessiner_pied_de_page)
