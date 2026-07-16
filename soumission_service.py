# soumission_service.py
"""
Génération de soumissions PDF — Cocktail Média
ReportLab — même charte graphique que invoice_service.py
"""

import os
import json
import pathlib
from datetime import date

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image, KeepTogether,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER

COULEUR_ACCENT  = colors.HexColor("#E83B14")
COULEUR_SOMBRE  = colors.HexColor("#2B2B2B")
COULEUR_GRIS    = colors.HexColor("#F5F5F5")
COULEUR_BORDURE = colors.HexColor("#E0D9D3")
COULEUR_TEXTE2  = colors.HexColor("#666666")

INFO_ENTREPRISE = {
    "nom":       "Cocktail Média",
    "adresse":   "1001 Rang Saint-Malo",
    "ville":     "Trois-Rivières, Québec  G8V 1X4",
    "pays":      "Canada",
    "email":     "felix.dumont@cocktailmedia.ca",
    "telephone": "(581) 802-5835",
    "tps":       "725896823 RT0001",
    "tvq":       "4027917505 TQ0001",
}

STATIC_DIR       = os.path.join(os.path.dirname(__file__), "static")
LOGO_PATH        = os.path.join(STATIC_DIR, "logo-cocktailmedia-bloc.png")
LOGO_FOOTER_PATH = os.path.join(STATIC_DIR, "cocktailos-logo-noir.png")

CHECK = "✓"
DASH  = "–"


def _styles():
    s_normal  = ParagraphStyle("s_normal",  fontSize=9,  leading=13, textColor=COULEUR_SOMBRE)
    s_small   = ParagraphStyle("s_small",   fontSize=8,  leading=11, textColor=COULEUR_TEXTE2)
    s_bold    = ParagraphStyle("s_bold",    fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_right   = ParagraphStyle("s_right",   fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, alignment=TA_RIGHT)
    s_center  = ParagraphStyle("s_center",  fontSize=9,  leading=13, textColor=COULEUR_SOMBRE, alignment=TA_CENTER)
    s_title   = ParagraphStyle("s_title",   fontSize=22, leading=26, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_accent  = ParagraphStyle("s_accent",  fontSize=9,  leading=13, textColor=COULEUR_ACCENT, fontName="Helvetica-Bold")
    s_opt     = ParagraphStyle("s_opt",     fontSize=13, leading=17, textColor=COULEUR_SOMBRE, fontName="Helvetica-Bold")
    s_prix    = ParagraphStyle("s_prix",    fontSize=18, leading=22, textColor=COULEUR_ACCENT, fontName="Helvetica-Bold")
    s_label   = ParagraphStyle("s_label",   fontSize=7,  leading=10, textColor=COULEUR_TEXTE2, fontName="Helvetica-Bold",
                                spaceAfter=1, textTransform="uppercase" if hasattr(ParagraphStyle, "textTransform") else None)
    return s_normal, s_small, s_bold, s_right, s_center, s_title, s_accent, s_opt, s_prix, s_label


def generer_pdf_soumission(soumission: dict, options: list, client: dict, output_path: str):
    """
    soumission : dict {id, titre, message_intro, date_expiration, ...}
    options    : list de dicts (soumission_options rows, avec inclus_json déjà parsé ou str)
    client     : dict {nom_complet, nom_entreprise, email, telephone, ...}
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    s_normal, s_small, s_bold, s_right, s_center, s_title, s_accent, s_opt, s_prix, s_label = _styles()
    story = []

    # ── EN-TÊTE ───────────────────────────────────────────
    logo_cell = Paragraph("<b>COCKTAIL MÉDIA</b>", s_bold)
    if os.path.exists(LOGO_PATH):
        try:
            logo_cell = Image(LOGO_PATH, width=1.8*inch, height=0.7*inch, kind='proportional')
        except Exception:
            pass

    today_str = date.today().strftime("%d %B %Y")
    titre_cell = Paragraph("SOUMISSION", s_title)
    meta_cell  = Paragraph(
        f"Date : {today_str}<br/>Référence : SOUM-{soumission.get('id', '')}",
        s_right
    )

    entete = Table(
        [[logo_cell, [titre_cell, Spacer(1, 4), meta_cell]]],
        colWidths=[2.5*inch, 4.75*inch]
    )
    entete.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN",  (1, 0), (1, 0),  "RIGHT"),
    ]))
    story.append(entete)
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=2, color=COULEUR_ACCENT))
    story.append(Spacer(1, 16))

    # ── ÉMETTEUR | DESTINATAIRE ───────────────────────────
    emetteur = [
        Paragraph(f"<b>{INFO_ENTREPRISE['nom']}</b>", s_bold),
        Paragraph(INFO_ENTREPRISE["adresse"], s_normal),
        Paragraph(INFO_ENTREPRISE["ville"],   s_normal),
        Paragraph(INFO_ENTREPRISE["pays"],    s_normal),
        Paragraph(INFO_ENTREPRISE["email"],   s_normal),
        Paragraph(f"Tél. : {INFO_ENTREPRISE['telephone']}", s_normal),
        Spacer(1, 6),
        Paragraph(f"TPS/TVH : {INFO_ENTREPRISE['tps']}", s_small),
        Paragraph(f"TVQ : {INFO_ENTREPRISE['tvq']}",     s_small),
    ]

    nom_client  = client.get("nom_complet", "")
    nom_ent     = client.get("nom_entreprise", "")
    email_c     = client.get("email", "")
    tel_c       = client.get("telephone", "")

    dest = [Paragraph("<b>Soumis à :</b>", s_bold),
            Paragraph(f"<b>{nom_client}</b>", s_bold)]
    if nom_ent and nom_ent != nom_client:
        dest.append(Paragraph(nom_ent, s_normal))
    if email_c:
        dest.append(Paragraph(email_c, s_normal))
    if tel_c:
        dest.append(Paragraph(f"Tél. : {tel_c}", s_normal))

    exp = soumission.get("date_expiration")
    validite = []
    if exp:
        validite = [
            Paragraph("<b>Valide jusqu'au :</b>", s_bold),
            Paragraph(str(exp), s_normal),
        ]

    bloc = Table([[emetteur, dest, validite]], colWidths=[2.4*inch, 2.7*inch, 2.15*inch])
    bloc.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(bloc)
    story.append(Spacer(1, 20))

    # ── TITRE SOUMISSION + MESSAGE INTRO ─────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=COULEUR_BORDURE))
    story.append(Spacer(1, 12))
    story.append(Paragraph(soumission.get("titre", ""), ParagraphStyle(
        "titre_soum", fontSize=14, leading=18, textColor=COULEUR_SOMBRE,
        fontName="Helvetica-Bold", spaceAfter=6
    )))
    intro = soumission.get("message_intro", "")
    if intro:
        story.append(Paragraph(intro, ParagraphStyle(
            "intro", fontSize=9, leading=14, textColor=COULEUR_TEXTE2, spaceAfter=4
        )))
    story.append(Spacer(1, 16))

    # ── OPTIONS ──────────────────────────────────────────
    for idx, opt in enumerate(options):
        inclus = opt.get("inclus_json", [])
        if isinstance(inclus, str):
            try:
                inclus = json.loads(inclus)
            except Exception:
                inclus = []

        prix_setup   = float(opt.get("prix_setup") or 0)
        prix_mensuel = float(opt.get("prix_mensuel") or 0)
        est_rec      = int(opt.get("est_recommande") or 0)

        # Coût mensuel : prix_mensuel si défini, sinon premier tiers avec /mois
        couts_tiers = opt.get("couts_tiers_json", [])
        if isinstance(couts_tiers, str):
            try:
                couts_tiers = json.loads(couts_tiers)
            except Exception:
                couts_tiers = []

        bloc_opt = []

        # Titre option
        badge_rec = " ★ RECOMMANDÉ" if est_rec else ""
        bloc_opt.append(Paragraph(
            f"{opt.get('nom','')}{badge_rec}",
            ParagraphStyle("opt_titre", fontSize=13, leading=17, textColor=COULEUR_SOMBRE,
                           fontName="Helvetica-Bold")
        ))
        bloc_opt.append(Spacer(1, 4))

        # Prix strip
        prix_setup_str = f"{prix_setup:,.2f} $" if prix_setup > 0 else "Sur devis"
        if prix_mensuel > 0:
            prix_mensuel_str = f"~{prix_mensuel:,.2f} $/mois"
        else:
            tiers_mois = next((c.get("cout", "") for c in couts_tiers if "/mois" in c.get("cout", "")), None)
            prix_mensuel_str = tiers_mois if tiers_mois else None

        prix_cells = [
            [Paragraph("INVESTISSEMENT INITIAL", ParagraphStyle("lbl", fontSize=7, textColor=COULEUR_TEXTE2,
                       fontName="Helvetica-Bold", leading=9)),
             Paragraph("ABONNEMENT MENSUEL", ParagraphStyle("lbl", fontSize=7, textColor=COULEUR_TEXTE2,
                       fontName="Helvetica-Bold", leading=9)) if prix_mensuel_str else Paragraph("", s_small),
             Paragraph("DÉLAI", ParagraphStyle("lbl", fontSize=7, textColor=COULEUR_TEXTE2,
                       fontName="Helvetica-Bold", leading=9)) if opt.get("delai_livraison") else Paragraph("", s_small)],
            [Paragraph(f"<b>{prix_setup_str}</b>", ParagraphStyle("pval", fontSize=14, textColor=COULEUR_ACCENT,
                       fontName="Helvetica-Bold", leading=18)),
             Paragraph(f"<b>{prix_mensuel_str}</b>", ParagraphStyle("pval", fontSize=12, textColor=COULEUR_SOMBRE,
                       fontName="Helvetica-Bold", leading=16)) if prix_mensuel_str else Paragraph("", s_small),
             Paragraph(f"<b>{opt.get('delai_livraison','')}</b>", ParagraphStyle("pval", fontSize=11, textColor=COULEUR_SOMBRE,
                       fontName="Helvetica-Bold", leading=15)) if opt.get("delai_livraison") else Paragraph("", s_small)],
            [Paragraph("avant taxes", s_small), Paragraph("avant taxes" if prix_mensuel_str else "", s_small), Paragraph("", s_small)],
        ]
        prix_tbl = Table(prix_cells, colWidths=[2.5*inch, 2.5*inch, 2.25*inch])
        prix_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), COULEUR_GRIS),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("LINEAFTER",     (0, 0), (1, -1),  0.5, COULEUR_BORDURE),
        ]))
        bloc_opt.append(prix_tbl)
        bloc_opt.append(Spacer(1, 8))

        # Description
        desc = opt.get("description", "")
        if desc:
            bloc_opt.append(Paragraph(desc, ParagraphStyle(
                "desc", fontSize=9, leading=14, textColor=COULEUR_TEXTE2, spaceAfter=6,
                leftIndent=2
            )))

        # Prestations incluses
        if inclus:
            bloc_opt.append(Paragraph("PRESTATIONS INCLUSES", ParagraphStyle(
                "inc_h", fontSize=7, fontName="Helvetica-Bold", textColor=COULEUR_TEXTE2,
                leading=10, spaceBefore=4, spaceAfter=4
            )))
            # 2 colonnes
            mid = (len(inclus) + 1) // 2
            col1 = inclus[:mid]
            col2 = inclus[mid:]
            rows = []
            for i in range(max(len(col1), len(col2))):
                l = col1[i] if i < len(col1) else ""
                r = col2[i] if i < len(col2) else ""
                rows.append([
                    Paragraph(f"<b>{CHECK}</b>  {l}", ParagraphStyle("item", fontSize=8, leading=11,
                               textColor=COULEUR_SOMBRE, leftIndent=4)) if l else Paragraph("", s_small),
                    Paragraph(f"<b>{CHECK}</b>  {r}", ParagraphStyle("item", fontSize=8, leading=11,
                               textColor=COULEUR_SOMBRE, leftIndent=4)) if r else Paragraph("", s_small),
                ])
            inclus_tbl = Table(rows, colWidths=[3.6*inch, 3.65*inch])
            inclus_tbl.setStyle(TableStyle([
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.3, COULEUR_BORDURE),
            ]))
            bloc_opt.append(inclus_tbl)
            bloc_opt.append(Spacer(1, 6))

        # Conditions de paiement
        cond = opt.get("conditions_paiement", "")
        if cond:
            bloc_opt.append(Paragraph(
                f"<b>Modalités de paiement :</b>  {cond}",
                ParagraphStyle("cond", fontSize=8, leading=12, textColor=COULEUR_SOMBRE, spaceBefore=2)
            ))

        story.append(KeepTogether(bloc_opt))
        story.append(Spacer(1, 14))

        if idx < len(options) - 1:
            story.append(HRFlowable(width="100%", thickness=0.5, color=COULEUR_BORDURE))
            story.append(Spacer(1, 14))

    # ── NOTE DE FIN ──────────────────────────────────────
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COULEUR_BORDURE))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Cette soumission est confidentielle et préparée exclusivement pour le destinataire indiqué. "
        "Pour toute question, contactez-nous à felix.dumont@cocktailmedia.ca ou au (581) 802-5835.",
        ParagraphStyle("note", fontSize=8, leading=12, textColor=COULEUR_TEXTE2, alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 12))

    # ── PIED DE PAGE ─────────────────────────────────────
    footer_logo = None
    if os.path.exists(LOGO_FOOTER_PATH):
        try:
            footer_logo = Image(LOGO_FOOTER_PATH, width=1.2*inch, height=0.45*inch, kind='proportional')
        except Exception:
            pass

    footer_text = Paragraph(
        "1001 Rang Saint-Malo, Trois-Rivières QC G8V 1X4 · (581) 802-5835 · cocktailmedia.ca",
        ParagraphStyle("footer", fontSize=7, textColor=colors.HexColor("#AAAAAA"), alignment=TA_CENTER)
    )

    if footer_logo:
        ft = Table([[footer_logo], [footer_text]], colWidths=[7.25*inch])
        ft.setStyle(TableStyle([
            ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(ft)
    else:
        story.append(footer_text)

    doc.build(story)
