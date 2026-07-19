# email_templates.py — Templates HTML emails Cocktail Média
# Style basé sur la newsletter officielle Cocktail Média

LOGO_URL = "https://static.wixstatic.com/media/603d87_ec59249ae1894c9ca598cf76288b5b2b~mv2.png"
PORTAIL_URL = "https://portail.cocktailmedia.ca"


def _add_to_calendar_html(google_url: str, outlook_url: str, ics_url: str) -> str:
    """Bloc HTML 'Ajouter à mon agenda' compatible email (3 boutons, aucun JS)."""
    btn = lambda label, url, icon_char: (
        f'<a href="{url}" target="_blank" '
        f'style="display:inline-block;margin:0 6px 8px 0;padding:10px 18px;'
        f'background:#faf7f3;border:1.5px solid #d8d3cc;border-radius:6px;'
        f'font-family:Montserrat,sans-serif;font-size:12px;font-weight:700;'
        f'color:#2b2b2b;text-decoration:none;text-transform:uppercase;letter-spacing:1px;">'
        f'{icon_char}&nbsp; {label}</a>'
    )
    return (
        '<p style="margin:16px 0 8px 0;font-family:Montserrat,sans-serif;font-size:11px;'
        'color:#888;text-transform:uppercase;letter-spacing:2px;font-weight:600;">'
        'Ajouter à mon agenda</p>' +
        btn('Google Calendar', google_url, '📅') +
        btn('Outlook', outlook_url, '📆') +
        btn('Apple / .ics', ics_url, '⬇')
    )

def _base(titre_hero, sous_titre_hero, sections, cta_texte=None, cta_url=None):
    """Génère un email HTML complet dans le style newsletter Cocktail Média."""

    sections_html = ""
    for s in sections:
        label = s.get("label", "")
        titre = s.get("titre", "")
        contenu = s.get("contenu", "")

        label_html = f'<p style="margin:0 0 6px 0;font-family:Montserrat,sans-serif;font-size:11px;color:#e83b14;text-transform:uppercase;letter-spacing:2px;font-weight:600;">{label}</p>' if label else ""
        titre_html = f'<h2 style="margin:0 0 15px 0;font-family:\'Bebas Neue\',Impact,sans-serif;font-size:24px;line-height:28px;color:#2b2b2b;letter-spacing:1px;text-transform:uppercase;">{titre}</h2>' if titre else ""

        sections_html += f"""
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr><td style="padding:35px 40px 25px 40px;">
            {label_html}
            {titre_html}
            {contenu}
          </td></tr>
        </table>
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr><td style="padding:0 40px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
              <tr><td style="border-top:2px solid #f0ede9;font-size:0;line-height:0;">&nbsp;</td></tr>
            </table>
          </td></tr>
        </table>"""

    cta_html = ""
    if cta_texte and cta_url:
        cta_html = f"""
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr><td align="center" style="padding:10px 40px 35px 40px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center">
              <tr><td style="border-radius:6px;background-color:#e83b14;">
                <a href="{cta_url}" target="_blank"
                   style="display:inline-block;padding:14px 32px;font-family:'Bebas Neue',Impact,sans-serif;
                          font-size:17px;letter-spacing:2px;color:#faf7f3;text-decoration:none;text-transform:uppercase;">
                  {cta_texte}
                </a>
              </td></tr>
            </table>
          </td></tr>
        </table>"""

    return f"""<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Cocktail Média</title>
  <style>
    body,table,td,a{{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}}
    table,td{{mso-table-lspace:0pt;mso-table-rspace:0pt;}}
    img{{-ms-interpolation-mode:bicubic;border:0;height:auto;line-height:100%;outline:none;text-decoration:none;}}
    body{{margin:0!important;padding:0!important;width:100%!important;background-color:#faf7f3;}}
    @media screen and (max-width:600px){{
      .email-container{{width:100%!important;max-width:100%!important;}}
      .padding-mobile{{padding-left:20px!important;padding-right:20px!important;}}
      .hero-title{{font-size:28px!important;line-height:32px!important;}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#faf7f3;font-family:Montserrat,'Helvetica Neue',Helvetica,Arial,sans-serif;">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color:#faf7f3;">
  <tr><td align="center" style="padding:20px 10px;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" class="email-container" style="max-width:600px;margin:auto;">

      <!-- HERO -->
      <tr><td style="background-color:#2b2b2b;border-radius:12px 12px 0 0;overflow:hidden;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr><td style="height:4px;background-color:#e83b14;font-size:0;line-height:0;">&nbsp;</td></tr>
          <tr><td align="center" style="padding:35px 40px 0 40px;" class="padding-mobile">
            <img src="{LOGO_URL}" width="200" alt="Cocktail Média"
                 style="display:block;border:0;max-width:200px;height:auto;">
          </td></tr>
          <tr><td align="center" style="padding:20px 40px 10px 40px;" class="padding-mobile">
            <p style="margin:0;font-family:Montserrat,sans-serif;font-size:11px;color:#e83b14;
                      text-transform:uppercase;letter-spacing:3px;font-weight:600;">
              Portail Client — Cocktail Média
            </p>
          </td></tr>
          <tr><td align="center" style="padding:0 40px 35px 40px;" class="padding-mobile">
            <h1 class="hero-title"
                style="margin:0;font-family:'Bebas Neue',Impact,sans-serif;font-size:36px;
                       line-height:40px;color:#faf7f3;letter-spacing:2px;text-transform:uppercase;">
              {titre_hero}
            </h1>
            <p style="margin:16px 0 0 0;font-family:Montserrat,sans-serif;font-size:14px;
                      line-height:22px;color:#c2bfbb;">
              {sous_titre_hero}
            </p>
          </td></tr>
        </table>
      </td></tr>

      <!-- BODY -->
      <tr><td style="background-color:#ffffff;padding:0;">
        {sections_html}
        {cta_html}
      </td></tr>

      <!-- FOOTER -->
      <tr><td style="background-color:#2b2b2b;border-radius:0 0 12px 12px;overflow:hidden;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr><td align="center" style="padding:30px 40px 15px 40px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center">
              <tr>
                <td style="padding:0 8px;">
                  <a href="https://www.instagram.com/cocktailmedia.ca" target="_blank"
                     style="color:#faf7f3;text-decoration:none;font-family:Montserrat,sans-serif;font-size:13px;">Instagram</a>
                </td>
                <td style="color:#555;font-size:13px;">&bull;</td>
                <td style="padding:0 8px;">
                  <a href="https://www.facebook.com/cocktailmedias" target="_blank"
                     style="color:#faf7f3;text-decoration:none;font-family:Montserrat,sans-serif;font-size:13px;">Facebook</a>
                </td>
                <td style="color:#555;font-size:13px;">&bull;</td>
                <td style="padding:0 8px;">
                  <a href="https://www.cocktailmedia.ca" target="_blank"
                     style="color:#faf7f3;text-decoration:none;font-family:Montserrat,sans-serif;font-size:13px;">Site web</a>
                </td>
              </tr>
            </table>
          </td></tr>
          <tr><td align="center" style="padding:10px 40px 12px 40px;">
            <p style="margin:0;font-family:Montserrat,sans-serif;font-size:12px;
                      line-height:18px;color:#888;">Cocktail Média — Trois-Rivières, Mauricie</p>
          </td></tr>
          <tr><td align="center" style="padding:0 40px 25px 40px;">
            <p style="margin:0;font-family:Montserrat,sans-serif;font-size:11px;
                      line-height:16px;color:#666;">
              Vous recevez ce courriel car vous êtes client de Cocktail Média.<br>
              <a href="{PORTAIL_URL}" style="color:#e83b14;text-decoration:underline;">Accéder au portail</a>
            </p>
          </td></tr>
          <tr><td style="height:4px;background-color:#e83b14;font-size:0;line-height:0;">&nbsp;</td></tr>
        </table>
      </td></tr>

      <tr><td style="height:30px;font-size:0;line-height:0;">&nbsp;</td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""

def _p(texte):
    return f'<p style="margin:0 0 15px 0;font-family:Montserrat,sans-serif;font-size:14px;line-height:23px;color:#555;">{texte}</p>'

def _highlight(texte):
    return f'<p style="margin:0 0 15px 0;padding:14px 18px;background:#faf7f3;border-left:4px solid #e83b14;border-radius:0 6px 6px 0;font-family:\'Bebas Neue\',Impact,sans-serif;font-size:18px;letter-spacing:1px;color:#2b2b2b;">{texte}</p>'

# ─── Templates individuels ─────────────────────────────────

def email_bienvenue(nom, email):
    return _base(
        titre_hero="Bienvenue chez Cocktail Média !",
        sous_titre_hero="Votre compte est actif. Bienvenue dans votre espace client.",
        sections=[
            {
                "label": "Votre portail",
                "titre": f"Bonjour {nom}, on est contents de vous avoir !",
                "contenu": (
                    _p("Votre compte portail est maintenant actif. Cet espace a été créé pour vous permettre de suivre vos projets, transmettre vos documents et consulter vos factures — le tout au même endroit.") +
                    _p("Notre équipe vous contactera bientôt pour démarrer votre premier projet. D'ici là, n'hésitez pas à explorer votre portail.")
                )
            }
        ],
        cta_texte="ACCÉDER À MON PORTAIL",
        cta_url=PORTAIL_URL
    )

def email_projet_cree(nom, nom_projet, lien_projet):
    return _base(
        titre_hero="Nouveau projet assigné",
        sous_titre_hero="Un nouveau projet vient d'être créé dans votre portail.",
        sections=[
            {
                "label": "Votre nouveau projet",
                "titre": "C'est parti !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Un nouveau projet vient de vous être assigné :") +
                    _highlight(nom_projet) +
                    _p("Consultez les détails et les documents requis directement sur votre portail.")
                )
            }
        ],
        cta_texte="VOIR MON PROJET",
        cta_url=lien_projet
    )

def email_documents_requis(nom, nom_projet, lien_projet):
    return _base(
        titre_hero="Documents requis",
        sous_titre_hero="Nous avons besoin de vos documents pour démarrer.",
        sections=[
            {
                "label": "Action requise",
                "titre": "On attend vos fichiers !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Nous avons besoin de certains documents pour démarrer votre projet :") +
                    _highlight(nom_projet) +
                    _p("Connectez-vous à votre portail et téléversez les documents demandés dans la checklist de votre projet. Plus vite on les reçoit, plus vite on commence !")
                )
            }
        ],
        cta_texte="ENVOYER MES DOCUMENTS",
        cta_url=lien_projet
    )

def email_travaux_en_cours(nom, nom_projet, lien_projet):
    return _base(
        titre_hero="Les travaux sont en cours !",
        sous_titre_hero="Documents reçus — on s'y met !",
        sections=[
            {
                "label": "Mise à jour de votre projet",
                "titre": "On a tout ce qu'il faut.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Bonne nouvelle — nous avons reçu tout ce dont nous avions besoin. Les travaux sont maintenant en cours sur votre projet :") +
                    _highlight(nom_projet) +
                    _p("Nous vous tiendrons informé de l'avancement. Vous pouvez suivre le statut en tout temps sur votre portail.")
                )
            }
        ],
        cta_texte="VOIR L'AVANCEMENT",
        cta_url=lien_projet
    )

def email_en_revision(nom, nom_projet, lien_projet):
    return _base(
        titre_hero="Votre projet est en révision",
        sous_titre_hero="Consultez et approuvez vos révisions.",
        sections=[
            {
                "label": "Révision",
                "titre": "On a besoin de votre avis.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Votre projet est maintenant en phase de révision :") +
                    _highlight(nom_projet) +
                    _p("Veuillez consulter les items de révision sur votre portail et nous faire part de vos commentaires.")
                )
            }
        ],
        cta_texte="VOIR MES RÉVISIONS",
        cta_url=lien_projet
    )

def email_revision_site_web(nom, nom_projet, lien_site_test, lien_portail, items=None):
    """Révision spécifique aux projets Site Web Vitrine : lien du site test + liste des items à vérifier."""
    items = items or []
    items_html = ""
    if items:
        items_html = '<ul style="margin:0 0 15px 0;padding:0 0 0 20px;font-family:Montserrat,sans-serif;font-size:14px;line-height:24px;color:#555;">'
        for it in items:
            items_html += f'<li style="margin:0 0 6px 0;">{it}</li>'
        items_html += '</ul>'

    site_html = ""
    if lien_site_test:
        site_html = (
            '<p style="margin:0 0 20px 0;text-align:center;">'
            f'<a href="{lien_site_test}" target="_blank" '
            'style="display:inline-block;padding:12px 28px;background:#2b2b2b;border-radius:6px;'
            'font-family:\'Bebas Neue\',Impact,sans-serif;font-size:15px;letter-spacing:1.5px;'
            'color:#faf7f3;text-decoration:none;text-transform:uppercase;">'
            'VOIR LE SITE TEST →</a></p>'
        )

    return _base(
        titre_hero="Votre site est prêt à être révisé",
        sous_titre_hero="On a besoin de votre avis avant la mise en ligne.",
        sections=[
            {
                "label": "Révision — Site web",
                "titre": "À vous de jouer !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Votre site web est maintenant prêt pour révision :") +
                    _highlight(nom_projet) +
                    site_html +
                    _p("Voici ce qu'on vous demande de vérifier sur le site test :") +
                    items_html +
                    _p("Pour chaque item, rendez-vous sur votre portail : cochez la case si tout est correct, ou décrivez ce qui doit changer (vous pouvez aussi joindre une image, par exemple pour remplacer une photo).")
                )
            }
        ],
        cta_texte="OUVRIR LA LISTE DE RÉVISION",
        cta_url=lien_portail
    )

def email_livraison(nom, nom_projet, lien_projet, lien_drive=None, ressources=None, lien_site=None, logos=None, note=None):
    drive_section = ""
    if lien_drive:
        drive_section = f'<p style="margin:0 0 15px 0;text-align:center;"><a href="{lien_drive}" style="color:#e83b14;font-size:14px;text-decoration:none;font-weight:700;font-family:Montserrat,sans-serif;">Accéder au dossier Google Drive →</a></p>'

    site_section = ""
    if lien_site:
        site_section = (
            '<p style="margin:0 0 20px 0;text-align:center;">'
            f'<a href="{lien_site}" target="_blank" '
            'style="display:inline-block;padding:12px 28px;background:#2b2b2b;border-radius:6px;'
            'font-family:\'Bebas Neue\',Impact,sans-serif;font-size:15px;letter-spacing:1.5px;'
            'color:#faf7f3;text-decoration:none;text-transform:uppercase;">'
            'VOIR LE SITE →</a></p>'
        )

    logo_section = ""
    if logos:
        items_html = ''.join(
            f'<li style="margin:0 0 8px 0;"><a href="{l["url"]}" target="_blank" style="color:#e83b14;text-decoration:none;font-weight:700;">{l["filename"]}</a></li>'
            for l in logos if l.get('url')
        )
        if items_html:
            plural = len(logos) > 1
            logo_section = (
                _p(f"Votre <strong>logo vectorisé</strong> {'est prêt' if not plural else 'et ses fichiers sont prêts'} à être utilisé{'s' if plural else ''} partout (impression, web, signature courriel) :") +
                f'<ul style="margin:0 0 15px 0;padding:0 0 0 20px;font-family:Montserrat,sans-serif;font-size:14px;line-height:23px;color:#555;">{items_html}</ul>'
            )

    ressources_section = ""
    if ressources:
        items_html = ''.join(
            f'<li style="margin:0 0 8px 0;"><a href="{r["url"]}" target="_blank" style="color:#e83b14;text-decoration:none;font-weight:700;">{r["titre"]}</a></li>'
            for r in ressources if r.get('url')
        )
        if items_html:
            ressources_section = (
                _p("On vous a aussi préparé quelques ressources utiles pour la suite :") +
                f'<ul style="margin:0 0 15px 0;padding:0 0 0 20px;font-family:Montserrat,sans-serif;font-size:14px;line-height:23px;color:#555;">{items_html}</ul>' +
                f'<p style="margin:0 0 15px 0;text-align:center;"><a href="{PORTAIL_URL}/dashboard" style="color:#e83b14;font-size:14px;text-decoration:none;font-weight:700;font-family:Montserrat,sans-serif;">Voir toutes mes ressources sur le portail →</a></p>'
            )

    return _base(
        titre_hero="Votre projet est terminé !",
        sous_titre_hero="Vos livrables sont prêts.",
        sections=[
            {
                "label": "Livraison",
                "titre": "C'est dans la boîte !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    (_highlight(note) if note else "") +
                    _p("Votre projet est maintenant <strong>terminé</strong> et vos livrables sont prêts :") +
                    _highlight(nom_projet) +
                    site_section +
                    _p("Vous pouvez consulter et télécharger vos fichiers via votre portail ou directement depuis votre dossier Google Drive.") +
                    drive_section +
                    logo_section +
                    ressources_section +
                    _p("Merci de nous avoir fait confiance. Ce fut un plaisir de travailler avec vous !")
                )
            }
        ],
        cta_texte="VOIR MON PROJET",
        cta_url=lien_projet
    )

def email_archive(nom, nom_projet):
    return _base(
        titre_hero="Projet archivé",
        sous_titre_hero="Votre projet est maintenant dans vos archives.",
        sections=[
            {
                "label": "Archives",
                "titre": "Tout est bien rangé.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Votre projet a été archivé et est maintenant disponible dans la section « Projets terminés » de votre profil :") +
                    _highlight(nom_projet) +
                    _p("Vous pouvez y accéder en tout temps depuis votre portail.")
                )
            }
        ],
        cta_texte="VOIR MON PROFIL",
        cta_url=f"{PORTAIL_URL}/profile"
    )

def email_nouvelle_facture(nom, numero=None, description=None, montant=None, date_echeance=None):
    resume_section = ""
    if numero or montant is not None:
        def _row(label, valeur, is_last=False):
            border = "" if is_last else "border-bottom:1px solid #f0ede9;"
            return (
                f'<tr><td style="padding:10px 0;{border}font-family:Montserrat,sans-serif;font-size:13px;color:#888;">{label}</td>'
                f'<td style="padding:10px 0;{border}font-family:Montserrat,sans-serif;font-size:13px;color:#2b2b2b;font-weight:700;text-align:right;">{valeur}</td></tr>'
            )
        rows = ""
        if numero:
            rows += _row("Numéro", numero)
        if description:
            rows += _row("Description", description)
        if montant is not None:
            rows += _row("Montant total", f"{montant:.2f} $")
        if date_echeance:
            rows += _row("Échéance", date_echeance, is_last=True)
        resume_section = (
            f'<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" '
            f'style="margin:0 0 20px 0;background:#faf7f3;border-radius:8px;padding:4px 18px;">{rows}</table>'
        )

    return _base(
        titre_hero="Nouvelle facture disponible",
        sous_titre_hero="Une nouvelle facture est disponible dans votre portail.",
        sections=[
            {
                "label": "Facturation",
                "titre": "Votre facture vous attend.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Une nouvelle facture est disponible — vous la trouverez en pièce jointe (PDF) à ce courriel, ou dans votre portail client.") +
                    resume_section
                )
            }
        ],
        cta_texte="VOIR MES FACTURES",
        cta_url=f"{PORTAIL_URL}/profile"
    )
def _base_confirm(nom, confirm_url):
    return _base(
        titre_hero="Confirmez votre compte",
        sous_titre_hero="Une dernière étape avant d'accéder à votre portail.",
        sections=[
            {
                "label": "Activation du compte",
                "titre": f"Bonjour {nom} !",
                "contenu": (
                    _p("Merci de vous être inscrit sur le portail client de Cocktail Média.") +
                    _p("Cliquez sur le bouton ci-dessous pour activer votre compte. Ce lien est valide pendant <strong>1 heure</strong>.") +
                    _p("Si vous n'avez pas créé de compte, ignorez simplement ce courriel.")
                )
            }
        ],
        cta_texte="CONFIRMER MON COMPTE",
        cta_url=confirm_url
    )
def email_documents_recus(nom, nom_projet, lien_projet):
    return _base(
        titre_hero="Documents bien reçus !",
        sous_titre_hero="Nous avons tout ce qu'il nous faut.",
        sections=[
            {
                "label": "Confirmation",
                "titre": "Vos documents sont entre nos mains.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Bonne nouvelle — nous avons bien reçu tous vos documents pour le projet :") +
                    _highlight(nom_projet) +
                    _p("Notre équipe va maintenant analyser vos fichiers et démarrer les travaux sous peu. Nous vous tiendrons informé de l'avancement.")
                )
            }
        ],
        cta_texte="VOIR MON PROJET",
        cta_url=lien_projet
    )
def email_travaux_en_cours_avec_date(nom, nom_projet, lien_projet, date_livraison_str, facture_numero=None, facture_total=None, facture_echeance=None):
    bloc_facture = ""
    if facture_numero and facture_total:
        bloc_facture = (
            f'<div style="margin:28px 0 0 0;border:1px solid #e0d9d3;border-radius:8px;overflow:hidden;">'
            f'<div style="background:#e83b14;padding:12px 20px;">'
            f'<p style="margin:0;font-family:\'Bebas Neue\',Impact,sans-serif;font-size:18px;color:#ffffff;letter-spacing:2px;">FACTURE {facture_numero}</p>'
            f'</div>'
            f'<div style="padding:16px 20px;background:#fff4e9;">'
            f'<table width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr>'
            f'<td style="font-family:Montserrat,sans-serif;font-size:12px;color:#666;padding:4px 0;">Montant total (taxes incluses)</td>'
            f'<td align="right" style="font-family:\'Bebas Neue\',Impact,sans-serif;font-size:20px;color:#2b2b2b;letter-spacing:1px;">{facture_total:,.2f} $CA</td>'
            f'</tr>'
            f'<tr>'
            f'<td style="font-family:Montserrat,sans-serif;font-size:12px;color:#666;padding:4px 0;">Échéance</td>'
            f'<td align="right" style="font-family:Montserrat,sans-serif;font-size:12px;color:#2b2b2b;font-weight:600;">{facture_echeance}</td>'
            f'</tr>'
            f'</table>'
            f'<p style="margin:12px 0 0 0;font-family:Montserrat,sans-serif;font-size:11px;color:#888;">La facture complète est jointe à cet email en format PDF.</p>'
            f'<p style="margin:6px 0 0 0;font-family:Montserrat,sans-serif;font-size:11px;color:#888;">Virement Interac : marie-christine.blanchette@cocktailmedia.ca</p>'
            f'</div>'
            f'</div>'
        )
    return _base(
        titre_hero="Les travaux sont en cours !",
        sous_titre_hero="On s'y met — voici votre date de livraison estimée.",
        sections=[
            {
                "label": "Mise à jour de votre projet",
                "titre": "C'est parti !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Bonne nouvelle — nous avons tout ce qu'il nous faut et les travaux sont maintenant en cours sur votre projet :") +
                    _highlight(nom_projet) +
                    f'<div style="text-align:center;margin:24px 0;">'
                    f'<p style="margin:0 0 6px 0;font-family:Montserrat,sans-serif;font-size:11px;color:#e83b14;text-transform:uppercase;letter-spacing:2px;font-weight:600;">Date de livraison estimée</p>'
                    f'<p style="margin:0;font-family:\'Bebas Neue\',Impact,sans-serif;font-size:32px;color:#2b2b2b;letter-spacing:2px;">{date_livraison_str}</p>'
                    f'</div>' +
                    _p("Vous serez avisé dès que vos livrables seront prêts. Vous pouvez suivre l'avancement en tout temps sur votre portail.") +
                    bloc_facture
                )
            }
        ],
        cta_texte="VOIR L'AVANCEMENT",
        cta_url=lien_projet
    )
def email_annulation(nom, nom_projet):
    return _base(
        titre_hero="Projet annulé",
        sous_titre_hero="Votre projet a été annulé.",
        sections=[
            {
                "label": "Annulation",
                "titre": "Nous vous informons d'une annulation.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Nous vous informons que le projet suivant a été annulé :") +
                    _highlight(nom_projet) +
                    _p("Si vous avez des questions, n'hésitez pas à nous contacter directement.")
                )
            }
        ],
        cta_texte="ACCÉDER AU PORTAIL",
        cta_url=PORTAIL_URL
    )

def _invitation_client(nom: str, lien: str) -> str:
    return _base(
        titre_hero="Bienvenue chez Cocktail Média !",
        sous_titre_hero="Votre espace client a été créé. Plus qu'une étape !",
        sections=[
            {
                "label": "Activation de votre compte",
                "titre": f"Bonjour {nom}, créez votre accès !",
                "contenu": (
                    _p("Votre accès au <strong>Portail Client Cocktail Média</strong> a été créé par notre équipe.") +
                    _p("Cliquez sur le bouton ci-dessous pour choisir votre mot de passe et accéder à vos projets, documents et factures.") +
                    _p("<strong>Ce lien est valide 7 jours.</strong> Si vous n'attendiez pas cet email, vous pouvez l'ignorer.")
                )
            }
        ],
        cta_texte="CRÉER MON MOT DE PASSE",
        cta_url=lien
    )
def email_nouveau_post_marketing(titre, date_publication, plateformes, description):
    plateformes_str = ', '.join(plateformes) if isinstance(plateformes, list) else plateformes
    return _base(
        titre_hero="Nouveau post planifié",
        sous_titre_hero="Un nouveau post a été planifié dans le calendrier marketing.",
        sections=[
            {
                "label": "📅 Calendrier marketing",
                "titre": "Voici les détails du post.",
                "contenu": (
                    f'<table style="width:100%;border-collapse:collapse;margin:0 0 15px 0;">'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:140px;">Titre</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{titre}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Date</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{date_publication}</td></tr>'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Plateformes</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{plateformes_str}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Description</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{description or "—"}</td></tr>'
                    f'</table>' +
                    _p("Connecte-toi au portail pour déposer les visuels.")
                )
            }
        ],
        cta_texte="ACCÉDER AU PORTAIL",
        cta_url=PORTAIL_URL
    )

def email_corrections_appliquees(nom, lien_site):
    return _base(
        titre_hero="Vos corrections sont en ligne !",
        sous_titre_hero="Voici ce qui a été ajusté sur votre site.",
        sections=[
            {
                "label": "Révision — Site web",
                "titre": "C'est fait !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Merci pour vos commentaires — voici les corrections apportées à votre site :") +
                    (
                        '<ul style="margin:0 0 15px 0;padding:0 0 0 20px;font-family:Montserrat,sans-serif;font-size:14px;line-height:24px;color:#555;">'
                        "<li style=\"margin:0 0 6px 0;\">Votre nom et votre titre (« une éducatrice spécialisée qui reste présente ») sont maintenant bien séparés dans l'en-tête</li>"
                        '<li style="margin:0 0 6px 0;">Le mot « interventions » a été remplacé par « outils »</li>'
                        '<li style="margin:0 0 6px 0;">La page Contact ne parle plus de « projet » — « Discutons ensemble »</li>'
                        '<li style="margin:0 0 6px 0;">« Soumission » a été remplacé par « appel découverte » partout sur le site</li>'
                        "<li style=\"margin:0 0 6px 0;\">On en a profité pour revoir le reste du site (page « Mon parcours », section services) afin que tout soit écrit à la première personne, en cohérence avec votre pratique</li>"
                        '</ul>'
                    ) +
                    _p("Pour le logo, on attend simplement la confirmation de votre lien Canva pour pouvoir l'ajuster directement sur le site — ce sera fait dès qu'on l'aura.")
                )
            }
        ],
        cta_texte="VOIR MON SITE",
        cta_url=lien_site
    )

def email_mon_site_disponible(nom, nom_entreprise=None):
    intro_entreprise = f" de <strong>{nom_entreprise}</strong>" if nom_entreprise else ""
    return _base(
        titre_hero="Modifiez votre site dès maintenant",
        sous_titre_hero="Une nouvelle section \"Mon site\" est disponible sur votre portail.",
        sections=[
            {
                "label": "Nouveauté — Portail Client",
                "titre": "Votre site, entre vos mains",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p(f"Vous pouvez maintenant modifier le contenu de votre site web{intro_entreprise} vous-même, directement depuis votre portail — sans nous écrire, sans attendre.") +
                    _highlight("Nouvelle section : Mon site") +
                    _p("Depuis cette section, vous pouvez mettre à jour :") +
                    (
                        '<ul style="margin:0 0 15px 0;padding:0 0 0 20px;font-family:Montserrat,sans-serif;font-size:14px;line-height:24px;color:#555;">'
                        '<li style="margin:0 0 6px 0;">Les textes de vos pages (accueil, à propos, contact…)</li>'
                        '<li style="margin:0 0 6px 0;">Vos services : descriptions, tarifs, formules et photos</li>'
                        '<li style="margin:0 0 6px 0;">Vos coordonnées et réseaux sociaux</li>'
                        '</ul>'
                    ) +
                    _p("Chaque modification est enregistrée immédiatement et mise à jour sur votre site en direct. Connectez-vous à votre portail et cliquez sur <strong>Mon site</strong> dans le menu pour commencer.")
                )
            }
        ],
        cta_texte="MODIFIER MON SITE",
        cta_url=f"{PORTAIL_URL}/mon-site"
    )

def email_identite_visuelle_prete(nom, nom_projet, lien_identite):
    return _base(
        titre_hero="Votre identité visuelle est prête !",
        sous_titre_hero="Consultez et téléchargez vos livrables finaux.",
        sections=[
            {
                "label": "Révision finale",
                "titre": "À vous de jouer !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Bonne nouvelle — votre identité visuelle est maintenant complète et prête pour révision :") +
                    _highlight(nom_projet) +
                    _p("Connectez-vous à votre portail pour consulter vos logos, palettes de couleurs, typographies et tous vos fichiers finaux. Vous pouvez tout télécharger depuis la page de votre identité visuelle.")
                )
            }
        ],
        cta_texte="VOIR MON IDENTITÉ VISUELLE",
        cta_url=lien_identite
    )

def email_reset_password(nom, reset_url):
    return _base(
        titre_hero="Réinitialisation de votre mot de passe",
        sous_titre_hero="Vous avez demandé un nouveau mot de passe pour votre compte.",
        sections=[
            {
                "label": "Sécurité du compte",
                "titre": f"Bonjour {nom} !",
                "contenu": (
                    _p("Nous avons reçu une demande de réinitialisation de mot de passe pour votre compte sur le Portail Client Cocktail Média.") +
                    _p("Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe. Ce lien est valide pendant <strong>1 heure</strong>.") +
                    _p("Si vous n'avez pas fait cette demande, ignorez simplement ce courriel. Votre mot de passe restera inchangé.")
                )
            }
        ],
        cta_texte="RÉINITIALISER MON MOT DE PASSE",
        cta_url=reset_url
    )

def email_nouveau_client(nom, email, nom_entreprise, lien_admin):
    return _base(
        titre_hero="Nouveau client inscrit",
        sous_titre_hero="Un client vient de confirmer son compte sur le portail.",
        sections=[
            {
                "label": "Nouveau compte confirmé",
                "titre": "Un nouveau client est prêt.",
                "contenu": (
                    _p("Un client vient de confirmer son adresse email et peut maintenant se connecter au portail.") +
                    f'<table style="width:100%;border-collapse:collapse;margin:0 0 15px 0;">'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:140px;">Nom</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{nom}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Email</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{email}</td></tr>'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Entreprise</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{nom_entreprise or "—"}</td></tr>'
                    f'</table>'
                )
            }
        ],
        cta_texte="VOIR LE NOUVEAU CLIENT",
        cta_url=lien_admin
    )

def email_soumission_disponible(nom, titre, lien_portail):
    return _base(
        titre_hero="Une soumission vous attend",
        sous_titre_hero="Consultez votre soumission confidentielle dans votre portail.",
        sections=[
            {
                "label": "Soumission",
                "titre": "Votre soumission est prête.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Une nouvelle soumission vient d'être préparée pour vous :") +
                    _highlight(titre) +
                    _p("Connectez-vous à votre portail pour consulter les options, comparer les prix et accepter la formule qui vous convient.")
                )
            }
        ],
        cta_texte="VOIR MA SOUMISSION",
        cta_url=lien_portail
    )


def email_soumission_acceptee_admin(nom_client, email_client, titre_soumission,
                                    nom_option, prix_setup, prix_mensuel,
                                    date_acceptation, lien_admin, extras_selectionnes=None):
    tps_setup = round(prix_setup * 0.05, 2)
    tvq_setup = round(prix_setup * 0.09975, 2)
    total_setup = round(prix_setup + tps_setup + tvq_setup, 2)
    tps_mensuel = round(prix_mensuel * 0.05, 2)
    tvq_mensuel = round(prix_mensuel * 0.09975, 2)
    total_mensuel = round(prix_mensuel + tps_mensuel + tvq_mensuel, 2)

    lignes_setup = (
        f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:180px;">Prix setup (avant taxes)</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{prix_setup:.2f} $</td></tr>'
        f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">TPS (5 %)</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{tps_setup:.2f} $</td></tr>'
        f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">TVQ (9,975 %)</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{tvq_setup:.2f} $</td></tr>'
        f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;font-weight:700;">Total setup</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:15px;color:#e83b14;font-weight:700;">{total_setup:.2f} $</td></tr>'
    )
    lignes_mensuel = (
        f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:180px;">Prix mensuel (avant taxes)</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{prix_mensuel:.2f} $</td></tr>'
        f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">TPS + TVQ</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{round(tps_mensuel+tvq_mensuel,2):.2f} $</td></tr>'
        f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;font-weight:700;">Total mensuel</td>'
        f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:15px;color:#e83b14;font-weight:700;">{total_mensuel:.2f} $</td></tr>'
    ) if prix_mensuel > 0 else ''

    return _base(
        titre_hero="Soumission acceptee",
        sous_titre_hero=f"{nom_client} a accepte une soumission.",
        sections=[
            {
                "label": "Details de l'acceptation",
                "titre": f"Option choisie : {nom_option}",
                "contenu": (
                    f'<table style="width:100%;border-collapse:collapse;margin:0 0 15px 0;">'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:180px;">Client</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{nom_client}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Email</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{email_client}</td></tr>'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Soumission</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{titre_soumission}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Option acceptee</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:700;">{nom_option}</td></tr>'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Date d\'acceptation</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;">{date_acceptation}</td></tr>'
                    f'</table>'
                    f'<table style="width:100%;border-collapse:collapse;margin:0 0 15px 0;">'
                    + lignes_setup + lignes_mensuel +
                    f'</table>'
                    + (
                        f'<p style="font-family:Montserrat,sans-serif;font-size:12px;font-weight:700;color:#e83b14;margin:18px 0 8px;text-transform:uppercase;letter-spacing:0.08em;">Extras sélectionnés par le client</p>'
                        f'<table style="width:100%;border-collapse:collapse;">'
                        + ''.join(
                            f'<tr style="background:{"#faf7f3" if i%2==0 else "#fff"};">'
                            f'<td style="padding:8px 14px;font-family:Montserrat,sans-serif;font-size:13px;color:#2b2b2b;">{e.get("situation","")}</td>'
                            f'<td style="padding:8px 14px;font-family:Montserrat,sans-serif;font-size:13px;color:#2b2b2b;font-weight:600;white-space:nowrap;">{e.get("cout","")}</td>'
                            f'</tr>'
                            for i, e in enumerate(extras_selectionnes)
                        )
                        + f'</table>'
                        if extras_selectionnes else ''
                    )
                )
            }
        ],
        cta_texte="VOIR LA SOUMISSION",
        cta_url=lien_admin
    )


def email_rendez_vous_confirme(nom: str, label: str, meet_link: str, google_url: str, outlook_url: str, ics_url: str) -> str:
    """Email de confirmation de rendez-vous avec boutons 'Ajouter à l'agenda'."""
    return _base(
        titre_hero="Rendez-vous confirmé",
        sous_titre_hero="Votre créneau est réservé.",
        sections=[{
            "label": "Votre rendez-vous",
            "titre": f"Bonjour {nom},",
            "contenu": (
                _p("Un rendez-vous a été planifié avec vous :") +
                f'<p style="margin:0 0 20px 0;padding:14px 18px;background:#faf7f3;border-left:4px solid #e83b14;'
                f'border-radius:0 6px 6px 0;font-family:\'Bebas Neue\',Impact,sans-serif;font-size:20px;'
                f'letter-spacing:1px;color:#2b2b2b;">{label}</p>' +
                _add_to_calendar_html(google_url, outlook_url, ics_url) +
                (f'<p style="margin:20px 0 0;font-family:Montserrat,sans-serif;font-size:13px;color:#555;">'
                 f'Rejoignez la réunion : <a href="{meet_link}" style="color:#e83b14;font-weight:700;">{meet_link}</a></p>'
                 if meet_link else '')
            )
        }],
        cta_texte="REJOINDRE LA RÉUNION" if meet_link else "ACCÉDER À MON PORTAIL",
        cta_url=meet_link or PORTAIL_URL
    )


def email_agenda_rendez_vous(nom, slots, booking_url=None, nom_service=None):
    """
    slots       = liste de dicts {'label': 'Lundi 9 juin à 9h00', 'url': 'https://...'}
    booking_url = lien vers le calendrier complet (optionnel)
    nom_service = si fourni, personnalise le texte pour la réservation d'une séance précise
    """
    boutons_html = ""
    for slot in slots:
        boutons_html += f"""
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom:10px;">
          <tr><td>
            <a href="{slot['url']}" target="_blank"
               style="display:block;padding:14px 24px;background-color:#faf7f3;border:2px solid #e83b14;border-radius:8px;
                      font-family:'Bebas Neue',Impact,sans-serif;font-size:16px;letter-spacing:1px;color:#2b2b2b;
                      text-decoration:none;text-transform:uppercase;text-align:center;">
              {slot['label']} &nbsp;→
            </a>
          </td></tr>
        </table>"""

    voir_calendrier = ""
    if booking_url:
        voir_calendrier = (
            f'<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top:18px;">'
            f'<tr><td align="center">'
            f'<a href="{booking_url}" target="_blank" '
            f'style="font-family:Montserrat,sans-serif;font-size:12px;color:#e83b14;font-weight:700;'
            f'text-decoration:underline;text-underline-offset:3px;">'
            f'Voir toutes les disponibilités →</a>'
            f'</td></tr></table>'
        )

    if nom_service:
        titre_hero = f"Réservez votre séance « {nom_service} »"
        sous_titre_hero = "Choisissez le créneau qui vous convient."
        intro = _p(f"Voici les prochains créneaux disponibles pour réserver votre séance « {nom_service} » — cliquez sur celui qui vous convient pour le confirmer.")
        note = _p('<span style="font-size:11px;color:#888;">Votre confirmation créera automatiquement votre projet et un événement dans notre agenda. On vous demandera l\'adresse de la séance à l\'étape suivante.</span>')
    else:
        titre_hero = "Planifiez votre rendez-vous"
        sous_titre_hero = "Choisissez un créneau qui vous convient."
        intro = _p("Nous aimerions échanger avec vous ! Voici les prochains créneaux disponibles dans notre agenda — cliquez sur celui qui vous convient pour confirmer instantanément.")
        note = _p('<span style="font-size:11px;color:#888;">Votre confirmation crée automatiquement un événement dans votre calendrier.</span>')

    return _base(
        titre_hero=titre_hero,
        sous_titre_hero=sous_titre_hero,
        sections=[
            {
                "label": "Rendez-vous",
                "titre": f"Bonjour {nom},",
                "contenu": (
                    intro +
                    boutons_html +
                    voir_calendrier +
                    note
                )
            }
        ]
    )


def email_visuel_depose(titre, date_publication, plateformes, nb_fichiers):
    plateformes_str = ', '.join(plateformes) if isinstance(plateformes, list) else plateformes
    return _base(
        titre_hero="Visuel(s) déposé(s)",
        sous_titre_hero="Les visuels pour ce post sont prêts !",
        sections=[
            {
                "label": "🎨 Calendrier marketing",
                "titre": "Les visuels sont prêts.",
                "contenu": (
                    f'<table style="width:100%;border-collapse:collapse;margin:0 0 15px 0;">'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;width:140px;">Post</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{titre}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Date prévue</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{date_publication}</td></tr>'
                    f'<tr><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Plateformes</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{plateformes_str}</td></tr>'
                    f'<tr style="background:#faf7f3;"><td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:12px;color:#888;">Fichiers déposés</td>'
                    f'<td style="padding:10px 14px;font-family:Montserrat,sans-serif;font-size:14px;color:#2b2b2b;font-weight:600;">{nb_fichiers} visuel(s)</td></tr>'
                    f'</table>' +
                    _p("Connecte-toi au portail pour les consulter et télécharger.")
                )
            }
        ],
        cta_texte="ACCÉDER AU PORTAIL",
        cta_url=PORTAIL_URL
    )
