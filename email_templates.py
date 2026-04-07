# email_templates.py — Templates HTML emails Cocktail Média
# Style basé sur la newsletter officielle Cocktail Média

LOGO_URL = "https://static.wixstatic.com/media/603d87_ec59249ae1894c9ca598cf76288b5b2b~mv2.png"
PORTAIL_URL = "https://portail.cocktailmedia.ca"

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

def email_livraison(nom, nom_projet, lien_projet, lien_drive=None):
    drive_section = ""
    if lien_drive:
        drive_section = f'<p style="margin:0 0 15px 0;text-align:center;"><a href="{lien_drive}" style="color:#e83b14;font-size:14px;text-decoration:none;font-weight:700;font-family:Montserrat,sans-serif;">Accéder au dossier Google Drive →</a></p>'
    return _base(
        titre_hero="Votre projet est terminé !",
        sous_titre_hero="Vos livrables sont prêts.",
        sections=[
            {
                "label": "Livraison",
                "titre": "C'est dans la boîte !",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Votre projet est maintenant <strong>terminé</strong> et vos livrables sont prêts :") +
                    _highlight(nom_projet) +
                    _p("Vous pouvez consulter et télécharger vos fichiers via votre portail ou directement depuis votre dossier Google Drive.") +
                    drive_section +
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

def email_nouvelle_facture(nom):
    return _base(
        titre_hero="Nouvelle facture disponible",
        sous_titre_hero="Une nouvelle facture est disponible dans votre portail.",
        sections=[
            {
                "label": "Facturation",
                "titre": "Votre facture vous attend.",
                "contenu": (
                    _p(f"Bonjour <strong>{nom}</strong>,") +
                    _p("Une nouvelle facture est disponible dans votre portail client. Vous pouvez la consulter et la télécharger directement depuis votre profil.")
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
