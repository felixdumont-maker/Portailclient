"""
Seed: insere un template de soumission de base avec 3 options.
Idempotent: ne fait rien si un template du meme nom existe deja.
Usage: python3 seed_soumission_template.py
"""
import os
import json
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "/data/instance/portail.db")

TEMPLATE_NOM = "Site web standard"

TEMPLATE = {
    "nom": TEMPLATE_NOM,
    "description": "Template de base pour les projets de site web",
    "message_intro_template": "Bonjour {nom_complet},\n\nVoici votre soumission personnalisee pour {nom_entreprise}. Vous trouverez ci-dessous les options disponibles pour votre projet.",
    "titre_template": "Soumission - {nom_entreprise}",
    "est_actif": 1,
}

OPTIONS = [
    {
        "nom": "Essentiel",
        "description": "Site vitrine simple et efficace, ideal pour etablir votre presence en ligne.",
        "prix_setup": 1500.0,
        "prix_mensuel": 75.0,
        "prix_horaire": 0.0,
        "delai_livraison": "3 a 4 semaines",
        "conditions_paiement": "50% a la signature, 50% a la livraison",
        "badge_texte": None,
        "est_recommande": 0,
        "ordre": 1,
        "features_json": json.dumps({
            "pages": "Jusqu'a 5 pages",
            "formulaire": "Formulaire de contact",
            "responsive": "Adapte mobile et tablette",
            "hebergement": "Hebergement inclus 1 an",
        }),
        "inclus_json": json.dumps([
            "Design personnalise",
            "Integration du contenu fourni",
            "Formation de base (1h)",
            "Support technique 30 jours",
        ]),
        "couts_tiers_json": json.dumps([
            {"nom": "Nom de domaine", "montant": 20.0, "periodicite": "annuel"},
        ]),
        "couts_supplementaires_json": json.dumps([]),
        "scenarios_json": json.dumps([]),
        "rachat_disponible": 0,
        "prix_rachat": 0.0,
        "inclus_rachat_json": json.dumps([]),
    },
    {
        "nom": "Professionnel",
        "description": "Site complet avec fonctionnalites avancees et optimisation SEO.",
        "prix_setup": 3200.0,
        "prix_mensuel": 120.0,
        "prix_horaire": 0.0,
        "delai_livraison": "5 a 7 semaines",
        "conditions_paiement": "50% a la signature, 50% a la livraison",
        "badge_texte": "Populaire",
        "est_recommande": 1,
        "ordre": 2,
        "features_json": json.dumps({
            "pages": "Jusqu'a 12 pages",
            "formulaire": "Formulaires avances + integration CRM",
            "responsive": "Adapte mobile et tablette",
            "hebergement": "Hebergement inclus 1 an",
            "seo": "Optimisation SEO de base",
            "analytics": "Google Analytics",
        }),
        "inclus_json": json.dumps([
            "Design sur mesure",
            "Integration du contenu fourni",
            "Optimisation SEO on-page",
            "Formation complete (2h)",
            "Support technique 60 jours",
            "Rapport de performance initial",
        ]),
        "couts_tiers_json": json.dumps([
            {"nom": "Nom de domaine", "montant": 20.0, "periodicite": "annuel"},
            {"nom": "Google Workspace", "montant": 12.0, "periodicite": "mensuel"},
        ]),
        "couts_supplementaires_json": json.dumps([
            {"nom": "Photos professionnelles", "montant": 500.0, "note": "Si requises"},
        ]),
        "scenarios_json": json.dumps([
            {
                "titre": "Scenario de base",
                "description": "Lancement avec le contenu existant",
                "prix_total": 3200.0,
            },
            {
                "titre": "Avec redaction de contenu",
                "description": "Inclut la redaction professionnelle de toutes les pages",
                "prix_total": 4700.0,
            },
        ]),
        "rachat_disponible": 1,
        "prix_rachat": 1800.0,
        "inclus_rachat_json": json.dumps([
            "Transfert complet des fichiers sources",
            "Documentation technique",
            "Session de formation avancee (3h)",
        ]),
    },
    {
        "nom": "Premium",
        "description": "Solution complete avec e-commerce, integrations et support prioritaire.",
        "prix_setup": 6500.0,
        "prix_mensuel": 200.0,
        "prix_horaire": 0.0,
        "delai_livraison": "8 a 12 semaines",
        "conditions_paiement": "33% a la signature, 33% mi-parcours, 33% a la livraison",
        "badge_texte": "Tout inclus",
        "est_recommande": 0,
        "ordre": 3,
        "features_json": json.dumps({
            "pages": "Pages illimitees",
            "formulaire": "Formulaires avances + CRM + automatisations",
            "responsive": "Adapte mobile et tablette",
            "hebergement": "Hebergement premium inclus 1 an",
            "seo": "Strategie SEO complete",
            "analytics": "Google Analytics + heatmaps",
            "ecommerce": "Boutique en ligne",
            "integrations": "CRM, facturation, calendrier",
        }),
        "inclus_json": json.dumps([
            "Design sur mesure haut de gamme",
            "Boutique en ligne complete",
            "Integrations tierces (CRM, paiement)",
            "Redaction de 5 pages cles",
            "Strategie SEO et rapport mensuel",
            "Formation equipe (4h)",
            "Support prioritaire 90 jours",
            "Maintenance mensuelle incluse",
        ]),
        "couts_tiers_json": json.dumps([
            {"nom": "Nom de domaine", "montant": 20.0, "periodicite": "annuel"},
            {"nom": "Stripe (frais de transaction)", "montant": 2.9, "periodicite": "par transaction (%)"},
            {"nom": "Google Workspace Business", "montant": 18.0, "periodicite": "mensuel"},
        ]),
        "couts_supplementaires_json": json.dumps([
            {"nom": "Photos professionnelles", "montant": 800.0, "note": "Selon volume"},
            {"nom": "Redaction additionnelle", "montant": 120.0, "note": "Par page"},
        ]),
        "scenarios_json": json.dumps([
            {
                "titre": "Lancement standard",
                "description": "Boutique avec catalogue de base",
                "prix_total": 6500.0,
            },
            {
                "titre": "Lancement avec migration",
                "description": "Inclut la migration depuis un systeme existant",
                "prix_total": 8200.0,
            },
            {
                "titre": "Pack complet avec marketing",
                "description": "Boutique + strategie de lancement + campagne initiale",
                "prix_total": 10500.0,
            },
        ]),
        "rachat_disponible": 1,
        "prix_rachat": 3500.0,
        "inclus_rachat_json": json.dumps([
            "Transfert complet des fichiers sources",
            "Documentation technique complete",
            "Formation equipe etendue (6h)",
            "Acces a tous les comptes et integrations",
        ]),
    },
]


def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    existing = conn.execute(
        "SELECT id FROM soumission_templates WHERE nom = ?", (TEMPLATE_NOM,)
    ).fetchone()

    if existing:
        print(f"Template '{TEMPLATE_NOM}' existe deja (id={existing['id']}). Rien a faire.")
        conn.close()
        return

    cur = conn.execute(
        """
        INSERT INTO soumission_templates
            (nom, description, message_intro_template, titre_template, est_actif)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            TEMPLATE["nom"],
            TEMPLATE["description"],
            TEMPLATE["message_intro_template"],
            TEMPLATE["titre_template"],
            TEMPLATE["est_actif"],
        ),
    )
    id_template = cur.lastrowid

    for opt in OPTIONS:
        conn.execute(
            """
            INSERT INTO soumission_template_options
                (id_template, nom, description, prix_setup, prix_mensuel, prix_horaire,
                 delai_livraison, conditions_paiement, badge_texte, est_recommande, ordre,
                 features_json, inclus_json, couts_tiers_json, couts_supplementaires_json,
                 scenarios_json, rachat_disponible, prix_rachat, inclus_rachat_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                id_template,
                opt["nom"],
                opt["description"],
                opt["prix_setup"],
                opt["prix_mensuel"],
                opt["prix_horaire"],
                opt["delai_livraison"],
                opt["conditions_paiement"],
                opt["badge_texte"],
                opt["est_recommande"],
                opt["ordre"],
                opt["features_json"],
                opt["inclus_json"],
                opt["couts_tiers_json"],
                opt["couts_supplementaires_json"],
                opt["scenarios_json"],
                opt["rachat_disponible"],
                opt["prix_rachat"],
                opt["inclus_rachat_json"],
            ),
        )

    conn.commit()
    conn.close()
    print(f"Template '{TEMPLATE_NOM}' insere (id={id_template}) avec {len(OPTIONS)} options.")


if __name__ == "__main__":
    seed()
