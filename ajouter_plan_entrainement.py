#!/usr/bin/env python3
"""Assigne un plan d'entraînement à un client (seed "en dur").

- Insère un plan dans entrainement_plans (et désactive les anciens du même client).
- Met clients.has_entrainement = 1 pour que la section apparaisse.

Le contenu du plan est défini dans PLAN ci-dessous (transcrit depuis le PDF).
Idempotent au sens "rejouable" : chaque exécution crée une NOUVELLE version active
et désactive les précédentes (historique conservé).

Usage:
    DB_PATH=/mnt/raid1/www/em/prod/data/instance/portail.db \
    python3 ajouter_plan_entrainement.py --email maman@example.com
"""
import argparse
import json
import os
import sqlite3
import sys

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "instance", "portail.db"))

# ──────────────────────────────────────────────────────────────
#  LE PLAN — à remplir depuis le PDF.
#  Structure: jours[] → { jour, focus?, repos?, exercices[] }
#  exercice: { nom, duree?, series?, consigne?, video? }
# ──────────────────────────────────────────────────────────────
TITRE = "Bouger sans se briser"
NOTE = ("Un cadre simple pour rester en forme et garder le moral pendant la guérison, "
        "en respectant la zone touchée. 💛")

# Séance du haut du corps — identique lundi et jeudi.
def _img(slug):
    return [f"/exercices/{slug}/0.jpg", f"/exercices/{slug}/1.jpg"]

def _lot(slug):
    return f"/lottie/{slug}.json"

# Note: pas d'animation illustrée libre pour « élévations latérales » → photo seulement.
_SEANCE_HAUT = [
    {"nom": "Développé couché", "series": "3 × 10-12", "consigne": "Couchée sur le banc, descends la charge lentement.", "images": _img("developpe-couche"), "lottie": _lot("developpe-couche")},
    {"nom": "Rowing assise", "series": "3 × 10-12", "consigne": "Buste un peu penché, tire les coudes vers l'arrière.", "images": _img("rowing-assise"), "lottie": _lot("rowing-assise")},
    {"nom": "Développé épaules", "series": "3 × 10-12", "consigne": "Assise, dos droit, pousse les haltères au-dessus.", "images": _img("developpe-epaules"), "lottie": _lot("developpe-epaules")},
    {"nom": "Élévations latérales", "series": "3 × 12-15", "consigne": "Monte les bras sur les côtés jusqu'aux épaules.", "images": _img("elevations-laterales")},
    {"nom": "Biceps", "series": "3 × 12", "consigne": "Assise, monte les haltères sans balancer le corps.", "images": _img("biceps"), "lottie": _lot("biceps")},
    {"nom": "Triceps", "series": "3 × 12", "consigne": "Haltère derrière la tête, tends le bras vers le haut.", "images": _img("triceps"), "lottie": _lot("triceps")},
    {"nom": "Abdos — en option, avec prudence",
     "consigne": "Gainage statique plus sûr que les crunchs. Si ça tire ou chauffe du côté touché, pendant ou le lendemain, on coupe.",
     "images": _img("gainage"), "lottie": _lot("gainage")},
]

_ETIREMENTS = {"nom": "Étirements doux", "duree": "5 min",
               "consigne": ("Haut du corps et mollets seulement : mollets assise, nuque/épaules, "
                            "ouverture de la poitrine, triceps — 20 à 30 s chacun. "
                            "On ne tire jamais sur la cuisse touchée.")}

PLAN = {
    "principe": ("Tout ce qui se fait sans charger ni tirer sur la cuisse touchée est permis. "
                 "Le haut du corps est ta vraie soupape : tu peux y aller à intensité normale. "
                 "La marche reste ton cardio, validée par le médecin. "
                 "On augmente toujours par la durée, jamais par l'impact."),
    "jours": [
        {
            "jour": "Lundi", "focus": "Séance haut du corps",
            "intro": ("Échauffe-toi 3 à 4 min (cercles de bras, épaules). 3 séries par exercice, "
                      "60 à 90 s de repos. Choisis un poids où les 2-3 dernières répétitions deviennent "
                      "exigeantes, mais propres. Tout se fait assise ou couchée — les jambes ne portent rien."),
            "exercices": _SEANCE_HAUT,
        },
        {
            "jour": "Mardi", "focus": "Marche",
            "intro": ("Semaines 1-2 : 20 à 30 min. Ensuite, si la zone reste stable : "
                      "jusqu'à 40-45 min, fractionnable en deux marches dans la journée."),
            "exercices": [
                {"nom": "Marche", "duree": "20 à 30 min", "consigne": "Rythme confortable, sans boiter."},
                _ETIREMENTS,
            ],
        },
        {
            "jour": "Mercredi", "focus": "Marche ou repos",
            "intro": "Selon comment tu te sens — le repos fait partie du plan.",
            "exercices": [
                {"nom": "Marche ou repos", "consigne": "À ta forme du jour. Aucune pression."},
            ],
        },
        {
            "jour": "Jeudi", "focus": "Séance haut du corps",
            "intro": ("La même séance que lundi — c'est ta séance « pour vrai ». "
                      "Même échauffement, 3 séries, 60 à 90 s de repos."),
            "exercices": _SEANCE_HAUT,
        },
        {
            "jour": "Vendredi", "focus": "Marche",
            "intro": "Marche régulière, fractionnable dans la journée.",
            "exercices": [
                {"nom": "Marche", "duree": "20 à 30 min", "consigne": "Tu peux la fractionner dans la journée."},
                _ETIREMENTS,
            ],
        },
        {
            "jour": "Samedi", "focus": "Marche plus longue",
            "intro": "Ta plus longue de la semaine, pour récupérer du volume de cardio.",
            "exercices": [
                {"nom": "Marche plus longue", "consigne": "Allure tranquille. On progresse par la durée, jamais par l'allure."},
            ],
        },
        {
            "jour": "Dimanche", "focus": "Repos complet", "repos": True,
            "exercices": [],
        },
    ],
    "securite": [
        {
            "titre": "La seule règle non négociable — le test du lendemain matin",
            "texte": ("Au réveil, et après une séance : si la bosse est plus douloureuse, plus grosse ou plus "
                      "chaude, c'est que quelque chose dans la veille était de trop. On retire cet élément, "
                      "sans culpabiliser. Tant que la zone reste stable d'un jour à l'autre, tu es dans ton "
                      "couloir sécuritaire."),
        },
        {
            "titre": "Quand recontacter le médecin",
            "texte": ("Si la masse augmente nettement de volume, devient beaucoup plus douloureuse ou plus "
                      "chaude de façon persistante, ce n'est pas un signal à pousser à travers. On met "
                      "l'entraînement en pause et on fait revérifier la zone. Le plan attendra, il sera encore "
                      "bon après."),
        },
    ],
    "avertissement": "Ce plan n'est pas un avis médical — à valider avec ton médecin.",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True, help="Courriel du compte client")
    ap.add_argument("--dry-run", action="store_true", help="N'écrit rien, affiche seulement")
    args = ap.parse_args()

    if not PLAN["jours"]:
        print("⚠️  PLAN vide — remplis la variable PLAN avec le contenu du PDF avant de lancer.")
        sys.exit(1)

    email = args.email.strip().lower()
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row

    client = conn.execute("SELECT id, nom_complet FROM clients WHERE lower(email) = ?", (email,)).fetchone()
    if not client:
        print(f"❌ Aucun client avec le courriel {email}. Crée d'abord le compte.")
        conn.close()
        sys.exit(1)

    client_id = client["id"]
    contenu_json = json.dumps(PLAN, ensure_ascii=False)
    print(f"Client #{client_id} — {client['nom_complet']} ({email})")
    print(f"Plan: {TITRE} — {len(PLAN['jours'])} jour(s)")

    if args.dry_run:
        print("[dry-run] rien écrit.")
        conn.close()
        return

    # Historise : désactive les anciens plans actifs de ce client
    conn.execute("UPDATE entrainement_plans SET actif = 0 WHERE client_id = ? AND actif = 1", (client_id,))
    conn.execute(
        "INSERT INTO entrainement_plans (client_id, titre, note, contenu_json, actif) VALUES (?, ?, ?, ?, 1)",
        (client_id, TITRE, NOTE, contenu_json),
    )
    conn.execute("UPDATE clients SET has_entrainement = 1 WHERE id = ?", (client_id,))
    new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    print(f"✅ Plan #{new_id} assigné et activé. has_entrainement = 1.")
    print("   (Le lien apparaît au prochain chargement du portail pour cette personne.)")


if __name__ == "__main__":
    main()
