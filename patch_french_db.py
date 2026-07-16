"""Correction des fautes de français et anglicismes dans les options de soumissions."""
import sqlite3, os, json

DB = os.environ.get('DB_PATH', '/data/instance/portail.db')
conn = sqlite3.connect(DB)
cur = conn.cursor()

# ─── Données corrigées par option (nom = clé de ciblage) ──────────────────────

CORRECTIONS = {
    'ESSENTIEL': {
        'description': (
            'Solution rapide et autonome. Idéale pour valider votre marché '
            'et lancer rapidement sans dépendance technique.'
        ),
        'conditions_paiement': (
            '100% à mi-mandat (livraison du site et des formations configurées)'
        ),
        'inclus_json': json.dumps([
            'Site web transactionnel Wix professionnel',
            'Plateforme formations en ligne Wix Learn (10 formations)',
            'Prise de rendez-vous Wix Booking',
            'Paiements intégrés Wix Payments',
            'Courriels automatiques (bienvenue, confirmation, rappels)',
            'Gestion clients CRM Wix de base',
            'Design et image de marque complets',
            'Contenu 4-5 pages',
            'Version mobile adaptée',
            'SEO de base',
            'Formation de 2h pour vous rendre autonome',
            'Documentation PDF remise à la livraison',
        ], ensure_ascii=False),
        'couts_tiers_json': json.dumps([
            {'service': 'Wix Business (Learn + Booking + Payments inclus)', 'cout': '~50$/mois', 'note': 'Géré par vous directement'},
            {'service': 'Domaine', 'cout': '~15$/an', 'note': 'Une fois par an'},
        ], ensure_ascii=False),
        'couts_supplementaires_json': json.dumps([
            {'situation': 'Révision supplémentaire après 2 rondes incluses', 'cout': '50$/h + tx'},
            {'situation': 'Contenu non fourni, rédaction par Cocktail Média', 'cout': '50$/h + tx'},
            {'situation': 'Photos non fournies, achat de photos libres de droits', 'cout': '15-50$/image'},
            {'situation': 'Retard client de plus de 2 semaines', 'cout': '50$/h reprise + tx'},
            {'situation': 'Projet mis en pause plus de 30 jours', 'cout': '250$ reprise + tx'},
            {'situation': 'Formation supplémentaire', 'cout': '50$/h + tx'},
            {'situation': 'Mise à niveau Wix si besoin de plus de stockage', 'cout': '~80$/mois'},
        ], ensure_ascii=False),
    },

    'PROFESSIONNEL': {
        'description': (
            'La solution équilibrée. Un site professionnel sur mesure combiné à '
            'une plateforme de gestion complète à votre image.'
        ),
        'conditions_paiement': (
            '100% à mi-mandat (site en ligne et portail fonctionnel)'
        ),
        'inclus_json': json.dumps([
            'Site vitrine professionnel Next.js déployé sur Vercel',
            'Portail à votre image (votre logo, vos couleurs, votre domaine)',
            'Module formations complet (vidéos, PDF, formulaires)',
            'Quiz choix multiples avec score automatique',
            'Résultats de quiz envoyés par courriel',
            'Certification automatique conditionnelle au score minimal',
            'Assignation des formations à vos clients',
            'Suivi de progression par client',
            'Courriels automatiques (bienvenue, rappels, complétion, certification)',
            'Facturation intégrée avec lien de paiement Stripe',
            'Gestion clients CRM complète',
            'Lecteur vidéo personnalisé (aucune mention des outils tiers)',
            'Certificats PDF générés automatiquement',
            'Hébergement VPS dédié inclus',
            'Sauvegardes quotidiennes incluses',
            'Support prioritaire, réponse en 24h',
            'Nouveaux modules CocktailOS inclus au fil du temps',
            'Formation de 2h pour vous rendre autonome',
            'Documentation PDF remise à la livraison',
        ], ensure_ascii=False),
        'couts_tiers_json': json.dumps([
            {'service': 'Bunny.net hébergement vidéos', 'cout': '~10$/mois + 0.01$/Go', 'note': 'Vos clients ne voient aucune mention Bunny'},
            {'service': 'Stripe paiements en ligne', 'cout': '2.9% + 0.30$ par transaction', 'note': 'Seulement sur vos ventes'},
            {'service': 'Domaine', 'cout': '~15$/an', 'note': 'Une fois par an'},
            {'service': 'Vercel hébergement site vitrine', 'cout': 'Gratuit', 'note': 'Plan hobby suffit'},
        ], ensure_ascii=False),
        'couts_supplementaires_json': json.dumps([
            {'situation': 'Révision supplémentaire après 2 rondes incluses', 'cout': '50$/h + tx'},
            {'situation': 'Nouvelle fonctionnalité hors périmètre', 'cout': '50$/h + tx'},
            {'situation': 'Contenu non fourni, rédaction par Cocktail Média', 'cout': '50$/h + tx'},
            {'situation': 'Photos non fournies, achat de photos libres de droits', 'cout': '15-50$/image'},
            {'situation': 'Retard client de plus de 2 semaines', 'cout': '50$/h reprise + tx'},
            {'situation': 'Projet mis en pause plus de 30 jours', 'cout': '250$ reprise + tx'},
            {'situation': 'Formation supplémentaire', 'cout': '50$/h + tx'},
            {'situation': 'Mise à niveau VPS si trafic élevé (1000+ utilisateurs)', 'cout': '80-120$/mois'},
            {'situation': 'CDN Cloudflare Pro si besoin en performance', 'cout': '~25$/mois'},
            {'situation': 'Courriels professionnels Google Workspace', 'cout': '~8$/utilisateur/mois'},
            {'situation': 'Sauvegarde supplémentaire hors site', 'cout': '~10$/mois'},
            {'situation': 'Rachat du code source', 'cout': '9 000$ + tx (10 349.25$ TTC)'},
        ], ensure_ascii=False),
    },

    'ENTREPRISE': {
        'description': (
            'La solution sur mesure haut de gamme. Une application propriétaire '
            'développée spécifiquement pour vous, avec intelligence artificielle intégrée. '
            'Le code source vous appartient entièrement.'
        ),
        'conditions_paiement': (
            '0$ au départ / 50% à mi-mandat (6 933$ TTC) / 50% à la livraison finale (6 933$ TTC)'
        ),
        'inclus_json': json.dumps([
            'Site vitrine professionnel Next.js déployé sur Vercel',
            'Application web sur mesure propriétaire à votre image',
            'Gestion 100% autonome de votre plateforme sans aide technique',
            'Gérez vos clients, formations, quiz, certificats et facturation',
            'Module formations complet (vidéos, PDF, formulaires)',
            'Lecteur vidéo personnalisé (aucune mention des outils tiers)',
            'Quiz choix multiples avec score automatique',
            'Résultats de quiz envoyés par courriel',
            'Certification conditionnelle au score minimal',
            'Suivi de progression par client',
            'Courriels automatiques (bienvenue, rappels, complétion, certification)',
            'Facturation intégrée avec paiement Stripe en ligne',
            'Gestion clients CRM complète',
            'Assistant IA disponible 24h/7j pour vos visiteurs',
            'Recommandations de formations personnalisées par IA',
            'Votre propre domaine',
            'Hébergement VPS dédié',
            'Code source propriétaire vous appartenant entièrement',
            'Formation de 2h pour vous rendre autonome',
            'Documentation PDF complète remise à la livraison',
        ], ensure_ascii=False),
        'couts_tiers_json': json.dumps([
            {'service': 'Hébergement VPS dédié', 'cout': '57.47$/mois TTC', 'note': 'Inclus dans le mensuel Cocktail Média'},
            {'service': 'Bunny.net hébergement vidéos', 'cout': '~10$/mois + 0.01$/Go', 'note': 'Vos clients ne voient aucune mention Bunny'},
            {'service': 'Stripe paiements en ligne', 'cout': '2.9% + 0.30$ par transaction', 'note': 'Seulement sur vos ventes'},
            {'service': 'OpenAI assistant IA et recommandations', 'cout': '~20-200$/mois selon volume', 'note': 'Selon utilisation'},
            {'service': 'Domaine', 'cout': '~15$/an', 'note': 'Une fois par an'},
            {'service': 'Vercel hébergement site vitrine', 'cout': 'Gratuit', 'note': 'Plan hobby suffit'},
        ], ensure_ascii=False),
        'couts_supplementaires_json': json.dumps([
            {'situation': 'Révision supplémentaire après 2 rondes incluses', 'cout': '85$/h + tx'},
            {'situation': 'Nouvelle fonctionnalité hors périmètre', 'cout': '85$/h + tx'},
            {'situation': 'Changement de périmètre en cours de mandat', 'cout': '85$/h + tx'},
            {'situation': 'Contenu non fourni, rédaction par Cocktail Média', 'cout': '85$/h + tx'},
            {'situation': 'Photos non fournies, achat de photos libres de droits', 'cout': '15-50$/image'},
            {'situation': 'Retard client de plus de 2 semaines', 'cout': '85$/h reprise + tx'},
            {'situation': 'Projet mis en pause plus de 30 jours', 'cout': '250$ reprise + tx'},
            {'situation': 'Formation supplémentaire ou nouvel employé', 'cout': '50$/h + tx'},
            {'situation': 'Mise à niveau VPS si trafic élevé (1000+ utilisateurs)', 'cout': '80-120$/mois'},
            {'situation': 'CDN Cloudflare Pro si besoin en performance', 'cout': '~25$/mois'},
            {'situation': 'Courriels professionnels Google Workspace', 'cout': '~8$/utilisateur/mois'},
            {'situation': 'Certificat SSL wildcard si sous-domaines multiples', 'cout': '~80$/an'},
            {'situation': 'Migration serveur si nécessaire', 'cout': '200-500$ + tx'},
            {'situation': 'Sauvegarde et restauration urgente', 'cout': '150$ + tx'},
            {'situation': 'Audit de sécurité annuel recommandé', 'cout': '500-1 500$/an'},
            {'situation': 'Conformité LPRPDE, consultation juridique', 'cout': '500-2 000$ (unique)'},
            {'situation': 'Maintenance corrective après livraison', 'cout': '50$/h + tx'},
        ], ensure_ascii=False),
    },
}

fields = ['description', 'conditions_paiement', 'inclus_json', 'couts_tiers_json', 'couts_supplementaires_json']

for table in ('soumission_template_options', 'soumission_options'):
    for nom, data in CORRECTIONS.items():
        set_clause = ', '.join(f'{f} = ?' for f in fields)
        vals = [data[f] for f in fields] + [nom]
        cur.execute(f'UPDATE {table} SET {set_clause} WHERE nom = ?', vals)
        print(f'[{table}] {nom}: {cur.rowcount} ligne(s) mise(s) à jour')

conn.commit()
conn.close()
print('Terminé.')
