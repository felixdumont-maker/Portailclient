# date_parser_fr.py
"""
Parseur de dates/heures en langage naturel français pour le quick-add des tâches.
Extrait une date + heure d'un texte et retourne le texte nettoyé.

Exemples gérés :
  "appeler comptable demain 14h"        -> ("appeler comptable", "2026-07-03", "14:00")
  "envoyer devis vendredi"              -> ("envoyer devis", "<prochain vendredi>", None)
  "payer facture le 15"                 -> ("payer facture", "<15 du mois>", None)
  "relancer client dans 3 jours à 9h30" -> ("relancer client", "<+3j>", "09:30")
  "réunion 2026-08-01 10h"              -> ("réunion", "2026-08-01", "10:00")

Objectif : fiabilité. En cas de doute, on ne parse PAS (mieux vaut pas de date qu'une mauvaise).
"""

import re
from datetime import date, datetime, timedelta

_JOURS = {
    'lundi': 0, 'mardi': 1, 'mercredi': 2, 'jeudi': 3,
    'vendredi': 4, 'samedi': 5, 'dimanche': 6,
}
_MOIS = {
    'janvier': 1, 'février': 2, 'fevrier': 2, 'mars': 3, 'avril': 4, 'mai': 5,
    'juin': 6, 'juillet': 7, 'août': 8, 'aout': 8, 'septembre': 9,
    'octobre': 10, 'novembre': 11, 'décembre': 12, 'decembre': 12,
}


def _prochain_jour(base: date, cible_wd: int) -> date:
    delta = (cible_wd - base.weekday()) % 7
    delta = delta or 7  # "vendredi" = le prochain, pas aujourd'hui
    return base + timedelta(days=delta)


def parse_todo(texte: str, today: date | None = None):
    """Retourne (texte_nettoyé, date_str|None, heure_str|None)."""
    today = today or date.today()
    original = texte
    d = None   # objet date
    h = None   # 'HH:MM'
    consumed = []  # spans (start, end) à retirer du texte

    low = texte.lower()

    # ── HEURE : "14h", "14h30", "9 h", "à 14h", "14:00" ──
    m = re.search(r'\b(?:à\s*)?(\d{1,2})\s*[h:]\s*(\d{2})?\b', low)
    if m:
        hh = int(m.group(1)); mm = int(m.group(2)) if m.group(2) else 0
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            h = f"{hh:02d}:{mm:02d}"
            consumed.append(m.span())

    # ── DATE ISO explicite : 2026-08-01 ──
    m = re.search(r'\b(\d{4})-(\d{2})-(\d{2})\b', low)
    if m and d is None:
        try:
            d = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            consumed.append(m.span())
        except ValueError:
            pass

    # ── "aujourd'hui" / "demain" / "après-demain" ──
    if d is None:
        for mot, delta in [("après-demain", 2), ("apres-demain", 2), ("aujourd'hui", 0),
                           ("aujourdhui", 0), ("demain", 1)]:
            idx = low.find(mot)
            if idx != -1:
                d = today + timedelta(days=delta)
                consumed.append((idx, idx + len(mot)))
                break

    # ── "dans N jours/semaines" ──
    if d is None:
        m = re.search(r'\bdans\s+(\d{1,3})\s+(jours?|semaines?)\b', low)
        if m:
            n = int(m.group(1))
            d = today + timedelta(days=n * (7 if 'sem' in m.group(2) else 1))
            consumed.append(m.span())

    # ── "la semaine prochaine" (= lundi prochain) ──
    if d is None:
        m = re.search(r'\b(la\s+)?semaine\s+prochaine\b', low)
        if m:
            d = _prochain_jour(today, 0)
            consumed.append(m.span())

    # ── jour de semaine : "vendredi", "lundi prochain" ──
    if d is None:
        for jour, wd in _JOURS.items():
            m = re.search(r'\b' + jour + r'(\s+prochain)?\b', low)
            if m:
                d = _prochain_jour(today, wd)
                consumed.append(m.span())
                break

    # ── "3 juillet" / "3 juillet 2026" / "le 3 juillet" ──
    if d is None:
        m = re.search(r'\b(\d{1,2})\s+(' + '|'.join(_MOIS.keys()) + r')(?:\s+(\d{4}))?\b', low)
        if m:
            jour = int(m.group(1)); mois = _MOIS[m.group(2)]
            annee = int(m.group(3)) if m.group(3) else today.year
            try:
                d = date(annee, mois, jour)
                if not m.group(3) and d < today:   # sans année, on vise le futur
                    d = date(annee + 1, mois, jour)
                consumed.append(m.span())
            except ValueError:
                pass

    # ── "le 15" (jour du mois courant/prochain) ──
    if d is None:
        m = re.search(r'\ble\s+(\d{1,2})\b', low)
        if m:
            jour = int(m.group(1))
            try:
                cand = today.replace(day=jour)
                if cand < today:
                    # mois suivant
                    if today.month == 12:
                        cand = date(today.year + 1, 1, jour)
                    else:
                        cand = date(today.year, today.month + 1, jour)
                d = cand
                consumed.append(m.span())
            except ValueError:
                pass

    # ── Nettoyage du texte : on retire les fragments consommés ──
    if consumed:
        # retire de la fin vers le début pour préserver les index
        chars = list(original)
        for start, end in sorted(consumed, key=lambda s: -s[0]):
            del chars[start:end]
        texte_net = ''.join(chars)
    else:
        texte_net = original

    # retire mots de liaison orphelins + espaces multiples
    texte_net = re.sub(r'\b(à|le|dans|pour)\s*$', '', texte_net.strip(), flags=re.IGNORECASE)
    texte_net = re.sub(r'\s{2,}', ' ', texte_net).strip(' ,-')

    date_str = d.strftime("%Y-%m-%d") if d else None
    return (texte_net or original.strip(), date_str, h)
