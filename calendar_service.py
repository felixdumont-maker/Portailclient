# calendar_service.py — Google Calendar API avec impersonation
import os
from datetime import datetime, timedelta, date
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import timezone, timedelta as td

# Offset Toronto UTC-4 (EDT) — ajuster à UTC-5 en hiver
TORONTO_OFFSET = td(hours=4)

MOIS_FR = {
    1: 'janvier', 2: 'février', 3: 'mars', 4: 'avril',
    5: 'mai', 6: 'juin', 7: 'juillet', 8: 'août',
    9: 'septembre', 10: 'octobre', 11: 'novembre', 12: 'décembre'
}

def format_date_fr(d):
    """Formate une date en français : 08 avril 2026"""
    return f"{d.day:02d} {MOIS_FR[d.month]} {d.year}"

SERVICE_ACCOUNT_FILE = os.path.join(os.path.dirname(__file__), 'service_account.json')
CALENDAR_ID = 'felix.dumont@cocktailmedia.ca'
IMPERSONATE_EMAIL = 'felix.dumont@cocktailmedia.ca'
SCOPES = ['https://www.googleapis.com/auth/calendar']

# Jours de production par catégorie (0=lundi, 1=mardi, 2=mercredi, 3=jeudi, 4=vendredi)
JOURS_PRODUCTION = {
    'graphisme': [0],        # lundi
    'photo':     [1, 3],     # mardi, jeudi
    'video':     [1, 3],     # mardi, jeudi
    'immobilier':[1, 2, 3],  # mardi, mercredi, jeudi (48h fixe)
    'web':       [2],        # mercredi
    'info':      [0],        # lundi (flex comme graphisme)
    'default':   [4],        # vendredi (flex)
}

def get_calendar_service():
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=SCOPES
    )
    # Impersonation — agit au nom de felix.dumont@cocktailmedia.ca
    delegated = creds.with_subject(IMPERSONATE_EMAIL)
    return build('calendar', 'v3', credentials=delegated)

def get_busy_slots(start_dt, end_dt):
    """Retourne les plages occupées dans l'agenda entre start et end."""
    service = get_calendar_service()
    body = {
        "timeMin": start_dt.isoformat() + 'Z',
        "timeMax": end_dt.isoformat() + 'Z',
        "items": [{"id": CALENDAR_ID}]
    }
    result = service.freebusy().query(body=body).execute()
    busy = result.get('calendars', {}).get(CALENDAR_ID, {}).get('busy', [])
    return busy

def find_next_available_slot(icon_service, duree_minutes, delai_fixe_heures=0):
    if delai_fixe_heures > 0:
        # Service à délai fixe (ex: immobilier 48h)
        # Pas de booking de plage — juste calcul de la date de livraison
        maintenant = datetime.utcnow()
        livraison = maintenant + timedelta(hours=delai_fixe_heures)
        # Ajuste si tombe un weekend
        while livraison.weekday() >= 5:
            livraison += timedelta(days=1)
        return None, None, livraison.date()

    jours_valides = JOURS_PRODUCTION.get(icon_service, JOURS_PRODUCTION['default'])
    duree = timedelta(minutes=duree_minutes)

    aujourd_hui = date.today()
    for delta in range(1, 31):
        jour_candidat = aujourd_hui + timedelta(days=delta)
        if jour_candidat.weekday() not in jours_valides:
            continue
        if jour_candidat.weekday() >= 5:
            continue

        # 8h00 Toronto = 12h00 UTC (EDT, UTC-4)
        debut_journee = datetime(jour_candidat.year, jour_candidat.month, jour_candidat.day, 8, 0) + TORONTO_OFFSET
        fin_journee = datetime(jour_candidat.year, jour_candidat.month, jour_candidat.day, 17, 0) + TORONTO_OFFSET

        busy = get_busy_slots(debut_journee, fin_journee)

        slot_debut = debut_journee
        while slot_debut + duree <= fin_journee:
            slot_fin = slot_debut + duree
            conflit = False
            for b in busy:
                b_start = datetime.fromisoformat(b['start'].replace('Z', ''))
                b_end = datetime.fromisoformat(b['end'].replace('Z', ''))
                if slot_debut < b_end and slot_fin > b_start:
                    conflit = True
                    slot_debut = b_end
                    break
            if not conflit:
                livraison = jour_candidat + timedelta(days=1)
                while livraison.weekday() >= 5:
                    livraison += timedelta(days=1)
                return slot_debut, slot_fin, livraison

    return None, None, None

def create_production_event(nom_projet, icon_service, duree_minutes, delai_fixe_heures=0):
    try:
        debut, fin, date_livraison = find_next_available_slot(
            icon_service, duree_minutes, delai_fixe_heures
        )

        if delai_fixe_heures > 0:
            # Immobilier — pas de bloc agenda, juste retourner la date
            return None, date_livraison

        if not debut:
            return None, None

        service = get_calendar_service()
        event = {
            'summary': f'🎬 Production — {nom_projet}',
            'description': f'Bloc de production réservé automatiquement par le Portail Client Cocktail Média.',
            'start': {
                'dateTime': debut.isoformat() + 'Z',
                'timeZone': 'UTC',
            },
            'end': {
                'dateTime': fin.isoformat() + 'Z',
                'timeZone': 'UTC',
            },

            'colorId': '11',
        }
        created = service.events().insert(calendarId=CALENDAR_ID, body=event).execute()
        return created['id'], date_livraison
    except Exception as e:
        print(f"[CALENDAR] Création événement échouée: {e}")
        return None, None
def delete_production_event(event_id):
    """Supprime un événement de production."""
    try:
        service = get_calendar_service()
        service.events().delete(calendarId=CALENDAR_ID, eventId=event_id).execute()
    except Exception as e:
        print(f"[CALENDAR] Suppression événement échouée: {e}")
