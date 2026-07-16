# calendar_service.py — Google Calendar API avec impersonation
import os
import json
import uuid
from datetime import datetime, timedelta, date
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import timezone, timedelta as td

# Offset Toronto UTC-4 (EDT) — ajuster à UTC-5 en hiver
TORONTO_OFFSET = td(hours=4)

MOIS_FR = {
    1: 'janvier', 2: 'février', 3: 'mars', 4: 'avril',
    5: 'mai', 6: 'juin', 7: 'juillet', 8: 'août',
    9: 'septembre', 10: 'octobre', 11: 'novembre', 12: 'décembre'
}

JOURS_FR = {0: 'Lundi', 1: 'Mardi', 2: 'Mercredi', 3: 'Jeudi', 4: 'Vendredi'}

# Créneaux proposés pour les réunions (Toronto local) — heure et demi-heure
HEURES_REUNION = [
    9.0, 9.5, 10.0, 10.5, 11.0, 11.5,
    12.0, 12.5, 13.0, 13.5, 14.0, 14.5,
    15.0, 15.5, 16.0, 16.5, 17.0
]

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

def _build_event_description(taches: list | None) -> str:
    if not taches:
        return 'Bloc de production réservé automatiquement par le Portail Client Cocktail Média.'
    lignes = ['📋 Tâches à compléter :\n']
    for t in taches:
        lignes.append(f'☐ {t}')
    lignes.append('\n— Portail Client Cocktail Média')
    return '\n'.join(lignes)

def create_production_event(nom_projet, icon_service, duree_minutes, delai_fixe_heures=0, taches=None):
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
            'description': _build_event_description(taches),
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
def create_meet_event(nom_projet: str, date_str: str, heure_str: str) -> str:
    """Crée un événement Google Calendar avec lien Meet et retourne le hangoutLink."""
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    tz = ZoneInfo("America/Toronto")
    dt_start = datetime.strptime(f"{date_str} {heure_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    dt_end = dt_start + timedelta(hours=1)

    service = get_calendar_service()
    event = {
        "summary": f"Appel — {nom_projet}",
        "start": {"dateTime": dt_start.isoformat(), "timeZone": "America/Toronto"},
        "end":   {"dateTime": dt_end.isoformat(),   "timeZone": "America/Toronto"},
        "conferenceData": {
            "createRequest": {
                "requestId": f"meet-{nom_projet[:20]}-{date_str}",
                "conferenceSolutionKey": {"type": "hangoutsMeet"}
            }
        }
    }
    result = service.events().insert(
        calendarId="felix.dumont@cocktailmedia.ca",
        body=event,
        conferenceDataVersion=1
    ).execute()
    return result.get("hangoutLink", "")
def create_seance_event(nom_projet: str, date_str: str, heure_str: str, duree_minutes: int, localisation: str, client_email: str) -> str:
    """Crée un événement de séance dans l'agenda avec le client comme invité."""
    from zoneinfo import ZoneInfo
    tz = ZoneInfo("America/Toronto")
    dt_start = datetime.strptime(f"{date_str} {heure_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    dt_end = dt_start + timedelta(minutes=duree_minutes)

    service = get_calendar_service()
    event = {
        "summary": f"📷 Séance — {nom_projet}",
        "location": localisation or "",
        "start": {"dateTime": dt_start.isoformat(), "timeZone": "America/Toronto"},
        "end":   {"dateTime": dt_end.isoformat(),   "timeZone": "America/Toronto"},
        "attendees": [{"email": client_email}],
        "sendUpdates": "all",
        "colorId": "5",
    }
    result = service.events().insert(
        calendarId=CALENDAR_ID,
        body=event,
        sendUpdates="all"
    ).execute()
    return result.get("id", "")

def create_todo_reminder(titre: str, date_echeance: str) -> str:
    """Crée un rappel journée entière dans l'agenda de Félix pour un todo à échéance."""
    try:
        service = get_calendar_service()
        event = {
            'summary': f'⏰ Rappel — {titre}',
            'description': 'Tâche à compléter — Portail Cocktail Média',
            'start': {'date': date_echeance},
            'end': {'date': date_echeance},
            'colorId': '11',
            'reminders': {'useDefault': False, 'overrides': [{'method': 'popup', 'minutes': 480}]},
        }
        result = service.events().insert(calendarId=CALENDAR_ID, body=event).execute()
        return result.get('id', '')
    except Exception as e:
        print(f"[CALENDAR] Rappel todo échoué: {e}")
        return ''

def create_task_block(titre: str, date_str: str, heure_str: str, duree_minutes: int, priorite: str = 'normale') -> str:
    """Crée un bloc de travail dans l'agenda avec heure de début et durée."""
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("America/Toronto")
        dt_start = datetime.strptime(f"{date_str} {heure_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
        dt_end = dt_start + timedelta(minutes=duree_minutes)
        color_map = {'haute': '11', 'normale': '7', 'basse': '8'}  # Rouge, Teal, Gris
        emoji_map = {'haute': '🔴', 'normale': '🟠', 'basse': '⚪'}
        service = get_calendar_service()
        event = {
            'summary': f"{emoji_map.get(priorite, '🟠')} {titre}",
            'description': f'Bloc de travail — {duree_minutes} min\nCréé depuis le Portail Cocktail Média',
            'start': {'dateTime': dt_start.isoformat(), 'timeZone': 'America/Toronto'},
            'end':   {'dateTime': dt_end.isoformat(),   'timeZone': 'America/Toronto'},
            'colorId': color_map.get(priorite, '7'),
            'reminders': {'useDefault': False, 'overrides': [{'method': 'popup', 'minutes': 10}]},
        }
        result = service.events().insert(calendarId=CALENDAR_ID, body=event).execute()
        return result.get('id', '')
    except Exception as e:
        print(f"[CALENDAR] Bloc tâche échoué: {e}")
        return ''

def format_slot_fr(slot_debut_utc: datetime) -> str:
    """Convertit un créneau UTC en label français lisible (ex: Lundi 9 juin à 9h30)."""
    from zoneinfo import ZoneInfo
    from datetime import timezone as _tz
    tz = ZoneInfo("America/Toronto")
    local = slot_debut_utc.replace(tzinfo=_tz.utc).astimezone(tz)
    minutes = f"{local.minute:02d}" if local.minute else "00"
    return f"{JOURS_FR[local.weekday()]} {local.day} {MOIS_FR[local.month]} à {local.hour}h{minutes}"


def get_available_meeting_slots(n: int = 4, duree_minutes: int = 60) -> list:
    """Retourne n créneaux libres, UN par jour ouvrable (lun-ven, 9h-17h Toronto)."""
    duree = timedelta(minutes=duree_minutes)
    aujourd_hui = date.today()
    slots = []

    for delta in range(1, 30):
        if len(slots) >= n:
            break
        jour = aujourd_hui + timedelta(days=delta)
        if jour.weekday() >= 5:
            continue

        debut_fenetre = datetime(jour.year, jour.month, jour.day, 8, 0) + TORONTO_OFFSET
        fin_fenetre   = datetime(jour.year, jour.month, jour.day, 18, 0) + TORONTO_OFFSET
        busy = get_busy_slots(debut_fenetre, fin_fenetre)

        # Cherche le premier créneau libre ce jour-là
        for heure in HEURES_REUNION:
            slot_debut = datetime(jour.year, jour.month, jour.day, heure, 0) + TORONTO_OFFSET
            slot_fin   = slot_debut + duree
            conflit = any(
                slot_debut < datetime.fromisoformat(b['end'].replace('Z', '')) and
                slot_fin   > datetime.fromisoformat(b['start'].replace('Z', ''))
                for b in busy
            )
            if not conflit:
                slots.append((slot_debut, slot_fin))
                break  # un seul créneau par jour

    return slots


def create_meeting_event(start_utc: datetime, end_utc: datetime, client_nom: str, client_email: str) -> tuple:
    """Crée un événement de réunion avec Meet et le client en invité. Retourne (event_id, meet_link)."""
    from zoneinfo import ZoneInfo
    from datetime import timezone as _tz
    tz = ZoneInfo("America/Toronto")
    utc = _tz.utc
    local_start = start_utc.replace(tzinfo=utc).astimezone(tz)
    local_end   = end_utc.replace(tzinfo=utc).astimezone(tz)

    service = get_calendar_service()
    event = {
        "summary": f"Réunion — {client_nom}",
        "start": {"dateTime": local_start.isoformat(), "timeZone": "America/Toronto"},
        "end":   {"dateTime": local_end.isoformat(),   "timeZone": "America/Toronto"},
        "attendees": [{"email": client_email}],
        "sendUpdates": "all",
        "colorId": "7",
        "conferenceData": {
            "createRequest": {
                "requestId": f"meet-{client_nom[:12].replace(' ','-')}-{start_utc.strftime('%Y%m%d%H%M')}",
                "conferenceSolutionKey": {"type": "hangoutsMeet"},
            }
        },
    }
    result = service.events().insert(
        calendarId=CALENDAR_ID, body=event,
        sendUpdates="all", conferenceDataVersion=1
    ).execute()
    meet_link = result.get("hangoutLink") or result.get("conferenceData", {}).get("entryPoints", [{}])[0].get("uri", "")
    return result.get("id", ""), meet_link


def delete_calendar_event(event_id: str) -> None:
    """Supprime un événement de l'agenda."""
    try:
        service = get_calendar_service()
        service.events().delete(calendarId=CALENDAR_ID, eventId=event_id).execute()
    except Exception as e:
        print(f"[CALENDAR] Suppression événement échouée: {e}")


def get_event_datetime(event_id: str):
    """Lit un événement et retourne (date 'YYYY-MM-DD', heure 'HH:MM') en heure Toronto.
       Retourne 'deleted' si l'événement n'existe plus, ou None en cas d'erreur."""
    from zoneinfo import ZoneInfo
    from googleapiclient.errors import HttpError
    try:
        service = get_calendar_service()
        ev = service.events().get(calendarId=CALENDAR_ID, eventId=event_id).execute()
        if ev.get('status') == 'cancelled':
            return 'deleted'
        start = ev.get('start', {})
        dt_raw = start.get('dateTime') or start.get('date')
        if not dt_raw:
            return None
        if 'T' in dt_raw:
            dt = datetime.fromisoformat(dt_raw).astimezone(ZoneInfo("America/Toronto"))
            return (dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M"))
        return (dt_raw[:10], None)  # événement journée entière
    except HttpError as e:
        if getattr(e, 'resp', None) is not None and e.resp.status in (404, 410):
            return 'deleted'
        print(f"[CALENDAR] get_event_datetime échoué: {e}")
        return None
    except Exception as e:
        print(f"[CALENDAR] get_event_datetime erreur: {e}")
        return None


# ── Push notifications (watch) ───────────────────────────────────────────────

WATCH_STATE_FILE = os.path.join(os.path.dirname(__file__), 'webhook_state.json')


def load_watch_state() -> dict:
    try:
        with open(WATCH_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_watch_state(state: dict) -> None:
    with open(WATCH_STATE_FILE, 'w') as f:
        json.dump(state, f)


def register_calendar_watch(webhook_url: str) -> dict:
    """Enregistre un push notification watch. Retourne l'état sauvegardé."""
    service = get_calendar_service()

    # Paginer jusqu'au nextSyncToken sans traiter les events existants
    result = service.events().list(calendarId=CALENDAR_ID, maxResults=250).execute()
    while 'nextPageToken' in result:
        result = service.events().list(
            calendarId=CALENDAR_ID,
            pageToken=result['nextPageToken'],
            maxResults=250,
        ).execute()
    sync_token = result.get('nextSyncToken', '')

    channel_id = str(uuid.uuid4())
    watch = service.events().watch(
        calendarId=CALENDAR_ID,
        body={'id': channel_id, 'type': 'web_hook', 'address': webhook_url},
    ).execute()

    state = {
        'channel_id': channel_id,
        'resource_id': watch.get('resourceId', ''),
        'expiration_ms': int(watch.get('expiration', 0)),
        'sync_token': sync_token,
    }
    save_watch_state(state)
    return state


def stop_calendar_watch(channel_id: str, resource_id: str) -> None:
    try:
        service = get_calendar_service()
        service.channels().stop(
            body={'id': channel_id, 'resourceId': resource_id}
        ).execute()
    except Exception as e:
        print(f"[CALENDAR] Stop watch échoué: {e}")


def list_changed_events(sync_token: str | None = None) -> tuple[list, str]:
    """Retourne (events, new_sync_token). Resync depuis 2h si token expiré."""
    service = get_calendar_service()
    try:
        if not sync_token:
            raise ValueError("no token")
        result = service.events().list(
            calendarId=CALENDAR_ID,
            syncToken=sync_token,
            showDeleted=True,
        ).execute()
    except (HttpError, ValueError):
        updated_min = (datetime.utcnow() - timedelta(hours=2)).isoformat() + 'Z'
        result = service.events().list(
            calendarId=CALENDAR_ID,
            updatedMin=updated_min,
            showDeleted=True,
            maxResults=50,
        ).execute()

    events = result.get('items', [])
    new_token = result.get('nextSyncToken', sync_token or '')
    return events, new_token
