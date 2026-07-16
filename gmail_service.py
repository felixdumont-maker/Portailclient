# gmail_service.py — lecture Gmail (scope gmail.readonly) pour l'ingestion de factures.
# Auth par jeton OAuth utilisateur (refresh_token stocké dans la table integrations),
# distinct du compte de service Drive. Réutilise GOOGLE_CLIENT_ID/SECRET du portail.
import os
import base64
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_URI = 'https://oauth2.googleapis.com/token'

def build_gmail(refresh_token):
    """Construit un client Gmail autorisé à partir d'un refresh_token."""
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        scopes=GMAIL_SCOPES,
    )
    return build('gmail', 'v1', credentials=creds, cache_discovery=False)

def profil_email(service):
    """Adresse de la boîte connectée (pour exclure ses propres envois)."""
    try:
        return (service.users().getProfile(userId='me').execute() or {}).get('emailAddress', '')
    except Exception:
        return ''

def trouver_label_id(service, nom):
    """ID du libellé Gmail par nom (ex. 'Factures'), ou None."""
    labels = (service.users().labels().list(userId='me').execute() or {}).get('labels', [])
    for l in labels:
        if (l.get('name') or '').lower() == nom.lower():
            return l.get('id')
    return None

def lister_messages(service, label_id, apres_epoch=None, maximum=25):
    """IDs des messages portant le libellé, dans la boîte de réception (jamais Envoyés),
    optionnellement après un timestamp epoch. Les plus récents d'abord."""
    q = 'in:inbox'
    if apres_epoch:
        q += f' after:{int(apres_epoch)}'
    ids, page = [], None
    while True:
        resp = service.users().messages().list(
            userId='me', labelIds=[label_id], q=q, maxResults=min(maximum, 100), pageToken=page
        ).execute() or {}
        ids += [m['id'] for m in resp.get('messages', [])]
        page = resp.get('nextPageToken')
        if not page or len(ids) >= maximum:
            break
    return ids[:maximum]

def _walk_parts(part, out):
    if not part:
        return
    filename = part.get('filename') or ''
    body = part.get('body') or {}
    mime = (part.get('mimeType') or '').lower()
    if filename and (mime == 'application/pdf' or mime.startswith('image/')):
        out.append({'filename': filename, 'mime': mime, 'attachmentId': body.get('attachmentId')})
    for sub in (part.get('parts') or []):
        _walk_parts(sub, out)

def lire_message(service, msg_id):
    """Retourne {expediteur, date, sujet, pieces:[{filename,mime,data(base64)}...]}.
    Ne renvoie que les pièces PDF/image (candidates factures)."""
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = {h['name'].lower(): h['value'] for h in (msg.get('payload', {}).get('headers') or [])}
    metas = []
    _walk_parts(msg.get('payload'), metas)
    pieces = []
    for m in metas:
        if not m['attachmentId']:
            continue
        att = service.users().messages().attachments().get(
            userId='me', messageId=msg_id, id=m['attachmentId']
        ).execute()
        data_b64std = base64.b64encode(base64.urlsafe_b64decode(att['data'])).decode('ascii')
        pieces.append({'filename': m['filename'], 'mime': m['mime'], 'data': data_b64std})
    return {
        'expediteur': headers.get('from', ''),
        'date': headers.get('date', ''),
        'sujet': headers.get('subject', ''),
        'pieces': pieces,
    }
