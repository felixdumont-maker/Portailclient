# =========================================================
# COCKTAIL MÉDIA — PORTAIL CLIENT
# drive_service.py — Intégration Google Drive API
# Service Account
# =========================================================

import io
import json as _json
import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseUpload, MediaIoBaseDownload

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = os.path.join(os.path.dirname(__file__), 'service_account.json')


def get_drive_service():
    """Crée et retourne un service Google Drive authentifié via Service Account."""
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=SCOPES
    )
    return build('drive', 'v3', credentials=creds)


def create_folder(name, parent_id=None):
    """Crée un dossier Drive ou réutilise un existant du même nom."""
    service = get_drive_service()
    SHARED_DRIVE_ID = os.getenv('GOOGLE_DRIVE_ROOT_FOLDER_ID')
    
    # Cherche si un dossier avec ce nom existe déjà dans le parent
    # Échapper \ et ' — sinon un nom contenant une apostrophe (ex: "Création d'un logo")
    # casse la syntaxe de la requête Drive ("Invalid Value")
    safe_name = name.replace('\\', '\\\\').replace("'", "\\'")
    query = f"name='{safe_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    
    results = service.files().list(q=query, fields='files(id, name)', supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
    files = results.get('files', [])
    
    if files:
        # Dossier existant — on réutilise
        return files[0]['id']
    
    # Nouveau dossier
    metadata = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder',
    }
    if parent_id:
        metadata['parents'] = [parent_id]
    folder = service.files().create(body=metadata, fields='id', supportsAllDrives=True).execute()
    return folder['id']

def upload_file(filepath, filename, folder_id):
    """Upload un fichier dans un dossier Drive et retourne son ID et lien."""
    service = get_drive_service()
    metadata = {
        'name': filename,
        'parents': [folder_id]
    }
    media = MediaFileUpload(filepath, resumable=True)
    file = service.files().create(
        body=metadata,
        media_body=media,
        fields='id, webViewLink',
        supportsAllDrives=True
    ).execute()
    return file['id'], file['webViewLink']


def get_folder_link(folder_id):
    """Retourne le lien web d'un dossier Drive."""
    return f"https://drive.google.com/drive/folders/{folder_id}"
def list_files_in_folder(folder_id):
    """Liste les fichiers dans un dossier Drive."""
    service = get_drive_service()
    results = service.files().list(
        q=f"'{folder_id}' in parents and trashed=false and mimeType!='application/vnd.google-apps.folder'",
        fields="files(id, name, webViewLink, createdTime, size)",
        orderBy="createdTime desc",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True
    ).execute()
    return results.get('files', [])

def make_file_public(file_id, filename=None):
    service = get_drive_service()
    service.permissions().create(
        fileId=file_id,
        supportsAllDrives=True,
        body={"role": "reader", "type": "anyone"}
    ).execute()
    return f"https://drive.google.com/thumbnail?id={file_id}&sz=w1200"
def delete_drive_folder(folder_id):
    """Supprime un dossier Drive et tout son contenu."""
    if not folder_id:
        return
    service = get_drive_service()
    try:
        service.files().delete(fileId=folder_id, supportsAllDrives=True).execute()
    except Exception as e:
        print(f"[DRIVE] Suppression dossier échouée ({folder_id}): {e}")
def list_subfolders(folder_id):
    """Liste les sous-dossiers d'un dossier Drive, excluant 'Dépôt de fichiers'."""
    service = get_drive_service()
    results = service.files().list(
        q=f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false",
        fields="files(id, name)",
        orderBy="name",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True
    ).execute()
    folders = results.get('files', [])
    return [f for f in folders if f['name'] != 'Dépôt de fichiers']
def make_folder_public(folder_id):
    """Rend un dossier Drive accessible à quiconque possède le lien."""
    if not folder_id:
        return
    service = get_drive_service()
    try:
        service.permissions().create(
            fileId=folder_id,
            body={'type': 'anyone', 'role': 'reader'},
            supportsAllDrives=True
        ).execute()
    except Exception as e:
        print(f"[DRIVE] make_folder_public échoué ({folder_id}): {e}")

def get_file_bytes(file_id):
    """Download any Drive file as raw bytes."""
    service = get_drive_service()
    req = service.files().get_media(fileId=file_id, supportsAllDrives=True)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return fh.getvalue()

def get_file_meta(file_id):
    """Return id, name, mimeType, size for a Drive file."""
    return get_drive_service().files().get(
        fileId=file_id,
        fields='id,name,mimeType,size',
        supportsAllDrives=True
    ).execute()

def upload_bytes(folder_id, filename, content: bytes, mimetype: str = 'application/octet-stream'):
    """Upload raw bytes to Drive without a temp file."""
    service = get_drive_service()
    fh = io.BytesIO(content)
    metadata = {'name': filename, 'parents': [folder_id]}
    media = MediaIoBaseUpload(fh, mimetype=mimetype, resumable=False)
    return service.files().create(
        body=metadata,
        media_body=media,
        fields='id, name, createdTime',
        supportsAllDrives=True
    ).execute()

def upload_json_content(folder_id, filename, json_data):
    """Upload JSON data directly to Drive without a temp file."""
    service = get_drive_service()
    content = _json.dumps(json_data, ensure_ascii=False).encode('utf-8')
    fh = io.BytesIO(content)
    metadata = {'name': filename, 'parents': [folder_id], 'mimeType': 'application/json'}
    media = MediaIoBaseUpload(fh, mimetype='application/json', resumable=False)
    return service.files().create(
        body=metadata,
        media_body=media,
        fields='id, name, createdTime, modifiedTime',
        supportsAllDrives=True
    ).execute()

def update_json_content(file_id, json_data):
    """Overwrite a JSON file's content on Drive."""
    service = get_drive_service()
    content = _json.dumps(json_data, ensure_ascii=False).encode('utf-8')
    fh = io.BytesIO(content)
    media = MediaIoBaseUpload(fh, mimetype='application/json', resumable=False)
    return service.files().update(
        fileId=file_id,
        media_body=media,
        fields='id, name, modifiedTime',
        supportsAllDrives=True
    ).execute()

def get_json_content(file_id):
    """Download and parse a JSON file from Drive."""
    service = get_drive_service()
    req = service.files().get_media(fileId=file_id, supportsAllDrives=True)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return _json.loads(fh.getvalue().decode('utf-8'))

def delete_drive_file(file_id):
    """Delete a single file from Drive."""
    get_drive_service().files().delete(fileId=file_id, supportsAllDrives=True).execute()

def share_folder_with_user(folder_id, email, role='reader'):
    """Partage un dossier Drive avec un utilisateur spécifique (idempotent)."""
    if not folder_id or not email:
        return
    service = get_drive_service()
    try:
        service.permissions().create(
            fileId=folder_id,
            supportsAllDrives=True,
            sendNotificationEmail=False,
            body={'type': 'user', 'role': role, 'emailAddress': email}
        ).execute()
    except Exception as e:
        print(f"[DRIVE] share_folder_with_user échoué ({folder_id}, {email}): {e}")
