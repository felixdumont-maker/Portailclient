# =========================================================
# COCKTAIL MÉDIA — PORTAIL CLIENT
# drive_service.py — Intégration Google Drive API
# Service Account
# =========================================================

import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

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
    query = f"name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
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
