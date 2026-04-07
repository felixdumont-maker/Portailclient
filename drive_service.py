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

def make_file_public(file_id):
    """Rend un fichier Drive public et retourne son URL directe pour affichage."""
    service = get_drive_service()
    service.permissions().create(
        fileId=file_id,
        body={'type': 'anyone', 'role': 'reader'},
        supportsAllDrives=True
    ).execute()
    # URL directe pour affichage image (pas webViewLink)
    return f"https://lh3.googleusercontent.com/d/{file_id}"

def delete_drive_folder(folder_id):
    """Supprime un dossier Drive et tout son contenu."""
    if not folder_id:
        return
    service = get_drive_service()
    try:
        service.files().delete(fileId=folder_id, supportsAllDrives=True).execute()
    except Exception as e:
        print(f"[DRIVE] Suppression dossier échouée ({folder_id}): {e}")
