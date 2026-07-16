# todoist_service.py
"""
Synchronisation Todoist → Portail (capture one-way + reflet des complétions).

- Lit les tâches actives d'un projet Todoist (API v1) et les insère dans todos_perso.
- Idempotent : chaque tâche est reliée par todoist_task_id (pas de doublon).
- Crée une notification admin (push_admin_notif) sur chaque nouvelle tâche.
- Si une tâche liée disparaît côté Todoist (complétée/supprimée), le todo du portail
  est coché automatiquement pour rester en phase.

Config (.env) :
  TODOIST_API_TOKEN   — clé API (obligatoire)
  TODOIST_PROJECT_ID  — projet à synchroniser ; vide = l'Inbox
"""

import os
import requests

API = "https://api.todoist.com/api/v1"


def _token():
    return os.getenv("TODOIST_API_TOKEN", "").strip()


def _headers():
    return {"Authorization": f"Bearer {_token()}"}


def _get(path, params=None):
    r = requests.get(f"{API}/{path}", headers=_headers(), params=params or {}, timeout=20)
    r.raise_for_status()
    return r.json()


def close_task(task_id):
    """Ferme (complète) une tâche Todoist. Retourne True si OK."""
    if not _token():
        return False
    r = requests.post(f"{API}/tasks/{task_id}/close", headers=_headers(), timeout=15)
    return r.status_code in (200, 204)


def reopen_task(task_id):
    """Rouvre une tâche Todoist complétée. Retourne True si OK."""
    if not _token():
        return False
    r = requests.post(f"{API}/tasks/{task_id}/reopen", headers=_headers(), timeout=15)
    return r.status_code in (200, 204)


def get_inbox_project_id():
    """Retourne l'id du projet Inbox du compte."""
    data = _get("projects")
    for p in data.get("results", data if isinstance(data, list) else []):
        if p.get("inbox_project"):
            return p["id"]
    return None


def get_owner_uid():
    """UID du propriétaire du token (pour distinguer les tâches ajoutées par un collaborateur)."""
    data = _get("projects")
    results = data.get("results", data if isinstance(data, list) else [])
    for p in results:
        if p.get("inbox_project") and p.get("creator_uid"):
            return str(p["creator_uid"])
    return str(results[0]["creator_uid"]) if results else None


def get_active_tasks(project_id):
    """Toutes les tâches actives d'un projet (paginé)."""
    tasks, cursor = [], None
    while True:
        params = {"project_id": project_id}
        if cursor:
            params["cursor"] = cursor
        data = _get("tasks", params)
        tasks += data.get("results", [])
        cursor = data.get("next_cursor")
        if not cursor:
            break
    return tasks


def _priorite(p):
    # Todoist : priority 4 = urgent (p1 UI) … 1 = normal (p4 UI)
    return "haute" if (p or 1) >= 3 else "normale"


def _due_date(t):
    due = t.get("due") or {}
    d = due.get("date")
    return d[:10] if d else None


def sync(conn):
    """Synchronise Todoist → todos_perso. Retourne un résumé dict.
       `conn` = connexion sqlite (autocommit) du portail."""
    if not _token():
        return {"skipped": "no_token"}

    project_id = os.getenv("TODOIST_PROJECT_ID", "").strip() or get_inbox_project_id()
    if not project_id:
        return {"error": "no_project"}

    owner_uid = None
    try:
        owner_uid = get_owner_uid()
    except Exception:
        pass

    tasks = get_active_tasks(project_id)
    seen = []
    nouvelles = 0

    for t in tasks:
        if t.get("is_deleted") or t.get("checked"):
            continue
        tid = str(t["id"])
        seen.append(tid)
        contenu = (t.get("content") or "").strip()
        prio = _priorite(t.get("priority"))
        date_ech = _due_date(t)

        # INSERT OR IGNORE : anti-doublon garanti par l'index unique (idx_todos_todoist).
        # rowcount==1 → tâche réellement nouvelle ; 0 → déjà présente (autre worker ou passe précédente).
        cur = conn.execute(
            "INSERT OR IGNORE INTO todos_perso (texte, priorite, date_echeance, source, todoist_task_id) "
            "VALUES (?, ?, ?, 'todoist', ?)",
            (contenu, prio, date_ech, tid),
        )
        if cur.rowcount == 1:
            nouvelles += 1
            # Notification : distinguer si ajoutée par un collaborateur (ex. Marie)
            added_by = str(t.get("added_by_uid") or "")
            de_collab = owner_uid and added_by and added_by != owner_uid
            titre = "Nouvelle tâche de ton équipe" if de_collab else "Nouvelle tâche Todoist"
            ntype = "assignation" if de_collab else "todoist"
            try:
                conn.execute(
                    "INSERT INTO admin_notifications (destinataire, type, titre, message, lien) "
                    "VALUES (NULL, ?, ?, ?, '/admin')",
                    (ntype, titre, contenu),
                )
            except Exception as e:
                print(f"[TODOIST] notif échouée: {e}")
        else:
            # déjà connue : maj contenu/prio/échéance tant que non cochée côté portail
            conn.execute(
                "UPDATE todos_perso SET texte=?, priorite=?, date_echeance=? "
                "WHERE todoist_task_id=? AND est_coche=0",
                (contenu, prio, date_ech, tid),
            )

    # Reflet des complétions : todos todoist encore ouverts mais absents du flux Todoist → cochés.
    # get_active_tasks lève en cas d'erreur API, donc seen vide = réellement aucune tâche active.
    if seen:
        placeholders = ",".join("?" * len(seen))
        cur = conn.execute(
            f"UPDATE todos_perso SET est_coche=1 "
            f"WHERE source='todoist' AND est_coche=0 AND todoist_task_id NOT IN ({placeholders})",
            seen,
        )
    else:
        cur = conn.execute(
            "UPDATE todos_perso SET est_coche=1 WHERE source='todoist' AND est_coche=0"
        )
    fermes = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    return {"synced": len(tasks), "nouvelles": nouvelles, "fermes": fermes, "project_id": project_id}
