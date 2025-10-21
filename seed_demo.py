import os, sqlite3, datetime

DB = os.environ.get("DB_PATH", "instance/portail.db")
con = sqlite3.connect(DB)
cur = con.cursor()

def table_exists(name):
    cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None

def table_info(name):
    cur.execute(f"PRAGMA table_info({name});")
    # cid, name, type, notnull, dflt_value, pk
    return [dict(cid=r[0], name=r[1], type=(r[2] or "").upper(), notnull=bool(r[3]), dflt=r[4], pk=bool(r[5])) for r in cur.fetchall()]

def pick_column(info, candidates, default=None):
    names = {c["name"] for c in info}
    for key in candidates:
        if key in names:
            return key
    return default

def insert_row(table, values):
    cols = ", ".join(values.keys())
    q = ", ".join(["?"] * len(values))
    cur.execute(f"INSERT INTO {table} ({cols}) VALUES ({q})", tuple(values.values()))
    return cur.lastrowid

# --- 1) client minimal ---
cur.execute("SELECT COUNT(*) FROM clients")
have_clients = cur.fetchone()[0] > 0
if not have_clients:
    cinfo = table_info("clients")
    values = {}
    now = datetime.datetime.utcnow().isoformat() + "Z"
    name_col = pick_column(cinfo, ["nom","name","nom_client","full_name","raison_sociale","company","entreprise"])
    email_col = pick_column(cinfo, ["email","courriel","mail","email_client"])
    created_col = pick_column(cinfo, ["created_at","date_creation"])
    updated_col = pick_column(cinfo, ["updated_at"])

    if name_col: values[name_col] = "Client Test"
    if email_col: values[email_col] = "client.test@example.local"
    if created_col: values[created_col] = now
    if updated_col: values[updated_col] = now

    # satisfaire les NOT NULL sans défaut
    need = {col["name"]: col for col in cinfo}
    for col in cinfo:
        if col["pk"] or col["name"] in values: continue
        if col["notnull"] and col["dflt"] is None:
            t = need[col["name"]]["type"]
            values[col["name"]] = 0 if "INT" in t else (0.0 if "REAL" in t else "N/A")
    client_id = insert_row("clients", values)
else:
    cur.execute("SELECT id FROM clients ORDER BY id DESC LIMIT 1")
    client_id = cur.fetchone()[0]

# --- 2) projet minimal dans 'projets' ---
pinfo = table_info("projets")
pvalues = {}
now = datetime.datetime.utcnow().isoformat() + "Z"

name_col = pick_column(pinfo, ["nom_projet","name","titre"])
statut_txt_col = pick_column(pinfo, ["statut"])
status_code_col = pick_column(pinfo, ["status"])
ratio_col = pick_column(pinfo, ["progress_ratio"])
gdrive_col = pick_column(pinfo, ["lien_gdrive","gdrive","drive"])
client_fk_col = pick_column(pinfo, ["id_client","client_id","idclient"])
created_col = pick_column(pinfo, ["created_at"])
updated_col = pick_column(pinfo, ["updated_at"])

if name_col: pvalues[name_col] = "Projet Test A"
if statut_txt_col: pvalues[statut_txt_col] = "Nouveau"
if status_code_col: pvalues[status_code_col] = "docs_missing"
if ratio_col: pvalues[ratio_col] = 0.0
if gdrive_col: pvalues[gdrive_col] = ""
if client_fk_col: pvalues[client_fk_col] = client_id
if created_col: pvalues[created_col] = now
if updated_col: pvalues[updated_col] = now

# satisfaire NOT NULL
needp = {col["name"]: col for col in pinfo}
for col in pinfo:
    if col["pk"] or col["name"] in pvalues: continue
    if col["notnull"] and col["dflt"] is None:
        t = needp[col["name"]]["type"]
        pvalues[col["name"]] = 0 if "INT" in t else (0.0 if "REAL" in t else ("N/A" if col["name"]!="status" else "docs_missing"))
project_id = insert_row("projets", pvalues)

# --- 3) détecter la table/checklist et ses colonnes ---
check_table = "checklist_items" if table_exists("checklist_items") else ("checklistes" if table_exists("checklistes") else None)
if not check_table:
    raise SystemExit("❌ Aucune table de checklist trouvée (checklist_items / checklistes manquantes).")

chinfo = table_info(check_table)
fk_col = pick_column(chinfo, ["project_id","projet_id","id_projet","projetid","idProjet"])
label_col = pick_column(chinfo, ["label","libelle","nom","nom_item","description","titre"])
req_col = pick_column(chinfo, ["required_file","fichier_requis","obligatoire","fichier_obligatoire","requis"])
pos_col = pick_column(chinfo, ["position","ordre","sort"])
done_col = pick_column(chinfo, ["is_done","done","fait","checked","complete","completed","statut_bool"])

if not fk_col or not label_col:
    raise SystemExit(f"❌ Impossible d'identifier les colonnes FK/label dans {check_table} (trouvé: fk={fk_col}, label={label_col})")

rows = []
def build_row(label, required, pos):
    values = {}
    values[fk_col] = project_id
    values[label_col] = label
    if req_col: values[req_col] = 1 if required else 0
    if pos_col: values[pos_col] = pos
    if done_col: values[done_col] = 0
    # compléter les NOT NULL sans défaut
    needc = {col["name"]: col for col in chinfo}
    for col in chinfo:
        if col["pk"] or col["name"] in values: continue
        if col["notnull"] and col["dflt"] is None:
            t = needc[col["name"]]["type"]
            values[col["name"]] = 0 if "INT" in t else (0.0 if "REAL" in t else "N/A")
    return values

rows.append(build_row("Logo PNG", True, 1))
rows.append(build_row("Logo SVG", True, 2))
rows.append(build_row("Texte descriptif", False, 3))

# insertion batch
for r in rows:
    insert_row(check_table, r)

con.commit()
print(f"✅ Seed OK — client_id={client_id}, project_id={project_id}, checklist_table={check_table}")
con.close()
