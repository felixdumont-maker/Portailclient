import sqlite3

conn = sqlite3.connect('portail.db')
cursor = conn.cursor()

print("--- Création d'une checklist pour un projet ---")

project_id = input("ID du projet auquel ajouter la checklist : ")
checklist_title = input("Titre de la checklist (ex: Documents requis) : ")

# Créer la checklist
cursor.execute("INSERT INTO checklistes (titre, id_projet) VALUES (?, ?)", (checklist_title, project_id))
checklist_id = cursor.lastrowid # Récupère l'ID de la checklist qu'on vient de créer
print(f"\nChecklist '{checklist_title}' créée avec succès.")

# Ajouter des items
while True:
    item_text = input("Ajouter un item (ou laissez vide pour terminer) : ")
    if not item_text:
        break
    cursor.execute("INSERT INTO checklist_items (texte, id_checklist) VALUES (?, ?)", (item_text, checklist_id))
    print(f" - Item '{item_text}' ajouté.")

conn.commit()
conn.close()
print("\nOpération terminée.")
