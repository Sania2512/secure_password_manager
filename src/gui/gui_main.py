import tkinter as tk
import datetime
from tkinter import messagebox, simpledialog
from src.auth.auth_manager import SESSION, logout
from src.auth.auth_manager import authenticate_user, create_user
from src.db.database import insert_entry, get_entries, delete_entry
from src.crypto.crypto_utils import encrypt_data, decrypt_data

# 🎨 Palette de couleurs
BG_COLOR = "#f0f2f5"
CARD_COLOR = "#ffffff"
PRIMARY = "#4CAF50"
SECONDARY = "#2196F3"
DANGER = "#f44336"
FONT = ("Segoe UI", 12)
TITLE_FONT = ("Segoe UI", 18, "bold")

def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()
    root.configure(bg=BG_COLOR)

# 🔐 Écran de connexion
def show_login_screen(root):
    clear_window(root)
    frame = tk.Frame(root, bg=CARD_COLOR, padx=20, pady=20)
    frame.pack(pady=30)

    tk.Label(frame, text="🔐 Gestionnaire de Mots de Passe", font=TITLE_FONT, bg=CARD_COLOR).pack(pady=10)

    tk.Label(frame, text="Nom d'utilisateur", font=FONT, bg=CARD_COLOR).pack(anchor="w")
    username_entry = tk.Entry(frame, font=FONT, width=30)
    username_entry.pack(pady=5)

    tk.Label(frame, text="Mot de passe maître", font=FONT, bg=CARD_COLOR).pack(anchor="w")
    password_entry = tk.Entry(frame, show="*", font=FONT, width=30)
    password_entry.pack(pady=5)

    show_pw_var = tk.BooleanVar(value=False)
    def toggle_password():
        password_entry.config(show="" if show_pw_var.get() else "*")

    tk.Checkbutton(frame, text="Afficher le mot de passe", variable=show_pw_var,
                   command=toggle_password, bg=CARD_COLOR, font=("Segoe UI", 10)).pack(pady=5)

    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        if authenticate_user(username, password):
            messagebox.showinfo("Succès", "Connexion réussie.")
            show_dashboard(root)
        else:
            messagebox.showerror("Erreur", "Échec de la connexion.")

    tk.Button(frame, text="Se connecter", command=attempt_login,
              font=FONT, bg=PRIMARY, fg="white", padx=10, pady=5).pack(pady=10)

    tk.Button(frame, text="Créer un compte", command=lambda: show_registration_screen(root),
              font=FONT, bg=SECONDARY, fg="white", padx=10, pady=5).pack()

# 🧑‍💻 Écran de création de compte
def show_registration_screen(root):
    clear_window(root)
    frame = tk.Frame(root, bg=CARD_COLOR, padx=20, pady=20)
    frame.pack(pady=30)

    tk.Label(frame, text="🆕 Créer un compte", font=TITLE_FONT, bg=CARD_COLOR).pack(pady=10)

    tk.Label(frame, text="Nom d'utilisateur", font=FONT, bg=CARD_COLOR).pack(anchor="w")
    username_entry = tk.Entry(frame, font=FONT, width=30)
    username_entry.pack(pady=5)

    tk.Label(frame, text="Mot de passe maître", font=FONT, bg=CARD_COLOR).pack(anchor="w")
    password_entry = tk.Entry(frame, show="*", font=FONT, width=30)
    password_entry.pack(pady=5)

    tk.Label(frame, text="Confirmer le mot de passe", font=FONT, bg=CARD_COLOR).pack(anchor="w")
    confirm_entry = tk.Entry(frame, show="*", font=FONT, width=30)
    confirm_entry.pack(pady=5)

    show_pw_var = tk.BooleanVar(value=False)
    def toggle_password():
        password_entry.config(show="" if show_pw_var.get() else "*")
        confirm_entry.config(show="" if show_pw_var.get() else "*")

    tk.Checkbutton(frame, text="Afficher le mot de passe", variable=show_pw_var,
                   command=toggle_password, bg=CARD_COLOR, font=("Segoe UI", 10)).pack(pady=5)

    def attempt_registration():
        username = username_entry.get()
        password = password_entry.get()
        confirm = confirm_entry.get()
        if password != confirm:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return
        if create_user(username, password):
            messagebox.showinfo("Succès", "Compte créé. Vous pouvez maintenant vous connecter.")
            show_login_screen(root)
        else:
            messagebox.showerror("Erreur", "Échec de la création du compte.")

    tk.Button(frame, text="Créer le compte", command=attempt_registration,
              font=FONT, bg=PRIMARY, fg="white", padx=10, pady=5).pack(pady=10)

    tk.Button(frame, text="Retour à la connexion", command=lambda: show_login_screen(root),
              font=FONT, bg=SECONDARY, fg="white", padx=10, pady=5).pack()

# 🏠 Tableau de bord
def show_dashboard(root, search_query=""):
    clear_window(root)
    tk.Label(root, text=f"👋 Bienvenue {SESSION['username']}", font=TITLE_FONT, bg=BG_COLOR).pack(pady=10)
    
    search_var = tk.StringVar(root)

    search_frame = tk.Frame(root, bg=BG_COLOR)
    search_frame.pack(pady=5)

    tk.Label(search_frame, text="🔎 Rechercher un service :", font=FONT, bg=BG_COLOR).pack(side=tk.LEFT)
    search_entry = tk.Entry(search_frame, textvariable=search_var, font=FONT, width=25)
    search_entry.pack(side=tk.LEFT, padx=5)

    def refresh_entries(*args):
        show_dashboard(root, search_query=search_var.get())

    search_var.trace_add("write", lambda *args: refresh_entries())

    def reset_search():
        search_var.set("")

    tk.Button(search_frame, text="Réinitialiser", command=reset_search,
            font=("Segoe UI", 10), bg=SECONDARY, fg="white").pack(side=tk.LEFT, padx=5)

    tk.Button(root, text="➕ Ajouter une entrée", command=lambda: add_entry(root),
              font=FONT, bg=PRIMARY, fg="white", padx=10, pady=5).pack(pady=5)

    tk.Button(root, text="🚪 Déconnexion", command=lambda: [logout(), show_login_screen(root)],
              font=FONT, bg=DANGER, fg="white", padx=10, pady=5).pack(pady=5)

    entries = get_entries(SESSION["user_id"])
    key = SESSION["encryption_key"]

    found = 0

    for entry in entries:
        (entry_id, service_enc, username_enc, password_enc,
         nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p) = entry
        try:
            service = decrypt_data(key, service_enc, nonce_s, tag_s).decode()
            username = decrypt_data(key, username_enc, nonce_u, tag_u).decode()
            password = decrypt_data(key, password_enc, nonce_p, tag_p).decode()
        except Exception:
            service = "[Erreur de déchiffrement]"
            username = password = ""

        # 🔍 Filtrage par recherche
        if search_query and search_query.lower() not in service.lower():
            continue

        found += 1

        frame = tk.Frame(root, bg=CARD_COLOR, relief=tk.RIDGE, borderwidth=1, padx=10, pady=10)
        frame.pack(pady=5, fill=tk.X, padx=20)

        tk.Label(frame, text=f"🔐 Service : {service}", font=FONT, bg=CARD_COLOR).pack(anchor="w")
        tk.Label(frame, text=f"👤 Identifiant : {username}", font=FONT, bg=CARD_COLOR).pack(anchor="w")
        tk.Label(frame, text=f"🔑 Mot de passe : {'*' * len(password)}", font=FONT, bg=CARD_COLOR).pack(anchor="w")

        def show_password_temporarily(p):
            # Crée une fenêtre temporaire
            popup = tk.Toplevel()
            popup.title("Mot de passe")
            popup.configure(bg=CARD_COLOR)
            popup.geometry("300x100")
            popup.resizable(False, False)

            label = tk.Label(popup, text=f"🔑 {p}", font=FONT, bg=CARD_COLOR)
            label.pack(pady=10)

            def copy_to_clipboard():
                popup.clipboard_clear()
                popup.clipboard_append(p)
                popup.update()  # Nécessaire pour que le presse-papiers soit actif
                messagebox.showinfo("Copié", "Mot de passe copié dans le presse-papiers.")

            tk.Button(popup, text="📋 Copier", command=copy_to_clipboard,
                    font=("Segoe UI", 10), bg=SECONDARY, fg="white").pack()

            # Ferme automatiquement après 5 secondes
            popup.after(5000, popup.destroy)

        tk.Button(frame, text="Afficher", command=lambda p=password: show_password_temporarily(p),
          font=("Segoe UI", 10), bg=SECONDARY, fg="white").pack(side=tk.RIGHT, padx=5)

        def confirm_delete(eid=entry_id):
            if messagebox.askyesno("Confirmer", "Supprimer cette entrée ?"):
                delete_entry(eid)
                show_dashboard(root)

        tk.Button(frame, text="Supprimer", command=confirm_delete,
                  font=("Segoe UI", 10), bg=DANGER, fg="white").pack(side=tk.RIGHT)
        
        def edit_entry(eid=entry_id, old_service=service, old_username=username, old_password=password):
            new_service = simpledialog.askstring("Modifier service", "Nouveau nom du service :", initialvalue=old_service)
            new_username = simpledialog.askstring("Modifier identifiant", "Nouvel identifiant :", initialvalue=old_username)
            new_password = simpledialog.askstring("Modifier mot de passe", "Nouveau mot de passe :", initialvalue=old_password)

            if not all([new_service, new_username, new_password]):
                messagebox.showerror("Erreur", "Tous les champs sont requis.")
                return

            key = SESSION["encryption_key"]
            service_enc, nonce_s, tag_s = encrypt_data(key, new_service.encode())
            username_enc, nonce_u, tag_u = encrypt_data(key, new_username.encode())
            password_enc, nonce_p, tag_p = encrypt_data(key, new_password.encode())

            from src.db.database import update_entry
            update_entry(eid, service_enc, username_enc, password_enc,
                        nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p)
            messagebox.showinfo("Succès", "Entrée modifiée.")
            show_dashboard(root)

        tk.Button(frame, text="Modifier", command=edit_entry,
                font=("Segoe UI", 10), bg=PRIMARY, fg="white").pack(side=tk.RIGHT, padx=5)
        
    if found == 0:
        tk.Label(root, text="Aucun service ne correspond à votre recherche.",
                font=FONT, bg=BG_COLOR, fg="gray").pack(pady=10)

# ➕ Ajout d’une entrée
def add_entry(root):
    service = simpledialog.askstring("Service", "Nom du service :")
    username = simpledialog.askstring("Identifiant", "Nom d'utilisateur ou email :")
    password = simpledialog.askstring("Mot de passe", "Mot de passe correspondant :")

    forbidden_chars = [";", "--", "'"]

    if any(c in service for c in forbidden_chars) or any(c in username for c in forbidden_chars):
        log_attempt("Tentative d'injection détectée", service, username)
        messagebox.showerror("Caractères interdits", "Les champs ne doivent pas contenir ';', '--' ou des apostrophes.")
        return

    if not all([service, username, password]):
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return

    key = SESSION["encryption_key"]
    service_enc, nonce_s, tag_s = encrypt_data(key, service.encode())
    username_enc, nonce_u, tag_u = encrypt_data(key, username.encode())
    password_enc, nonce_p, tag_p = encrypt_data(key, password.encode())

    insert_entry(
        SESSION["user_id"],
        service_enc, username_enc, password_enc,
        nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p
    )
    messagebox.showinfo("Succès", "Entrée ajoutée.")
    show_dashboard(root)

def log_attempt(message, service="", username=""):
    with open("security_log.txt", "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message} | Service: {service} | Identifiant: {username}\n")

# 🚀 Lancement
def launch_gui():
    root = tk.Tk()
    root.title("🔐 Gestionnaire de Mots de Passe")
    root.geometry("450x650")
    root.configure(bg=BG_COLOR)
    show_login_screen(root)
    root.mainloop()