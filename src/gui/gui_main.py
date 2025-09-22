from tkinter import messagebox, simpledialog
from src.db.database import insert_entry
from src.crypto.crypto_utils import encrypt_data
from src.auth.auth_manager import SESSION, logout
from src.db.database import get_entries
from src.crypto.crypto_utils import decrypt_data
import tkinter as tk

def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()


def show_login_screen(root):
    clear_window(root)
    tk.Label(root, text="Gestionnaire de Mots de Passe", font=("Arial", 16)).pack(pady=10)

    tk.Label(root, text="Nom d'utilisateur").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Mot de passe maître").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def attempt_login():
        from src.auth.auth_manager import authenticate_user
        username = username_entry.get()
        password = password_entry.get()
        if authenticate_user(username, password):
            messagebox.showinfo("Succès", "Connexion réussie.")
            show_dashboard(root)
        else:
            messagebox.showerror("Erreur", "Échec de la connexion.")

    tk.Button(root, text="Se connecter", command=attempt_login).pack(pady=5)
    tk.Button(root, text="Créer un compte", command=lambda: [clear_window(root), show_registration_screen(root)]).pack(pady=5)

def show_registration_screen(root):
    clear_window(root)
    tk.Label(root, text="Créer un compte", font=("Arial", 16)).pack(pady=10)

    tk.Label(root, text="Nom d'utilisateur").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Mot de passe maître").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    tk.Label(root, text="Confirmer le mot de passe").pack()
    confirm_entry = tk.Entry(root, show="*")
    confirm_entry.pack()

    def attempt_registration():
        from src.auth.auth_manager import create_user
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

    tk.Button(root, text="Créer le compte", command=attempt_registration).pack(pady=5)
    tk.Button(root, text="Retour à la connexion", command=lambda: [clear_window(root), show_login_screen(root)]).pack(pady=5)

def show_dashboard(root):
    clear_window(root)
    tk.Label(root, text=f"Bienvenue {SESSION['username']}", font=("Arial", 14)).pack(pady=10)
    tk.Button(root, text="Ajouter une entrée", command=lambda: add_entry(root)).pack(pady=5)
    tk.Button(root, text="Déconnexion", command=lambda: [logout(), show_login_screen(root)]).pack(pady=5)

    entries = get_entries(SESSION["user_id"])
    key = SESSION["encryption_key"]

    for entry in entries:
        entry_id, service_enc, username_enc, password_enc, nonce, tag = entry
        try:
            service = decrypt_data(key, service_enc, nonce, tag).decode()
            username = decrypt_data(key, username_enc, nonce, tag).decode()
            password = decrypt_data(key, password_enc, nonce, tag).decode()
        except Exception:
            service = "[Erreur de déchiffrement]"
            username = password = ""

        frame = tk.Frame(root, relief=tk.RIDGE, borderwidth=1)
        frame.pack(pady=5, fill=tk.X, padx=10)

        tk.Label(frame, text=f"🔐 {service}").pack(anchor="w")
        tk.Label(frame, text=f"Identifiant : {username}").pack(anchor="w")
        tk.Label(frame, text=f"Mot de passe : {'*' * len(password)}").pack(anchor="w")

        def show_password(p=password):
            messagebox.showinfo("Mot de passe", p)

        tk.Button(frame, text="Afficher", command=show_password).pack(side=tk.RIGHT)

        def confirm_delete(eid=entry_id):
            if messagebox.askyesno("Confirmer", "Supprimer cette entrée ?"):
                from src.db.database import delete_entry
                delete_entry(eid)
                show_dashboard(root)

        tk.Button(frame, text="Supprimer", command=confirm_delete).pack(side=tk.RIGHT)

def add_entry(root):
    service = simpledialog.askstring("Service", "Nom du service :")
    username = simpledialog.askstring("Identifiant", "Nom d'utilisateur ou email :")
    password = simpledialog.askstring("Mot de passe", "Mot de passe à stocker :")

    if not all([service, username, password]):
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return

    key = SESSION["encryption_key"]
    service_enc, nonce_s, tag_s = encrypt_data(key, service.encode())
    username_enc, nonce_u, tag_u = encrypt_data(key, username.encode())
    password_enc, nonce_p, tag_p = encrypt_data(key, password.encode())

    insert_entry(
        SESSION["user_id"],
        service_enc,
        username_enc,
        password_enc,
        nonce_p,
        tag_p
    )
    messagebox.showinfo("Succès", "Entrée ajoutée.")
    show_dashboard(root)

def launch_gui():
    root = tk.Tk()
    root.title("Gestionnaire de Mots de Passe")
    root.geometry("400x600")
    show_login_screen(root)
    root.mainloop()


