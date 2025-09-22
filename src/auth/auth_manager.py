import re
import time
from src.crypto.crypto_utils import generate_salt, derive_key, verify_password
from src.db.database import insert_user, get_user

# Session temporaire en mémoire
SESSION = {
    "user_id": None,
    "username": None,
    "encryption_key": None,
    "login_attempts": 0,
    "last_attempt_time": 0
}

# Vérifie la complexité du mot de passe maître
def is_password_strong(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+=\-]", password)
    )

# Création de compte utilisateur
def create_user(username: str, master_password: str) -> bool:
    if not is_password_strong(master_password):
        print("Mot de passe trop faible.")
        return False

    salt = generate_salt()
    password_hash = derive_key(master_password, salt)
    try:
        insert_user(username, password_hash, salt)
        print("Compte créé avec succès.")
        return True
    except Exception as e:
        print(f"Erreur lors de la création du compte : {e}")
        return False

# Connexion utilisateur avec protection contre brute-force
def authenticate_user(username: str, master_password: str) -> bool:
    now = time.time()
    if SESSION["login_attempts"] >= 3 and now - SESSION["last_attempt_time"] < 10:
        print("Trop de tentatives. Attendez quelques secondes.")
        return False

    user = get_user(username)
    if not user:
        print("Utilisateur inconnu.")
        return False

    user_id, stored_hash, salt = user
    if verify_password(stored_hash, master_password, salt):
        key = derive_key(master_password, salt)
        SESSION.update({
            "user_id": user_id,
            "username": username,
            "encryption_key": key,
            "login_attempts": 0
        })
        print("Connexion réussie.")
        return True
    else:
        SESSION["login_attempts"] += 1
        SESSION["last_attempt_time"] = now
        print("Mot de passe incorrect.")
        return False

# Déconnexion et nettoyage mémoire
def logout():
    SESSION.update({
        "user_id": None,
        "username": None,
        "encryption_key": None
    })
    print("Déconnexion effectuée. Mémoire nettoyée.")