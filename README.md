# 🔐 Gestionnaire de Mots de Passe

Un gestionnaire de mots de passe local, sécurisé et moderne, développé en Python avec une interface graphique intuitive. Il permet de stocker, chiffrer, visualiser et gérer vos identifiants en toute confidentialité.

---

## 🚀 Fonctionnalités

- 🔒 Chiffrement AES-GCM des données sensibles (service, identifiant, mot de passe)
- 🧠 Authentification par mot de passe maître
- 🖥️ Interface graphique Tkinter avec design moderne (ttk, arrondis, fond personnalisé)
- 🔍 Barre de recherche dynamique pour filtrer les services
- 📋 Affichage temporaire du mot de passe + copie dans le presse-papiers
- 🔄 Générateur de mots de passe forts
- 🧪 Journalisation des tentatives suspectes (`security_log.txt`)
- 🧹 Nettoyage automatique de la session à la déconnexion
- 🛡️ Validation des champs pour empêcher les caractères dangereux (`;`, `'`, `--`,etc)
- 🧰 Modification et suppression des entrées
- 🧑‍💻 Création de compte et connexion sécurisée

---

## 🛠️ Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-utilisateur/secure_password_manager.git
cd secure_password_manager

---

### 2. Création de l'environnment virtuel

python3 -m venv venv
source venv/bin/activate


### 3. Installation des dépendances

pip install -r requirements.txt

### Lancer l'application
python main.py

📂 Structure du projet
secure_password_manager/
│
├── main.py                      # Point d'entrée
├── requirements.txt             # Dépendances
├── README.md                    # Documentation
│
├── src/
│   ├── gui/
│   │   └── gui_main.py          # Interface Tkinter
│   ├── auth/
│   │   └── auth_manager.py      # Authentification & session
│   ├── crypto/
│   │   └── crypto_utils.py   

🔐 Sécurité
- Les mots de passe sont chiffrés avec AES-GCM et une clé dérivée en mémoire
- Les entrées sont protégées contre l’injection SQL
- Les caractères dangereux (;, ', --) sont interdits dans les champs sensibles
- Les tentatives suspectes sont journalisées dans security_log.txt
- Les erreurs de déchiffrement sont gérées sans fuite d’information
- La base SQLite est isolée et peut être protégée par des droits Unix (chmod 600)

🧑‍💻 Auteur
Moussa & Khadidja



