import sqlite3
from pathlib import Path
import pandas as pd

DB_PATH = Path("secure_passwords.db")

def get_connection():
    return sqlite3.connect(DB_PATH)

def initialize_database():
    with get_connection() as conn:
        cursor = conn.cursor()

        # Table des utilisateurs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            master_password_hash BLOB NOT NULL,
            salt BLOB NOT NULL
        );
        """)

        # Table des entrées chiffrées
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            service BLOB,
            username BLOB,
            password BLOB,
            nonce_service BLOB,
            tag_service BLOB,
            nonce_username BLOB,
            tag_username BLOB,
            nonce_password BLOB,
            tag_password BLOB,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)

        conn.commit()

def insert_user(username, password_hash, salt):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO users (username, master_password_hash, salt)
        VALUES (?, ?, ?);
        """, (username, password_hash, salt))
        conn.commit()

def get_user(username):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, master_password_hash, salt FROM users WHERE username = ?;
        """, (username,))
        return cursor.fetchone()

def insert_entry(user_id, service, username, password,
                 nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO entries (
                user_id, service, username, password,
                nonce_service, tag_service,
                nonce_username, tag_username,
                nonce_password, tag_password
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            user_id, service, username, password,
            nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p
        ))
        conn.commit()

def get_entries(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, service, username, password,
                   nonce_service, tag_service,
                   nonce_username, tag_username,
                   nonce_password, tag_password
            FROM entries WHERE user_id = ?;
        """, (user_id,))
        return cursor.fetchall()


def update_entry(entry_id, service_name, username, password, nonce, tag):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE entries
        SET service_name_encrypted = ?, username_encrypted = ?, password_encrypted = ?, nonce = ?, tag = ?
        WHERE id = ?;
        """, (service_name, username, password, nonce, tag, entry_id))
        conn.commit()

def delete_entry(entry_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        DELETE FROM entries WHERE id = ?;
        """, (entry_id,))
        conn.commit()

# Initialisation de la base de données à l'importation du module
initialize_database()