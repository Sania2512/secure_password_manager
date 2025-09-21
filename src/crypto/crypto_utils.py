import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets
import string

# Génère un sel cryptographiquement sûr
def generate_salt(length=16):
    return secrets.token_bytes(length)

# Dérive une clé symétrique à partir du mot de passe maître
def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Vérifie un mot de passe maître contre un hash stocké
def verify_password(stored_hash: bytes, password: str, salt: bytes, iterations: int = 100_000) -> bool:
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        kdf.verify(password.encode(), stored_hash)
        return True
    except Exception:
        return False
    
# Chiffre une donnée avec AES-GCM
def encrypt_data(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96 bits recommandé
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext[-16:]  # Derniers 16 octets = tag
    encrypted = ciphertext[:-16]
    return encrypted, nonce, tag

# Déchiffre une donnée avec AES-GCM
def decrypt_data(key: bytes, encrypted: bytes, nonce: bytes, tag: bytes):
    aesgcm = AESGCM(key)
    ciphertext = encrypted + tag
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_password(length=16, use_upper=True, use_digits=True, use_symbols=True):
    charset = string.ascii_lowercase
    if use_upper:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{};:,.<>?"

    return ''.join(secrets.choice(charset) for _ in range(length))