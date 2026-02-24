"""
encryption.py - File Encryption / Decryption Module
Uses AES-256-GCM (authenticated encryption) via cryptography library.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Magic header to identify encrypted files
MAGIC = b"SFMS_ENC_V1\n"
SALT_LEN = 32
NONCE_LEN = 12


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypt a file using AES-256-GCM.
    Output format: MAGIC | salt(32) | nonce(12) | ciphertext+tag
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(MAGIC + salt + nonce + ciphertext)

    print(f"  [+] Encrypted → {output_path}")


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Decrypt an AES-256-GCM encrypted file.
    Raises ValueError on wrong password or tampered data.
    """
    with open(input_path, "rb") as f:
        raw = f.read()

    magic_len = len(MAGIC)
    if not raw.startswith(MAGIC):
        raise ValueError("File is not a valid SFMS encrypted file.")

    offset = magic_len
    salt = raw[offset: offset + SALT_LEN]
    offset += SALT_LEN
    nonce = raw[offset: offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = raw[offset:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed: wrong password or file is corrupted / tampered.")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"  [+] Decrypted → {output_path}")


def is_encrypted(path: str) -> bool:
    """Check if a file was encrypted by this system."""
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except Exception:
        return False
