"""
auth.py - Authentication Module
Handles password-based authentication and TOTP-based 2FA
"""

import os
import json
import time
import hmac
import struct
import base64
import hashlib
import secrets
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ──────────────────────────────────────────────
#  TOTP (Time-based One-Time Password) – RFC 6238
# ──────────────────────────────────────────────

def _hotp(key_bytes: bytes, counter: int) -> int:
    """Compute HMAC-based OTP."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset: offset + 4])[0] & 0x7FFFFFFF
    return code % 10 ** 6


def generate_totp_secret() -> str:
    """Generate a random base32 TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def get_totp_code(secret: str, window: int = 0) -> str:
    """Return current 6-digit TOTP code."""
    key_bytes = base64.b32decode(secret.upper())
    counter = int(time.time()) // 30 + window
    return f"{_hotp(key_bytes, counter):06d}"


def verify_totp(secret: str, code: str) -> bool:
    """Verify TOTP code with ±1 window tolerance."""
    code = code.strip()
    for window in (-1, 0, 1):
        if hmac.compare_digest(get_totp_code(secret, window), code):
            return True
    return False


# ──────────────────────────────────────────────
#  Password Hashing (PBKDF2 + SHA-256)
# ──────────────────────────────────────────────

PBKDF2_ITERATIONS = 390_000   # OWASP 2023 recommendation


def hash_password(password: str) -> dict:
    """Hash a password with PBKDF2-HMAC-SHA256. Returns salt + hash."""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(key).decode(),
        "iterations": PBKDF2_ITERATIONS
    }


def verify_password(password: str, stored: dict) -> bool:
    """Verify a password against stored hash data."""
    salt = base64.b64decode(stored["salt"])
    expected = base64.b64decode(stored["hash"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=stored["iterations"],
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), expected)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
#  Password Strength Checker
# ──────────────────────────────────────────────

def check_password_strength(password: str) -> tuple[bool, list]:
    """Returns (is_strong, list_of_issues)."""
    issues = []
    if len(password) < 8:
        issues.append("Must be at least 8 characters long")
    if not any(c.isupper() for c in password):
        issues.append("Must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        issues.append("Must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("Must contain at least one digit")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("Must contain at least one special character")
    return (len(issues) == 0, issues)


# ──────────────────────────────────────────────
#  User Registry
# ──────────────────────────────────────────────

class UserRegistry:
    """
    Manages user accounts: registration, login, 2FA setup/verification.
    Users file: users.json
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._users: dict = {}
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r") as f:
                self._users = json.load(f)

    def _save(self):
        with open(self.db_path, "w") as f:
            json.dump(self._users, f, indent=2)

    def user_exists(self, username: str) -> bool:
        return username in self._users

    def register(self, username: str, password: str, role: str = "user") -> tuple[bool, str]:
        """Register a new user. Returns (success, message/totp_secret)."""
        if self.user_exists(username):
            return False, "Username already exists."

        ok, issues = check_password_strength(password)
        if not ok:
            return False, "Weak password:\n  - " + "\n  - ".join(issues)

        totp_secret = generate_totp_secret()
        self._users[username] = {
            "password": hash_password(password),
            "role": role,
            "totp_secret": totp_secret,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "locked": False
        }
        self._save()
        return True, totp_secret

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        """Step 1: verify username + password."""
        user = self._users.get(username)
        if not user:
            return False, "Invalid credentials."
        if user.get("locked"):
            return False, "Account is locked. Contact administrator."
        if not verify_password(password, user["password"]):
            return False, "Invalid credentials."
        return True, "Password verified. Proceed to 2FA."

    def verify_2fa(self, username: str, code: str) -> bool:
        """Step 2: verify TOTP code."""
        user = self._users.get(username)
        if not user:
            return False
        return verify_totp(user["totp_secret"], code)

    def get_role(self, username: str) -> str:
        return self._users.get(username, {}).get("role", "user")

    def update_last_login(self, username: str):
        if username in self._users:
            self._users[username]["last_login"] = datetime.utcnow().isoformat()
            self._save()

    def lock_user(self, username: str):
        if username in self._users:
            self._users[username]["locked"] = True
            self._save()

    def unlock_user(self, username: str):
        if username in self._users:
            self._users[username]["locked"] = False
            self._save()

    def get_totp_secret(self, username: str) -> str | None:
        return self._users.get(username, {}).get("totp_secret")

    def list_users(self) -> list[dict]:
        return [
            {"username": u, "role": d["role"], "locked": d.get("locked", False),
             "last_login": d.get("last_login")}
            for u, d in self._users.items()
        ]
