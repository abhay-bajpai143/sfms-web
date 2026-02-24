"""
threat_detection.py - Security Threat Detection Module
Detects: brute force attacks, unusual login times, repeated failures,
         unauthorized access attempts, and suspicious file patterns.
"""

import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5        # Max failed attempts before lockout
BRUTE_FORCE_WINDOW_SEC = 300     # 5-minute sliding window
LOCKOUT_DURATION_SEC = 900       # 15-minute lockout after breach
ALERT_LOG = "security_alerts.log"

# ──────────────────────────────────────────────
#  In-memory state (persists across session)
# ──────────────────────────────────────────────

_failed_attempts: dict[str, list[float]] = defaultdict(list)   # {username: [timestamps]}
_ip_attempts: dict[str, list[float]] = defaultdict(list)        # {ip: [timestamps]}
_lockouts: dict[str, float] = {}                                  # {username: lockout_end_time}
_alert_callbacks: list = []                                        # Optional callback hooks


# ──────────────────────────────────────────────
#  Alert System
# ──────────────────────────────────────────────

def _log_alert(level: str, category: str, detail: str, username: str = ""):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "level": level,
        "category": category,
        "username": username,
        "detail": detail
    }
    print(f"\n  ⚠️  [{level}] {category}: {detail}")
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    for cb in _alert_callbacks:
        try:
            cb(entry)
        except Exception:
            pass


def register_alert_callback(fn):
    """Register a function to be called on every security alert."""
    _alert_callbacks.append(fn)


# ──────────────────────────────────────────────
#  Brute Force Detection
# ──────────────────────────────────────────────

def record_failed_login(username: str, ip: str = "local") -> bool:
    """
    Record a failed login attempt.
    Returns True if the account should now be locked.
    """
    now = time.time()

    # Clean old entries outside the window
    window_start = now - BRUTE_FORCE_WINDOW_SEC
    _failed_attempts[username] = [t for t in _failed_attempts[username] if t > window_start]
    _ip_attempts[ip] = [t for t in _ip_attempts[ip] if t > window_start]

    _failed_attempts[username].append(now)
    _ip_attempts[ip].append(now)

    count = len(_failed_attempts[username])

    if count >= BRUTE_FORCE_THRESHOLD:
        _lockouts[username] = now + LOCKOUT_DURATION_SEC
        _log_alert(
            "CRITICAL", "BRUTE_FORCE_DETECTED",
            f"{count} failed login attempts in {BRUTE_FORCE_WINDOW_SEC}s. "
            f"Account locked for {LOCKOUT_DURATION_SEC}s.",
            username=username
        )
        return True

    if count >= 3:
        _log_alert(
            "WARNING", "REPEATED_FAILURE",
            f"{count} failed login attempts detected.",
            username=username
        )

    # IP-level check (e.g. credential stuffing)
    ip_count = len(_ip_attempts[ip])
    if ip_count >= BRUTE_FORCE_THRESHOLD * 2:
        _log_alert(
            "WARNING", "IP_RATE_LIMIT",
            f"IP {ip} has {ip_count} failed attempts across accounts."
        )

    return False


def record_successful_login(username: str):
    """Clear failed attempts on successful login."""
    _failed_attempts.pop(username, None)
    _lockouts.pop(username, None)


def is_locked_out(username: str) -> tuple[bool, int]:
    """Returns (is_locked, seconds_remaining)."""
    lockout_end = _lockouts.get(username, 0)
    remaining = int(lockout_end - time.time())
    if remaining > 0:
        return True, remaining
    elif username in _lockouts:
        del _lockouts[username]
    return False, 0


def get_failed_count(username: str) -> int:
    window_start = time.time() - BRUTE_FORCE_WINDOW_SEC
    return sum(1 for t in _failed_attempts.get(username, []) if t > window_start)


# ──────────────────────────────────────────────
#  Unauthorized Access Detection
# ──────────────────────────────────────────────

def record_access_denial(username: str, action: str, resource: str):
    """Log when a user tries to perform an unauthorized action."""
    _log_alert(
        "WARNING", "UNAUTHORIZED_ACCESS",
        f"User '{username}' attempted '{action}' on '{resource}' without permission.",
        username=username
    )


# ──────────────────────────────────────────────
#  Suspicious File Pattern Detection
# ──────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs",
    ".js", ".py", ".php", ".dll", ".so", ".dylib"
}

SUSPICIOUS_NAME_PATTERNS = [
    "passwd", "shadow", "credentials", "secret", "token", "key", "private"
]


def scan_file(filename: str) -> list[str]:
    """
    Scan a file path for suspicious patterns.
    Returns list of warnings (empty = clean).
    """
    warnings = []
    lower = filename.lower()
    _, ext = os.path.splitext(lower)

    if ext in SUSPICIOUS_EXTENSIONS:
        warnings.append(f"Suspicious file extension: '{ext}'")

    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in lower:
            warnings.append(f"Sensitive keyword in filename: '{pattern}'")

    if warnings:
        _log_alert(
            "INFO", "SUSPICIOUS_FILE",
            f"File '{filename}' flagged: {'; '.join(warnings)}"
        )

    return warnings


# ──────────────────────────────────────────────
#  Unusual Login Time Detection
# ──────────────────────────────────────────────

BUSINESS_HOURS_START = 7    # 07:00
BUSINESS_HOURS_END = 22     # 22:00


def check_login_time(username: str) -> bool:
    """
    Warn if login occurs outside business hours.
    Returns True if the login time is unusual.
    """
    hour = datetime.now().hour
    if not (BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END):
        _log_alert(
            "INFO", "OFF_HOURS_LOGIN",
            f"Login at {datetime.now().strftime('%H:%M')} (outside {BUSINESS_HOURS_START}:00–{BUSINESS_HOURS_END}:00).",
            username=username
        )
        return True
    return False


# ──────────────────────────────────────────────
#  Summary Report
# ──────────────────────────────────────────────

def get_threat_summary() -> dict:
    """Return a summary of current threat state."""
    return {
        "active_lockouts": {u: int(t - time.time()) for u, t in _lockouts.items() if t > time.time()},
        "users_with_failures": {
            u: get_failed_count(u)
            for u in _failed_attempts
            if get_failed_count(u) > 0
        },
        "alert_log_path": ALERT_LOG
    }
