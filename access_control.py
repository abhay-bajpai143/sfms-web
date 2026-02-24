"""
access_control.py - Role-Based Access Control (RBAC)
Defines permissions for admin / user / guest roles.
"""

# ──────────────────────────────────────────────
#  Permission Definitions
# ──────────────────────────────────────────────

PERMISSIONS = {
    "admin": {
        "read", "write", "delete", "encrypt", "decrypt",
        "list", "share", "manage_users", "view_logs"
    },
    "user": {
        "read", "write", "delete", "encrypt", "decrypt", "list", "share"
    },
    "guest": {
        "read", "list"
    }
}

# File ownership map: {filename: owner_username}
# Owners can always access their own files.
_file_owners: dict[str, str] = {}


def get_permissions(role: str) -> set:
    return PERMISSIONS.get(role.lower(), set())


def has_permission(role: str, action: str) -> bool:
    """Check if a role has a specific permission."""
    return action in get_permissions(role)


def check_access(username: str, role: str, action: str, filename: str | None = None) -> tuple[bool, str]:
    """
    Comprehensive access check.
    Owners bypass role restrictions for their own files.
    Returns (allowed, reason).
    """
    if filename and _file_owners.get(filename) == username:
        return True, "Access granted (file owner)."

    if has_permission(role, action):
        return True, f"Access granted (role: {role})."

    return False, f"Access denied: '{role}' role cannot perform '{action}'."


def register_file_owner(filename: str, username: str):
    """Record ownership when a file is uploaded/created."""
    _file_owners[filename] = username


def get_file_owner(filename: str) -> str | None:
    return _file_owners.get(filename)


def list_permissions(role: str) -> list[str]:
    return sorted(get_permissions(role))


ROLE_HIERARCHY = ["guest", "user", "admin"]


def is_role_at_least(role: str, minimum: str) -> bool:
    try:
        return ROLE_HIERARCHY.index(role) >= ROLE_HIERARCHY.index(minimum)
    except ValueError:
        return False
