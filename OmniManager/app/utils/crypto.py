"""
Symmetric encryption for sensitive fields (WinRM passwords).
The Fernet key is derived from Flask's SECRET_KEY so no extra
config variable is needed — but changing SECRET_KEY will
invalidate all stored passwords.
"""
import hashlib
import base64

from cryptography.fernet import Fernet, InvalidToken


def _fernet() -> Fernet:
    from flask import current_app
    raw = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt(value: str) -> str:
    """Encrypt a plaintext string. Returns empty string for empty input."""
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Decrypt an encrypted string. Returns empty string for empty input.
    Falls back to returning the raw value if it was stored unencrypted
    (migration path from plaintext passwords).
    """
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, Exception):
        # Value was stored unencrypted — return as-is and it will be
        # re-encrypted on next save.
        return value
