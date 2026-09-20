# app/services/security.py

"""
Security & Authentication Utilities for VAJRA.

Features:
1. Cryptographically secure password hashing (PBKDF2-HMAC-SHA256 with 100,000 iterations & random salt).
2. Constant-time timing-attack safe string comparison (hmac.compare_digest).
3. Secret signature and API key validation.
4. Input validation and path traversal defenses.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Optional

VAJRA_SECRET_KEY = os.environ.get("VAJRA_SECRET_KEY")
VAJRA_API_KEY = os.environ.get("VAJRA_API_KEY")
SAFE_WORKSPACE_ID_REGEX = re.compile(r"^[0-9a-fA-F-]{8,64}$")


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 rounds and a 16-byte salt.
    Format: salt_hex$hash_hex
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${hashed.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plain password against a stored PBKDF2 salt$hash in constant time.
    """
    if not password or not stored_hash or "$" not in stored_hash:
        return False
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def verify_signature(signature: Optional[str]) -> bool:
    """
    Constant-time comparison of X-Vajra-Signature against server secret key.
    Fails closed if server secret key is not configured or signature is empty.
    """
    secret = os.environ.get("VAJRA_SECRET_KEY") or VAJRA_SECRET_KEY
    if not signature or not secret:
        return False
    return hmac.compare_digest(signature.strip(), secret.strip())


def verify_api_key(api_key: Optional[str]) -> bool:
    """
    Constant-time comparison of X-API-Key against server configured key.
    """
    if not VAJRA_API_KEY:
        # If no API key is set in environment, allow access or check signature
        return True
    if not api_key:
        return False
    return hmac.compare_digest(api_key.strip(), VAJRA_API_KEY.strip())


def is_safe_workspace_id(workspace_id: str) -> bool:
    """
    Ensures workspace ID consists strictly of alphanumeric and hyphens (UUID format).
    Prevents directory traversal attacks like `../` or `..\\`.
    """
    if not isinstance(workspace_id, str):
        return False
    return bool(SAFE_WORKSPACE_ID_REGEX.match(workspace_id.strip()))
