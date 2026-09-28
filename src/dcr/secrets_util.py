"""Client secret generation and one-way hash storage.

Secrets are never stored in clear text. PBKDF2-HMAC-SHA256 with a random
per-secret salt is used so that a database leak does not reveal secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGO = "sha256"


def generate_client_secret(length: int = 32) -> str:
    """Return a high-entropy URL-safe client secret."""
    if length < 16:
        raise ValueError("length must be >= 16 bytes of entropy")
    return secrets.token_urlsafe(length)


def hash_secret(secret: str, *, salt: str = "", iterations: int = 200_000) -> tuple[str, str]:
    """Return ``(salt, hash)`` using PBKDF2-HMAC-SHA256.

    ``salt`` is a URL-safe random string generated here when not supplied;
    ``hash`` is hex encoded.
    """
    if not salt:
        salt = secrets.token_urlsafe(16)
    digest = hashlib.pbkdf2_hmac(_ALGO, secret.encode("utf-8"), salt.encode("utf-8"), iterations)
    return salt, digest.hex()


def verify_secret(secret: str, salt: str, expected_hash: str, iterations: int) -> bool:
    """Constant-time verification of a presented secret."""
    _, digest = hash_secret(secret, salt=salt, iterations=iterations)
    return hmac.compare_digest(digest, expected_hash)
