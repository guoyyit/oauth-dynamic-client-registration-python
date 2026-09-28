"""Service configuration.

The service is fully local: the trusted software-statement signing key(s)
live in local configuration rather than an external identity provider.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_ISSUER = "local-software-statement-authority"

# RFC 7591 / OpenID Connect metadata defaults.
DEFAULT_GRANT_TYPES = ("authorization_code", "refresh_token")
DEFAULT_RESPONSE_TYPES = ("code",)
ALLOWED_GRANT_TYPES = frozenset({
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "implicit",
})
ALLOWED_TOKEN_AUTH_METHODS = frozenset({
    "client_secret_basic",
    "client_secret_post",
    "none",
})
REDIRECT_REQUIRED_GRANTS = frozenset({"authorization_code", "implicit"})


@dataclass(frozen=True)
class Settings:
    database_path: str = "data/dcr.sqlite3"
    trusted_issuer: str = DEFAULT_ISSUER
    signing_secret: str = ""
    signing_kid: str = "local-key-1"
    allowed_scopes: frozenset[str] = field(
        default_factory=lambda: frozenset({"openid", "profile", "email", "offline_access", "api:read"})
    )
    secret_ttl_seconds: int = 90 * 24 * 3600
    overlap_ttl_seconds: int = 24 * 3600
    pbkdf2_iterations: int = 200_000
    page_size_max: int = 200
    page_size_default: int = 50


def load_settings() -> Settings:
    secret = os.environ.get("DCR_SIGNING_SECRET", "local-dev-signing-secret-change-me")
    return Settings(
        database_path=os.environ.get("DCR_DATABASE_PATH", Settings.database_path),
        trusted_issuer=os.environ.get("DCR_TRUSTED_ISSUER", DEFAULT_ISSUER),
        signing_secret=secret,
        signing_kid=os.environ.get("DCR_SIGNING_KID", Settings.signing_kid),
    )
