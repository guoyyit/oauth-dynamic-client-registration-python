"""Local configuration: trusted statement issuers and service policy.

Everything is configured locally; there is no external identity source.
Issuer secrets (shared HMAC keys) are supplied through environment
variables or fall back to deterministic development defaults so that the
service can boot out of the box.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

DEFAULT_ISSUER = "local-software-authority"
DEFAULT_ISSUER_SECRET = "dev-only-issuer-secret-change-me"
DEFAULT_AUDIENCE = "local-dcr-service"


def _load_issuer_secrets() -> dict[str, str]:
    """Return mapping of trusted software statement issuer -> HMAC secret."""
    raw = os.environ.get("DCR_ISSUER_SECRETS")
    if raw:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
        ):
            raise ValueError("DCR_ISSUER_SECRETS must be a JSON object of strings")
        return dict(parsed)
    return {
        os.environ.get("DCR_ISSUER", DEFAULT_ISSUER): os.environ.get(
            "DCR_ISSUER_SECRET", DEFAULT_ISSUER_SECRET
        )
    }


@dataclass(frozen=True)
class Settings:
    database_path: str = "data/registry.db"
    issuer_secrets: dict[str, str] = field(default_factory=dict)
    trusted_audience: str = DEFAULT_AUDIENCE
    secret_ttl_seconds: int | None = None
    old_secret_grace_seconds: int = 0
    default_page_size: int = 20
    max_page_size: int = 100


def get_settings() -> Settings:
    return Settings(
        database_path=os.environ.get("DCR_DATABASE_PATH", "data/registry.db"),
        issuer_secrets=_load_issuer_secrets(),
        trusted_audience=os.environ.get("DCR_AUDIENCE", DEFAULT_AUDIENCE),
        secret_ttl_seconds=None,
        old_secret_grace_seconds=int(os.environ.get("DCR_OLD_SECRET_GRACE_SECONDS", "0")),
        default_page_size=20,
        max_page_size=100,
    )
