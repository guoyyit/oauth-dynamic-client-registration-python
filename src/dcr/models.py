"""Domain types: client lifecycle states and persistence records."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ClientState(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    DELETED = "deleted"


# Allowed lifecycle transitions. Revocation/deletion are terminal; re-activation
# of a revoked client is only possible through the independent recovery flow.
STATE_TRANSITIONS: dict[ClientState, frozenset[ClientState]] = {
    ClientState.ACTIVE: frozenset({
        ClientState.SUSPENDED,
        ClientState.REVOKED,
        ClientState.DELETED,
    }),
    ClientState.SUSPENDED: frozenset({
        ClientState.ACTIVE,
        ClientState.REVOKED,
        ClientState.DELETED,
    }),
    ClientState.REVOKED: frozenset({ClientState.DELETED}),
    ClientState.DELETED: frozenset(),
}


class SecretStatus(str, enum.Enum):
    CURRENT = "current"
    PREVIOUS = "previous"
    REVOKED = "revoked"


@dataclass
class SoftwareStatement:
    iss: str
    sub: str
    software_id: str
    client_id: str | None
    metadata: dict
    issued_at: int
    expires_at: int
    jti: str
    kid: str
    raw: str = ""


@dataclass
class Client:
    client_id: str
    software_id: str
    issuer: str
    state: ClientState
    version: int
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    scope: str
    client_name: str
    jti: str
    created_at: str
    updated_at: str
    secret: "ClientSecret | None" = None


@dataclass
class ClientSecret:
    id: int
    client_id: str
    secret_hash: str
    salt: str
    iterations: int
    status: SecretStatus
    expires_at: str | None
    created_at: str


@dataclass
class ClientPage:
    items: list[Client] = field(default_factory=list)
    next_cursor: str | None = None
    total: int = 0
