"""HTTP response shaping and opaque keyset-pagination cursor handling."""

from __future__ import annotations

import base64
import json

from .errors import DCR, ErrorCode
from .models import Client, ClientPage


def client_to_public_dict(
    client: Client,
    *,
    include_secret: bool = False,
    secret_plain: str | None = None,
    secret_expires_at: str | None = None,
) -> dict:
    """Shape a client record for an HTTP response.

    Secret material is only included when the caller just generated/rotated
    it; stored hashes never leave the service.
    """
    data: dict = {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "software_id": client.software_id,
        "issuer": client.issuer,
        "state": client.state.value,
        "version": client.version,
        "redirect_uris": list(client.redirect_uris),
        "grant_types": list(client.grant_types),
        "response_types": list(client.response_types),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "scope": client.scope,
        "created_at": client.created_at,
        "updated_at": client.updated_at,
    }
    if include_secret:
        data["client_secret"] = secret_plain
        data["client_secret_expires_at"] = secret_expires_at
    return data


def encode_cursor(last_rowid: int) -> str:
    raw = json.dumps([last_rowid], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + padding)
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 1:
            raise ValueError
        (last_rowid,) = value
        if not isinstance(last_rowid, int) or last_rowid < 0:
            raise ValueError
        return last_rowid
    except (ValueError, TypeError) as exc:
        raise DCR(ErrorCode.INVALID_REQUEST, "malformed pagination cursor", status_code=400) from exc


def page_to_dict(page: ClientPage) -> dict:
    return {
        "clients": [client_to_public_dict(c) for c in page.items],
        "next_cursor": page.next_cursor,
        "total": page.total,
    }
