"""Application service orchestrating statements, storage and policy."""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

from app.crypto import (
    generate_client_id,
    generate_client_secret,
    hash_secret,
    verify_secret,
    verify_software_statement,
)
from app.errors import (
    ERR_CLIENT_NOT_FOUND,
    ERR_CLIENT_REVOKED,
    ERR_NO_ACTIVE_SECRET,
    ERR_OWNERSHIP_MISMATCH,
    ERR_VERSION_CONFLICT,
    RegistrationError,
)
from app.lifecycle import (
    STATE_DELETED,
    ensure_transition,
    is_known_state,
    recovery_target,
)
from app.storage import (
    DuplicateSoftwareError,
    Storage,
    VersionConflictError,
)
from app.validation import (
    merge_metadata,
    validate_metadata,
    validate_registration_request,
    validate_statement_claims,
    validate_update_payload,
)

_SECRET_ID_BYTES = 9


def _new_secret_id() -> str:
    return base64.urlsafe_b64encode(
        secrets.token_bytes(_SECRET_ID_BYTES)
    ).rstrip(b"=").decode("ascii")


def _public_view(row: dict[str, Any]) -> dict[str, Any]:
    """Project a storage row into the API representation (never leaks hashes)."""
    now = time.time()
    old_expires = row.get("old_secret_expires_at")
    has_secret = row.get("secret_hash") is not None
    return {
        "client_id": row["client_id"],
        "software_id": row["software_id"],
        "issuer": row["issuer"],
        "metadata": row["metadata"],
        "state": row["state"],
        "version": row["version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "has_secret": has_secret,
        "active_secret_id": row.get("secret_id"),
        "old_secret_expires_at": old_expires,
    }


def _encode_cursor(created_at: float, client_id: str) -> str:
    raw = json.dumps([created_at, client_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> tuple[float, str]:
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + padding).decode())
        created_at, client_id = value
        if not isinstance(created_at, (int, float)) or not isinstance(client_id, str):
            raise ValueError
        return float(created_at), client_id
    except (ValueError, UnicodeDecodeError):
        from app.errors import ERR_INVALID_REQUEST

        raise RegistrationError(
            ERR_INVALID_REQUEST, "malformed pagination cursor", 400
        ) from None


class ClientService:
    def __init__(self, storage: Storage, settings: Any) -> None:
        self._storage = storage
        self._settings = settings

    # ------------------------------------------------------------------ helpers

    def _verify(self, token: str) -> dict[str, Any]:
        claims = verify_software_statement(
            token,
            self._settings.issuer_secrets,
            self._settings.trusted_audience,
        )
        return validate_statement_claims(claims)

    def _load_live(self, client_id: str) -> dict[str, Any]:
        row = self._storage.get_client(client_id)
        if row is None or row["state"] == STATE_DELETED:
            raise RegistrationError(
                ERR_CLIENT_NOT_FOUND, f"unknown client: {client_id!r}", 404
            )
        return row

    def _check_ownership(self, row: dict[str, Any], claims: dict[str, Any]) -> None:
        if row["software_id"] != claims["software_id"] or row["issuer"] != claims["iss"]:
            raise RegistrationError(
                ERR_OWNERSHIP_MISMATCH,
                "software statement does not own this client",
                403,
            )

    def _expire_old_secret(self, row: dict[str, Any]) -> dict[str, Any] | None:
        """Clear the old secret column if its grace period has elapsed."""
        expires = row.get("old_secret_expires_at")
        if expires is not None and expires <= time.time():
            return {
                "old_secret_hash": None,
                "old_secret_id": None,
                "old_secret_expires_at": None,
            }
        return None

    def verify_client_secret(self, client_id: str, presented: str) -> str | None:
        """Verify a presented secret against active then (grace) old secret.

        Returns ``"active"``, ``"old"`` or ``None``.  Expired grace secrets
        are purged lazily and persist the purge, so the outcome is identical
        after a restart.
        """
        row = self._load_live(client_id)
        expired = self._expire_old_secret(row)
        if expired:
            row = self._storage.mutate_client(client_id, row["version"], lambda _c: expired)

        active_hash = row.get("secret_hash")
        if active_hash and verify_secret(presented, active_hash):
            return "active"
        old_hash = row.get("old_secret_hash")
        if old_hash and verify_secret(presented, old_hash):
            return "old"
        return None

    # -------------------------------------------------------------- registration

    def register(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], bool]:
        """Validate and store a registration.

        Returns ``(client_view, secret_issue, created)``.  Repeated or racing
        submissions for the same ``software_id`` return the existing record
        (``created=False``) instead of creating a second row.
        """
        checked = validate_registration_request(payload)
        claims = self._verify(checked["software_statement"])

        metadata = merge_metadata(claims.get("metadata", {}), checked["metadata"])

        now = time.time()
        secret_plain = generate_client_secret()
        record = {
            "client_id": generate_client_id(),
            "software_id": claims["software_id"],
            "issuer": claims["iss"],
            "metadata": metadata,
            "state": "active",
            "version": 1,
            "created_at": now,
            "updated_at": now,
            "secret_hash": hash_secret(secret_plain),
            "secret_id": _new_secret_id(),
            "secret_created_at": now,
            "secret_expires_at": self._settings.secret_ttl_seconds
            and now + self._settings.secret_ttl_seconds,
            "old_secret_hash": None,
            "old_secret_id": None,
            "old_secret_expires_at": None,
        }
        try:
            stored = self._storage.insert_client(record)
        except DuplicateSoftwareError as conflict:
            existing = conflict.existing
            expired = self._expire_old_secret(existing)
            if expired:
                try:
                    existing = self._storage.mutate_client(
                        existing["client_id"], existing["version"], lambda _cur: expired
                    )
                except VersionConflictError:
                    # A concurrent writer already advanced the row; the idempotent
                    # response is still the existing client record.
                    existing = conflict.existing
            return _public_view(existing), {}, False

        secret_issue = {
            "client_id": stored["client_id"],
            "secret_id": stored["secret_id"],
            "client_secret": secret_plain,
            "secret_expires_at": stored["secret_expires_at"],
            "old_secret_id": None,
            "old_secret_expires_at": None,
            "version": stored["version"],
        }
        return _public_view(stored), secret_issue, True

    # -------------------------------------------------------------------- update

    def update(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        checked = validate_update_payload(payload)
        claims = self._verify(checked["software_statement"])
        row = self._load_live(client_id)
        self._check_ownership(row, claims)

        if row["state"] == "revoked":
            raise RegistrationError(
                ERR_CLIENT_REVOKED,
                "a revoked client cannot be updated; use the recovery flow",
                409,
            )

        merged = dict(row["metadata"])
        merged.update(checked["metadata"])
        new_metadata = validate_metadata(merged)

        try:
            updated = self._storage.mutate_client(
                client_id,
                checked["expected_version"],
                lambda cur: {
                    "metadata_json": new_metadata,
                    "updated_at": time.time(),
                },
            )
        except VersionConflictError as exc:
            raise RegistrationError(
                ERR_VERSION_CONFLICT,
                "client metadata was modified concurrently; retry with the latest version",
                409,
            ) from exc
        assert updated is not None
        return _public_view(updated)

    # ------------------------------------------------------------------- secrets

    def rotate_secret(
        self, client_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        token = _require_statement(payload)
        retain = bool(payload.get("retain_old_secret", True))
        grace = payload.get("grace_period_seconds")
        if grace is not None and (not isinstance(grace, int) or isinstance(grace, bool) or grace < 0):
            from app.errors import ERR_INVALID_REQUEST

            raise RegistrationError(
                ERR_INVALID_REQUEST,
                "'grace_period_seconds' must be a non-negative integer",
                400,
            )
        if grace is None:
            grace = self._settings.old_secret_grace_seconds

        claims = self._verify(token)
        row = self._load_live(client_id)
        self._check_ownership(row, claims)
        if row["state"] == "revoked" or row["state"] == "deleted":
            raise RegistrationError(
                ERR_CLIENT_REVOKED, "cannot rotate secrets for a revoked client", 409
            )
        if not row.get("secret_hash"):
            raise RegistrationError(
                ERR_NO_ACTIVE_SECRET, "client has no active secret to rotate", 409
            )

        now = time.time()
        new_secret = generate_client_secret()
        new_id = _new_secret_id()
        if retain:
            old_overrides = {
                "old_secret_hash": row["secret_hash"],
                "old_secret_id": row["secret_id"],
                "old_secret_expires_at": now + grace if grace else None,
            }
        else:
            old_overrides = {
                "old_secret_hash": None,
                "old_secret_id": None,
                "old_secret_expires_at": None,
            }

        def apply(cur: dict[str, Any]) -> dict[str, Any]:
            changes = dict(old_overrides)
            changes.update(
                {
                    "secret_hash": hash_secret(new_secret),
                    "secret_id": new_id,
                    "secret_created_at": now,
                    "secret_expires_at": self._settings.secret_ttl_seconds
                    and now + self._settings.secret_ttl_seconds,
                    "updated_at": now,
                }
            )
            return changes

        try:
            updated = self._storage.mutate_client(client_id, row["version"], apply)
        except VersionConflictError as exc:
            raise RegistrationError(
                ERR_VERSION_CONFLICT,
                "client changed concurrently while rotating the secret",
                409,
            ) from exc
        assert updated is not None
        return {
            "client_id": client_id,
            "secret_id": new_id,
            "client_secret": new_secret,
            "secret_expires_at": updated["secret_expires_at"],
            "old_secret_id": updated.get("old_secret_id"),
            "old_secret_expires_at": updated.get("old_secret_expires_at"),
            "version": updated["version"],
        }

    def revoke_secret(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        token = _require_statement(payload)
        secret_id = payload.get("secret_id")
        if secret_id is not None and not isinstance(secret_id, str):
            from app.errors import ERR_INVALID_REQUEST

            raise RegistrationError(ERR_INVALID_REQUEST, "'secret_id' must be a string", 400)
        claims = self._verify(token)
        row = self._load_live(client_id)
        self._check_ownership(row, claims)

        target_old = secret_id is not None and secret_id == row.get("old_secret_id")
        if secret_id is not None and secret_id != row.get("secret_id") and not target_old:
            from app.errors import ERR_NO_ACTIVE_SECRET

            raise RegistrationError(
                ERR_NO_ACTIVE_SECRET, f"no such secret for client: {secret_id!r}", 404
            )

        now = time.time()
        if target_old:
            overrides = {
                "old_secret_hash": None,
                "old_secret_id": None,
                "old_secret_expires_at": None,
                "updated_at": now,
            }
        else:
            overrides = {
                "secret_hash": None,
                "secret_id": None,
                "secret_created_at": None,
                "secret_expires_at": None,
                "old_secret_hash": None,
                "old_secret_id": None,
                "old_secret_expires_at": None,
                "updated_at": now,
            }
        try:
            updated = self._storage.mutate_client(client_id, row["version"], lambda _c: overrides)
        except VersionConflictError as exc:
            raise RegistrationError(
                ERR_VERSION_CONFLICT,
                "client changed concurrently while revoking the secret",
                409,
            ) from exc
        assert updated is not None
        return _public_view(updated)

    # --------------------------------------------------------------- lifecycle

    def transition_state(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        token = _require_statement(payload)
        target = payload.get("target_state")
        if not isinstance(target, str) or not is_known_state(target):
            from app.errors import ERR_INVALID_STATE_TRANSITION

            raise RegistrationError(
                ERR_INVALID_STATE_TRANSITION, "'target_state' is invalid", 400
            )
        expected_version = payload.get("expected_version")
        if expected_version is not None and (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
        ):
            from app.errors import ERR_INVALID_REQUEST

            raise RegistrationError(
                ERR_INVALID_REQUEST, "'expected_version' must be a positive integer", 400
            )
        claims = self._verify(token)
        row = self._load_live(client_id)
        self._check_ownership(row, claims)
        ensure_transition(row["state"], target)

        now = time.time()
        overrides: dict[str, Any] = {"state": target, "updated_at": now}
        if target == "revoked":
            # Revocation immediately invalidates all secrets.
            overrides.update(
                secret_hash=None,
                secret_id=None,
                secret_created_at=None,
                secret_expires_at=None,
                old_secret_hash=None,
                old_secret_id=None,
                old_secret_expires_at=None,
            )
        try:
            updated = self._storage.mutate_client(
                client_id, expected_version, lambda _c: overrides
            )
        except VersionConflictError as exc:
            raise RegistrationError(
                ERR_VERSION_CONFLICT,
                "client changed concurrently while transitioning state",
                409,
            ) from exc
        assert updated is not None
        return _public_view(updated)

    def recover(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Independent recovery flow for revoked clients.

        The statement's owner must additionally present the matching
        ``software_id``; recovery lands the client in ``suspended`` (never
        straight back to ``active``) and issues no secret.
        """
        token = _require_statement(payload)
        claims = self._verify(token)
        row = self._load_live(client_id)
        self._check_ownership(row, claims)
        target = recovery_target(row["state"])  # raises unless recoverable
        now = time.time()
        try:
            updated = self._storage.mutate_client(
                client_id,
                payload.get("expected_version"),
                lambda _c: {"state": target, "updated_at": now},
            )
        except VersionConflictError as exc:
            raise RegistrationError(
                ERR_VERSION_CONFLICT,
                "client changed concurrently during recovery",
                409,
            ) from exc
        assert updated is not None
        return _public_view(updated)

    # ------------------------------------------------------------------ queries

    def get(self, client_id: str) -> dict[str, Any]:
        return _public_view(self._load_live(client_id))

    def list_clients(self, params: dict[str, Any]) -> dict[str, Any]:
        limit = params.get("limit")
        if limit is None:
            limit = self._settings.default_page_size
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            from app.errors import ERR_INVALID_REQUEST

            raise RegistrationError(ERR_INVALID_REQUEST, "'limit' must be a positive integer", 400)
        limit = min(limit, self._settings.max_page_size)

        cursor = params.get("cursor")
        created_at, cursor_id = (None, None)
        if cursor:
            created_at, cursor_id = _decode_cursor(cursor)

        filters = {
            "state": params.get("state"),
            "issuer": params.get("issuer"),
            "grant_type": params.get("grant_type"),
        }
        for name, value in list(filters.items()):
            if value is not None and not isinstance(value, str):
                from app.errors import ERR_INVALID_REQUEST

                raise RegistrationError(
                    ERR_INVALID_REQUEST, f"filter {name!r} must be a string", 400
                )
        if filters["state"] is not None and not is_known_state(filters["state"]):
            from app.errors import ERR_INVALID_STATE_TRANSITION

            raise RegistrationError(
                ERR_INVALID_STATE_TRANSITION, "unknown state filter", 400
            )

        items, next_keyset = self._storage.list_clients(
            limit=limit,
            cursor_created_at=created_at,
            cursor_client_id=cursor_id,
            state=filters["state"],
            issuer=filters["issuer"],
            grant_type=filters["grant_type"],
        )
        next_cursor = None
        if next_keyset is not None:
            next_cursor = _encode_cursor(
                next_keyset["created_at"], next_keyset["client_id"]
            )
        return {
            "items": [_public_view(row) for row in items],
            "next_cursor": next_cursor,
            "limit": limit,
        }


def _require_statement(payload: dict[str, Any]) -> str:
    from app.errors import ERR_INVALID_REQUEST

    if not isinstance(payload, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "request body must be a JSON object", 400)
    token = payload.get("software_statement")
    if not isinstance(token, str) or not token:
        raise RegistrationError(
            ERR_INVALID_REQUEST, "'software_statement' is required", 400
        )
    return token
