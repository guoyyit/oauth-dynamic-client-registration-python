"""Application services: registration, update, secrets, lifecycle, listing.

All persistence mutations happen only *after* the software statement and
metadata have been fully validated, and each mutating flow is serialized on
the repository write lock, so failed/illegal requests never leave partial
state behind.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Settings
from .errors import DCR, ErrorCode
from .models import Client, ClientPage, ClientSecret, ClientState, SecretStatus, STATE_TRANSITIONS
from .repository import (
    ClientRepository,
    ConcurrentUpdateError,
    DuplicateClientError,
    utcnow_iso,
)
from .schemas import decode_cursor, encode_cursor
from .secrets_util import generate_client_secret, hash_secret
from .tokens import verify_software_statement
from .validation import assert_statement_owns_client, validate_metadata
from .models import SoftwareStatement


@dataclass
class OperationResult:
    client: Client
    status_code: int = 200
    secret_plain: str | None = None
    secret_expires_at: str | None = None

    @property
    def has_secret(self) -> bool:
        return self.secret_plain is not None


def _iso_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="microseconds")


class ClientService:
    def __init__(self, settings: Settings, repository: ClientRepository):
        self._settings = settings
        self._repo = repository
        # Second line of defence after DB constraints: serialize the
        # check-then-act registration window inside this process.
        self._register_lock = threading.Lock()

    # ---------------------------------------------------------------- helpers
    def _verify(self, payload: dict, *, now: int | None = None) -> SoftwareStatement:
        if not isinstance(payload, dict):
            raise DCR(ErrorCode.INVALID_REQUEST, "request body must be a JSON object", status_code=400)
        token = payload.get("software_statement")
        if not token:
            raise DCR(
                ErrorCode.INVALID_SOFTWARE_STATEMENT,
                "software_statement is required",
                status_code=400,
            )
        return verify_software_statement(token, self._settings, now=now)

    def _load_or_404(self, client_id: str) -> Client:
        client = self._repo.get(client_id)
        if client is None:
            raise DCR(ErrorCode.CLIENT_NOT_FOUND, f"unknown client_id: {client_id}", status_code=404)
        return client

    def _make_secret(self, client_id: str, ttl_seconds: int) -> tuple[ClientSecret, str, str]:
        plain = generate_client_secret()
        salt, digest = hash_secret(plain, iterations=self._settings.pbkdf2_iterations)
        expires = _iso_from_epoch(_now_epoch() + ttl_seconds) if ttl_seconds > 0 else None
        record = ClientSecret(
            id=0,
            client_id=client_id,
            secret_hash=digest,
            salt=salt,
            iterations=self._settings.pbkdf2_iterations,
            status=SecretStatus.CURRENT,
            expires_at=expires,
            created_at=utcnow_iso(),
        )
        return record, plain, expires

    # ------------------------------------------------------------ registration
    def register(self, payload: dict, *, now: int | None = None) -> OperationResult:
        statement = self._verify(payload, now=now)
        metadata = validate_metadata(statement.metadata, self._settings)

        # An explicit client_id claim is honored; otherwise a fresh random one
        # is minted. Either way both client_id and software_id are UNIQUE.
        client_id = statement.client_id or secrets.token_urlsafe(18)
        timestamp = utcnow_iso()

        with self._register_lock:
            by_software = self._repo.get_by_software_id(statement.software_id)
            if by_software is not None:
                # Idempotent replay: same statement token -> exact replay;
                # a different token for the same software identity is a
                # conflict, never a silent overwrite.
                if by_software.jti == statement.jti:
                    return OperationResult(client=by_software, status_code=200)
                raise DCR(
                    ErrorCode.DUPLICATE_CLIENT,
                    f"software_id {statement.software_id!r} is already registered "
                    f"as {by_software.client_id!r}",
                    status_code=409,
                )

            by_client = self._repo.get(client_id)
            if by_client is not None:
                raise DCR(
                    ErrorCode.DUPLICATE_CLIENT,
                    f"client_id {client_id!r} is already registered to another software statement",
                    status_code=409,
                )

            client = Client(
                client_id=client_id,
                software_id=statement.software_id,
                issuer=statement.iss,
                state=ClientState.ACTIVE,
                version=1,
                redirect_uris=metadata["redirect_uris"],
                grant_types=metadata["grant_types"],
                response_types=metadata["response_types"],
                token_endpoint_auth_method=metadata["token_endpoint_auth_method"],
                scope=metadata["scope"],
                client_name=metadata["client_name"],
                jti=statement.jti,
                created_at=timestamp,
                updated_at=timestamp,
            )

            issued_secret: tuple[ClientSecret, str, str] | None = None
            if metadata["token_endpoint_auth_method"] != "none":
                issued_secret = self._make_secret(client_id, self._settings.secret_ttl_seconds)

            try:
                stored = self._repo.insert_client(client, issued_secret[0] if issued_secret else None)
            except DuplicateClientError:
                # Concurrent registrant won the UNIQUE race. Resolve to one
                # canonical record with a consistent, explainable result.
                winner = self._repo.get_by_software_id(statement.software_id)
                if winner is not None:
                    if winner.jti == statement.jti:
                        return OperationResult(client=winner, status_code=200)
                    code = ErrorCode.DUPLICATE_CLIENT
                    message = (
                        f"concurrent registration for software_id {statement.software_id!r} "
                        "arrived with a different software statement"
                    )
                else:
                    winner = self._repo.get(client_id)
                    code = ErrorCode.DUPLICATE_CLIENT
                    message = f"concurrent registration already claimed client_id {client_id!r}"
                raise DCR(code, message, status_code=409)

            return OperationResult(
                client=stored,
                status_code=201,
                secret_plain=issued_secret[1] if issued_secret else None,
                secret_expires_at=issued_secret[2] if issued_secret else None,
            )

    # ------------------------------------------------------------------ update
    def update(self, client_id: str, payload: dict, *, now: int | None = None) -> OperationResult:
        statement = self._verify(payload, now=now)
        existing = self._load_or_404(client_id)
        assert_statement_owns_client(statement, existing.software_id, existing.issuer)

        if existing.state in (ClientState.REVOKED, ClientState.DELETED):
            raise DCR(
                ErrorCode.CLIENT_REVOKED if existing.state is ClientState.REVOKED
                else ErrorCode.INVALID_STATE_TRANSITION,
                "a revoked/deleted client cannot be updated; use the recovery flow for revoked clients",
                status_code=409,
            )

        expected_version = payload.get("version")
        if not isinstance(expected_version, int) or isinstance(expected_version, bool):
            raise DCR(ErrorCode.INVALID_REQUEST, "'version' (integer) is required for conditional updates", 400)

        # Validate *before* any write: illegal metadata cannot disturb state.
        metadata = validate_metadata(statement.metadata, self._settings)

        updated = Client(
            client_id=existing.client_id,
            software_id=existing.software_id,
            issuer=existing.issuer,
            state=existing.state,
            version=expected_version,
            redirect_uris=metadata["redirect_uris"],
            grant_types=metadata["grant_types"],
            response_types=metadata["response_types"],
            token_endpoint_auth_method=metadata["token_endpoint_auth_method"],
            scope=metadata["scope"],
            client_name=metadata["client_name"],
            jti=statement.jti,
            created_at=existing.created_at,
            updated_at=utcnow_iso(),
        )
        try:
            stored = self._repo.update_client(updated, expected_version)
        except ConcurrentUpdateError:
            current = self._load_or_404(client_id)
            raise DCR(
                ErrorCode.VERSION_CONFLICT,
                f"version {expected_version} is stale; current version is {current.version}",
                status_code=409,
            )
        return OperationResult(client=stored, status_code=200)

    # ----------------------------------------------------------------- secrets
    def rotate_secret(
        self,
        client_id: str,
        payload: dict,
        *,
        now: int | None = None,
    ) -> OperationResult:
        statement = self._verify(payload, now=now)
        existing = self._load_or_404(client_id)
        assert_statement_owns_client(statement, existing.software_id, existing.issuer)

        if existing.state is not ClientState.ACTIVE:
            raise DCR(
                ErrorCode.SECRET_ROTATION_REJECTED,
                f"secret rotation requires an active client (state={existing.state.value})",
                status_code=409,
            )
        if existing.token_endpoint_auth_method == "none":
            raise DCR(
                ErrorCode.SECRET_ROTATION_REJECTED,
                "public clients (token_endpoint_auth_method='none') have no secret to rotate",
                status_code=409,
            )

        retire_previous = bool(payload.get("revoke_previous", False))
        record, plain, expires = self._make_secret(client_id, self._settings.secret_ttl_seconds)
        if retire_previous:
            previous_expires = None
        else:
            overlap_epoch = _now_epoch() + self._settings.overlap_ttl_seconds
            previous_expires = _iso_from_epoch(overlap_epoch)

        try:
            self._repo.rotate_secret(
                client_id, record,
                retire_previous=retire_previous,
                previous_expires_at=previous_expires,
            )
        except Exception as exc:  # pragma: no cover - defensive, no partial writes
            raise DCR(ErrorCode.INTERNAL_ERROR, "secret rotation failed", status_code=500) from exc
        refreshed = self._load_or_404(client_id)
        return OperationResult(
            client=refreshed, status_code=200, secret_plain=plain, secret_expires_at=expires
        )

    def revoke_secret(self, client_id: str, payload: dict, *, now: int | None = None) -> OperationResult:
        statement = self._verify(payload, now=now)
        existing = self._load_or_404(client_id)
        assert_statement_owns_client(statement, existing.software_id, existing.issuer)
        self._repo.revoke_secrets(client_id)
        return OperationResult(client=self._load_or_404(client_id), status_code=200)

    # --------------------------------------------------------------- lifecycle
    def transition(
        self,
        client_id: str,
        target: ClientState,
        payload: dict,
        *,
        now: int | None = None,
    ) -> OperationResult:
        statement = self._verify(payload, now=now)
        existing = self._load_or_404(client_id)
        assert_statement_owns_client(statement, existing.software_id, existing.issuer)

        if target not in STATE_TRANSITIONS[existing.state]:
            raise DCR(
                ErrorCode.INVALID_STATE_TRANSITION,
                f"illegal transition {existing.state.value} -> {target.value}",
                status_code=409,
            )

        expected_version = payload.get("version", existing.version)
        if not isinstance(expected_version, int) or isinstance(expected_version, bool):
            raise DCR(ErrorCode.INVALID_REQUEST, "'version' must be an integer", 400)

        if target is ClientState.REVOKED:
            # Revocation is security-sensitive: secrets die with the client.
            self._repo.revoke_secrets(client_id)

        try:
            stored = self._repo.transition_state(client_id, target, expected_version)
        except ConcurrentUpdateError:
            current = self._load_or_404(client_id)
            raise DCR(
                ErrorCode.VERSION_CONFLICT,
                f"version {expected_version} is stale; current version is {current.version}",
                status_code=409,
            )
        return OperationResult(client=stored, status_code=200)

    def recover(self, client_id: str, payload: dict, *, now: int | None = None) -> OperationResult:
        """Independent recovery flow for revoked clients.

        Deliberately distinct from the normal update path: only clients in
        ``revoked`` state are eligible, the caller must prove ownership with a
        fresh software statement and explicitly assert ``"recover": true``,
        and a brand-new secret is issued so that revoked credentials can never
        be resurrected.
        """
        statement = self._verify(payload, now=now)
        existing = self._load_or_404(client_id)
        assert_statement_owns_client(statement, existing.software_id, existing.issuer)

        if existing.state is not ClientState.REVOKED:
            raise DCR(
                ErrorCode.INVALID_STATE_TRANSITION,
                f"recovery only applies to revoked clients (state={existing.state.value})",
                status_code=409,
            )
        if payload.get("recover") is not True:
            raise DCR(
                ErrorCode.INVALID_REQUEST,
                "recovery requires an explicit \"recover\": true assertion",
                status_code=400,
            )

        # Revoked -> active is intentionally reachable ONLY from this flow.
        try:
            stored = self._repo.transition_state(client_id, ClientState.ACTIVE, existing.version)
        except ConcurrentUpdateError:
            raise DCR(ErrorCode.VERSION_CONFLICT, "client changed concurrently", status_code=409)

        issued: tuple[ClientSecret, str, str] | None = None
        if stored.token_endpoint_auth_method != "none":
            issued = self._make_secret(client_id, self._settings.secret_ttl_seconds)
            self._repo.rotate_secret(
                client_id, issued[0], retire_previous=True, previous_expires_at=None
            )
        refreshed = self._load_or_404(client_id)
        return OperationResult(
            client=refreshed,
            status_code=200,
            secret_plain=issued[1] if issued else None,
            secret_expires_at=issued[2] if issued else None,
        )

    # ----------------------------------------------------------------- queries
    def get(self, client_id: str) -> Client:
        return self._load_or_404(client_id)

    def authenticate(self, client_id: str, secret_plain: str) -> bool:
        client = self._repo.get(client_id)
        if client is None or client.state is not ClientState.ACTIVE:
            return False
        return self._repo.authenticate_secret(client_id, secret_plain)

    def list_clients(
        self,
        *,
        state: str | None = None,
        cursor: str | None = None,
        page_size: int | str | None = None,
    ) -> ClientPage:
        state_filter: ClientState | None = None
        if state is not None:
            try:
                state_filter = ClientState(state)
            except ValueError:
                raise DCR(
                    ErrorCode.INVALID_REQUEST,
                    f"unknown state filter: {state!r}",
                    status_code=400,
                )
        after_rowid = decode_cursor(cursor)
        if page_size is None:
            limit = self._settings.page_size_default
        else:
            try:
                limit = int(page_size)
            except (TypeError, ValueError):
                limit = -1
            if isinstance(page_size, bool):
                limit = -1
        if not isinstance(limit, int) or limit <= 0:
            raise DCR(ErrorCode.INVALID_REQUEST, "page_size must be a positive integer", status_code=400)
        limit = min(limit, self._settings.page_size_max)

        total = self._repo.count_clients(state=state_filter)
        items = self._repo.list_clients(
            state=state_filter, after_rowid=after_rowid, limit=limit + 1
        )
        next_cursor = None
        if len(items) > limit:
            last = items[limit - 1]
            items = items[:limit]
            next_cursor = encode_cursor(self._repo.rowid_of(last.client_id))
        return ClientPage(items=items, next_cursor=next_cursor, total=total)


def _now_epoch() -> int:
    import time

    return int(time.time())
