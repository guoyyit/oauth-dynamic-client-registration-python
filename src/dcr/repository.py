"""SQLite-backed persistence with atomic registration and optimistic locking.

Concurrency strategy:

* A process-wide :class:`threading.RLock` serializes write transactions within
  the service process (tests hammer the API from many threads).
* SQLite ``UNIQUE`` constraints on ``client_id`` and ``software_id`` plus a
  partial unique index guaranteeing a single ``current`` secret provide
  cross-process safety.
* Metadata updates use compare-and-swap on the integer ``version`` column.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

from .config import Settings
from .models import Client, ClientSecret, ClientState, SecretStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id                   TEXT PRIMARY KEY,
    software_id                 TEXT NOT NULL UNIQUE,
    issuer                      TEXT NOT NULL,
    jti                         TEXT NOT NULL,
    state                       TEXT NOT NULL,
    version                     INTEGER NOT NULL DEFAULT 1,
    redirect_uris               TEXT NOT NULL,
    grant_types                 TEXT NOT NULL,
    response_types              TEXT NOT NULL,
    token_endpoint_auth_method  TEXT NOT NULL,
    scope                       TEXT NOT NULL,
    client_name                 TEXT NOT NULL DEFAULT '',
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_secrets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    secret_hash  TEXT NOT NULL,
    salt         TEXT NOT NULL,
    iterations   INTEGER NOT NULL,
    status       TEXT NOT NULL,
    expires_at   TEXT,
    created_at   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_one_current
    ON client_secrets(client_id) WHERE status = 'current';
CREATE INDEX IF NOT EXISTS idx_secrets_client ON client_secrets(client_id);
CREATE INDEX IF NOT EXISTS idx_clients_listing ON clients(created_at, client_id);
CREATE INDEX IF NOT EXISTS idx_clients_state ON clients(state);
"""


def utcnow_iso() -> str:
    """Monotonic-ish, lexicographically sortable UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class DuplicateClientError(Exception):
    """UNIQUE constraint hit while inserting a client."""


class ConcurrentUpdateError(Exception):
    """Compare-and-swap on version affected zero rows."""


class ClientRepository:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle -----------------------------------------------------------
    def initialize(self) -> None:
        """Open the database file and create schema if missing."""
        db_path = self._settings.database_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        self._conn = conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("repository not initialized")
        return self._conn

    # -- row mapping ---------------------------------------------------------
    @staticmethod
    def _row_to_client(row: sqlite3.Row, secret_row: sqlite3.Row | None) -> Client:
        secret = None
        if secret_row is not None:
            secret = ClientSecret(
                id=secret_row["id"],
                client_id=secret_row["client_id"],
                secret_hash=secret_row["secret_hash"],
                salt=secret_row["salt"],
                iterations=secret_row["iterations"],
                status=SecretStatus(secret_row["status"]),
                expires_at=secret_row["expires_at"],
                created_at=secret_row["created_at"],
            )
        return Client(
            client_id=row["client_id"],
            software_id=row["software_id"],
            issuer=row["issuer"],
            state=ClientState(row["state"]),
            version=row["version"],
            redirect_uris=json.loads(row["redirect_uris"]),
            grant_types=json.loads(row["grant_types"]),
            response_types=json.loads(row["response_types"]),
            token_endpoint_auth_method=row["token_endpoint_auth_method"],
            scope=row["scope"],
            client_name=row["client_name"],
            jti=row["jti"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            secret=secret,
        )

    def _load_secret(self, client_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM client_secrets WHERE client_id = ? AND status = 'current'",
            (client_id,),
        ).fetchone()

    def _hydrate(self, row: sqlite3.Row) -> Client:
        return self._row_to_client(row, self._load_secret(row["client_id"]))

    # -- reads ---------------------------------------------------------------
    def get(self, client_id: str) -> Client | None:
        row = self.connection.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return self._hydrate(row) if row else None

    def get_by_software_id(self, software_id: str) -> Client | None:
        row = self.connection.execute(
            "SELECT * FROM clients WHERE software_id = ?", (software_id,)
        ).fetchone()
        return self._hydrate(row) if row else None

    def count_clients(self, *, state: ClientState | None = None) -> int:
        """Total rows matching the filter, independent of pagination cursor."""
        if state is None:
            return self.connection.execute("SELECT COUNT(*) AS c FROM clients").fetchone()["c"]
        return self.connection.execute(
            "SELECT COUNT(*) AS c FROM clients WHERE state = ?", (state.value,)
        ).fetchone()["c"]

    def list_clients(
        self,
        *,
        state: ClientState | None = None,
        after_rowid: int | None = None,
        limit: int = 50,
    ) -> list[Client]:
        """Stable keyset order over the monotonic insert ``rowid``.

        Rowids are assigned in insertion order, so rows committed while a
        client pages through results can never be skipped or repeated.
        """
        clauses: list[str] = []
        params: list[object] = []
        if state is not None:
            clauses.append("state = ?")
            params.append(state.value)
        if after_rowid is not None:
            clauses.append("rowid > ?")
            params.append(after_rowid)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        rows = self.connection.execute(
            f"SELECT * FROM clients {where} ORDER BY rowid ASC LIMIT ?",
            [*params, limit],
        ).fetchall()
        return [self._hydrate(row) for row in rows]

    def rowid_of(self, client_id: str) -> int:
        row = self.connection.execute("SELECT rowid FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            raise KeyError(client_id)
        return int(row["rowid"])

    # -- writes --------------------------------------------------------------
    def insert_client(self, client: Client, secret: ClientSecret | None) -> Client:
        """Atomic insert of client (+ optional initial secret)."""
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute(
                    """INSERT INTO clients(
                        client_id, software_id, issuer, jti, state, version,
                        redirect_uris, grant_types, response_types,
                        token_endpoint_auth_method, scope, client_name,
                        created_at, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        client.client_id,
                        client.software_id,
                        client.issuer,
                        client.jti,
                        client.state.value,
                        client.version,
                        json.dumps(client.redirect_uris),
                        json.dumps(client.grant_types),
                        json.dumps(client.response_types),
                        client.token_endpoint_auth_method,
                        client.scope,
                        client.client_name,
                        client.created_at,
                        client.updated_at,
                    ),
                )
                if secret is not None:
                    self.connection.execute(
                        """INSERT INTO client_secrets(
                            client_id, secret_hash, salt, iterations, status, expires_at, created_at
                        ) VALUES (?,?,?,?,?,?,?)""",
                        (
                            client.client_id,
                            secret.secret_hash,
                            secret.salt,
                            secret.iterations,
                            secret.status.value,
                            secret.expires_at,
                            secret.created_at,
                        ),
                    )
                self.connection.execute("COMMIT")
            except sqlite3.IntegrityError:
                self.connection.execute("ROLLBACK")
                raise DuplicateClientError(client.client_id)
        stored = self.get(client.client_id)
        assert stored is not None
        return stored

    def update_client(self, client: Client, expected_version: int) -> Client:
        """Compare-and-swap on version; raise ConcurrentUpdateError on mismatch."""
        timestamp = utcnow_iso()
        with self._lock:
            cur = self.connection.execute(
                """UPDATE clients SET
                       issuer = ?, jti = ?, redirect_uris = ?, grant_types = ?,
                       response_types = ?, token_endpoint_auth_method = ?,
                       scope = ?, client_name = ?, updated_at = ?,
                       version = version + 1
                 WHERE client_id = ? AND version = ?""",
                (
                    client.issuer,
                    client.jti,
                    json.dumps(client.redirect_uris),
                    json.dumps(client.grant_types),
                    json.dumps(client.response_types),
                    client.token_endpoint_auth_method,
                    client.scope,
                    client.client_name,
                    timestamp,
                    client.client_id,
                    expected_version,
                ),
            )
            if cur.rowcount == 0:
                raise ConcurrentUpdateError(client.client_id)
        stored = self.get(client.client_id)
        assert stored is not None
        return stored

    def transition_state(self, client_id: str, target: ClientState, expected_version: int) -> Client:
        timestamp = utcnow_iso()
        with self._lock:
            cur = self.connection.execute(
                """UPDATE clients SET state = ?, updated_at = ?, version = version + 1
                 WHERE client_id = ? AND version = ?""",
                (target.value, timestamp, client_id, expected_version),
            )
            if cur.rowcount == 0:
                raise ConcurrentUpdateError(client_id)
        stored = self.get(client_id)
        assert stored is not None
        return stored

    def rotate_secret(self, client_id: str, new_secret: ClientSecret, *, retire_previous: bool,
                      previous_expires_at: str | None = None) -> None:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                if retire_previous:
                    # Immediate cut-over: every old credential dies at once.
                    self.connection.execute(
                        "UPDATE client_secrets SET status = 'revoked' "
                        "WHERE client_id = ? AND status != 'revoked'",
                        (client_id,),
                    )
                else:
                    # Overlap policy: the previous current stays usable for a
                    # bounded grace window; older overlaps are retired so that
                    # at most one 'previous' secret ever exists.
                    self.connection.execute(
                        "UPDATE client_secrets SET status = 'revoked' "
                        "WHERE client_id = ? AND status = 'previous'",
                        (client_id,),
                    )
                    self.connection.execute(
                        "UPDATE client_secrets SET status = 'previous', "
                        "expires_at = COALESCE(?, expires_at) "
                        "WHERE client_id = ? AND status = 'current'",
                        (previous_expires_at, client_id),
                    )
                self.connection.execute(
                    """INSERT INTO client_secrets(
                        client_id, secret_hash, salt, iterations, status, expires_at, created_at
                    ) VALUES (?,?,?,?,?,?,?)""",
                    (
                        client_id,
                        new_secret.secret_hash,
                        new_secret.salt,
                        new_secret.iterations,
                        SecretStatus.CURRENT.value,
                        new_secret.expires_at,
                        new_secret.created_at,
                    ),
                )
                self.connection.execute(
                    "UPDATE clients SET updated_at = ? WHERE client_id = ?",
                    (utcnow_iso(), client_id),
                )
                self.connection.execute("COMMIT")
            except sqlite3.IntegrityError:
                self.connection.execute("ROLLBACK")
                raise

    def revoke_secrets(self, client_id: str) -> None:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute(
                    "UPDATE client_secrets SET status = ? WHERE client_id = ? AND status != ?",
                    (SecretStatus.REVOKED.value, client_id, SecretStatus.REVOKED.value),
                )
                self.connection.execute(
                    "UPDATE clients SET updated_at = ? WHERE client_id = ?",
                    (utcnow_iso(), client_id),
                )
                self.connection.execute("COMMIT")
            except sqlite3.Error:
                self.connection.execute("ROLLBACK")
                raise

    def authenticate_secret(self, client_id: str, secret_plain: str) -> bool:
        """Verify a presented secret against current or not-yet-expired previous."""
        from .secrets_util import verify_secret

        rows = self.connection.execute(
            "SELECT * FROM client_secrets WHERE client_id = ? AND status IN ('current','previous')",
            (client_id,),
        ).fetchall()
        now = utcnow_iso()
        for r in rows:
            if r["expires_at"] is not None and r["expires_at"] <= now:
                continue
            if verify_secret(secret_plain, r["salt"], r["secret_hash"], r["iterations"]):
                return True
        return False

    def list_secrets(self, client_id: str) -> list[ClientSecret]:
        rows = self.connection.execute(
            "SELECT * FROM client_secrets WHERE client_id = ? ORDER BY id", (client_id,)
        ).fetchall()
        return [
            ClientSecret(
                id=r["id"],
                client_id=r["client_id"],
                secret_hash=r["secret_hash"],
                salt=r["salt"],
                iterations=r["iterations"],
                status=SecretStatus(r["status"]),
                expires_at=r["expires_at"],
                created_at=r["created_at"],
            )
            for r in rows
        ]
