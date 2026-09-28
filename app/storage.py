"""SQLite-backed persistent storage.

Guarantees provided:

* a partial unique index ensures at most one non-deleted client per
  ``software_id`` (idempotent/unique registration);
* every successful write bumps an integer ``version`` used for optimistic
  concurrency control;
* reads use keyset pagination over immutable ``(created_at, client_id)``
  so concurrent writes never cause duplicate or skipped rows;
* all state lives in SQLite, so a process restart restores it exactly.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Any

_COLUMNS = (
    "client_id",
    "software_id",
    "issuer",
    "metadata_json",
    "state",
    "version",
    "created_at",
    "updated_at",
    "secret_hash",
    "secret_id",
    "secret_created_at",
    "secret_expires_at",
    "old_secret_hash",
    "old_secret_id",
    "old_secret_expires_at",
)


class VersionConflictError(Exception):
    """Raised when a write's expected row version does not match."""

    def __init__(self, current: dict[str, Any]) -> None:
        super().__init__("client version conflict")
        self.current = current


class DuplicateSoftwareError(Exception):
    """Raised when a live client with the same software_id already exists."""

    def __init__(self, existing: dict[str, Any]) -> None:
        super().__init__("duplicate software_id")
        self.existing = existing


class Storage:
    def __init__(self, database_path: str) -> None:
        directory = os.path.dirname(os.path.abspath(database_path))
        os.makedirs(directory, exist_ok=True)
        self._database_path = database_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            database_path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        # busy_timeout must be configured before any statement that can hit a
        # lock (notably journal_mode=WAL during concurrent first connections).
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._set_wal_mode()
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _set_wal_mode(self) -> None:
        # Switching journal mode requires an exclusive checkpoint lock; retry
        # when another connection is initializing the same database.
        for attempt in range(50):
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError:
                if attempt == 49:
                    raise
                time.sleep(0.02)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS clients (
                    client_id            TEXT PRIMARY KEY,
                    software_id          TEXT NOT NULL,
                    issuer               TEXT NOT NULL,
                    metadata_json        TEXT NOT NULL,
                    state                TEXT NOT NULL,
                    version              INTEGER NOT NULL,
                    created_at           REAL NOT NULL,
                    updated_at           REAL NOT NULL,
                    secret_hash          TEXT,
                    secret_id            TEXT,
                    secret_created_at    REAL,
                    secret_expires_at    REAL,
                    old_secret_hash      TEXT,
                    old_secret_id        TEXT,
                    old_secret_expires_at REAL
                )
                """
                )
                self._conn.execute(
                    """
                CREATE UNIQUE INDEX IF NOT EXISTS ux_clients_live_software
                    ON clients(software_id) WHERE state != 'deleted'
                """
                )
                self._conn.execute(
                    """
                CREATE INDEX IF NOT EXISTS ix_clients_created
                    ON clients(created_at, client_id)
                """
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        data["metadata"] = json.loads(data.pop("metadata_json"))
        return data

    def insert_client(self, record: dict[str, Any]) -> dict[str, Any]:
        """Insert a new client; raise DuplicateSoftwareError on conflict."""
        placeholders = ", ".join("?" for _ in _COLUMNS)
        params = (
            record["client_id"],
            record["software_id"],
            record["issuer"],
            json.dumps(record["metadata"], separators=(",", ":"), sort_keys=True),
            record["state"],
            record["version"],
            record["created_at"],
            record["updated_at"],
            record.get("secret_hash"),
            record.get("secret_id"),
            record.get("secret_created_at"),
            record.get("secret_expires_at"),
            record.get("old_secret_hash"),
            record.get("old_secret_id"),
            record.get("old_secret_expires_at"),
        )
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    f"INSERT INTO clients ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
                    params,
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                existing = self.get_client_by_software(record["software_id"])
                if existing is not None:
                    raise DuplicateSoftwareError(existing) from None
                raise
            except Exception:
                self._conn.rollback()
                raise
        stored = self.get_client(record["client_id"])
        assert stored is not None
        return stored

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_client_by_software(self, software_id: str) -> dict[str, Any] | None:
        """Return the single live (non-deleted) client for a software_id."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM clients "
                "WHERE software_id = ? AND state != 'deleted' "
                "ORDER BY created_at DESC, client_id DESC LIMIT 1",
                (software_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def mutate_client(
        self,
        client_id: str,
        expected_version: int | None,
        mutate: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Lock the row, check version, apply *mutate* and bump the version.

        ``mutate`` receives the current row dict and returns a dict of column
        overrides (table column names).  Raising inside it aborts the write.
        Returns ``None`` when the client does not exist.
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM clients WHERE client_id = ?",
                    (client_id,),
                ).fetchone()
                current = self._row_to_dict(row)
                if current is None:
                    self._conn.rollback()
                    return None
                if (
                    expected_version is not None
                    and current["version"] != expected_version
                ):
                    self._conn.rollback()
                    raise VersionConflictError(current)

                overrides = mutate(current)
                new_version = current["version"] + 1
                columns = dict(overrides)
                columns["version"] = new_version
                sets = ", ".join(f"{name} = ?" for name in columns)
                values = [
                    json.dumps(v, separators=(",", ":"), sort_keys=True)
                    if name == "metadata_json"
                    else v
                    for name, v in columns.items()
                ]
                values.append(client_id)
                self._conn.execute(
                    f"UPDATE clients SET {sets} WHERE client_id = ?", values
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.get_client(client_id)

    def list_clients(
        self,
        *,
        limit: int,
        cursor_created_at: float | None = None,
        cursor_client_id: str | None = None,
        state: str | None = None,
        issuer: str | None = None,
        grant_type: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Keyset-ordered listing: (created_at ASC, client_id ASC)."""
        where = ["state != 'deleted'"]
        params: list[Any] = []
        if state is not None:
            where.append("state = ?")
            params.append(state)
        if issuer is not None:
            where.append("issuer = ?")
            params.append(issuer)
        if grant_type is not None:
            where.append(
                "EXISTS (SELECT 1 FROM json_each(json_extract(metadata_json, '$.grant_types')) "
                "WHERE value = ?)"
            )
            params.append(grant_type)
        if cursor_created_at is not None and cursor_client_id is not None:
            where.append("(created_at, client_id) > (?, ?)")
            params.extend([cursor_created_at, cursor_client_id])

        sql = (
            f"SELECT {', '.join(_COLUMNS)} FROM clients "
            f"WHERE {' AND '.join(where)} "
            "ORDER BY created_at ASC, client_id ASC LIMIT ?"
        )
        params.append(limit + 1)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        items = [self._row_to_dict(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit:
            last = items[-1]
            next_cursor = {
                "created_at": last["created_at"],
                "client_id": last["client_id"],
            }
        return items, next_cursor
