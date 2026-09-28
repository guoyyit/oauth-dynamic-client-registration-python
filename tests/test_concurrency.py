"""Concurrent registration uniqueness and concurrent update conflict tests."""

from __future__ import annotations

import threading

import pytest

from app.config import Settings
from app.errors import RegistrationError
from app.service import ClientService
from app.storage import Storage


def _settings(db_path: str) -> Settings:
    return Settings(
        database_path=db_path,
        issuer_secrets={"issuer-a": "test-issuer-secret"},
        trusted_audience="test-dcr",
    )


def _run_threads(workers: list, count: int) -> None:
    """Start *count* workers behind a barrier; failures never hang the run."""
    barrier = threading.Barrier(count)
    exceptions: list[BaseException] = []

    def target(worker) -> None:
        try:
            barrier.wait()
            worker()
        except BaseException as exc:  # noqa: BLE001 - propagate after join
            exceptions.append(exc)

    threads = [threading.Thread(target=target, args=(w,)) for w in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "worker thread hung"
    assert exceptions == []


def test_concurrent_registration_creates_single_record(tmp_path, statement) -> None:
    db_path = str(tmp_path / "c.db")
    settings = _settings(db_path)
    thread_count = 12
    body = {
        "software_statement": statement("sw-race"),
        "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
    }

    # Open every connection on the main thread before racing on writes.
    services = [ClientService(Storage(db_path), settings) for _ in range(thread_count)]
    results: list[tuple] = []
    lock = threading.Lock()

    def make_worker(service: ClientService):
        def worker() -> None:
            view, issue, created = service.register(body)
            with lock:
                results.append((view["client_id"], created, bool(issue)))
        return worker

    _run_threads([make_worker(s) for s in services], thread_count)

    assert len(results) == thread_count
    client_ids = {cid for cid, _, _ in results}
    assert len(client_ids) == 1, results
    created_flags = [created for _, created, _ in results]
    assert created_flags.count(True) == 1
    assert created_flags.count(False) == thread_count - 1
    assert [had_secret for _, _, had_secret in results].count(True) == 1

    audit = Storage(db_path)
    try:
        rows, cursor = audit.list_clients(limit=100)
        assert cursor is None and len(rows) == 1
    finally:
        audit.close()
    for service in services:
        service._storage.close()


def test_concurrent_updates_only_one_succeeds(tmp_path, statement) -> None:
    db_path = str(tmp_path / "u.db")
    settings = _settings(db_path)
    bootstrap = ClientService(Storage(db_path), settings)
    view, _, created = bootstrap.register(
        {
            "software_statement": statement("sw-upd"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        }
    )
    assert created
    cid = view["client_id"]

    thread_count = 8
    services = [ClientService(Storage(db_path), settings) for _ in range(thread_count)]
    outcomes: list[str] = []
    lock = threading.Lock()

    def make_worker(service: ClientService, index: int):
        def worker() -> None:
            try:
                service.update(
                    cid,
                    {
                        "software_statement": statement("sw-upd"),
                        "expected_version": 1,
                        "metadata": {"client_name": f"name-{index}"},
                    },
                )
                with lock:
                    outcomes.append("ok")
            except RegistrationError as exc:
                with lock:
                    outcomes.append(exc.code)
        return worker

    _run_threads(
        [make_worker(s, i) for i, s in enumerate(services)], thread_count
    )

    assert outcomes.count("ok") == 1, outcomes
    assert outcomes.count("version_conflict") == thread_count - 1

    audit = ClientService(Storage(db_path), settings)
    final = audit.get(cid)
    assert final["version"] == 2
    assert final["metadata"]["client_name"].startswith("name-")
    for service in services:
        service._storage.close()
    bootstrap._storage.close()
    audit._storage.close()


def test_concurrent_rotations_serialize_and_keep_integrity(tmp_path, statement) -> None:
    db_path = str(tmp_path / "r.db")
    settings = _settings(db_path)
    bootstrap = ClientService(Storage(db_path), settings)
    view, _, _ = bootstrap.register(
        {
            "software_statement": statement("sw-rot"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        }
    )
    cid = view["client_id"]

    services = [ClientService(Storage(db_path), settings) for _ in range(6)]

    def make_worker(service: ClientService):
        def worker() -> None:
            try:
                service.rotate_secret(
                    cid,
                    {
                        "software_statement": statement("sw-rot"),
                        "retain_old_secret": False,
                    },
                )
            except RegistrationError:
                pass
        return worker

    _run_threads([make_worker(s) for s in services], 6)

    audit = Storage(db_path)
    try:
        row = audit.get_client(cid)
        assert row["version"] >= 2
        assert row["secret_hash"] is not None
        assert row["old_secret_hash"] is None
    finally:
        audit.close()
    for service in services:
        service._storage.close()
    bootstrap._storage.close()
