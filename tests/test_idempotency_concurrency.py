"""Requirement 2: idempotent registration; duplicate/concurrent uniqueness."""

from __future__ import annotations

import threading

from dcr.errors import ErrorCode
from dcr.tokens import issue_software_statement

SIGNING_SECRET = "test-signing-secret"


def _token(software_id, **overrides):
    claims = {"software_id": software_id, "metadata": {"redirect_uris": ["https://a/cb"]}}
    claims.update(overrides)
    return issue_software_statement(claims, secret=SIGNING_SECRET)


def test_identical_payload_is_idempotent(client):
    token = _token("sw-idem")
    r1 = client.post("/register", json={"software_statement": token})
    r2 = client.post("/register", json={"software_statement": token})
    assert r1.status_code == 201
    assert r2.status_code == 200
    assert r1.json()["client_id"] == r2.json()["client_id"]
    assert "client_secret" not in r2.json()  # secret shown only on creation


def test_distinct_statement_same_software_id_conflicts(client):
    r1 = client.post("/register", json={"software_statement": _token("sw-dup")})
    assert r1.status_code == 201
    r2 = client.post("/register", json={"software_statement": _token("sw-dup")})
    assert r2.status_code == 409
    body = r2.json()
    assert body["error"] == ErrorCode.DUPLICATE_CLIENT
    assert r1.json()["client_id"] in body["error_description"]


def test_explicit_client_id_collision_conflicts(client):
    t1 = _token("sw-a", client_id="fixed-id")
    t2 = _token("sw-b", client_id="fixed-id")
    r1 = client.post("/register", json={"software_statement": t1})
    r2 = client.post("/register", json={"software_statement": t2})
    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == ErrorCode.DUPLICATE_CLIENT
    # only the winner exists
    assert client.get("/clients/fixed-id").json()["software_id"] == "sw-a"


def test_concurrent_identical_registration_creates_single_record(client):
    token = _token("sw-concurrent")
    results: list = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        results.append(client.post("/register", json={"software_statement": token}))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r.status_code == 201]
    replays = [r for r in results if r.status_code == 200]
    assert len(created) == 1
    assert len(replays) == 15
    ids = {r.json()["client_id"] for r in results}
    assert ids == {created[0].json()["client_id"]}
    assert client.get("/clients").json()["total"] == 1


def test_concurrent_distinct_statements_same_software_id_one_winner(client):
    tokens = [_token("sw-race") for _ in range(20)]
    results: list = []
    barrier = threading.Barrier(20)

    def worker(tok):
        barrier.wait()
        results.append(client.post("/register", json={"software_statement": tok}))

    threads = [threading.Thread(target=worker, args=(tok,)) for tok in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = sorted(r.status_code for r in results)
    assert statuses.count(201) == 1
    assert statuses.count(409) == 19
    assert client.get("/clients").json()["total"] == 1
    winner = next(r for r in results if r.status_code == 201).json()
    losers = [r for r in results if r.status_code == 409]
    assert all(winner["client_id"] in r.json()["error_description"] or "concurrent" in r.json()["error_description"]
               for r in losers)


def test_concurrent_distinct_software_ids_all_registered(client):
    tokens = [_token(f"sw-ind-{i}") for i in range(30)]
    barrier = threading.Barrier(30)
    results: list = []

    def worker(tok):
        barrier.wait()
        results.append(client.post("/register", json={"software_statement": tok}))

    threads = [threading.Thread(target=worker, args=(tok,)) for tok in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r.status_code == 201 for r in results)
    assert len({r.json()["client_id"] for r in results}) == 30
    assert client.get("/clients").json()["total"] == 30
