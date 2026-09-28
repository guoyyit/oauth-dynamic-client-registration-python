"""Requirement 3: metadata updates, statement ownership, version CAS."""

from __future__ import annotations

import threading

from dcr.errors import ErrorCode
from dcr.tokens import issue_software_statement

SECRET = "test-signing-secret"


def _stmt(software_id, metadata=None, **overrides):
    claims = {"software_id": software_id, "metadata": metadata or {"redirect_uris": ["https://a/cb"]}}
    raw = overrides.pop("raw_claims", None)
    claims.update(overrides)
    if raw:
        claims.update(raw)
    return {"software_statement": issue_software_statement(claims, secret=SECRET)}
def _register(client, software_id="sw-1", metadata=None):
    resp = client.post("/register", json=_stmt(software_id, metadata))
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_update_requires_version(client):
    cid = _register(client)["client_id"]
    resp = client.put(f"/clients/{cid}", json=_stmt("sw-1", {"redirect_uris": ["https://a/v2"]}))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_successful_versioned_update(client):
    cid = _register(client)["client_id"]
    resp = client.put(
        f"/clients/{cid}",
        json={**_stmt("sw-1", {"redirect_uris": ["https://a/v2"], "client_name": "New"}), "version": 1},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 2
    assert body["redirect_uris"] == ["https://a/v2"]
    assert body["client_name"] == "New"


def test_stale_version_conflict(client):
    cid = _register(client)["client_id"]
    payload = {**_stmt("sw-1", {"redirect_uris": ["https://a/v2"]}), "version": 1}
    assert client.put(f"/clients/{cid}", json=payload).status_code == 200
    # retry with the same (now stale) version
    resp = client.put(f"/clients/{cid}", json=payload)
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.VERSION_CONFLICT
    assert "2" in resp.json()["error_description"]
    # first update's state is intact
    assert client.get(f"/clients/{cid}").json()["redirect_uris"] == ["https://a/v2"]


def test_unknown_client_update_returns_404(client):
    resp = client.put("/clients/nope", json={**_stmt("sw-1"), "version": 1})
    assert resp.status_code == 404
    assert resp.json()["error"] == ErrorCode.CLIENT_NOT_FOUND


def test_update_requires_ownership_statement(client):
    cid = _register(client, "sw-owner")["client_id"]
    resp = client.put(
        f"/clients/{cid}",
        json={**_stmt("sw-attacker", {"redirect_uris": ["https://evil/cb"]}), "version": 1},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == ErrorCode.SOFTWARE_STATEMENT_MISMATCH
    # state untouched
    assert client.get(f"/clients/{cid}").json()["version"] == 1


def test_update_with_foreign_issuer_rejected(client):
    cid = _register(client, "sw-iss")["client_id"]
    resp = client.put(
        f"/clients/{cid}",
        json={**_stmt("sw-iss", raw_claims={"iss": "https://other.example"}), "version": 1},
    )
    # foreign issuer is rejected already during statement verification
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.UNTRUSTED_ISSUER


def test_failed_update_preserves_state(client):
    cid = _register(client)["client_id"]
    bad = {**_stmt("sw-1", {"redirect_uris": ["http://plain.example/cb"]}), "version": 1}
    resp = client.put(f"/clients/{cid}", json=bad)
    assert resp.status_code == 400
    body = client.get(f"/clients/{cid}").json()
    assert body["version"] == 1
    assert body["redirect_uris"] == ["https://a/cb"]


def test_concurrent_updates_exactly_one_succeeds(client):
    cid = _register(client)["client_id"]
    barrier = threading.Barrier(12)
    results: list = []

    def worker(i):
        barrier.wait()
        payload = {
            **_stmt("sw-1", {"redirect_uris": [f"https://a/v{i}"], "client_name": f"n{i}"}),
            "version": 1,
        }
        results.append(client.put(f"/clients/{cid}", json=payload))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for r in results if r.status_code == 200) == 1
    assert sum(1 for r in results if r.status_code == 409) == 11
    final = client.get(f"/clients/{cid}").json()
    assert final["version"] == 2
    # the stored name matches exactly the single winner
    winner = next(r for r in results if r.status_code == 200).json()
    assert final["client_name"] == winner["client_name"]
    assert final["redirect_uris"] == winner["redirect_uris"]


def test_sequential_updates_increment_version(client):
    cid = _register(client)["client_id"]
    for v in range(1, 6):
        resp = client.put(
            f"/clients/{cid}",
            json={**_stmt("sw-1", {"redirect_uris": [f"https://a/v{v}"]}), "version": v},
        )
        assert resp.status_code == 200
        assert resp.json()["version"] == v + 1
    assert client.get(f"/clients/{cid}").json()["version"] == 6


def test_update_on_revoked_client_blocked(client):
    cid = _register(client)["client_id"]
    client.post(f"/clients/{cid}/state/revoked", json=_stmt("sw-1"))
    resp = client.put(
        f"/clients/{cid}",
        json={**_stmt("sw-1", {"redirect_uris": ["https://a/new"]}), "version": 2},
    )
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.CLIENT_REVOKED


def test_signed_update_request_with_forged_signature_rejected(client):
    cid = _register(client)["client_id"]
    forged = {"software_statement": issue_software_statement(
        {"software_id": "sw-1", "metadata": {"redirect_uris": ["https://evil/cb"]}},
        secret="attacker",
    )}
    resp = client.put(f"/clients/{cid}", json={**forged, "version": 1})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SIGNATURE
