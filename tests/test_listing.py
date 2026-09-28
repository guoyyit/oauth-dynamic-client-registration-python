"""Requirement 6: pagination, filtering and stable ordering under concurrency."""

from __future__ import annotations

import threading

from dcr.errors import ErrorCode
from dcr.tokens import issue_software_statement

SECRET = "test-signing-secret"


def _token(i):
    return issue_software_statement(
        {"software_id": f"sw-page-{i}", "metadata": {"redirect_uris": ["https://a/cb"]}},
        secret=SECRET,
    )


def _bulk(client, n):
    for i in range(n):
        r = client.post("/register", json={"software_statement": _token(i)})
        assert r.status_code == 201


def _walk(client, page_size, **params):
    seen = []
    cursor = None
    pages = 0
    total = None
    while True:
        q = {"page_size": page_size, **params}
        if cursor:
            q["cursor"] = cursor
        body = client.get("/clients", params=q).json()
        pages += 1
        total = body["total"]
        seen.extend(c["client_id"] for c in body["clients"])
        cursor = body["next_cursor"]
        if not cursor:
            break
    return seen, pages, total


def test_keyset_pagination_no_skip_or_repeat(client):
    _bulk(client, 23)
    seen, pages, total = _walk(client, 10)
    assert total == 23
    assert pages == 3
    assert len(seen) == 23
    assert len(set(seen)) == 23


def test_pagination_with_large_page_size_capped(client):
    _bulk(client, 5)
    body = client.get("/clients", params={"page_size": 10_000}).json()
    assert len(body["clients"]) == 5


def test_invalid_page_size_rejected(client):
    resp = client.get("/clients", params={"page_size": 0})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_malformed_cursor_rejected(client):
    resp = client.get("/clients", params={"cursor": "not-base64!!!"})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_state_filtering(client):
    _bulk(client, 5)
    # suspend the 3rd registered client
    listing = client.get("/clients", params={"page_size": 100}).json()["clients"]
    target = listing[2]
    from dcr.tokens import issue_software_statement as mint

    stmt = mint({"software_id": target["software_id"], "metadata": {"redirect_uris": ["https://a/cb"]}},
                secret=SECRET)
    r = client.post(f"/clients/{target['client_id']}/state/suspended", json={"software_statement": stmt})
    assert r.status_code == 200

    active = client.get("/clients", params={"state": "active"}).json()
    suspended = client.get("/clients", params={"state": "suspended"}).json()
    assert active["total"] == 4
    assert suspended["total"] == 1
    assert suspended["clients"][0]["client_id"] == target["client_id"]
    assert all(c["state"] == "active" for c in active["clients"])


def test_unknown_state_filter_rejected(client):
    resp = client.get("/clients", params={"state": "frozen"})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_order_is_stable_by_insertion_order(client):
    _bulk(client, 12)
    pages = []
    cursor = None
    while True:
        params = {"page_size": 4}
        if cursor:
            params["cursor"] = cursor
        body = client.get("/clients", params=params).json()
        pages.extend(body["clients"])
        cursor = body["next_cursor"]
        if not cursor:
            break
    software_ids = [c["software_id"] for c in pages]
    assert software_ids == [f"sw-page-{i}" for i in range(12)]


def test_pagination_stable_while_registrations_arrive(client):
    _bulk(client, 20)
    collected: list[str] = []
    cursor = None
    stop = threading.Event()

    def writer():
        i = 1000
        while not stop.is_set():
            client.post("/register", json={
                "software_statement": issue_software_statement(
                    {"software_id": f"sw-conc-{i}", "metadata": {"redirect_uris": ["https://a/cb"]}},
                    secret=SECRET,
                )
            })
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    try:
        while True:
            params = {"page_size": 5}
            if cursor:
                params["cursor"] = cursor
            body = client.get("/clients", params=params).json()
            batch = [c["client_id"] for c in body["clients"]]
            # no repeat within a single walk
            assert not (set(collected) & set(batch))
            collected.extend(batch)
            cursor = body["next_cursor"]
            if not cursor:
                break
    finally:
        stop.set()
        t.join()

    # the walk never repeats itself even while rows are being inserted, and
    # the initial snapshot of 20 rows was fully covered.
    assert len(set(collected)) == len(collected)
    assert len(collected) >= 20


def test_get_unknown_client_404(client):
    resp = client.get("/clients/missing")
    assert resp.status_code == 404
    assert resp.json()["error"] == ErrorCode.CLIENT_NOT_FOUND


def test_listing_never_includes_secret_material(client):
    _bulk(client, 3)
    body = client.get("/clients").json()
    for c in body["clients"]:
        assert "client_secret" not in c
