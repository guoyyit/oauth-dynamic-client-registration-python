"""End-to-end HTTP workflow across registration, update, lifecycle and listing."""

from __future__ import annotations


def test_full_client_lifecycle_over_http(client, statement) -> None:
    sw = "sw-http-workflow"

    # register
    r = client.post(
        "/register",
        json={
            "software_statement": statement(sw),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"], "client_name": "V1"},
        },
    )
    assert r.status_code == 201, r.text
    record = r.json()
    cid = record["client_id"]
    assert record["version"] == 1 and record["client_secret"]

    # update with optimistic version
    r = client.put(
        f"/clients/{cid}",
        json={
            "client_id": cid,
            "software_statement": statement(sw),
            "expected_version": 1,
            "metadata": {"client_name": "V2"},
        },
    )
    assert r.status_code == 200 and r.json()["version"] == 2
    assert r.json()["metadata"]["client_name"] == "V2"

    # stale update rejected
    r = client.put(
        f"/clients/{cid}",
        json={
            "client_id": cid,
            "software_statement": statement(sw),
            "expected_version": 1,
            "metadata": {"client_name": "Stale"},
        },
    )
    assert r.status_code == 409 and r.json()["error"] == "version_conflict"

    # suspend -> revoke
    assert client.post(f"/clients/{cid}/state", json={"software_statement": statement(sw), "target_state": "suspended"}).json()["state"] == "suspended"
    revoked = client.post(f"/clients/{cid}/state", json={"software_statement": statement(sw), "target_state": "revoked"})
    assert revoked.status_code == 200 and revoked.json()["state"] == "revoked"

    # no reactivation through the normal state endpoint
    blocked = client.post(f"/clients/{cid}/state", json={"software_statement": statement(sw), "target_state": "active"})
    assert blocked.status_code == 409 and blocked.json()["error"] == "invalid_state_transition"

    # independent recovery -> suspended, then activate
    recovered = client.post(f"/clients/{cid}/recover", json={"software_statement": statement(sw)})
    assert recovered.status_code == 200 and recovered.json()["state"] == "suspended"
    activated = client.post(f"/clients/{cid}/state", json={"software_statement": statement(sw), "target_state": "active"})
    assert activated.json()["state"] == "active"


def test_list_pagination_and_filters_over_http(client, statement) -> None:
    for i in range(4):
        r = client.post(
            "/register",
            json={
                "software_statement": statement(f"sw-http-list-{i}"),
                "metadata": {
                    "redirect_uris": ["https://app.example.com/cb"],
                    "grant_types": ["client_credentials"] if i % 2 else ["authorization_code"],
                },
            },
        )
        assert r.status_code == 201

    seen: set[str] = set()
    cursor = None
    pages = 0
    while True:
        params = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = client.get("/clients", params=params)
        assert page.status_code == 200
        body = page.json()
        for item in body["items"]:
            assert item["client_id"] not in seen
            seen.add(item["client_id"])
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
        assert pages <= 5

    assert len(seen) == 4

    cc = client.get("/clients", params={"grant_type": "client_credentials"})
    assert cc.status_code == 200 and len(cc.json()["items"]) == 2

    bad_state = client.get("/clients", params={"state": "bogus"})
    assert bad_state.status_code == 400 and bad_state.json()["error"] == "invalid_state_transition"


def test_unknown_client_returns_404(client) -> None:
    r = client.get("/clients/does-not-exist")
    assert r.status_code == 404 and r.json()["error"] == "client_not_found"
