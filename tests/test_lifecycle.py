"""Requirement 5: lifecycle state transitions and independent recovery."""

from __future__ import annotations

from dcr.errors import ErrorCode
from dcr.tokens import issue_software_statement

SECRET = "test-signing-secret"


def _stmt(software_id="sw-1", metadata=None, **overrides):
    claims = {
        "software_id": software_id,
        "metadata": metadata or {"redirect_uris": ["https://app.example/cb"]},
    }
    claims.update(overrides)
    return {"software_statement": issue_software_statement(claims, secret=SECRET)}


def _transition(client, cid, target, *, version=None, software_id="sw-1"):
    payload = _stmt(software_id)
    if version is not None:
        payload["version"] = version
    return client.post(f"/clients/{cid}/state/{target}", json=payload)


def _register(client, software_id="sw-1"):
    r = client.post("/register", json=_stmt(software_id))
    assert r.status_code == 201, r.text
    return r.json()


def test_active_to_suspended_and_back(client):
    cid = _register(client)["client_id"]
    assert _transition(client, cid, "suspended").status_code == 200
    assert client.get(f"/clients/{cid}").json()["state"] == "suspended"
    assert _transition(client, cid, "active").status_code == 200
    assert client.get(f"/clients/{cid}").json()["state"] == "active"


def test_revoked_cannot_transition_to_active(client):
    cid = _register(client)["client_id"]
    _transition(client, cid, "revoked")
    for target in ("active", "suspended"):
        resp = _transition(client, cid, target)
        assert resp.status_code == 409
        assert resp.json()["error"] == ErrorCode.INVALID_STATE_TRANSITION
    assert client.get(f"/clients/{cid}").json()["state"] == "revoked"


def test_deleted_is_terminal(client):
    cid = _register(client)["client_id"]
    assert _transition(client, cid, "deleted").status_code == 200
    for target in ("active", "suspended", "revoked"):
        resp = _transition(client, cid, target)
        assert resp.status_code == 409
        assert resp.json()["error"] == ErrorCode.INVALID_STATE_TRANSITION


def test_active_directly_to_deleted_allowed(client):
    cid = _register(client, "sw-del")["client_id"]
    resp = _transition(client, cid, "deleted", software_id="sw-del")
    assert resp.status_code == 200


def test_unknown_target_state_rejected(client):
    cid = _register(client)["client_id"]
    resp = client.post(f"/clients/{cid}/state/frozen", json=_stmt())
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_revocation_revokes_all_secrets(client):
    cid = _register(client)["client_id"]
    secret = client.post(f"/clients/{cid}/secret/rotate", json=_stmt()).json()["client_secret"]
    assert client.app.state.service.authenticate(cid, secret)
    _transition(client, cid, "revoked")
    assert not client.app.state.service.authenticate(cid, secret)


def test_state_transition_uses_optimistic_version(client):
    cid = _register(client)["client_id"]
    # bump to version 2 via an update
    client.put(f"/clients/{cid}", json={**_stmt(), "version": 1})
    # stale version on suspend
    resp = _transition(client, cid, "suspended", version=1)
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.VERSION_CONFLICT
    assert _transition(client, cid, "suspended", version=2).status_code == 200


def test_state_transition_requires_ownership(client):
    cid = _register(client, "sw-life")["client_id"]
    resp = client.post(f"/clients/{cid}/state/suspended", json=_stmt("sw-intruder"))
    assert resp.status_code == 403
    assert resp.json()["error"] == ErrorCode.SOFTWARE_STATEMENT_MISMATCH


def test_recovery_flow_reactivates_revoked_client_with_new_secret(client):
    cid = _register(client)["client_id"]
    old_secret = client.post(f"/clients/{cid}/secret/rotate", json=_stmt()).json()["client_secret"]
    _transition(client, cid, "revoked")

    # normal update path stays blocked
    blocked = client.put(f"/clients/{cid}", json={**_stmt(), "version": 2})
    assert blocked.status_code == 409
    assert blocked.json()["error"] == ErrorCode.CLIENT_REVOKED

    # recovery without explicit assertion is refused
    no_assert = client.post(f"/clients/{cid}/recover", json=_stmt())
    assert no_assert.status_code == 400
    assert no_assert.json()["error"] == ErrorCode.INVALID_REQUEST

    rec = client.post(f"/clients/{cid}/recover", json={**_stmt(), "recover": True})
    assert rec.status_code == 200
    body = rec.json()
    assert body["state"] == "active"
    assert body["client_secret"]
    assert body["client_secret"] != old_secret
    # old credential stays dead, new credential works
    assert not client.app.state.service.authenticate(cid, old_secret)
    assert client.app.state.service.authenticate(cid, body["client_secret"])


def test_recovery_requires_ownership(client):
    cid = _register(client, "sw-rec")["client_id"]
    _transition(client, cid, "revoked", software_id="sw-rec")
    resp = client.post(f"/clients/{cid}/recover", json={**_stmt("sw-rec-attacker"), "recover": True})
    assert resp.status_code == 403
    assert resp.json()["error"] == ErrorCode.SOFTWARE_STATEMENT_MISMATCH


def test_recovery_only_applies_to_revoked_state(client):
    cid = _register(client, "sw-active")["client_id"]
    resp = client.post(f"/clients/{cid}/recover", json={**_stmt("sw-active"), "recover": True})
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.INVALID_STATE_TRANSITION


def test_suspended_client_update_allowed_but_revoked_is_not(client):
    cid = _register(client, "sw-mix")["client_id"]
    _transition(client, cid, "suspended", software_id="sw-mix")
    ok = client.put(
        f"/clients/{cid}",
        json={**_stmt("sw-mix", {"redirect_uris": ["https://a/v2"]}), "version": 2},
    )
    assert ok.status_code == 200
