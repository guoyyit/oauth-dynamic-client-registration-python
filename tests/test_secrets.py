"""Requirement 4: secret generation, hashed storage, rotation and revocation."""

from __future__ import annotations

import sqlite3

from dcr.errors import ErrorCode


def test_secret_returned_plaintext_once_and_stored_hashed(client, register_client, db_path):
    cid, body = register_client("sw-secret")
    plain = body["client_secret"]
    assert plain and plain not in (cid,)
    assert body["client_secret_expires_at"]

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT secret_hash, salt, status FROM client_secrets").fetchall()
    conn.close()
    assert rows, "secret row must exist"
    assert all(plain not in (r[0], r[1]) for r in rows), "plaintext secret must not be stored"
    assert all(r[2] == "current" for r in rows)


def test_rotate_keeps_previous_secret_during_overlap(client, register_client):
    cid, body = register_client("sw-rot")
    first = body["client_secret"]
    resp = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": _token("sw-rot")})
    assert resp.status_code == 200
    second = resp.json()["client_secret"]
    assert second != first
    # overlap policy: both work immediately after rotation
    assert _auth(client, cid, first) is True
    assert _auth(client, cid, second) is True


def test_rotate_with_revoke_previous_invalidates_old(client, register_client):
    cid, body = register_client("sw-rot2")
    first = body["client_secret"]
    resp = client.post(
        f"/clients/{cid}/secret/rotate",
        json={"software_statement": _token("sw-rot2"), "revoke_previous": True},
    )
    assert resp.status_code == 200
    second = resp.json()["client_secret"]
    assert _auth(client, cid, first) is False
    assert _auth(client, cid, second) is True


def test_multiple_rotations_only_current_and_one_previous(client, register_client, repo):
    cid, _ = register_client("sw-multi")
    for _ in range(3):
        r = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": _token("sw-multi")})
        assert r.status_code == 200
    statuses = [s.status.value for s in repo.list_secrets(cid)]
    assert statuses.count("current") == 1
    assert statuses.count("previous") <= 1


def test_revoke_secret_blocks_all_credentials(client, register_client):
    cid, body = register_client("sw-rev")
    old = body["client_secret"]
    rotated = client.post(
        f"/clients/{cid}/secret/rotate", json={"software_statement": _token("sw-rev")}
    ).json()["client_secret"]
    resp = client.post(f"/clients/{cid}/secret/revoke", json={"software_statement": _token("sw-rev")})
    assert resp.status_code == 200
    assert _auth(client, cid, old) is False
    assert _auth(client, cid, rotated) is False


def test_rotation_requires_ownership(client, register_client):
    cid, _ = register_client("sw-own")
    from dcr.tokens import issue_software_statement

    forged = issue_software_statement(
        {"software_id": "sw-other", "metadata": {}}, secret="test-signing-secret"
    )
    resp = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": forged})
    assert resp.status_code == 403
    assert resp.json()["error"] == ErrorCode.SOFTWARE_STATEMENT_MISMATCH


def test_rotation_forged_signature(client, register_client):
    cid, _ = register_client("sw-forge")
    from dcr.tokens import issue_software_statement

    forged = issue_software_statement(
        {"software_id": "sw-forge", "metadata": {}}, secret="wrong-key"
    )
    resp = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": forged})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SIGNATURE


def test_rotation_blocked_for_public_client(client, make_statement):
    meta = {
        "redirect_uris": ["https://a/cb"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
    }
    reg = client.post("/register", json=make_statement("sw-public", meta))
    cid = reg.json()["client_id"]
    resp = client.post(f"/clients/{cid}/secret/rotate", json=make_statement("sw-public", meta))
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.SECRET_ROTATION_REJECTED


def test_rotation_on_suspended_client_rejected(client, register_client):
    cid, _ = register_client("sw-susp")
    client.post(f"/clients/{cid}/state/suspended", json={"software_statement": _token("sw-susp")})
    resp = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": _token("sw-susp")})
    assert resp.status_code == 409
    assert resp.json()["error"] == ErrorCode.SECRET_ROTATION_REJECTED


def test_unknown_client_rotation_404(client):
    resp = client.post("/clients/ghost/secret/rotate", json={"software_statement": _token()})
    assert resp.status_code == 404
    assert resp.json()["error"] == ErrorCode.CLIENT_NOT_FOUND


# --------------------------------------------------------------------------- #
# helpers (module level so tests above read naturally)

from dcr.tokens import issue_software_statement  # noqa: E402

SECRET = "test-signing-secret"


def _token(software_id="sw-1"):
    return issue_software_statement(
        {"software_id": software_id, "metadata": {"redirect_uris": ["https://app.example/cb"]}},
        secret=SECRET,
    )


def _auth(client, cid, secret):
    # Exercise the service's authentication path through app.state.
    return client.app.state.service.authenticate(cid, secret)
