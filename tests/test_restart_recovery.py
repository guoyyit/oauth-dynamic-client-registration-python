"""Requirement 4: state remains consistent across service restarts."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dcr.app import create_app
from dcr.config import Settings
from dcr.tokens import issue_software_statement

SECRET = "test-signing-secret"


def _settings(db_path):
    return Settings(
        database_path=db_path,
        signing_secret=SECRET,
        pbkdf2_iterations=1000,
        secret_ttl_seconds=3600,
        overlap_ttl_seconds=300,
    )


def _token(software_id="sw-persist"):
    return issue_software_statement(
        {"software_id": software_id, "metadata": {"redirect_uris": ["https://a/cb"]}},
        secret=SECRET,
    )


def _new_client(db_path):
    app = create_app(_settings(db_path))
    return TestClient(app)


def test_state_and_secrets_survive_restart(tmp_path):
    db_path = str(tmp_path / "dcr.sqlite3")

    with _new_client(db_path) as c1:
        reg = c1.post("/register", json={"software_statement": _token()})
        assert reg.status_code == 201
        body = reg.json()
        cid = body["client_id"]
        secret = body["client_secret"]
        rotated = c1.post(
            f"/clients/{cid}/secret/rotate", json={"software_statement": _token()}
        ).json()["client_secret"]
        c1.post(f"/clients/{cid}/state/suspended", json={"software_statement": _token()})

    # brand new process/app, same database file
    with _new_client(db_path) as c2:
        got = c2.get(f"/clients/{cid}")
        assert got.status_code == 200
        assert got.json()["state"] == "suspended"
        assert got.json()["version"] == 2  # register v1; rotation only touches secret timestamps

        svc = c2.app.state.service
        # while suspended, login is refused even though credentials are intact
        assert not svc.authenticate(cid, rotated)
        assert c2.app.state.repository.authenticate_secret(cid, rotated)
        assert c2.app.state.repository.authenticate_secret(cid, secret)

        # re-activate: both the current and overlap-window secret work
        c2.post(f"/clients/{cid}/state/active", json={"software_statement": _token()})
        assert svc.authenticate(cid, rotated)
        assert svc.authenticate(cid, secret)

        # revoke; revocation must persist into the next process
        c2.post(f"/clients/{cid}/state/revoked", json={"software_statement": _token()})

    with _new_client(db_path) as c3:
        assert c3.get(f"/clients/{cid}").json()["state"] == "revoked"
        assert not c3.app.state.service.authenticate(cid, secret)

        # recovery across restart works and issues a fresh secret
        rec = c3.post(f"/clients/{cid}/recover", json={
            "software_statement": _token(), "recover": True,
        })
        assert rec.status_code == 200
        assert rec.json()["state"] == "active"
        new_secret = rec.json()["client_secret"]

    with _new_client(db_path) as c4:
        assert c4.app.state.service.authenticate(cid, new_secret)
        assert c4.get(f"/clients/{cid}").json()["state"] == "active"


def test_idempotent_replay_after_restart(tmp_path):
    db_path = str(tmp_path / "dcr.sqlite3")
    token = _token("sw-restart-idem")
    with _new_client(db_path) as c1:
        r1 = c1.post("/register", json={"software_statement": token})
        cid = r1.json()["client_id"]
        assert r1.status_code == 201
    with _new_client(db_path) as c2:
        r2 = c2.post("/register", json={"software_statement": token})
        assert r2.status_code == 200
        assert r2.json()["client_id"] == cid


def test_hashed_secret_verification_after_restart(tmp_path):
    db_path = str(tmp_path / "dcr.sqlite3")
    with _new_client(db_path) as c1:
        reg = c1.post("/register", json={"software_statement": _token("sw-hash")})
        cid, secret = reg.json()["client_id"], reg.json()["client_secret"]
    with _new_client(db_path) as c2:
        assert c2.app.state.service.authenticate(cid, secret)
        assert not c2.app.state.service.authenticate(cid, "guessed-secret")
