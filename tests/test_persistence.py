"""Restart recovery and persistence consistency tests."""

from __future__ import annotations

from app.config import Settings
from app.service import ClientService
from app.storage import Storage


def _settings(path: str) -> Settings:
    return Settings(
        database_path=path,
        issuer_secrets={"issuer-a": "test-issuer-secret"},
        trusted_audience="test-dcr",
    )


def test_state_and_secrets_survive_restart(tmp_path, statement) -> None:
    db_path = str(tmp_path / "restart.db")
    svc1 = ClientService(Storage(db_path), _settings(db_path))
    view, first_secret = None, None
    view, issue, created = svc1.register(
        {
            "software_statement": statement("sw-persist"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"], "client_name": "Persisted"},
        }
    )
    assert created
    cid = view["client_id"]
    rotation = svc1.rotate_secret(
        cid,
        {
            "software_statement": statement("sw-persist"),
            "retain_old_secret": True,
            "grace_period_seconds": 3600,
        },
    )
    svc1.transition_state(
        cid, {"software_statement": statement("sw-persist"), "target_state": "suspended"}
    )
    svc1._storage.close()

    # fresh process: new Storage instance over the same file
    svc2 = ClientService(Storage(db_path), _settings(db_path))
    restored = svc2.get(cid)
    assert restored["state"] == "suspended"
    assert restored["version"] == 3
    assert restored["metadata"]["client_name"] == "Persisted"
    assert restored["active_secret_id"] == rotation["secret_id"]
    assert restored["old_secret_expires_at"] is not None

    # stored hashes still verify the issued secrets
    row = svc2._storage.get_client(cid)
    from app.crypto import verify_secret

    assert verify_secret(rotation["client_secret"], row["secret_hash"])
    assert verify_secret(issue["client_secret"], row["old_secret_hash"])
    svc2._storage.close()


def test_revocation_and_version_survive_restart(tmp_path, statement) -> None:
    db_path = str(tmp_path / "revoked.db")
    svc1 = ClientService(Storage(db_path), _settings(db_path))
    view, _, _ = svc1.register(
        {
            "software_statement": statement("sw-rev"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        }
    )
    cid = view["client_id"]
    svc1.transition_state(
        cid, {"software_statement": statement("sw-rev"), "target_state": "revoked"}
    )
    svc1._storage.close()

    svc2 = ClientService(Storage(db_path), _settings(db_path))
    restored = svc2.get(cid)
    assert restored["state"] == "revoked"
    assert restored["has_secret"] is False  # revocation wiped secrets persistently

    from app.errors import RegistrationError
    import pytest

    with pytest.raises(RegistrationError) as exc:
        svc2.update(
            cid,
            {
                "software_statement": statement("sw-rev"),
                "expected_version": 2,
                "metadata": {"client_name": "Nope"},
            },
        )
    assert exc.value.code == "client_revoked"
    svc2._storage.close()


def test_idempotency_survives_restart(tmp_path, statement) -> None:
    db_path = str(tmp_path / "idem.db")
    svc1 = ClientService(Storage(db_path), _settings(db_path))
    body = {
        "software_statement": statement("sw-idem"),
        "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
    }
    view1, _, created1 = svc1.register(body)
    assert created1
    svc1._storage.close()

    svc2 = ClientService(Storage(db_path), _settings(db_path))
    view2, issue2, created2 = svc2.register(body)
    assert created2 is False
    assert view2["client_id"] == view1["client_id"]
    assert issue2 == {}
    svc2._storage.close()
