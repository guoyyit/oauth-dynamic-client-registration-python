"""Client secret generation, rotation, grace policy and revocation tests."""

from __future__ import annotations

import time

import pytest

from app.crypto import verify_secret
from app.errors import RegistrationError


def test_secret_is_hashed_at_rest(service, statement, register, storage) -> None:
    view, secret_issue = register("sw-1")
    row = storage.get_client(view["client_id"])
    assert row["secret_hash"] != secret_issue["client_secret"]
    assert verify_secret(secret_issue["client_secret"], row["secret_hash"])


def test_rotation_retains_old_secret_with_grace(service, statement, register) -> None:
    view, first = register("sw-1")
    result = service.rotate_secret(
        view["client_id"],
        {
            "software_statement": statement("sw-1"),
            "retain_old_secret": True,
            "grace_period_seconds": 600,
        },
    )
    assert result["secret_id"] != first["secret_id"]
    assert result["old_secret_id"] == first["secret_id"]
    assert result["old_secret_expires_at"] > time.time()
    assert result["client_secret"] != first["client_secret"]
    assert result["version"] == 2

    from app.storage import Storage  # noqa: F401


def test_rotation_immediately_invalidates_old(service, statement, register, storage) -> None:
    view, first = register("sw-1")
    result = service.rotate_secret(
        view["client_id"],
        {"software_statement": statement("sw-1"), "retain_old_secret": False},
    )
    assert result["old_secret_id"] is None
    assert result["old_secret_expires_at"] is None
    row = storage.get_client(view["client_id"])
    assert row["old_secret_hash"] is None
    assert verify_secret(result["client_secret"], row["secret_hash"])
    assert not verify_secret(first["client_secret"], row["secret_hash"])


def test_rotation_requires_ownership(service, statement, register) -> None:
    view, _ = register("sw-1")
    register("sw-2")
    with pytest.raises(RegistrationError) as exc:
        service.rotate_secret(
            view["client_id"],
            {"software_statement": statement("sw-2"), "retain_old_secret": False},
        )
    assert exc.value.code == "ownership_mismatch"


def test_revoked_client_cannot_rotate(service, statement, register) -> None:
    view, _ = register("sw-1")
    service.transition_state(
        view["client_id"],
        {"software_statement": statement("sw-1"), "target_state": "revoked"},
    )
    with pytest.raises(RegistrationError) as exc:
        service.rotate_secret(
            view["client_id"],
            {"software_statement": statement("sw-1"), "retain_old_secret": False},
        )
    assert exc.value.code == "client_revoked"


def test_revoke_active_secret_clears_both(service, statement, register, storage) -> None:
    view, _ = register("sw-1")
    service.rotate_secret(
        view["client_id"],
        {
            "software_statement": statement("sw-1"),
            "retain_old_secret": True,
            "grace_period_seconds": 600,
        },
    )
    result = service.revoke_secret(
        view["client_id"], {"software_statement": statement("sw-1")}
    )
    assert result["has_secret"] is False
    row = storage.get_client(view["client_id"])
    assert row["secret_hash"] is None and row["old_secret_hash"] is None


def test_revoke_only_old_secret(service, statement, register, storage) -> None:
    view, first = register("sw-1")
    rotation = service.rotate_secret(
        view["client_id"],
        {
            "software_statement": statement("sw-1"),
            "retain_old_secret": True,
            "grace_period_seconds": 600,
        },
    )
    service.revoke_secret(
        view["client_id"],
        {"software_statement": statement("sw-1"), "secret_id": rotation["old_secret_id"]},
    )
    row = storage.get_client(view["client_id"])
    assert row["old_secret_hash"] is None
    assert row["secret_id"] == rotation["secret_id"]
    assert verify_secret(rotation["client_secret"], row["secret_hash"])
    assert first["secret_id"] != row["secret_id"]


def test_rotate_after_full_revoke_is_rejected(service, statement, register) -> None:
    view, _ = register("sw-1")
    service.revoke_secret(view["client_id"], {"software_statement": statement("sw-1")})
    with pytest.raises(RegistrationError) as exc:
        service.rotate_secret(
            view["client_id"],
            {"software_statement": statement("sw-1"), "retain_old_secret": False},
        )
    assert exc.value.code == "no_active_secret"


def test_http_rotate_and_revoke(client, statement) -> None:
    r = client.post(
        "/register",
        json={
            "software_statement": statement("sw-http-secret"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        },
    )
    cid = r.json()["client_id"]
    rot = client.post(
        f"/clients/{cid}/secret/rotate",
        json={"software_statement": statement("sw-http-secret"), "retain_old_secret": False},
    )
    assert rot.status_code == 200
    assert rot.json()["client_secret"]
    rev = client.post(
        f"/clients/{cid}/secret/revoke",
        json={"software_statement": statement("sw-http-secret")},
    )
    assert rev.status_code == 200 and rev.json()["has_secret"] is False


def test_secret_verification_active_old_and_grace_expiry(service, statement, register, storage) -> None:
    view, first = register("sw-verify")
    rotation = service.rotate_secret(
        view["client_id"],
        {
            "software_statement": statement("sw-verify"),
            "retain_old_secret": True,
            "grace_period_seconds": 3600,
        },
    )
    cid = view["client_id"]
    assert service.verify_client_secret(cid, rotation["client_secret"]) == "active"
    assert service.verify_client_secret(cid, first["client_secret"]) == "old"
    assert service.verify_client_secret(cid, "totally-wrong") is None

    # expire the grace period directly; old secret must stop working and be purged
    storage.mutate_client(
        cid, None, lambda _c: {"old_secret_expires_at": 1.0}
    )
    assert service.verify_client_secret(cid, first["client_secret"]) is None
    assert service.verify_client_secret(cid, rotation["client_secret"]) == "active"
    row = storage.get_client(cid)
    assert row["old_secret_hash"] is None and row["old_secret_expires_at"] is None


def test_secret_verification_grace_expiry_survives_restart(tmp_path, statement) -> None:
    from app.config import Settings
    from app.service import ClientService
    from app.storage import Storage

    db_path = str(tmp_path / "grace.db")
    settings = Settings(
        database_path=db_path,
        issuer_secrets={"issuer-a": "test-issuer-secret"},
        trusted_audience="test-dcr",
    )
    svc1 = ClientService(Storage(db_path), settings)
    view, first = None, None
    view, issue, created = svc1.register(
        {
            "software_statement": statement("sw-grace"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        }
    )
    assert created
    svc1.rotate_secret(
        view["client_id"],
        {
            "software_statement": statement("sw-grace"),
            "retain_old_secret": True,
            "grace_period_seconds": 3600,
        },
    )
    # force past expiry, then "restart" without verifying
    svc1._storage.mutate_client(
        view["client_id"], None, lambda _c: {"old_secret_expires_at": 1.0}
    )
    svc1._storage.close()

    svc2 = ClientService(Storage(db_path), settings)
    assert svc2.verify_client_secret(view["client_id"], issue["client_secret"]) is None
    svc2._storage.close()
