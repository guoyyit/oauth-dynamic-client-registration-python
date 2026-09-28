"""Lifecycle state machine and HTTP transition tests."""

from __future__ import annotations

import pytest

from app.errors import RegistrationError


def test_legal_transitions(service, statement, register) -> None:
    view, _ = register("sw-1")
    cid = view["client_id"]

    suspended = service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "suspended"}
    )
    assert suspended["state"] == "suspended" and suspended["version"] == 2

    active = service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "active"}
    )
    assert active["state"] == "active"

    deleted = service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "deleted"}
    )
    assert deleted["state"] == "deleted"

    with pytest.raises(RegistrationError) as exc:
        service.get(cid)
    assert exc.value.code == "client_not_found"


def test_illegal_transitions_rejected(service, statement, register) -> None:
    view, _ = register("sw-1")
    cid = view["client_id"]
    service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "revoked"}
    )

    for target in ("active", "suspended"):
        with pytest.raises(RegistrationError) as exc:
            service.transition_state(
                cid,
                {"software_statement": statement("sw-1"), "target_state": target},
            )
        assert exc.value.code == "invalid_state_transition"
        assert exc.value.status_code == 409

    # delete is still allowed from revoked
    deleted = service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "deleted"}
    )
    assert deleted["state"] == "deleted"

    # deleted is terminal
    with pytest.raises(RegistrationError):
        service.transition_state(
            cid, {"software_statement": statement("sw-1"), "target_state": "active"}
        )


def test_unknown_target_state_rejected(service, statement, register) -> None:
    view, _ = register("sw-1")
    with pytest.raises(RegistrationError) as exc:
        service.transition_state(
            view["client_id"],
            {"software_statement": statement("sw-1"), "target_state": "frozen"},
        )
    assert exc.value.code == "invalid_state_transition"


def test_revoked_client_cannot_update_then_recover(service, statement, register) -> None:
    view, _ = register("sw-1")
    cid = view["client_id"]
    service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "revoked"}
    )

    with pytest.raises(RegistrationError) as exc:
        service.update(
            cid,
            {
                "software_statement": statement("sw-1"),
                "expected_version": 2,
                "metadata": {"client_name": "Backdoor"},
            },
        )
    assert exc.value.code == "client_revoked"

    # independent recovery restores to suspended, not active
    recovered = service.recover(cid, {"software_statement": statement("sw-1")})
    assert recovered["state"] == "suspended"
    # no secret was re-issued by recovery
    assert recovered["has_secret"] is False

    # normal update is allowed again after reactivation via suspend->active
    service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "active"}
    )
    updated = service.update(
        cid,
        {
            "software_statement": statement("sw-1"),
            "expected_version": recovered["version"] + 1,
            "metadata": {"client_name": "Legit"},
        },
    )
    assert updated["metadata"]["client_name"] == "Legit"


def test_recover_only_from_revoked(service, statement, register) -> None:
    view, _ = register("sw-1")
    cid = view["client_id"]
    # active client cannot be "recovered"
    with pytest.raises(RegistrationError) as exc:
        service.recover(cid, {"software_statement": statement("sw-1")})
    assert exc.value.code == "invalid_state_transition"


def test_state_change_requires_ownership(service, statement, register) -> None:
    view, _ = register("sw-1")
    register("sw-2")
    with pytest.raises(RegistrationError) as exc:
        service.transition_state(
            view["client_id"],
            {"software_statement": statement("sw-2"), "target_state": "suspended"},
        )
    assert exc.value.code == "ownership_mismatch"


def test_optimistic_state_transition_conflict(service, statement, register) -> None:
    view, _ = register("sw-1")
    cid = view["client_id"]
    service.transition_state(
        cid, {"software_statement": statement("sw-1"), "target_state": "suspended"}
    )
    with pytest.raises(RegistrationError) as exc:
        service.transition_state(
            cid,
            {
                "software_statement": statement("sw-1"),
                "target_state": "active",
                "expected_version": 1,
            },
        )
    assert exc.value.code == "version_conflict"
    # state remains suspended
    assert service.get(cid)["state"] == "suspended"


def test_http_state_transitions(client, statement) -> None:
    r = client.post(
        "/register",
        json={
            "software_statement": statement("sw-life"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        },
    )
    cid = r.json()["client_id"]
    sus = client.post(
        f"/clients/{cid}/state",
        json={"software_statement": statement("sw-life"), "target_state": "suspended"},
    )
    assert sus.status_code == 200 and sus.json()["state"] == "suspended"
    bad = client.post(
        f"/clients/{cid}/state",
        json={"software_statement": statement("sw-life"), "target_state": "deleted"},
    )
    # suspended -> deleted is valid; revoked -> active is not. Test illegal next:
    assert bad.status_code == 200 and bad.json()["state"] == "deleted"
    illegal = client.post(
        f"/clients/{cid}/state",
        json={"software_statement": statement("sw-life"), "target_state": "active"},
    )
    assert illegal.status_code == 404
